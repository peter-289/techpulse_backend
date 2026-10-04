"""How the artifact is turned into a response body, and into a header.

Split out from the end-to-end download test on purpose. httpx's ASGI transport
buffers a response before returning it, so through ``TestClient`` every response
looks like a single chunk no matter how the server produced it -- the property
that matters here cannot be observed from outside. These call the two functions
the endpoint composes directly, where the chunk boundaries are visible.

The bug being pinned: ``StreamingResponse`` accepts any iterable, and a raw
binary file *is* an iterable that yields lines. Handing it ``open(path, "rb")``
therefore streams newline-delimited records, and an artifact with no trailing
newline came out as one chunk the size of the entire file. Passing a generator
that reads a fixed number of bytes at a time is what makes the streaming real.
"""

from __future__ import annotations

import io

import pytest

from app.modules.software_management.api.routers.software_router import (
    STREAM_CHUNK_SIZE,
    _content_disposition,
    _iter_chunks,
)


class _FakeFile:
    """A handle that records how it was read, so ``read(size)`` can be told apart
    from bare iteration."""

    def __init__(self, data: bytes) -> None:
        self._buffer = io.BytesIO(data)
        self.read_sizes: list[int] = []
        self.closed = False
        self.iterated = False

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self._buffer.read(size)

    def __iter__(self):
        self.iterated = True
        return self

    def __next__(self):
        line = self._buffer.readline()
        if not line:
            raise StopIteration
        return line

    def close(self) -> None:
        self.closed = True


class TestTheBodyIsStreamed:
    def test_the_file_is_never_iterated_line_by_line(self) -> None:
        """The regression. ``read(size)`` with an explicit size means nothing
        depends on newlines."""
        handle = _FakeFile(b"%PDF-1.7\n" + b"x" * 5000)

        list(_iter_chunks(handle, chunk_size=1024))

        assert not handle.iterated
        assert handle.read_sizes and set(handle.read_sizes) == {1024}

    def test_a_large_artifact_yields_many_fixed_size_chunks(self) -> None:
        body = b"%PDF-1.7\n" + bytes(range(256)) * 40_000  # ~10 MB, no trailing newline
        handle = _FakeFile(body)

        chunks = list(_iter_chunks(handle, chunk_size=STREAM_CHUNK_SIZE))

        assert len(chunks) > 1
        assert all(len(chunk) == STREAM_CHUNK_SIZE for chunk in chunks[:-1])
        assert b"".join(chunks) == body

    def test_the_final_chunk_is_the_remainder_and_still_non_empty(self) -> None:
        """``read`` returning b"" is what ends the loop, so a zero-length read
        must never be yielded -- a spurious empty chunk would terminate the
        client's copy loop early."""
        handle = _FakeFile(b"x" * (STREAM_CHUNK_SIZE + 17))

        chunks = list(_iter_chunks(handle, chunk_size=STREAM_CHUNK_SIZE))

        assert [len(chunk) for chunk in chunks] == [STREAM_CHUNK_SIZE, 17]
        assert all(chunks)

    def test_an_empty_artifact_yields_nothing_rather_than_an_empty_chunk(self) -> None:
        handle = _FakeFile(b"")

        assert list(_iter_chunks(handle, chunk_size=STREAM_CHUNK_SIZE)) == []

    def test_the_handle_is_closed_when_the_body_is_consumed(self) -> None:
        handle = _FakeFile(b"payload")

        list(_iter_chunks(handle, chunk_size=STREAM_CHUNK_SIZE))

        assert handle.closed

    def test_the_handle_is_closed_when_the_client_gives_up_part_way(self) -> None:
        """The generator's ``finally`` is the only thing that runs when the
        consumer stops early, which is exactly what happens when a client hangs
        up mid-download."""
        handle = _FakeFile(b"x" * (STREAM_CHUNK_SIZE * 10))
        chunks = _iter_chunks(handle, chunk_size=STREAM_CHUNK_SIZE)

        next(chunks)
        del chunks  # dropped mid-body, as a broken connection would

        assert handle.closed

    def test_the_handle_is_closed_when_reading_raises(self) -> None:
        class _Broken(_FakeFile):
            def read(self, size: int = -1) -> bytes:
                raise OSError("the volume went away")

        handle = _Broken(b"payload")

        with pytest.raises(OSError):
            list(_iter_chunks(handle, chunk_size=STREAM_CHUNK_SIZE))

        assert handle.closed


class TestTheFilenameHeader:
    def test_the_filename_is_the_last_segment_of_the_key(self) -> None:
        disposition = _content_disposition(
            "software/123/versions/1.0.0/abcd/setup installer.exe"
        )

        assert 'filename="setup installer.exe"' in disposition
        assert disposition.startswith("attachment;")
        assert "abcd" not in disposition, "the internal layout leaked into the header"

    def test_the_header_declares_a_download(self) -> None:
        disposition = _content_disposition("software/123/x/y/file.zip")

        assert disposition.startswith("attachment;")

    def test_a_non_ascii_filename_is_carried_in_both_forms(self) -> None:
        """The quoted form cannot hold non-ASCII, so RFC 5987 carries it."""
        disposition = _content_disposition("software/123/x/y/日本語.pdf")

        assert "filename*=UTF-8''%E6%97%A5%E6%9C%AC%E8%AA%9E.pdf" in disposition
        # The ASCII fallback has to still be a legal quoted string.
        quoted = disposition.split("filename=\"")[1].split("\"")[0]
        quoted.encode("ascii")

    def test_a_quote_or_newline_in_the_filename_cannot_break_out_of_the_header(self) -> None:
        """The filename comes from a storage key, and a storage key reaches this
        endpoint as an unauthenticated path parameter. A newline here would let a
        response inject headers."""
        for hostile in (
            'evil".txt',
            'evil\r\nSet-Cookie: admin=1',
            "evil\nX-Injected: 1",
            "back\\slash.txt",
        ):
            disposition = _content_disposition(f"software/123/x/y/{hostile}")

            assert "\n" not in disposition, f"{hostile!r} injected a newline"
            assert "\r" not in disposition, f"{hostile!r} injected a carriage return"
            header_value = disposition.split("filename=\"")[1].split("\"")[0]
            assert "\"" not in header_value

    def test_a_key_naming_a_directory_still_produces_a_filename(self) -> None:
        """Defensive only: the serving endpoint refuses a directory before this is
        reached, so this is about the header helper not raising a 500 if that
        ever changes."""
        assert _content_disposition("software/123/x/y/")
