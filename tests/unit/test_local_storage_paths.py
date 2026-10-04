"""``LocalStorage``: a storage key is an identifier, never a filesystem path.

The signed artifact endpoint has no session, so its ``storage_key`` path
parameter is attacker-controlled on every single request. Everything between the
route and ``open()`` can be bypassed by a caller who never holds a token; the one
check that cannot be skipped is the one inside the adapter, and these tests exist
to make sure removing or weakening it fails.

They also pin the half of the contract that makes downloads work at all: a
well-formed key resolves under the configured root, and a file that is there
opens. In Docker that root is ``/app/storage``, a named volume — but nothing here
depends on that, and nothing in the adapter may.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.infrastructure.storage.local_storage import LocalStorage, StorageSettings
from app.modules.software_management.domain.ports.storage import (
    Storage,
    StorageFileNotFoundError,
    StorageReadError,
    StorageSecurityError,
)

KEY = "software/2f0cdb03-b4a2-410b-b10b-ecc856cfaa41/versions/64999d7d-a276-4050-8bcc-dbb729b3a5fb/7f26ed36-3bad-4ecc-a961-cbcd60ee080d/Polymorphism.pdf"


@pytest.fixture
def storage_root(tmp_path: Path) -> Path:
    root = tmp_path / "storage"
    root.mkdir()
    return root


@pytest.fixture
def storage(storage_root: Path) -> LocalStorage:
    return LocalStorage(
        settings=StorageSettings(
            backend_url="http://localhost:8000",
            storage_root=str(storage_root),
            signing_secret="secret",
        )
    )


def _store(storage: LocalStorage, storage_key: str, content: bytes) -> Path:
    """Put a file at ``storage_key`` the way an upload would have."""
    path = Path(storage._settings.storage_root) / storage_key  # noqa: SLF001 -- test-only reach
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


class TestValidKeys:
    def test_a_key_resolves_to_a_path_under_the_root(self, storage: LocalStorage, storage_root: Path) -> None:
        path = storage._resolve_path(KEY)  # noqa: SLF001 -- the invariant under test

        assert path == storage_root / KEY
        assert path.is_relative_to(storage_root)

    def test_the_resolved_path_stays_under_the_root_even_after_symlinks(self, storage_root: Path) -> None:
        """``.resolve()`` runs on both sides of the comparison, so a symlink
        planted inside the root cannot be used to read outside it."""
        outside = storage_root.parent / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("secret")
        (storage_root / "link").symlink_to(outside)

        storage = LocalStorage(
            settings=StorageSettings(
                backend_url="http://localhost:8000", storage_root=str(storage_root), signing_secret="s"
            )
        )
        with pytest.raises(StorageSecurityError):
            storage._resolve_path("link/secret.txt")  # noqa: SLF001

    def test_an_existing_artifact_opens(self, storage: LocalStorage) -> None:
        expected = _store(storage, KEY, b"%PDF-1.7 payload")

        with storage.open(storage_key=KEY) as handle:
            assert handle.read() == b"%PDF-1.7 payload"
        assert expected.exists()

    def test_a_missing_artifact_raises_the_storage_exception(self, storage: LocalStorage) -> None:
        """``StorageFileNotFoundError`` specifically: the service maps it to a 404
        naming the artifact, and it must not be confused with a security refusal
        or with storage being down."""
        with pytest.raises(StorageFileNotFoundError):
            storage.open(storage_key="software/nobody/versions/nothing/x/y.pdf")

    def test_a_directory_is_not_an_artifact(self, storage: LocalStorage, storage_root: Path) -> None:
        """A directory is not a 500. ``exists()`` is true for one, so before this
        was checked the open raised ``IsADirectoryError``, which the adapter
        wrapped as a read failure -- and the client got a 500 for asking for
        something that simply is not there."""
        (storage_root / "software" / "a-directory").mkdir(parents=True)

        with pytest.raises(StorageFileNotFoundError):
            storage.open(storage_key="software/a-directory")


class TestTraversalIsRefused:
    @pytest.mark.parametrize(
        "storage_key",
        [
            "../secret.txt",
            "../../etc/passwd",
            "software/../../../etc/passwd",
            "software/./../../escape.pdf",
            "..",
            "../",
            "software/..",
        ],
    )
    def test_a_traversing_key_is_refused(self, storage: LocalStorage, storage_key: str) -> None:
        with pytest.raises((StorageSecurityError, ValueError)):
            storage.open(storage_key=storage_key)

    @pytest.mark.parametrize(
        "storage_key",
        ["/etc/passwd", "/app/storage/anything", "/"],
    )
    def test_an_absolute_path_is_refused(self, storage: LocalStorage, storage_key: str) -> None:
        """An absolute key is not "the storage root itself"; it is an escape
        hatch. ``_validate_storage_key`` rejects it before any path is built."""
        with pytest.raises((StorageSecurityError, ValueError)):
            storage.open(storage_key=storage_key)

    @pytest.mark.parametrize(
        "storage_key",
        [
            r"..\..\Windows\System32\config",
            r"C:\Windows\System32\drivers\etc\hosts",
            "C:/Windows/System32",
            r"software\..\..\escape.pdf",
        ],
    )
    def test_a_windows_style_path_is_refused(self, storage: LocalStorage, storage_key: str) -> None:
        """Backslashes are normalised to ``/`` before the traversal check, so
        ``..\\..\\`` is caught by the same rule as ``../../``. A drive-qualified
        path is rejected outright."""
        with pytest.raises((StorageSecurityError, ValueError)):
            storage.open(storage_key=storage_key)

    def test_a_file_outside_the_root_cannot_be_reached_by_any_spelling(self, storage: LocalStorage, storage_root: Path) -> None:
        """The concrete attack: a secret next to the root, and every key that
        might be used to ask for it."""
        secret = storage_root.parent / "outside-secret.txt"
        secret.write_text("do not serve me")

        for attempt in (
            "../outside-secret.txt",
            "./../outside-secret.txt",
            "software/../../outside-secret.txt",
            str(secret),
            f"{storage_root}/../outside-secret.txt",
        ):
            with pytest.raises((StorageSecurityError, ValueError)):
                storage.open(storage_key=attempt)

    def test_a_key_carrying_a_null_byte_is_refused(self, storage: LocalStorage) -> None:
        with pytest.raises((StorageSecurityError, ValueError)):
            storage.open(storage_key="software/a\x00b/c.pdf")


class TestTheAdapterStaysMechanical:
    def test_it_implements_the_port(self, storage: LocalStorage) -> None:
        assert isinstance(storage, Storage)

    def test_it_knows_nothing_about_who_is_downloading(self) -> None:
        """The adapter must not grow an ``authorized`` parameter. Authorization is
        a domain question; the adapter only answers whether a key is addressable
        and whether a file is there. Both of these would be that mistake."""
        import inspect

        for name in ("save", "open", "delete", "exists"):
            signature = inspect.signature(getattr(LocalStorage, name))
            assert list(signature.parameters) == ["self", "storage_key"] or list(
                signature.parameters
            ) == ["self", "storage_key", "source_path"], f"{name}{signature}"

        source = inspect.getsource(LocalStorage).lower()
        for forbidden in ("user", "purchase", "role", "permission", "owner"):
            assert forbidden not in source, (
                f"LocalStorage mentions {forbidden!r}; it must stay unaware of authorization"
            )

    def test_a_read_failure_is_its_own_exception(self, storage: LocalStorage) -> None:
        """An unreadable file and a missing one are different problems and get
        different statuses, so they must not share an exception class."""
        path = _store(storage, KEY, b"payload")
        path.chmod(0o000)
        try:
            try:
                readable = path.read_bytes() == b"payload"
            except OSError:
                readable = False
            if readable:
                pytest.skip("this user can read a 0000 file; the failure cannot be provoked")

            with pytest.raises(StorageReadError):
                storage.open(storage_key=KEY)
        finally:
            path.chmod(0o600)

    def test_nothing_in_the_adapter_mentions_the_container_path(self) -> None:
        """``/app/storage`` is the deployment's choice, made by
        ``UPLOAD_ROOT``. Hard-coding it would make the adapter unusable anywhere
        else and would leak the container layout into error messages."""
        import inspect

        assert "/app/storage" not in inspect.getsource(LocalStorage)
        assert "/app/storage" not in inspect.getsource(inspect.getmodule(LocalStorage))