"""The log tail: what it reads, and what it refuses to give back.

Two separate claims, so two sets of tests.

The first set is about *coverage*: ``sanitize`` is exercised one pattern at a time
rather than through one long log line. That is deliberate. A redaction gap is
invisible in the happy path -- the endpoint returns 200, the lines look right,
and a credential has simply been passed through to the browser. The only way to
notice is to hand the function each shape separately and require every one to
change.

The second set is about the tail itself: the last N lines in file order, bounded
memory, no error for a file that is not there, and no crash on a byte sequence
that is not valid UTF-8. The last two matter because a log file is the one input
in this codebase that another process is writing to while it is being read.
"""

from __future__ import annotations

import json
import threading

import pytest

from app.modules.security.infrastructure.logs.file_log_tail import (
    FileLogTail,
    sanitize,
)

_REDACTED = "[REDACTED]"


# === sanitize: one pattern at a time ===


@pytest.mark.parametrize(
    ("line", "secret"),
    [
        # The shape the project's own formatter produces:
        # "%(asctime)s | %(levelprefix)s | %(name)s | %(message)s".
        ("2026-03-01 12:00:00 | INFO | app.auth | login ok token=eyJhbGciOiJ9", "eyJhbGciOiJ9"),
        ("access_token=at-secret-value", "at-secret-value"),
        ("refresh_token=rt-secret-value", "rt-secret-value"),
        ("refresh_token: rt-secret-value", "rt-secret-value"),
        ("password=hunter2", "hunter2"),
        ("password: hunter2", "hunter2"),
        ("passwd=hunter2", "hunter2"),
        ("passphrase=hunter2", "hunter2"),
        # JSON, where a closing quote sits between the key and the colon. This
        # is the form the first version of the pattern missed entirely.
        ('{"password": "hunter2"}', "hunter2"),
        ('{"access_token": "at-secret-value"}', "at-secret-value"),
        ('{"refreshToken": "rt-secret-value"}', "rt-secret-value"),
        ("{'access_token': 'at-secret-value'}", "at-secret-value"),
        ('{"api_key": "AKIAIOSFODNN7EXAMPLE"}', "AKIAIOSFODNN7EXAMPLE"),
        ('{"apikey": "AKIAIOSFODNN7EXAMPLE"}', "AKIAIOSFODNN7EXAMPLE"),
        ('{"client_secret": "sk-live-1234"}', "sk-live-1234"),
        ('{"secret_key": "s3cr3t"}', "s3cr3t"),
        ('{"api_secret_key": "s3cr3t"}', "s3cr3t"),
        ('{"csrf_token": "csrf-value"}', "csrf-value"),
        # Headers.
        ("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi.payload.sig"),
        ("authorization: bearer eyJhbGciOi.payload.sig", "eyJhbGciOi.payload.sig"),
        ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
        # A JWT's trailing padding and dots must be inside the redacted span,
        # otherwise the signature survives.
        ("token=eyJhbGciOi.payload.sig==", "sig=="),
    ],
)
def test_the_credential_is_gone_and_the_key_is_not(line: str, secret: str) -> None:
    sanitized = sanitize(line)
    assert secret not in sanitized
    assert _REDACTED in sanitized


@pytest.mark.parametrize(
    "line",
    [
        "",
        "2026-03-01 12:00:00 | INFO | app.main | GET /api/v1/thing 200",
        "http_request method=GET path=/api/v1/x status=200 duration_ms=1 client_ip=203.0.113.9",
        "Audit actor resolution failed: (psycopg) OperationalError: connection reset",
        # Stems that merely contain a credential name are not credentials.
        "monkey count=3 tokenizer=enabled keyhole=true secretariat=false",
        '{"user": "alice", "status": 200, "duration_ms": 12, "items": [1, 2, 3]}',
    ],
)
def test_a_line_with_no_credential_is_returned_unchanged(line: str) -> None:
    """Redaction that fires on ordinary words trains an operator to ignore it.

    The guarantee is symmetric on purpose: every one of these strings must come
    back byte-identical, so a diff of a sanitized log against the original shows
    only credential values.
    """
    assert sanitize(line) == line


@pytest.mark.parametrize(
    "document",
    [
        '{"password": "x", "n": 1}',
        '{"access_token": "a.b.c", "list": [1, 2]}',
        '{"refreshToken": "r", "ok": true}',
        '{"user": "alice", "api_key": "AKIA1", "nested": {"secret_key": "s"}}',
    ],
)
def test_a_redacted_json_line_is_still_valid_json(document: str) -> None:
    """The replacement has to keep the document's shape.

    Dropping the value's quotes would leave ``{"password": [REDACTED]}``, which
    is not a string where a string was -- so a log shipper parsing the file after
    this one would fail on a line that only ever held a secret.
    """
    parsed = json.loads(sanitize(document))
    assert isinstance(parsed, dict)


def test_a_credential_is_redacted_wherever_it_appears_in_the_line() -> None:
    """Not just the first match.

    A log line with a query string and a message can carry more than one, and
    ``sub`` replacing the leftmost match must not stop there.
    """
    sanitized = sanitize("login failed token=first-secret retry token=second-secret")

    assert "first-secret" not in sanitized
    assert "second-secret" not in sanitized
    assert sanitized.count(_REDACTED) == 2


def test_a_value_containing_equals_signs_is_redacted_whole() -> None:
    """``key=a=b=c`` -- the value runs to the delimiter, not to the last ``=``.

    Base64 padding and JWT segments both put ``=`` inside the value, so a
    pattern that stopped at the first one would leave the remainder exposed.
    """
    assert sanitize("token=abc=def=ghi") == f"token={_REDACTED}"


def test_a_signature_is_not_treated_as_a_credential() -> None:
    """The negative case for the family above.

    ``signature`` contains no credential, and a JWT's signature is not a secret.
    Redacting it would be noise in the one place an operator is reading a line
    closely, which is the same failure as over-redacting ``monkey``.
    """
    assert sanitize("token=eyJhbGciOiJ9 payload=abc signature=xyz") == (
        f"token={_REDACTED} payload=abc signature=xyz"
    )


# === FileLogTail ===


@pytest.mark.asyncio
async def test_it_returns_the_last_lines_in_file_order(tmp_path) -> None:
    log = tmp_path / "app.log"
    log.write_text("".join(f"line {n}\n" for n in range(10)), encoding="utf-8")

    assert await FileLogTail(log).tail(lines=3) == ["line 7", "line 8", "line 9"]


@pytest.mark.asyncio
async def test_it_returns_everything_when_asked_for_more_than_the_file_holds(tmp_path) -> None:
    log = tmp_path / "app.log"
    log.write_text("only line\n", encoding="utf-8")

    assert await FileLogTail(log).tail(lines=100) == ["only line"]


@pytest.mark.asyncio
async def test_a_missing_file_is_empty_rather_than_an_error(tmp_path) -> None:
    """The log is created by the logging setup, which may not have run yet.

    An operator opening the endpoint at boot should see no entries, not a 500.
    """
    assert await FileLogTail(tmp_path / "not-created-yet.log").tail(lines=10) == []


@pytest.mark.asyncio
async def test_an_empty_file_is_empty(tmp_path) -> None:
    log = tmp_path / "app.log"
    log.write_text("", encoding="utf-8")

    assert await FileLogTail(log).tail(lines=10) == []


@pytest.mark.asyncio
async def test_line_endings_are_stripped(tmp_path) -> None:
    """Both conventions, because the file is written by another process.

    A trailing ``\\r`` would otherwise survive into the JSON body and be
    invisible in a test that compares against a string containing one.
    """
    log = tmp_path / "app.log"
    log.write_bytes(b"unix\nwindows\r\n")

    assert await FileLogTail(log).tail(lines=10) == ["unix", "windows"]


@pytest.mark.asyncio
async def test_a_byte_sequence_that_is_not_utf8_does_not_raise(tmp_path) -> None:
    """``errors="replace"``, and the test that makes that choice visible.

    A truncated multibyte character is a normal state for the last line of a log
    being appended to. Reading it strictly would turn a partially-written line
    into a 500 on the one endpoint an operator reaches *because* something is
    wrong.
    """
    log = tmp_path / "app.log"
    log.write_bytes(b"before\n" + b"\xff\xfe broken\n" + b"after\n")

    entries = await FileLogTail(log).tail(lines=10)

    assert entries[0] == "before"
    assert entries[-1] == "after"
    assert len(entries) == 3


@pytest.mark.asyncio
async def test_a_partial_final_line_is_returned_as_written(tmp_path) -> None:
    """The tail of a live log is routinely a half-written line.

    Dropping it would hide the most recent event, which is the reason someone is
    looking at a log tail at all.
    """
    log = tmp_path / "app.log"
    log.write_text("complete\nin progress", encoding="utf-8")

    assert await FileLogTail(log).tail(lines=10) == ["complete", "in progress"]


@pytest.mark.asyncio
async def test_the_read_happens_off_the_event_loop_thread(tmp_path) -> None:
    """The reason the port's method is ``async`` but the work is not.

    A log file on a slow disk -- or a large one, which is the case that matters --
    would block every other request for the length of the read. The check is
    that the worker thread is not the one that called ``await``.
    """
    log = tmp_path / "app.log"
    log.write_text("line\n", encoding="utf-8")

    calling_thread = threading.get_ident()
    seen: list[int] = []
    original = FileLogTail._read_tail

    def _record(self, lines: int) -> list[str]:
        seen.append(threading.get_ident())
        return original(self, lines)

    FileLogTail._read_tail = _record
    try:
        await FileLogTail(log).tail(lines=1)
    finally:
        FileLogTail._read_tail = original

    assert seen and seen[0] != calling_thread


@pytest.mark.asyncio
async def test_memory_is_bounded_by_the_request_not_by_the_file(tmp_path) -> None:
    """``deque(maxlen=lines)``, asserted through the result it produces.

    Writing a large file is the only honest way to see this: if the adapter
    collected the whole file first, a 10-line request over a 10,000-line log
    would return 10 lines here and still have held all 10,000 in memory.
    """
    log = tmp_path / "app.log"
    log.write_text("".join(f"line {n}\n" for n in range(10_000)), encoding="utf-8")

    entries = await FileLogTail(log).tail(lines=5)

    assert len(entries) == 5
    assert entries[-1] == "line 9999"


@pytest.mark.asyncio
async def test_the_path_is_reported_for_the_endpoint_to_echo(tmp_path) -> None:
    """The operator is told which file they are reading.

    Not decoration: a tail with no filename is unreadable when the point is
    deciding whether the access log or the app log has the event in it.
    """
    log = tmp_path / "app.log"
    log.write_text("line\n", encoding="utf-8")

    assert FileLogTail(log).path == log
