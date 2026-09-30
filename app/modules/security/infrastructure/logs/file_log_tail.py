"""Filesystem implementation of the log-tail capability.

Reads the tail of one file and redacts it. Lives in this context's
``infrastructure`` because that is where ADR 0001 puts an adapter: it depends on
a capability this context declares, and the module it is wired into imports
nothing from the domain beyond the port.

Why redaction is here and not in the port's caller: the port's contract is that
what comes back is safe to send to a browser, and an implementation that
returned raw lines would satisfy the signature while breaking the promise. The
patterns are private to this module, so there is exactly one definition of
"a credential" in the codebase for this purpose.

The read is synchronous and bounded -- ``deque`` with ``maxlen`` holds at most
``lines`` entries, so memory does not scale with the file -- and it runs on a
worker thread because a multi-hundred-megabyte log on a slow disk would block
the event loop otherwise. The operator endpoint is the only caller and it is
already a ``def``-free async handler, so the hop is worth it.
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from pathlib import Path

_REDACTED = "[REDACTED]"

#: A credential value: a quoted string, or a run of characters up to the next
#: delimiter. The quoted alternative exists so that a JSON log line loses its
#: value but stays parseable; the bare alternative is the ``key=value`` shape the
#: project's own formatter produces. Quoting is handled *here* rather than in the
#: key group -- if the key group ate the opening quote, the quoted alternative
#: could never match and the closing quote would have nowhere to come from.
_VALUE = r"""(?:"[^"]*"|'[^']*'|[^\s,;}\]&]+)"""

#: Key names that introduce a credential. A stem, optionally qualified on either
#: side, with one deliberate asymmetry:
#:
#: * ``token`` accepts a prefix with or without a separator, so ``access_token``
#:   and camelCase ``refreshToken`` both match.
#: * ``key`` and ``secret`` require a separator, because a prefix-free ``key``
#:   would match inside ``monkey`` and ``keyhole``.
#:
#: Every branch is anchored with ``\b`` afterwards, so ``tokenizer`` is left
#: alone. Over-redacting a field named ``key`` is acceptable; redacting half the
#: words in a log line is not.
_KEY = (
    r"""(?:[A-Za-z0-9_-]*)?token"""
    r"""|(?:[A-Za-z0-9]*[_-])?key"""
    r"""|(?:[A-Za-z0-9]*[_-])?secret"""
    r"""|(?:[A-Za-z0-9]*[_-])?pass(?:word|wd|phrase)"""
    r"""|apikey"""
)

#: A credential behind an ``Authorization`` header. Separate from the pattern
#: above because the value there is a bare token, not a delimited field -- and
#: ``Basic`` is here for the same reason as ``Bearer``: the header is the most
#: common place a live credential reaches a log line at all.
_AUTH_SCHEME_RE = re.compile(
    r"((?:bearer|basic)\s+)[A-Za-z0-9\-\._~\+\/]+=*", flags=re.IGNORECASE
)
_CREDENTIAL_RE = re.compile(
    rf"""(?P<head>\b(?:{_KEY})(?:[-_](?:key|token|secret))?\b['"]?\s*[:=]\s*)"""
    rf"(?P<value>{_VALUE})",
    flags=re.IGNORECASE,
)


def _redact(match: re.Match[str]) -> str:
    """Swap the value, re-emitting the quotes that were removed with it.

    Both quotes come back when the original had them, which is what keeps a JSON
    log line valid: ``{"password": "[REDACTED]"}`` is still a document, whereas
    dropping the value's opening quote would leave a bare ``[REDACTED]`` in a
    string position and break any parser reading the file after this one.
    """
    value = match.group("value")
    quote = value[0] if value[:1] in ('"', "'") else ""
    return f"{match.group('head')}{quote}{_REDACTED}{quote}"


def sanitize(line: str) -> str:
    """Replace credential values in one log line, keeping the rest readable.

    The key is always kept, so an operator reading the line can still tell
    *that* a credential was present, which is usually the point of looking.

    Exposed for the tests that assert each pattern independently, which is the
    only reason it is not a nested function: a redaction bug is silent and
    invisible, and the cheap defence is one test per pattern rather than one test
    per combined log line.
    """
    line = _AUTH_SCHEME_RE.sub(rf"\1{_REDACTED}", line)
    return _CREDENTIAL_RE.sub(_redact, line)


class FileLogTail:
    """Tail one log file on disk.

    Args:
        path: The file to read. Resolved by the composition root from settings;
            this class does not read the environment, so a test can point it at
            a temporary file.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        """The file this instance tails, for the endpoint to report back."""
        return self._path

    async def tail(self, *, lines: int) -> list[str]:
        """The last ``lines`` entries of the log, oldest first, redacted."""
        return await asyncio.to_thread(self._read_tail, lines)

    def _read_tail(self, lines: int) -> list[str]:
        """Read and redact synchronously, on a worker thread.

        A missing file yields an empty list rather than an error: the log is
        created by the logging setup, and "the operator asked before anything was
        written" is not a failure.
        """
        if not self._path.exists():
            return []
        with self._path.open("r", encoding="utf-8", errors="replace") as handle:
            recent = deque(handle, maxlen=lines)
        return [sanitize(entry.rstrip("\r\n")) for entry in recent]
