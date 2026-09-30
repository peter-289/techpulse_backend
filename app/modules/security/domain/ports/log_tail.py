"""Reading the tail of a log file, as a capability.

The operator log endpoint used to open the file itself. It was a handler in
``app/modules/user/api/router/admin_router.py`` that built a ``Path`` from
``settings.LOG_FILE_PATH``, read the last N lines with ``collections.deque``,
ran three regexes over them and returned the result -- repository-shaped work,
configuration lookup and redaction policy, in a transport-layer function, behind
a route guard.

R8 already holds application services to the same standard: it forbids the
framework, the ORM and the filesystem in a ``*_service.py``, on the grounds that
file I/O inside a transaction boundary cannot be rolled back and is not the
use-case's business. A router has no equivalent rule, so the same reasoning
simply went unchecked here.

So the capability is declared, and the interesting part is the contract rather
than the mechanism: what comes back is *safe to hand to a browser*. A log tail
contains whatever was logged, and a bearer token or a password in it would be
returned verbatim to whoever opened the page. Redaction is therefore part of
implementing this port, not a nicety an adapter may or may not do -- which is
why the port says "lines with credentials removed" and the adapter is the only
place the patterns are defined.

The file path is adapter configuration rather than a parameter. The only caller
wants the application's own log and has no opinion about where it lives, so
asking it would mean passing ``settings`` a path it does not own; the adapter is
constructed with the resolved path at the composition root, the same way
``LocalStorage`` is constructed with its settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class LogTail(Protocol):
    """The last few lines of the application's log, safe to return over HTTP."""

    @property
    def path(self) -> Path:
        """The file this capability reads.

        Part of the port because the endpoint's response names the file it
        tailed, and that name has to come from the same place the lines did --
        otherwise the response could report one file while serving another.
        """
        ...

    async def tail(self, *, lines: int) -> list[str]:
        """Return at most the last ``lines`` log lines, oldest first.

        Returns an empty list when the log does not exist. A missing log is a
        normal state -- the file is created by the logging setup, and an
        operator asking for a tail before the first line is written should get
        an empty page, not a 500.

        Credentials are removed. Implementations must not return a line
        containing a bearer token, a password or a refresh/access token, because
        the only caller of this capability renders the result to a browser.
        """
        ...
