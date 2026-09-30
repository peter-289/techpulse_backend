"""Detection thresholds as an injected value object.

The four numbers that decide when the security context raises an alert were read
from ``app.core.config.settings`` inside the application service, which made them
ambient: unreachable from a test, unchangeable without mutating a global, and
undiscoverable from the code that enforces them. They are now built once at the
composition root and injected, so a test can say "fail after 2 attempts in 1
minute" instead of monkeypatching a settings object.

Placed in ``domain/ports/`` rather than ``domain/value_objects/`` because the
composition root may only reach another context's ports
(``tests/architecture/layer_rules.py``, rule R2). It is configuration handed to a
use case rather than a concept the domain reasons about, so the ports package is
where it belongs anyway -- and it is the same placement ``UploadLimits`` was
given in Phase 3 for the same reason.

The validation exists because these are the values that stand between a real
attack and a silent one. A threshold of 0 would fire on every audited request; a
negative lookback would count the future and never fire; a zero-length window
would deduplicate every alert against itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True, slots=True)
class AlertThresholds:
    """How much suspicious activity is tolerated before an alert is raised.

    ``login_failures`` and ``access_denied`` are counts within ``lookback``.
    ``dedup`` is how long an unacknowledged alert for the same rule and subject
    suppresses a repeat, so a sustained attack produces one alert an operator
    can act on rather than one per request.
    """

    login_failures: int
    access_denied: int
    lookback: timedelta
    dedup: timedelta

    def __post_init__(self) -> None:
        if self.login_failures < 1:
            raise ValueError(
                f"login_failures must be at least 1, got {self.login_failures}."
            )
        if self.access_denied < 1:
            raise ValueError(
                f"access_denied must be at least 1, got {self.access_denied}."
            )
        if self.lookback <= timedelta(0):
            raise ValueError(f"lookback must be positive, got {self.lookback}.")
        if self.dedup <= timedelta(0):
            raise ValueError(f"dedup must be positive, got {self.dedup}.")

    @property
    def lookback_minutes(self) -> int:
        """The lookback in whole minutes, as the alert descriptions read it."""
        return int(self.lookback.total_seconds() // 60)
