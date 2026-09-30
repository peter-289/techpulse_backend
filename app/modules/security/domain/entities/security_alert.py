"""The security alert aggregate root.

A ``SecurityAlert`` is the actionable half of the security context: the audit
trail records what happened, an alert says it is worth a human's attention. It
is an aggregate root rather than part of ``AuditEvent`` because it has its own
lifecycle -- raised once, acknowledged once, on a timescale unrelated to the
request that produced it -- and because acknowledging one must never require
loading the events that led to it.

No domain events are recorded here yet. ``AggregateRoot`` would give the class
a queue to fill, but this context has no ``DomainEventPublisher`` wired, so
every recorded event would be exactly the construct-and-drop pattern Phase 3
removed from the upload path. The base class arrives with the publisher.

``id`` is ``None`` until persisted: the column is an autoincrement. It points at
the ``AuditEvent`` that triggered it, which is why ``raise_alert`` refuses to
build an alert without one and why the repository returns the saved entity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.modules.shared.enums import AlertRuleCode, AlertSeverity
from app.modules.security.domain.exceptions import AlertAlreadyAcknowledgedError


def utc_now() -> datetime:
    """Return the current time in UTC as a timezone-aware value."""
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    """Coerce a naive datetime to UTC and normalize aware ones to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(slots=True)
class SecurityAlert:
    """An open or acknowledged finding from the detection rules."""

    rule_code: AlertRuleCode
    severity: AlertSeverity
    title: str
    description: str
    audit_event_id: int
    actor_user_id: str | None = None
    ip_address: str | None = None

    acknowledged: bool = False
    acknowledged_at: datetime | None = None
    acknowledged_by_user_id: str | None = None

    created_at: datetime = field(default_factory=utc_now)
    id: int | None = None

    def __post_init__(self) -> None:
        self.created_at = _ensure_utc(self.created_at)
        if self.acknowledged_at is not None:
            self.acknowledged_at = _ensure_utc(self.acknowledged_at)
        if self.acknowledged and self.acknowledged_at is None:
            # An acknowledged alert with no timestamp cannot be ordered against
            # other alerts, which is the first thing a triage list does.
            self.acknowledged_at = self.created_at

    # ─── Factories ───
    @classmethod
    def raise_alert(
        cls,
        *,
        rule_code: AlertRuleCode,
        severity: AlertSeverity,
        title: str,
        description: str,
        audit_event_id: int,
        actor_user_id: str | None = None,
        ip_address: str | None = None,
        raised_at: datetime | None = None,
    ) -> "SecurityAlert":
        """Raise a new, unacknowledged alert.

        Named ``raise_alert`` rather than ``create`` because an alert is a
        response to a rule firing, not something a user asks for.
        """
        return cls(
            rule_code=rule_code,
            severity=severity,
            title=title,
            description=description,
            audit_event_id=audit_event_id,
            actor_user_id=actor_user_id,
            ip_address=ip_address,
            created_at=raised_at or utc_now(),
        )

    # ─── Behaviour ───
    def acknowledge(self, *, acknowledged_by_user_id: str) -> None:
        """Take responsibility for this alert.

        Raises:
            AlertAlreadyAcknowledgedError: If the alert was already
                acknowledged. Returning quietly would lose the fact that a
                second operator opened it, which is what an incident review
                asks for.
        """
        if self.acknowledged:
            raise AlertAlreadyAcknowledgedError(
                f"Alert {self.rule_code} was already acknowledged."
            )
        self.acknowledged = True
        self.acknowledged_at = utc_now()
        self.acknowledged_by_user_id = acknowledged_by_user_id

    # ─── Queries ───
    def is_acknowledged(self) -> bool:
        """Whether a human has taken responsibility for this alert."""
        return self.acknowledged
