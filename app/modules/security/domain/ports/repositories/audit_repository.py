"""The audit trail's repository port.

Declared in domain terms rather than as SQLAlchemy constructs. The previous
signature took ``list[ColumnElement[bool]]`` -- the service built
``AuditEvent.event_type == ...`` expressions and handed them over, so the
persistence query shape leaked into the application layer through a port that
was nominally the boundary. Two consequences: ``audit_service`` imported the ORM
models to build the expressions, and the alerting logic could not be exercised
without a database.

The port now says what it needs in words -- an event type, a window, an actor, an
address -- and the repository owns how that becomes a ``WHERE``. This mirrors
Phase 3's rule that a repository translates, and a caller catches the
translation rather than the ORM.

Note what the port does *not* offer: no ``get_alert``, no generic predicate
list, no ORM object in or out. ``save_event`` and ``save_alert`` return the
persisted entity because the audit event's autoincrement id is only known after
the insert, and a ``SecurityAlert`` has to point at it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from app.modules.security.domain.entities.audit_event import AuditEvent
from app.modules.security.domain.entities.security_alert import SecurityAlert


@runtime_checkable
class AuditRepository(Protocol):
    """Persistence for audit events and security alerts."""

    async def save_event(self, event: AuditEvent) -> AuditEvent:
        """Persist a new audit event and return it with its assigned id.

        The id is required by the caller: an alert raised for this event stores
        it as a foreign key.
        """
        ...

    async def count_events(
        self,
        *,
        event_type: str,
        since: datetime,
        actor_user_id: str | None = None,
        ip_address: str | None = None,
    ) -> int:
        """Count audit events of one type within a window.

        ``actor_user_id`` and ``ip_address`` narrow the count only when set. A
        set value must match exactly; an unset one places no constraint, which
        is what lets a single call serve both a per-address rule and a
        per-actor one.
        """
        ...

    async def has_unacknowledged_alert(
        self,
        *,
        rule_code: str,
        since: datetime,
        actor_user_id: str | None = None,
        ip_address: str | None = None,
    ) -> bool:
        """Whether an unacknowledged alert for this rule and subject is in the window.

        The deduplication check behind a single boolean. It answers "has an
        operator already been told about this?" and nothing more: the operator
        who acknowledged it, and when, are on the alert row.
        """
        ...

    async def save_alert(self, alert: SecurityAlert) -> SecurityAlert:
        """Persist a new security alert and return it with its assigned id."""
        ...
