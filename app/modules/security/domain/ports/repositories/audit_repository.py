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

Phase 8 added the operator read path to this port, which is where the
"no ``get_alert``" note above stops being true. It was written when the trail
was write-only: nothing read the audit trail at all, because the two endpoints
that wanted to went around the port and issued their own SQL. They are
``get_alert``, ``list_alerts`` and ``list_events`` below, phrased in the same
domain terms as the counting methods -- a rule code, a set of event types, an
actor, a page size -- so a caller still cannot express a query it has not
described in words. The generic predicate list stays excluded: that is the
leak this port was rewritten to remove, and re-admitting it in the name of
convenience would put it back.
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
        """Persist a security alert and return it with its assigned id.

        Inserts when ``alert.id`` is ``None`` and updates an existing row when
        it is set, so acknowledging an alert is a tracked write through the same
        call the raise path uses. The entity it returns is the one the database
        holds, not the one passed in: an update is merged, and the merged row is
        what knows its stored values.
        """
        ...

    async def get_alert(self, alert_id: int) -> SecurityAlert | None:
        """One alert by identity, or ``None`` if there is no such alert.

        ``None`` rather than an exception because "no such alert" is an ordinary
        answer to an operator's question, and the caller decides what it means
        for its endpoint.
        """
        ...

    async def list_alerts(
        self, *, only_unacknowledged: bool = False, limit: int
    ) -> list[SecurityAlert]:
        """Alerts newest first, at most ``limit`` of them.

        A triage list is ordered by ``created_at`` descending and truncated, not
        paged. The two admin endpoints that read alerts are for looking at what
        has just fired, and a cursor would be a second parameter the caller has
        to thread through for no reader who has reached the end of a 100-row
        page.
        """
        ...

    async def list_events(
        self,
        *,
        event_types: tuple[str, ...] | None = None,
        actor_user_id: str | None = None,
        limit: int,
    ) -> list[AuditEvent]:
        """Audit events newest first, at most ``limit`` of them.

        ``event_types`` is a set rather than a single type because one of the
        callers is not asking about a type but about a category -- everything
        the client reports about consent and activity -- and expressing that as
        a caller's own ``IN`` clause is how the predicate list this port
        deliberately omits would come back through the front door.

        ``None`` places no constraint on the type; an empty tuple would match
        nothing, and is the caller's error rather than a query.
        """
        ...
