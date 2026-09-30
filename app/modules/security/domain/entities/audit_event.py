"""The audit trail's domain entity.

An ``AuditEvent`` is an immutable fact: a request happened, and this is what was
known about it at the time. It has no lifecycle and nothing mutates it after it
is recorded, so it is an entity rather than an aggregate root -- it has an
identity (the row id, so an alert can point back at the event that raised it)
but no behaviour of its own.

What the entity does own is the *validity* of a fact, which used to be
unexpressed. The service truncated ``path`` to 500 characters while the column
is ``varchar(255)``, so a request with a long path raised a database error
instead of being recorded. Truncating at a fixed length is a storage concern and
belongs to the mapper; what the domain can say is that the event must describe
something real.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.modules.security.domain.exceptions import AuditEventInvalidError


def utc_now() -> datetime:
    """Return the current time in UTC as a timezone-aware value."""
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    """Coerce a naive datetime to UTC and normalize aware ones to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(slots=True)
class AuditEvent:
    """A recorded request fact.

    ``id`` is ``None`` until the repository persists the event: the column is an
    autoincrement, so the identifier is only known after the insert. A
    ``SecurityAlert`` references it, which is why ``save_event`` returns the
    persisted entity rather than ``None``.
    """

    event_type: str
    method: str
    path: str
    status_code: int
    actor_user_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    metadata: dict[str, Any] | None = None
    occurred_at: datetime = field(default_factory=utc_now)
    id: int | None = None

    def __post_init__(self) -> None:
        self.occurred_at = _ensure_utc(self.occurred_at)
        self.method = self.method.strip().upper()
        self.path = self.path.strip()
        self.event_type = self.event_type.strip()
        self._validate()

    def _validate(self) -> None:
        """Reject a record that could not describe a request.

        A blank ``event_type`` or ``path`` is not a fact worth auditing: it is
        a bug in the caller, and storing it silently makes the trail useless for
        the investigation it exists to support.
        """
        if not self.event_type:
            raise AuditEventInvalidError("Audit event type is required.")
        if not self.path:
            raise AuditEventInvalidError("Audit event path is required.")
        if not self.method:
            raise AuditEventInvalidError("Audit event method is required.")
        if not 100 <= self.status_code <= 599:
            raise AuditEventInvalidError(
                f"Audit event status code out of range: {self.status_code}."
            )

    @classmethod
    def create(
        cls,
        *,
        event_type: str,
        method: str,
        path: str,
        status_code: int,
        actor_user_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> "AuditEvent":
        """Record a request fact.

        Named ``create`` rather than left to the constructor because every
        caller of the audit trail is recording a fact that is happening now;
        ``occurred_at`` exists for the repository's read path and for tests.
        """
        return cls(
            event_type=event_type,
            method=method,
            path=path,
            status_code=status_code,
            actor_user_id=actor_user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata=metadata or {},
            occurred_at=occurred_at or utc_now(),
        )

    def is_from(self, *, actor_user_id: str | None, ip_address: str | None) -> bool:
        """Whether this event came from the same actor and address.

        Used to decide what history a detection rule should count. ``None`` on
        either side means "no constraint" rather than "matches nothing", which
        is how the queries this replaces treated a missing value.
        """
        if actor_user_id is not None and self.actor_user_id != actor_user_id:
            return False
        if ip_address is not None and self.ip_address != ip_address:
            return False
        return True
