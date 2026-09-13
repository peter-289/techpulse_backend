from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True, kw_only=True)
class DomainEvent:
    """This is the base class for all domain events that might occur in any domain.
       Each event in every domain should inherit from this base class if it publishes events of any sort.

       A domain event represents an immutable business fact that has already occurred inside an aggregate.

       Responsibilities:
          - Provide a globally unique event identifier.
          - Record when the event occurred.
          - Identify the aggregate that raised the event.
        
       Notes:
          - Domain events contain no business logic.
          - Domain events never dispatch themselves.
          - Infrastructure is responsible for publishing them.
    """
    aggregate_id: UUID
    event_id: UUID = field(default_factory=uuid4)
    actor_id: UUID | None = None

    occured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def event_type(self) -> str:
        """Return logical event type."""
        return self.__class__.__name__
