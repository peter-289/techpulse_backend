from __future__ import annotations

from typing import List, Final
from abc import ABC
from app.modules.shared.events import DomainEvent
from dataclasses import dataclass, field

@dataclass
class AggregateRoot(ABC):
    """ Base class for all aggregate roots.
        
        Responsibilities:
           - Collect domain events raised by the aggregate.
           - Expose pending events to the `UnitOfWork`.
           - Never dispatch events.

        Notes:
           - Events are recorded as business facts occur.
           - The `UnitOfWork` is responsible for pulling and dispatching them after a successful transaction commit.
    """

    _events: List[DomainEvent] = field(default_factory=list, init=False, repr=False)

    def _record_event(self, event: DomainEvent) -> None:
        """Record a new domain event."""
        self._events.append(event)

    def pull_events(self) -> list[DomainEvent]:
        """Return and clear pending domain events."""

        events = self._events.copy()
        self._events.clear()
        return events

    def has_events(self) -> bool:
        """Return whether pending events exists."""
        return bool(self._events)

    @property
    def pending_events(self) -> tuple[DomainEvent, ...]:
        """Return a read-only snapshot of pending events."""
        return tuple(self._events)



  
