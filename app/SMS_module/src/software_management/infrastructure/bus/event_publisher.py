from __future__ import annotations

from ...application.ports import EventPublisherPort
from ...domain.events import DomainEvent


class InMemoryEventPublisher(EventPublisherPort):
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []

    async def publish(self, events: list[DomainEvent]) -> None:
        self.events.extend(events)
