from __future__ import annotations

from software_management.application.interfaces import EventPublisher


class NoOpEventPublisher(EventPublisher):
    async def publish(self, event: object) -> None:
        return None

    async def publish_many(self, events: list[object]) -> None:
        return None
