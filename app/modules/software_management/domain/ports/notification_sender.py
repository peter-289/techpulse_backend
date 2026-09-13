from typing import Protocol, runtime_checkable
from uuid import UUID

from app.modules.software_management.domain.events.events import SoftwareDomainEvent


@runtime_checkable
class NotificationSender(Protocol):
    """Port for notification delivery adapters."""

    async def send(
        self,
        *,
        recipient_id: UUID,
        event: SoftwareDomainEvent,
        channels: list[str],
    ) -> None:
        """Deliver a domain event to the specified recipient via channels."""
        ...
