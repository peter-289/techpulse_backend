from typing import Protocol, runtime_checkable
from uuid import UUID

from app.modules.software_management.domain.events import SoftwareEvent


@runtime_checkable
class NotificationSender(Protocol):
    """Port for notification delivery adapters."""

    async def send(
        self,
        *,
        recipient_id: UUID,
        event: SoftwareEvent,
        channels: list[str],
    ) -> None:
        """Deliver a domain event to the specified recipient via channels."""
        ...
