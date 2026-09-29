from __future__ import annotations

from typing import Protocol, Sequence, runtime_checkable

from app.modules.shared.events import DomainEvent


@runtime_checkable
class DomainEventPublisher(Protocol):
    """Outbound port for handing committed domain events to an adapter.

    ARCHITECTURE.md 11.1: the aggregate records, the application service
    dispatches after commit, the adapter delivers. Only the last of those three
    is an infrastructure concern, so only that one is a port.

    Speaks the shared ``DomainEvent`` base rather than a software-specific
    subtype. Delivery does not need to know which context produced an event, and
    an adapter that names the subtype would have to import this context's domain
    model just to satisfy the port.

    Called exclusively after the transaction commits. Dispatching earlier would
    announce facts that a rollback then un-does, and a subscriber that trusted
    the notification would be acting on state that no longer exists.
    """

    async def publish(self, events: Sequence[DomainEvent]) -> None:
        """Deliver committed events.

        Must not raise. A delivery failure is the publisher's problem to retry
        or log; propagating it would report the business operation itself as
        failed, even though its state is already durably committed.
        """
        ...
