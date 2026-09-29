"""Logging adapter for domain event dispatch.

The software_management context now records its events and dispatches them
after commit, which means the events are real rather than constructed and
dropped. Nothing consumes them yet, so this adapter logs them. It is the
delivery seam a queue, webhook, or notification fan-out would be added behind,
and it is the place to look first when wiring one: the port already says what
delivery has to guarantee.
"""

from __future__ import annotations

import logging
from typing import Sequence

from app.modules.shared.events import DomainEvent

logger = logging.getLogger(__name__)

__all__ = ["LoggingDomainEventPublisher"]


class LoggingDomainEventPublisher:
    """Writes each dispatched event to the log.

    Never raises, per the port's contract: a logging backend that fails must
    not be able to fail the business operation whose events it is reporting on.
    """

    def __init__(self, *, logger_: logging.Logger | None = None) -> None:
        self._logger = logger_ or logger

    async def publish(self, events: Sequence[DomainEvent]) -> None:
        for event in events:
            self._logger.info(
                "domain_event event_type=%s aggregate_id=%s event_id=%s",
                event.event_type,
                event.aggregate_id,
                event.event_id,
            )
