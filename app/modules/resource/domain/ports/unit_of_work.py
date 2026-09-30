"""The resource context's Unit of Work port.

See ``app/modules/shared/unit_of_work.py`` and ``docs/adr/0001``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.modules.resource.domain.ports.repositories.resource_repository import (
    ResourceRepository,
)
from app.modules.shared.unit_of_work import UnitOfWorkPort


@runtime_checkable
class ResourceUnitOfWork(UnitOfWorkPort, Protocol):
    """Transaction boundary for the resource context."""

    @property
    def resource_repo(self) -> ResourceRepository:
        """Aggregate repository for the Resource aggregate."""
        ...
