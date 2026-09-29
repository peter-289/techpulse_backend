"""The resource context's Unit of Work port.

See ``app/modules/shared/unit_of_work.py`` and ``docs/adr/0001``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.modules.shared.unit_of_work import UnitOfWorkPort


@runtime_checkable
class ResourceUnitOfWork(UnitOfWorkPort, Protocol):
    """Transaction boundary for the resource context."""

    @property
    def resource_repo(self) -> object:
        """Aggregate repository for the Resource aggregate.

        ``object`` until Phase 5 introduces the domain model; the concrete
        repository currently returns ``infrastructure.database.models.Resource``
        ORM rows.
        """
        ...
