"""The software_management context's Unit of Work port.

Declares only the repositories this bounded context owns. A service in
software_management cannot reach the user, resource or security tables through
this port, which is what makes the context extractable.

See ``app/modules/shared/unit_of_work.py`` for the shared contract and
``docs/adr/0001`` for why each context gets its own port.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.modules.shared.unit_of_work import UnitOfWorkPort
from app.modules.software_management.domain.ports.repositories.category_repository import (
    ICategoryRepository,
)
from app.modules.software_management.domain.ports.repositories.software_repository import (
    ISoftwareRepository,
)


@runtime_checkable
class SoftwareManagementUnitOfWork(UnitOfWorkPort, Protocol):
    """Transaction boundary for the software_management context."""

    @property
    def software_repo(self) -> ISoftwareRepository:
        """Aggregate repository for Software, the aggregate root."""
        ...

    @property
    def category_repo(self) -> ICategoryRepository:
        """Aggregate repository for Category, its own aggregate root.

        Deliberately *not* exposed: ``Artifact`` has no independent lifecycle.
        It is persisted through ``software_repo.save`` as part of the Software
        aggregate, so there is no artifact repository to hand out.
        """
        ...
