from typing import Protocol, runtime_checkable
from uuid import UUID

from app.modules.software_management.domain.entities.category import Category


@runtime_checkable
class ICategoryRepository(Protocol):
    """Repository interface for categories.

    The repository owns persistence only. It never commits or rolls back;
    the UnitOfWork owns the transaction lifecycle.
    """

    async def save(self, category: Category) -> Category:
        """Persist (insert or update) a category and return the entity."""

    async def get(self, category_id: UUID) -> Category | None:
        """Return a single category by id, or ``None`` if absent."""

    async def find_by_name(self, name: str) -> Category | None:
        """Resolve a single category by its (case-insensitive) name.

        The match is performed case-insensitively so that ``"Developer Tools"``
        and ``"developer tools"`` resolve to the same record. Returns ``None``
        when no category matches.
        """

    async def list_categories(
        self,
        *,
        limit: int,
        offset: int,
        include_deleted: bool = False,
    ) -> tuple[list[Category], int]:
        """Return a paginated page of categories and the total count."""

    async def exists(self, name: str) -> bool:
        """Case-insensitive duplicate check."""

    async def rename(self, category_id: UUID, name: str) -> None:
        """Persist a rename for the given category."""

    async def soft_delete(self, category_id: UUID) -> None:
        """Mark a category as deleted (soft delete)."""

    async def restore(self, category_id: UUID) -> None:
        """Restore a previously soft-deleted category."""

    async def count_software(self, category_id: UUID) -> int:
        """Return the number of software assigned to the category."""
