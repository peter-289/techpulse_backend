from __future__ import annotations

from uuid import UUID

import logging

from app.modules.software_management.domain.entities.category import Category
from app.modules.software_management.domain.exceptions import (
    CategoryInUseError,
    CategoryNotFoundError,
    DuplicateCategoryError,
)
from app.modules.software_management.domain.ports.repositories.category_repository import ICategoryRepository
from app.infrastructure.database.unit_of_work import UnitOfWork


logger = logging.getLogger(__name__)


class CategoryService:
    """Application service coordinating the category use cases.

    Coordinates the :class:`UnitOfWork` and :class:`ICategoryRepository`.
    Contains no HTTP concerns and never exposes SQLAlchemy models.
    """

    def __init__(self, unit_of_work: UnitOfWork) -> None:
        self._uow = unit_of_work

    @property
    def _repo(self) -> ICategoryRepository:
        return self._uow.category_repo

    async def create(
        self,
        *,
        name: str,
        description: str | None,
    ) -> Category:
        """Create a new category.

        Responsibilities:
        * trim whitespace and normalize the name
        * prevent duplicate (case-insensitive) names
        * create the aggregate and persist it

        Raises:
            DuplicateCategoryError: If a category with the same name exists.
        """
        name = " ".join(name.strip().split())
        if not name:
            raise DuplicateCategoryError("Category name is required.")

        async with self._uow.read_only():
            if await self._repo.exists(name):
                logger.warning("Duplicate category creation attempted: name=%s", name)
                raise DuplicateCategoryError(f"A category named '{name}' already exists.")

        category = Category.create(name=name, description=description)
        async with self._uow:
            saved = await self._repo.save(category)
            logger.info("Category created: id=%s admin_actor=service", saved.id)
            return saved

    async def rename(
        self,
        *,
        category_id: UUID,
        name: str,
    ) -> Category:
        """Rename a category.

        Raises:
            CategoryNotFoundError: If the category does not exist.
            DuplicateCategoryError: If the new name collides with another category.
        """
        name = " ".join(name.strip().split())
        if not name:
            raise DuplicateCategoryError("Category name is required.")

        async with self._uow.read_only():
            category = await self._repo.get(category_id)
            if category is None:
                raise CategoryNotFoundError(f"Category {category_id} not found.")
            if category.name.lower() != name.lower() and await self._repo.exists(name):
                raise DuplicateCategoryError(f"A category named '{name}' already exists.")

        category.rename(name)
        async with self._uow:
            await self._repo.rename(category.id, name)
            logger.info("Category renamed: id=%s", category_id)
            return category

    async def update_description(
        self,
        *,
        category_id: UUID,
        description: str | None,
    ) -> Category:
        """Update a category description.

        Raises:
            CategoryNotFoundError: If the category does not exist.
        """
        async with self._uow.read_only():
            category = await self._repo.get(category_id)
            if category is None:
                raise CategoryNotFoundError(f"Category {category_id} not found.")

        category.update_description(description)
        async with self._uow:
            await self._repo.save(category)
            logger.info("Category description updated: id=%s", category_id)
            return category

    async def delete(self, category_id: UUID) -> None:
        """Soft-delete a category.

        Deletion is prevented while software is still assigned to the category.

        Raises:
            CategoryNotFoundError: If the category does not exist.
            CategoryInUseError: If software is still assigned to the category.
        """
        async with self._uow.read_only():
            category = await self._repo.get(category_id)
            if category is None:
                raise CategoryNotFoundError(f"Category {category_id} not found.")
            assigned = await self._repo.count_software(category_id)

        if assigned > 0:
            logger.warning(
                "Category delete blocked (in use): id=%s assigned=%s",
                category_id,
                assigned,
            )
            raise CategoryInUseError(
                f"Category {category_id} is assigned to {assigned} software item(s); "
                "reassign or remove them before deletion."
            )

        async with self._uow:
            await self._repo.soft_delete(category_id)
            logger.info("Category deleted: id=%s", category_id)

    async def restore(self, category_id: UUID) -> Category:
        """Restore a previously soft-deleted category.

        Raises:
            CategoryNotFoundError: If the category does not exist or is not deleted.
        """
        async with self._uow.read_only():
            category = await self._repo.get(category_id)
            if category is None:
                raise CategoryNotFoundError(f"Category {category_id} not found.")

        category.restore()
        async with self._uow:
            await self._repo.restore(category_id)
            logger.info("Category restored: id=%s", category_id)
            return category

    async def get(self, category_id: UUID) -> Category:
        """Return a single category.

        Raises:
            CategoryNotFoundError: If the category does not exist.
        """
        async with self._uow.read_only():
            category = await self._repo.get(category_id)
            if category is None:
                raise CategoryNotFoundError(f"Category {category_id} not found.")
            return category

    async def find_by_name(self, name: str) -> Category:
        """Return a single category by its (case-insensitive) name.

        This is the canonical way to resolve a category from a human-facing
        name (e.g. when a client only knows the display name rather than the
        UUID). The lookup is case-insensitive to match the repository's
        duplicate-detection semantics.

        Args:
            name: The category name to look up. Leading/trailing whitespace is
                trimmed and internal runs of whitespace are collapsed before the
                lookup, mirroring how names are normalized on creation/rename.

        Returns:
            The matching :class:`Category` aggregate.

        Raises:
            CategoryNotFoundError: If no category matches the given name.
        """
        normalized = " ".join(name.strip().split())
        if not normalized:
            raise CategoryNotFoundError("Category name is required.")

        async with self._uow.read_only():
            category = await self._repo.find_by_name(normalized)
            if category is None:
                raise CategoryNotFoundError(f"No category found with name '{normalized}'.")
            return category

    async def list_categories(
        self,
        *,
        limit: int,
        offset: int,
        include_deleted: bool = False,
    ) -> tuple[list[Category], int]:
        """Return a paginated list of categories and the total count."""
        async with self._uow.read_only():
            return await self._repo.list_categories(
                limit=limit,
                offset=offset,
                include_deleted=include_deleted,
            )
