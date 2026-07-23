from __future__ import annotations

from uuid import UUID
from datetime import datetime, timezone

import logging
from sqlalchemy import func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.category import CategoryModel
from app.infrastructure.database.models.software import SoftwareModel
from app.modules.software_management.domain.entities.category import Category
from app.modules.software_management.domain.exceptions import (
    CategoryNotFoundError,
    CategoryRepositoryUnavailableError,
)
from app.modules.software_management.domain.ports.repositories.category_repository import ICategoryRepository


logger = logging.getLogger(__name__)


def _category_to_model(category: Category) -> CategoryModel:
    """Map a domain ``Category`` to a persistence ``CategoryModel``."""
    return CategoryModel(
        id=category.id,
        slug=category.name.lower().replace(" ", "-"),
        name=category.name,
        description=category.description,
        created_at=category.created_at,
        updated_at=category.updated_at,
        deleted_at=category.deleted_at,
    )


def _category_to_entity(model: CategoryModel) -> Category:
    """Map a persistence ``CategoryModel`` to a domain ``Category``.

    Never let SQLAlchemy model types leak outside the repository boundary.
    """
    return Category(
        id=model.id,
        name=model.name,
        description=model.description,
        created_at=model.created_at,
        updated_at=model.updated_at,
        deleted_at=model.deleted_at,
    )


class CategoryRepository(ICategoryRepository):
    """SQLAlchemy 2.0 async implementation of :class:`ICategoryRepository`."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def save(self, category: Category) -> Category:
        """Persist (insert or update) a category and return the entity.

        Stages the change via ``merge`` + ``flush``; the caller (UnitOfWork)
        commits. Never commits or rolls back here.
        """
        try:
            model = _category_to_model(category)
            merged = await self.session.merge(model)
            await self.session.flush()
            await self.session.refresh(merged)
            return _category_to_entity(merged)
        except SQLAlchemyError as exc:
            logger.error("Failed to persist category %s: %s", category.id, exc, exc_info=False)
            raise CategoryRepositoryUnavailableError("Failed to persist category.") from exc

    async def get(self, category_id: UUID) -> Category | None:
        """Return a single category by id, or ``None`` if absent."""
        try:
            stmt = select(CategoryModel).where(CategoryModel.id == category_id)
            model = await self.session.scalar(stmt)
            return _category_to_entity(model) if model is not None else None
        except SQLAlchemyError as exc:
            logger.error("Failed to get category %s: %s", category_id, exc, exc_info=False)
            raise CategoryRepositoryUnavailableError("Failed to retrieve category.") from exc

    async def find_by_name(self, name: str) -> Category | None:
        """Resolve a single category by its (case-insensitive) name.

        Delegates to a case-insensitive equality filter on ``CategoryModel.name``.
        Returns the mapped domain entity, or ``None`` when no category matches.
        The UnitOfWork owns the surrounding transaction; this method only reads.
        """
        try:
            stmt = select(CategoryModel).where(
                func.lower(CategoryModel.name) == (name or "").strip().lower()
            )
            model = await self.session.scalar(stmt)
            return _category_to_entity(model) if model is not None else None
        except SQLAlchemyError as exc:
            logger.error("Failed to find category by name: %s", exc, exc_info=False)
            raise CategoryRepositoryUnavailableError("Failed to find category by name.") from exc

    async def list_categories(
        self,
        *,
        limit: int,
        offset: int,
        include_deleted: bool = False,
    ) -> tuple[list[Category], int]:
        """Return a paginated page of categories and the total count."""
        try:
            where = [] if include_deleted else [CategoryModel.deleted_at.is_(None)]

            total = await self.session.scalar(
                select(func.count()).select_from(CategoryModel).where(*where)
            ) or 0

            stmt = (
                select(CategoryModel)
                .where(*where)
                .order_by(CategoryModel.sort_order.asc(), CategoryModel.name.asc())
                .limit(limit)
                .offset(offset)
            )
            result = await self.session.scalars(stmt)
            items = [_category_to_entity(m) for m in result.all()]
            return items, total
        except SQLAlchemyError as exc:
            logger.error("Failed to list categories: %s", exc, exc_info=False)
            raise CategoryRepositoryUnavailableError("Failed to list categories.") from exc

    async def exists(self, name: str) -> bool:
        """Case-insensitive duplicate check."""
        try:
            stmt = select(
                select(CategoryModel.id)
                .where(func.lower(CategoryModel.name) == (name or "").strip().lower())
                .exists()
            )
            return bool(await self.session.scalar(stmt))
        except SQLAlchemyError as exc:
            logger.error("Failed to check category existence: %s", exc, exc_info=False)
            raise CategoryRepositoryUnavailableError("Failed to check category existence.") from exc

    async def rename(self, category_id: UUID, name: str) -> None:
        """Persist a rename for the given category.

        Raises:
            CategoryNotFoundError: If the category does not exist.
        """
        try:
            stmt = (
                update(CategoryModel)
                .where(CategoryModel.id == category_id)
                .values(
                    name=name,
                    slug=name.lower().replace(" ", "-"),
                    updated_at=datetime.now(timezone.utc),
                )
            )
            result = await self.session.execute(stmt)
            await self.session.flush()
        except SQLAlchemyError as exc:
            logger.error("Failed to rename category %s: %s", category_id, exc, exc_info=False)
            raise CategoryRepositoryUnavailableError("Failed to rename category.") from exc

        if result.rowcount == 0:
            raise CategoryNotFoundError(f"Category {category_id} not found.")

    async def soft_delete(self, category_id: UUID) -> None:
        """Mark a category as deleted (soft delete).

        Raises:
            CategoryNotFoundError: If the category does not exist.
        """
        try:
            stmt = (
                update(CategoryModel)
                .where(CategoryModel.id == category_id, CategoryModel.deleted_at.is_(None))
                .values(
                    deleted_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
            )
            result = await self.session.execute(stmt)
            await self.session.flush()
        except SQLAlchemyError as exc:
            logger.error("Failed to soft delete category %s: %s", category_id, exc, exc_info=False)
            raise CategoryRepositoryUnavailableError("Failed to delete category.") from exc

        if result.rowcount == 0:
            raise CategoryNotFoundError(f"Category {category_id} not found.")

    async def restore(self, category_id: UUID) -> None:
        """Restore a previously soft-deleted category.

        Raises:
            CategoryNotFoundError: If the category does not exist.
        """
        try:
            stmt = (
                update(CategoryModel)
                .where(CategoryModel.id == category_id, CategoryModel.deleted_at.isnot(None))
                .values(
                    deleted_at=None,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            result = await self.session.execute(stmt)
            await self.session.flush()
        except SQLAlchemyError as exc:
            logger.error("Failed to restore category %s: %s", category_id, exc, exc_info=False)
            raise CategoryRepositoryUnavailableError("Failed to restore category.") from exc

        if result.rowcount == 0:
            raise CategoryNotFoundError(f"Category {category_id} not found or not deleted.")

    async def count_software(self, category_id: UUID) -> int:
        """Return the number of software assigned to the category."""
        try:
            stmt = (
                select(func.count())
                .select_from(SoftwareModel)
                .where(SoftwareModel.category_id == category_id)
            )
            return await self.session.scalar(stmt) or 0
        except SQLAlchemyError as exc:
            logger.error("Failed to count software for category %s: %s", category_id, exc, exc_info=False)
            raise CategoryRepositoryUnavailableError("Failed to count software for category.") from exc
