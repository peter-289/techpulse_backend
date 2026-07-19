from __future__ import annotations

from datetime import datetime
from typing import Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field

from app.modules.shared.pagination import OffsetPage
from app.modules.software_management.category.domain.category import Category


class CategoryCreate(BaseModel):
    """Request body for creating a category."""

    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)


class CategoryUpdate(BaseModel):
    """Request body for renaming and/or updating a category description."""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)


class CategoryResponse(BaseModel):
    """Category representation returned by the API."""

    id: UUID
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None

    @classmethod
    def from_domain(cls, category: Category) -> "CategoryResponse":
        """Build a response model from a domain ``Category``.

        Never construct response dictionaries manually; always use this factory.
        """
        return cls(
            id=category.id,
            name=category.name,
            description=category.description,
            created_at=category.created_at,
            updated_at=category.updated_at,
            deleted_at=category.deleted_at,
        )


T = TypeVar("T")


class CategoryPage(OffsetPage[T], Generic[T]):
    """Typed alias for a paginated page of categories."""
