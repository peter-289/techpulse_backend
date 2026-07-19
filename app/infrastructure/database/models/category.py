# models/category.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.database.db_setup import Base

if TYPE_CHECKING:
    from app.infrastructure.database.models.software import SoftwareModel

class CategoryModel(Base):
    """Persistence model for software categories.

    Supports soft deletion via ``deleted_at``. Category names are unique
    (case-insensitively enforced by the repository/application layers).
    """

    __tablename__ = "categories"
    __table_args__ = (
        UniqueConstraint("name", name="uq_categories_name"),
    )

    id: Mapped[PGUUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str | None] = mapped_column(String(50), unique=True, index=True)  # "dev-tools"
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)     # "Developer Tools"
    description: Mapped[str | None] = mapped_column(String(500))
    icon: Mapped[str | None] = mapped_column(String(100))  # Lucide icon name or URL
    sort_order: Mapped[int] = mapped_column(default=0)
    is_active: Mapped[bool] = mapped_column(default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    software: Mapped[list[SoftwareModel]] = relationship(
        back_populates="category",
        lazy="selectin",
    )