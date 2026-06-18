from __future__ import annotations

from uuid import UUID
from abc import ABC, abstractmethod
import logging
from uuid import UUID


from sqlalchemy import or_, select, update, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import SQLAlchemyError

from app.modules.software_management.software import Software
from app.infrastructure.database.models.software import SoftwareModel, SoftwareVersionModel
from app.modules.software_management.utils import _software_to_entity, _software_to_model
from app.modules.software_management.software.exceptions import RepositoryUnavailableError
from app.modules.software_management.software.value_objects import SoftwareCard, OwnedSoftwareCard  

# Logger setup
logger = logging.getLogger(__name__)

# Repository interface and implementation for software packages.
class ISoftwareRepository(ABC):
    """Repository interface for software packages."""

    # ─── Write operations ───
    @abstractmethod
    async def save(self, software: Software) -> None:
        """Persist or update software."""
        ...

    # ─── Single item operations ───
    @abstractmethod
    async def get(self, software_id: UUID) -> Software | None:
        """Get software by ID with all relationships loaded."""
        ...

    @abstractmethod
    async def get_by_slug(self, slug: str) -> Software | None:
        """Get software by URL slug."""
        ...

    @abstractmethod
    async def exists(self, software_id: UUID) -> bool:
        """Fast existence check without loading full model."""
        """Persist or update software."""
        ...
        ...


    @abstractmethod
    async def soft_delete(self, software_id: UUID) -> None:
        """Mark as deleted."""
        ...

    # ─── List operations ───
    @abstractmethod
    async def list_marketplace(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[SoftwareCard]:
        """List software cards for marketplace. Returns (items, total)."""
        ...

    @abstractmethod
    async def list_owned(
        self,
        owner_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Software], int]:
        """
        List software owned by owner. Returns (items, total).
         If owner_id is None, returns empty list.
         Used for "My Software" page.
        """
        ...

    @abstractmethod
    async def list_by_ids(
        self,
        software_ids: list[UUID],
    ) -> list[Software]:
        """Batch fetch by IDs. Order not guaranteed."""
        ...

    # ─── Search ───
    @abstractmethod
    async def search(
        self,
        query: str | None = None,
        *,
        category_id: UUID | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Software], int]:
        """Full-text + faceted search. Returns (items, total)."""
        ...

    # ─── Analytics ───
    @abstractmethod
    async def count(
        self,
        *,
        owner_id: UUID | None = None,
        is_public: bool | None = None,
    ) -> int:
        """Count software matching filters."""
        ...



# Concrete implementation using SQLAlchemy ORM.
class SoftwareRepository(ISoftwareRepository):
    def __init__(self, session: AsyncSession):
        self.session = session


    # ─── Single item operations ───
    async def get(self, software_id: UUID) -> Software | None:
        """Get software by ID with all relationships loaded."""

        try:
            stmt = (
                     select(SoftwareModel)
                     .where(SoftwareModel.id == str(software_id))
                     .options(selectinload(SoftwareModel.versions)
                     .selectinload(SoftwareVersionModel.artifact))
                    )
            model = await self.session.scalar(stmt)
            if model is None:
                return None
            return _software_to_entity(model)

        except SQLAlchemyError as e:
            logger.error(f"Error constructing query for get: {e}", exc_info=False)
            raise RepositoryUnavailableError("Failed to retrieve software") from e
        
    async def save(self, software: Software) -> Software:
        """
         Stage software for persistence. Caller must commit.
    
         Raises:
           RepositoryUnavailableError: On database failure.
         """
        try:
           model = _software_to_model(software)
           merged = await self.session.merge(model)
           await self.session.flush()
           await self.session.refresh(merged)
           return _software_to_entity(merged)
        
        except SQLAlchemyError as exc:
           logger.error("Error staging software for save: %s", exc, exc_info=False)
           raise RepositoryUnavailableError(
            f"Failed to stage software aggregation."
           ) from exc
    
    async def list_marketplace(
    self,
    *,
    limit: int = 100,
    offset: int = 0
    ) -> list[SoftwareCard]:
        """
         List software cards for marketplace (public only).
         Returns lightweight projection for fast UI rendering.
         Raises:
           RepositoryUnavailableError: On database failure.
         """
        try:
           stmt = (
            select(
                SoftwareModel.id,
                SoftwareModel.name,
                SoftwareModel.description,
                SoftwareModel.price_cents,
                SoftwareModel.currency,
                SoftwareModel.created_at,
                SoftwareVersionModel.version.label("latest_version"),
            )
            .outerjoin(
                SoftwareVersionModel,
                SoftwareModel.latest_version_id == SoftwareVersionModel.id,
            )
            .where(SoftwareModel.is_public.is_(True))
            .order_by(
                SoftwareModel.created_at.desc(),
                SoftwareModel.id.desc(),  # stable pagination
            )
            .limit(limit)
            .offset(offset)
            )

           result = await self.session.execute(stmt)

           # Safe, explicit column access (no index-based access)
           rows = result.mappings().all()

           return [
            SoftwareCard(
                id=row["id"],
                name=row["name"],
                description=row["description"],
                price_cents=row["price_cents"],
                currency=row["currency"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

        except SQLAlchemyError as exc:
           logger.exception("Failed to list marketplace software")
           raise RepositoryUnavailableError(
              "Failed to list marketplace software"
           ) from exc

    async def list_owned(self, owner_id: UUID, *, limit: int = 100, offset: int = 0) -> tuple[list[OwnedSoftwareCard], int]:
           try:
               where = SoftwareModel.owner_id == str(owner_id)

               # Count statement
               count_stmt = (
                   select(func.count())
                   .select_from(SoftwareModel)
                   .where(where)
               )
               total = await self.session.scalar(count_stmt) or 0

               # Scalar subquery
               latest_version_sq = (
                                    select(SoftwareVersionModel.version)
                                    .where(SoftwareVersionModel.software_id == SoftwareModel.id)
                                    .order_by(SoftwareVersionModel.created_at.desc())
                                    .limit(1)
                                    .scalar_subquery()
                                )
               # Statement
               stmt = (
                        select(
                            SoftwareModel.id,
                            SoftwareModel.name,
                            SoftwareModel.description,
                            SoftwareModel.visibility,
                            SoftwareModel.price_cents,
                            SoftwareModel.currency,
                            SoftwareModel.created_at,
                            SoftwareModel.updated_at,
                            latest_version_sq.label("latest_version"),
                        )
                        .where(where)
                        .order_by(
                            SoftwareModel.updated_at.desc(),
                            SoftwareModel.id.desc(),
                        )
                        .offset(offset)
                        .limit(limit)
                    )
               result = await self.session.execute(stmt)
               rows = result.mappings().all()

               return [
                      OwnedSoftwareCard(
                            id=row["id"],
                            name=row["name"],
                            description=row["description"],
                            visibility=row["visibility"],
                            status=row["status"],
                            price_cents=row["price_cents"],
                            currency=row["currency"],
                            created_at=row["created_at"],
                            updated_at=row["updated_at"],
                            latest_version=row["latest_version"],
                        )
                        for row in rows
                    ], total
           
           except SQLAlchemyError as exc:
               logger.exception("Failed to list owned software by: %s, %s", owner_id, exc)
               raise RepositoryUnavailableError(f"Failed to software for owner: {owner_id}")


    async def increment_download_count(self, version_id: UUID) -> None:
        stmt = (
            update(SoftwareVersionModel)
            .where(SoftwareVersionModel.id == str(version_id))
            .values(download_count=SoftwareVersionModel.download_count + 1)
        )
        await self.session.execute(stmt)
