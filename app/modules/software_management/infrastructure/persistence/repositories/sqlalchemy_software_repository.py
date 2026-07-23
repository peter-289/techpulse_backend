from __future__ import annotations

from typing import Optional
from uuid import UUID
import logging
from datetime import datetime, timezone


from sqlalchemy import or_, select, update, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.modules.software_management.domain.ports.repositories.software_repository import ISoftwareRepository
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.value_objects import SoftwareCard, OwnedSoftwareCard
from app.modules.software_management.domain.exceptions import RepositoryUnavailableError, SoftwareNotFoundError
from app.infrastructure.database.models.software import SoftwareArtifactModel, SoftwareModel, SoftwareVersionModel
from app.modules.shared.mappers import _software_to_entity, _software_to_model
from app.modules.shared.enums import SoftwareStatus, SoftwareVisibility
from app.infrastructure.database.models.payment import SoftwarePurchaseModel


# Logger setup
logger = logging.getLogger(__name__)

# Repository interface and implementation for software packages.
class SQLAlchemySoftwareRepository(ISoftwareRepository):
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
    
    async def has_purchase(self, *, software_id: UUID, user_id: UUID) -> bool:
        stmt = select(SoftwarePurchaseModel.id).where(
            SoftwarePurchaseModel.software_id == str(software_id),
            SoftwarePurchaseModel.buyer_id == str(user_id),
        )
        results = await self.session.scalar(stmt)
        return results is not None
    
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
            .where(SoftwareModel.visibility == SoftwareVisibility.PUBLIC)
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
                           SoftwareModel.status,
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
      
    async def soft_delete(self, software_id: UUID, deleted_by: UUID | None = None) -> None:
          """
          Stage soft delete. UoW commits/rolls back.
          """
          stmt = (
                 update(SoftwareModel)
                .where(
                      SoftwareModel.id == software_id,
                      SoftwareModel.status != SoftwareStatus.DELETED,
                )
                .values(
                       status=SoftwareStatus.DELETED,
                       deleted_at=datetime.now(timezone.utc),
                        deleted_by=str(deleted_by) if deleted_by is not None else None,
                 )
            )
          try:
            result = await self.session.execute(stmt)
          except SQLAlchemyError as exc:
            raise RepositoryUnavailableError(
               f"Failed to stage soft delete for {software_id}"
              ) from exc
    
          if result.rowcount == 0:
                raise SoftwareNotFoundError(
                f"Software {software_id} not found or already deleted"
             )

    async def search_candidates(
        self,
        query: str | None = None,
        *,
        category_id: UUID | None = None,
        tags: list[str] | None = None,
        limit: int = 500,
    ) -> list[Software]:
        """
        Concrete implementation: fetch unranked candidates.

        Constraints applied here:
        - `visibility` must be PUBLIC
        - `status` must not be DELETED
        - apply category_id and tags filters if provided
        - search query applied using ILIKE on name and description
        - eager load versions and artifacts
        - hard limit of `limit` (max 500 enforced by caller)
        """
        try:
            q = query.strip() if query else None
            stmt = select(SoftwareModel).options(
                selectinload(SoftwareModel.versions).selectinload(SoftwareVersionModel.artifact)
            ).where(
                SoftwareModel.visibility == SoftwareVisibility.PUBLIC,
                SoftwareModel.status != SoftwareStatus.DELETED,
            )

            if category_id:
                # Compare UUIDs directly; repository accepts UUID or None
                stmt = stmt.where(SoftwareModel.category_id == category_id)

            if tags:
                # tags stored in a text column as comma-separated values (assumption)
                for tag in tags:
                    stmt = stmt.where(func.lower(SoftwareModel.description).ilike(f"%{tag.lower()}%"))

            if q:
                pattern = f"%{q}%"
                stmt = stmt.where(
                    or_(
                        SoftwareModel.name.ilike(pattern),
                        SoftwareModel.description.ilike(pattern),
                    )
                )

            stmt = stmt.order_by(SoftwareModel.created_at.desc()).limit(min(limit, 500))

            result = await self.session.execute(stmt)
            models = result.scalars().all()
            return [_software_to_entity(m) for m in models]

        except SQLAlchemyError as exc:
            logger.exception("Failed to search candidates: %s", exc)
            raise RepositoryUnavailableError("Failed to fetch search candidates") from exc



    