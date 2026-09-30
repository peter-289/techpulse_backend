"""SQLAlchemy implementation of the resource repository port."""

from __future__ import annotations

import logging

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.resource import Resource as ResourceModel
from app.modules.resource.domain.entities.resource import Resource
from app.modules.resource.domain.exceptions import ResourceRepositoryUnavailableError
from app.modules.resource.infrastructure.persistence.mappers.resource_mapper import (
    to_domain,
    to_model,
)

logger = logging.getLogger(__name__)


class SQLAlchemyResourceRepository:
    """Adapts ``AsyncSession`` to :class:`ResourceRepository`."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def add(self, resource: Resource) -> Resource:
        model = to_model(resource)
        try:
            self.db.add(model)
            await self.db.flush()
            await self.db.refresh(model)
        except SQLAlchemyError as exc:
            logger.warning("Resource insert failed: %s", exc, exc_info=True)
            raise ResourceRepositoryUnavailableError("Resource storage unavailable") from exc
        return to_domain(model)

    async def get_by_slug(self, slug: str) -> Resource | None:
        stmt = select(ResourceModel).where(ResourceModel.slug == slug)
        try:
            result = await self.db.execute(stmt)
        except SQLAlchemyError as exc:
            logger.warning("Resource lookup by slug failed: %s", exc, exc_info=True)
            raise ResourceRepositoryUnavailableError("Resource storage unavailable") from exc
        model = result.scalar_one_or_none()
        return to_domain(model) if model is not None else None

    async def list_resources(self, type_filter: str | None = None) -> list[Resource]:
        stmt = select(ResourceModel).order_by(ResourceModel.created_at.desc())
        if type_filter:
            stmt = stmt.where(ResourceModel.type == type_filter)
        try:
            result = await self.db.execute(stmt)
        except SQLAlchemyError as exc:
            logger.warning("Resource listing failed: %s", exc, exc_info=True)
            raise ResourceRepositoryUnavailableError("Resource storage unavailable") from exc
        return [to_domain(model) for model in result.scalars().all()]

    async def delete(self, resource: Resource) -> None:
        # A statement-level DELETE keyed on the unique slug, not
        # ``db.delete(model)``. The service hands this port a detached domain
        # entity, so the mapped row is transient; asking the session to delete
        # a transient instance raises InvalidRequestError, which would turn
        # every 204 into a 500. Nothing references ``resources`` by foreign key,
        # so dropping the row is the whole operation.
        stmt = sa_delete(ResourceModel).where(ResourceModel.slug == resource.slug)
        try:
            await self.db.execute(stmt)
        except SQLAlchemyError as exc:
            logger.warning("Resource delete failed: %s", exc, exc_info=True)
            raise ResourceRepositoryUnavailableError("Resource storage unavailable") from exc
