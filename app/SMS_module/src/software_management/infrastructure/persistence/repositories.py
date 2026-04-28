from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.exc import StaleDataError

from ...application.ports import SoftwareRepositoryPort
from ...domain.entities.software import Software
from ...domain.exceptions import ConcurrencyError
from .mappers import software_entity_to_model, software_model_to_entity
from .sqlalchemy_models import SoftwareModel, VersionModel


class SQLAlchemySoftwareRepository(SoftwareRepositoryPort):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, software_id: UUID) -> Software | None:
        stmt = (
            select(SoftwareModel)
            .where(SoftwareModel.id == str(software_id))
            .options(selectinload(SoftwareModel.versions).selectinload(VersionModel.artifact))
        )
        model = await self._session.scalar(stmt)
        if model is None:
            return None
        return software_model_to_entity(model)

    async def save(self, software: Software) -> None:
        model = software_entity_to_model(software)
        try:
            await self._session.merge(model)
            await self._session.commit()
        except StaleDataError as exc:
            await self._session.rollback()
            raise ConcurrencyError(
                "Version update conflict detected. Reload aggregate and retry."
            ) from exc

    async def list_for_owner(self, owner_id: UUID) -> list[Software]:
        stmt = (
            select(SoftwareModel)
            .where(SoftwareModel.owner_id == str(owner_id))
            .options(selectinload(SoftwareModel.versions).selectinload(VersionModel.artifact))
        )
        models = (await self._session.scalars(stmt)).all()
        return [software_model_to_entity(item) for item in models]
