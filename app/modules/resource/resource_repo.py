from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.resource import Resource


class ResourceRepo:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def add(self, resource: Resource) -> Resource:
        self.db.add(resource)
        await self.db.flush()
        await self.db.refresh(resource)
        return resource

    async def get_by_slug(self, slug: str) -> Optional[Resource]:
        stmt = select(Resource).where(Resource.slug == slug)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_resources(self, type_filter: str | None = None) -> list[Resource]:
        stmt = select(Resource).order_by(Resource.created_at.desc())
        if type_filter:
            stmt = stmt.where(Resource.type == type_filter)
            result = await self.db.execute(stmt)
            return result.scalars().all()

    async def delete(self, resource: Resource) -> None:
        await self.db.delete(resource)

