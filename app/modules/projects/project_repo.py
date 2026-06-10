from typing import Optional

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.project import Project


class ProjectRepo:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def add(self, project: Project) -> Project:
        self.db.add(project)
        await self.db.flush()
        await self.db.refresh(project)
        return project

    async def get_by_id(self, project_id: int) -> Optional[Project]:
        return await self.db.get(Project, project_id)

    async def list_visible_for_user(self, user_id: int, cursor: int | None = None, limit: int = 50) -> list[Project]:
        stmt = (
            select(Project)
            .where(or_(Project.is_public.is_(True), Project.user_id == user_id))
            .order_by(Project.id.desc())
            .limit(limit)
        )
        if cursor is not None:
            stmt = stmt.where(Project.id < cursor)
            result = await self.db.execute(stmt)
            return result.scalars().all()

    async def increment_download_count(self, project_id: int) -> None:
        stmt = (
            update(Project)
            .where(Project.id == project_id)
            .values(download_count=Project.download_count + 1)
        )
        await self.db.execute(stmt)

    async def delete(self, project: Project) -> None:
        await self.db.delete(project)
