from datetime import datetime
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.infrastructure.database.models.session import UserSession


class SessionRepo:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def add_session(self, session: UserSession) -> UserSession:
        self.db.add(session)
        await self.db.flush()
        await self.db.refresh(session)
        return session

    async def get_by_refresh_hash(self, refresh_hash: str) -> Optional[UserSession]:
        stmt = select(UserSession).where(UserSession.refresh_token_hash == refresh_hash)
        result = await self.db.execute(stmt)
        
        return result.scalar_one_or_none()

    def revoke_session(self, session: UserSession, revoked_at: datetime) -> None:
        session.revoked_at = revoked_at

    async def revoke_user_sessions(self, user_id: int, revoked_at: datetime) -> None:
        stmt = (
            update(UserSession)
            .where(UserSession.user_id == user_id)
            .where(UserSession.revoked_at.is_(None))
            .values(revoked_at=revoked_at)
        )
        await self.db.execute(stmt)