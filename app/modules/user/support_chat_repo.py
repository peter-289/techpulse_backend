from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.user import ChatMessage


class ChatMessageRepo:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def add(self, message: ChatMessage) -> ChatMessage:
        self.db.add(message)
        await self.db.flush()
        await self.db.refresh(message)
        return message

    async def list_for_user(self, user_id: int, limit: int = 25) -> list[ChatMessage]:
        stmt = (
            select(ChatMessage)
            .where(ChatMessage.user_id == user_id)
            .order_by(ChatMessage.created_at.desc())
            .limit(limit)
        )
        results = await self.db.execute(stmt)
        result = list((results.scalars().all()))
        return reversed(result)

