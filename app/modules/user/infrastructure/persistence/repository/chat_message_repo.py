"""SQLAlchemy implementation of the chat message repository port."""

from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.chat_message import ChatMessage as ChatMessageModel
from app.modules.user.domain.entities.chat_message import ChatMessage
from app.modules.user.domain.exceptions import ChatMessageRepositoryUnavailableError
from app.modules.user.infrastructure.persistence.mappers.chat_message_mapper import (
    to_domain,
    to_model,
)

logger = logging.getLogger(__name__)


class SQLAlchemyChatMessageRepository:
    """Adapts ``AsyncSession`` to :class:`ChatMessageRepository`."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def add(self, message: ChatMessage) -> ChatMessage:
        model = to_model(message)
        try:
            self.db.add(model)
            await self.db.flush()
            await self.db.refresh(model)
        except SQLAlchemyError as exc:
            logger.warning("Chat exchange insert failed: %s", exc, exc_info=True)
            raise ChatMessageRepositoryUnavailableError("Chat storage unavailable") from exc
        return to_domain(model)

    async def list_for_user(self, user_id: str | UUID, limit: int = 25) -> list[ChatMessage]:
        user_id = str(user_id)
        # Newest first to apply the LIMIT to the most recent exchanges, then
        # reversed so the API returns them oldest first. Both the ordering and
        # the direction are part of the endpoint's contract.
        stmt = (
            select(ChatMessageModel)
            .where(ChatMessageModel.user_id == user_id)
            .order_by(ChatMessageModel.created_at.desc())
            .limit(limit)
        )
        try:
            results = await self.db.execute(stmt)
        except SQLAlchemyError as exc:
            logger.warning("Chat exchange listing failed: %s", exc, exc_info=True)
            raise ChatMessageRepositoryUnavailableError("Chat storage unavailable") from exc
        return [to_domain(model) for model in reversed(results.scalars().all())]

    async def delete_for_user(self, message_id: int, user_id: str | UUID) -> None:
        stmt = delete(ChatMessageModel).where(
            ChatMessageModel.id == message_id,
            ChatMessageModel.user_id == str(user_id),
        )
        try:
            await self.db.execute(stmt)
        except SQLAlchemyError as exc:
            logger.warning("Chat exchange deletion failed: %s", exc, exc_info=True)
            raise ChatMessageRepositoryUnavailableError("Chat storage unavailable") from exc
