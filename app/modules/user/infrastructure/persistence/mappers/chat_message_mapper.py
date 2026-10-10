"""Translation between the ChatMessage entity and the ``chat_messages`` table."""

from __future__ import annotations

from app.infrastructure.database.models.chat_message import ChatMessage as ChatMessageModel
from app.modules.user.domain.entities.chat_message import ChatMessage, ChatRole


def to_domain(model: ChatMessageModel) -> ChatMessage:
    """Map a database row onto a domain entity."""
    return ChatMessage(
        id=model.id,
        user_id=model.user_id,
        role=ChatRole(model.role),
        user_message=model.user_message,
        assistant_message=model.assistant_message,
        created_at=model.created_at,
    )


def to_model(message: ChatMessage) -> ChatMessageModel:
    """Map a domain entity onto a database row."""
    return ChatMessageModel(
        id=message.id,
        user_id=str(message.user_id),
        role=message.role.value,
        user_message=message.user_message,
        assistant_message=message.assistant_message,
        created_at=message.created_at,
    )
