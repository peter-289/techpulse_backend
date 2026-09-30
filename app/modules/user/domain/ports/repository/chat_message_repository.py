"""Persistence port for stored support exchanges.

Ordering is part of the contract: ``GET /api/v1/support-chat/messages`` returns
the oldest first, which the adapter gets by selecting newest-first and
reversing.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.modules.user.domain.entities.chat_message import ChatMessage


@runtime_checkable
class ChatMessageRepository(Protocol):
    """Storage boundary for support exchanges."""

    async def add(self, message: ChatMessage) -> ChatMessage:
        """Persist a completed exchange and return it with its assigned id."""
        ...

    async def list_for_user(self, user_id: str, limit: int = 25) -> list[ChatMessage]:
        """Return a user's exchanges, oldest first, capped at ``limit``."""
        ...
