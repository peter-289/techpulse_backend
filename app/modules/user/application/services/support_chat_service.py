"""Support chat use cases.

The service used to hold the system prompt, a length check, and a synchronous
``requests.post`` with its own error taxonomy. All three moved: the prompt and
the length rule to ``domain.policies.support_chat_policy``, the HTTP call behind
the ``SupportAI`` port. What is left here is the decision that matters, which is
what to do when the model is unavailable.
"""

from __future__ import annotations

import logging

from app.modules.user.domain.entities.chat_message import ChatMessage
from app.modules.user.domain.ports.repository.chat_message_repository import (
    ChatMessageRepository,
)
from app.modules.user.domain.ports.support_ai import SupportAI, SupportAIUnavailableError
from app.modules.user.domain.ports.unit_of_work import UserUnitOfWork
from app.modules.user.domain.policies.support_chat_policy import (
    FALLBACK_REPLY,
    SYSTEM_PROMPT,
    clean_question,
)

logger = logging.getLogger(__name__)


class SupportChatService:
    def __init__(self, uow: UserUnitOfWork, support_ai: SupportAI):
        self.uow = uow
        self._ai = support_ai

    async def ask(self, *, user_id: str, message: str) -> ChatMessage:
        """Answer a question and record the exchange.

        The question is cleaned and length-checked before the model is called,
        so a junk submission costs no round trip. An unavailable model is not an
        error: the exchange is still recorded, with the canned reply, because
        the customer's question is worth keeping even when the answer is not
        worth having.
        """
        cleaned = clean_question(message)

        try:
            assistant_reply = await self._ai.generate_reply(
                cleaned, system_prompt=SYSTEM_PROMPT
            )
        except SupportAIUnavailableError as exc:
            logger.warning("Support AI unavailable, falling back to canned reply: %s", exc)
            assistant_reply = FALLBACK_REPLY

        chat_message = ChatMessage.create(
            user_id=user_id,
            user_message=cleaned,
            assistant_message=assistant_reply,
        )
        async with self.uow:
            return await self.uow.chat_message_repo.add(chat_message)

    async def list_messages(self, *, user_id: str, limit: int = 25) -> list[ChatMessage]:
        """Return a user's recorded exchanges, oldest first.

        Uses ``read_only`` rather than a write transaction. This opened a
        transaction and committed on a pure read; nothing observes the
        difference, but a read that commits can mask a missing commit elsewhere
        in the same request.
        """
        async with self.uow.read_only():
            return await self.uow.chat_message_repo.list_for_user(
                user_id=user_id, limit=limit
            )

    async def delete_message(self, *, user_id: str, message_id: int) -> None:
        async with self.uow:
            await self.uow.chat_message_repo.delete_for_user(
                message_id=message_id,
                user_id=user_id,
            )
