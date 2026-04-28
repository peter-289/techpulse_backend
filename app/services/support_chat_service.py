from __future__ import annotations

import logging
import requests

from app.core.config import settings
from app.core.unit_of_work import UnitOfWork
from app.exceptions.exceptions import ExternalServiceError, ValidationError
from app.models.chat_message import ChatMessage

logger = logging.getLogger(__name__)


class SupportChatService:
    SYSTEM_PROMPT = (
        "You are Tech Pulse customer support. "
        "Be concise, accurate, and provide actionable troubleshooting steps. "
        "If a user asks for account details, you may provide them."
        "If a user asks for a refund, you may provide instructions on how to request one. "
        "If a user asks for a feature, you may acknowledge the request and suggest they submit it through the feedback form. "
        "If a user asks for a status update on an issue, you may provide a generic response that the team is investigating and will provide updates as they become available. "
    )

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    @staticmethod
    def _fallback_reply() -> str:
        return (
            "Support assistant is temporarily unavailable. "
            "Please include your issue details, expected behavior, and any error message."
        )

    def ask(self, *, user_id: int, message: str) -> ChatMessage:
        cleaned = (message or "").strip()
        if len(cleaned) < 2:
            raise ValidationError("Message is too short")

        try:
            assistant_reply = self._generate_reply(cleaned)
        except ExternalServiceError as exc:
            logger.warning("Support AI unavailable, falling back to canned reply: %s", exc)
            assistant_reply = self._fallback_reply()

        chat_message = ChatMessage(
            user_id=user_id,
            role="assistant",
            user_message=cleaned,
            assistant_message=assistant_reply,
        )
        with self.uow:
            return self.uow.chat_message_repo.add(chat_message)

    def list_messages(self, *, user_id: int, limit: int = 25) -> list[ChatMessage]:
        with self.uow:
            return self.uow.chat_message_repo.list_for_user(user_id=user_id, limit=limit)

    def _generate_reply(self, message: str) -> str:
        if not settings.AI_API_KEY:
            return self._fallback_reply()

        url = f"{settings.AI_BASE_URL.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {settings.AI_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": settings.SUPPORT_CHAT_MODEL,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": message},
            ],
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
        except requests.RequestException as exc:
            raise ExternalServiceError("Failed to reach AI support service") from exc

        if response.status_code >= 400:
            raise ExternalServiceError(f"AI support service failed: {response.text[:200]}")

        try:
            data = response.json()
        except ValueError as exc:
            logger.warning("AI support service returned non-JSON response: %s", response.text[:200])
            raise ExternalServiceError("AI support service returned an invalid response") from exc

        content = self._extract_assistant_content(data)
        if not content:
            raise ExternalServiceError("AI support service returned an empty response")
        return content

    @staticmethod
    def _extract_assistant_content(data: dict) -> str:
        # OpenAI-compatible shape
        choices = data.get("choices") or []
        if choices:
            message = choices[0].get("message") or {}
            content = message.get("content")
            if isinstance(content, str):
                return content.strip()
            if isinstance(content, list):
                text_parts = []
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        text_parts.append(part["text"])
                if text_parts:
                    return "\n".join(text_parts).strip()

        # Some providers expose text directly
        output_text = data.get("output_text")
        if isinstance(output_text, str):
            return output_text.strip()

        return ""
