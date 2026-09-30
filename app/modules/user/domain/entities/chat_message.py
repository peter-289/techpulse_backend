"""The stored support exchange.

A note on the name. One row holds a *question and its answer*: ``user_message``
and ``assistant_message`` are always written together by the same call, and
nothing ever writes a row with only one of them. So the type models an exchange
even though the column and the API field are called a message. Renaming the
table or the API field would be a schema and contract change, so the awkward
spelling stays and the mismatch is recorded in ``docs/REVIEW.md``.

The ``role`` column defaults to ``"user"`` but has only ever been written as
``"assistant"``, because every row is one completed exchange. Both values are
modelled so the column's default stays reachable; the fact that only one is
used is a finding, not an oversight.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum


class ChatRole(StrEnum):
    """Whose turn a row represents."""

    USER = "user"
    ASSISTANT = "assistant"


@dataclass(slots=True)
class ChatMessage:
    """One question and the assistant's answer to it."""

    user_id: str
    user_message: str
    assistant_message: str
    role: ChatRole = ChatRole.ASSISTANT
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: int | None = None

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        user_message: str,
        assistant_message: str,
    ) -> "ChatMessage":
        """Record a completed exchange.

        Takes the question already cleaned and length-checked by
        ``support_chat_policy.clean_question``, which has to run *before* the
        model is called. Re-trimming here would be harmless and re-validating
        would be redundant, so this constructor stays a plain factory.
        """
        return cls(
            user_id=user_id,
            user_message=user_message,
            assistant_message=assistant_message,
            role=ChatRole.ASSISTANT,
        )
