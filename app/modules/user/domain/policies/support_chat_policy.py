"""Policy for what the support bot will accept and say.

``SupportChatService`` held this as a ``SYSTEM_PROMPT`` class attribute and an
inline length check. Both are rules about the support conversation rather than
about transport, so they live here.
"""

from __future__ import annotations

from app.modules.user.domain.exceptions import ChatMessageTooShortError

#: The instructions sent to the model as the system message.
#:
#: This is policy, not configuration: it states what the bot may tell a
#: customer, and it is the part most likely to change when support policy
#: changes. The model name, endpoint and API key travel separately as
#: ``SupportAIConfig``.
SYSTEM_PROMPT = (
    "You are Tech Pulse customer support. "
    "Be concise, accurate, and provide actionable troubleshooting steps. "
    "If a user asks for account details, you may provide them."
    "If a user asks for a refund, you may provide instructions on how to request one. "
    "If a user asks for a feature, you may acknowledge the request and suggest they submit it through the feedback form. "
    "If a user asks for a status update on an issue, you may provide a generic response that the team is investigating and will provide updates as they become available. "
)

#: The canned reply sent when the model cannot be reached.
#:
#: The response schema has no field for "this was not a real answer", so a
#: customer cannot currently tell a canned reply from a model reply. Recorded
#: in ``docs/REVIEW.md``; changing it means changing the response shape.
FALLBACK_REPLY = (
    "Support assistant is temporarily unavailable. "
    "Please include your issue details, expected behavior, and any error message."
)

#: Questions shorter than this are rejected before the model is called at all.
MIN_QUESTION_LENGTH = 2


def clean_question(raw: str | None) -> str:
    """Trim a submitted question and reject it if it is too short to answer.

    Called before the model is asked, so a junk submission costs no tokens and
    no round trip. Returns the cleaned question to send.
    """
    cleaned = (raw or "").strip()
    if len(cleaned) < MIN_QUESTION_LENGTH:
        raise ChatMessageTooShortError("Message is too short")
    return cleaned
