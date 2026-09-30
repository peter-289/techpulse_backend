"""Support chat: the policy, the entity, and the degraded-mode decision.

``SupportChatService`` had no tests. It was the only place in the codebase making
a network call from an application service, and the decision that mattered --
what to do when the model is unreachable -- was a bare ``except
ExternalServiceError`` with no way to exercise it without reaching for a real
endpoint.

These tests drive the service with a fake ``SupportAI``, so the fallback path is
directly testable. That is the point of the port: the interesting behaviour is
application policy, not HTTP.
"""

from __future__ import annotations

import pytest

from app.modules.user.application.services.support_chat_service import SupportChatService
from app.modules.user.domain.entities.chat_message import ChatMessage, ChatRole
from app.modules.user.domain.exceptions import ChatMessageTooShortError
from app.modules.user.domain.ports.support_ai import SupportAIUnavailableError
from app.modules.user.domain.policies.support_chat_policy import (
    FALLBACK_REPLY,
    MIN_QUESTION_LENGTH,
    SYSTEM_PROMPT,
    clean_question,
)


class _FakeAI:
    """Stands in for the model. Records what it was asked."""

    def __init__(self, reply: str | Exception = "a real answer") -> None:
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    async def generate_reply(self, question: str, system_prompt: str) -> str:
        self.calls.append((question, system_prompt))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


class _FakeRepo:
    def __init__(self) -> None:
        self.saved: list[ChatMessage] = []

    async def add(self, message: ChatMessage) -> ChatMessage:
        message.id = len(self.saved) + 1
        self.saved.append(message)
        return message

    async def list_for_user(self, user_id: str, limit: int = 25) -> list[ChatMessage]:
        return [m for m in self.saved if m.user_id == user_id][:limit]


class _FakeUow:
    def __init__(self, repo: _FakeRepo) -> None:
        self.chat_message_repo = repo
        self.writes = 0
        self.reads = 0

    async def __aenter__(self) -> "_FakeUow":
        self.writes += 1
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    def read_only(self):
        uow = self

        class _Ctx:
            async def __aenter__(self_inner) -> "_FakeUow":
                uow.reads += 1
                return uow

            async def __aexit__(self_inner, *exc_info: object) -> None:
                return None

        return _Ctx()


def _service(ai: _FakeAI) -> tuple[SupportChatService, _FakeUow, _FakeAI]:
    repo = _FakeRepo()
    uow = _FakeUow(repo)
    return SupportChatService(uow=uow, support_ai=ai), uow, ai


# === the too-short rule ===

@pytest.mark.parametrize(
    ("raw", "expected"),
    [("hi", "hi"), ("  hi  ", "hi"), ("a longer question", "a longer question")],
)
def test_clean_question_trims(raw, expected) -> None:
    assert clean_question(raw) == expected


@pytest.mark.parametrize("raw", [None, "", " ", "h", "\n\t"])
def test_clean_question_rejects_what_is_too_short(raw) -> None:
    """A one-character submission cannot be answered, so it is not sent."""
    with pytest.raises(ChatMessageTooShortError) as excinfo:
        clean_question(raw)
    assert str(excinfo.value) == "Message is too short"


def test_minimum_length_is_two() -> None:
    assert MIN_QUESTION_LENGTH == 2


@pytest.mark.asyncio
async def test_a_short_question_never_reaches_the_model() -> None:
    """Ordering matters: validating after the call would burn a round trip."""
    service, uow, ai = _service(_FakeAI())

    with pytest.raises(ChatMessageTooShortError):
        await service.ask(user_id="u1", message=" ")

    assert ai.calls == []
    assert uow.writes == 0
    assert uow.chat_message_repo.saved == []


# === the happy path ===

@pytest.mark.asyncio
async def test_ask_records_the_question_and_the_reply() -> None:
    service, uow, _ = _service(_FakeAI("try restarting the service"))

    saved = await service.ask(user_id="u1", message="  app will not start  ")

    assert saved.user_id == "u1"
    assert saved.user_message == "app will not start"
    assert saved.assistant_message == "try restarting the service"
    assert saved.id == 1
    assert uow.writes == 1


@pytest.mark.asyncio
async def test_ask_sends_the_support_system_prompt() -> None:
    service, _, ai = _service(_FakeAI())

    await service.ask(user_id="u1", message="help")

    question, prompt = ai.calls[0]
    assert question == "help"
    assert prompt == SYSTEM_PROMPT
    assert "Tech Pulse customer support" in prompt


@pytest.mark.asyncio
async def test_a_stored_exchange_is_tagged_as_the_assistant() -> None:
    """The column has been written ``assistant`` for every row ever created."""
    service, _, _ = _service(_FakeAI())

    saved = await service.ask(user_id="u1", message="help")

    assert saved.role is ChatRole.ASSISTANT


# === degraded mode ===

@pytest.mark.asyncio
async def test_an_unavailable_model_yields_the_canned_reply_and_still_records() -> None:
    """The customer asked something worth keeping, so the exchange is stored.

    Losing the record because the model was down would make the transcript
    depend on a third party's uptime.
    """
    service, uow, _ = _service(_FakeAI(SupportAIUnavailableError("provider down")))

    saved = await service.ask(user_id="u1", message="help")

    assert saved.assistant_message == FALLBACK_REPLY
    assert saved.user_message == "help"
    assert uow.chat_message_repo.saved == [saved]


@pytest.mark.asyncio
async def test_an_unavailable_model_does_not_fail_the_request() -> None:
    """Still a 201 with a body, as it was when ExternalServiceError was caught."""
    service, _, _ = _service(_FakeAI(SupportAIUnavailableError("provider down")))

    saved = await service.ask(user_id="u1", message="help")

    assert saved.id == 1
    assert isinstance(saved.assistant_message, str)


# === reads ===

@pytest.mark.asyncio
async def test_list_messages_uses_a_read_only_transaction() -> None:
    """A read must not commit. The shared UoW docstring says so explicitly."""
    service, uow, _ = _service(_FakeAI())
    await service.ask(user_id="u1", message="help")

    listed = await service.list_messages(user_id="u1")

    assert uow.reads == 1
    assert uow.writes == 1  # only the earlier ask wrote
    assert [m.user_message for m in listed] == ["help"]


@pytest.mark.asyncio
async def test_list_messages_is_scoped_to_the_user() -> None:
    service, _, _ = _service(_FakeAI())
    await service.ask(user_id="u1", message="mine")
    await service.ask(user_id="u2", message="theirs")

    listed = await service.list_messages(user_id="u1")

    assert [m.user_message for m in listed] == ["mine"]
