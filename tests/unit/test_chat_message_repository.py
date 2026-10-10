"""Round-trip tests for the chat message repository and its mapper.

The ordering is the load-bearing part: the endpoint returns oldest first, which
the adapter gets by selecting newest-first, applying the LIMIT to the most recent
exchanges, and then reversing. Reversing twice, or dropping the reversal, still
returns a list of the right length and would pass a naive assertion.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.infrastructure.database.db_setup import Base
from app.infrastructure.database.models.chat_message import ChatMessage as ChatMessageModel
from app.modules.user.domain.entities.chat_message import ChatMessage, ChatRole
from app.modules.user.infrastructure.persistence.mappers.chat_message_mapper import (
    to_domain,
    to_model,
)
from app.modules.user.infrastructure.persistence.repository.chat_message_repo import (
    SQLAlchemyChatMessageRepository,
)

import app.infrastructure.database.models  # noqa: F401  (registers all tables)


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db:
        yield db
    await engine.dispose()


def _exchange(question: str, answer: str = "an answer") -> ChatMessage:
    return ChatMessage.create(user_id="u1", user_message=question, assistant_message=answer)


async def _seed(session, exchanges: list[ChatMessage]) -> None:
    """Insert rows with explicit, distinct timestamps so ordering is decidable."""
    repo = SQLAlchemyChatMessageRepository(session)
    for exchange in exchanges:
        await repo.add(exchange)
    await session.commit()

    rows = (await session.execute(select(ChatMessageModel))).scalars().all()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for offset, row in enumerate(sorted(rows, key=lambda r: r.id)):
        row.created_at = base + timedelta(minutes=offset)
    await session.commit()


@pytest.mark.asyncio
async def test_add_returns_the_entity_with_its_generated_id(session) -> None:
    saved = await SQLAlchemyChatMessageRepository(session).add(_exchange("why?"))

    assert saved.id is not None
    assert saved.user_message == "why?"
    assert saved.role is ChatRole.ASSISTANT


@pytest.mark.asyncio
async def test_add_picks_up_created_at_from_the_database_default(session) -> None:
    saved = await SQLAlchemyChatMessageRepository(session).add(_exchange("why?"))
    assert saved.created_at is not None


@pytest.mark.asyncio
async def test_listing_returns_exchanges_oldest_first(session) -> None:
    await _seed(session, [_exchange("first"), _exchange("second"), _exchange("third")])

    listed = await SQLAlchemyChatMessageRepository(session).list_for_user(user_id="u1")

    assert [m.user_message for m in listed] == ["first", "second", "third"]


@pytest.mark.asyncio
async def test_limit_keeps_the_most_recent_and_still_returns_them_oldest_first(session) -> None:
    """LIMIT applies to the newest rows, then the result is reversed.

    Taking the *oldest* 3 of 5 would be a plausible and wrong reading of
    "newest 3", so the assertion names which end the cap applies to.
    """
    await _seed(session, [_exchange(f"q{n}") for n in range(5)])

    listed = await SQLAlchemyChatMessageRepository(session).list_for_user(user_id="u1", limit=3)

    assert [m.user_message for m in listed] == ["q2", "q3", "q4"]


@pytest.mark.asyncio
async def test_listing_is_scoped_to_one_user(session) -> None:
    repo = SQLAlchemyChatMessageRepository(session)
    await repo.add(_exchange("mine"))
    await repo.add(ChatMessage.create(user_id="u2", user_message="theirs", assistant_message="x"))
    await session.commit()

    listed = await SQLAlchemyChatMessageRepository(session).list_for_user(user_id="u1")

    assert [m.user_message for m in listed] == ["mine"]


@pytest.mark.asyncio
async def test_listing_for_an_unknown_user_is_an_empty_list(session) -> None:
    listed = await SQLAlchemyChatMessageRepository(session).list_for_user(user_id="nobody")
    assert listed == []


@pytest.mark.asyncio
async def test_listing_normalizes_uuid_user_ids_for_string_columns(session) -> None:
    user_id = UUID("1da31c9c-ee2e-4fa6-9e3b-e2a94cbc5965")
    await _seed(
        session,
        [ChatMessage.create(user_id=str(user_id), user_message="hello", assistant_message="hi")],
    )

    listed = await SQLAlchemyChatMessageRepository(session).list_for_user(user_id=user_id)

    assert [message.user_message for message in listed] == ["hello"]


def test_mapper_round_trips_the_role_as_a_string() -> None:
    entity = _exchange("why?", "because")
    entity.id = 42

    model = to_model(entity)
    assert model.role == "assistant"
    assert isinstance(model.role, str)

    restored = to_domain(model)
    assert restored.id == 42
    assert restored.user_id == "u1"
    assert restored.role is ChatRole.ASSISTANT
    assert restored.user_message == "why?"
    assert restored.assistant_message == "because"
