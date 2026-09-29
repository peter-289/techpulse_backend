"""Pagination and list-endpoint regression tests.

Guards two implicit-``None`` returns: ``UserRepo.list_users`` returned ``None``
whenever ``cursor`` was ``None``, and ``ResourceRepo.list_resources`` returned
``None`` whenever no type filter was supplied. Both turned into 500s.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.infrastructure.database.db_setup import Base
from app.infrastructure.database.models.resource import Resource
from app.infrastructure.database.models.user import User
from app.modules.resource.resource_repo import ResourceRepo
from app.modules.user.infrastructure.persistence.repository.user_repo import UserRepo

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


def _user(index: int) -> User:
    return User(
        id=f"{index:08d}-0000-0000-0000-000000000000",
        full_name=f"User {index}",
        username=f"user{index}",
        email=f"user{index}@example.test",
        password_hash="hash",
    )


async def _seed_users(db, count: int) -> None:
    for index in range(count):
        db.add(_user(index))
    await db.commit()


@pytest.mark.asyncio
async def test_list_users_without_cursor_returns_a_list(session) -> None:
    await _seed_users(session, 3)
    users = await UserRepo(session).list_users(cursor=None, limit=10)
    assert users is not None
    assert isinstance(users, list)
    assert len(users) == 3


@pytest.mark.asyncio
async def test_list_users_with_no_arguments_returns_a_list(session) -> None:
    users = await UserRepo(session).list_users()
    assert users == []


@pytest.mark.asyncio
async def test_list_users_orders_by_id_descending(session) -> None:
    await _seed_users(session, 5)
    users = await UserRepo(session).list_users(limit=5)
    assert [u.id for u in users] == sorted((u.id for u in users), reverse=True)


@pytest.mark.asyncio
async def test_list_users_honours_limit(session) -> None:
    await _seed_users(session, 5)
    assert len(await UserRepo(session).list_users(limit=2)) == 2


@pytest.mark.asyncio
async def test_list_users_keyset_pages_without_overlap(session) -> None:
    await _seed_users(session, 5)
    repo = UserRepo(session)

    first = await repo.list_users(limit=2)
    assert len(first) == 2

    second = await repo.list_users(limit=2, before_id=first[-1].id)
    assert len(second) == 2

    ids = [u.id for u in first] + [u.id for u in second]
    assert len(set(ids)) == 4
    assert second[-1].id < first[-1].id


@pytest.mark.asyncio
async def test_list_users_clamps_out_of_range_limits(session) -> None:
    await _seed_users(session, 2)
    repo = UserRepo(session)
    # A limit below 1 is clamped up to 1 rather than returning an empty page.
    assert len(await repo.list_users(limit=0)) == 1
    assert len(await repo.list_users(limit=-5)) == 1
    assert len(await repo.list_users(limit=10_000)) == 2


def _resource(slug: str, resource_type: str) -> Resource:
    return Resource(
        title=slug.title(),
        slug=slug,
        type=resource_type,
        description=f"{slug} description",
    )


@pytest.mark.asyncio
async def test_list_resources_without_filter_returns_a_list(session) -> None:
    session.add(_resource("docs", "knowledge"))
    session.add(_resource("api", "api"))
    await session.commit()

    resources = await ResourceRepo(session).list_resources()
    assert resources is not None
    assert isinstance(resources, list)
    assert {r.slug for r in resources} == {"docs", "api"}


@pytest.mark.asyncio
async def test_list_resources_filters_by_type(session) -> None:
    session.add(_resource("docs", "knowledge"))
    session.add(_resource("api", "api"))
    await session.commit()

    resources = await ResourceRepo(session).list_resources(type_filter="api")
    assert [r.slug for r in resources] == ["api"]


@pytest.mark.asyncio
async def test_list_resources_unknown_type_returns_empty_list(session) -> None:
    session.add(_resource("docs", "knowledge"))
    await session.commit()

    assert await ResourceRepo(session).list_resources(type_filter="nope") == []
