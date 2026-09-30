"""Round-trip tests for the resource repository and its mapper.

The delete case is the load-bearing one. The service hands the port a
*detached domain entity*, so the mapped row is transient; passing that to
``session.delete()`` raises ``InvalidRequestError`` and turns a 204 into a
500. The repository uses a statement-level DELETE for exactly that reason, and
this test is what proves it still removes the row.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.infrastructure.database.db_setup import Base
from app.infrastructure.database.models.resource import Resource as ResourceModel
from app.modules.resource.domain.entities.resource import Resource
from app.modules.resource.domain.value_objects.resource_type import ResourceType
from app.modules.resource.infrastructure.persistence.mappers.resource_mapper import (
    to_domain,
    to_model,
)
from app.modules.resource.infrastructure.persistence.repositories.resource_repo import (
    SQLAlchemyResourceRepository,
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


def _entity(slug: str, resource_type: str = "api", title: str | None = None) -> Resource:
    return Resource.create(
        title=title or slug.title(),
        slug=slug,
        resource_type=resource_type,
        description=f"{slug} description",
        url=None,
    )


@pytest.mark.asyncio
async def test_add_returns_the_entity_with_its_generated_id(session) -> None:
    saved = await SQLAlchemyResourceRepository(session).add(_entity("docs"))

    assert saved.id is not None
    assert saved.slug == "docs"
    assert saved.resource_type is ResourceType.API


@pytest.mark.asyncio
async def test_add_populates_created_at_from_the_database_default(session) -> None:
    saved = await SQLAlchemyResourceRepository(session).add(_entity("docs"))
    assert saved.created_at is not None


@pytest.mark.asyncio
async def test_get_by_slug_returns_a_domain_entity_not_a_row(session) -> None:
    repo = SQLAlchemyResourceRepository(session)
    await repo.add(_entity("docs", "knowledge"))
    await session.commit()

    found = await SQLAlchemyResourceRepository(session).get_by_slug("docs")

    assert isinstance(found, Resource)
    assert found.resource_type is ResourceType.KNOWLEDGE


@pytest.mark.asyncio
async def test_get_by_slug_returns_none_when_absent(session) -> None:
    assert await SQLAlchemyResourceRepository(session).get_by_slug("nope") is None


@pytest.mark.asyncio
async def test_delete_of_a_detached_entity_actually_removes_the_row(session) -> None:
    """A DELETE that silently no-ops still returns 204, so only this catches it."""
    repo = SQLAlchemyResourceRepository(session)
    await repo.add(_entity("docs"))
    await session.commit()

    found = await SQLAlchemyResourceRepository(session).get_by_slug("docs")
    assert found is not None

    await SQLAlchemyResourceRepository(session).delete(found)
    await session.commit()

    rows = (await session.execute(select(ResourceModel))).scalars().all()
    assert [r.slug for r in rows] == []


@pytest.mark.asyncio
async def test_delete_leaves_other_resources_alone(session) -> None:
    repo = SQLAlchemyResourceRepository(session)
    await repo.add(_entity("docs"))
    await repo.add(_entity("api"))
    await session.commit()

    found = await SQLAlchemyResourceRepository(session).get_by_slug("docs")
    await SQLAlchemyResourceRepository(session).delete(found)
    await session.commit()

    remaining = await SQLAlchemyResourceRepository(session).list_resources()
    assert [r.slug for r in remaining] == ["api"]


@pytest.mark.asyncio
async def test_listing_is_newest_first(session) -> None:
    repo = SQLAlchemyResourceRepository(session)
    await repo.add(_entity("oldest", title="Oldest"))
    await repo.add(_entity("newest", title="Newest"))
    await repo.add(_entity("middle", title="Middle"))
    await session.commit()

    # created_at comes from the database default, so order the rows explicitly
    # rather than depending on sub-millisecond insertion timing.
    now = datetime.now(timezone.utc)
    offsets = {"oldest": 0, "middle": 1, "newest": 2}
    rows = (await session.execute(select(ResourceModel))).scalars().all()
    for row in rows:
        row.created_at = now + timedelta(minutes=offsets[row.slug])
    await session.commit()

    listed = await SQLAlchemyResourceRepository(session).list_resources()
    assert [r.slug for r in listed] == ["newest", "middle", "oldest"]


def test_mapper_round_trips_the_renamed_type_field() -> None:
    """``resource_type`` in the domain, ``type`` in the column."""
    entity = Resource.create(
        title="Docs", slug="docs", resource_type="support", description="Docs"
    )
    entity.id = 7

    model = to_model(entity)
    assert model.type == "support"
    assert not hasattr(model, "resource_type")

    restored = to_domain(model)
    assert restored.resource_type is ResourceType.SUPPORT
    assert restored.id == 7
    assert restored.title == "Docs"
    assert restored.slug == "docs"
    assert restored.description == "Docs"
    assert restored.url is None
