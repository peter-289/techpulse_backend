"""Resource use cases, exercised without a database.

The service used to hold a mutable ``ALLOWED_TYPES`` set, normalize five fields
inline, and raise shared-kernel errors. These tests pin what replaced it: the
vocabulary lives in ``ResourceType``, normalization in ``Resource.create``, and
the service only orchestrates the transaction.

The fake Unit of Work records whether a *write* transaction was opened at all,
because the invalid-type path is supposed to fail before it does.
"""

from __future__ import annotations

import pytest

from app.modules.resource.application.services.resource_service import ResourceService
from app.modules.resource.domain.entities.resource import Resource
from app.modules.resource.domain.exceptions import (
    DuplicateResourceSlugError,
    InvalidResourceTypeError,
    ResourceNotFoundError,
)
from app.modules.resource.domain.value_objects.resource_type import ResourceType


class _FakeRepo:
    def __init__(self, existing: Resource | None = None) -> None:
        self.existing = existing
        self.saved: list[Resource] = []
        self.deleted: list[Resource] = []
        self.list_calls: list[str | None] = []
        self.get_calls: list[str] = []

    async def add(self, resource: Resource) -> Resource:
        resource.id = 1
        self.saved.append(resource)
        return resource

    async def get_by_slug(self, slug: str) -> Resource | None:
        self.get_calls.append(slug)
        return self.existing

    async def list_resources(self, type_filter: str | None = None) -> list[Resource]:
        self.list_calls.append(type_filter)
        return []

    async def delete(self, resource: Resource) -> None:
        self.deleted.append(resource)


class _FakeUow:
    def __init__(self, repo: _FakeRepo) -> None:
        self.resource_repo = repo
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


def _service(*, existing: Resource | None = None) -> tuple[ResourceService, _FakeUow]:
    repo = _FakeRepo(existing=existing)
    uow = _FakeUow(repo)
    return ResourceService(uow), uow


def _existing() -> Resource:
    return Resource.create(
        title="Docs", slug="docs", resource_type="api", description="Docs"
    )


# === create ===

@pytest.mark.asyncio
async def test_create_persists_a_normalized_resource() -> None:
    service, uow = _service()

    created = await service.create_resource(
        title="  API Docs  ",
        slug="  API-Docs  ",
        resource_type="API",
        description="  Docs.  ",
        url="  https://example.com  ",
    )

    assert created.slug == "api-docs"
    assert created.resource_type is ResourceType.API
    assert created.id == 1
    assert uow.resource_repo.saved == [created]


@pytest.mark.asyncio
async def test_create_rejects_an_invalid_type_without_opening_a_transaction() -> None:
    """The type check must not cost a connection.

    It is a domain rule, so it can run before the unit of work is entered.
    """
    service, uow = _service()

    with pytest.raises(InvalidResourceTypeError):
        await service.create_resource(
            title="Docs", slug="docs", resource_type="blogs", description="Docs"
        )

    assert uow.writes == 0
    assert uow.resource_repo.saved == []


@pytest.mark.asyncio
async def test_create_rejects_a_taken_slug_against_the_normalized_slug() -> None:
    """``Docs`` and ``docs`` are the same slug, so the duplicate must be caught."""
    service, uow = _service(existing=_existing())

    with pytest.raises(DuplicateResourceSlugError):
        await service.create_resource(
            title="Other", slug="DOCS", resource_type="api", description="Other"
        )

    assert uow.resource_repo.get_calls == ["docs"]
    assert uow.resource_repo.saved == []


@pytest.mark.asyncio
async def test_create_looks_the_slug_up_after_normalizing_it() -> None:
    service, uow = _service()

    await service.create_resource(
        title="Docs", slug="  New-Docs  ", resource_type="api", description="Docs"
    )

    assert uow.resource_repo.get_calls == ["new-docs"]


# === read ===

@pytest.mark.asyncio
async def test_get_by_slug_missing_raises_not_found() -> None:
    service, _ = _service()

    with pytest.raises(ResourceNotFoundError):
        await service.get_by_slug(slug="nope")


@pytest.mark.asyncio
async def test_get_by_slug_returns_the_entity_and_uses_a_read_only_transaction() -> None:
    service, uow = _service(existing=_existing())

    found = await service.get_by_slug(slug="docs")

    assert found.slug == "docs"
    assert uow.reads == 1
    assert uow.writes == 0


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (None, None),
        ("", None),
        # Whitespace-only normalizes to "" rather than None. Both are falsy so
        # the repository applies no filter either way, and the pre-domain
        # service passed "" here too, so the value is left as it lands.
        ("  ", ""),
        ("API", "api"),
        ("  Knowledge  ", "knowledge"),
    ],
)
@pytest.mark.asyncio
async def test_list_normalizes_the_type_filter(given, expected) -> None:
    service, uow = _service()

    await service.list_resources(type_filter=given)

    assert uow.resource_repo.list_calls == [expected]


@pytest.mark.asyncio
async def test_list_does_not_validate_the_type_filter() -> None:
    """An unknown filter is an empty result, not a 422.

    Pre-existing contract. A read path that stays usable as a lookup is worth
    more than symmetry with the write path, so it is kept deliberately.
    """
    service, uow = _service()

    await service.list_resources(type_filter="nope")

    assert uow.resource_repo.list_calls == ["nope"]


# === delete ===

@pytest.mark.asyncio
async def test_delete_missing_raises_not_found() -> None:
    service, _ = _service()

    with pytest.raises(ResourceNotFoundError):
        await service.delete_resource(slug="nope")


@pytest.mark.asyncio
async def test_delete_removes_the_loaded_resource() -> None:
    service, uow = _service(existing=_existing())

    await service.delete_resource(slug="docs")

    assert [r.slug for r in uow.resource_repo.deleted] == ["docs"]
