"""The Resource aggregate and its type vocabulary.

Covers the rules that used to sit on ``ResourceService`` as string manipulation:
``ALLOWED_TYPES`` membership, and the trim/lower coercion applied to every
field on the way in.
"""

from __future__ import annotations

import pytest

from app.modules.resource.domain.entities.resource import Resource
from app.modules.resource.domain.exceptions import InvalidResourceTypeError
from app.modules.resource.domain.value_objects.resource_type import ResourceType


def test_create_normalizes_every_field() -> None:
    resource = Resource.create(
        title="  API Docs  ",
        slug="  API-Docs  ",
        resource_type="API",
        description="  How to call us.  ",
        url="  https://example.com/docs  ",
    )

    assert resource.title == "API Docs"
    assert resource.slug == "api-docs"
    assert resource.resource_type is ResourceType.API
    assert resource.description == "How to call us."
    assert resource.url == "https://example.com/docs"


@pytest.mark.parametrize("blank", [None, "", "   "])
def test_blank_url_becomes_none_rather_than_empty_string(blank) -> None:
    """A blank URL is absent, not a link to nowhere.

    ``url or ""`` then ``or None`` existed to stop ``""`` reaching a
    ``varchar(500)`` that would serialize as an empty string in the API.
    """
    resource = Resource.create(
        title="Docs",
        slug="docs",
        resource_type="knowledge",
        description="Docs",
        url=blank,
    )
    assert resource.url is None


@pytest.mark.parametrize("raw", ["api", "API", "Knowledge", "SUPPORT", "updates"])
def test_type_vocabulary_accepts_its_members_case_insensitively(raw: str) -> None:
    assert ResourceType.from_input(raw) in set(ResourceType)


@pytest.mark.parametrize("raw", ["", "blogs", "api docs", "api-doc", "apis"])
def test_type_vocabulary_rejects_anything_else(raw: str) -> None:
    with pytest.raises(InvalidResourceTypeError):
        ResourceType.from_input(raw)


def test_rejection_message_lists_the_allowed_types() -> None:
    """The 422 body is part of the contract and used to come from the service."""
    with pytest.raises(InvalidResourceTypeError) as excinfo:
        ResourceType.from_input("blogs")

    assert str(excinfo.value) == (
        "Invalid resource type. Allowed: api, knowledge, support, updates"
    )


def test_padded_type_is_rejected_even_though_it_would_normalize_to_a_valid_one() -> None:
    """Documents an inherited quirk rather than silently changing the contract.

    The service tested ``raw.lower()`` against the allowed set but stored
    ``raw.strip().lower()``, so ``" api "`` was rejected even though stripping
    it yields a legal type. Normalizing first would widen the accepted set,
    which is an API change, so the behaviour is preserved and flagged in
    ``docs/REVIEW.md``.
    """
    with pytest.raises(InvalidResourceTypeError):
        ResourceType.from_input(" api ")


def test_create_rejects_an_invalid_type_before_any_persistence() -> None:
    with pytest.raises(InvalidResourceTypeError):
        Resource.create(
            title="Docs",
            slug="docs",
            resource_type="blogs",
            description="Docs",
        )


def test_created_resource_has_an_id_only_once_persisted() -> None:
    resource = Resource.create(
        title="Docs", slug="docs", resource_type="api", description="Docs"
    )
    assert resource.id is None


def test_type_serializes_to_its_wire_value() -> None:
    """The API field is a string, so the enum must serialize to ``"api"``."""
    resource = Resource.create(
        title="Docs", slug="docs", resource_type="api", description="Docs"
    )
    assert resource.resource_type.value == "api"
    assert str(resource.resource_type) == "api"
