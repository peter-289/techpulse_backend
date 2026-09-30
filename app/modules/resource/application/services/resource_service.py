"""Resource use cases.

The service orchestrates: it opens the transaction, asks the port whether a
slug is taken, and delegates every rule to the domain. There is no normalization
and no type vocabulary here any more.
"""

from __future__ import annotations

from app.modules.resource.domain.entities.resource import Resource
from app.modules.resource.domain.exceptions import (
    DuplicateResourceSlugError,
    ResourceNotFoundError,
)
from app.modules.resource.domain.ports.unit_of_work import ResourceUnitOfWork


class ResourceService:
    def __init__(self, uow: ResourceUnitOfWork):
        self.uow = uow

    async def list_resources(self, type_filter: str | None = None) -> list[Resource]:
        """Return resources newest first, optionally filtered by type.

        The filter is normalized for comparison but not validated: an unknown
        type is an empty result set, not an error. That is the pre-existing
        contract and it is worth keeping -- the read path stays usable as a
        lookup even if a caller knows a type the vocabulary has since dropped.
        """
        normalized = type_filter.strip().lower() if type_filter else None
        async with self.uow.read_only():
            return await self.uow.resource_repo.list_resources(type_filter=normalized)

    async def get_by_slug(self, slug: str) -> Resource:
        async with self.uow.read_only():
            resource = await self.uow.resource_repo.get_by_slug(slug=slug)
            if not resource:
                raise ResourceNotFoundError("Resource not found")
            return resource

    async def create_resource(
        self,
        *,
        title: str,
        slug: str,
        resource_type: str,
        description: str,
        url: str | None = None,
    ) -> Resource:
        """Create a resource, rejecting a slug that is already taken.

        Takes the fields individually rather than a pydantic model: the request
        schema belongs to the transport layer, and a use case that imports it
        couples the domain to FastAPI's validation rules.
        """
        # Built before the transaction opens so an invalid type cannot open one.
        # ValidationError was previously raised here for the same reason.
        resource = Resource.create(
            title=title,
            slug=slug,
            resource_type=resource_type,
            description=description,
            url=url,
        )
        async with self.uow:
            existing = await self.uow.resource_repo.get_by_slug(slug=resource.slug)
            if existing:
                raise DuplicateResourceSlugError("Resource slug already exists")
            return await self.uow.resource_repo.add(resource)

    async def delete_resource(self, slug: str) -> None:
        async with self.uow:
            resource = await self.uow.resource_repo.get_by_slug(slug=slug)
            if not resource:
                raise ResourceNotFoundError("Resource not found")
            await self.uow.resource_repo.delete(resource)
