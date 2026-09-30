"""Persistence port for the Resource aggregate.

The port talks in domain entities, so nothing above ``infrastructure`` can see
a ``SELECT`` or an ORM row. Ordering by creation date descending is part of the
contract because ``GET /api/v1/resources`` relies on it to return the newest
first.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.modules.resource.domain.entities.resource import Resource


@runtime_checkable
class ResourceRepository(Protocol):
    """Storage boundary for resources."""

    async def add(self, resource: Resource) -> Resource:
        """Persist a new resource and return it with its assigned id."""
        ...

    async def get_by_slug(self, slug: str) -> Resource | None:
        """Return the resource with this slug, or ``None``."""
        ...

    async def list_resources(self, type_filter: str | None = None) -> list[Resource]:
        """Return resources newest first, optionally restricted to a type.

        An absent or blank filter returns every resource; it must never return
        ``None``.
        """
        ...

    async def delete(self, resource: Resource) -> None:
        """Remove the resource."""
        ...
