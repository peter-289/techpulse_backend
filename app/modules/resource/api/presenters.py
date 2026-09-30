"""Entity-to-schema translation for the resource context.

The API field is ``type`` and the domain field is ``resource_type``; that
rename exists so the aggregate does not shadow the builtin. The presenter is
the one place that knows both spellings.
"""

from __future__ import annotations

from app.modules.resource.domain.entities.resource import Resource
from app.modules.resource.schema.resource_schema import ResourceRead


def resource_read(resource: Resource) -> ResourceRead:
    return ResourceRead(
        id=resource.id,
        title=resource.title,
        slug=resource.slug,
        type=resource.resource_type.value,
        description=resource.description,
        url=resource.url,
        created_at=resource.created_at,
    )
