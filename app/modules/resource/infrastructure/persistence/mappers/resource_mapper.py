"""Translation between the Resource entity and the ``resources`` table.

Kept in infrastructure because the two spellings of "type" exist only at the
edges: the domain calls it ``resource_type`` to avoid shadowing the builtin, the
column and the API have always called it ``type``.
"""

from __future__ import annotations

from app.infrastructure.database.models.resource import Resource as ResourceModel
from app.modules.resource.domain.entities.resource import Resource
from app.modules.resource.domain.value_objects.resource_type import ResourceType


def to_domain(model: ResourceModel) -> Resource:
    """Map a database row onto a domain entity."""
    return Resource(
        id=model.id,
        title=model.title,
        slug=model.slug,
        resource_type=ResourceType(model.type),
        description=model.description,
        url=model.url,
        created_at=model.created_at,
    )


def to_model(resource: Resource) -> ResourceModel:
    """Map a domain entity onto a database row."""
    return ResourceModel(
        id=resource.id,
        title=resource.title,
        slug=resource.slug,
        type=resource.resource_type.value,
        description=resource.description,
        url=resource.url,
        created_at=resource.created_at,
    )
