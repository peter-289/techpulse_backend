"""The Resource aggregate root.

Deliberately thin. Resources have no lifecycle, no state machine and no
invariants that span more than one instance: the only rules are "the type is in
the vocabulary" and "trimmed text is stored trimmed". Those are enforced in
``create``, which is the sole construction path, and in ``ResourceType``.

Two things a reader might expect to find here and will not:

* **No ``update``/``retitle``.** The API exposes no edit route, so the aggregate
  has no mutator for one. Adding an unused mutator would put normalization in
  two places.
* **No ``delete``.** Removal is a hard ``DELETE``, which is a statement about
  the row rather than a change of the resource's state, so the repository
  owns it. See the "why hard delete" note in ``docs/REVIEW.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.modules.resource.domain.value_objects.resource_type import ResourceType


@dataclass(slots=True)
class Resource:
    """A documentation or support resource.

    ``resource_type`` is named for the domain; the ``type`` column and the
    ``type`` API field keep their existing spelling so the wire format and the
    database are untouched. The mapping between the two lives in the mapper and
    the presenter.
    """

    title: str
    slug: str
    resource_type: ResourceType
    description: str
    url: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: int | None = None

    @classmethod
    def create(
        cls,
        *,
        title: str,
        slug: str,
        resource_type: str,
        description: str,
        url: str | None = None,
    ) -> "Resource":
        """Build a resource from untrusted input.

        Normalizes the way the service used to: title, slug, type and
        description are trimmed, the slug and type are lowercased, and a blank
        URL becomes ``None`` rather than an empty string.
        """
        return cls(
            title=title.strip(),
            slug=slug.strip().lower(),
            resource_type=ResourceType.from_input(resource_type),
            description=description.strip(),
            url=(url or "").strip() or None,
        )
