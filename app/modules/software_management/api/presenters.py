"""Response presenters for the software_management API layer.

Turns domain entities into the Pydantic response models declared in
``schema/software_schema.py``. This is transport shaping, so it belongs in the
API layer rather than in the application layer: an application service that
returns a Pydantic model has taken a dependency on the wire format, and the
moment the same use case is reached over a message or a CLI the shape is wrong.

Routers are the only callers.
"""

from __future__ import annotations

from uuid import UUID

from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.entities.version import Version
from app.modules.software_management.schema.software_schema import (
    ArtifactResponse,
    SoftwareRead,
    SoftwareVersionRead,
)


def _category(description: str) -> str:
    """Derive a display category from the leading ``Category:`` line.

    Temporary shim: the Software aggregate has a ``category_id`` but no
    category name, and the read model still exposes a free-text ``category``.
    Replace with a join against the Category aggregate once
    ``ARCHITECTURE.md`` section 4.4's Category lookup is reachable from the
    software read path.
    """
    for line in (description or "").splitlines(keepends=True):
        if line.lower().startswith("category:"):
            return line.split(":", 1)[1].strip().lower() or "others"
    return "others"


def software_item(software: Software, *, viewer_user_id: UUID) -> SoftwareRead:
    """Render a Software aggregate as a read model for ``viewer_user_id``."""
    latest = software.latest_downloadable()
    return SoftwareRead(
        id=str(software.id),
        name=software.name,
        description=software.description,
        owner_id=int(software.owner_id.int),
        is_public=software.visibility.value == "public",
        price_cents=software.price.amount_cents,
        currency=software.price.currency.code,
        viewer_has_access=(
            software.owner_id == viewer_user_id or software.price.amount_cents == 0
        ),
        category=_category(software.description),
        latest_version=str(latest.number) if latest else None,
        download_count=software.download_count,
        created_at=software.created_at.isoformat(),
        updated_at=software.updated_at.isoformat(),
    )


def version_item(version: Version) -> SoftwareVersionRead:
    """Render a Version entity, with its artifacts, as a read model."""
    return SoftwareVersionRead(
        id=version.id,
        software_id=version.software_id,
        version=version.number,
        status=version.status,
        download_count=version.download_count,
        release_notes=version.release_notes,
        created_at=version.created_at,
        published_at=version.published_at,
        artifacts=[
            ArtifactResponse(
                id=artifact.id,
                filename=artifact.filename,
                size_bytes=artifact.size_bytes,
                sha256=artifact.sha256,
                content_type=artifact.mime_type,
                status=artifact.status.value,
            )
            for artifact in version.artifacts
        ],
    )
