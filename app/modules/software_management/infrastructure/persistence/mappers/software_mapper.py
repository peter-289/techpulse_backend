"""Persistence mappers between the software_management domain and its ORM models.

Placed in infrastructure, not in ``app/modules/shared``. A mapper depends on
both the persistence model and the domain entities of exactly one bounded
context, so the shared kernel has no business importing it -- doing so coupled
every module to software_management's aggregates. See
``app/modules/software_management/ARCHITECTURE.md`` section 5.3 and
``docs/adr/0002-mappers-live-in-infrastructure.md``.

The repository is the only caller. Nothing outside
``infrastructure/persistence`` should import from this module.
"""

from __future__ import annotations

from uuid import UUID

from app.infrastructure.database.models.software import (
    SoftwareArtifactModel,
    SoftwareModel,
    SoftwareVersionModel,
)
from app.modules.shared.enums import (
    ArtifactStatus,
    SoftwareStatus,
    SoftwareVisibility,
    VersionStatus,
)
from app.modules.software_management.domain.entities.artifact import Artifact
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.entities.version import Version
from app.modules.software_management.domain.value_objects import SemVer
from app.modules.software_management.domain.value_objects.value_objects import (
    Currency,
    Money,
)


def _artifact_status(raw: str | None) -> ArtifactStatus:
    """Coerce a persisted status string to ``ArtifactStatus``.

    Unknown or missing values fall back to ACTIVE so a row written by an older
    release is still readable.
    """
    try:
        return ArtifactStatus((raw or ArtifactStatus.ACTIVE.value).lower())
    except ValueError:
        return ArtifactStatus.ACTIVE


def _version_status(raw: str | None) -> VersionStatus:
    """Coerce a persisted status string to ``VersionStatus``.

    Anything that is not a recognised version status is treated as DRAFT, since
    treating an unknown value as PUBLISHED would make an unreviewed version
    downloadable.
    """
    candidate = (raw or "").lower()
    if candidate:
        try:
            return VersionStatus(candidate)
        except ValueError:
            pass
    return (
        VersionStatus.PUBLISHED
        if candidate == VersionStatus.PUBLISHED.value.lower()
        else VersionStatus.DRAFT
    )


# --------------------------------------------------------------------------
# ORM model -> domain entity
# --------------------------------------------------------------------------


def _artifact_to_entity(model: SoftwareArtifactModel, version_id: str) -> Artifact:
    return Artifact(
        id=UUID(model.id),
        version_id=UUID(version_id),
        storage_key=model.storage_key,
        sha256=model.file_hash,
        size_bytes=model.size_bytes,
        mime_type=model.content_type,
        filename=model.file_name,
        status=_artifact_status(model.status),
        quarantine_reason=model.quarantine_reason,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _version_to_entity(model: SoftwareVersionModel) -> Version:
    return Version(
        id=UUID(model.id),
        software_id=UUID(model.software_id),
        number=SemVer.parse(model.version),
        release_notes=model.release_notes,
        status=_version_status(model.status),
        lock_version=model.lock_version,
        download_count=model.download_count,
        created_at=model.created_at,
        updated_at=model.updated_at,
        published_at=model.published_at,
        _artifacts=[_artifact_to_entity(artifact, model.id) for artifact in model.artifacts],
    )


def software_to_entity(model: SoftwareModel) -> Software:
    """Rebuild the Software aggregate, with versions and artifacts, from a row."""
    status_value = getattr(model, "status", SoftwareStatus.ACTIVE)
    visibility_value = getattr(model, "visibility", SoftwareVisibility.PUBLIC)
    status_raw = (
        status_value.value
        if isinstance(status_value, SoftwareStatus)
        else str(status_value).lower()
    )
    visibility_raw = (
        visibility_value.value
        if isinstance(visibility_value, SoftwareVisibility)
        else str(visibility_value).lower()
    )
    return Software(
        id=UUID(model.id),
        name=model.name,
        description=model.description,
        owner_id=UUID(model.owner_id),
        status=SoftwareStatus(status_raw),
        visibility=SoftwareVisibility(visibility_raw),
        category_id=model.category_id if getattr(model, "category_id", None) else None,
        price=Money(
            amount_cents=model.price_cents or 0,
            currency=Currency(code=model.currency or "USD"),
        ),
        versions=[_version_to_entity(item) for item in model.versions],
        created_at=model.created_at,
        updated_at=model.updated_at,
        download_count=model.download_count or 0,
    )


# --------------------------------------------------------------------------
# domain entity -> ORM model
# --------------------------------------------------------------------------


def _artifact_to_model(entity: Artifact) -> SoftwareArtifactModel:
    return SoftwareArtifactModel(
        id=str(entity.id),
        version_id=str(entity.version_id),
        storage_key=entity.storage_key,
        file_hash=entity.sha256,
        size_bytes=entity.size_bytes,
        content_type=entity.mime_type,
        file_name=entity.filename,
        status=entity.status.name,
        quarantine_reason=entity.quarantine_reason,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


def _version_to_model(entity: Version) -> SoftwareVersionModel:
    model = SoftwareVersionModel(
        id=str(entity.id),
        software_id=str(entity.software_id),
        version=str(entity.number),
        release_notes=entity.release_notes,
        status=entity.status.name,
        lock_version=entity.lock_version,
        download_count=entity.download_count,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        published_at=entity.published_at,
    )
    model.artifacts = [_artifact_to_model(artifact) for artifact in entity.artifacts]
    return model


def software_to_model(entity: Software) -> SoftwareModel:
    """Project the aggregate onto a detached ORM row for the repository to merge."""
    model = SoftwareModel(
        id=str(entity.id),
        owner_id=str(entity.owner_id),
        name=entity.name,
        description=entity.description,
        visibility=entity.visibility.value,
        category_id=entity.category_id,
        price_cents=entity.price.amount_cents,
        currency=entity.price.currency.code,
        access_policy=entity.access_type,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        download_count=entity.download_count,
    )
    model.versions = [_version_to_model(version) for version in entity.versions]
    return model
