from __future__ import annotations

from uuid import UUID
from fastapi import HTTPException, status

from app.modules.software_management.domain.entities.artifact import Artifact
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.entities.version import Version
from app.modules.software_management.schema.software_schema import ArtifactResponse, SoftwareRead, SoftwareVersionRead
from app.modules.shared.enums import ArtifactStatus, VersionStatus, SoftwareStatus, SoftwareVisibility
from app.infrastructure.database.models.software import SoftwareArtifactModel, SoftwareModel, SoftwareVersionModel

from app.modules.software_management.domain.exceptions import SoftwareDomainError, SoftwareAccessDeniedError, SoftwareNotFoundError
from app.modules.software_management.domain.value_objects import SemVer
from app.modules.software_management.domain.value_objects.value_objects import Currency, Money


def _actor_uuid(user_id: int) -> UUID:
    try:
        return UUID(int=max(0, int(user_id)))
    except Exception:
        # fallback for non-numeric inputs
        return UUID(int=0)


def _actor_int(user_id: UUID) -> int:
    return int(user_id.int)


def _category(description: str) -> str:
    for line in (description or "").splitlines(keepends=True):
        if line.lower().startswith("category:"):
            return line.split(":", 1)[1].strip().lower() or "others"
    return "others"


def _software_item(software: Software, *, viewer_user_id: UUID) -> SoftwareRead:
    latest = software.latest_downloadable()
    return SoftwareRead(
        id=str(software.id),
        name=software.name,
        description=software.description,
        owner_id=int(software.owner_id.int),
        is_public=software.visibility.value == "public",
        price_cents=software.price.amount_cents,
        currency=software.price.currency.code,
        viewer_has_access=software.owner_id == viewer_user_id or software.price.amount_cents == 0,
        category=_category(software.description),
        latest_version=str(latest.number) if latest else None,
        download_count=software.download_count,
        created_at=software.created_at.isoformat(),
        updated_at=software.updated_at.isoformat(),
    )


def _version_item(version: Version) -> SoftwareVersionRead:
    """Version read model"""
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




def _error(exc: SoftwareDomainError) -> HTTPException:
    if isinstance(exc, SoftwareAccessDeniedError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, SoftwareNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


def _artifact_status(raw: str | None) -> ArtifactStatus:
    try:
        return ArtifactStatus((raw or ArtifactStatus.ACTIVE.value).lower())
    except ValueError:
        return ArtifactStatus.ACTIVE


def _version_status(raw: str | None) -> VersionStatus:
    candidate = (raw or "").lower()
    if candidate:
        try:
            return VersionStatus(candidate)
        except ValueError:
            pass
    return VersionStatus.PUBLISHED if candidate == VersionStatus.PUBLISHED.value.lower() else VersionStatus.DRAFT


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


def _software_to_entity(model: SoftwareModel) -> Software:
    status_value = getattr(model, "status", SoftwareStatus.ACTIVE)
    visibility_value = getattr(model, "visibility", SoftwareVisibility.PUBLIC)
    status_raw = status_value.value if isinstance(status_value, SoftwareStatus) else str(status_value).lower()
    visibility_raw = (
        visibility_value.value if isinstance(visibility_value, SoftwareVisibility) else str(visibility_value).lower()
    )
    return Software(
        id=UUID(model.id),
        name=model.name,
        description=model.description,
        owner_id=UUID(model.owner_id),
        status=SoftwareStatus(status_raw),
        visibility=SoftwareVisibility(visibility_raw),
        category_id=model.category_id if getattr(model, "category_id", None) else None,
        price=Money(amount_cents=model.price_cents or 0, currency=Currency(code=model.currency or "USD")),
        versions=[_version_to_entity(item) for item in model.versions],
        created_at=model.created_at,
        updated_at=model.updated_at,
        download_count=model.download_count or 0,
    )


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


def _software_to_model(entity: Software) -> SoftwareModel:
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
