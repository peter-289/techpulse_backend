from app.modules.software_management.software_service import SoftwareService
from app.modules.software_management.software_schema import SoftwareRead, SoftwareVersionRead, SoftwareCheckoutRead
from app.modules.software_management.software.software import Software, SoftwareStatus, SoftwareVisibility
from app.modules.software_management.software.version import Version
from app.infrastructure.database.models.software import SoftwareArtifactModel, SoftwareModel, SoftwareVersionModel
from app.infrastructure.database.models.software import SoftwareArtifactModel
from app.modules.software_management.software.artifact import Artifact
from app.modules.software_management.software.value_objects import SemVer, SoftwareCard
from techpulse_backend.app.modules.software_management import software
from .software.exceptions import SoftwareAccessDeniedError, SoftwareNotFoundError, SoftwareDomainError
from .software.enums import ArtifactStatus, VersionStatus


from uuid import UUID
from fastapi import HTTPException, status


def _category(description: str) -> str:
    for line in (description or "").splitlines(keepends=True):
        if line.lower().startswith("category:"):
            return line.split(":", 1)[1].strip().lower() or "others"
    return "others"


def _software_item(software: Software, *, viewer_user_id: int) -> SoftwareRead:
    latest = software.latest_downloadable()
    viewer = SoftwareService.actor_uuid(viewer_user_id)
    return SoftwareRead(
        id=str(software.id),
        name=software.name,
        description=software.description,
        owner_id=SoftwareService.actor_int(software.owner_id),
        is_public=software.visibility.value == "public",
        price_cents=software.price_cents,
        currency=software.currency,
        viewer_has_access=software.owner_id == viewer or software.price_cents == 0,
        category=_category(software.description),
        latest_version=str(latest.number) if latest else None,
        download_count=sum(version.download_count for version in software.versions),
        created_at=software.created_at.isoformat(),
        updated_at=software.updated_at.isoformat(),
    )


def _version_item(version: Version) -> SoftwareVersionRead:
    artifact = version.artifact
    return SoftwareVersionRead(
        id=str(version.id),
        software_id=str(version.software_id),
        version=str(version.number),
        is_published=version.status.value in {"published", "deprecated"},
        status=version.status.value,
        download_count=version.download_count,
        release_notes=version.release_notes,
        created_at=version.created_at.isoformat(),
        published_at=version.published_at.isoformat() if version.published_at else None,
        file_hash=artifact.sha256 if artifact else None,
        size_bytes=artifact.size_bytes if artifact else None,
        content_type=artifact.mime_type if artifact else None,
        file_name=artifact.filename if artifact else None,
        artifact_status=artifact.status.value if artifact else None,
        quarantine_reason=artifact.quarantine_reason if artifact else None,
    )


def _payment_item(payment) -> SoftwareCheckoutRead:
    return SoftwareCheckoutRead(
        id=payment.id,
        software_id=payment.software_id,
        buyer_id=SoftwareService.actor_int(UUID(payment.buyer_id)),
        owner_id=SoftwareService.actor_int(UUID(payment.owner_id)),
        amount_cents=payment.amount_cents,
        currency=payment.currency,
        status=payment.status,
        provider=payment.provider,
        provider_reference=payment.provider_reference,
        created_at=payment.created_at.isoformat(),
        completed_at=payment.completed_at.isoformat() if payment.completed_at else None,
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


def _version_status(raw: str | None, is_published: bool) -> VersionStatus:
    candidate = (raw or "").lower()
    if candidate:
        try:
            return VersionStatus(candidate)
        except ValueError:
            pass
    return VersionStatus.PUBLISHED if is_published else VersionStatus.DRAFT


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
        status=_version_status(model.status, model.is_published),
        lock_version=model.lock_version,
        download_count=model.download_count,
        created_at=model.created_at,
        updated_at=model.updated_at,
        published_at=model.published_at,
        artifact=_artifact_to_entity(model.artifact, model.id) if model.artifact else None,
    )


def _software_to_entity(model: SoftwareModel) -> Software:
    return Software(
        id=UUID(model.id),
        name=model.name,
        description=model.description,
        owner_id=UUID(model.owner_id),
        status=SoftwareStatus.ACTIVE,
        visibility=SoftwareVisibility.PUBLIC if model.is_public else SoftwareVisibility.PRIVATE,
        price_cents=model.price_cents or 0,
        currency=model.currency or "USD",
        versions=[_version_to_entity(item) for item in model.versions],
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _artifact_to_model(entity: Artifact) -> SoftwareArtifactModel:
    return SoftwareArtifactModel(
        id=str(entity.id),
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
        is_published=entity.status in {VersionStatus.PUBLISHED, VersionStatus.DEPRECATED},
        status=entity.status.name,
        lock_version=entity.lock_version,
        download_count=entity.download_count,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        published_at=entity.published_at,
    )
    if entity.artifact is not None:
        artifact = _artifact_to_model(entity.artifact)
        model.artifact = artifact
        model.artifact_id = artifact.id
    return model


def _software_to_model(entity: Software) -> SoftwareModel:
    model = SoftwareModel(
        id=str(entity.id),
        owner_id=str(entity.owner_id),
        name=entity.name,
        description=entity.description,
        is_public=entity.visibility == SoftwareVisibility.PUBLIC,
        price_cents=entity.price_cents,
        currency=entity.currency,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )
    model.versions = [_version_to_model(version) for version in entity.versions]
    return model


