from uuid import UUID

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session, selectinload

from app.domain.software import Artifact, ArtifactStatus, SemVer, Software, SoftwareStatus, SoftwareVisibility, Version, VersionStatus
from app.models.software import SoftwareArtifactModel, SoftwareModel, SoftwareVersionModel


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


class SoftwareRepository:
    def __init__(self, session: Session):
        self.session = session

    def get(self, software_id: UUID) -> Software | None:
        stmt = (
            select(SoftwareModel)
            .where(SoftwareModel.id == str(software_id))
            .options(selectinload(SoftwareModel.versions).selectinload(SoftwareVersionModel.artifact))
        )
        model = self.session.scalar(stmt)
        return _software_to_entity(model) if model else None

    def save(self, software: Software) -> None:
        self.session.merge(_software_to_model(software))

    def list_visible_for_user(self, user_id: UUID, *, limit: int = 100) -> list[Software]:
        stmt = (
            select(SoftwareModel)
            .where(or_(SoftwareModel.is_public.is_(True), SoftwareModel.owner_id == str(user_id)))
            .order_by(SoftwareModel.created_at.desc())
            .limit(limit)
            .options(selectinload(SoftwareModel.versions).selectinload(SoftwareVersionModel.artifact))
        )
        return [_software_to_entity(item) for item in self.session.scalars(stmt).all()]

    def increment_download_count(self, version_id: UUID) -> None:
        stmt = (
            update(SoftwareVersionModel)
            .where(SoftwareVersionModel.id == str(version_id))
            .values(download_count=SoftwareVersionModel.download_count + 1)
        )
        self.session.execute(stmt)
