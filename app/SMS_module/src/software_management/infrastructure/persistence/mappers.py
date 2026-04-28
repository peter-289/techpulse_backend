from __future__ import annotations

from uuid import UUID

from ...domain.entities.artifact import Artifact
from ...domain.entities.software import Software
from ...domain.entities.version import Version
from ...domain.enums import ArtifactStatus, SoftwareStatus, SoftwareVisibility, VersionStatus
from ...domain.value_objects import SemVer
from .sqlalchemy_models import ArtifactModel, SoftwareModel, VersionModel


def artifact_model_to_entity(model: ArtifactModel) -> Artifact:
    return Artifact(
        id=UUID(model.id),
        version_id=UUID(model.version_id),
        storage_key=model.storage_key,
        sha256=model.sha256,
        size_bytes=model.size_bytes,
        mime_type=model.mime_type,
        filename=model.filename,
        status=ArtifactStatus(model.status),
        quarantine_reason=model.quarantine_reason,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def version_model_to_entity(model: VersionModel) -> Version:
    artifact = artifact_model_to_entity(model.artifact) if model.artifact is not None else None
    return Version(
        id=UUID(model.id),
        software_id=UUID(model.software_id),
        number=SemVer.parse(model.number),
        release_notes=model.release_notes,
        status=VersionStatus(model.status),
        lock_version=model.lock_version,
        created_at=model.created_at,
        updated_at=model.updated_at,
        published_at=model.published_at,
        artifact=artifact,
    )


def software_model_to_entity(model: SoftwareModel) -> Software:
    return Software(
        id=UUID(model.id),
        name=model.name,
        description=model.description,
        owner_id=UUID(model.owner_id),
        status=SoftwareStatus(model.status),
        visibility=SoftwareVisibility(model.visibility),
        versions=[version_model_to_entity(item) for item in model.versions],
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def artifact_entity_to_model(entity: Artifact) -> ArtifactModel:
    return ArtifactModel(
        id=str(entity.id),
        version_id=str(entity.version_id),
        storage_key=entity.storage_key,
        sha256=entity.sha256,
        size_bytes=entity.size_bytes,
        mime_type=entity.mime_type,
        filename=entity.filename,
        status=entity.status.value,
        quarantine_reason=entity.quarantine_reason,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


def version_entity_to_model(entity: Version) -> VersionModel:
    model = VersionModel(
        id=str(entity.id),
        software_id=str(entity.software_id),
        number=str(entity.number),
        release_notes=entity.release_notes,
        status=entity.status.value,
        lock_version=entity.lock_version,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        published_at=entity.published_at,
    )
    if entity.artifact is not None:
        model.artifact = artifact_entity_to_model(entity.artifact)
    return model


def software_entity_to_model(entity: Software) -> SoftwareModel:
    model = SoftwareModel(
        id=str(entity.id),
        name=entity.name,
        description=entity.description,
        owner_id=str(entity.owner_id),
        status=entity.status.value,
        visibility=entity.visibility.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )
    model.versions = [version_entity_to_model(item) for item in entity.versions]
    return model
