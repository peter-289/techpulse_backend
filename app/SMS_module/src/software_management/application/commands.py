from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class CreateSoftwareCommand:
    name: str
    description: str
    owner_id: UUID
    visibility: str = "public"


@dataclass(frozen=True, slots=True)
class AddVersionCommand:
    software_id: UUID
    number: str
    release_notes: str


@dataclass(frozen=True, slots=True)
class RequestArtifactUploadCommand:
    software_id: UUID
    version_id: UUID
    filename: str
    content_type: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ProcessMalwareScanSuccessCommand:
    software_id: UUID
    version_id: UUID
    artifact_id: UUID


@dataclass(frozen=True, slots=True)
class ProcessMalwareScanFailedCommand:
    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class PublishVersionCommand:
    software_id: UUID
    version_id: UUID


@dataclass(frozen=True, slots=True)
class GenerateDownloadLinkQuery:
    user_id: UUID
    software_id: UUID
    version_id: UUID | None = None
