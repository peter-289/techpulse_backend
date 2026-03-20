from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import AsyncIterator
from uuid import UUID


@dataclass(frozen=True, slots=True)
class StoredObject:
    storage_key: str
    file_hash: str
    size_bytes: int
    file_name: str
    content_type: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class UploadSoftwareInput:
    actor_id: str
    software_name: str
    software_description: str
    version: str
    file_name: str
    content_type: str
    stream: AsyncIterator[bytes]
    is_public: bool = True
    software_id: UUID | None = None
    publish_now: bool = False
    expected_software_row_version: int | None = None
    idempotency_key: str | None = None
    expected_file_hash: str | None = None


@dataclass(frozen=True, slots=True)
class UploadSoftwareOutput:
    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    version: str
    file_hash: str
    size_bytes: int
    software_row_version: int
    published: bool


@dataclass(frozen=True, slots=True)
class PublishVersionInput:
    actor_id: str
    software_id: UUID
    version: str
    expected_software_row_version: int | None = None
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class PublishVersionOutput:
    software_id: UUID
    version_id: UUID
    version: str
    published_at: datetime
    software_row_version: int


@dataclass(frozen=True, slots=True)
class DeprecateVersionInput:
    actor_id: str
    software_id: UUID
    version: str
    expected_software_row_version: int | None = None


@dataclass(frozen=True, slots=True)
class DeprecateVersionOutput:
    software_id: UUID
    version_id: UUID
    version: str
    deprecated_at: datetime
    software_row_version: int


@dataclass(frozen=True, slots=True)
class RevokeVersionInput:
    actor_id: str
    software_id: UUID
    version: str
    expected_software_row_version: int | None = None
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class RevokeVersionOutput:
    software_id: UUID
    version_id: UUID
    version: str
    revoked_at: datetime
    software_row_version: int


@dataclass(frozen=True, slots=True)
class DownloadSoftwareInput:
    actor_id: str
    software_id: UUID
    version: str


@dataclass(frozen=True, slots=True)
class DownloadSoftwareOutput:
    software_id: UUID
    version_id: UUID
    version: str
    file_name: str
    content_type: str
    size_bytes: int
    file_hash: str
    stream: AsyncIterator[bytes]


@dataclass(frozen=True, slots=True)
class DeleteSoftwareInput:
    actor_id: str
    software_id: UUID
    expected_software_row_version: int | None = None


@dataclass(frozen=True, slots=True)
class DeleteSoftwareOutput:
    software_id: UUID
    deleted_versions: int
    deleted_artifacts: int


@dataclass(frozen=True, slots=True)
class ListSoftwareInput:
    actor_id: str
    offset: int = 0
    limit: int = 100


@dataclass(frozen=True, slots=True)
class SoftwareListItem:
    id: UUID
    owner_id: str
    name: str
    description: str
    is_public: bool
    latest_version: str | None
    latest_version_id: UUID | None
    download_count: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ListVersionsInput:
    actor_id: str
    software_id: UUID
    limit: int = 20


@dataclass(frozen=True, slots=True)
class VersionListItem:
    id: UUID
    software_id: UUID
    version: str
    is_published: bool
    download_count: int
    file_name: str
    content_type: str
    size_bytes: int
    file_hash: str
    created_at: datetime
    published_at: datetime | None


@dataclass(frozen=True, slots=True)
class AdminSummaryOutput:
    total_packages: int
    private_packages: int
    public_packages: int
    total_versions: int
    total_downloads: int


@dataclass(frozen=True, slots=True)
class AdminSoftwareItem:
    package_id: UUID
    name: str
    owner_id: str
    is_public: bool
    latest_version: str | None
    download_count: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ListAdminSoftwareInput:
    offset: int = 0
    limit: int = 100
