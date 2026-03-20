from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import AsyncIterable, AsyncIterator, Protocol
from uuid import UUID

from .dtos import StoredObject


@dataclass(frozen=True, slots=True)
class CreateVersionCommand:
    actor_id: str
    software_name: str
    software_description: str
    version: str
    artifact_storage_key: str
    artifact_file_hash: str
    artifact_size_bytes: int
    artifact_file_name: str
    artifact_content_type: str
    is_public: bool
    software_id: UUID | None = None
    publish_now: bool = False
    expected_software_row_version: int | None = None


@dataclass(frozen=True, slots=True)
class CreateVersionResult:
    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    version: str
    software_row_version: int
    published: bool


@dataclass(frozen=True, slots=True)
class PublishVersionResult:
    software_id: UUID
    version_id: UUID
    owner_id: str
    version: str
    published_at: datetime
    software_row_version: int


@dataclass(frozen=True, slots=True)
class DeprecateVersionResult:
    software_id: UUID
    version_id: UUID
    owner_id: str
    version: str
    deprecated_at: datetime
    software_row_version: int


@dataclass(frozen=True, slots=True)
class RevokeVersionResult:
    software_id: UUID
    version_id: UUID
    owner_id: str
    version: str
    revoked_at: datetime
    software_row_version: int


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    scope: str
    actor_id: str
    key: str
    request_hash: str
    response_json: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class DownloadDescriptor:
    software_id: UUID
    version_id: UUID
    owner_id: str
    version: str
    published: bool
    file_name: str
    content_type: str
    size_bytes: int
    file_hash: str
    storage_key: str


@dataclass(frozen=True, slots=True)
class DeleteSoftwareResult:
    software_id: UUID
    deleted_versions: int
    deleted_artifacts: int
    storage_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SoftwareListRecord:
    id: UUID
    owner_id: str
    name: str
    description: str
    is_public: bool
    latest_version: str | None
    latest_version_id: UUID | None
    latest_download_count: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class VersionListRecord:
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
class AdminSummaryRecord:
    total_packages: int
    private_packages: int
    public_packages: int
    total_versions: int
    total_downloads: int


@dataclass(frozen=True, slots=True)
class AdminSoftwareRecord:
    package_id: UUID
    name: str
    owner_id: str
    is_public: bool
    latest_version: str | None
    download_count: int
    created_at: datetime
    updated_at: datetime


class SoftwareRepository(Protocol):
    async def get_software_owner(self, software_id: UUID) -> str | None:
        ...

    async def create_version(self, command: CreateVersionCommand) -> CreateVersionResult:
        ...

    async def publish_version(
        self,
        actor_id: str,
        software_id: UUID,
        version: str,
        expected_software_row_version: int | None = None,
    ) -> PublishVersionResult:
        ...

    async def deprecate_version(
        self,
        actor_id: str,
        software_id: UUID,
        version: str,
        expected_software_row_version: int | None = None,
    ) -> DeprecateVersionResult:
        ...

    async def revoke_version(
        self,
        actor_id: str,
        software_id: UUID,
        version: str,
        expected_software_row_version: int | None = None,
    ) -> RevokeVersionResult:
        ...

    async def get_download_descriptor(
        self, software_id: UUID, version: str
    ) -> DownloadDescriptor | None:
        ...

    async def increment_download_count(self, version_id: UUID) -> None:
        ...

    async def delete_software(
        self,
        actor_id: str,
        software_id: UUID,
        expected_software_row_version: int | None = None,
    ) -> DeleteSoftwareResult:
        ...

    async def list_softwares(
        self,
        actor_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> list[SoftwareListRecord]:
        ...

    async def list_versions(
        self,
        actor_id: str,
        software_id: UUID,
        *,
        limit: int = 20,
    ) -> list[VersionListRecord]:
        ...

    async def get_admin_summary(self) -> AdminSummaryRecord:
        ...

    async def list_admin_softwares(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AdminSoftwareRecord]:
        ...

    async def get_idempotency_record(
        self, scope: str, actor_id: str, key: str
    ) -> IdempotencyRecord | None:
        ...

    async def store_idempotency_record(
        self,
        scope: str,
        actor_id: str,
        key: str,
        request_hash: str,
        response_json: str,
    ) -> None:
        ...


class StorageService(Protocol):
    async def store_stream(
        self,
        stream: AsyncIterable[bytes],
        *,
        file_name: str,
        content_type: str,
    ) -> StoredObject:
        ...

    async def open_stream(
        self,
        storage_key: str,
        *,
        chunk_size: int,
        start: int = 0,
        end: int | None = None,
    ) -> AsyncIterator[bytes]:
        ...

    async def delete(self, storage_key: str) -> None:
        ...


class AccessControlService(Protocol):
    async def assert_upload_allowed(self, actor_id: str) -> None:
        ...

    async def assert_publish_allowed(self, actor_id: str, owner_id: str) -> None:
        ...

    async def assert_download_allowed(self, actor_id: str, owner_id: str, published: bool) -> None:
        ...

    async def assert_delete_allowed(self, actor_id: str, owner_id: str) -> None:
        ...


class VirusScannerService(Protocol):
    def wrap_stream(
        self,
        stream: AsyncIterable[bytes],
        *,
        file_name: str,
        content_type: str,
        ) -> AsyncIterable[bytes]:
        ...


class EventPublisher(Protocol):
    async def publish(self, event: object) -> None:
        ...

    async def publish_many(self, events: list[object]) -> None:
        ...
