from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from uuid import UUID

from software_management.domain.events import SoftwareDeleted, VersionPublished, VersionRevoked
from software_management.domain.value_objects import FileHash, VersionNumber

from .dtos import (
    AdminSoftwareItem,
    AdminSummaryOutput,
    DeleteSoftwareInput,
    DeleteSoftwareOutput,
    DownloadSoftwareInput,
    DownloadSoftwareOutput,
    DeprecateVersionInput,
    DeprecateVersionOutput,
    ListAdminSoftwareInput,
    ListSoftwareInput,
    ListVersionsInput,
    PublishVersionInput,
    PublishVersionOutput,
    RevokeVersionInput,
    RevokeVersionOutput,
    SoftwareListItem,
    UploadSoftwareInput,
    UploadSoftwareOutput,
    VersionListItem,
)
from .errors import ConflictError, NotFoundError, ValidationError
from .interfaces import (
    AccessControlService,
    CreateVersionCommand,
    EventPublisher,
    SoftwareRepository,
    StorageService,
    VirusScannerService,
)

_UPLOAD_IDEMPOTENCY_SCOPE = "sms_upload"
_PUBLISH_IDEMPOTENCY_SCOPE = "sms_publish"
_REVOKE_IDEMPOTENCY_SCOPE = "sms_revoke"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_idempotency_key(key: str | None) -> str | None:
    if key is None:
        return None
    normalized = key.strip()
    if not normalized:
        return None
    if len(normalized) > 128:
        raise ValidationError("idempotency key is too long")
    return normalized


def _hash_payload(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_uuid(value: str) -> UUID:
    return UUID(value)


def _validate_version(version: str) -> None:
    try:
        VersionNumber(version)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


def _decode_upload_output(raw_json: str) -> UploadSoftwareOutput:
    data = json.loads(raw_json)
    return UploadSoftwareOutput(
        software_id=_parse_uuid(data["software_id"]),
        version_id=_parse_uuid(data["version_id"]),
        artifact_id=_parse_uuid(data["artifact_id"]),
        version=data["version"],
        file_hash=data["file_hash"],
        size_bytes=int(data["size_bytes"]),
        software_row_version=int(data["software_row_version"]),
        published=bool(data["published"]),
    )


def _encode_upload_output(output: UploadSoftwareOutput) -> str:
    payload = {
        "software_id": str(output.software_id),
        "version_id": str(output.version_id),
        "artifact_id": str(output.artifact_id),
        "version": output.version,
        "file_hash": output.file_hash,
        "size_bytes": output.size_bytes,
        "software_row_version": output.software_row_version,
        "published": output.published,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _decode_publish_output(raw_json: str) -> PublishVersionOutput:
    data = json.loads(raw_json)
    return PublishVersionOutput(
        software_id=_parse_uuid(data["software_id"]),
        version_id=_parse_uuid(data["version_id"]),
        version=data["version"],
        published_at=_parse_datetime(data["published_at"]),
        software_row_version=int(data["software_row_version"]),
    )


def _encode_publish_output(output: PublishVersionOutput) -> str:
    payload = {
        "software_id": str(output.software_id),
        "version_id": str(output.version_id),
        "version": output.version,
        "published_at": output.published_at.isoformat(),
        "software_row_version": output.software_row_version,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _decode_revoke_output(raw_json: str) -> RevokeVersionOutput:
    data = json.loads(raw_json)
    return RevokeVersionOutput(
        software_id=_parse_uuid(data["software_id"]),
        version_id=_parse_uuid(data["version_id"]),
        version=data["version"],
        revoked_at=_parse_datetime(data["revoked_at"]),
        software_row_version=int(data["software_row_version"]),
    )


def _encode_revoke_output(output: RevokeVersionOutput) -> str:
    payload = {
        "software_id": str(output.software_id),
        "version_id": str(output.version_id),
        "version": output.version,
        "revoked_at": output.revoked_at.isoformat(),
        "software_row_version": output.software_row_version,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


@dataclass(slots=True)
class UploadSoftware:
    repository: SoftwareRepository
    storage: StorageService
    access_control: AccessControlService
    virus_scanner: VirusScannerService

    async def execute(self, dto: UploadSoftwareInput) -> UploadSoftwareOutput:
        _validate_version(dto.version)
        await self.access_control.assert_upload_allowed(dto.actor_id)
        idempotency_key = _normalize_idempotency_key(dto.idempotency_key)
        request_hash = _hash_payload(
            {
                "software_id": str(dto.software_id) if dto.software_id else None,
                "software_name": dto.software_name.strip(),
                "software_description": dto.software_description.strip(),
                "version": dto.version.strip(),
                "file_name": dto.file_name.strip(),
                "content_type": dto.content_type.strip(),
                "is_public": dto.is_public,
                "publish_now": dto.publish_now,
            }
        )
        if idempotency_key:
            record = await self.repository.get_idempotency_record(
                _UPLOAD_IDEMPOTENCY_SCOPE, dto.actor_id, idempotency_key
            )
            if record is not None:
                if record.request_hash != request_hash:
                    raise ConflictError("idempotency key already used with different request")
                return _decode_upload_output(record.response_json)
        scanned_stream = self.virus_scanner.wrap_stream(
            dto.stream,
            file_name=dto.file_name,
            content_type=dto.content_type,
        )
        stored_object = await self.storage.store_stream(
            scanned_stream,
            file_name=dto.file_name,
            content_type=dto.content_type,
        )
        FileHash(stored_object.file_hash)
        if dto.expected_file_hash is not None:
            try:
                expected_hash = FileHash(dto.expected_file_hash).value
            except ValueError as exc:
                await self.storage.delete(stored_object.storage_key)
                raise ValidationError(str(exc)) from exc
            if expected_hash != stored_object.file_hash:
                await self.storage.delete(stored_object.storage_key)
                raise ValidationError("artifact hash mismatch")
        command = CreateVersionCommand(
            actor_id=dto.actor_id,
            software_name=dto.software_name,
            software_description=dto.software_description,
            version=dto.version,
            artifact_storage_key=stored_object.storage_key,
            artifact_file_hash=stored_object.file_hash,
            artifact_size_bytes=stored_object.size_bytes,
            artifact_file_name=stored_object.file_name,
            artifact_content_type=stored_object.content_type,
            is_public=dto.is_public,
            software_id=dto.software_id,
            publish_now=dto.publish_now,
            expected_software_row_version=dto.expected_software_row_version,
        )
        try:
            result = await self.repository.create_version(command)
        except ConflictError:
            await self.storage.delete(stored_object.storage_key)
            if idempotency_key:
                record = await self.repository.get_idempotency_record(
                    _UPLOAD_IDEMPOTENCY_SCOPE, dto.actor_id, idempotency_key
                )
                if record is not None and record.request_hash == request_hash:
                    return _decode_upload_output(record.response_json)
            raise
        except Exception:
            await self.storage.delete(stored_object.storage_key)
            raise
        output = UploadSoftwareOutput(
            software_id=result.software_id,
            version_id=result.version_id,
            artifact_id=result.artifact_id,
            version=result.version,
            file_hash=stored_object.file_hash,
            size_bytes=stored_object.size_bytes,
            software_row_version=result.software_row_version,
            published=result.published,
        )
        if idempotency_key:
            try:
                await self.repository.store_idempotency_record(
                    _UPLOAD_IDEMPOTENCY_SCOPE,
                    dto.actor_id,
                    idempotency_key,
                    request_hash,
                    _encode_upload_output(output),
                )
            except ConflictError:
                record = await self.repository.get_idempotency_record(
                    _UPLOAD_IDEMPOTENCY_SCOPE, dto.actor_id, idempotency_key
                )
                if record is None or record.request_hash != request_hash:
                    raise
                return _decode_upload_output(record.response_json)
        return output


@dataclass(slots=True)
class PublishVersion:
    repository: SoftwareRepository
    access_control: AccessControlService
    event_publisher: EventPublisher

    async def execute(self, dto: PublishVersionInput) -> PublishVersionOutput:
        _validate_version(dto.version)
        owner_id = await self.repository.get_software_owner(dto.software_id)
        if owner_id is None:
            raise NotFoundError("software not found")
        await self.access_control.assert_publish_allowed(dto.actor_id, owner_id)
        idempotency_key = _normalize_idempotency_key(dto.idempotency_key)
        request_hash = _hash_payload(
            {
                "software_id": str(dto.software_id),
                "version": dto.version.strip(),
            }
        )
        if idempotency_key:
            record = await self.repository.get_idempotency_record(
                _PUBLISH_IDEMPOTENCY_SCOPE, dto.actor_id, idempotency_key
            )
            if record is not None:
                if record.request_hash != request_hash:
                    raise ConflictError("idempotency key already used with different request")
                return _decode_publish_output(record.response_json)
        try:
            result = await self.repository.publish_version(
                actor_id=dto.actor_id,
                software_id=dto.software_id,
                version=dto.version,
                expected_software_row_version=dto.expected_software_row_version,
            )
        except ConflictError:
            if idempotency_key:
                record = await self.repository.get_idempotency_record(
                    _PUBLISH_IDEMPOTENCY_SCOPE, dto.actor_id, idempotency_key
                )
                if record is not None and record.request_hash == request_hash:
                    return _decode_publish_output(record.response_json)
            raise
        output = PublishVersionOutput(
            software_id=result.software_id,
            version_id=result.version_id,
            version=result.version,
            published_at=result.published_at,
            software_row_version=result.software_row_version,
        )
        if idempotency_key:
            try:
                await self.repository.store_idempotency_record(
                    _PUBLISH_IDEMPOTENCY_SCOPE,
                    dto.actor_id,
                    idempotency_key,
                    request_hash,
                    _encode_publish_output(output),
                )
            except ConflictError:
                record = await self.repository.get_idempotency_record(
                    _PUBLISH_IDEMPOTENCY_SCOPE, dto.actor_id, idempotency_key
                )
                if record is None or record.request_hash != request_hash:
                    raise
                return _decode_publish_output(record.response_json)
        await self.event_publisher.publish(
            VersionPublished(
                software_id=result.software_id,
                version_id=result.version_id,
                version=VersionNumber(result.version),
                occurred_at=result.published_at,
            )
        )
        return output


@dataclass(slots=True)
class DownloadSoftware:
    repository: SoftwareRepository
    storage: StorageService
    access_control: AccessControlService
    chunk_size: int

    async def execute(self, dto: DownloadSoftwareInput) -> DownloadSoftwareOutput:
        _validate_version(dto.version)
        descriptor = await self.repository.get_download_descriptor(dto.software_id, dto.version)
        if descriptor is None:
            raise NotFoundError("software version not found")
        await self.access_control.assert_download_allowed(
            dto.actor_id,
            descriptor.owner_id,
            descriptor.published,
        )
        stream = await self.storage.open_stream(
            descriptor.storage_key,
            chunk_size=self.chunk_size,
        )
        await self.repository.increment_download_count(descriptor.version_id)
        return DownloadSoftwareOutput(
            software_id=descriptor.software_id,
            version_id=descriptor.version_id,
            version=descriptor.version,
            file_name=descriptor.file_name,
            content_type=descriptor.content_type,
            size_bytes=descriptor.size_bytes,
            file_hash=descriptor.file_hash,
            stream=stream,
        )


@dataclass(slots=True)
class DeprecateVersion:
    repository: SoftwareRepository
    access_control: AccessControlService

    async def execute(self, dto: DeprecateVersionInput) -> DeprecateVersionOutput:
        _validate_version(dto.version)
        owner_id = await self.repository.get_software_owner(dto.software_id)
        if owner_id is None:
            raise NotFoundError("software not found")
        await self.access_control.assert_publish_allowed(dto.actor_id, owner_id)
        result = await self.repository.deprecate_version(
            actor_id=dto.actor_id,
            software_id=dto.software_id,
            version=dto.version,
            expected_software_row_version=dto.expected_software_row_version,
        )
        return DeprecateVersionOutput(
            software_id=result.software_id,
            version_id=result.version_id,
            version=result.version,
            deprecated_at=result.deprecated_at,
            software_row_version=result.software_row_version,
        )


@dataclass(slots=True)
class RevokeVersion:
    repository: SoftwareRepository
    access_control: AccessControlService
    event_publisher: EventPublisher

    async def execute(self, dto: RevokeVersionInput) -> RevokeVersionOutput:
        _validate_version(dto.version)
        owner_id = await self.repository.get_software_owner(dto.software_id)
        if owner_id is None:
            raise NotFoundError("software not found")
        await self.access_control.assert_publish_allowed(dto.actor_id, owner_id)
        idempotency_key = _normalize_idempotency_key(dto.idempotency_key)
        request_hash = _hash_payload(
            {
                "software_id": str(dto.software_id),
                "version": dto.version.strip(),
            }
        )
        if idempotency_key:
            record = await self.repository.get_idempotency_record(
                _REVOKE_IDEMPOTENCY_SCOPE, dto.actor_id, idempotency_key
            )
            if record is not None:
                if record.request_hash != request_hash:
                    raise ConflictError("idempotency key already used with different request")
                return _decode_revoke_output(record.response_json)
        try:
            result = await self.repository.revoke_version(
                actor_id=dto.actor_id,
                software_id=dto.software_id,
                version=dto.version,
                expected_software_row_version=dto.expected_software_row_version,
            )
        except ConflictError:
            if idempotency_key:
                record = await self.repository.get_idempotency_record(
                    _REVOKE_IDEMPOTENCY_SCOPE, dto.actor_id, idempotency_key
                )
                if record is not None and record.request_hash == request_hash:
                    return _decode_revoke_output(record.response_json)
            raise
        output = RevokeVersionOutput(
            software_id=result.software_id,
            version_id=result.version_id,
            version=result.version,
            revoked_at=result.revoked_at,
            software_row_version=result.software_row_version,
        )
        if idempotency_key:
            try:
                await self.repository.store_idempotency_record(
                    _REVOKE_IDEMPOTENCY_SCOPE,
                    dto.actor_id,
                    idempotency_key,
                    request_hash,
                    _encode_revoke_output(output),
                )
            except ConflictError:
                record = await self.repository.get_idempotency_record(
                    _REVOKE_IDEMPOTENCY_SCOPE, dto.actor_id, idempotency_key
                )
                if record is None or record.request_hash != request_hash:
                    raise
                return _decode_revoke_output(record.response_json)
        await self.event_publisher.publish(
            VersionRevoked(
                software_id=result.software_id,
                version_id=result.version_id,
                version=VersionNumber(result.version),
                occurred_at=result.revoked_at,
            )
        )
        return output


@dataclass(slots=True)
class DeleteSoftware:
    repository: SoftwareRepository
    storage: StorageService
    access_control: AccessControlService
    event_publisher: EventPublisher

    async def execute(self, dto: DeleteSoftwareInput) -> DeleteSoftwareOutput:
        owner_id = await self.repository.get_software_owner(dto.software_id)
        if owner_id is None:
            raise NotFoundError("software not found")
        await self.access_control.assert_delete_allowed(dto.actor_id, owner_id)
        result = await self.repository.delete_software(
            actor_id=dto.actor_id,
            software_id=dto.software_id,
            expected_software_row_version=dto.expected_software_row_version,
        )
        for storage_key in result.storage_keys:
            await self.storage.delete(storage_key)
        output = DeleteSoftwareOutput(
            software_id=result.software_id,
            deleted_versions=result.deleted_versions,
            deleted_artifacts=result.deleted_artifacts,
        )
        await self.event_publisher.publish(
            SoftwareDeleted(
                software_id=result.software_id,
                deleted_versions=result.deleted_versions,
                deleted_artifacts=result.deleted_artifacts,
                occurred_at=_utc_now(),
            )
        )
        return output


@dataclass(slots=True)
class ListSoftware:
    repository: SoftwareRepository

    async def execute(self, dto: ListSoftwareInput) -> list[SoftwareListItem]:
        rows = await self.repository.list_softwares(
            dto.actor_id,
            offset=dto.offset,
            limit=dto.limit,
        )
        return [
            SoftwareListItem(
                id=row.id,
                owner_id=row.owner_id,
                name=row.name,
                description=row.description,
                is_public=row.is_public,
                latest_version=row.latest_version,
                latest_version_id=row.latest_version_id,
                download_count=row.latest_download_count,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in rows
        ]


@dataclass(slots=True)
class ListVersions:
    repository: SoftwareRepository

    async def execute(self, dto: ListVersionsInput) -> list[VersionListItem]:
        rows = await self.repository.list_versions(
            dto.actor_id,
            dto.software_id,
            limit=dto.limit,
        )
        return [
            VersionListItem(
                id=row.id,
                software_id=row.software_id,
                version=row.version,
                is_published=row.is_published,
                download_count=row.download_count,
                file_name=row.file_name,
                content_type=row.content_type,
                size_bytes=row.size_bytes,
                file_hash=row.file_hash,
                created_at=row.created_at,
                published_at=row.published_at,
            )
            for row in rows
        ]


@dataclass(slots=True)
class GetAdminSummary:
    repository: SoftwareRepository

    async def execute(self) -> AdminSummaryOutput:
        row = await self.repository.get_admin_summary()
        return AdminSummaryOutput(
            total_packages=row.total_packages,
            private_packages=row.private_packages,
            public_packages=row.public_packages,
            total_versions=row.total_versions,
            total_downloads=row.total_downloads,
        )


@dataclass(slots=True)
class ListAdminSoftware:
    repository: SoftwareRepository

    async def execute(self, dto: ListAdminSoftwareInput) -> list[AdminSoftwareItem]:
        rows = await self.repository.list_admin_softwares(offset=dto.offset, limit=dto.limit)
        return [
            AdminSoftwareItem(
                package_id=row.package_id,
                name=row.name,
                owner_id=row.owner_id,
                is_public=row.is_public,
                latest_version=row.latest_version,
                download_count=row.download_count,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in rows
        ]
