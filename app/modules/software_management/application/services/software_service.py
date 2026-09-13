from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO, Sequence
from uuid import UUID, uuid4

from app.core.config import settings
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.shared.enums import ArtifactStatus, SoftwareVisibility, VersionStatus
from app.modules.software_management.application.services.category_service import CategoryService
from app.modules.software_management.application.services.download_service import DownloadService
from app.modules.software_management.domain.entities.artifact import Artifact
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.entities.version import Version
from app.modules.software_management.domain.events.events import (
    ArtifactAddedToVersion,
    malware_scan_failed,
    malware_scan_requested,
    malware_scan_success,
)
from app.modules.software_management.domain.exceptions import (
    DownloadDeniedError,
    InvalidSemVerError,
    SoftwareAccessDeniedError,
    SoftwareDomainError,
    SoftwareNotFoundError,
)
from app.modules.software_management.domain.ports.download_signer import SignedDownloadUrl
from app.modules.software_management.domain.ports.malware_scanner import MalwareScanner, ScanResult
from app.modules.software_management.domain.ports.storage import Storage
from app.modules.software_management.domain.value_objects import ArtifactUpload, OwnedSoftwareCard, SemVer, UploadedFile
from app.modules.software_management.schema.software_schema import ArtifactResponse, SoftwareVersionRead

logger = logging.getLogger(__name__)


class SoftwareService:
    """Application service orchestrating software lifecycle use cases."""

    def __init__(
        self,
        *,
        download_service: DownloadService | None = None,
        storage: Storage | None = None,
        malware_scanner: MalwareScanner | None = None,
        unit_of_work: UnitOfWork | None = None,
        category_service: CategoryService | None = None,
    ) -> None:
        self._download_service = download_service
        self._storage = storage
        self._malware_scanner = malware_scanner
        self._uow = unit_of_work
        self._category_service = category_service

    @property
    def repository(self):
        override = getattr(self, "_repository_override", None)
        if override is not None:
            return override
        return self._uow.software_repo

    @repository.setter
    def repository(self, value) -> None:
        self._repository_override = value

    @staticmethod
    async def spool_file(
        file: BinaryIO,
        filename: str,
        content_type: str | None = None,
        chunk_size: int = 1024 * 1024,
        max_size_bytes: int | None = None,
    ) -> ArtifactUpload:
        digest = hashlib.sha256()
        total = 0
        limit = max_size_bytes or settings.PACKAGE_UPLOAD_MAX_SIZE_BYTES
        suffix = Path(filename or "package.bin").suffix
        temp = NamedTemporaryFile(delete=False, suffix=suffix)
        temp_path = Path(temp.name)
        try:
            with temp:
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    digest.update(chunk)
                    total += len(chunk)
                    if total > limit:
                        raise SoftwareDomainError("Uploaded file exceeds the maximum allowed size.")
                    temp.write(chunk)
            return UploadedFile(
                filename=filename or "package.bin",
                content_type=content_type,
                size_bytes=total,
                sha256=digest.hexdigest(),
                temp_path=temp_path,
            )
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

    @staticmethod
    async def spool_files(
        files: Sequence[tuple[BinaryIO, str, str | None]],
        *,
        max_size_bytes: int | None = None,
    ) -> tuple[ArtifactUpload, ...]:
        uploads: list[ArtifactUpload] = []
        for file, filename, content_type in files:
            uploads.append(
                await SoftwareService.spool_file(
                    file,
                    filename,
                    content_type=content_type,
                    max_size_bytes=max_size_bytes,
                )
            )
        return tuple(uploads)

    async def list_visible(
        self,
        *,
        user_id: UUID,
        is_admin: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[OwnedSoftwareCard], int]:
        async with self._uow.read_only():
            return await self._uow.software_repo.list_owned(
                owner_id=user_id,
                limit=limit,
                offset=offset,
            )

    async def get(self, software_id: UUID) -> Software:
        """Retrieve a software using its id"""
        async with self._uow.read_only():
            software = await self._uow.software_repo.get(software_id)
        if software is None:
            raise SoftwareNotFoundError("Software not found.")
        return software

    async def list_versions(self, *, software_id: UUID, user_id: UUID, limit: int) -> list[SoftwareVersionRead]:
        """List all versions of a software."""
        async with self._uow.read_only():
            software = await self._uow.software_repo.get(software_id=software_id)
        if software is None:
            raise SoftwareNotFoundError("Software not found.")

        return [
            SoftwareVersionRead(
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
            for version in software.versions[:limit]
        ]

    async def upload_package(
        self,
        *,
        user_id: UUID,
        category_id: UUID,
        name: str,
        description: str,
        version_number: str,
        visibility: SoftwareVisibility,
        price_cents: int = 0,
        currency: str = "KSH",
        artifacts: Sequence[ArtifactUpload],
    ) -> tuple[Software, Version]:
        uploads = tuple(artifacts)
        if not uploads:
            raise SoftwareDomainError("At least one artifact is required.")
        if self._storage is None:
            raise SoftwareDomainError("Storage is not configured.")

        if self._category_service is not None:
            await self._category_service.get(category_id)

        software = Software.create(
            name=name.strip(),
            description=description.strip(),
            owner_id=user_id,
            category_id=category_id,
            visibility=visibility,
            price_cents=price_cents,
            currency=currency,
        )
        version = Version(
            id=uuid4(),
            software_id=software.id,
            number=SemVer.parse(version_number),
            release_notes="Initial upload",
            status=VersionStatus.DRAFT,
            lock_version=0,
        )
        return await self._persist_version_with_artifacts(
            software=software,
            version=version,
            artifacts=uploads,
        )

    async def upload_version(
        self,
        *,
        software_id: UUID,
        user_id: UUID,
        version_number: str,
        release_notes: str,
        artifacts: Sequence[ArtifactUpload],
        is_admin: bool = False,
    ) -> Version:
        uploads = tuple(artifacts)
        if not uploads:
            raise SoftwareDomainError("At least one artifact is required.")
        if self._storage is None:
            raise SoftwareDomainError("Storage is not configured.")

        software = await self.require_owner(
            software_id=software_id,
            user_id=user_id,
            is_admin=is_admin,
        )
        version = Version(
            id=uuid4(),
            software_id=software.id,
            number=SemVer.parse(version_number),
            release_notes=release_notes.strip() or "Version upload",
            status=VersionStatus.DRAFT,
            lock_version=0,
        )
        _, persisted_version = await self._persist_version_with_artifacts(
            software=software,
            version=version,
            artifacts=uploads,
        )
        return persisted_version

    async def _persist_version_with_artifacts(
        self,
        *,
        software: Software,
        version: Version,
        artifacts: Sequence[ArtifactUpload],
    ) -> tuple[Software, Version]:
        saved_storage_keys: list[str] = []
        try:
            for uploaded in artifacts:
                artifact = await self._process_artifact(version=version, software=software, uploaded=uploaded)
                version.add_artifact(artifact)
                saved_storage_keys.append(artifact.storage_key)

            software.add_version(version)
            if version.artifacts and all(artifact.status == ArtifactStatus.ACTIVE for artifact in version.artifacts):
                software.publish_version(version.id)

            async with self._uow:
                await self._uow.software_repo.save(software)

            return software, version
        except Exception:
            for storage_key in saved_storage_keys:
                try:
                    self._storage.delete(storage_key=storage_key)
                except Exception:
                    logger.exception("Failed to clean up stored artifact %s", storage_key)
            raise

    async def update_pricing(
        self,
        *,
        software_id: UUID,
        user_id: UUID,
        price_cents: int,
        currency: str,
        is_admin: bool = False,
    ) -> Software:
        software = await self.require_owner(
            software_id=software_id,
            user_id=user_id,
            is_admin=is_admin,
        )
        software.update_pricing(price_cents=price_cents, currency=currency)
        async with self._uow:
            await self._uow.software_repo.save(software)
        return software

    async def require_owner(
        self,
        *,
        software_id: UUID,
        user_id: UUID,
        is_admin: bool = False,
    ) -> Software:
        async with self._uow.read_only():
            software = await self._uow.software_repo.get(software_id)
        if software is None:
            raise SoftwareNotFoundError("Software not found.")
        if not is_admin and not software.is_owned_by(user_id):
            raise SoftwareAccessDeniedError("Only the owner or an admin can modify this software.")
        return software

    async def download_url(
        self,
        *,
        software_id: UUID,
        version_number: str,
        user_id: UUID,
    ) -> SignedDownloadUrl:
        software = await self.get(software_id)
        try:
            semver = SemVer.parse(version_number)
        except InvalidSemVerError as exc:
            raise SoftwareDomainError(f"Invalid version format: {version_number}") from exc

        version = software.get_version_by_semver(semver=semver)
        if len(version.artifacts) != 1:
            raise SoftwareDomainError("Version download requires a single artifact. Use the artifact download endpoint.")
        has_purchase = await self.has_purchase(software_id=software.id, user_id=user_id)
        if software.requires_payment() and not software.is_owned_by(user_id) and not has_purchase:
            raise DownloadDeniedError("A purchase is required to download this software.")
        if not software.is_public() and not software.is_owned_by(user_id) and not has_purchase:
            raise DownloadDeniedError("A purchase is required to download this software.")
        return self._download_service.create_download_url(
            software_id=software.id,
            version_number=version.number,
            user_id=user_id,
        )

    async def download_artifact_url(
        self,
        *,
        software_id: UUID,
        version_number: str,
        artifact_id: UUID,
        user_id: UUID,
    ) -> SignedDownloadUrl:
        software = await self.get(software_id)
        try:
            semver = SemVer.parse(version_number)
        except InvalidSemVerError as exc:
            raise SoftwareDomainError(f"Invalid version format: {version_number}") from exc

        version = software.get_version_by_semver(semver=semver)
        artifact = next((item for item in version.artifacts if item.id == artifact_id), None)
        if artifact is None:
            raise SoftwareNotFoundError("Artifact not found.")
        has_purchase = await self.has_purchase(software_id=software.id, user_id=user_id)
        if software.requires_payment() and not software.is_owned_by(user_id) and not has_purchase:
            raise DownloadDeniedError("A purchase is required to download this software.")
        if not software.is_public() and not software.is_owned_by(user_id) and not has_purchase:
            raise DownloadDeniedError("A purchase is required to download this software.")
        return self._download_service.create_artifact_download_url(artifact=artifact)

    async def deprecate_version(
        self,
        *,
        software_id: UUID,
        version_number: str,
        user_id: UUID,
        is_admin: bool = False,
    ) -> Version:
        software = await self.require_owner(
            software_id=software_id,
            user_id=user_id,
            is_admin=is_admin,
        )
        semver = SemVer.parse(version_number)
        version = software.get_version_by_semver(semver)
        software.deprecate_version(version.id)
        async with self._uow:
            await self._uow.software_repo.save(software)
        return version

    async def revoke_version(
        self,
        *,
        software_id: UUID,
        version_number: str,
        user_id: UUID,
        is_admin: bool = False,
    ) -> Version:
        software = await self.require_owner(
            software_id=software_id,
            user_id=user_id,
            is_admin=is_admin,
        )
        semver = SemVer.parse(version_number)
        version = software.get_version_by_semver(semver)
        software.revoke_version(version.id)
        async with self._uow:
            await self._uow.software_repo.save(software)
        return version

    async def has_purchase(self, *, software_id: UUID, user_id: UUID) -> bool:
        async with self._uow.read_only():
            return await self._uow.software_repo.has_purchase(software_id=software_id, user_id=user_id)

    async def _process_artifact(
        self,
        *,
        version: Version,
        software: Software,
        uploaded: ArtifactUpload,
    ) -> Artifact:
        filename = self._sanitize_filename(uploaded.filename)
        if uploaded.size_bytes <= 0:
            raise SoftwareDomainError("Uploaded file is empty.")
        if len(filename) > 255:
            raise SoftwareDomainError("Filename is too long.")

        content_type = uploaded.content_type or "application/octet-stream"
        self._validate_artifact_upload(uploaded=uploaded, filename=filename, content_type=content_type)
        scan = await self._scan_file(
            file_path=uploaded.temp_path,
            filename=filename,
            sha256=uploaded.sha256,
            content_type=content_type,
        )
        if not scan.is_clean:
            raise SoftwareDomainError(scan.reason or "Malware detected.")

        storage_key = f"software/{software.id}/versions/{version.id}/{uuid4()}/{filename}"
        self._storage.save(storage_key=storage_key, source_path=uploaded.temp_path)

        artifact = Artifact(
            id=uuid4(),
            version_id=version.id,
            storage_key=storage_key,
            sha256=uploaded.sha256,
            size_bytes=uploaded.size_bytes,
            mime_type=content_type,
            filename=filename,
            status=ArtifactStatus.ACTIVE,
            created_at=version.created_at,
            updated_at=version.updated_at,
        )
        _ = malware_scan_requested(
            software_id=software.id,
            version_id=version.id,
            artifact_id=artifact.id,
            storage_key=artifact.storage_key,
            actor_id=software.owner_id,
            aggregate_id=software.id,
        )
        _ = malware_scan_success(
            software_id=software.id,
            version_id=version.id,
            artifact_id=artifact.id,
            actor_id=software.owner_id,
            aggregate_id=software.id,
        )
        _ = ArtifactAddedToVersion(
            actor_id=software.owner_id,
            aggregate_id=software.id,
            software_id=software.id,
            version_id=version.id,
            artifact_id=artifact.id,
            filename=artifact.filename,
            storage_key=artifact.storage_key,
            size_bytes=artifact.size_bytes,
            sha256=artifact.sha256,
        )
        return artifact

    @staticmethod
    def _validate_artifact_upload(*, uploaded: ArtifactUpload, filename: str, content_type: str) -> None:
        if uploaded.size_bytes <= 0:
            raise SoftwareDomainError("Uploaded file is empty.")
        if not filename.strip():
            raise SoftwareDomainError("Invalid filename.")
        if len(content_type) > 255:
            raise SoftwareDomainError("Content type is too long.")

    @staticmethod
    def _sanitize_filename(filename: str) -> str:
        safe = Path(filename or "artifact.bin").name.strip()
        if not safe or safe in {".", ".."}:
            raise SoftwareDomainError("Unsafe artifact filename.")
        return safe

    async def _scan_file(
        self,
        *,
        file_path: Path,
        filename: str,
        sha256: str,
        content_type: str,
    ) -> ScanResult:
        if self._malware_scanner is None:
            return ScanResult(is_clean=True, provider="noop", reference=sha256)

        scan_method = self._malware_scanner.scan_file
        if inspect.iscoroutinefunction(scan_method):
            return await scan_method(
                file_path=file_path,
                filename=filename,
                sha256=sha256,
                content_type=content_type,
            )

        return await asyncio.to_thread(
            scan_method,
            file_path=file_path,
            filename=filename,
            sha256=sha256,
            content_type=content_type,
        )
