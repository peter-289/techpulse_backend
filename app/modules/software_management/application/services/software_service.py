from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO
from uuid import UUID, uuid4

from app.core.config import settings
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.shared.enums import ArtifactStatus, SoftwareVisibility, VersionStatus
from app.modules.software_management.application.services.category_service import CategoryService
from app.modules.software_management.domain.entities.artifact import Artifact
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.entities.version import Version
from app.modules.software_management.domain.events import malware_scan_failed, malware_scan_requested, malware_scan_success
from app.modules.software_management.domain.exceptions import (
    InvalidSemVerError,
    SoftwareAccessDeniedError,
    SoftwareDomainError,
    SoftwareNotFoundError,
)
from app.modules.software_management.domain.ports.download_signer import DownloadSigner, SignedDownloadUrl
from app.modules.software_management.domain.ports.malware_scanner import MalwareScanner, ScanResult
from app.modules.software_management.domain.ports.storage import Storage
from app.modules.software_management.domain.value_objects import OwnedSoftwareCard, SemVer, UploadedFile
from app.modules.software_management.schema.software_schema import SoftwareVersionRead
from app.modules.software_management.application.services.download_service import DownloadService

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
        return self._uow.software_repo

    @staticmethod
    async def spool_file(
        file: BinaryIO,
        filename: str,
        chunk_size: int = 1024 * 1024,
        max_size_bytes: int | None = None,
    ) -> UploadedFile:
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
                content_type="application/octet-stream",
                size_bytes=total,
                sha256=digest.hexdigest(),
                temp_path=temp_path,
            )
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

    async def list_visible(
        self,
        *,
        user_id: UUID,
        is_admin: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[OwnedSoftwareCard], int]:
        async with self._uow.read_only():
            # The reference architecture uses a dedicated marketplace listing
            # port, but this module currently exposes owned-package cards here.
            return await self._uow.software_repo.list_owned(
                owner_id=user_id,
                limit=limit,
                offset=offset,
            )

    async def get(self, software_id: UUID) -> Software:
        async with self._uow.read_only():
            software = await self._uow.software_repo.get(software_id)
        if software is None:
            raise SoftwareNotFoundError("Software not found.")
        return software

    async def list_versions(self, *, software_id: UUID, user_id: UUID, limit: int) -> list[SoftwareVersionRead]:
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
                artifact_id=version.artifact.id if version.artifact else None,
                artifact_status=str(version.artifact.status).lower() if version.artifact else None,
                file_hash=version.artifact.sha256 if version.artifact else None,
                size_bytes=version.artifact.size_bytes if version.artifact else None,
                content_type=version.artifact.mime_type if version.artifact else None,
                file_name=version.artifact.filename if version.artifact else None,
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
        uploaded: UploadedFile,
        content_type: str | None,
    ) -> tuple[Software, Version]:
        if uploaded.size_bytes <= 0:
            raise SoftwareDomainError("Uploaded file is empty.")
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

        version = await self._build_scanned_version(
            software=software,
            version_number=version_number,
            release_notes="Initial upload",
            uploaded=uploaded,
            content_type=content_type,
        )
        software.add_version(version)
        if version.artifact and version.artifact.status == ArtifactStatus.ACTIVE:
            software.publish_version(version.id)

        async with self._uow:
            await self._uow.software_repo.save(software)
        return software, version

    async def upload_version(
        self,
        *,
        software_id: UUID,
        user_id: UUID,
        version_number: str,
        release_notes: str,
        uploaded: UploadedFile,
        content_type: str | None,
        is_admin: bool = False,
    ) -> Version:
        if uploaded.size_bytes <= 0:
            raise SoftwareDomainError("Uploaded file is empty.")
        if self._storage is None:
            raise SoftwareDomainError("Storage is not configured.")

        software = await self.require_owner(
            software_id=software_id,
            user_id=user_id,
            is_admin=is_admin,
        )

        version = await self._build_scanned_version(
            software=software,
            version_number=version_number,
            release_notes=release_notes.strip() or "Version upload",
            uploaded=uploaded,
            content_type=content_type,
        )
        software.add_version(version)
        if version.artifact and version.artifact.status == ArtifactStatus.ACTIVE:
            software.publish_version(version.id)

        async with self._uow:
            await self._uow.software_repo.save(software)
        return version

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

    async def has_purchase(self, *, software_id: UUID, user_id: UUID) -> bool:
        async with self._uow.read_only():
            return await self._uow.software_repo.has_purchase(software_id=software_id, user_id=user_id)

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
        if version.artifact is None:
            raise SoftwareNotFoundError("Version artifact not found.")
        return self._download_service.create_download_url(
            software_id=software.id, 
            version_number=version.number, 
            user_id=user_id
            )

        
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

    async def _build_scanned_version(
        self,
        *,
        software: Software,
        version_number: str,
        release_notes: str,
        uploaded: UploadedFile,
        content_type: str | None,
    ) -> Version:
        semver = SemVer.parse(version_number)
        version = Version(
            id=uuid4(),
            software_id=software.id,
            number=semver,
            release_notes=release_notes,
            status=VersionStatus.DRAFT,
            lock_version=0,
        )

        safe_filename = Path(uploaded.filename or "artifact.bin").name
        if ".." in safe_filename or "/" in safe_filename or "\\" in safe_filename:
            safe_filename = "artifact.bin"

        artifact = Artifact(
            id=uuid4(),
            version_id=version.id,
            storage_key=f"software/{software.id}/versions/{version.id}/{uuid4()}/{safe_filename}",
            sha256=uploaded.sha256,
            size_bytes=uploaded.size_bytes,
            mime_type=content_type or uploaded.content_type,
            filename=safe_filename,
            status=ArtifactStatus.UPLOADING,
            created_at=version.created_at,
            updated_at=version.updated_at,
        )
        version.attach_artifact(artifact)
        _ = malware_scan_requested(software.id, version.id, artifact.id, artifact.storage_key)

        self._storage.save(storage_key=artifact.storage_key, source_path=uploaded.temp_path)

        scan = await self._scan_file(
            file_path=uploaded.temp_path,
            filename=safe_filename,
            sha256=uploaded.sha256,
            content_type=content_type or uploaded.content_type,
        )

        if scan.is_clean:
            artifact.process_malware_scan_success(
                malware_scan_success(software.id, version.id, artifact.id)
            )
        else:
            artifact.process_malware_scan_failed(
                malware_scan_failed(
                    software.id,
                    version.id,
                    artifact.id,
                    scan.reason or "Malware scanner rejected this artifact.",
                )
            )

        return version

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
