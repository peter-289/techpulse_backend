from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO
from uuid import UUID, uuid4


from app.core.config import settings
from app.modules.software_management.software.software import Software
from app.modules.software_management.software.artifact import Artifact
from app.modules.software_management.software.version import Version
from app.modules.software_management.software.value_objects import SemVer, UploadedFile
from app.modules.shared.enums import SoftwareVisibility, VersionStatus, ArtifactStatus
from app.modules.software_management.software.events import malware_scan_failed, malware_scan_success, malware_scan_requested
from app.modules.software_management.software.exceptions import (
    SoftwareAccessDeniedError,
    SoftwareDomainError,
    SoftwareNotFoundError,
)
from app.infrastructure.external_apis.scanner_service.malware_scanner import MalwareScanner
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.software_management.category.application.category_service import CategoryService
from app.infrastructure.storage.local_storage import LocalSoftwareStorage


# Software service class that handles software management operations
class SoftwareService:
    def __init__(
        self,
        storage: LocalSoftwareStorage | None = None,
        malware_scanner: MalwareScanner | None = None,
        unit_of_work: UnitOfWork | None = None,
        category_service: CategoryService | None = None
        
    ):
        
        self._malware_scanner = malware_scanner 
        self._storage = storage 
        self._uow = unit_of_work
        self._category_service = category_service or CategoryService(unit_of_work=self._uow)
        


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
    ) -> list[Software]:
        """List packages visible to a user."""
        async with self._uow.read_only():
             if is_admin:
               # Admin sees all public software
                 result, _ = await self._uow.software_repo.list_owned(
                 owner_id=user_id,
                 limit=limit,
                 offset=offset,
                )
             else:
                 result, _ = await self._uow.software_repo.list_owned(
                 owner_id=user_id,
                 limit=limit,
                 offset=offset,
                )
             return result

    async def get(self, software_id: UUID) -> Software:
        """Get software by ID."""
        async with self._uow.read_only():
              software = await self._uow.software_repo.get(software_id)
              if software is None:
                 raise SoftwareNotFoundError("Software not found.")
              return software

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
        """Upload a software package with initial version."""
        if uploaded.size_bytes <= 0:
            raise SoftwareDomainError("Uploaded file is empty.")
        
        # Fetch category
        # category = await self._category_service.find_by_name(name.strip())
        
        software = Software.create(
            name=name.strip(),
            description=description.strip(),
            owner_id=user_id,
            category_id=category_id, # TODO: We will posibly need to query the category from the database or have it as an input parameter
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
        """Upload a new version to existing software."""
        if uploaded.size_bytes <= 0:
            raise SoftwareDomainError("Uploaded file is empty.")

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

    async def _build_scanned_version(
        self,
        *,
        software: Software,
        version_number: str,
        release_notes: str,
        uploaded: UploadedFile,
        content_type: str | None,
    ) -> Version:
        """Build version with artifact and run malware scan."""
        try:
            semver = SemVer.parse(version_number)
        except ValueError as exc:
            raise SoftwareDomainError(f"Invalid version format: {version_number}") from exc

        version = Version(
            id=uuid4(),
            software_id=software.id,
            number=semver,
            release_notes=release_notes,
            status=VersionStatus.DRAFT,
            lock_version=0,
        )

        safe_filename = Path(uploaded.filename).name
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

        malware_scan_requested(software.id, version.id, artifact.id, artifact.storage_key)
        self._storage.save_path(artifact.storage_key, uploaded.temp_path)

        # Run scanner in thread pool if synchronous
        scan = await asyncio.to_thread(
            self._malware_scanner.scan_file,
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

    async def update_pricing(
        self,
        *,
        software_id: UUID,
        user_id: UUID,
        price_cents: int,
        currency: str,
        is_admin: bool = False,
    ) -> Software:
        """Update software pricing."""
        software = await self.require_owner(
            software_id=software_id,
            user_id=user_id,
            is_admin=is_admin,
        )
        software.update_pricing(price_cents=price_cents, currency=currency)
        async with self._uow:
              await self._uow.software_repo.save(software)
        
              return software

    async def has_purchase(self, *, software_id: UUID, user_id: UUID ) -> bool:
        """Check if a user has purchased a software package."""
        async with self._uow.read_only():
            return await self._uow.software_repo.has_purchase(
                software_id=software_id,
                user_id=user_id,
            )

    async def require_owner(
        self,
        *,
        software_id: UUID,
        user_id: UUID,
        is_admin: bool = False,
    ) -> Software:
        """Verify user owns software or is admin."""
        async with self._uow.read_only():
              software = await self._uow.software_repo.get(software_id)
        if not is_admin and software.owner_id != user_id:
            raise SoftwareAccessDeniedError(
                "Only the owner or an admin can modify this software."
            )
        return software

    async def download_url(
        self,
        *,
        software_id: UUID,
        version_number: str,
        user_id: UUID,
    ) -> str:
        """Generate a signed download URL for a software version."""
        software = await self.get(software_id)
        try:
            semver = SemVer.parse(version_number)
        except ValueError as exc:
            raise SoftwareDomainError(f"Invalid version format: {version_number}") from exc
        version = software.get_version_by_semver(semver)
        if not version.artifact:
            raise SoftwareNotFoundError("Version artifact not found.")
        return self._storage.create_download_url(version.artifact.storage_key)

    async def deprecate_version(
        self,
        *,
        software_id: UUID,
        version_number: str,
        user_id: UUID,
        is_admin: bool = False,
    ) -> Version:
        """Deprecate a software version."""
        software = await self.require_owner(
            software_id=software_id,
            user_id=user_id,
            is_admin=is_admin,
        )

        try:
            semver = SemVer.parse(version_number)
        except ValueError as exc:
            raise SoftwareDomainError(f"Invalid version format: {version_number}") from exc

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
        """Revoke a software version."""
        software = await self.require_owner(
            software_id=software_id,
            user_id=user_id,
            is_admin=is_admin,
        )

        try:
            semver = SemVer.parse(version_number)
        except ValueError as exc:
            raise SoftwareDomainError(f"Invalid version format: {version_number}") from exc

        version = software.get_version_by_semver(semver)
        software.revoke_version(version.id)

        async with self._uow:
              await self._uow.software_repo.save(software)
              return version


                       
        

 