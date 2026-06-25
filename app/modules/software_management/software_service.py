from __future__ import annotations

import asyncio
import hashlib
import hmac
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO
from urllib.parse import quote
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.modules.software_management.software.software import Software
from app.modules.software_management.software.artifact import Artifact
from app.modules.software_management.software.version import Version
from app.modules.software_management.software.value_objects import SemVer
from app.modules.shared.enums import SoftwareVisibility, VersionStatus, ArtifactStatus
from app.modules.software_management.software.events import malware_scan_failed, malware_scan_success, malware_scan_requested
from app.modules.software_management.software.exceptions import (
    SoftwareAccessDeniedError,
    SoftwareDomainError,
    SoftwareNotFoundError,
)
from app.infrastructure.database.models.payment import SoftwarePaymentModel, SoftwarePurchaseModel
from app.modules.software_management.software_repo import SoftwareRepository
from app.infrastructure.external_apis.scanner_service.malware_scanner import MalwareScanner, get_malware_scanner
from techpulse_backend.app.modules.billing.payment_service import PaymentProvider, get_payment_provider
from app.infrastructure.database.unit_of_work import UnitOfWork
from techpulse_backend.app.modules.billing.billing_service import BillingService


@dataclass(frozen=True, slots=True)
class UploadedFile:
    """Upload file data shape."""
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    temp_path: Path


class LocalSoftwareStorage:
    """Storage management for local disk storage."""

    def __init__(
        self,
        storage_root: str | Path,
        signing_secret: str,
        backend_url: str,
    ) -> None:
        self.root = Path(storage_root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._secret = signing_secret.encode("utf-8")
        self._backend_url = backend_url.rstrip("/")

    def resolve_path(self, storage_key: str) -> Path:
        """Resolve path if it exists using a storage key."""
        key = self._validate_storage_key(storage_key)
        target = (self.root / key).resolve()
        if not target.is_relative_to(self.root):
            raise ValueError("Invalid storage key path traversal")
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def save_path(self, storage_key: str, source_path: Path) -> None:
        target = self.resolve_path(storage_key)
        with source_path.open("rb") as source, target.open("wb") as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)

    def read(self, storage_key: str) -> tuple[bytes, str]:
        target = self.resolve_path(storage_key)
        if not target.exists():
            raise FileNotFoundError(storage_key)
        return target.read_bytes(), "application/octet-stream"

    def delete(self, storage_key: str) -> None:
        target = self.resolve_path(storage_key)
        target.unlink(missing_ok=True)

    def create_download_url(self, storage_key: str, expires_in_seconds: int = 900) -> str:
        key = self._validate_storage_key(storage_key)
        expires_at = int(time.time()) + expires_in_seconds
        token = self._sign(storage_key=key, expires_at=expires_at, method="GET")
        return (
            f"{self._backend_url}/api/v1/software-management/storage/download/"
            f"{quote(key, safe='')}?expires={expires_at}&token={token}"
        )

    def verify_signed_request(
        self,
        *,
        storage_key: str,
        expires: int,
        token: str,
        method: str,
    ) -> bool:
        key = self._validate_storage_key(storage_key)
        if expires < int(time.time()):
            return False
        expected = self._sign(storage_key=key, expires_at=expires, method=method.upper())
        return hmac.compare_digest(expected, token)

    def _validate_storage_key(self, storage_key: str) -> str:
        key = storage_key.strip()
        if not key or key.startswith("/") or any(ord(char) < 32 for char in key):
            raise ValueError("Invalid storage key")
        return key

    def _sign(self, *, storage_key: str, expires_at: int, method: str) -> str:
        payload = f"{method}:{storage_key}:{expires_at}".encode("utf-8")
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()


class SoftwareService:
    def __init__(
        self,
        storage: LocalSoftwareStorage | None = None,
        payment_provider: PaymentProvider | None = None,
        malware_scanner: MalwareScanner | None = None,
        unit_of_work: UnitOfWork | None = None,
        billing_service: BillingService | None = None,
    ):
        self.payment_provider = payment_provider or get_payment_provider()
        self.malware_scanner = malware_scanner or get_malware_scanner()
        self.storage = storage or LocalSoftwareStorage(
            Path(settings.UPLOAD_ROOT) / "software_management",
            settings.SECRET_KEY,
            settings.BACKEND_URL,
        )
        self.uow = unit_of_work
        self.billing_service = billing_service or BillingService(
            unit_of_work=self.uow,
            payment_provider=self.payment_provider,
        )


    @staticmethod
    def actor_uuid(user_id: int) -> UUID:
        return UUID(int=max(0, int(user_id)))

    @staticmethod
    def actor_int(user_id: UUID) -> int:
        return int(user_id.int)

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
        user_id: int,
        is_admin: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Software]:
        """List packages visible to a user."""
        async with self.uow.read_only():
             if is_admin:
               # Admin sees all public software
                 result, _ = await self.uow.software_repo.list_owned(
                 owner_id=user_id,
                 limit=limit,
                 offset=offset,
                )
             else:
                 result, _ = await self.uow.software_repo.list_owned(
                 owner_id=self.actor_uuid(user_id),
                 limit=limit,
                 offset=offset,
                )
             return result

    async def get(self, software_id: UUID) -> Software:
        """Get software by ID."""
        async with self.uow.read_only():
              software = await self.uow.software_repo.get(software_id)
              if software is None:
                 raise SoftwareNotFoundError("Software not found.")
              return software

    async def create(
        self,
        *,
        user_id: int,
        name: str,
        description: str,
        visibility: str,
        price_cents: int = 0,
        currency: str = "",
    ) -> Software:
        """Create a new software package."""
        software = Software.create(
            name=name.strip(),
            description=description.strip(),
            owner_id=self.actor_uuid(user_id),
            visibility=SoftwareVisibility(visibility),
            price_cents=price_cents,
            currency=currency,
        )
        async with self.uow:
              await self.uow.software_repo.save(software)
            
              return software

    async def upload_package(
        self,
        *,
        user_id: int,
        name: str,
        description: str,
        version_number: str,
        is_public: bool,
        price_cents: int = 0,
        currency: str = "KSH",
        uploaded: UploadedFile,
        content_type: str | None,
    ) -> tuple[Software, Version]:
        """Upload a software package with initial version."""
        if uploaded.size_bytes <= 0:
            raise SoftwareDomainError("Uploaded file is empty.")

        software = Software.create(
            name=name.strip(),
            description=description.strip(),
            owner_id=self.actor_uuid(user_id),
            visibility=SoftwareVisibility.PUBLIC if is_public else SoftwareVisibility.PRIVATE,
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

        async with self.uow:
            await self.uow.software_repo.save(software)
        
            return software, version

    async def upload_version(
        self,
        *,
        software_id: UUID,
        user_id: int,
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
        async with self.uow:
            await self.uow.software_repo.save(software)
        
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
        self.storage.save_path(artifact.storage_key, uploaded.temp_path)

        # Run scanner in thread pool if synchronous
        scan = await asyncio.to_thread(
            self.malware_scanner.scan_file,
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
        user_id: int,
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
        async with self.uow:
              await self.uow.software_repo.save(software)
        
              return software

    async def require_owner(
        self,
        *,
        software_id: UUID,
        user_id: int,
        is_admin: bool = False,
    ) -> Software:
        """Verify user owns software or is admin."""
        async with self.uow.read_only():
              software = await self.uow.software_repo.get(software_id)
        if not is_admin and software.owner_id != self.actor_uuid(user_id):
            raise SoftwareAccessDeniedError(
                "Only the owner or an admin can modify this software."
            )
        return software

    async def deprecate_version(
        self,
        *,
        software_id: UUID,
        version_number: str,
        user_id: int,
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
        async with self.uow:
              await self.uow.software_repo.save(software)
              return version

    async def revoke_version(
        self,
        *,
        software_id: UUID,
        version_number: str,
        user_id: int,
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

        async with self.uow:
              await self.uow.software_repo.save(software)
              return version

    async def download_url( 
        self,
        *,
        software_id: UUID,
        version_number: str,
        user_id: int,
    ) -> str:
        """Generate signed download URL for a version."""
        software = await self.get(software_id)
        actor = self.actor_uuid(user_id)

        if software.visibility == SoftwareVisibility.PRIVATE and software.owner_id != actor:
            raise SoftwareAccessDeniedError("User is not entitled to this software.")

        has_purchase = await self.has_purchase(software_id=software_id, user_id=user_id)
        if software.price_cents > 0 and software.owner_id != actor and not has_purchase:
            raise SoftwareAccessDeniedError(
                "Purchase is required before downloading this software."
            )

        try:
            semver = SemVer.parse(version_number)
        except ValueError as exc:
            raise SoftwareDomainError(f"Invalid version format: {version_number}") from exc

        version = software.get_version_by_semver(semver)
        if not version.is_downloadable() or version.artifact is None:
            raise SoftwareNotFoundError("Requested version is not downloadable.")
        async with self.uow:
             raise NotImplementedError()
             
       

        return self.storage.create_download_url(version.artifact.storage_key)

    async def has_purchase(self, *, software_id: UUID, user_id: int) -> bool:
        """Check if user has purchased software."""
        buyer_id = str(self.actor_uuid(user_id))
        async with self.uow.read_only():
            has_purchase = await self.uow.software_repo.has_purchase(software_id, buyer_id)
        return has_purchase

    async def create_checkout(self, *, software_id: UUID, user_id: int) -> SoftwarePaymentModel:
        software = await self.get(software_id)
        buyer_id = self.actor_uuid(user_id)

        if software.owner_id == buyer_id:
            raise SoftwareDomainError("Owners already have access to their own software.")

        if software.visibility == SoftwareVisibility.PRIVATE:
            raise SoftwareAccessDeniedError(
                "This software is private and cannot be purchased."
            )

        if software.price_cents <= 0:
            raise SoftwareDomainError("This software is free and does not require checkout.")

        if await self.has_purchase(software_id=software_id, user_id=user_id):
            raise SoftwareDomainError("You already own this software.")
        
        
    
    async def confirm_checkout():
        raise NotImplementedError()
                       
        

 