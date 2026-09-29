from __future__ import annotations

import asyncio
import inspect
import logging
from pathlib import Path
from typing import Sequence
from uuid import UUID, uuid4

from app.modules.software_management.domain.ports.unit_of_work import SoftwareManagementUnitOfWork
from app.modules.shared.enums import ArtifactStatus, SoftwareVisibility, VersionStatus
from app.modules.software_management.application.services.category_service import CategoryService
from app.modules.software_management.application.services.download_service import DownloadService
from app.modules.software_management.domain.entities.artifact import Artifact
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.entities.version import Version
from app.modules.software_management.domain.exceptions import (
    DownloadDeniedError,
    InvalidSemVerError,
    SoftwareAccessDeniedError,
    SoftwareDomainError,
    SoftwareNotFoundError,
)
from app.modules.software_management.domain.ports.artifact_stager import ArtifactUpload
from app.modules.software_management.domain.ports.download_signer import SignedDownloadUrl
from app.modules.software_management.domain.ports.event_publisher import DomainEventPublisher
from app.modules.software_management.domain.ports.malware_scanner import MalwareScanner, ScanResult
from app.modules.software_management.domain.ports.storage import Storage
from app.modules.software_management.domain.value_objects import OwnedSoftwareCard, SemVer

logger = logging.getLogger(__name__)


class SoftwareService:
    """Application service orchestrating software lifecycle use cases."""

    def __init__(
        self,
        *,
        download_service: DownloadService | None = None,
        storage: Storage | None = None,
        malware_scanner: MalwareScanner | None = None,
        unit_of_work: SoftwareManagementUnitOfWork | None = None,
        category_service: CategoryService | None = None,
        event_publisher: DomainEventPublisher | None = None,
    ) -> None:
        self._download_service = download_service
        self._storage = storage
        self._malware_scanner = malware_scanner
        self._uow = unit_of_work
        self._category_service = category_service
        self._event_publisher = event_publisher

    @property
    def repository(self):
        override = getattr(self, "_repository_override", None)
        if override is not None:
            return override
        return self._uow.software_repo

    @repository.setter
    def repository(self, value) -> None:
        self._repository_override = value

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

    async def list_versions(self, *, software_id: UUID, user_id: UUID, limit: int) -> list[Version]:
        """List all versions of a software.

        Returns domain entities; the API layer renders them. Returning the
        Pydantic read model from here would make the use-case depend on the wire
        format it happens to be delivered over.
        """
        async with self._uow.read_only():
            software = await self._uow.software_repo.get(software_id=software_id)
        if software is None:
            raise SoftwareNotFoundError("Software not found.")

        return list(software.versions[:limit])

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
                software.add_artifact_to_version(version=version, artifact=artifact)
                saved_storage_keys.append(artifact.storage_key)

            software.add_version(version)
            if version.artifacts and all(artifact.status == ArtifactStatus.ACTIVE for artifact in version.artifacts):
                software.publish_version(version.id)

            async with self._uow:
                await self._uow.software_repo.save(software)

        except Exception:
            for storage_key in saved_storage_keys:
                try:
                    self._storage.delete(storage_key=storage_key)
                except Exception:
                    logger.exception("Failed to clean up stored artifact %s", storage_key)
            raise

        # Dispatch only after the transaction has committed. The aggregate
        # recorded these facts as they happened, but until the commit lands they
        # are only true in memory, and a rollback would take them back.
        await self._dispatch_events(software)
        return software, version

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
        return artifact

    async def _dispatch_events(self, software: Software) -> None:
        """Hand the aggregate's pending events to the outbound publisher.

        A delivery failure is logged rather than raised: by this point the
        transaction has committed, so the business operation succeeded. Raising
        here would report a committed upload as failed, and the caller would
        retry a change that had already been applied.
        """
        events = software.pull_events()
        if not events or self._event_publisher is None:
            return
        try:
            await self._event_publisher.publish(events)
        except Exception:
            logger.exception("Failed to dispatch %d domain event(s)", len(events))

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
