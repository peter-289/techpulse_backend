from __future__ import annotations

import logging
from typing import BinaryIO
from uuid import UUID

from fastapi.concurrency import run_in_threadpool
from sqlalchemy.exc import SQLAlchemyError

from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.software_management.domain.exceptions import (
    ArtifactNotFoundError,
    RepositoryUnavailableError,
    SoftwareAccessDeniedError,
    SoftwareNotFoundError,
    VersionNotDownloadableError,
    VersionNotFoundError,
)
from app.modules.software_management.domain.ports.download_signer import DownloadSigner, SignedDownloadUrl
from app.modules.software_management.domain.value_objects import SemVer
from app.infrastructure.storage.local_storage import Storage, StorageFileNotFoundError, StorageSecurityError, StorageUnavailableError
from app.exceptions.exceptions import ExternalServiceError

logger = logging.getLogger(__name__)


class DownloadService:
    """Application service for generating download URLs and recording downloads."""

    def __init__(self, *, uow: UnitOfWork, url_signer: DownloadSigner, storage: Storage) -> None:
        self._uow = uow
        self._url_signer = url_signer
        self._storage = storage

    async def create_download_url(
        self,
        *,
        software_id: UUID,
        version_number: str | SemVer,
        user_id: UUID,
    ) -> SignedDownloadUrl:
        try:
            async with self._uow.read_only():
                software = await self._uow.software_repo.get(software_id)
        except SQLAlchemyError as exc:
            raise RepositoryUnavailableError("Failed to load software for download URL generation.") from exc

        if software is None:
            raise SoftwareNotFoundError(f"Software {software_id} not found.")

        semver = version_number if isinstance(version_number, SemVer) else SemVer.parse(version_number)
        try:
            version = software.get_version_by_semver(semver)
        except SoftwareNotFoundError as exc:
            raise VersionNotFoundError(f"Version {semver} not found.") from exc

        if not version.is_downloadable():
            raise VersionNotDownloadableError(f"Version {semver} is not downloadable.")

        if version.artifact is None:
            raise ArtifactNotFoundError(f"Version {semver} has no artifact.")

        has_purchase = await self._uow.software_repo.has_purchase(
            software_id=software_id,
            user_id=user_id,
        )
        if not (software.is_public() or software.is_owned_by(user_id) or has_purchase):
            raise SoftwareAccessDeniedError("You are not authorized to download this software.")

        url = self._url_signer.create_url(storage_key=version.artifact.storage_key, method="GET")
        
        await self.record_download(software_id=software_id, version_id=version.id)
        logger.info(
            "download_url_generated software=%s version=%s user=%s",
            software_id,
            semver,
            user_id,
        )
        return url

    async def verify_token(
            self, 
            *, 
            storage_key: str,
            expires: int,
            token: str,
            method: str,) -> bool:
        """Calls verify_token() from any implementation of DownloadUrlSigner Protocol."""
        if not self._url_signer.verify_token(
            storage_key=storage_key,
            expires=expires,
            token=token,
            method=method,
            ):
            raise SoftwareAccessDeniedError("Invalid or expired download token")
        
    async def record_download(self, *, software_id: UUID, version_id: UUID | None = None) -> None:
        try:
            async with self._uow:
                software = await self._uow.software_repo.get(software_id)
                if software is None:
                    raise SoftwareNotFoundError(f"Software {software_id} not found.")

                software.increment_download_count()
                if version_id is not None:
                    try:
                        version = software.get_version(version_id)
                    except SoftwareNotFoundError:
                        version = None
                    if version is not None:
                        version.download_count += 1
                        version._touch()

                await self._uow.software_repo.save(software)
        except SQLAlchemyError as exc:
            raise RepositoryUnavailableError("Failed to record software download.") from exc

        logger.info("download_recorded software=%s version=%s", software_id, version_id)

    async def read_file(self, *, storage_key: str) -> BinaryIO:
        """Calls open() for any implementation of Storage() protocol."""
        try:
            file_handle = await run_in_threadpool(self._storage.open, storage_key=storage_key)
        except StorageFileNotFoundError as exc:
            raise ArtifactNotFoundError("Stored artifact not found.") from exc
        except StorageSecurityError as exc:
            raise SoftwareAccessDeniedError("Invalid storage key.") from exc
        except StorageUnavailableError as exc:
            raise ExternalServiceError("Storage temporarily unavailable.") from exc

        return file_handle