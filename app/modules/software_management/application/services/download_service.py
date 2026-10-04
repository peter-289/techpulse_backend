from __future__ import annotations

import asyncio
import logging
from typing import BinaryIO
from uuid import UUID

from app.exceptions.exceptions import ExternalServiceError
from app.modules.software_management.domain.ports.unit_of_work import SoftwareManagementUnitOfWork
from app.modules.software_management.domain.ports.storage import (
    Storage,
    StorageFileNotFoundError,
    StorageReadError,
    StorageSecurityError,
    StorageUnavailableError,
)
from app.modules.shared.enums import ArtifactStatus

from app.modules.software_management.domain.exceptions import (
    ArtifactNotFoundError,
    ArtifactStorageUnreadableError,
    ExpiredDownloadTokenError,
    InvalidDownloadTokenError,
    SoftwareAccessDeniedError,
    SoftwareNotFoundError,
    UnsafeStorageKeyError,
    VersionNotDownloadableError,
    VersionNotFoundError,
)
from app.modules.software_management.domain.ports.download_signer import (
    DownloadSigner,
    SignedDownloadUrl,
    TokenRejectionReason,
)
from app.modules.software_management.domain.value_objects import SemVer

logger = logging.getLogger(__name__)


class DownloadService:
    """Application service for generating download URLs and recording downloads."""

    def __init__(self, *, uow: SoftwareManagementUnitOfWork, url_signer: DownloadSigner, storage: Storage) -> None:
        self._uow = uow # unit_of_work Abstraction
        self._url_signer = url_signer # URL Signer Abstraction
        self._storage = storage  # Storage Abstraction

    async def create_download_url(
        self,
        *,
        software_id: UUID,
        version_number: str | SemVer,
        user_id: UUID,
    ) -> SignedDownloadUrl:
        async with self._uow.read_only():
            software = await self._uow.software_repo.get(software_id)

        if software is None:
            raise SoftwareNotFoundError(f"Software {software_id} not found.")

        semver = version_number if isinstance(version_number, SemVer) else SemVer.parse(version_number)
        try:
            version = software.get_version_by_semver(semver)
        except SoftwareNotFoundError as exc:
            raise VersionNotFoundError(f"Version {semver} not found.") from exc

        if not version.is_downloadable():
            raise VersionNotDownloadableError(f"Version {semver} is not downloadable.")
        if len(version.artifacts) != 1:
            raise ArtifactNotFoundError("Version download requires exactly one artifact.")
        has_purchase = await self._uow.software_repo.has_purchase(
            software_id=software_id, user_id=user_id
        )
        if not software.is_public() and not software.is_owned_by(user_id) and not has_purchase:
            raise SoftwareAccessDeniedError("You are not authorized to download this software.")

        artifact = version.artifacts[0]
        url = self._url_signer.create_url(storage_key=artifact.storage_key, method="GET")
        await self.record_download(software_id=software_id, version_id=version.id)
        logger.info("download_url_generated software=%s version=%s user=%s", software_id, semver, user_id)
        return url

    async def create_artifact_download_url(
        self,
        *,
        software_id: UUID,
        version_number: str | SemVer,
        artifact_id: UUID,
        user_id: UUID,
    ) -> SignedDownloadUrl:
        """Authorize a single-artifact download and sign it.

        Takes identifiers rather than an ``Artifact`` so the authorization cannot
        be skipped by handing it a resolved entity. The caller chooses *which*
        artifact it wants; this method decides whether that request is allowed,
        which means re-reading the aggregate rather than trusting the caller's copy.

        The rules are the same as :meth:`create_download_url` -- a draft, revoked
        or deleted version is not downloadable, and a private or paid package needs
        ownership or a purchase. They are enforced here rather than at the caller
        because this path previously reimplemented them and dropped
        ``is_downloadable``: revoking a version did not stop downloads through
        this endpoint, while the version endpoint honoured the revocation.
        """
        async with self._uow.read_only():
            software = await self._uow.software_repo.get(software_id)
        if software is None:
            raise SoftwareNotFoundError(f"Software {software_id} not found.")

        semver = version_number if isinstance(version_number, SemVer) else SemVer.parse(version_number)
        try:
            version = software.get_version_by_semver(semver)
        except SoftwareNotFoundError as exc:
            raise VersionNotFoundError(f"Version {semver} not found.") from exc

        if not version.is_downloadable():
            raise VersionNotDownloadableError(f"Version {semver} is not downloadable.")

        artifact = next((item for item in version.artifacts if item.id == artifact_id), None)
        if artifact is None:
            raise ArtifactNotFoundError(f"Artifact {artifact_id} not found in version {semver}.")
        if artifact.status is not ArtifactStatus.ACTIVE:
            raise VersionNotDownloadableError("Artifact is not active.")

        has_purchase = await self._uow.software_repo.has_purchase(
            software_id=software_id, user_id=user_id
        )
        if not software.is_public() and not software.is_owned_by(user_id) and not has_purchase:
            raise SoftwareAccessDeniedError("You are not authorized to download this software.")

        url = self._url_signer.create_url(storage_key=artifact.storage_key, method="GET")
        # Counted here, not left to the caller: the version path records its
        # download, and this path silently under-reported every download it served.
        await self.record_download(software_id=software_id, version_id=version.id)
        logger.info("artifact_download_url_generated artifact=%s user=%s", artifact.id, user_id)
        return url

    async def verify_token(
        self,
        *,
        storage_key: str,
        expires: int,
        token: str,
        method: str,
    ) -> bool:
        """Check a presented signed URL, or refuse it.

        Cryptographic verification is the signer's job and authorization is not
        performed here at all -- this endpoint is reachable without a session,
        so the token *is* the credential. The signer reports which check failed
        so an expired link and a tampered one do not both surface as one opaque
        refusal.

        Raises:
            ExpiredDownloadTokenError: the signature is authentic but has lapsed.
            InvalidDownloadTokenError: missing, malformed, forged, bound to a
                different resource, or bound to a different method.
        """
        result = self._url_signer.verify_token(
            storage_key=storage_key,
            expires=expires,
            token=token,
            method=method,
        )
        if result.valid:
            return True

        if result.reason is TokenRejectionReason.EXPIRED:
            raise ExpiredDownloadTokenError("This download link has expired.")
        raise InvalidDownloadTokenError("Invalid download token.")

    async def record_download(self, *, software_id: UUID, version_id: UUID | None = None) -> None:
        # No try/except around this transaction. The repository already maps
        # SQLAlchemyError onto RepositoryUnavailableError, so a handler here
        # would be a second place to forget that mapping and a lint against the
        # rule the repositories are supposed to own.
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
                    version.record_download()

            await self._uow.software_repo.save(software)

        logger.info("download_recorded software=%s version=%s", software_id, version_id)

    async def read_file(self, *, storage_key: str) -> BinaryIO:
        """Open a stored artifact for streaming, through the Storage port.

        Every storage failure is translated into its own domain error rather
        than collapsed: the caller has to be able to answer 404 "no such
        artifact" separately from 403 "that key is not addressable", 503 "storage
        is down" and 500 "storage is up but the read failed".

        raises:
            ArtifactNotFoundError: the key is valid but no file is stored there.
            UnsafeStorageKeyError: the token was authentic but the key it is bound
                to is not addressable (traversal, absolute path, malformed). Kept
                distinct from a bad token: nothing about the client's link was
                wrong, so it must not be reported or logged as a bad link.
            ArtifactStorageUnreadableError: the file exists but could not be
                opened or read.
            ExternalServiceError: storage itself is unavailable.
        """
        try:
            return await asyncio.to_thread(self._storage.open, storage_key=storage_key)
        except StorageFileNotFoundError as exc:
            raise ArtifactNotFoundError("Stored artifact not found.") from exc
        except StorageSecurityError as exc:
            # The signature was already verified against this exact key before
            # storage was consulted, so reaching here means a genuine token names
            # something the adapter will not resolve. That is a security event, not
            # a client error, and it is logged as one.
            logger.warning(
                "artifact_storage_key_refused reason=%s", type(exc).__name__
            )
            raise UnsafeStorageKeyError("Storage key is not addressable.") from exc
        except StorageUnavailableError as exc:
            raise ExternalServiceError("Storage temporarily unavailable.") from exc
        except StorageReadError as exc:
            # The adapter's message can name the resolved filesystem path. It is
            # logged here and never returned, so no storage layout escapes.
            logger.warning("artifact_read_failed storage_error=%s", type(exc).__name__)
            raise ArtifactStorageUnreadableError("Stored artifact could not be read.") from exc
