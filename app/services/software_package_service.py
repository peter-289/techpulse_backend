from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterable

from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.unit_of_work import UnitOfWork
from app.domain.software_package import FileVersionDraft, SoftwarePackageDraft
from app.exceptions.exceptions import ConflictError, NotFoundError, PermissionError, ValidationError
from app.infrastructure.checksum import StreamingSHA256
from app.infrastructure.security.malware_scanner import MalwareScanner, NoOpMalwareScanner
from app.infrastructure.storage.base import StorageBackend


@dataclass(frozen=True)
class UploadInitResult:
    upload_id: str
    offset: int
    max_size_bytes: int


@dataclass(frozen=True)
class UploadAppendResult:
    upload_id: str
    offset: int
    status: str


@dataclass(frozen=True)
class DownloadTicket:
    storage_key: str
    file_name: str
    content_type: str | None
    file_size_bytes: int
    checksum_sha256: str


@dataclass(frozen=True)
class AdminPackageItem:
    package_id: int
    name: str
    category: str
    language: str
    owner_id: int
    owner_username: str
    owner_email: str
    is_public: bool
    latest_version: str | None
    created_at: object
    updated_at: object


class SoftwarePackageService:
    ALLOWED_CATEGORIES = {
        "networking software",
        "cracked software",
        "student projects",
        "desktop applications",
        "mobile application",
    }
    ALLOWED_EXTENSIONS = {
        ".zip",
        ".tar",
        ".gz",
        ".rar",
        ".7z",
        ".exe",
        ".msi",
        ".deb",
        ".rpm",
        ".whl",
    }

    def __init__(
        self,
        uow: UnitOfWork,
        storage: StorageBackend,
        scanner: MalwareScanner | None = None,
        max_file_size_bytes: int = settings.PACKAGE_UPLOAD_MAX_SIZE_BYTES,
        user_quota_bytes: int = settings.PACKAGE_USER_QUOTA_BYTES,
    ):
        self.uow = uow
        self.storage = storage
        self.scanner = scanner or NoOpMalwareScanner()
        self.max_file_size_bytes = max_file_size_bytes
        self.user_quota_bytes = user_quota_bytes

    def _validate_file_name(self, file_name: str) -> None:
        suffix = Path(file_name or "").suffix.lower()
        if suffix not in self.ALLOWED_EXTENSIONS:
            raise ValidationError("Unsupported package file format")

    def _build_storage_key(self, checksum_sha256: str) -> str:
        return f"blobs/{checksum_sha256[:2]}/{checksum_sha256}"

    def init_upload_session(
        self,
        *,
        user_id: int,
        package_name: str,
        package_description: str,
        package_category: str,
        package_language: str,
        package_version: str,
        is_public: bool,
        file_name: str,
        content_type: str | None,
        max_size_bytes: int | None = None,
    ) -> UploadInitResult:
        package_draft = SoftwarePackageDraft(
            owner_id=user_id,
            name=(package_name or "").strip(),
            description=(package_description or "").strip(),
            category=(package_category or "").strip().lower(),
            language=(package_language or "").strip(),
            version=(package_version or "").strip(),
            file_name=(file_name or "").strip(),
            content_type=content_type,
            is_public=is_public,
        )
        package_draft.validate()
        if package_draft.category not in self.ALLOWED_CATEGORIES:
            raise ValidationError("Unsupported package category")
        self._validate_file_name(package_draft.file_name)

        effective_max = max_size_bytes or self.max_file_size_bytes
        if effective_max <= 0:
            raise ValidationError("Invalid max size")
        if effective_max > self.max_file_size_bytes:
            raise ValidationError("Requested max size exceeds server limit")

        upload_id = uuid.uuid4().hex
        with self.uow:
            self.uow.software_package_repo.create_upload_session(
                upload_id=upload_id,
                user_id=user_id,
                package_name=package_draft.name,
                package_description=package_draft.description,
                package_category=package_draft.category,
                package_language=package_draft.language,
                package_version=package_draft.version,
                is_public=is_public,
                file_name=package_draft.file_name,
                content_type=content_type,
                max_size_bytes=effective_max,
                status="PENDING",
            )

        return UploadInitResult(upload_id=upload_id, offset=0, max_size_bytes=effective_max)

    async def append_upload_stream(
        self,
        *,
        upload_id: str,
        user_id: int,
        expected_offset: int,
        chunk_stream: AsyncIterable[bytes],
    ) -> UploadAppendResult:
        with self.uow:
            session = self.uow.software_package_repo.get_upload_session_for_user_for_update(
                upload_id=upload_id, user_id=user_id
            )
            if not session:
                raise NotFoundError("Upload session not found")
            if session.status in {"COMPLETED", "FAILED", "FINALIZING"}:
                raise ConflictError(f"Upload session is not writable (status={session.status})")
            if session.bytes_received != expected_offset:
                raise ConflictError(
                    f"Upload offset mismatch. expected={session.bytes_received}, provided={expected_offset}"
                )
            session.status = "UPLOADING"
            max_size = session.max_size_bytes

        bytes_appended = 0
        try:
            async for chunk in chunk_stream:
                if not chunk:
                    continue
                bytes_appended += len(chunk)
                projected = expected_offset + bytes_appended
                if projected > max_size:
                    raise ValidationError("Upload exceeds maximum allowed file size")
                await self.storage.append_upload_chunk(upload_id, chunk)
        except Exception:
            current_size = await self.storage.get_upload_size(upload_id)
            with self.uow:
                failed = self.uow.software_package_repo.get_upload_session_for_user_for_update(
                    upload_id=upload_id, user_id=user_id
                )
                if failed:
                    failed.bytes_received = current_size
                    failed.status = "FAILED"
                    failed.error_message = "Chunk append failed"
            raise

        new_offset = await self.storage.get_upload_size(upload_id)
        with self.uow:
            session = self.uow.software_package_repo.get_upload_session_for_user_for_update(
                upload_id=upload_id, user_id=user_id
            )
            if not session:
                raise NotFoundError("Upload session not found")
            session.bytes_received = new_offset
            session.status = "UPLOADING"
            session.error_message = None
            return UploadAppendResult(upload_id=upload_id, offset=new_offset, status=session.status)

    async def upload_single_request(
        self,
        *,
        user_id: int,
        package_name: str,
        package_description: str,
        package_category: str,
        package_language: str,
        package_version: str,
        is_public: bool,
        file_name: str,
        content_type: str | None,
        chunk_stream: AsyncIterable[bytes],
    ) -> tuple[str, int]:
        start = time.perf_counter()
        init = self.init_upload_session(
            user_id=user_id,
            package_name=package_name,
            package_description=package_description,
            package_category=package_category,
            package_language=package_language,
            package_version=package_version,
            is_public=is_public,
            file_name=file_name,
            content_type=content_type,
        )
        await self.storage.init_upload(init.upload_id)
        hasher = StreamingSHA256()
        try:
            async def _single_request_stream():
                async for chunk in chunk_stream:
                    if chunk:
                        hasher.update(chunk)
                        yield chunk

            await self.append_upload_stream(
                upload_id=init.upload_id,
                user_id=user_id,
                expected_offset=0,
                chunk_stream=_single_request_stream(),
            )
            version_id = await self._finalize_upload_with_checksum(
                upload_id=init.upload_id,
                user_id=user_id,
                checksum=hasher.hexdigest(),
                size_bytes=hasher.size_bytes,
            )
        except Exception:
            await self.storage.abort_upload(init.upload_id)
            raise
        finally:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            logging.info(
                "[package_upload] upload_id=%s user_id=%s elapsed_ms=%s",
                init.upload_id,
                user_id,
                elapsed_ms,
            )
        return init.upload_id, version_id

    async def complete_upload(self, *, upload_id: str, user_id: int) -> int:
        hasher = StreamingSHA256()
        async for chunk in self.storage.stream_upload(upload_id, chunk_size=settings.PACKAGE_UPLOAD_CHUNK_SIZE_BYTES):
            hasher.update(chunk)
        return await self._finalize_upload_with_checksum(
            upload_id=upload_id,
            user_id=user_id,
            checksum=hasher.hexdigest(),
            size_bytes=hasher.size_bytes,
        )

    async def _finalize_upload_with_checksum(
        self,
        *,
        upload_id: str,
        user_id: int,
        checksum: str,
        size_bytes: int,
    ) -> int:
        try:
            with self.uow:
                session = self.uow.software_package_repo.get_upload_session_for_user_for_update(
                    upload_id=upload_id, user_id=user_id
                )
                if not session:
                    raise NotFoundError("Upload session not found")
                if session.status == "COMPLETED":
                    if session.completed_file_version_id is None:
                        raise ConflictError("Upload already completed with missing version reference")
                    return session.completed_file_version_id
                if session.status == "FAILED":
                    raise ConflictError("Upload session failed and cannot be completed")
                if session.status == "FINALIZING":
                    raise ConflictError("Upload session is already finalizing")
                session.status = "FINALIZING"
                if session.bytes_received <= 0:
                    raise ValidationError("Upload contains no data")

                package_name = session.package_name
                package_description = session.package_description
                package_category = session.package_category
                package_language = session.package_language
                package_version = session.package_version
                is_public = session.is_public
                file_name = session.file_name
                content_type = session.content_type
                max_size_bytes = session.max_size_bytes

            if size_bytes <= 0:
                raise ValidationError("Upload contains no data")
            if size_bytes > max_size_bytes:
                raise ValidationError("Upload exceeds maximum allowed file size")

            version_draft = FileVersionDraft(
                version=package_version,
                checksum_sha256=checksum,
                size_bytes=size_bytes,
            )
            version_draft.validate()

            await self.scanner.scan_stream(
                self.storage.stream_upload(upload_id, chunk_size=settings.PACKAGE_UPLOAD_CHUNK_SIZE_BYTES),
                filename=file_name,
                content_type=content_type,
            )

            storage_key = self._build_storage_key(checksum_sha256=checksum)

            with self.uow:
                repo = self.uow.software_package_repo
                current_usage = repo.get_total_uploaded_bytes_for_user(user_id)
                if current_usage + size_bytes > self.user_quota_bytes:
                    raise ValidationError("Storage quota exceeded")

            blob = None
            with self.uow:
                blob = self.uow.software_package_repo.get_blob_by_checksum_and_size(
                    checksum_sha256=checksum,
                    size_bytes=size_bytes,
                )
                if blob:
                    self.uow.software_package_repo.increment_blob_refcount(blob)

            if not blob:
                await self.storage.promote_upload(upload_id, storage_key)
                try:
                    with self.uow:
                        blob = self.uow.software_package_repo.get_blob_by_checksum_and_size(
                            checksum_sha256=checksum,
                            size_bytes=size_bytes,
                        )
                        if blob:
                            self.uow.software_package_repo.increment_blob_refcount(blob)
                        else:
                            blob = self.uow.software_package_repo.add_blob(
                                checksum_sha256=checksum,
                                size_bytes=size_bytes,
                                storage_key=storage_key,
                            )
                except IntegrityError as exc:
                    raise ConflictError("Blob consistency conflict") from exc
            else:
                await self.storage.abort_upload(upload_id)

            try:
                with self.uow:
                    repo = self.uow.software_package_repo
                    package = repo.upsert_package(
                        owner_id=user_id,
                        name=package_name,
                        description=package_description,
                        category=package_category,
                        language=package_language,
                        is_public=is_public,
                        latest_version=package_version,
                    )
                    version_row = repo.add_file_version(
                        package_id=package.id,
                        blob_id=blob.id,
                        file_name=file_name,
                        content_type=content_type,
                        version=package_version,
                        size_bytes=size_bytes,
                        checksum_sha256=checksum,
                    )
                    session = repo.get_upload_session_for_user_for_update(upload_id=upload_id, user_id=user_id)
                    if not session:
                        raise NotFoundError("Upload session not found")
                    session.status = "COMPLETED"
                    session.completed_file_version_id = version_row.id
                    session.error_message = None
                    return version_row.id
            except IntegrityError as exc:
                with self.uow:
                    repo = self.uow.software_package_repo
                    dup_blob = repo.get_blob_by_checksum_and_size(checksum_sha256=checksum, size_bytes=size_bytes)
                    if dup_blob and dup_blob.id == blob.id:
                        repo.decrement_blob_refcount(dup_blob)
                    failed = repo.get_upload_session_for_user_for_update(upload_id=upload_id, user_id=user_id)
                    if failed:
                        failed.status = "FAILED"
                        failed.error_message = "Version already exists for this package"
                raise ConflictError("Package version already exists") from exc
        except (ConflictError, NotFoundError):
            raise
        except Exception as exc:
            with self.uow:
                failed = self.uow.software_package_repo.get_upload_session_for_user_for_update(
                    upload_id=upload_id, user_id=user_id
                )
                if failed and failed.status != "COMPLETED":
                    failed.status = "FAILED"
                    failed.error_message = "Upload finalize failed"
            raise exc

    def list_packages(self, *, user_id: int, offset: int = 0, limit: int = 50, language: str | None = None):
        with self.uow:
            return self.uow.software_package_repo.list_packages(
                user_id=user_id,
                offset=offset,
                limit=limit,
                language=language,
            )

    def list_package_versions(
        self,
        *,
        user_id: int,
        package_id: int,
        limit: int = 20,
    ):
        with self.uow:
            repo = self.uow.software_package_repo
            package = repo.get_package_by_id(package_id)
            if not package:
                raise NotFoundError("Package not found")
            if not package.is_public and package.owner_id != user_id:
                raise PermissionError("You do not have access to this package")
            return repo.list_file_versions_for_package(package_id=package_id, limit=limit)

    def fail_upload_session(self, *, upload_id: str, user_id: int, error_message: str) -> None:
        with self.uow:
            session = self.uow.software_package_repo.get_upload_session_for_user_for_update(
                upload_id=upload_id, user_id=user_id
            )
            if not session or session.status == "COMPLETED":
                return
            session.status = "FAILED"
            session.error_message = (error_message or "Upload initialization failed")[:500]

    def get_download_ticket(
        self,
        *,
        user_id: int,
        package_id: int,
        version_id: int,
    ) -> DownloadTicket:
        with self.uow:
            repo = self.uow.software_package_repo
            package = repo.get_package_by_id(package_id)
            if not package:
                raise NotFoundError("Package not found")
            if not package.is_public:
                raise PermissionError("Private software is view-only and cannot be downloaded")

            version_row = repo.get_file_version_for_package(package_id=package_id, version_id=version_id)
            if not version_row:
                raise NotFoundError("File version not found")

            blob = repo.get_blob_by_checksum_and_size(
                checksum_sha256=version_row.checksum_sha256,
                size_bytes=version_row.size_bytes,
            )
            if not blob:
                raise NotFoundError("Backing file not found")

            repo.increment_file_version_download_count(version_row)
            return DownloadTicket(
                storage_key=blob.storage_key,
                file_name=version_row.file_name,
                content_type=version_row.content_type,
                file_size_bytes=version_row.size_bytes,
                checksum_sha256=version_row.checksum_sha256,
            )

    async def cancel_upload(self, *, upload_id: str, user_id: int) -> None:
        with self.uow:
            session = self.uow.software_package_repo.get_upload_session_for_user_for_update(
                upload_id=upload_id,
                user_id=user_id,
            )
            if not session:
                raise NotFoundError("Upload session not found")
            if session.status == "COMPLETED":
                raise ConflictError("Cannot cancel completed upload")
            session.status = "FAILED"
            session.error_message = "Upload canceled by client"
        await self.storage.abort_upload(upload_id)

    async def delete_package_for_owner(self, *, package_id: int, user_id: int) -> None:
        storage_keys_to_delete: list[str] = []
        with self.uow:
            repo = self.uow.software_package_repo
            package = repo.get_package_by_id(package_id)
            if not package:
                raise NotFoundError("Package not found")
            if package.owner_id != user_id:
                raise PermissionError("Only the package owner can delete this package")

            versions = repo.list_all_file_versions_for_package(package_id=package_id)
            for version_row in versions:
                blob = repo.get_blob_by_id(version_row.blob_id)
                repo.delete_file_version(version_row)
                if blob:
                    repo.decrement_blob_refcount(blob)
                    if blob.reference_count <= 0:
                        storage_keys_to_delete.append(blob.storage_key)
                        repo.delete_blob(blob)
            repo.delete_package(package)

        for storage_key in storage_keys_to_delete:
            try:
                await self.storage.delete_object(storage_key)
            except Exception as exc:
                logging.warning("[package_delete] failed to delete storage_key=%s: %s", storage_key, exc)

    def get_admin_summary(self) -> dict:
        with self.uow:
            repo = self.uow.software_package_repo
            total_packages = repo.get_total_package_count()
            private_packages = repo.get_private_package_count()
            total_versions = repo.get_total_file_version_count()
            total_downloads = repo.get_total_download_count()
            top_languages = repo.get_top_languages(limit=5)
            top_categories = repo.get_top_categories(limit=5)
            return {
                "total_packages": total_packages,
                "private_packages": private_packages,
                "public_packages": max(0, total_packages - private_packages),
                "total_versions": total_versions,
                "total_downloads": total_downloads,
                "top_languages": [
                    {"language": language, "count": count} for language, count in top_languages
                ],
                "top_categories": [
                    {"category": category, "count": count} for category, count in top_categories
                ],
            }

    def list_packages_admin(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        owner_query: str | None = None,
        only_private: bool = False,
    ) -> list[AdminPackageItem]:
        with self.uow:
            rows = self.uow.software_package_repo.list_packages_admin(
                offset=offset,
                limit=limit,
                owner_query=owner_query,
                only_private=only_private,
            )
            return [
                AdminPackageItem(
                    package_id=package.id,
                    name=package.name,
                    category=package.category,
                    language=package.language,
                    owner_id=user.id,
                    owner_username=user.username,
                    owner_email=user.email,
                    is_public=package.is_public,
                    latest_version=package.latest_version,
                    created_at=package.created_at,
                    updated_at=package.updated_at,
                )
                for package, user in rows
            ]
