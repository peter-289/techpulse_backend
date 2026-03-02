from __future__ import annotations

from typing import Optional

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.models.file_blob import FileBlob
from app.models.file_version import FileVersion
from app.models.software_package import SoftwarePackage
from app.models.upload_session import UploadSession
from app.models.user import User


class SoftwarePackageRepo:
    def __init__(self, db: Session):
        self.db = db

    def get_package_by_id(self, package_id: int) -> Optional[SoftwarePackage]:
        return self.db.get(SoftwarePackage, package_id)

    def get_package_by_owner_and_name(self, owner_id: int, name: str) -> Optional[SoftwarePackage]:
        stmt = select(SoftwarePackage).where(
            and_(SoftwarePackage.owner_id == owner_id, SoftwarePackage.name == name)
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def upsert_package(
        self,
        *,
        owner_id: int,
        name: str,
        description: str,
        category: str,
        language: str,
        is_public: bool,
        latest_version: str,
    ) -> SoftwarePackage:
        package = self.get_package_by_owner_and_name(owner_id=owner_id, name=name)
        if package:
            package.description = description
            package.category = category
            package.language = language
            package.is_public = is_public
            package.latest_version = latest_version
            return package
        package = SoftwarePackage(
            owner_id=owner_id,
            name=name,
            description=description,
            category=category,
            language=language,
            is_public=is_public,
            latest_version=latest_version,
        )
        self.db.add(package)
        self.db.flush()
        self.db.refresh(package)
        return package

    def list_packages(
        self,
        *,
        user_id: int,
        offset: int = 0,
        limit: int = 50,
        language: str | None = None,
    ) -> list[SoftwarePackage]:
        stmt = (
            select(SoftwarePackage)
            .where(
                or_(
                    SoftwarePackage.is_public.is_(True),
                    SoftwarePackage.owner_id == user_id,
                )
            )
            .order_by(SoftwarePackage.updated_at.desc())
        )
        if language:
            stmt = stmt.where(SoftwarePackage.language.ilike(f"%{language.strip()}%"))
        stmt = stmt.offset(offset).limit(limit)
        return self.db.execute(stmt).scalars().all()

    def get_blob_by_checksum_and_size(self, *, checksum_sha256: str, size_bytes: int) -> Optional[FileBlob]:
        stmt = select(FileBlob).where(
            and_(FileBlob.checksum_sha256 == checksum_sha256, FileBlob.size_bytes == size_bytes)
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def add_blob(self, *, checksum_sha256: str, size_bytes: int, storage_key: str) -> FileBlob:
        blob = FileBlob(
            checksum_sha256=checksum_sha256,
            size_bytes=size_bytes,
            storage_key=storage_key,
        )
        self.db.add(blob)
        self.db.flush()
        self.db.refresh(blob)
        return blob

    def increment_blob_refcount(self, blob: FileBlob) -> None:
        blob.reference_count += 1

    def decrement_blob_refcount(self, blob: FileBlob) -> None:
        blob.reference_count = max(0, blob.reference_count - 1)

    def add_file_version(
        self,
        *,
        package_id: int,
        blob_id: int,
        file_name: str,
        content_type: str | None,
        version: str,
        size_bytes: int,
        checksum_sha256: str,
    ) -> FileVersion:
        version_row = FileVersion(
            package_id=package_id,
            blob_id=blob_id,
            file_name=file_name,
            content_type=content_type,
            version=version,
            size_bytes=size_bytes,
            checksum_sha256=checksum_sha256,
        )
        self.db.add(version_row)
        self.db.flush()
        self.db.refresh(version_row)
        return version_row

    def get_file_version_by_id(self, version_id: int) -> Optional[FileVersion]:
        return self.db.get(FileVersion, version_id)

    def get_file_version_for_package(self, *, package_id: int, version_id: int) -> Optional[FileVersion]:
        stmt = select(FileVersion).where(
            and_(FileVersion.id == version_id, FileVersion.package_id == package_id)
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def list_file_versions_for_package(self, *, package_id: int, limit: int = 20) -> list[FileVersion]:
        stmt = (
            select(FileVersion)
            .where(FileVersion.package_id == package_id)
            .order_by(FileVersion.created_at.desc())
            .limit(limit)
        )
        return self.db.execute(stmt).scalars().all()

    def list_all_file_versions_for_package(self, *, package_id: int) -> list[FileVersion]:
        stmt = select(FileVersion).where(FileVersion.package_id == package_id)
        return self.db.execute(stmt).scalars().all()

    def increment_file_version_download_count(self, version_row: FileVersion) -> None:
        version_row.download_count += 1

    def get_total_uploaded_bytes_for_user(self, user_id: int) -> int:
        stmt = (
            select(func.coalesce(func.sum(FileVersion.size_bytes), 0))
            .select_from(FileVersion)
            .join(SoftwarePackage, SoftwarePackage.id == FileVersion.package_id)
            .where(SoftwarePackage.owner_id == user_id)
        )
        return int(self.db.execute(stmt).scalar_one())

    def get_blob_by_id(self, blob_id: int) -> Optional[FileBlob]:
        return self.db.get(FileBlob, blob_id)

    def delete_file_version(self, version_row: FileVersion) -> None:
        self.db.delete(version_row)

    def delete_blob(self, blob: FileBlob) -> None:
        self.db.delete(blob)

    def delete_package(self, package: SoftwarePackage) -> None:
        self.db.delete(package)

    def get_total_package_count(self) -> int:
        stmt = select(func.count(SoftwarePackage.id))
        return int(self.db.execute(stmt).scalar_one())

    def get_private_package_count(self) -> int:
        stmt = select(func.count(SoftwarePackage.id)).where(SoftwarePackage.is_public.is_(False))
        return int(self.db.execute(stmt).scalar_one())

    def get_total_file_version_count(self) -> int:
        stmt = select(func.count(FileVersion.id))
        return int(self.db.execute(stmt).scalar_one())

    def get_total_download_count(self) -> int:
        stmt = select(func.coalesce(func.sum(FileVersion.download_count), 0))
        return int(self.db.execute(stmt).scalar_one())

    def get_top_languages(self, limit: int = 5) -> list[tuple[str, int]]:
        stmt = (
            select(SoftwarePackage.language, func.count(SoftwarePackage.id))
            .group_by(SoftwarePackage.language)
            .order_by(func.count(SoftwarePackage.id).desc())
            .limit(limit)
        )
        return [(row[0], int(row[1])) for row in self.db.execute(stmt).all()]

    def get_top_categories(self, limit: int = 5) -> list[tuple[str, int]]:
        stmt = (
            select(SoftwarePackage.category, func.count(SoftwarePackage.id))
            .group_by(SoftwarePackage.category)
            .order_by(func.count(SoftwarePackage.id).desc())
            .limit(limit)
        )
        return [(row[0], int(row[1])) for row in self.db.execute(stmt).all()]

    def list_packages_admin(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        owner_query: str | None = None,
        only_private: bool = False,
    ) -> list[tuple[SoftwarePackage, User]]:
        stmt = (
            select(SoftwarePackage, User)
            .join(User, User.id == SoftwarePackage.owner_id)
            .order_by(SoftwarePackage.updated_at.desc())
            .offset(offset)
            .limit(limit)
        )
        if only_private:
            stmt = stmt.where(SoftwarePackage.is_public.is_(False))
        if owner_query:
            query = f"%{owner_query.strip()}%"
            stmt = stmt.where(
                (User.username.ilike(query))
                | (User.email.ilike(query))
                | (User.full_name.ilike(query))
            )
        return self.db.execute(stmt).all()

    def create_upload_session(
        self,
        *,
        upload_id: str,
        user_id: int,
        package_name: str,
        package_description: str,
        package_category: str,
        package_language: str,
        package_version: str,
        is_public: bool,
        file_name: str,
        content_type: str | None,
        max_size_bytes: int,
        status: str = "PENDING",
    ) -> UploadSession:
        session = UploadSession(
            id=upload_id,
            user_id=user_id,
            package_name=package_name,
            package_description=package_description,
            package_category=package_category,
            package_language=package_language,
            package_version=package_version,
            is_public=is_public,
            file_name=file_name,
            content_type=content_type,
            max_size_bytes=max_size_bytes,
            status=status,
        )
        self.db.add(session)
        self.db.flush()
        self.db.refresh(session)
        return session

    def get_upload_session(self, upload_id: str) -> Optional[UploadSession]:
        return self.db.get(UploadSession, upload_id)

    def get_upload_session_for_update(self, upload_id: str) -> Optional[UploadSession]:
        stmt = select(UploadSession).where(UploadSession.id == upload_id).with_for_update()
        return self.db.execute(stmt).scalar_one_or_none()

    def get_upload_session_for_user(self, *, upload_id: str, user_id: int) -> Optional[UploadSession]:
        stmt = select(UploadSession).where(
            and_(UploadSession.id == upload_id, UploadSession.user_id == user_id)
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def get_upload_session_for_user_for_update(self, *, upload_id: str, user_id: int) -> Optional[UploadSession]:
        stmt = (
            select(UploadSession)
            .where(and_(UploadSession.id == upload_id, UploadSession.user_id == user_id))
            .with_for_update()
        )
        return self.db.execute(stmt).scalar_one_or_none()
