from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker

from software_management.application.errors import ConflictError, ForbiddenError, NotFoundError
from software_management.application.interfaces import (
    AdminSoftwareRecord,
    AdminSummaryRecord,
    CreateVersionCommand,
    CreateVersionResult,
    DeleteSoftwareResult,
    DeprecateVersionResult,
    DownloadDescriptor,
    IdempotencyRecord,
    PublishVersionResult,
    RevokeVersionResult,
    SoftwareListRecord,
    SoftwareRepository,
    VersionListRecord,
)

from .models import ArtifactModel, IdempotencyKeyModel, SoftwareModel, VersionModel


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


_STATUS_DRAFT = "DRAFT"
_STATUS_PUBLISHED = "PUBLISHED"
_STATUS_DEPRECATED = "DEPRECATED"
_STATUS_REVOKED = "REVOKED"


class SQLAlchemySoftwareRepository(SoftwareRepository):
    def __init__(self, sessionmaker: async_sessionmaker) -> None:
        self._sessionmaker = sessionmaker

    async def get_software_owner(self, software_id: UUID) -> str | None:
        async with self._sessionmaker() as session:
            owner_stmt = select(SoftwareModel.owner_id).where(SoftwareModel.id == software_id)
            return (await session.execute(owner_stmt)).scalar_one_or_none()

    async def create_version(self, command: CreateVersionCommand) -> CreateVersionResult:
        now = _utc_now()
        try:
            async with self._sessionmaker() as session:
                async with session.begin():
                    software = await self._resolve_software_for_write(session, command, now)
                    artifact = ArtifactModel(
                        storage_key=command.artifact_storage_key,
                        file_name=command.artifact_file_name,
                        content_type=command.artifact_content_type,
                        file_hash=command.artifact_file_hash,
                        size_bytes=command.artifact_size_bytes,
                        created_at=now,
                    )
                    session.add(artifact)
                    await session.flush()

                    version = VersionModel(
                        software_id=software.id,
                        artifact_id=artifact.id,
                        version=command.version,
                        is_published=command.publish_now,
                        status=_STATUS_PUBLISHED if command.publish_now else _STATUS_DRAFT,
                        download_count=0,
                        created_at=now,
                        published_at=now if command.publish_now else None,
                        deprecated_at=None,
                        revoked_at=None,
                    )
                    session.add(version)
                    await session.flush()
                    software.row_version += 1
                    software.updated_at = now
                    if command.publish_now:
                        software.current_version_id = version.id
                    await session.flush()
                    return CreateVersionResult(
                        software_id=software.id,
                        version_id=version.id,
                        artifact_id=artifact.id,
                        version=version.version,
                        software_row_version=software.row_version,
                        published=version.is_published,
                    )
        except IntegrityError as exc:
            raise ConflictError("version already exists for software") from exc

    async def publish_version(
        self,
        actor_id: str,
        software_id: UUID,
        version: str,
        expected_software_row_version: int | None = None,
    ) -> PublishVersionResult:
        now = _utc_now()
        async with self._sessionmaker() as session:
            async with session.begin():
                software_stmt = (
                    select(SoftwareModel).where(SoftwareModel.id == software_id).with_for_update()
                )
                software = (await session.execute(software_stmt)).scalar_one_or_none()
                if software is None:
                    raise NotFoundError("software not found")
                if software.owner_id != actor_id:
                    raise ForbiddenError("actor cannot publish this software")
                if (
                    expected_software_row_version is not None
                    and software.row_version != expected_software_row_version
                ):
                    raise ConflictError("software version conflict")

                version_stmt = (
                    select(VersionModel)
                    .where(VersionModel.software_id == software.id, VersionModel.version == version)
                    .with_for_update()
                )
                version_row = (await session.execute(version_stmt)).scalar_one_or_none()
                if version_row is None:
                    raise NotFoundError("software version not found")
                if version_row.status == _STATUS_PUBLISHED:
                    raise ConflictError("software version already published")
                if version_row.status == _STATUS_DEPRECATED:
                    raise ConflictError("software version is deprecated")
                if version_row.status == _STATUS_REVOKED:
                    raise ConflictError("software version is revoked")
                if version_row.status != _STATUS_DRAFT:
                    raise ConflictError("software version cannot be published")

                version_row.status = _STATUS_PUBLISHED
                version_row.is_published = True
                version_row.published_at = now
                version_row.deprecated_at = None
                version_row.revoked_at = None
                software.row_version += 1
                software.updated_at = now
                software.current_version_id = version_row.id
                await session.flush()
                return PublishVersionResult(
                    software_id=software.id,
                    version_id=version_row.id,
                    owner_id=software.owner_id,
                    version=version_row.version,
                    published_at=now,
                    software_row_version=software.row_version,
                )

    async def deprecate_version(
        self,
        actor_id: str,
        software_id: UUID,
        version: str,
        expected_software_row_version: int | None = None,
    ) -> DeprecateVersionResult:
        now = _utc_now()
        async with self._sessionmaker() as session:
            async with session.begin():
                software_stmt = (
                    select(SoftwareModel).where(SoftwareModel.id == software_id).with_for_update()
                )
                software = (await session.execute(software_stmt)).scalar_one_or_none()
                if software is None:
                    raise NotFoundError("software not found")
                if software.owner_id != actor_id:
                    raise ForbiddenError("actor cannot deprecate this software")
                if (
                    expected_software_row_version is not None
                    and software.row_version != expected_software_row_version
                ):
                    raise ConflictError("software version conflict")

                version_stmt = (
                    select(VersionModel)
                    .where(VersionModel.software_id == software.id, VersionModel.version == version)
                    .with_for_update()
                )
                version_row = (await session.execute(version_stmt)).scalar_one_or_none()
                if version_row is None:
                    raise NotFoundError("software version not found")
                if version_row.status != _STATUS_PUBLISHED:
                    raise ConflictError("software version is not published")

                version_row.status = _STATUS_DEPRECATED
                version_row.is_published = True
                version_row.deprecated_at = now
                software.row_version += 1
                software.updated_at = now
                await session.flush()
                if software.current_version_id == version_row.id:
                    await self._heal_current_version(session, software)
                await session.flush()
                return DeprecateVersionResult(
                    software_id=software.id,
                    version_id=version_row.id,
                    owner_id=software.owner_id,
                    version=version_row.version,
                    deprecated_at=now,
                    software_row_version=software.row_version,
                )

    async def revoke_version(
        self,
        actor_id: str,
        software_id: UUID,
        version: str,
        expected_software_row_version: int | None = None,
    ) -> RevokeVersionResult:
        now = _utc_now()
        async with self._sessionmaker() as session:
            async with session.begin():
                software_stmt = (
                    select(SoftwareModel).where(SoftwareModel.id == software_id).with_for_update()
                )
                software = (await session.execute(software_stmt)).scalar_one_or_none()
                if software is None:
                    raise NotFoundError("software not found")
                if software.owner_id != actor_id:
                    raise ForbiddenError("actor cannot revoke this software")
                if (
                    expected_software_row_version is not None
                    and software.row_version != expected_software_row_version
                ):
                    raise ConflictError("software version conflict")

                version_stmt = (
                    select(VersionModel)
                    .where(VersionModel.software_id == software.id, VersionModel.version == version)
                    .with_for_update()
                )
                version_row = (await session.execute(version_stmt)).scalar_one_or_none()
                if version_row is None:
                    raise NotFoundError("software version not found")
                if version_row.status != _STATUS_DEPRECATED:
                    raise ConflictError("software version must be deprecated before revoking")

                version_row.status = _STATUS_REVOKED
                version_row.is_published = False
                version_row.revoked_at = now
                software.row_version += 1
                software.updated_at = now
                await session.flush()
                if software.current_version_id == version_row.id:
                    await self._heal_current_version(session, software)
                await session.flush()
                return RevokeVersionResult(
                    software_id=software.id,
                    version_id=version_row.id,
                    owner_id=software.owner_id,
                    version=version_row.version,
                    revoked_at=now,
                    software_row_version=software.row_version,
                )

    async def get_download_descriptor(
        self, software_id: UUID, version: str
    ) -> DownloadDescriptor | None:
        async with self._sessionmaker() as session:
            stmt = (
                select(SoftwareModel, VersionModel, ArtifactModel)
                .join(VersionModel, VersionModel.software_id == SoftwareModel.id)
                .join(ArtifactModel, ArtifactModel.id == VersionModel.artifact_id)
                .where(SoftwareModel.id == software_id, VersionModel.version == version)
            )
            row = (await session.execute(stmt)).one_or_none()
            if row is None:
                return None
            software, version_row, artifact = row
            return DownloadDescriptor(
                software_id=software.id,
                version_id=version_row.id,
                owner_id=software.owner_id,
                version=version_row.version,
                published=version_row.is_published,
                file_name=artifact.file_name,
                content_type=artifact.content_type,
                size_bytes=artifact.size_bytes,
                file_hash=artifact.file_hash,
                storage_key=artifact.storage_key,
            )

    async def increment_download_count(self, version_id: UUID) -> None:
        async with self._sessionmaker() as session:
            async with session.begin():
                stmt = select(VersionModel).where(VersionModel.id == version_id).with_for_update()
                version_row = (await session.execute(stmt)).scalar_one_or_none()
                if version_row is None:
                    raise NotFoundError("software version not found")
                version_row.download_count += 1
                await session.flush()

    async def delete_software(
        self,
        actor_id: str,
        software_id: UUID,
        expected_software_row_version: int | None = None,
    ) -> DeleteSoftwareResult:
        async with self._sessionmaker() as session:
            async with session.begin():
                software_stmt = (
                    select(SoftwareModel).where(SoftwareModel.id == software_id).with_for_update()
                )
                software = (await session.execute(software_stmt)).scalar_one_or_none()
                if software is None:
                    raise NotFoundError("software not found")
                if software.owner_id != actor_id:
                    raise ForbiddenError("actor cannot delete this software")
                if (
                    expected_software_row_version is not None
                    and software.row_version != expected_software_row_version
                ):
                    raise ConflictError("software version conflict")

                rows_stmt = (
                    select(VersionModel, ArtifactModel)
                    .join(ArtifactModel, ArtifactModel.id == VersionModel.artifact_id)
                    .where(VersionModel.software_id == software_id)
                )
                rows = (await session.execute(rows_stmt)).all()
                storage_keys = tuple(dict.fromkeys(artifact.storage_key for _, artifact in rows))
                for version_row, artifact in rows:
                    await session.delete(version_row)
                    await session.delete(artifact)
                await session.delete(software)
                return DeleteSoftwareResult(
                    software_id=software_id,
                    deleted_versions=len(rows),
                    deleted_artifacts=len(rows),
                    storage_keys=storage_keys,
                )

    async def list_softwares(
        self,
        actor_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> list[SoftwareListRecord]:
        latest_subq = (
            select(
                VersionModel.software_id.label("software_id"),
                func.max(VersionModel.created_at).label("max_created_at"),
            )
            .group_by(VersionModel.software_id)
            .subquery()
        )
        stmt = (
            select(SoftwareModel, VersionModel)
            .outerjoin(latest_subq, latest_subq.c.software_id == SoftwareModel.id)
            .outerjoin(
                VersionModel,
                (VersionModel.software_id == SoftwareModel.id)
                & (VersionModel.created_at == latest_subq.c.max_created_at),
            )
            .where(or_(SoftwareModel.is_public.is_(True), SoftwareModel.owner_id == actor_id))
            .order_by(SoftwareModel.updated_at.desc())
            .offset(offset)
            .limit(limit)
        )
        async with self._sessionmaker() as session:
            rows = (await session.execute(stmt)).all()
        return [
            SoftwareListRecord(
                id=software.id,
                owner_id=software.owner_id,
                name=software.name,
                description=software.description,
                is_public=software.is_public,
                latest_version=version_row.version if version_row else None,
                latest_version_id=version_row.id if version_row else None,
                latest_download_count=version_row.download_count if version_row else 0,
                created_at=software.created_at,
                updated_at=software.updated_at,
            )
            for software, version_row in rows
        ]

    async def list_versions(
        self,
        actor_id: str,
        software_id: UUID,
        *,
        limit: int = 20,
    ) -> list[VersionListRecord]:
        async with self._sessionmaker() as session:
            software = (await session.execute(select(SoftwareModel).where(SoftwareModel.id == software_id))).scalar_one_or_none()
            if software is None:
                raise NotFoundError("software not found")
            if not software.is_public and software.owner_id != actor_id:
                raise ForbiddenError("actor cannot access versions for this software")

            stmt = (
                select(VersionModel, ArtifactModel)
                .join(ArtifactModel, ArtifactModel.id == VersionModel.artifact_id)
                .where(VersionModel.software_id == software_id)
                .order_by(VersionModel.created_at.desc())
                .limit(limit)
            )
            rows = (await session.execute(stmt)).all()
        return [
            VersionListRecord(
                id=version_row.id,
                software_id=version_row.software_id,
                version=version_row.version,
                is_published=version_row.is_published,
                download_count=version_row.download_count,
                file_name=artifact.file_name,
                content_type=artifact.content_type,
                size_bytes=artifact.size_bytes,
                file_hash=artifact.file_hash,
                created_at=version_row.created_at,
                published_at=version_row.published_at,
            )
            for version_row, artifact in rows
        ]

    async def get_admin_summary(self) -> AdminSummaryRecord:
        async with self._sessionmaker() as session:
            total_packages = int((await session.execute(select(func.count(SoftwareModel.id)))).scalar_one())
            private_packages = int(
                (await session.execute(select(func.count(SoftwareModel.id)).where(SoftwareModel.is_public.is_(False)))).scalar_one()
            )
            total_versions = int((await session.execute(select(func.count(VersionModel.id)))).scalar_one())
            total_downloads = int(
                (await session.execute(select(func.coalesce(func.sum(VersionModel.download_count), 0)))).scalar_one()
            )
        return AdminSummaryRecord(
            total_packages=total_packages,
            private_packages=private_packages,
            public_packages=max(0, total_packages - private_packages),
            total_versions=total_versions,
            total_downloads=total_downloads,
        )

    async def list_admin_softwares(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AdminSoftwareRecord]:
        latest_subq = (
            select(
                VersionModel.software_id.label("software_id"),
                func.max(VersionModel.created_at).label("max_created_at"),
            )
            .group_by(VersionModel.software_id)
            .subquery()
        )
        stmt = (
            select(SoftwareModel, VersionModel)
            .outerjoin(latest_subq, latest_subq.c.software_id == SoftwareModel.id)
            .outerjoin(
                VersionModel,
                (VersionModel.software_id == SoftwareModel.id)
                & (VersionModel.created_at == latest_subq.c.max_created_at),
            )
            .order_by(SoftwareModel.updated_at.desc())
            .offset(offset)
            .limit(limit)
        )
        async with self._sessionmaker() as session:
            rows = (await session.execute(stmt)).all()
        return [
            AdminSoftwareRecord(
                package_id=software.id,
                name=software.name,
                owner_id=software.owner_id,
                is_public=software.is_public,
                latest_version=version_row.version if version_row else None,
                download_count=version_row.download_count if version_row else 0,
                created_at=software.created_at,
                updated_at=software.updated_at,
            )
            for software, version_row in rows
        ]

    async def get_idempotency_record(
        self, scope: str, actor_id: str, key: str
    ) -> IdempotencyRecord | None:
        async with self._sessionmaker() as session:
            stmt = select(IdempotencyKeyModel).where(
                IdempotencyKeyModel.scope == scope,
                IdempotencyKeyModel.actor_id == actor_id,
                IdempotencyKeyModel.key == key,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None
            return IdempotencyRecord(
                scope=row.scope,
                actor_id=row.actor_id,
                key=row.key,
                request_hash=row.request_hash,
                response_json=row.response_json,
                created_at=row.created_at,
            )

    async def store_idempotency_record(
        self,
        scope: str,
        actor_id: str,
        key: str,
        request_hash: str,
        response_json: str,
    ) -> None:
        try:
            async with self._sessionmaker() as session:
                async with session.begin():
                    session.add(
                        IdempotencyKeyModel(
                            scope=scope,
                            actor_id=actor_id,
                            key=key,
                            request_hash=request_hash,
                            response_json=response_json,
                            created_at=_utc_now(),
                        )
                    )
                    await session.flush()
        except IntegrityError as exc:
            raise ConflictError("idempotency key already used") from exc

    async def _heal_current_version(self, session, software: SoftwareModel) -> None:
        stmt = (
            select(VersionModel.id)
            .where(
                VersionModel.software_id == software.id,
                VersionModel.status == _STATUS_PUBLISHED,
            )
            .order_by(VersionModel.published_at.desc(), VersionModel.created_at.desc())
            .limit(1)
        )
        latest_id = (await session.execute(stmt)).scalar_one_or_none()
        software.current_version_id = latest_id

    async def _resolve_software_for_write(
        self,
        session,
        command: CreateVersionCommand,
        now: datetime,
    ) -> SoftwareModel:
        if command.software_id is not None:
            stmt = (
                select(SoftwareModel)
                .where(SoftwareModel.id == command.software_id)
                .with_for_update()
            )
            software = (await session.execute(stmt)).scalar_one_or_none()
            if software is None:
                raise NotFoundError("software not found")
            if software.owner_id != command.actor_id:
                raise ForbiddenError("actor cannot modify this software")
            if (
                command.expected_software_row_version is not None
                and software.row_version != command.expected_software_row_version
            ):
                raise ConflictError("software version conflict")
            software.description = command.software_description.strip()
            software.is_public = command.is_public
            software.updated_at = now
            return software

        stmt = (
            select(SoftwareModel)
            .where(
                SoftwareModel.owner_id == command.actor_id,
                SoftwareModel.name == command.software_name.strip(),
            )
            .with_for_update()
        )
        software = (await session.execute(stmt)).scalar_one_or_none()
        if software is not None:
            if (
                command.expected_software_row_version is not None
                and software.row_version != command.expected_software_row_version
            ):
                raise ConflictError("software version conflict")
            software.description = command.software_description.strip()
            software.is_public = command.is_public
            software.updated_at = now
            return software

        software = SoftwareModel(
            owner_id=command.actor_id,
            name=command.software_name.strip(),
            description=command.software_description.strip(),
            is_public=command.is_public,
            row_version=1,
            created_at=now,
            updated_at=now,
        )
        session.add(software)
        await session.flush()
        return software
