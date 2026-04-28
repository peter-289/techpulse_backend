from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
from urllib.parse import quote
from uuid import UUID

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.database.db_setup import SessionLocal
from app.models.enums import RoleEnum
from app.models.user import User
from app.services.audit_service import log_http_audit_event

from app.SMS_module.src.software_management.api import dependencies as sms_api_dependencies
from app.SMS_module.src.software_management.api.router import router as sms_router
from app.SMS_module.src.software_management.application.ports import (
    EventPublisherPort,
    MalwareScanQueuePort,
    PaymentPort,
    PresignedUpload,
    SoftwareRepositoryPort,
    StoragePort,
    SubscriptionPort,
)
from app.SMS_module.src.software_management.application.services import DownloadService, SoftwareCommandService
from app.SMS_module.src.software_management.domain.entities.software import Software
from app.SMS_module.src.software_management.domain.enums import SoftwareVisibility
from app.SMS_module.src.software_management.domain.events import DomainEvent, MalwareScanRequestedEvent
from app.SMS_module.src.software_management.infrastructure.persistence.repositories import SQLAlchemySoftwareRepository
from app.SMS_module.src.software_management.infrastructure.persistence.sqlalchemy_models import Base as SMSBase


def _to_async_db_url(database_url: str) -> str:
    if database_url.startswith("sqlite:///"):
        return database_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    if database_url.startswith("postgresql+asyncpg://"):
        return database_url
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+asyncpg://", 1)
    return database_url


def _user_uuid_from_int(user_id: int) -> UUID:
    return UUID(int=max(0, user_id))


def _user_int_from_uuid(user_id: UUID) -> int:
    return int(user_id.int)


@dataclass(frozen=True, slots=True)
class SMSBootstrapConfig:
    database_url: str
    storage_root: Path
    upload_chunk_size: int
    upload_max_size_bytes: int
    upload_rate_limit: int
    upload_rate_window_seconds: int
    download_rate_limit: int
    download_rate_window_seconds: int
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 1800


class SMSDatabase:
    def __init__(self, engine) -> None:
        self._engine = engine

    async def create_schema(self) -> None:
        async with self._engine.begin() as connection:
            await connection.run_sync(SMSBase.metadata.create_all)

    async def close(self) -> None:
        await self._engine.dispose()


class SessionFactorySoftwareRepository(SoftwareRepositoryPort):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get(self, software_id: UUID) -> Software | None:
        async with self._session_factory() as session:
            return await SQLAlchemySoftwareRepository(session).get(software_id)

    async def save(self, software: Software) -> None:
        async with self._session_factory() as session:
            await SQLAlchemySoftwareRepository(session).save(software)

    async def list_for_owner(self, owner_id: UUID) -> list[Software]:
        async with self._session_factory() as session:
            return await SQLAlchemySoftwareRepository(session).list_for_owner(owner_id)


class HostSubscriptionAdapter(SubscriptionPort):
    def __init__(self, software_repository: SoftwareRepositoryPort) -> None:
        self._software_repository = software_repository

    async def verify_access(self, user_id: UUID, software_id: UUID) -> bool:
        software = await self._software_repository.get(software_id)
        if software is None:
            return False

        host_user_id = _user_int_from_uuid(user_id)
        session = SessionLocal()
        try:
            user = session.get(User, host_user_id)
            if user is None:
                return False
            if user.role == RoleEnum.ADMIN:
                return True
        finally:
            session.close()

        if software.visibility == SoftwareVisibility.PUBLIC:
            return True
        return software.owner_id == user_id


class HostPaymentAdapter(PaymentPort):
    async def record_download_charge(self, user_id: UUID, software_id: UUID, version_id: UUID) -> None:
        log_http_audit_event(
            event_type="sms.download.charge.recorded",
            actor_user_id=_user_int_from_uuid(user_id),
            method="SYSTEM",
            path=f"/api/v1/software/{software_id}/download",
            status_code=200,
            ip_address=None,
            user_agent="sms-module",
            request_id=None,
            metadata={"software_id": str(software_id), "version_id": str(version_id)},
        )


class HostEventPublisher(EventPublisherPort):
    async def publish(self, events: list[DomainEvent]) -> None:
        for event in events:
            log_http_audit_event(
                event_type=f"sms.event.{event.__class__.__name__}",
                actor_user_id=None,
                method="SYSTEM",
                path="/api/v1/software/events",
                status_code=202,
                ip_address=None,
                user_agent="sms-module",
                request_id=None,
                metadata={"event": event.__class__.__name__, "occurred_at": event.occurred_at.isoformat()},
            )


class HostMalwareScanQueue(MalwareScanQueuePort):
    async def enqueue_scan(self, event: MalwareScanRequestedEvent) -> None:
        log_http_audit_event(
            event_type="sms.malware.scan.requested",
            actor_user_id=None,
            method="SYSTEM",
            path="/api/v1/software/malware/scan",
            status_code=202,
            ip_address=None,
            user_agent="sms-module",
            request_id=None,
            metadata={
                "software_id": str(event.software_id),
                "version_id": str(event.version_id),
                "artifact_id": str(event.artifact_id),
                "storage_key": event.storage_key,
            },
        )


class HostStorageAdapter(StoragePort):
    def __init__(self, storage_root: Path, signing_secret: str, backend_url: str) -> None:
        self._storage_root = storage_root
        self._storage_root.mkdir(parents=True, exist_ok=True)
        self._secret = signing_secret.encode("utf-8")
        self._backend_url = backend_url.rstrip("/")

    async def create_presigned_upload(
        self,
        storage_key: str,
        content_type: str,
        expires_in_seconds: int = 900,
    ) -> PresignedUpload:
        expires_at = int(time.time()) + expires_in_seconds
        token = self._sign(storage_key=storage_key, expires_at=expires_at, method="PUT")
        return PresignedUpload(
            url=(
                f"{self._backend_url}/api/v1/software/storage/upload/"
                f"{quote(storage_key, safe='')}?expires={expires_at}&token={token}"
            ),
            fields={"Content-Type": content_type},
            expires_in_seconds=expires_in_seconds,
        )

    async def create_presigned_download(
        self,
        storage_key: str,
        expires_in_seconds: int = 900,
    ) -> str:
        expires_at = int(time.time()) + expires_in_seconds
        token = self._sign(storage_key=storage_key, expires_at=expires_at, method="GET")
        return (
            f"{self._backend_url}/api/v1/software/storage/download/"
            f"{quote(storage_key, safe='')}?expires={expires_at}&token={token}"
        )

    async def delete_object(self, storage_key: str) -> None:
        path = self.resolve_path_for_testing(storage_key)
        path.unlink(missing_ok=True)

    def resolve_path_for_testing(self, storage_key: str) -> Path:
        candidate = (self._storage_root / storage_key).resolve()
        root = self._storage_root.resolve()
        if not str(candidate).startswith(str(root)):
            raise ValueError("Invalid storage key path traversal")
        candidate.parent.mkdir(parents=True, exist_ok=True)
        return candidate

    def verify_signed_request(self, *, storage_key: str, expires: int, token: str, method: str) -> bool:
        if expires < int(time.time()):
            return False
        expected = self._sign(storage_key=storage_key, expires_at=expires, method=method.upper())
        return hmac.compare_digest(expected, token)

    def _sign(self, *, storage_key: str, expires_at: int, method: str) -> str:
        payload = f"{method}:{storage_key}:{expires_at}".encode("utf-8")
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()


class HostInternalStorageGateway:
    def __init__(self, storage: HostStorageAdapter) -> None:
        self._storage = storage

    async def upload(self, storage_key: str, content: bytes, content_type: str | None) -> None:
        self._storage.resolve_path_for_testing(storage_key).write_bytes(content)

    async def download(self, storage_key: str) -> tuple[bytes, str]:
        path = self._storage.resolve_path_for_testing(storage_key)
        if not path.exists():
            raise FileNotFoundError(storage_key)
        return path.read_bytes(), "application/octet-stream"

    async def delete(self, storage_key: str) -> None:
        path = self._storage.resolve_path_for_testing(storage_key)
        if not path.exists():
            raise FileNotFoundError(storage_key)
        path.unlink()

    def verify_signature(self, *, storage_key: str, expires: int, token: str, method: str) -> bool:
        return self._storage.verify_signed_request(
            storage_key=storage_key,
            expires=expires,
            token=token,
            method=method,
        )


@dataclass(slots=True)
class SMSModuleHandle:
    router: Any
    database: SMSDatabase
    dependency_overrides: dict[Callable[..., Any], Callable[..., Any]]

    async def initialize(self) -> None:
        await self.database.create_schema()

    async def close(self) -> None:
        await self.database.close()


def build_sms_module(*, config: SMSBootstrapConfig, current_actor_dependency: Callable[..., Any]) -> SMSModuleHandle:
    engine = create_async_engine(_to_async_db_url(config.database_url), pool_pre_ping=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    repository = SessionFactorySoftwareRepository(session_factory)
    storage = HostStorageAdapter(
        storage_root=Path(config.storage_root),
        signing_secret=settings.SECRET_KEY,
        backend_url=settings.BACKEND_URL,
    )
    subscription = HostSubscriptionAdapter(repository)

    command_service = SoftwareCommandService(
        repository=repository,
        storage=storage,
        scan_queue=HostMalwareScanQueue(),
        event_publisher=HostEventPublisher(),
    )
    download_service = DownloadService(
        repository=repository,
        storage=storage,
        subscription=subscription,
        payment=HostPaymentAdapter(),
    )

    sms_api_dependencies.configure_dependencies(
        command_service_factory=lambda: command_service,
        download_service_factory=lambda: download_service,
        subscription_factory=lambda: subscription,
        test_storage_gateway_factory=lambda: HostInternalStorageGateway(storage),
    )

    async def current_user_uuid(actor: dict = Depends(current_actor_dependency)) -> UUID:
        return _user_uuid_from_int(int(actor.get("user_id")))

    router = SimpleNamespace(router=sms_router, prefix="/api/v1", tags=["software-management"])
    return SMSModuleHandle(
        router=router,
        database=SMSDatabase(engine),
        dependency_overrides={sms_api_dependencies.get_current_user_id: current_user_uuid},
    )
