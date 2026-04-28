from __future__ import annotations

from collections.abc import Callable
from typing import Protocol
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status

from ..application.ports import SubscriptionPort
from ..application.services import DownloadService, SoftwareCommandService

CommandServiceFactory = Callable[[], SoftwareCommandService]
DownloadServiceFactory = Callable[[], DownloadService]
SubscriptionFactory = Callable[[], SubscriptionPort]


class InternalStorageTestGateway(Protocol):
    async def upload(self, storage_key: str, content: bytes, content_type: str | None) -> None:
        ...

    async def download(self, storage_key: str) -> tuple[bytes, str]:
        ...

    async def delete(self, storage_key: str) -> None:
        ...

    def verify_signature(self, *, storage_key: str, expires: int, token: str, method: str) -> bool:
        ...


InternalStorageTestGatewayFactory = Callable[[], InternalStorageTestGateway]

_command_service_factory: CommandServiceFactory | None = None
_download_service_factory: DownloadServiceFactory | None = None
_subscription_factory: SubscriptionFactory | None = None
_internal_storage_test_gateway_factory: InternalStorageTestGatewayFactory | None = None


def configure_dependencies(
    command_service_factory: CommandServiceFactory,
    download_service_factory: DownloadServiceFactory,
    subscription_factory: SubscriptionFactory,
    test_storage_gateway_factory: InternalStorageTestGatewayFactory | None = None,
) -> None:
    global _command_service_factory
    global _download_service_factory
    global _subscription_factory
    global _internal_storage_test_gateway_factory
    _command_service_factory = command_service_factory
    _download_service_factory = download_service_factory
    _subscription_factory = subscription_factory
    _internal_storage_test_gateway_factory = test_storage_gateway_factory


def get_command_service() -> SoftwareCommandService:
    if _command_service_factory is None:
        raise RuntimeError("SMS command service factory is not configured.")
    return _command_service_factory()


def get_download_service() -> DownloadService:
    if _download_service_factory is None:
        raise RuntimeError("SMS download service factory is not configured.")
    return _download_service_factory()


def get_subscription_port() -> SubscriptionPort:
    if _subscription_factory is None:
        raise RuntimeError("SMS subscription factory is not configured.")
    return _subscription_factory()


def get_internal_storage_test_gateway() -> InternalStorageTestGateway:
    if _internal_storage_test_gateway_factory is None:
        raise RuntimeError("SMS internal storage test gateway is not configured.")
    return _internal_storage_test_gateway_factory()


async def get_current_user_id(x_user_id: str = Header(..., alias="x-user-id")) -> UUID:
    try:
        return UUID(x_user_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid x-user-id header.",
        ) from exc


async def gatekeeper(
    software_id: UUID,
    user_id: UUID = Depends(get_current_user_id),
    subscription: SubscriptionPort = Depends(get_subscription_port),
) -> UUID:
    entitled = await subscription.verify_access(user_id=user_id, software_id=software_id)
    if not entitled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not entitled to this software.",
        )
    return user_id
