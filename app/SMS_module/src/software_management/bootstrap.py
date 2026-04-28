from __future__ import annotations

from fastapi import FastAPI

from .api.dependencies import configure_dependencies
from .api.router import router
from .application.ports import SubscriptionPort
from .application.services import DownloadService, SoftwareCommandService


def create_sms_app(
    command_service_factory,
    download_service_factory,
    subscription_factory,
    test_storage_gateway_factory=None,
    *,
    title: str = "Software Management Module",
) -> FastAPI:
    app = FastAPI(title=title)
    configure_dependencies(
        command_service_factory=command_service_factory,
        download_service_factory=download_service_factory,
        subscription_factory=subscription_factory,
        test_storage_gateway_factory=test_storage_gateway_factory,
    )
    app.include_router(router)
    return app


__all__ = ["create_sms_app", "SoftwareCommandService", "DownloadService", "SubscriptionPort"]
