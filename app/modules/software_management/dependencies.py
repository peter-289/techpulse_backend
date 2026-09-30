"""Wiring for the software management context.

Moved out of ``app/modules/shared/dependencies.py`` in Phase 7b. Every provider
here is software management's to answer for: where uploads are staged, what limits
them, who signs a download URL, and which use cases the routers depend on. The
configuration is read from the environment *here*, at the composition root, so
the services receive value objects and ports and cannot see ``app.core``.

``app/modules/shared/container.py`` still builds the storage adapter and the
signer, because it predates this split and both are process-wide singletons that
``app.infrastructure.storage.local_storage`` needs to construct. Nothing here
imports the context's own modules lazily, so no :pep:`562` ``__getattr__`` is
needed -- see ``app/modules/software_management/__init__.py`` for the cycle that
one exists to avoid.
"""

from __future__ import annotations

from fastapi import Depends

from app.core.config import settings
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.infrastructure.events.logging_event_publisher import (
    LoggingDomainEventPublisher,
)
from app.infrastructure.external_apis.scanner_service.malware_scanner import (
    MalwareScanner,
    get_malware_scanner,
)
from app.infrastructure.storage.local_artifact_stager import LocalArtifactStager
from app.modules.software_management.application.services.category_service import (
    CategoryService,
)
from app.modules.software_management.application.services.download_service import (
    DownloadService,
)
from app.modules.software_management.application.services.software_service import (
    SoftwareService,
)
from app.modules.software_management.domain.ports.artifact_stager import (
    ArtifactStager,
    UploadLimits,
)
from app.modules.software_management.domain.ports.download_signer import (
    DownloadSigner,
)
from app.modules.software_management.domain.ports.event_publisher import (
    DomainEventPublisher,
)
from app.modules.software_management.domain.ports.storage import Storage
from app.modules.shared.container import signer, storage
from app.modules.shared.dependencies import get_unit_of_work

# === GET LOCAL STORAGE ===
def get_storage() -> Storage:
    return storage


# === GET HMAC SIGNER ===
def get_signer() -> DownloadSigner:
    return signer


# === GET DOMAIN EVENT PUBLISHER ===
event_publisher = LoggingDomainEventPublisher()


def get_event_publisher() -> DomainEventPublisher:
    return event_publisher


# === GET SCANNER ===
def get_scanner() -> MalwareScanner:
    return get_malware_scanner()


# === GET CATEGORY SERVICE ===
def get_category_service(unit_of_work: UnitOfWork = Depends(get_unit_of_work)) -> CategoryService:
    return CategoryService(unit_of_work=unit_of_work)


# === GET DOWNLOAD SERVICE ===
def get_download_service(
        signer: DownloadSigner = Depends(get_signer),
        unit_of_work: UnitOfWork = Depends(get_unit_of_work),
        storage: Storage = Depends(get_storage),
) -> DownloadService:
    return DownloadService(uow=unit_of_work, url_signer=signer, storage=storage)


# === GET SOFTWARE SERVICE ===
def get_software_service(
        download_service: DownloadService = Depends(get_download_service),
        storage: Storage = Depends(get_storage),
        malware_scanner: MalwareScanner = Depends(get_scanner),
        unit_of_work: UnitOfWork = Depends(get_unit_of_work),
        category_service: CategoryService = Depends(get_category_service),
        event_publisher: DomainEventPublisher = Depends(get_event_publisher),
) -> SoftwareService:
    return SoftwareService(
        download_service=download_service,
        storage=storage,
        malware_scanner=malware_scanner,
        unit_of_work=unit_of_work,
        category_service=category_service,
        event_publisher=event_publisher,
        )


# === GET ARTIFACT STAGER ===
# The upload limit is resolved here, at the composition root, rather than read out
# of the environment by the code that enforces it. That is what lets the stager
# take an UploadLimits value object and keeps app.core out of the application
# layer.
upload_limits = UploadLimits(
    max_size_bytes=settings.PACKAGE_UPLOAD_MAX_SIZE_BYTES,
)

stager = LocalArtifactStager()


def get_artifact_stager() -> ArtifactStager:
    return stager