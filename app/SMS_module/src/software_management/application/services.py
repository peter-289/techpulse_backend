from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from ..domain.entities.artifact import Artifact
from ..domain.entities.software import Software
from ..domain.entities.version import Version
from ..domain.enums import ArtifactStatus, SoftwareVisibility, VersionStatus
from ..domain.events import malware_scan_failed, malware_scan_requested, malware_scan_success
from ..domain.exceptions import AccessDeniedError, NotFoundError
from ..domain.services import ReleaseSelector
from ..domain.value_objects import SemVer
from .commands import (
    AddVersionCommand,
    CreateSoftwareCommand,
    GenerateDownloadLinkQuery,
    ProcessMalwareScanFailedCommand,
    ProcessMalwareScanSuccessCommand,
    PublishVersionCommand,
    RequestArtifactUploadCommand,
)
from .ports import (
    EventPublisherPort,
    MalwareScanQueuePort,
    PaymentPort,
    PresignedUpload,
    SoftwareRepositoryPort,
    StoragePort,
    SubscriptionPort,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class UploadArtifactResult:
    artifact_id: UUID
    storage_key: str
    upload: PresignedUpload


class SoftwareCommandService:
    def __init__(
        self,
        repository: SoftwareRepositoryPort,
        storage: StoragePort,
        scan_queue: MalwareScanQueuePort,
        event_publisher: EventPublisherPort | None = None,
    ) -> None:
        self._repository = repository
        self._storage = storage
        self._scan_queue = scan_queue
        self._event_publisher = event_publisher

    async def create_software(self, command: CreateSoftwareCommand) -> Software:
        visibility = SoftwareVisibility(command.visibility)
        software = Software.create(
            name=command.name,
            description=command.description,
            owner_id=command.owner_id,
            visibility=visibility,
        )
        await self._repository.save(software)
        return software

    async def add_version(self, command: AddVersionCommand) -> Version:
        software = await self._require_software(command.software_id)
        version = Version(
            id=uuid4(),
            software_id=software.id,
            number=SemVer.parse(command.number),
            release_notes=command.release_notes,
            status=VersionStatus.DRAFT,
            lock_version=0,
        )
        software.add_version(version)
        await self._repository.save(software)
        return version

    async def request_artifact_upload(
        self,
        command: RequestArtifactUploadCommand,
    ) -> UploadArtifactResult:
        software = await self._require_software(command.software_id)
        version = software.get_version(command.version_id)

        artifact_id = uuid4()
        storage_key = f"software/{software.id}/versions/{version.id}/{artifact_id}/{command.filename}"
        now = _utc_now()

        artifact = Artifact(
            id=artifact_id,
            version_id=version.id,
            storage_key=storage_key,
            sha256=command.sha256,
            size_bytes=command.size_bytes,
            mime_type=command.content_type,
            filename=command.filename,
            status=ArtifactStatus.UPLOADING,
            created_at=now,
            updated_at=now,
        )

        version.attach_artifact(artifact)
        upload = await self._storage.create_presigned_upload(
            storage_key=storage_key,
            content_type=command.content_type,
        )

        scan_event = malware_scan_requested(
            software_id=software.id,
            version_id=version.id,
            artifact_id=artifact.id,
            storage_key=storage_key,
        )
        await self._scan_queue.enqueue_scan(scan_event)
        await self._repository.save(software)

        if self._event_publisher is not None:
            await self._event_publisher.publish([scan_event])

        return UploadArtifactResult(artifact_id=artifact.id, storage_key=storage_key, upload=upload)

    async def process_malware_scan_success(
        self,
        command: ProcessMalwareScanSuccessCommand,
    ) -> None:
        software = await self._require_software(command.software_id)
        version = software.get_version(command.version_id)
        if version.artifact is None:
            raise NotFoundError("Artifact not found for version.")

        event = malware_scan_success(
            software_id=command.software_id,
            version_id=command.version_id,
            artifact_id=command.artifact_id,
        )
        version.artifact.process_malware_scan_success(event)

        await self._repository.save(software)
        if self._event_publisher is not None:
            await self._event_publisher.publish([event])

    async def process_malware_scan_failed(
        self,
        command: ProcessMalwareScanFailedCommand,
    ) -> None:
        software = await self._require_software(command.software_id)
        version = software.get_version(command.version_id)
        if version.artifact is None:
            raise NotFoundError("Artifact not found for version.")

        event = malware_scan_failed(
            software_id=command.software_id,
            version_id=command.version_id,
            artifact_id=command.artifact_id,
            reason=command.reason,
        )
        version.artifact.process_malware_scan_failed(event)

        await self._repository.save(software)
        if self._event_publisher is not None:
            await self._event_publisher.publish([event])

    async def publish_version(self, command: PublishVersionCommand) -> None:
        software = await self._require_software(command.software_id)
        software.publish_version(command.version_id)
        await self._repository.save(software)

        events = software.pull_events()
        if self._event_publisher is not None and events:
            await self._event_publisher.publish(events)

    async def _require_software(self, software_id: UUID) -> Software:
        software = await self._repository.get(software_id)
        if software is None:
            raise NotFoundError(f"Software {software_id} not found.")
        return software


class DownloadService:
    def __init__(
        self,
        repository: SoftwareRepositoryPort,
        storage: StoragePort,
        subscription: SubscriptionPort,
        payment: PaymentPort | None = None,
    ) -> None:
        self._repository = repository
        self._storage = storage
        self._subscription = subscription
        self._payment = payment

    async def generate_download_url(self, query: GenerateDownloadLinkQuery) -> str:
        software = await self._repository.get(query.software_id)
        if software is None:
            raise NotFoundError(f"Software {query.software_id} not found.")

        allowed = await self._subscription.verify_access(
            user_id=query.user_id,
            software_id=query.software_id,
        )
        if not allowed:
            raise AccessDeniedError("User is not entitled to this software.")

        requested_version = None
        if query.version_id is not None:
            requested_version = software.get_version(query.version_id)

        release = ReleaseSelector.resolve(software, requested_version)
        if release.artifact is None:
            raise NotFoundError("Artifact missing for selected version.")

        if self._payment is not None:
            await self._payment.record_download_charge(
                user_id=query.user_id,
                software_id=query.software_id,
                version_id=release.id,
            )

        return await self._storage.create_presigned_download(
            storage_key=release.artifact.storage_key
        )
