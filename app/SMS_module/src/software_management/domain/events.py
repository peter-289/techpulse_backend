from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class DomainEvent:
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class MalwareScanRequestedEvent(DomainEvent):
    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    storage_key: str


@dataclass(frozen=True, slots=True)
class MalwareScanSuccessEvent(DomainEvent):
    software_id: UUID
    version_id: UUID
    artifact_id: UUID


@dataclass(frozen=True, slots=True)
class MalwareScanFailedEvent(DomainEvent):
    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class VersionPublishedEvent(DomainEvent):
    software_id: UUID
    version_id: UUID


def malware_scan_requested(
    software_id: UUID,
    version_id: UUID,
    artifact_id: UUID,
    storage_key: str,
) -> MalwareScanRequestedEvent:
    return MalwareScanRequestedEvent(
        occurred_at=_utc_now(),
        software_id=software_id,
        version_id=version_id,
        artifact_id=artifact_id,
        storage_key=storage_key,
    )


def malware_scan_success(
    software_id: UUID,
    version_id: UUID,
    artifact_id: UUID,
) -> MalwareScanSuccessEvent:
    return MalwareScanSuccessEvent(
        occurred_at=_utc_now(),
        software_id=software_id,
        version_id=version_id,
        artifact_id=artifact_id,
    )


def malware_scan_failed(
    software_id: UUID,
    version_id: UUID,
    artifact_id: UUID,
    reason: str,
) -> MalwareScanFailedEvent:
    return MalwareScanFailedEvent(
        occurred_at=_utc_now(),
        software_id=software_id,
        version_id=version_id,
        artifact_id=artifact_id,
        reason=reason,
    )


def version_published(software_id: UUID, version_id: UUID) -> VersionPublishedEvent:
    return VersionPublishedEvent(
        occurred_at=_utc_now(),
        software_id=software_id,
        version_id=version_id,
    )
