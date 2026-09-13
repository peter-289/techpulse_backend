from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from app.modules.shared.events import DomainEvent


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class SoftwareDomainEvent(DomainEvent):
    """Represents any event that occurrs in the software context."""
    ...



@dataclass(frozen=True, slots=True)
class MalwareScanRequestedEvent(SoftwareDomainEvent):
    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    storage_key: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class MalwareScanSuccessEvent(SoftwareDomainEvent):
    """MalwareScan event"""
    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    occurred_at: datetime

@dataclass(frozen=True, slots=True)
class MalwareScanFailedEvent(SoftwareDomainEvent):
    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    reason: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class ArtifactAddedToVersion(SoftwareDomainEvent):
    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    filename: str
    storage_key: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ArtifactRemovedFromVersion(SoftwareDomainEvent):
    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    filename: str


# === VERSION EVENTS ===
@dataclass(frozen=True, slots=True)
class VersionPublishedEvent(SoftwareDomainEvent):
    software_id: UUID
    version_id: UUID

@dataclass(frozen=True, slots=True)
class VersionAddedEvent(SoftwareDomainEvent):
    added_at: datetime
    software_id: UUID
    version_id: UUID

@dataclass(frozen=True, slots=True)
class VersionDeprecatedEvent(SoftwareDomainEvent):
    deprecated_at: datetime
    software_id: UUID
    version_id: UUID

@dataclass(frozen=True, slots=True)
class VersionRevokedEvent(SoftwareDomainEvent):
    revoked_at: datetime
    software_id: UUID
    version_id: UUID

@dataclass(frozen=True, slots=True)
class VersionRemovedEvent(SoftwareDomainEvent):
    removed_at: datetime
    software_id: UUID
    version_id: UUID


# ==== SOFTWARE EVENTS ====
@dataclass(frozen=True, slots=True)
class SoftwareDownloadedEvent(SoftwareDomainEvent):
    """Software downloaded event"""
    software_id: UUID

@dataclass(frozen=True, slots=True)
class SoftwareAccessPolicyUpdatedEvent(SoftwareDomainEvent):
    """Access policy changed event"""
    software_id: UUID

@dataclass(frozen=True, slots=True)
class SoftwareArchivedEvent(SoftwareDomainEvent):
    """Software archived event."""
    software_id: UUID

@dataclass(frozen=True, slots=True)
class SoftwarePriceUpdatedEvent(SoftwareDomainEvent):
    """Software price updated event."""
    old_price: int
    new_price: int

@dataclass(frozen=True, slots=True)
class SoftwareRenamedEvent(SoftwareDomainEvent):
    """Software rename event"""
    new_name: str
    old_name: str

@dataclass(frozen=True, slots=True)
class SoftwareDescriptionUpdatedEvent(SoftwareDomainEvent):
    """Software description changed event."""
    old_description: str
    new_description: str

@dataclass(frozen=True, slots=True)
class SoftwareDeletedEvent(SoftwareDomainEvent):
    """Software deleted event"""
    deleted_at: datetime

@dataclass(frozen=True, slots=True)
class SoftwareVisibilityUpdatedEvent(SoftwareDomainEvent):
    """Software visibility changed event"""
    old_visibility: str
    new_visibility: str


@dataclass(frozen=True, slots=True)
class SoftwarePublishedEvent(SoftwareDomainEvent):
    """Software published event"""
    published_at: datetime

@dataclass(frozen=True, slots=True)
class SoftwareRestoredEvent(SoftwareDomainEvent):
    """Software restored."""
    software_id: UUID



def malware_scan_requested(
    *,
    software_id: UUID,
    version_id: UUID,
    artifact_id: UUID,
    storage_key: str,
    actor_id: UUID | None = None,
    aggregate_id: UUID | None = None,
) -> MalwareScanRequestedEvent:
    return MalwareScanRequestedEvent(
        actor_id=actor_id or software_id,
        aggregate_id=aggregate_id or software_id,
        occurred_at=utc_now(),
        software_id=software_id,
        version_id=version_id,
        artifact_id=artifact_id,
        storage_key=storage_key,
    )


def malware_scan_success(
        software_id: UUID, 
        version_id: UUID, 
        artifact_id: UUID,
        actor_id: UUID | None = None,
        aggregate_id: UUID | None = None,
        ) -> MalwareScanSuccessEvent:
    return MalwareScanSuccessEvent(
        occurred_at=utc_now(),
        software_id=software_id,
        version_id=version_id,
        artifact_id=artifact_id,
        actor_id=actor_id or software_id,
        aggregate_id=aggregate_id or software_id,
    )


def malware_scan_failed(
    software_id: UUID,
    version_id: UUID,
    artifact_id: UUID,
    reason: str,
    actor_id: UUID | None = None,
    aggregate_id: UUID | None = None,
) -> MalwareScanFailedEvent:
    return MalwareScanFailedEvent(
        occurred_at=utc_now(),
        software_id=software_id,
        version_id=version_id,
        artifact_id=artifact_id,
        reason=reason,
        actor_id=actor_id or software_id,
        aggregate_id=aggregate_id or software_id,
    )


def version_published(software_id: UUID, version_id: UUID) -> VersionPublishedEvent:
    return VersionPublishedEvent(occurred_at=utc_now(), software_id=software_id, version_id=version_id)
