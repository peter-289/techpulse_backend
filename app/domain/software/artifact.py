from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from .enums import ArtifactStatus
from .events import MalwareScanFailedEvent, MalwareScanSuccessEvent
from .exceptions import ArtifactIntegrityError, InvalidStateTransitionError


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(slots=True)
class Artifact:
    id: UUID
    version_id: UUID
    storage_key: str
    sha256: str
    size_bytes: int
    mime_type: str
    filename: str
    status: ArtifactStatus
    created_at: datetime
    updated_at: datetime
    quarantine_reason: str | None = None

    def __post_init__(self) -> None:
        self.created_at = _ensure_utc(self.created_at)
        self.updated_at = _ensure_utc(self.updated_at)

    def verify_integrity(self, computed_hash_sha256: str) -> None:
        if computed_hash_sha256 != self.sha256:
            raise ArtifactIntegrityError("Artifact checksum validation failed.")

    def process_malware_scan_success(self, event: MalwareScanSuccessEvent) -> None:
        if event.artifact_id != self.id:
            raise InvalidStateTransitionError("Scan event does not belong to this artifact.")
        if self.status == ArtifactStatus.DELETED:
            raise InvalidStateTransitionError("Deleted artifact cannot be re-activated.")
        self.status = ArtifactStatus.ACTIVE
        self.quarantine_reason = None
        self.updated_at = event.occurred_at

    def process_malware_scan_failed(self, event: MalwareScanFailedEvent) -> None:
        if event.artifact_id != self.id:
            raise InvalidStateTransitionError("Scan event does not belong to this artifact.")
        if self.status == ArtifactStatus.DELETED:
            return
        self.status = ArtifactStatus.QUARANTINED
        self.quarantine_reason = event.reason
        self.updated_at = event.occurred_at

    def soft_delete(self, at: datetime) -> None:
        self.status = ArtifactStatus.DELETED
        self.updated_at = _ensure_utc(at)
