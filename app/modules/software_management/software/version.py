from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

from .artifact import Artifact
from .enums import ArtifactStatus, VersionStatus
from .exceptions import InvalidStateTransitionError, MalwareScanPendingError
from .value_objects import SemVer


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(slots=True)
class Version:
    id: UUID
    software_id: UUID
    number: SemVer
    release_notes: str
    status: VersionStatus
    lock_version: int
    download_count: int = 0
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    published_at: datetime | None = None
    artifact: Artifact | None = None

    def __post_init__(self) -> None:
        self.created_at = _ensure_utc(self.created_at)
        self.updated_at = _ensure_utc(self.updated_at)
        if self.published_at is not None:
            self.published_at = _ensure_utc(self.published_at)

    def attach_artifact(self, artifact: Artifact) -> None:
        """ Attach an artifact to a version."""
        if artifact.version_id != self.id:
            raise InvalidStateTransitionError("Artifact does not belong to this version.")
        self.artifact = artifact
        self._touch()

    def publish(self) -> None:
        """ Publish a version."""
        if self.status == VersionStatus.REVOKED:
            raise InvalidStateTransitionError("Revoked version cannot be published.")
        if self.artifact is None:
            raise InvalidStateTransitionError("Version requires artifact before publishing.")
        if self.artifact.status != ArtifactStatus.ACTIVE:
            raise MalwareScanPendingError("Artifact cannot become downloadable until malware scan succeeds.")
        self.status = VersionStatus.PUBLISHED
        if self.published_at is None:
            self.published_at = utc_now()
        self._touch()

    def deprecate(self) -> None:
        """ Deprecate a version"""
        if self.status != VersionStatus.PUBLISHED:
            raise InvalidStateTransitionError("Only published versions can be deprecated.")
        self.status = VersionStatus.DEPRECATED
        self._touch()

    def revoke(self) -> None:
        """ Revoke a version"""
        if self.status == VersionStatus.REVOKED:
            return
        self.status = VersionStatus.REVOKED
        self._touch()

    def is_downloadable(self) -> bool:
        """ Check if a version is downloadable."""
        return self.status in {VersionStatus.PUBLISHED, VersionStatus.DEPRECATED}

    def _touch(self) -> None:
        """ Updates time asocciated with an event. """
        self.updated_at = utc_now()
        self.lock_version += 1
