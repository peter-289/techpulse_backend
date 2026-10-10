from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

from app.modules.shared.enums import ArtifactStatus, VersionStatus
from app.modules.software_management.domain.entities.artifact import Artifact
from app.modules.software_management.domain.exceptions import InvalidStateTransitionError, MalwareScanPendingError
from app.modules.software_management.domain.value_objects import SemVer


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
    _artifacts: list[Artifact] = field(default_factory=list, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.created_at = _ensure_utc(self.created_at)
        self.updated_at = _ensure_utc(self.updated_at)
        if self.published_at is not None:
            self.published_at = _ensure_utc(self.published_at)

    @property
    def artifacts(self) -> tuple[Artifact, ...]:
        return tuple(self._artifacts)

    def add_artifact(self, artifact: Artifact) -> None:
        """Attach an artifact to this version."""
        self._ensure_modifiable()
        if self.status == VersionStatus.DELETED:
            raise InvalidStateTransitionError("Deleted version cannot receive artifacts.")
        if artifact.version_id != self.id:
            raise InvalidStateTransitionError("Artifact does not belong to this version.")
        if any(existing.id == artifact.id for existing in self._artifacts):
            raise InvalidStateTransitionError("Duplicate artifact cannot be attached.")
        if any(existing.filename == artifact.filename for existing in self._artifacts):
            raise InvalidStateTransitionError("Duplicate artifact filename in version.")
        self._artifacts.append(artifact)
        self._touch()

    def remove_artifact(self, artifact_id: UUID) -> None:
        """Remove an artifact from this version."""
        self._ensure_modifiable()
        if self.status == VersionStatus.DELETED:
            raise InvalidStateTransitionError("Deleted version cannot remove artifacts.")
        for index, artifact in enumerate(self._artifacts):
            if artifact.id == artifact_id:
                del self._artifacts[index]
                self._touch()
                return
        raise InvalidStateTransitionError(f"Artifact {artifact_id} not found.")

    def publish(self) -> None:
        """ Publish a version."""
        self._ensure_modifiable()
        if not self._artifacts:
            raise InvalidStateTransitionError("Version requires at least one artifact before publishing.")
        for a in self._artifacts:
           if a.status != ArtifactStatus.ACTIVE:
              raise MalwareScanPendingError("Artifact cannot become downloadable until malware scan succeeds.")
        self.status = VersionStatus.PUBLISHED
        if self.published_at is None:
            self.published_at = utc_now()
        self._touch()

    def _ensure_modifiable(self) -> None:
        """ Ensure a version is modifiable before performing any operation."""
        if self.status == VersionStatus.REVOKED:
            raise InvalidStateTransitionError("Revoked version cannot be modified.")
        if self.status == VersionStatus.PUBLISHED:
            return
    

    def deprecate(self) -> None:
        """ Deprecate a version"""
        if self.status != VersionStatus.PUBLISHED:
            raise InvalidStateTransitionError("Only published versions can be deprecated.")
        self.status = VersionStatus.DEPRECATED
        self._touch()
    
    def revoke(self) -> None:
        """ Revoke a version"""
        if self.status in {VersionStatus.DELETED, VersionStatus.ARCHIVED}:
            raise InvalidStateTransitionError("Archived or deleted version cannot be revoked.")
        if self.status == VersionStatus.REVOKED:
            return
        self.status = VersionStatus.REVOKED
        self._touch()

    def archive(self) -> None:
        """Retain a version historically while removing it from distribution."""
        if self.status == VersionStatus.ARCHIVED:
            return
        if self.status in {VersionStatus.DRAFT, VersionStatus.DELETED}:
            raise InvalidStateTransitionError("Only released versions can be archived.")
        self.status = VersionStatus.ARCHIVED
        self._touch()

    def record_download(self) -> None:
        """Count a completed download of this version.

        The counter and the optimistic-lock bump are two halves of one fact, so
        they are set together here. A caller that increments the field and then
        reaches for ``_touch()`` can forget the second half and leave the row
        looking unwritten to a concurrent transaction.
        """
        self.download_count += 1
        self._touch()

    # === QUERIES ===
    def is_downloadable(self) -> bool:
        """ Check if a version is downloadable."""
        return self.status in {VersionStatus.PUBLISHED, VersionStatus.DEPRECATED}

    def is_published(self) -> bool:
        """Return whether the version is currently published."""
        return self.status == VersionStatus.PUBLISHED

    def _touch(self) -> None:
        """ Updates time asocciated with an event. """
        self.updated_at = utc_now()
        self.lock_version += 1
