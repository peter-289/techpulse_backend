from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

from ..enums import ArtifactStatus, VersionStatus
from ..exceptions import InvalidStateTransitionError, MalwareScanPendingError
from ..value_objects import SemVer
from .artifact import Artifact


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        raise ValueError("Version timestamps must be timezone-aware.")
    return ts.astimezone(timezone.utc)


@dataclass(slots=True)
class Version:
    id: UUID
    software_id: UUID
    number: SemVer
    release_notes: str
    status: VersionStatus
    lock_version: int
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    published_at: datetime | None = None
    artifact: Artifact | None = None

    def __post_init__(self) -> None:
        self.created_at = _ensure_utc(self.created_at)
        self.updated_at = _ensure_utc(self.updated_at)
        if self.published_at is not None:
            self.published_at = _ensure_utc(self.published_at)

    def attach_artifact(self, artifact: Artifact) -> None:
        if artifact.version_id != self.id:
            raise InvalidStateTransitionError("Artifact does not belong to this version.")
        self.artifact = artifact
        self._touch()

    def publish(self) -> None:
        if self.status == VersionStatus.REVOKED:
            raise InvalidStateTransitionError("Revoked version cannot be published.")
        if self.artifact is None:
            raise InvalidStateTransitionError("Version requires artifact before publishing.")
        if self.artifact.status != ArtifactStatus.ACTIVE:
            raise MalwareScanPendingError(
                "Artifact cannot become downloadable until malware scan succeeds."
            )

        self.status = VersionStatus.PUBLISHED
        if self.published_at is None:
            self.published_at = _utc_now()
        self._touch()

    def deprecate(self) -> None:
        if self.status != VersionStatus.PUBLISHED:
            raise InvalidStateTransitionError("Only published versions can be deprecated.")
        self.status = VersionStatus.DEPRECATED
        self._touch()

    def revoke(self) -> None:
        if self.status == VersionStatus.REVOKED:
            return
        self.status = VersionStatus.REVOKED
        self._touch()

    def is_downloadable(self) -> bool:
        return self.status in {VersionStatus.PUBLISHED, VersionStatus.DEPRECATED}

    def _touch(self) -> None:
        self.updated_at = _utc_now()
        self.lock_version += 1
