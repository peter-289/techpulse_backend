from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from ..enums import SoftwareStatus, SoftwareVisibility
from ..events import DomainEvent, VersionPublishedEvent, version_published
from ..exceptions import InvalidStateTransitionError, NotFoundError
from ..value_objects import SemVer
from .version import Version


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        raise ValueError("Software timestamps must be timezone-aware.")
    return ts.astimezone(timezone.utc)


@dataclass(slots=True)
class Software:
    id: UUID
    name: str
    description: str
    owner_id: UUID
    status: SoftwareStatus
    visibility: SoftwareVisibility
    versions: list[Version] = field(default_factory=list)
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    _events: list[DomainEvent] = field(default_factory=list, init=False, repr=False)

    @classmethod
    def create(
        cls,
        name: str,
        description: str,
        owner_id: UUID,
        visibility: SoftwareVisibility = SoftwareVisibility.PUBLIC,
    ) -> "Software":
        return cls(
            id=uuid4(),
            name=name,
            description=description,
            owner_id=owner_id,
            status=SoftwareStatus.ACTIVE,
            visibility=visibility,
        )

    def __post_init__(self) -> None:
        self.created_at = _ensure_utc(self.created_at)
        self.updated_at = _ensure_utc(self.updated_at)

    def add_version(self, version: Version) -> None:
        if version.software_id != self.id:
            raise InvalidStateTransitionError("Version/software ownership mismatch.")
        if any(v.number == version.number for v in self.versions):
            raise InvalidStateTransitionError(f"Version {version.number} already exists.")
        self.versions.append(version)
        self._touch()

    def get_version(self, version_id: UUID) -> Version:
        for version in self.versions:
            if version.id == version_id:
                return version
        raise NotFoundError(f"Version {version_id} not found.")

    def get_version_by_semver(self, semver: SemVer) -> Version:
        for version in self.versions:
            if version.number == semver:
                return version
        raise NotFoundError(f"Version {semver} not found.")

    def publish_version(self, version_id: UUID) -> VersionPublishedEvent:
        version = self.get_version(version_id)
        version.publish()
        event = version_published(self.id, version.id)
        self._events.append(event)
        self._touch()
        return event

    def deprecate_version(self, version_id: UUID) -> None:
        version = self.get_version(version_id)
        version.deprecate()
        self._touch()

    def revoke_version(self, version_id: UUID) -> None:
        version = self.get_version(version_id)
        version.revoke()
        self._touch()

    def latest_downloadable(self) -> Version | None:
        downloadable = [item for item in self.versions if item.is_downloadable()]
        if not downloadable:
            return None
        return max(downloadable, key=lambda v: v.published_at or v.created_at)

    def pull_events(self) -> list[DomainEvent]:
        events = list(self._events)
        self._events.clear()
        return events

    def _touch(self) -> None:
        self.updated_at = _utc_now()
