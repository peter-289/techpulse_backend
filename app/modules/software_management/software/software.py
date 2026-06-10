from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from .enums import SoftwareStatus, SoftwareVisibility
from .events import SoftwareEvent, VersionPublishedEvent, utc_now, version_published
from .exceptions import InvalidStateTransitionError, SoftwareNotFoundError
from .value_objects import SemVer
from .version import Version


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(slots=True)
class Software:
    id: UUID
    name: str
    description: str
    owner_id: UUID
    status: SoftwareStatus
    visibility: SoftwareVisibility
    price_cents: int = 0
    currency: str = "USD"
    versions: list[Version] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    _events: list[SoftwareEvent] = field(default_factory=list, init=False, repr=False)

    @classmethod
    def create(
        cls,
        *,
        name: str,
        description: str,
        owner_id: UUID,
        visibility: SoftwareVisibility = SoftwareVisibility.PUBLIC,
        price_cents: int = 0,
        currency: str = "USD",
    ) -> "Software":
        return cls(
            id=uuid4(),
            name=name,
            description=description,
            owner_id=owner_id,
            status=SoftwareStatus.ACTIVE,
            visibility=visibility,
            price_cents=max(0, int(price_cents)),
            currency=currency.upper()[:3] or "USD",
        )

    def __post_init__(self) -> None:
        self.created_at = _ensure_utc(self.created_at)
        self.updated_at = _ensure_utc(self.updated_at)
        self.price_cents = max(0, int(self.price_cents or 0))
        self.currency = (self.currency or "USD").upper()[:3]

    def update_pricing(self, *, price_cents: int, currency: str = "USD") -> None:
        self.price_cents = max(0, int(price_cents))
        self.currency = (currency or "USD").upper()[:3]
        self._touch()

    def add_version(self, version: Version) -> None:
        if version.software_id != self.id:
            raise InvalidStateTransitionError("Version/software ownership mismatch.")
        if any(item.number == version.number for item in self.versions):
            raise InvalidStateTransitionError(f"Version {version.number} already exists.")
        self.versions.append(version)
        self._touch()

    def get_version(self, version_id: UUID) -> Version:
        for version in self.versions:
            if version.id == version_id:
                return version
        raise SoftwareNotFoundError(f"Version {version_id} not found.")

    def get_version_by_semver(self, semver: SemVer) -> Version:
        for version in self.versions:
            if version.number == semver:
                return version
        raise SoftwareNotFoundError(f"Version {semver} not found.")

    def publish_version(self, version_id: UUID) -> VersionPublishedEvent:
        version = self.get_version(version_id)
        version.publish()
        event = version_published(self.id, version.id)
        self._events.append(event)
        self._touch()
        return event

    def deprecate_version(self, version_id: UUID) -> None:
        self.get_version(version_id).deprecate()
        self._touch()

    def revoke_version(self, version_id: UUID) -> None:
        self.get_version(version_id).revoke()
        self._touch()

    def latest_downloadable(self) -> Version | None:
        downloadable = [item for item in self.versions if item.is_downloadable()]
        if not downloadable:
            return None
        return max(downloadable, key=lambda item: item.published_at or item.created_at)

    def pull_events(self) -> list[SoftwareEvent]:
        events = list(self._events)
        self._events.clear()
        return events

    def _touch(self) -> None:
        self.updated_at = utc_now()
