from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4


from app.modules.shared.enums import SoftwareStatus, SoftwareVisibility, AccessType
from app.modules.software_management.domain.events import (
    SoftwareDownloadedEvent,
    SoftwareEvent,
    VersionPublishedEvent,
    software_created,
    utc_now,
    version_published,
)
from app.modules.software_management.domain.exceptions import InvalidStateTransitionError, SoftwareNotFoundError
from app.modules.software_management.domain.value_objects import SemVer
from app.modules.software_management.domain.entities.version import Version
from app.modules.billing.domain.value_objects import Currency, Money



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
    price: Money
    category_id: UUID | None = None

    status: SoftwareStatus = SoftwareStatus.DRAFT
    visibility: SoftwareVisibility = SoftwareVisibility.PUBLIC
    access_type: AccessType = AccessType.FREE
    
    versions: list[Version] = field(default_factory=list)

    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    download_count: int = 0

    deleted_by: UUID | None = None
    deleted_at: datetime | None = None

    _events: list[SoftwareEvent] = field(default_factory=list, init=False, repr=False)

    @classmethod
    def create(
        cls,
        *,
        name: str,
        description: str,
        owner_id: UUID,
        category_id: UUID | None = None,
        visibility: SoftwareVisibility = SoftwareVisibility.PUBLIC,
        price_cents: int = 0,
        currency: str = "KES",
    ) -> "Software":
        """Create a new software instance.

        The aggregate owns pricing invariants and constructs the Money value
        object internally from primitive values.
        """
        price = Money(amount_cents=price_cents, currency=Currency(code=currency))
        access_type = (AccessType.FREE if price.amount_cents == 0 else AccessType.PURCHASE_REQUIRED)


        return cls(
            id=uuid4(),
            name=name,
            description=description,
            owner_id=owner_id,
            category_id=category_id,
            status=SoftwareStatus.DRAFT,
            visibility=visibility,
            access_type=access_type,
            price=price,
        )._emit_created()

    def __post_init__(self) -> None:
        self.created_at = _ensure_utc(self.created_at)
        self.updated_at = _ensure_utc(self.updated_at)

    def _emit_created(self) -> "Software":
        self._events.append(software_created(self.id, self.owner_id))
        return self

    # Check if a software is modifiable.
    def _ensure_modifiable(self) -> None:
        """Guard that blocks state-changing commands when the aggregate is not modifiable.

        Queries must never call this method.
        """
        if self.status in {SoftwareStatus.DELETED, SoftwareStatus.ARCHIVED}:
            raise InvalidStateTransitionError(
                "Software must be ACTIVE to be modifiable."
            )


    # === PRICING MANAGEMENT ===
    def update_pricing(self, *, price_cents: int, currency: str) -> None:
        """Update the pricing of the software.

        The aggregate constructs the Money value object internally, preserving
        pricing invariants. Negative price cents are normalized to zero.
        """
        self._ensure_modifiable()
        normalized = max(price_cents, 0)
        self.price = Money(amount_cents=normalized, currency=Currency(code=currency))
        self._touch()


    # == SOFTWARE MANAGEMENT ===
    def rename(self, name: str) -> None:
        """Rename the software. Name is required and cannot be empty."""
        self._ensure_modifiable()
        if not name or not name.strip():
            raise InvalidStateTransitionError("Name required.")
        self.name = name.strip()
        self._touch()
        
    def update_description(self, description: str) -> None:
        """Update the description of the software."""
        self._ensure_modifiable()
        self.description = description.strip()
        self._touch()

    def change_visibility(self, visibility: SoftwareVisibility) -> None:
        """Change the visibility of the software."""
        self._ensure_modifiable()
        self.visibility = visibility
        self._touch()
        
    def publish(self) -> None:
        """Publish the software."""
        if self.status == SoftwareStatus.ACTIVE:
            return
        self._ensure_modifiable()
        self.status = SoftwareStatus.ACTIVE
        self._touch()

    def mark_deleted(self, *, actor_id: UUID, marked_at: datetime | None) -> None:
        """Mark the software as deleted.
           Deleted software is not modifiable and cannot be published."""
        self._ensure_modifiable()
        self.status = SoftwareStatus.DELETED
        self.deleted_at = marked_at or utc_now()
        self.deleted_by = actor_id
        self._touch()

    def archive(self) -> None:
        """Archive the software. 
           Archived software is not modifiable and cannot be published."""
        if self.status == SoftwareStatus.ARCHIVED:
            return
        self._ensure_modifiable()
        self.status = SoftwareStatus.ARCHIVED
        self._touch()

    def restore(self) -> None:
        """Restore the software from ARCHIVED or DELETED state.

        This is a *command* that transitions the aggregate back to ACTIVE.
        Restoration is only permitted when the software is currently ARCHIVED or DELETED.

        Raises:
            InvalidStateTransitionError: If the current state does not support restoration.
        """

        if self.status == SoftwareStatus.ACTIVE:
            return

        if self.status not in {SoftwareStatus.ARCHIVED, SoftwareStatus.DELETED}:
            raise InvalidStateTransitionError(
                "Restore is only allowed from ARCHIVED or DELETED state."
            )

        self.status = SoftwareStatus.ACTIVE
        self.deleted_at = None
        self.deleted_by = None
        self._touch()

    
    def change_access_policy(self, access_type: AccessType) -> None:
        """Change the access policy of the software."""
        self._ensure_modifiable()
        self.access_type = access_type
        self._touch()
    

    # === VERSION MANAGEMENT ===
    def add_version(self, version: Version) -> None:
        """Add a new version to the software."""
        self._ensure_modifiable()
        if version.software_id != self.id:
            raise InvalidStateTransitionError("Version/software ownership mismatch.")
        if any(item.number == version.number for item in self.versions):
            raise InvalidStateTransitionError(f"Version {version.number} already exists.")
        self.versions.append(version)
        self._touch()

    def get_version(self, version_id: UUID) -> Version:
        """Get a version by its ID.

        Query-only: must be side-effect free and must not depend on the
        aggregate being modifiable (e.g., archived/deleted software may still
        expose versions for read use-cases).

        Raises:
            SoftwareNotFoundError: If the version does not exist.
        """

        for version in self.versions:
            if version.id == version_id:
                return version
        raise SoftwareNotFoundError(f"Version {version_id} not found.")

    def get_version_by_semver(self, semver: SemVer) -> Version:
        """Get a version by its semantic version.

        Query-only: must be side-effect free and must not depend on the
        aggregate being modifiable.

        Raises:
            SoftwareNotFoundError: If the version does not exist.
        """

        for version in self.versions:
            if version.number == semver or str(version.number) == str(semver):
                return version
        raise SoftwareNotFoundError(f"Version {semver} not found.")

    def publish_version(self, version_id: UUID) -> VersionPublishedEvent:
        """Publish a version of the software."""
        self._ensure_modifiable()
        version = self.get_version(version_id)
        version.publish()
        event = version_published(self.id, version.id)
        self._events.append(event)
        self._touch()
        return event

    def deprecate_version(self, version_id: UUID) -> None:
        """Deprecate a version of the software."""
        self._ensure_modifiable()
        self.get_version(version_id).deprecate()
        self._touch()

    def revoke_version(self, version_id: UUID) -> None:
        """Revoke a version of the software."""
        self._ensure_modifiable()
        self.get_version(version_id).revoke()
        self._touch()
    
    def remove_version(self, version_id: UUID) -> None:
        """Remove a version of the software."""
        self._ensure_modifiable()
        version = self.get_version(version_id)
        self.versions.remove(version)
        self._touch()

    def latest_downloadable(self) -> Version | None:
        """Get the latest downloadable version of the software.

        Query-only: side-effect free; must not require the aggregate to be
        modifiable.
        """
        downloadable = [item for item in self.versions if item.is_downloadable()]

        if not downloadable:
            return None
        return max(downloadable, key=lambda item: item.published_at or item.created_at)

    # === INTENTION-REVEALING QUERIES ===
    def is_owned_by(self, actor_id: UUID) -> bool:
        """Return whether the given actor owns this software."""
        return self.owner_id == actor_id

    def is_public(self) -> bool:
        """Return whether the software is publicly visible."""
        return self.visibility == SoftwareVisibility.PUBLIC

    def is_active(self) -> bool:
        """Return whether the software is in ACTIVE state."""
        return self.status == SoftwareStatus.ACTIVE

    def is_archived(self) -> bool:
        """Return whether the software is in ARCHIVED state."""
        return self.status == SoftwareStatus.ARCHIVED

    def is_deleted(self) -> bool:
        """Return whether the software is in DELETED state."""
        return self.status == SoftwareStatus.DELETED

    def requires_payment(self) -> bool:
        """Return whether the access type requires payment."""
        return self.access_type != AccessType.FREE

    def has_versions(self) -> bool:
        """Return whether the software has any versions."""
        return len(self.versions) > 0

    def has_downloadable_versions(self) -> bool:
        """Return whether the software has any downloadable versions."""
        return any(v.is_downloadable() for v in self.versions)

    def latest_version(self) -> Version | None:
        """Return the latest version by publication time (or creation time)."""
        if not self.versions:
            return None
        return max(self.versions, key=lambda v: v.published_at or v.created_at)

    def published_versions(self) -> list[Version]:
        """Return all versions that are published."""
        return [v for v in self.versions if v.is_published()]



    def increment_download_count(self) -> None:
        """Record a successful download.

        Increments the download counter and emits a domain event.

        Raises:
            InvalidStateTransitionError: If software is deleted.
        """
        self._ensure_modifiable()
        self.download_count += 1
        self._touch()
        self._events.append(SoftwareDownloadedEvent(
            software_id=self.id,
            occurred_at=utc_now(),
        ))

    def pull_events(self) -> list[SoftwareEvent]:
        """Pull and clear the list of events for the software."""
        events = list(self._events)
        self._events.clear()
        return events

    # === Compatibility layer ===
    # Internal code may call these query helpers; keep them side-effect free.
    def is_publicly_visible(self) -> bool:
        return self.is_public()


    def _touch(self) -> None:
        """Update the updated_at timestamp to the current UTC time."""
        self.updated_at = utc_now()







