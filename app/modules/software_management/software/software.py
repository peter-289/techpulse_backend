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
    currency: str = "KSH"
    versions: list[Version] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
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
        visibility: SoftwareVisibility = SoftwareVisibility.PUBLIC,
        price_cents: int = 0,
        currency: str = "KSH",
    ) -> "Software":
        return cls(
            id=uuid4(),
            name=name,
            description=description,
            owner_id=owner_id,
            status=SoftwareStatus.DRAFT,
            visibility=visibility,
            price_cents=max(0, int(price_cents)),
            currency=currency.upper()[:3] or "KSH",
        )

    def __post_init__(self) -> None:
        self.created_at = _ensure_utc(self.created_at)
        self.updated_at = _ensure_utc(self.updated_at)
        self.price_cents = max(0, int(self.price_cents or 0))
        self.currency = (self.currency or "KSH").upper()[:3]

    # Check if a software is modifiable.
    def _ensure_modifiable(self)-> None:
        if self.status == SoftwareStatus.DELETED:
           raise InvalidStateTransitionError("Deleted software can not be modified.")
        

    # === PRICING MANAGEMENT ===
    def update_pricing(self, *, price_cents: int, currency: str = "KSH") -> None:
        self._ensure_modifiable()
        self.price_cents = max(0, int(price_cents))
        self.currency = (currency or "KSH").upper()[:3]
        self._touch()


    # == SOFTWARE MANAGEMENT ===
    def rename(self, name: str) -> None:
        self._ensure_modifiable()
        if not name:
            raise InvalidStateTransitionError("Name required.")
        self.name = name
        self._touch()
        
    def update_description(self, description: str) -> None:
        self._ensure_modifiable()
        self.description = description.strip()
        self._touch()

    def change_visibility(self, visibility: SoftwareVisibility) -> None:
        self._ensure_modifiable()
        self.visibility = visibility
        self._touch()
        
    def publish(self) -> None:
        if self.status == SoftwareStatus.ACTIVE:
            return
        self._ensure_modifiable()
        self.status = SoftwareStatus.ACTIVE
        self._touch()

    def mark_deleted(self, *, actor_id: UUID, marked_at: datetime | None) -> None:
        self._ensure_modifiable()
        self.status = SoftwareStatus.DELETED
        self.deleted_at = marked_at or utc_now()
        self.deleted_by = actor_id
        self._touch()

    def archive(self) -> None:
        if self.status == SoftwareStatus.ARCHIVED:
            return
        self._ensure_modifiable()
        self.status = SoftwareStatus.ARCHIVED


    def restore(self) -> None:
        self._ensure_modifiable()
        if self.status == SoftwareStatus.ACTIVE:
            return
        self.status = SoftwareStatus.ACTIVE
        self.deleted_at = None
        self.deleted_by = None
        
    

    # === VERSION MANAGEMENT ===
    def add_version(self, version: Version) -> None:
        self._ensure_modifiable()
        if version.software_id != self.id:
            raise InvalidStateTransitionError("Version/software ownership mismatch.")
        if any(item.number == version.number for item in self.versions):
            raise InvalidStateTransitionError(f"Version {version.number} already exists.")
        self.versions.append(version)
        self._touch()

    def get_version(self, version_id: UUID) -> Version:
        self._ensure_modifiable()
        for version in self.versions:
            if version.id == version_id:
                return version
        raise SoftwareNotFoundError(f"Version {version_id} not found.")

    def get_version_by_semver(self, semver: SemVer) -> Version:
        self._ensure_modifiable()
        for version in self.versions:
            if version.number == semver:
                return version
        raise SoftwareNotFoundError(f"Version {semver} not found.")

    def publish_version(self, version_id: UUID) -> VersionPublishedEvent:
        self._ensure_modifiable()
        version = self.get_version(version_id)
        version.publish()
        event = version_published(self.id, version.id)
        self._events.append(event)
        self._touch()
        return event

    def deprecate_version(self, version_id: UUID) -> None:
        self._ensure_modifiable()
        self.get_version(version_id).deprecate()
        self._touch()

    def revoke_version(self, version_id: UUID) -> None:
        self._ensure_modifiable()
        self.get_version(version_id).revoke()
        self._touch()
    
    def remove_version(self, version_id: UUID) -> None:
        self.versions.remove()
        pass

    def latest_downloadable(self) -> Version | None:
        self._ensure_modifiable()
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



from app.modules.software_management.software_schema import SoftwareRead, SoftwareVersionRead, SoftwareCheckoutRead
from app.infrastructure.database.models.software import SoftwareArtifactModel, SoftwareModel, SoftwareVersionModel
from app.modules.software_management.software.artifact import Artifact
from .exceptions import SoftwareAccessDeniedError, SoftwareNotFoundError, SoftwareDomainError
from .enums import ArtifactStatus, VersionStatus

from fastapi import HTTPException, status


def _actor_uuid(user_id: int) -> UUID:
    try:
        return UUID(int=max(0, int(user_id)))
    except Exception:
        # fallback for non-numeric inputs
        return UUID(int=0)


def _actor_int(user_id: UUID) -> int:
    return int(user_id.int)


def _category(description: str) -> str:
    for line in (description or "").splitlines(keepends=True):
        if line.lower().startswith("category:"):
            return line.split(":", 1)[1].strip().lower() or "others"
    return "others"


def _software_item(software: Software, *, viewer_user_id: int) -> SoftwareRead:
    latest = software.latest_downloadable()
    viewer = _actor_uuid(viewer_user_id)
    return SoftwareRead(
        id=str(software.id),
        name=software.name,
        description=software.description,
        owner_id=_actor_int(software.owner_id),
        is_public=software.visibility.value == "public",
        price_cents=software.price_cents,
        currency=software.currency,
        viewer_has_access=software.owner_id == viewer or software.price_cents == 0,
        category=_category(software.description),
        latest_version=str(latest.number) if latest else None,
        download_count=sum(version.download_count for version in software.versions),
        created_at=software.created_at.isoformat(),
        updated_at=software.updated_at.isoformat(),
    )


def _version_item(version: Version) -> SoftwareVersionRead:
    artifact = version.artifact
    return SoftwareVersionRead(
        id=str(version.id),
        software_id=str(version.software_id),
        version=str(version.number),
        is_published=version.status.value in {"published", "deprecated"},
        status=version.status.value,
        download_count=version.download_count,
        release_notes=version.release_notes,
        created_at=version.created_at.isoformat(),
        published_at=version.published_at.isoformat() if version.published_at else None,
        file_hash=artifact.sha256 if artifact else None,
        size_bytes=artifact.size_bytes if artifact else None,
        content_type=artifact.mime_type if artifact else None,
        file_name=artifact.filename if artifact else None,
        artifact_status=artifact.status.value if artifact else None,
        quarantine_reason=artifact.quarantine_reason if artifact else None,
    )


def _payment_item(payment) -> SoftwareCheckoutRead:
    return SoftwareCheckoutRead(
        id=payment.id,
        software_id=payment.software_id,
        buyer_id=_actor_int(UUID(payment.buyer_id)),
        owner_id=_actor_int(UUID(payment.owner_id)),
        amount_cents=payment.amount_cents,
        currency=payment.currency,
        status=payment.status,
        provider=payment.provider,
        provider_reference=payment.provider_reference,
        created_at=payment.created_at.isoformat(),
        completed_at=payment.completed_at.isoformat() if payment.completed_at else None,
    )


def _error(exc: SoftwareDomainError) -> HTTPException:
    if isinstance(exc, SoftwareAccessDeniedError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, SoftwareNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


def _artifact_status(raw: str | None) -> ArtifactStatus:
    try:
        return ArtifactStatus((raw or ArtifactStatus.ACTIVE.value).lower())
    except ValueError:
        return ArtifactStatus.ACTIVE


def _version_status(raw: str | None, is_published: bool) -> VersionStatus:
    candidate = (raw or "").lower()
    if candidate:
        try:
            return VersionStatus(candidate)
        except ValueError:
            pass
    return VersionStatus.PUBLISHED if is_published else VersionStatus.DRAFT


def _artifact_to_entity(model: SoftwareArtifactModel, version_id: str) -> Artifact:
    return Artifact(
        id=UUID(model.id),
        version_id=UUID(version_id),
        storage_key=model.storage_key,
        sha256=model.file_hash,
        size_bytes=model.size_bytes,
        mime_type=model.content_type,
        filename=model.file_name,
        status=_artifact_status(model.status),
        quarantine_reason=model.quarantine_reason,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _version_to_entity(model: SoftwareVersionModel) -> Version:
    return Version(
        id=UUID(model.id),
        software_id=UUID(model.software_id),
        number=SemVer.parse(model.version),
        release_notes=model.release_notes,
        status=_version_status(model.status, model.is_published),
        lock_version=model.lock_version,
        download_count=model.download_count,
        created_at=model.created_at,
        updated_at=model.updated_at,
        published_at=model.published_at,
        artifact=_artifact_to_entity(model.artifact, model.id) if model.artifact else None,
    )


def _software_to_entity(model: SoftwareModel) -> Software:
    return Software(
        id=UUID(model.id),
        name=model.name,
        description=model.description,
        owner_id=UUID(model.owner_id),
        status=SoftwareStatus.ACTIVE,
        visibility=SoftwareVisibility.PUBLIC if model.is_public else SoftwareVisibility.PRIVATE,
        price_cents=model.price_cents or 0,
        currency=model.currency or "USD",
        versions=[_version_to_entity(item) for item in model.versions],
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _artifact_to_model(entity: Artifact) -> SoftwareArtifactModel:
    return SoftwareArtifactModel(
        id=str(entity.id),
        storage_key=entity.storage_key,
        file_hash=entity.sha256,
        size_bytes=entity.size_bytes,
        content_type=entity.mime_type,
        file_name=entity.filename,
        status=entity.status.name,
        quarantine_reason=entity.quarantine_reason,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


def _version_to_model(entity: Version) -> SoftwareVersionModel:
    model = SoftwareVersionModel(
        id=str(entity.id),
        software_id=str(entity.software_id),
        version=str(entity.number),
        release_notes=entity.release_notes,
        is_published=entity.status in {VersionStatus.PUBLISHED, VersionStatus.DEPRECATED},
        status=entity.status.name,
        lock_version=entity.lock_version,
        download_count=entity.download_count,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        published_at=entity.published_at,
    )
    if entity.artifact is not None:
        artifact = _artifact_to_model(entity.artifact)
        model.artifact = artifact
        model.artifact_id = artifact.id
    return model


def _software_to_model(entity: Software) -> SoftwareModel:
    model = SoftwareModel(
        id=str(entity.id),
        owner_id=str(entity.owner_id),
        name=entity.name,
        description=entity.description,
        is_public=entity.visibility == SoftwareVisibility.PUBLIC,
        price_cents=entity.price_cents,
        currency=entity.currency,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )
    model.versions = [_version_to_model(version) for version in entity.versions]
    return model


