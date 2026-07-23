from __future__ import annotations

from uuid import UUID
from fastapi import HTTPException, status

from app.modules.software_management.domain.entities.artifact import Artifact
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.entities.version import Version
from app.modules.software_management.schema.software_schema import SoftwareCheckoutRead, SoftwareRead, SoftwareVersionRead
from app.modules.shared.enums import ArtifactStatus, VersionStatus, SoftwareStatus, SoftwareVisibility
from app.infrastructure.database.models.software import SoftwareArtifactModel, SoftwareModel, SoftwareVersionModel

from app.modules.software_management.domain.exceptions import SoftwareDomainError, SoftwareAccessDeniedError, SoftwareNotFoundError
from app.modules.software_management.domain.value_objects import SemVer
from app.modules.billing.domain.value_objects import Currency, Money





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


def _software_item(software: Software, *, viewer_user_id: UUID) -> SoftwareRead:
    latest = software.latest_downloadable()
    return SoftwareRead(
        id=str(software.id),
        name=software.name,
        description=software.description,
        owner_id=int(software.owner_id.int),
        is_public=software.visibility.value == "public",
        price_cents=software.price.amount_cents,
        currency=software.price.currency.code,
        viewer_has_access=software.owner_id == viewer_user_id or software.price.amount_cents == 0,
        category=_category(software.description),
        latest_version=str(latest.number) if latest else None,
        download_count=software.download_count,
        created_at=software.created_at.isoformat(),
        updated_at=software.updated_at.isoformat(),
    )


def _version_item(version: Version) -> SoftwareVersionRead:
    """Version read model"""
    artifact = version.artifact
    return SoftwareVersionRead(
        id=version.id,
        software_id=version.software_id,
        artifact_id=artifact.id if artifact else None,
        version=version.number,
        status=version.status,
        download_count=version.download_count,
        release_notes=version.release_notes,
        created_at=version.created_at,
        published_at=version.published_at,
        file_hash=artifact.sha256 if artifact else None,
        size_bytes=artifact.size_bytes if artifact else None,
        content_type=artifact.mime_type if artifact else None,
        file_name=artifact.filename if artifact else None,
        artifact_status=artifact.status.value if artifact else None,
    )


def _payment_item(payment_or_session: object, *, owner_id: UUID) -> SoftwareCheckoutRead:
    from app.modules.billing.api.schemas.payment_schema import CheckoutSessionRead
    from app.modules.billing.domain.payment import Payment

    if isinstance(payment_or_session, CheckoutSessionRead):
        session = payment_or_session
        return SoftwareCheckoutRead(
            id=str(session.id),
            software_id=str(session.software_id),
            buyer_id=int(session.buyer_id.int),
            owner_id=int(owner_id.int),
            amount_cents=session.amount_cents,
            currency=session.currency,
            status=session.status.value,
            provider=session.provider.value,
            provider_reference=session.provider_reference,
            client_secret=None,
            checkout_url=session.checkout_url,
            created_at=session.created_at.isoformat(),
            completed_at=session.completed_at.isoformat() if session.completed_at else None,
        )

    if isinstance(payment_or_session, Payment):
        payment = payment_or_session
        reference = payment.provider_details.reference if payment.provider_details else None
        return SoftwareCheckoutRead(
            id=str(payment.id),
            software_id=str(payment.subject.resource_id),
            buyer_id=int(payment.buyer_id.int),
            owner_id=int(owner_id.int),
            amount_cents=payment.amount.amount_cents,
            currency=str(payment.amount.currency),
            status=payment.status.value,
            provider=payment.provider.value,
            provider_reference=reference,
            client_secret=None,
            checkout_url=None,
            created_at=payment.created_at.isoformat(),
            completed_at=payment.completed_at.isoformat() if payment.completed_at else None,
        )

    raise TypeError(f"Cannot map {type(payment_or_session)} to SoftwareCheckoutRead")


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


def _version_status(raw: str | None) -> VersionStatus:
    candidate = (raw or "").lower()
    if candidate:
        try:
            return VersionStatus(candidate)
        except ValueError:
            pass
    return VersionStatus.PUBLISHED if candidate == VersionStatus.PUBLISHED.value.lower() else VersionStatus.DRAFT


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
        status=_version_status(model.status),
        lock_version=model.lock_version,
        download_count=model.download_count,
        created_at=model.created_at,
        updated_at=model.updated_at,
        published_at=model.published_at,
        artifact=_artifact_to_entity(model.artifact, model.id) if model.artifact else None,
    )


def _software_to_entity(model: SoftwareModel) -> Software:
    status_value = getattr(model, "status", SoftwareStatus.ACTIVE)
    visibility_value = getattr(model, "visibility", SoftwareVisibility.PUBLIC)
    status_raw = status_value.value if isinstance(status_value, SoftwareStatus) else str(status_value).lower()
    visibility_raw = (
        visibility_value.value if isinstance(visibility_value, SoftwareVisibility) else str(visibility_value).lower()
    )
    return Software(
        id=UUID(model.id),
        name=model.name,
        description=model.description,
        owner_id=UUID(model.owner_id),
        status=SoftwareStatus(status_raw),
        visibility=SoftwareVisibility(visibility_raw),
        category_id=model.category_id if getattr(model, "category_id", None) else None,
        price=Money(amount_cents=model.price_cents or 0, currency=Currency(code=model.currency or "USD")),
        versions=[_version_to_entity(item) for item in model.versions],
        created_at=model.created_at,
        updated_at=model.updated_at,
        download_count=model.download_count or 0,
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
        visibility=entity.visibility.value,
        category_id=entity.category_id,
        price_cents=entity.price.amount_cents,
        currency=entity.price.currency.code,
        access_policy=entity.access_type,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        download_count=entity.download_count,
    )
    model.versions = [_version_to_model(version) for version in entity.versions]
    return model
