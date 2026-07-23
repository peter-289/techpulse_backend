from uuid import UUID, uuid4

import pytest

from app.modules.billing.domain.value_objects import Currency, Money
from app.modules.shared.enums import AccessType, SoftwareStatus, SoftwareVisibility, VersionStatus
from app.modules.software_management.policies.software_access_policy import SoftwareAccessPolicy
from app.modules.software_management.software.exceptions import (
    DownloadDeniedError,
    DuplicatePurchaseError,
    OwnerCannotPurchaseError,
    SoftwareAccessDeniedError,
    SoftwareArchivedError,
    SoftwareDeletedError,
    SoftwareNotPublishedError,
    VersionUnavailableError,
)
from app.modules.software_management.software.software import Software
from techpulse_backend.app.modules.software_management.domain.value_objects.value_objects import SemVer
from app.modules.software_management.software.version import Version


def _make_software(*, owner_id: UUID, visibility: SoftwareVisibility = SoftwareVisibility.PUBLIC, status: SoftwareStatus = SoftwareStatus.ACTIVE, access_type: AccessType = AccessType.PURCHASE_REQUIRED) -> Software:
    return Software(
        id=uuid4(),
        name="Widget",
        description="Test software",
        owner_id=owner_id,
        price=Money(amount_cents=500, currency=Currency("KES")),
        category_id=uuid4(),
        status=status,
        visibility=visibility,
        access_type=access_type,
        versions=[],
    )


def _make_version(software_id: UUID, *, status: VersionStatus = VersionStatus.PUBLISHED) -> Version:
    return Version(
        id=uuid4(),
        software_id=software_id,
        number=SemVer.parse("1.0.0"),
        release_notes="Initial release",
        status=status,
        lock_version=1,
    )


def test_purchase_is_denied_for_owner() -> None:
    owner_id = uuid4()
    software = _make_software(owner_id=owner_id)

    with pytest.raises(OwnerCannotPurchaseError):
        SoftwareAccessPolicy.ensure_can_purchase(
            software=software,
            buyer_id=owner_id,
            has_purchase=False,
        )


def test_purchase_is_denied_for_duplicate_purchase() -> None:
    buyer_id = uuid4()
    software = _make_software(owner_id=uuid4())

    with pytest.raises(DuplicatePurchaseError):
        SoftwareAccessPolicy.ensure_can_purchase(
            software=software,
            buyer_id=buyer_id,
            has_purchase=True,
        )


def test_download_is_denied_without_active_ownership() -> None:
    buyer_id = uuid4()
    software = _make_software(owner_id=uuid4())
    version = _make_version(software.id)

    with pytest.raises(DownloadDeniedError):
        SoftwareAccessPolicy.ensure_can_download(
            software=software,
            version=version,
            actor_id=buyer_id,
            owns_software=False,
        )


def test_download_is_denied_for_revoked_version() -> None:
    buyer_id = uuid4()
    software = _make_software(owner_id=uuid4())
    version = _make_version(software.id, status=VersionStatus.REVOKED)

    with pytest.raises(VersionUnavailableError):
        SoftwareAccessPolicy.ensure_can_download(
            software=software,
            version=version,
            actor_id=buyer_id,
            owns_software=True,
        )


def test_view_is_denied_for_non_owner_when_private() -> None:
    owner_id = uuid4()
    software = _make_software(owner_id=owner_id, visibility=SoftwareVisibility.PRIVATE)

    with pytest.raises(SoftwareAccessDeniedError):
        SoftwareAccessPolicy.ensure_can_view(
            software=software,
            actor_id=uuid4(),
        )


def test_modify_is_denied_for_archived_software() -> None:
    owner_id = uuid4()
    software = _make_software(owner_id=owner_id, status=SoftwareStatus.ARCHIVED)

    with pytest.raises(SoftwareArchivedError):
        SoftwareAccessPolicy.ensure_can_modify(
            software=software,
            actor_id=owner_id,
        )


def test_publish_is_denied_without_downloadable_version() -> None:
    owner_id = uuid4()
    software = _make_software(owner_id=owner_id)
    software.versions.append(_make_version(software.id, status=VersionStatus.DRAFT))

    with pytest.raises(VersionUnavailableError):
        SoftwareAccessPolicy.ensure_can_publish(
            software=software,
            actor_id=owner_id,
        )


def test_delete_is_denied_with_pending_payments() -> None:
    owner_id = uuid4()
    software = _make_software(owner_id=owner_id)

    with pytest.raises(SoftwareAccessDeniedError):
        SoftwareAccessPolicy.ensure_can_delete(
            software=software,
            actor_id=owner_id,
            active_purchases=0,
            pending_payments=1,
        )
