from __future__ import annotations

from uuid import UUID

from app.modules.shared.enums import VersionStatus
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
from app.modules.software_management.software.version import Version


class SoftwareAccessPolicy:
    """Authoritative policy for software access decisions in the Software domain.

    The policy is intentionally stateless and contains only domain business
    rules. It operates on domain aggregates and primitive facts and raises
    domain-specific exceptions when an operation is not permitted.
    """

    @staticmethod
    def ensure_can_purchase(
        *,
        software: Software,
        buyer_id: UUID,
        has_purchase: bool,
    ) -> None:
        """Ensure a buyer can purchase the given software."""
        if software.is_owned_by(buyer_id):
            raise OwnerCannotPurchaseError("Owners cannot purchase their own software.")

        if software.is_archived():
            raise SoftwareArchivedError("Archived software cannot be purchased.")

        if software.is_deleted():
            raise SoftwareDeletedError("Deleted software cannot be purchased.")

        if not software.is_public():
            raise SoftwareAccessDeniedError("Private software is not available for purchase.")

        if has_purchase:
            raise DuplicatePurchaseError("Buyer already owns or has purchased this software.")

        if not software.requires_payment():
            raise SoftwareAccessDeniedError("Software does not require payment.")

        if not software.is_active():
            raise SoftwareAccessDeniedError("Software is not active and cannot be purchased.")

    @staticmethod
    def ensure_can_download(
        *,
        software: Software,
        version: Version,
        actor_id: UUID,
        owns_software: bool,
    ) -> None:
        """Ensure the actor may download the specified software version."""
        if software.is_owned_by(actor_id):
            return

        if not owns_software:
            raise DownloadDeniedError("Only active owners may download this software.")

        if version.status == VersionStatus.REVOKED:
            raise VersionUnavailableError("The requested version has been revoked.")

        if version.status != VersionStatus.PUBLISHED:
            raise SoftwareNotPublishedError("The requested version is not published.")

        if not software.is_active():
            raise SoftwareNotPublishedError("Software is not active and cannot be downloaded.")

        if not software.is_public():
            raise SoftwareAccessDeniedError("Software is not visible to the requesting actor.")

    @staticmethod
    def ensure_can_view(
        *,
        software: Software,
        actor_id: UUID | None,
    ) -> None:
        """Ensure the actor may view the given software."""
        if software.is_public():
            return

        if actor_id is not None and software.is_owned_by(actor_id):
            return

        raise SoftwareAccessDeniedError("Only the owner can view private software.")

    @staticmethod
    def ensure_can_modify(
        *,
        software: Software,
        actor_id: UUID,
    ) -> None:
        """Ensure the actor may modify the given software."""
        if software.is_deleted():
            raise SoftwareDeletedError("Deleted software cannot be modified.")

        if software.is_archived():
            raise SoftwareArchivedError("Archived software cannot be modified.")

        if not software.is_owned_by(actor_id):
            raise SoftwareAccessDeniedError("Only the owner may modify software.")

    @staticmethod
    def ensure_can_publish(
        *,
        software: Software,
        actor_id: UUID,
    ) -> None:
        """Ensure the actor may publish the given software."""
        if software.is_deleted():
            raise SoftwareDeletedError("Deleted software cannot be published.")

        if software.is_archived():
            raise SoftwareArchivedError("Archived software cannot be published.")

        if not software.is_owned_by(actor_id):
            raise SoftwareAccessDeniedError("Only the owner may publish software.")

        if not software.has_downloadable_versions():
            raise VersionUnavailableError("Software must contain at least one downloadable version.")

    @staticmethod
    def ensure_can_delete(
        *,
        software: Software,
        actor_id: UUID,
        active_purchases: int,
        pending_payments: int,
    ) -> None:
        """Ensure the actor may delete the given software."""
        if not software.is_owned_by(actor_id):
            raise SoftwareAccessDeniedError("Only the owner may delete software.")

        if active_purchases > 0:
            raise SoftwareAccessDeniedError("Software cannot be deleted while active purchases exist.")

        if pending_payments > 0:
            raise SoftwareAccessDeniedError("Software cannot be deleted while pending payments exist.")