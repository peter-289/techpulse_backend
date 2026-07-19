from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from app.modules.shared.enums import PurchaseStatus
from app.modules.billing.domain.value_objects import Money
from app.exceptions.exceptions import PurchaseDomainError


@dataclass(slots=True)
class Purchase:
    """Rich domain aggregate representing a software purchase."""

    id: UUID
    buyer_id: UUID
    software_id: UUID
    payment_id: UUID
    amount: Money
    status: PurchaseStatus
    purchased_at: datetime
    updated_at: datetime
    revoked_at: datetime | None = None
    refunded_at: datetime | None = None
    lock_version: int = 0

    @classmethod
    def create(
        cls,
        *,
        buyer_id: UUID,
        software_id: UUID,
        payment_id: UUID,
        amount: Money,
    ) -> "Purchase":
        now = datetime.now(timezone.utc)
        return cls(
            id=uuid4(),
            buyer_id=buyer_id,
            software_id=software_id,
            payment_id=payment_id,
            amount=amount,
            status=PurchaseStatus.ACTIVE,
            purchased_at=now,
            updated_at=now,
            revoked_at=None,
            refunded_at=None,
            lock_version=0,
        )

    # ─── Commands ───
    def revoke(self) -> None:
        self._ensure_can_revoke()
        self.status = PurchaseStatus.REVOKED
        self.revoked_at = datetime.now(timezone.utc)
        self._touch()

    def refund(self) -> None:
        self._ensure_can_refund()
        self.status = PurchaseStatus.REFUNDED
        self.refunded_at = datetime.now(timezone.utc)
        self._touch()

    def restore(self) -> None:
        if self.status != PurchaseStatus.REVOKED:
            raise PurchaseDomainError(
                f"Cannot restore purchase with status {self.status.value}. "
                "Only REVOKED purchases can be restored."
            )
        self.status = PurchaseStatus.ACTIVE
        self.revoked_at = None
        self._touch()

    # ─── Queries ───
    @property
    def is_active(self) -> bool:
        return self.status == PurchaseStatus.ACTIVE

    @property
    def is_refunded(self) -> bool:
        return self.status == PurchaseStatus.REFUNDED

    @property
    def is_revoked(self) -> bool:
        return self.status == PurchaseStatus.REVOKED

    @property
    def is_terminal(self) -> bool:
        return self.status in {PurchaseStatus.REFUNDED, PurchaseStatus.REVOKED}

    @property
    def can_download(self) -> bool:
        return self.is_active

    @property
    def can_revoke(self) -> bool:
        return self.status == PurchaseStatus.ACTIVE

    @property
    def can_refund(self) -> bool:
        return self.status == PurchaseStatus.ACTIVE and self.refunded_at is None

    def assert_active(self) -> None:
        if not self.is_active:
            raise PurchaseDomainError(f"Purchase is not active (status: {self.status.value}).")

    # ─── Helpers ───
    def _ensure_can_revoke(self) -> None:
        if not self.can_revoke:
            raise PurchaseDomainError(f"Cannot revoke purchase with status {self.status.value}.")

    def _ensure_can_refund(self) -> None:
        if not self.can_refund:
            raise PurchaseDomainError(f"Cannot refund purchase with status {self.status.value}.")

    def _touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)
        self.lock_version += 1


__all__ = ["Purchase"]
