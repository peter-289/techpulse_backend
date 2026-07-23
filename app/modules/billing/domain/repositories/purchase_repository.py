from __future__ import annotations

from typing import Protocol, runtime_checkable
from uuid import UUID

from app.modules.billing.domain.purchase import Purchase
from app.modules.billing.domain.value_objects import PurchaseHistoryCard
from app.modules.software_management.domain.value_objects.value_objects import OwnedSoftwareCard


@runtime_checkable
class PurchaseRepositoryProtocol(Protocol):
    """Port for purchase persistence. Implemented by infrastructure."""

    async def find_by_payment(self, payment_id: UUID) -> Purchase | None: ...

    async def has_purchase(self, software_id: UUID, buyer_id: UUID) -> bool: ...

    async def save(self, purchase: Purchase) -> None: ...

    async def get(self, purchase_id: UUID) -> Purchase | None: ...

    async def get_purchase(self, *, software_id: UUID, buyer_id: UUID) -> Purchase | None: ...

    async def list_history(
        self,
        buyer_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[PurchaseHistoryCard], int]: ...

    async def list_owned(
        self,
        buyer_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[OwnedSoftwareCard], int]: ...


@runtime_checkable
class PurchaseUnitOfWorkProtocol(Protocol):
    """Port for the purchase Unit of Work boundary."""

    purchase_repository: PurchaseRepositoryProtocol
