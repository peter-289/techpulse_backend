from __future__ import annotations

from typing import Protocol, runtime_checkable
from uuid import UUID

from app.modules.billing.domain.payment import Payment
from app.modules.billing.domain.value_objects import PaymentSubject
# Read models are framework-free data structures owned by the application layer.
# The repository port returns them for projection queries; this is a deliberate,
# benign coupling to a dependency-free DTO (no FastAPI/SQLAlchemy).
from app.modules.billing.application.read_models.payment_summary import PaymentSummary


@runtime_checkable
class PaymentRepositoryProtocol(Protocol):
    """Port for payment persistence. Implemented by infrastructure."""

    async def save(self, payment: Payment) -> Payment: ...

    async def get(self, payment_id: UUID) -> Payment | None: ...

    async def find_by_provider_reference(self, provider_reference: str) -> Payment | None: ...

    async def list_for_buyer(
        self,
        buyer_id: UUID,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[PaymentSummary], int]: ...

    async def exists_pending(self, buyer_id: UUID, subject: PaymentSubject) -> bool: ...


@runtime_checkable
class PaymentUnitOfWorkProtocol(Protocol):
    """Port for the payment Unit of Work boundary."""

    payment_repository: PaymentRepositoryProtocol
