from __future__ import annotations

from uuid import UUID
from sqlalchemy.exc import SQLAlchemyError
import logging

from app.exceptions.exceptions import DuplicatePurchaseError, PurchaseNotFoundError, PurchaseDomainError, RepositoryUnavailableError
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.billing.domain.purchase_model import Purchase
from app.modules.billing.domain.value_objects import PurchaseHistoryCard
from app.modules.shared.enums import PaymentResourceType

from .domain.payment_model import Payment


# === Configure logging ===
logger = logging.getLogger(__name__)


class PurchaseService:
    def __init__(self, unit_of_work: UnitOfWork):
        self.uow = unit_of_work

    async def has_purchase(self, software_id: UUID, buyer_id: UUID) -> bool:
        """Check whether the buyer already owns the software."""
        async with self.uow.read_only():
            return await self.uow.purchase_repository.has_purchase(software_id, buyer_id)

    async def grant_purchase(self, payment: Payment) -> Purchase:
        """Create a purchase aggregate when a payment has completed successfully."""
        if not payment.is_successful:
            raise PurchaseDomainError("Cannot grant purchase for an unsuccessful payment.")

        if payment.subject.resource_type != PaymentResourceType.SOFTWARE:
            raise PurchaseDomainError("Only software purchases can create ownership.")

        async with self.uow:
            existing_payment_purchase = await self.uow.purchase_repository.find_by_payment(payment.id)
            if existing_payment_purchase is not None:
                return existing_payment_purchase

            owned = await self.uow.purchase_repository.has_purchase(
                software_id=payment.subject.resource_id,
                buyer_id=payment.buyer_id,
            )
            if owned:
                raise DuplicatePurchaseError("You already own this software.")

            purchase = Purchase.create(
                buyer_id=payment.buyer_id,
                software_id=payment.subject.resource_id,
                payment_id=payment.id,
                amount=payment.amount,
            )
            await self.uow.purchase_repository.save(purchase)
            return purchase

    async def revoke_purchase(
        self,
        purchase_id: UUID,
        *,
        reason: str,
        actor_id: UUID,
    ) -> Purchase:
        """Revoke ownership for a purchase that is currently active."""
        del reason
        del actor_id

        async with self.uow:
            purchase = await self.uow.purchase_repository.get(purchase_id)
            if purchase is None:
                raise PurchaseDomainError("Purchase not found.")

            purchase.revoke()
            await self.uow.purchase_repository.save(purchase)
            return purchase

    async def refund_purchase(
        self,
        purchase_id: UUID,
        *,
        reason: str,
        refund_reference: str,
    ) -> Purchase:
        """Mark a purchase as refunded when the refund workflow has been approved."""
        del reason
        del refund_reference

        async with self.uow:
            purchase = await self.uow.purchase_repository.get(purchase_id)
            if purchase is None:
                raise PurchaseDomainError("Purchase not found.")

            purchase.refund()
            await self.uow.purchase_repository.save(purchase)
            return purchase

    async def restore_purchase(self, purchase_id: UUID, *, actor_id: UUID) -> Purchase:
        """Restore a previously revoked purchase to an active state."""
        del actor_id

        async with self.uow:
            purchase = await self.uow.purchase_repository.get(purchase_id)
            if purchase is None:
                raise PurchaseDomainError("Purchase not found.")

            purchase.restore()
            await self.uow.purchase_repository.save(purchase)
            return purchase

    async def get_purchase(self, purchase_id: UUID) -> Purchase | None:
        """Retrieve a purchase aggregate by identifier."""
        async with self.uow.read_only():
             
            purchase = await self.uow.purchase_repository.get(purchase_id=purchase_id)
            if not purchase:
                raise PurchaseNotFoundError("Purchase not found.")

    async def get_purchase_for_buyer_and_software(
        self,
        *,
        buyer_id: UUID,
        software_id: UUID,
    ) -> Purchase | None:
        """Retrieve the purchase aggregate for a buyer/software pair."""
        async with self.uow.read_only():
            return await self.uow.purchase_repository.get_purchase(
                software_id=software_id,
                buyer_id=buyer_id,
            )

    async def list_purchase_history(
        self,
        buyer_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[PurchaseHistoryCard], int]:
        """Return a read projection for the purchase history page."""
        async with self.uow.read_only():


            return await self.uow.purchase_repository.list_history(
                buyer_id,
                limit=limit,
                offset=offset,
            )

    async def list_owned(
         self,
         buyer_id: UUID,
         *,
         limit: int = 50,
         offset: int = 0,
        ) -> tuple[list[Purchase], int]:
       """
        List purchases owned by a buyer.
       """
       try:
         async with self.uow.read_only():
            purchases, total = await self.uow.purchase_repository.list_owned(
                buyer_id=buyer_id,
                limit=limit,
                offset=offset,
            )
            return purchases, total
            
       except SQLAlchemyError as exc:
         # Log and re-raise as domain error
          logger.error("Failed to list purchases for %s: %s", buyer_id, exc)
          raise RepositoryUnavailableError("Failed to load purchases") from exc