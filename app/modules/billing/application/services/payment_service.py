from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from app.exceptions.exceptions import PaymentDomainError, RepositoryUnavailableError
from app.modules.billing.application.mappers.payment_mapper import PaymentMapper
from app.modules.billing.api.schemas.payment_schema import PaymentRead, PaymentSummaryRead
from app.modules.billing.domain.exceptions import (
    DuplicatePendingPaymentError,
    InvalidPaymentStateTransitionError,
    PaymentAccessDenied,
    PaymentNotFoundError,
)
from app.modules.billing.domain.payment import Payment
from app.modules.billing.domain.value_objects import Money, PaymentProviderDetails, PaymentSubject
from app.modules.billing.domain.repositories.payment_repository import (
    PaymentUnitOfWorkProtocol,
)
from app.modules.shared.enums import PaymentProvider

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CreatePaymentCommand:
    buyer_id: UUID
    subject: PaymentSubject
    amount: Money
    provider: PaymentProvider


class PaymentService:
    """Application service for the Billing bounded context.

    Orchestrates domain behaviors and persistence via the Unit of Work. Owns
    transaction boundaries but contains no business rules of its own beyond
    load/persist orchestration. Raises domain exceptions only.
    """

    def __init__(self, uow: PaymentUnitOfWorkProtocol) -> None:
        self._uow = uow

    async def create(self, cmd: CreatePaymentCommand) -> Payment:
        if await self._uow.payment_repository.exists_pending(cmd.buyer_id, cmd.subject):
            logger.info(
                "PaymentService.create duplicate pending payment prevented buyer_id=%s subject_resource_id=%s",
                str(cmd.buyer_id),
                str(cmd.subject.resource_id),
            )
            raise DuplicatePendingPaymentError(
                "An unfinished payment already exists for this buyer and subject."
            )

        payment = Payment.create(
            buyer_id=cmd.buyer_id,
            subject=cmd.subject,
            amount=cmd.amount,
            provider=cmd.provider,
            provider_details=PaymentProviderDetails(reference=""),
        )

        try:
            return await self._uow.payment_repository.save(payment)
        except RepositoryUnavailableError:
            logger.exception(
                "PaymentService.create failed buyer_id=%s subject_resource_id=%s",
                str(cmd.buyer_id),
                str(cmd.subject.resource_id),
            )
            raise

    async def attach_provider_reference(
        self,
        *,
        payment_id: UUID,
        provider_reference: str,
    ) -> Payment:
        async with self._uow:  # type: ignore[attr-defined]
            payment = await self._uow.payment_repository.get(payment_id)
            if payment is None:
                raise PaymentNotFoundError(f"Payment not found: {payment_id}")

            try:
                payment.attach_provider_reference(provider_reference)
            except PaymentDomainError as exc:
                raise InvalidPaymentStateTransitionError(
                    "Cannot attach provider reference to this payment."
                ) from exc

            updated = await self._uow.payment_repository.save(payment)

        logger.info("Attached provider reference payment=%s provider_reference=%s", payment_id, provider_reference)
        return updated

    async def get(self, payment_id: UUID) -> Payment:
        """Retrieve a payment aggregate by id (unscoped, internal use)."""
        try:
            payment = await self._uow.payment_repository.get(payment_id)
        except RepositoryUnavailableError:
            logger.exception("PaymentService.get repository error payment_id=%s", str(payment_id))
            raise

        if payment is None:
            raise PaymentNotFoundError(f"Payment not found: {payment_id}")
        return payment

    async def get_for_buyer(self, *, payment_id: UUID, buyer_id: UUID) -> PaymentRead:
        """Retrieve a payment, enforcing buyer ownership.

        Authorization lives in the service layer: the router must call this
        method rather than the unscoped ``get``.
        """
        payment = await self.get(payment_id=payment_id)
        if payment.buyer_id != buyer_id:
            logger.warning(
                "Payment access denied payment=%s buyer=%s requested_by=%s",
                payment_id,
                payment.buyer_id,
                buyer_id,
            )
            raise PaymentAccessDenied("You do not have access to this payment.")
        return PaymentMapper.to_payment_read(payment)

    async def complete(self, *, payment_id: UUID) -> Payment:
        async with self._uow:  # type: ignore[attr-defined]
            payment = await self._uow.payment_repository.get(payment_id)
            if payment is None:
                raise PaymentNotFoundError(f"Payment not found: {payment_id}")

            if payment.is_successful:
                logger.info("Payment already completed: payment=%s buyer=%s", payment.id, payment.buyer_id)
                return payment

            payment.mark_succeeded(provider_reference=None)
            updated = await self._uow.payment_repository.save(payment)

        logger.info("Completed payment %s for buyer %s", updated.id, updated.buyer_id)
        return updated

    async def confirm_by_provider_reference(self, provider_reference: str) -> Payment:
        try:
            payment = await self._uow.payment_repository.find_by_provider_reference(provider_reference)
        except RepositoryUnavailableError:
            logger.exception(
                "PaymentService.confirm_by_provider_reference repository error provider_reference=%s",
                provider_reference,
            )
            raise

        if payment is None:
            raise PaymentNotFoundError("Payment not found for provider reference.")

        if payment.is_successful:
            logger.info(
                "Payment already completed for provider reference=%s payment=%s",
                provider_reference,
                payment.id,
            )
            return payment

        try:
            payment.mark_succeeded(provider_reference=provider_reference)
        except PaymentDomainError as exc:
            raise InvalidPaymentStateTransitionError("Invalid payment state transition.") from exc

        return await self._uow.payment_repository.save(payment)

    async def list_for_buyer(
        self, buyer_id: UUID, *, limit: int, offset: int
    ) -> tuple[list[PaymentSummaryRead], int]:
        try:
            summaries, total = await self._uow.payment_repository.list_for_buyer(
                buyer_id, limit=limit, offset=offset
            )
        except RepositoryUnavailableError:
            logger.exception("PaymentService.list_for_buyer failed buyer_id=%s", str(buyer_id))
            raise

        return [PaymentMapper.to_summary_read(s) for s in summaries], total


__all__ = ["PaymentService", "CreatePaymentCommand"]
