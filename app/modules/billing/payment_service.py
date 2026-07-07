from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID

from app.exceptions.exceptions import RepositoryUnavailableError
from app.modules.billing.domain.payment_model import Payment
from app.modules.billing.domain.value_objects import Money, PaymentProviderDetails, PaymentSubject
from app.modules.billing.payment_exceptions import (
    DuplicatePendingPaymentError,
    InvalidPaymentStateTransitionError,
    PaymentNotFoundError,
)
from app.modules.shared.enums import PaymentProvider, PaymentStatus

logger = logging.getLogger(__name__)


class PaymentRepositoryProtocol(Protocol):
    async def save(self, payment: Payment) -> Payment: ...

    async def get(self, payment_id: UUID) -> Payment | None: ...

    async def find_by_provider_reference(self, provider_reference: str) -> Payment | None: ...

    async def exists_pending(self, buyer_id: UUID, subject: PaymentSubject) -> bool: ...

    async def list_for_buyer(
        self,
        buyer_id: UUID,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[object], int]: ...


class UnitOfWorkProtocol(Protocol):
    payment_repository: PaymentRepositoryProtocol


@dataclass(frozen=True, slots=True)
class CreatePaymentCommand:
    buyer_id: UUID
    subject: PaymentSubject
    amount: Money
    provider: PaymentProvider


class PaymentService:
    """Application service for the Billing bounded context.



    Architectural role:
    - Orchestrates domain behaviors and persistence via the Unit of Work.
    - Keeps business rules at the application/domain layers (not in repository).

    Transaction expectations:
    - Does not call commit/rollback. Assumes the surrounding infrastructure layer
      manages transactions and commits.

    Performance notes:
    - `create()` uses `exists_pending()` to prevent duplicates with an indexed EXISTS query.
    - List endpoints delegate to repository projection queries.
    """

    def __init__(self, uow: UnitOfWorkProtocol) -> None:
        self._uow = uow

    async def create(self, cmd: CreatePaymentCommand) -> Payment:
        """Create and persist a new payment in PENDING state.

        Args:
            cmd: Command containing buyer, subject, amount, and payment provider.

        Returns:
            Persisted `Payment` aggregate.

        Raises:
            DuplicatePendingPaymentError: If an unfinished payment already exists.
            RepositoryUnavailableError: If persistence fails.

        Transaction expectations:
            Only stages changes; does not commit.

        Performance notes:
            Uses an indexed EXISTS query via `repository.exists_pending()`.
        """

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

    async def get(self, payment_id: UUID) -> Payment:
        """Retrieve a payment aggregate by id.

        Args:
            payment_id: Payment UUID.

        Returns:
            Hydrated `Payment` aggregate.

        Raises:
            PaymentNotFoundError: If the payment does not exist.
            RepositoryUnavailableError: If persistence fails.

        Transaction expectations:
            Read-only; does not commit.

        Performance notes:
            Single-row lookup.
        """

        try:
            payment = await self._uow.payment_repository.get(payment_id)
        except RepositoryUnavailableError:
            logger.exception("PaymentService.get repository error payment_id=%s", str(payment_id))
            raise

        if payment is None:
            raise PaymentNotFoundError(f"Payment not found: {payment_id}")
        return payment

    async def complete(
        self,
        *,
        payment_id: UUID,
    ) -> Payment:
        """Complete a payment aggregate.

        This method is the Billing bounded context's authoritative entry point
        for transitioning a payment into the successful state after a trusted
        payment provider confirmation.

        The service:
        - Owns the Unit of Work / transaction boundary.
        - Loads the Payment aggregate.
        - Delegates idempotency and lifecycle invariants to the aggregate.
        - Persists the aggregate.
        - Logs successful completion.

        Args:
            payment_id: Trusted internal payment identifier.

        Returns:
            The updated Payment aggregate.

        Raises:
            PaymentNotFoundError: If the payment does not exist.
            InvalidPaymentStateTransitionError: If the aggregate refuses
                completion due to an invalid state transition.
            RepositoryUnavailableError: If persistence fails.

        Notes:
            Domain invariants are enforced by the Payment aggregate.
            This service contains no business rules beyond orchestration.
        """

        async with self._uow:
            payment = await self._uow.payment_repository.get(payment_id)
            if payment is None:
                raise PaymentNotFoundError(f"Payment not found: {payment_id}")

            if payment.is_successful:
                logger.info(
                    "Payment already completed: payment=%s buyer=%s",
                    payment.id,
                    payment.buyer_id,
                )
                return payment

            payment.mark_succeeded(provider_reference=None)
            updated = await self._uow.payment_repository.save(payment)

        logger.info(
            "Completed payment %s for buyer %s",
            updated.id,
            updated.buyer_id,
        )
        return updated

    async def confirm_by_provider_reference(self, provider_reference: str) -> Payment:

        """Confirm a payment using a provider reference.

        Args:
            provider_reference: External provider reference.

        Returns:
            Updated `Payment` aggregate.

        Raises:
            PaymentNotFoundError: If no payment exists.
            InvalidPaymentStateTransitionError: If domain state transition fails.
            RepositoryUnavailableError: If persistence fails.

        Transaction expectations:
            Only stages changes; does not commit.

        Performance notes:
            Uses an indexed provider reference lookup.
        """

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

        try:
            # Domain method validates transition based on current status.
            # This service assumes caller verified provider outcome.
            payment.mark_succeeded(provider_reference=provider_reference)
        except Exception as exc:
            # Domain already raises PaymentDomainError, but prompt requires explicit exception.
            raise InvalidPaymentStateTransitionError("Invalid payment state transition.") from exc

        return await self._uow.payment_repository.save(payment)

    async def list_for_buyer(self, buyer_id: UUID, *, limit: int, offset: int) -> tuple[list[object], int]:
        """List payment summaries for UI history.

        Args:
            buyer_id: Buyer UUID.
            limit: Page size.
            offset: Page offset.

        Returns:
            Tuple of (items, total_count). Items are lightweight `PaymentSummary` projections.

        Raises:
            RepositoryUnavailableError: If persistence fails.

        Transaction expectations:
            Read-only; does not commit.

        Performance notes:
            Delegates to repository projection + separate count query.
        """

        try:
            return await self._uow.payment_repository.list_for_buyer(
                buyer_id,
                limit=limit,
                offset=offset,
            )
        except RepositoryUnavailableError:
            logger.exception("PaymentService.list_for_buyer failed buyer_id=%s", str(buyer_id))
            raise


# Backwards-compatible name (some parts of the codebase may import it)
__all__ = ["PaymentService", "CreatePaymentCommand"]

