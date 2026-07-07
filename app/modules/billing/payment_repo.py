from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Final
from uuid import UUID

from sqlalchemy import exists, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.payment import SoftwarePaymentModel
from app.modules.billing.domain.payment_model import Payment
from app.modules.billing.domain.value_objects import Money, PaymentProviderDetails, PaymentSubject, PaymentSummary
from app.modules.software_management.software.exceptions import RepositoryUnavailableError

logger = logging.getLogger(__name__)


class IPaymentRepository(ABC):
    """Billing bounded context payment repository contract."""

    @abstractmethod
    async def save(self, payment: Payment) -> Payment: ...

    @abstractmethod
    async def get(self, payment_id: UUID) -> Payment | None: ...

    @abstractmethod
    async def find_by_provider_reference(self, provider_reference: str) -> Payment | None: ...

    @abstractmethod
    async def list_for_buyer(
        self,
        buyer_id: UUID,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[PaymentSummary], int]: ...

    @abstractmethod
    async def exists_pending(self, buyer_id: UUID, subject: PaymentSubject) -> bool: ...


class PaymentRepository(IPaymentRepository):
    """SQLAlchemy async implementation of the Billing payment repository.

    Architectural role:
    - Infrastructure-only persistence component.
    - Translates between domain aggregates (`Payment`) and persistence models (`SoftwarePaymentModel`).
    - Supports CQRS-style read patterns:
      * `get()` hydrates a `Payment` aggregate
      * `list_for_buyer()` returns lightweight `PaymentSummary` projections (no aggregate hydration)

    Transaction expectations:
    - This repository never commits, rollbacks, or begins transactions.
    - It relies on the surrounding Unit of Work to manage the transaction lifecycle.

    Performance notes:
    - `exists_pending()` uses SQL `EXISTS` (no materialization of rows).
    - `list_for_buyer()` uses projection query + separate `COUNT(*)` query.
    - `find_by_provider_reference()` is a single-row lookup and assumes an index on `provider_reference`.
    """

    _PENDING_STATUSES: Final[tuple[str, ...]] = ("PENDING", "PROCESSING")

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # -----------------------------
    # Domain <-> Model mapping
    # -----------------------------
    @staticmethod
    def _payment_to_model(payment: Payment) -> SoftwarePaymentModel:
        """Convert a domain `Payment` into a persistence `SoftwarePaymentModel`.

        Note:
        The current persistence schema uses:
        - `id`, `buyer_id`, `software_id`, `owner_id` as strings.
        - `amount` stored via Money composite (`amount_cents`, `currency`).
        - `provider_reference` nullable.
        """

        provider_details = payment.provider_details
        provider_reference: str | None = provider_details.reference if provider_details is not None else None

        amount: Money = payment.amount
        now = datetime.now(timezone.utc)

        created_at = getattr(payment, "created_at", now)
        updated_at = getattr(payment, "updated_at", now)

        # provider/status are stored as strings in the model
        provider_value = str(payment.provider.value) if hasattr(payment.provider, "value") else str(payment.provider)
        status_value = str(payment.status.value) if hasattr(payment.status, "value") else str(payment.status)

        return SoftwarePaymentModel(
            id=str(payment.id),
            software_id=str(payment.subject.resource_id),
            buyer_id=str(payment.buyer_id),
            owner_id=str(payment.subject.resource_id),
            amount_cents=int(amount.amount_cents),
            currency=str(amount.currency.code),
            status=status_value,
            provider=provider_value,
            provider_reference=provider_reference,
            created_at=created_at,
            updated_at=updated_at,
            completed_at=getattr(payment, "completed_at", None),
        )

    @staticmethod
    def _model_to_payment(model: SoftwarePaymentModel) -> Payment:
        """Hydrate a domain `Payment` aggregate from a persistence model."""

        # Import locally to avoid potential import cycles.
        from app.modules.shared.enums import PaymentProvider, PaymentStatus, PaymentResourceType

        amount = Money(amount_cents=int(model.amount_cents), currency=payment_currency_from_code(model.currency))

        subject = PaymentSubject(
            resource_type=PaymentResourceType.SOFTWARE,
            resource_id=UUID(str(model.software_id)),
        )

        provider_details = (
            PaymentProviderDetails(reference=model.provider_reference)
            if model.provider_reference is not None
            else None
        )

        return Payment(
            id=UUID(str(model.id)),
            buyer_id=UUID(str(model.buyer_id)),
            subject=subject,
            amount=amount,
            provider=PaymentProvider(model.provider),
            status=PaymentStatus(model.status),
            created_at=model.created_at,
            updated_at=model.updated_at,
            provider_details=provider_details,
            refund_reference=getattr(model, "refund_reference", None),
            failure_reason=getattr(model, "failure_reason", None),
            completed_at=getattr(model, "completed_at", None),
            refunded_at=getattr(model, "refunded_at", None),
            canceled_at=getattr(model, "canceled_at", None),
            lock_version=getattr(model, "lock_version", 0),
        )

    @staticmethod
    def _model_to_summary(model: SoftwarePaymentModel) -> PaymentSummary:
        """Convert a persistence model into a lightweight `PaymentSummary`."""

        from app.modules.shared.enums import PaymentProvider, PaymentStatus

        amount = Money(amount_cents=int(model.amount_cents), currency=payment_currency_from_code(model.currency))

        return PaymentSummary(
            payment_id=UUID(str(model.id)),
            software_id=UUID(str(model.software_id)),
            software_name="",
            amount=amount,
            provider=PaymentProvider(model.provider),
            status=PaymentStatus(model.status),
            created_at=model.created_at,
        )

    # -----------------------------
    # Public repository API
    # -----------------------------
    async def save(self, payment: Payment) -> Payment:
        """Persist a `Payment` aggregate.

        Purpose:
            Stage/merge the payment aggregate into the database and flush changes.

        Args:
            payment: The payment aggregate to persist.

        Returns:
            A hydrated domain `Payment` aggregate (same instance as input, unless refresh succeeds).

        Raises:
            RepositoryUnavailableError: If SQLAlchemy fails.

        Transaction expectations:
            Does not commit/rollback/begin. Caller/UoW manages transaction.

        Performance notes:
            Uses `merge()` and `flush()`. Performs `refresh()` best-effort.
        """

        try:
            model = self._payment_to_model(payment)
            await self._session.merge(model)
            await self._session.flush()
            try:
                await self._session.refresh(model)
                return self._model_to_payment(model)
            except SQLAlchemyError:
                # Return input if refresh fails.
                return payment
        except SQLAlchemyError as e:
            logger.exception(
                "PaymentRepository.save failed: payment_id=%s buyer_id=%s provider_reference=%s",
                str(getattr(payment, "id", None)),
                str(getattr(payment, "buyer_id", None)),
                str(getattr(getattr(payment, "provider_details", None), "reference", None)),
            )
            raise RepositoryUnavailableError("Failed to save payment due to database error.") from e

    async def get(self, payment_id: UUID) -> Payment | None:
        """Retrieve a `Payment` aggregate by its primary key.

        Args:
            payment_id: Payment UUID.

        Returns:
            Hydrated `Payment` aggregate, or `None` when not found.

        Raises:
            RepositoryUnavailableError: If SQLAlchemy fails.

        Transaction expectations:
            Read-only lookup; does not commit/rollback/begin.

        Performance notes:
            Single-row primary-key lookup.
        """

        try:
            stmt = select(SoftwarePaymentModel).where(SoftwarePaymentModel.id == str(payment_id))
            model = await self._session.scalar(stmt)
            return self._model_to_payment(model) if model is not None else None
        except SQLAlchemyError as e:
            logger.exception("PaymentRepository.get failed: payment_id=%s", str(payment_id))
            raise RepositoryUnavailableError("Failed to fetch payment due to database error.") from e

    async def find_by_provider_reference(self, provider_reference: str) -> Payment | None:
        """Find a payment by provider reference.

        Purpose:
            Used by webhook processing to correlate provider events.

        Args:
            provider_reference: Provider reference identifier.

        Returns:
            Hydrated `Payment` aggregate, or `None` when not found.

        Raises:
            RepositoryUnavailableError: If SQLAlchemy fails.

        Transaction expectations:
            Read-only lookup; does not commit/rollback/begin.

        Performance notes:
            Assumes an index on `provider_reference`.
        """

        try:
            stmt = select(SoftwarePaymentModel).where(
                SoftwarePaymentModel.provider_reference == provider_reference
            )
            model = await self._session.scalar(stmt)
            return self._model_to_payment(model) if model is not None else None
        except SQLAlchemyError as e:
            logger.exception(
                "PaymentRepository.find_by_provider_reference failed: provider_reference=%s",
                provider_reference,
            )
            raise RepositoryUnavailableError(
                "Failed to fetch payment by provider reference due to database error."
            ) from e

    async def exists_pending(self, buyer_id: UUID, subject: PaymentSubject) -> bool:
        """Check whether an unfinished payment exists for the same buyer and subject.

        Args:
            buyer_id: Buyer UUID.
            subject: Payment subject.

        Returns:
            True when an unfinished payment exists, otherwise False.

        Raises:
            RepositoryUnavailableError: If SQLAlchemy fails.

        Transaction expectations:
            Read-only lookup; does not commit/rollback/begin.

        Performance notes:
            Uses SQL `EXISTS` to avoid row materialization.
        """

        try:
            stmt = (
                select(
                    exists(
                        select(1).select_from(SoftwarePaymentModel).where(
                            SoftwarePaymentModel.buyer_id == str(buyer_id),
                            SoftwarePaymentModel.software_id == str(subject.resource_id),
                            SoftwarePaymentModel.status.in_(self._PENDING_STATUSES),
                        )
                    )
                )
            )
            value = await self._session.scalar(stmt)
            return bool(value)
        except SQLAlchemyError as e:
            logger.exception(
                "PaymentRepository.exists_pending failed: buyer_id=%s subject_resource_id=%s",
                str(buyer_id),
                str(subject.resource_id),
            )
            raise RepositoryUnavailableError("Failed to check pending payment due to database error.") from e

    async def list_for_buyer(
        self,
        buyer_id: UUID,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[PaymentSummary], int]:
        """List `PaymentSummary` projections for a buyer.

        Args:
            buyer_id: Buyer UUID.
            limit: Page size.
            offset: Pagination offset.

        Returns:
            (items, total_count) where items are lightweight `PaymentSummary` objects.

        Raises:
            RepositoryUnavailableError: If SQLAlchemy fails.

        Transaction expectations:
            Read-only; does not commit/rollback/begin.

        Performance notes:
            - Uses a projection query (no `Payment` hydration).
            - Separate `COUNT(*)` query.
            - Orders newest first.
        """

        try:
            base_where = SoftwarePaymentModel.buyer_id == str(buyer_id)

            stmt = (
                select(SoftwarePaymentModel)
                .where(base_where)
                .order_by(SoftwarePaymentModel.created_at.desc(), SoftwarePaymentModel.id.desc())
                .limit(limit)
                .offset(offset)
            )
            models = (await self._session.scalars(stmt)).all()
            items = [self._model_to_summary(m) for m in models]

            count_stmt = select(func.count()).select_from(SoftwarePaymentModel).where(base_where)
            total = await self._session.scalar(count_stmt)

            return items, int(total or 0)
        except SQLAlchemyError as e:
            logger.exception(
                "PaymentRepository.list_for_buyer failed: buyer_id=%s limit=%s offset=%s",
                str(buyer_id),
                limit,
                offset,
            )
            raise RepositoryUnavailableError("Failed to list payments due to database error.") from e


def payment_currency_from_code(code: str):
    """Create the Money Currency value object from stored ISO code."""

    from app.modules.billing.domain.value_objects import Currency

    return Currency(code=code)

