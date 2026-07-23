"""SQLAlchemy async persistence adapter for payments.

Infrastructure-only. Translates between the ``Payment`` aggregate and the
``SoftwarePaymentModel`` persistence model. Never commits, rolls back, or
begins transactions; the Unit of Work owns the transaction lifecycle.
"""

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
from app.modules.billing.domain.payment import Payment
from app.modules.billing.application.read_models.payment_summary import PaymentSummary
from app.modules.billing.domain.value_objects import (
    Money,
    PaymentProviderDetails,
    PaymentSubject,
)
from app.modules.billing.domain.repositories.payment_repository import (
    PaymentRepositoryProtocol,
)
from app.modules.software_management.domain.exceptions import RepositoryUnavailableError

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
        self, buyer_id: UUID, *, limit: int, offset: int
    ) -> tuple[list[PaymentSummary], int]: ...

    @abstractmethod
    async def exists_pending(self, buyer_id: UUID, subject: PaymentSubject) -> bool: ...


class PaymentRepository(IPaymentRepository, PaymentRepositoryProtocol):
    """SQLAlchemy async implementation of the payment repository."""

    _PENDING_STATUSES: Final[tuple[str, ...]] = ("PENDING", "PROCESSING")

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _payment_to_model(payment: Payment) -> SoftwarePaymentModel:
        provider_details = payment.provider_details
        provider_reference: str | None = (
            provider_details.reference if provider_details is not None else None
        )
        amount: Money = payment.amount
        now = datetime.now(timezone.utc)
        created_at = getattr(payment, "created_at", now)
        updated_at = getattr(payment, "updated_at", now)
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
        from app.modules.shared.enums import PaymentProvider, PaymentStatus, PaymentResourceType

        amount = Money(
            amount_cents=int(model.amount_cents),
            currency=payment_currency_from_code(model.currency),
        )
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
        from app.modules.shared.enums import PaymentProvider, PaymentStatus

        amount = Money(
            amount_cents=int(model.amount_cents),
            currency=payment_currency_from_code(model.currency),
        )
        return PaymentSummary(
            payment_id=UUID(str(model.id)),
            software_id=UUID(str(model.software_id)),
            software_name="",
            amount=amount,
            provider=PaymentProvider(model.provider),
            status=PaymentStatus(model.status),
            created_at=model.created_at,
        )

    async def save(self, payment: Payment) -> Payment:
        try:
            model = self._payment_to_model(payment)
            await self._session.merge(model)
            await self._session.flush()
            try:
                await self._session.refresh(model)
                return self._model_to_payment(model)
            except SQLAlchemyError:
                return payment
        except SQLAlchemyError as e:
            logger.exception(
                "PaymentRepository.save failed: payment_id=%s buyer_id=%s",
                str(getattr(payment, "id", None)),
                str(getattr(payment, "buyer_id", None)),
            )
            raise RepositoryUnavailableError("Failed to save payment due to database error.") from e

    async def get(self, payment_id: UUID) -> Payment | None:
        try:
            stmt = select(SoftwarePaymentModel).where(SoftwarePaymentModel.id == str(payment_id))
            model = await self._session.scalar(stmt)
            return self._model_to_payment(model) if model is not None else None
        except SQLAlchemyError as e:
            logger.exception("PaymentRepository.get failed: payment_id=%s", str(payment_id))
            raise RepositoryUnavailableError("Failed to fetch payment due to database error.") from e

    async def find_by_provider_reference(self, provider_reference: str) -> Payment | None:
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
        try:
            stmt = select(
                exists(
                    select(1)
                    .select_from(SoftwarePaymentModel)
                    .where(
                        SoftwarePaymentModel.buyer_id == str(buyer_id),
                        SoftwarePaymentModel.software_id == str(subject.resource_id),
                        SoftwarePaymentModel.status.in_(self._PENDING_STATUSES),
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
        self, buyer_id: UUID, *, limit: int, offset: int
    ) -> tuple[list[PaymentSummary], int]:
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


def payment_currency_from_code(code: str) -> "object":
    """Create the Money Currency value object from a stored ISO code."""
    from app.modules.billing.domain.value_objects import Currency

    return Currency(code=code)


__all__ = ["IPaymentRepository", "PaymentRepository"]
