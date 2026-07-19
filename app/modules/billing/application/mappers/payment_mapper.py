from __future__ import annotations

from app.modules.billing.application.read_models.payment_summary import PaymentSummary
from app.modules.billing.domain.payment import Payment
from app.modules.billing.api.schemas.payment_schema import (
    PaymentRead,
    PaymentSummaryRead,
)


class PaymentMapper:
    """Maps payment domain objects and read models to API DTOs.

    Pure, side-effect-free transformations. No business logic.
    """

    @staticmethod
    def to_summary_read(summary: PaymentSummary) -> PaymentSummaryRead:
        return PaymentSummaryRead(
            payment_id=summary.payment_id,
            software_id=summary.software_id,
            software_name=summary.software_name,
            amount_cents=summary.amount.amount_cents,
            currency=str(summary.amount.currency),
            provider=summary.provider,
            status=summary.status,
            created_at=summary.created_at,
        )

    @staticmethod
    def to_payment_read(payment: Payment) -> PaymentRead:
        reference = payment.provider_details.reference if payment.provider_details else None
        return PaymentRead(
            id=payment.id,
            buyer_id=payment.buyer_id,
            software_id=payment.subject.resource_id,
            amount_cents=payment.amount.amount_cents,
            currency=str(payment.amount.currency),
            provider=payment.provider,
            status=payment.status,
            provider_reference=reference,
            created_at=payment.created_at,
            completed_at=payment.completed_at,
        )


__all__ = ["PaymentMapper"]
