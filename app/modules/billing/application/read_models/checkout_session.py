from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.modules.billing.domain.value_objects import Money
from app.modules.shared.enums import PaymentProvider, PaymentStatus


@dataclass(frozen=True, slots=True)
class CheckoutSession:
    """Read model returned to the caller after checkout initiation.

    The frontend uses this object to render the payment flow and to track the
    status of the checkout without coupling to the domain aggregate.
    """

    id: UUID
    software_id: UUID
    buyer_id: UUID
    owner_id: UUID
    amount: Money
    provider: PaymentProvider
    status: PaymentStatus
    created_at: datetime
    completed_at: datetime | None = None
    provider_reference: str | None = None
    client_secret: str | None = None
    checkout_url: str | None = None
    expires_at: datetime | None = None

    @classmethod
    def from_payment(
        cls,
        *,
        payment: object,
        software_id: UUID,
        owner_id: UUID,
        provider: PaymentProvider,
        checkout_url: str | None = None,
        client_secret: str | None = None,
        provider_reference: str | None = None,
        expires_at: datetime | None = None,
    ) -> "CheckoutSession":
        """Create a read model from a created payment aggregate."""
        resolved_provider_reference = provider_reference
        if resolved_provider_reference is None and payment.provider_details is not None:
            resolved_provider_reference = payment.provider_details.reference

        return cls(
            id=payment.id,
            software_id=software_id,
            buyer_id=payment.buyer_id,
            owner_id=owner_id,
            amount=payment.amount,
            provider=provider,
            status=payment.status,
            created_at=payment.created_at,
            completed_at=payment.completed_at,
            provider_reference=resolved_provider_reference,
            client_secret=client_secret,
            checkout_url=checkout_url,
            expires_at=expires_at,
        )


__all__ = ["CheckoutSession"]
