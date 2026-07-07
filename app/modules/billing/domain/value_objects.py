# from __future__ import annotations


from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping
from uuid import UUID

from pydantic import BaseModel, Field


from app.exceptions.exceptions import InvalidCurrencyError, InvalidMoneyError
from app.modules.shared.enums import PaymentResourceType, PurchaseStatus, PaymentStatus, PaymentProvider






@dataclass(frozen=True, slots=True)
class PaymentSubject:
    resource_type: PaymentResourceType
    resource_id: UUID

@dataclass(frozen=True, slots=True)
class PaymentProviderDetails:
    reference: str
    metadata: Mapping[str, str] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class Currency:
    """
    Immutable value object representing a supported ISO 4217 currency code.

    Guarantees:
        - Uppercase
        - Exactly 3 alphabetic characters
        - Supported by the business
    """

    code: str
    _SUPPORTED: frozenset[str] = frozenset({
        "USD",
        "KES",
        "EUR",
    })

    def __post_init__(self) -> None:
        code = self.code.strip().upper()

        if len(code) != 3 or not code.isalpha():
            raise InvalidCurrencyError(
                "Currency code must contain exactly three alphabetic characters."
            )

        if code not in self._SUPPORTED:
            raise InvalidCurrencyError(
                f"Unsupported currency '{code}'."
            )

        object.__setattr__(self, "code", code)

    def __str__(self) -> str:
        return self.code

    def __repr__(self) -> str:
        return f"Currency('{self.code}')"

@dataclass(frozen=True, slots=True)
class Money:
    amount_cents: int
    currency: Currency

    def __post_init__(self) -> None:
        if self.amount_cents < 0:
            raise InvalidMoneyError(
                "Amount cannot be negative."
            )
    
    def __composite_values__(self):
        return (
            self.amount_cents,
            self.currency,
        )

@dataclass(frozen=True, slots=True)
class PurchaseHistoryCard:
    purchase_id: UUID
    software_id: UUID
    software_name: str
    amount: Money
    status: PurchaseStatus
    purchased_at: datetime
    last_activity_at: datetime
    refunded_at: datetime | None
    revoked_at: datetime | None

class PurchaseHistoryQuery(BaseModel):
    limit: int = Field(50, ge=1, le=100)
    offset: int = Field(0, ge=0)

class PurchaseHistoryPage(BaseModel):
    items: list[PurchaseHistoryCard]
    total: int
    limit: int
    offset: int

@dataclass(frozen=True, slots=True)
class PaymentSummary:
    """
    Lightweight projection used for payment history
    and account billing pages.
    """

    payment_id: UUID

    software_id: UUID
    software_name: str

    amount: Money

    provider: PaymentProvider
    status: PaymentStatus

    created_at: datetime


@dataclass(frozen=True, slots=True)
class CheckoutSession:
    """Read model returned to the caller after checkout initiation.

    The frontend can use this object to render the payment flow and to track
    the status of the checkout without coupling to the domain aggregate.
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
    ) -> "CheckoutSession":
        """Create a read model from a created payment aggregate."""
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
            provider_reference=payment.provider_details.reference if payment.provider_details else None,
            client_secret=client_secret,
            checkout_url=checkout_url,
        )