from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.modules.shared.enums import PaymentProvider, PaymentStatus


class CreateCheckoutRequest(BaseModel):
    """Request body to start a software checkout."""

    software_id: UUID
    provider: PaymentProvider


class PaymentSummaryRead(BaseModel):
    """Lightweight payment projection for a buyer's history list."""

    payment_id: UUID
    software_id: UUID
    software_name: str
    amount_cents: int
    currency: str
    provider: PaymentProvider
    status: PaymentStatus
    created_at: datetime


class CheckoutSessionRead(BaseModel):
    """Read model returned to the caller after a checkout is initiated."""

    id: UUID
    software_id: UUID
    buyer_id: UUID
    owner_id: UUID
    amount_cents: int
    currency: str
    provider: PaymentProvider
    status: PaymentStatus
    created_at: datetime
    completed_at: datetime | None = None
    provider_reference: str | None = None
    client_secret: str | None = None
    checkout_url: str | None = None
    expires_at: datetime | None = None


class PaymentRead(BaseModel):
    """Full payment detail for the authenticated owner."""

    id: UUID
    buyer_id: UUID
    software_id: UUID
    amount_cents: int
    currency: str
    provider: PaymentProvider
    status: PaymentStatus
    provider_reference: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


__all__ = [
    "CreateCheckoutRequest",
    "PaymentSummaryRead",
    "CheckoutSessionRead",
    "PaymentRead",
]
