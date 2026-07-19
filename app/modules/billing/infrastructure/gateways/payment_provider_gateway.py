"""Payment provider gateway port and normalized DTOs.

This module defines the only abstraction the application layer is allowed to
depend on for talking to external payment providers. Concrete adapters
(Stripe, M-Pesa, PayPal, ...) live under ``infrastructure/gateways/`` and must
never leak provider SDK types; they return only the normalized DTOs defined
here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal, Mapping, Protocol, runtime_checkable
from datetime import datetime

from app.modules.billing.domain.payment import Payment
from app.modules.billing.infrastructure.webhooks.models import (
    ProviderWebhookEvent,
    WebhookOutcome,
)

logger = logging.getLogger(__name__)




@dataclass(frozen=True, slots=True)
class ProviderCheckoutSession:
    """Hosted checkout session created at provider."""

    provider_reference: str
    url: str
    expires_at: datetime | None = None
    client_secret: str | None = None
    metadata: Mapping[str, str] | None = None

    @property
    def checkout_url(self) -> str:
        return self.url


@dataclass(frozen=True, slots=True)
class ProviderPaymentStatus:
    """Current payment status at provider."""

    provider_reference: str
    status: Literal["pending", "processing", "completed", "failed", "canceled", "refunded"]
    amount_cents: int | None = None
    currency: str | None = None


@dataclass(frozen=True, slots=True)
class VerifiedWebhook:
    """Result of webhook signature verification."""

    provider_reference: str
    event_type: str


@dataclass(frozen=True, slots=True)
class ProviderRefund:
    """Provider-independent refund DTO."""

    provider_reference: str
    status: str


@runtime_checkable
class PaymentProviderGateway(Protocol):
    """Hexagonal port for all external payment provider integrations."""

    async def create_checkout(self, payment: Payment) -> ProviderCheckoutSession:
        """Create a hosted checkout session for the given payment."""

    async def verify_webhook(self, *, headers: Mapping[str, str], body: bytes) -> VerifiedWebhook:
        """Verify webhook signature and return a normalized verification result."""

    async def parse_webhook(self, *, body: bytes) -> ProviderWebhookEvent:
        """Parse a provider webhook payload into a normalized event.

        The returned event must carry a classified ``WebhookOutcome``.
        """

    async def verify_and_parse(
        self, *, headers: Mapping[str, str], body: bytes
    ) -> ProviderWebhookEvent:
        """Verify the signature and parse the payload in a single step.

        Implementations read the request body once and return an event whose
        ``outcome`` is already classified. Used by the webhook receiver.
        """

    async def get_payment_status(self, provider_reference: str) -> ProviderPaymentStatus:
        """Get latest payment status from the provider."""

    async def refund(self, payment: Payment, *, amount_cents: int | None = None) -> ProviderRefund:
        """Issue a refund via the provider."""

    async def cancel(self, provider_reference: str) -> None:
        """Cancel a payment at the provider."""


__all__ = [
    "ProviderCheckoutSession",
    "ProviderPaymentStatus",
    "VerifiedWebhook",
    "ProviderWebhookEvent",
    "WebhookOutcome",
    "ProviderRefund",
    "PaymentProviderGateway",
]
