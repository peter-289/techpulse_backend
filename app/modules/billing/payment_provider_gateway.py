from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping, Protocol
from uuid import UUID

from app.modules.billing.domain.payment_model import Payment

logger = logging.getLogger(__name__)


class PaymentProviderGatewayError(Exception):
    """Base exception for provider gateway errors."""


class PaymentGatewayUnavailableError(PaymentProviderGatewayError):
    """Raised when the provider cannot be reached or is unavailable."""


class PaymentProviderTimeoutError(PaymentGatewayUnavailableError):
    """Raised when a provider request times out."""


class PaymentProviderAuthenticationError(PaymentGatewayUnavailableError):
    """Raised when authentication with a provider fails."""


class InvalidWebhookSignatureError(PaymentProviderGatewayError):
    """Raised when a webhook signature fails verification."""


class PaymentProviderRequestError(PaymentProviderGatewayError):
    """Raised when a provider request fails for a non-timeout reason."""


class RefundFailedError(PaymentProviderGatewayError):
    """Raised when issuing a refund fails."""


@dataclass(frozen=True, slots=True)
class ProviderCheckoutSession:
    """Provider-independent hosted checkout session DTO."""

    provider_reference: str
    url: str


@dataclass(frozen=True, slots=True)
class VerifiedWebhook:
    """Result of webhook verification."""

    provider_reference: str
    event_type: str


@dataclass(frozen=True, slots=True)
class ProviderWebhookEvent:
    """Normalized provider webhook event DTO."""

    provider_reference: str
    event_type: str


@dataclass(frozen=True, slots=True)
class ProviderPaymentStatus:
    """Provider-independent payment status DTO."""

    provider_reference: str
    status: str


@dataclass(frozen=True, slots=True)
class ProviderRefund:
    """Provider-independent refund DTO."""

    provider_reference: str
    status: str


class PaymentProviderGateway(Protocol):
    """Hexagonal port for all external payment provider integrations."""

    async def create_checkout(self, payment: Payment) -> ProviderCheckoutSession:
        """Create a hosted checkout session for the given payment."""

    async def verify_webhook(
        self,
        *,
        headers: Mapping[str, str],
        body: bytes,
    ) -> VerifiedWebhook:
        """Verify webhook signature and return a normalized verification result."""

    async def parse_webhook(self, *, body: bytes) -> ProviderWebhookEvent:
        """Parse a provider webhook payload into a normalized event."""

    async def get_payment_status(self, provider_reference: str) -> ProviderPaymentStatus:
        """Get latest payment status from the provider."""

    async def refund(self, payment: Payment) -> ProviderRefund:
        """Issue a refund via the provider."""

    async def cancel(self, provider_reference: str) -> None:
        """Cancel a payment at the provider."""

