from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping

from app.modules.billing.domain.payment_model import Payment
from app.modules.billing.payment_provider_gateway import (
    InvalidWebhookSignatureError,
    PaymentGatewayUnavailableError,
    PaymentProviderGatewayError,
    ProviderCheckoutSession,
    ProviderPaymentStatus,
    ProviderRefund,
    ProviderWebhookEvent,
    PaymentProviderGateway,
    VerifiedWebhook,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StripeSettings:
    """Provider configuration for Stripe integration."""

    api_key: str
    webhook_secret: str
    base_url: str
    timeout_seconds: float = 10.0


class StripeGateway(PaymentProviderGateway):
    """Infrastructure adapter for Stripe.

    This file intentionally contains a skeleton implementation.
    Concrete HTTP/SDK calls should be implemented behind the same interface.

    Security notes:
    - Never log API keys/secrets.
    - Never return raw provider payloads.
    - Verify webhook signatures before parsing.
    """

    def __init__(self, *, settings: StripeSettings) -> None:
        self._settings = settings

    async def create_checkout(self, payment: Payment) -> ProviderCheckoutSession:
        """Create a hosted checkout session on Stripe.

        Returns:
            ProviderCheckoutSession containing provider reference and redirect URL.
        """
        del payment
        # TODO: Use Stripe SDK / HTTP client to create a hosted checkout session.
        raise PaymentProviderGatewayError("StripeGateway.create_checkout is not implemented.")

    async def verify_webhook(
        self,
        *,
        headers: Mapping[str, str],
        body: bytes,
    ) -> VerifiedWebhook:
        """Verify Stripe webhook signature.

        Raises:
            InvalidWebhookSignatureError: if the signature verification fails.
        """
        del headers
        del body
        # TODO: Verify signature with settings.webhook_secret.
        raise InvalidWebhookSignatureError("Invalid Stripe webhook signature.")

    async def parse_webhook(self, *, body: bytes) -> ProviderWebhookEvent:
        """Parse a verified Stripe webhook into a normalized event DTO."""
        del body
        raise PaymentProviderGatewayError("StripeGateway.parse_webhook is not implemented.")

    async def get_payment_status(self, provider_reference: str) -> ProviderPaymentStatus:
        """Query Stripe for latest payment status."""
        del provider_reference
        raise PaymentProviderGatewayError("StripeGateway.get_payment_status is not implemented.")

    async def refund(self, payment: Payment) -> ProviderRefund:
        """Issue a refund via Stripe."""
        del payment
        raise PaymentProviderGatewayError("StripeGateway.refund is not implemented.")

    async def cancel(self, provider_reference: str) -> None:
        """Cancel a payment via Stripe, if supported."""
        del provider_reference
        raise PaymentProviderGatewayError("StripeGateway.cancel is not implemented.")

