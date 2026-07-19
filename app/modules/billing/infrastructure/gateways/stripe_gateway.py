"""Stripe infrastructure adapter.

Implements the :class:`PaymentProviderGateway` port. It must never leak Stripe
SDK types: every return value is a normalized DTO, and every provider-specific
event string is classified into a :class:`WebhookOutcome` before it leaves the
adapter.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Mapping

from app.modules.billing.domain.payment import Payment
from app.modules.billing.infrastructure.gateways.payment_provider_gateway import (
    ProviderCheckoutSession,
    ProviderPaymentStatus,
    ProviderRefund,
    VerifiedWebhook,
)
from app.exceptions.exceptions import (
    InvalidWebhookSignatureError,
    PaymentProviderGatewayError,        
)

from app.modules.billing.infrastructure.webhooks.models import (
    ProviderWebhookEvent,
    WebhookOutcome,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StripeSettings:
    """Provider configuration for Stripe integration."""

    api_key: str
    webhook_secret: str
    base_url: str
    timeout_seconds: float = 10.0


class StripeGateway:
    """Infrastructure adapter for Stripe.

    Security notes:
    - Never log API keys/secrets.
    - Never return raw provider payloads.
    - Verify webhook signatures before parsing.
    """

    def __init__(self, *, settings: StripeSettings) -> None:
        self._settings = settings

    async def create_checkout(self, payment: Payment) -> ProviderCheckoutSession:
        del payment
        # TODO: Use Stripe SDK / HTTP client to create a hosted checkout session.
        raise PaymentProviderGatewayError("StripeGateway.create_checkout is not implemented.")

    async def verify_webhook(self, *, headers: Mapping[str, str], body: bytes) -> VerifiedWebhook:
        del headers
        del body
        # TODO: Verify signature with settings.webhook_secret.
        raise InvalidWebhookSignatureError("Invalid Stripe webhook signature.")

    async def parse_webhook(self, *, body: bytes) -> ProviderWebhookEvent:
        """Parse a verified Stripe webhook into a normalized event with outcome."""
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError as exc:
            raise PaymentProviderGatewayError("Malformed Stripe webhook payload.") from exc

        event_type = str(payload.get("type", ""))
        object_data = payload.get("data", {}).get("object", {})
        reference = str(object_data.get("id") or payload.get("id") or "")
        return ProviderWebhookEvent(
            provider_reference=reference,
            outcome=self._classify_event(event_type),
            event_type=event_type,
        )

    async def verify_and_parse(
        self, *, headers: Mapping[str, str], body: bytes
    ) -> ProviderWebhookEvent:
        """Verify the signature and parse in one pass, returning a classified event."""
        await self.verify_webhook(headers=headers, body=body)
        return await self.parse_webhook(body=body)

    async def get_payment_status(self, provider_reference: str) -> ProviderPaymentStatus:
        del provider_reference
        raise PaymentProviderGatewayError("StripeGateway.get_payment_status is not implemented.")

    async def refund(self, payment: Payment) -> ProviderRefund:
        del payment
        raise PaymentProviderGatewayError("StripeGateway.refund is not implemented.")

    async def cancel(self, provider_reference: str) -> None:
        del provider_reference
        raise PaymentProviderGatewayError("StripeGateway.cancel is not implemented.")

    @staticmethod
    def _classify_event(event_type: str) -> WebhookOutcome:
        """Map a Stripe event type string onto a canonical :class:`WebhookOutcome`."""
        et = (event_type or "").lower()
        if any(token in et for token in ("succeed", "complete", "paid", "captured", "fulfill")):
            return WebhookOutcome.COMPLETED
        if any(token in et for token in ("fail", "cancel", "expire", "refund", "void")):
            return WebhookOutcome.FAILED
        return WebhookOutcome.IGNORED


__all__ = ["StripeGateway", "StripeSettings"]
