"""M-Pesa infrastructure adapter (placeholder).

Implements the :class:`PaymentProviderGateway` port. Once the provider SDK is
wired, it must classify its event strings into :class:`WebhookOutcome` exactly
like :class:`StripeGateway`.
"""

from __future__ import annotations

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
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class MpesaSettings:
    api_key: str
    webhook_secret: str
    base_url: str
    timeout_seconds: float = 10.0


class MpesaGateway:
    """Infrastructure adapter for M-Pesa."""

    def __init__(self, *, settings: MpesaSettings) -> None:
        self._settings = settings

    async def create_checkout(self, payment: Payment) -> ProviderCheckoutSession:
        del payment
        raise PaymentProviderGatewayError("MpesaGateway.create_checkout is not implemented.")

    async def verify_webhook(self, *, headers: Mapping[str, str], body: bytes) -> VerifiedWebhook:
        del headers
        del body
        raise InvalidWebhookSignatureError("Invalid M-Pesa webhook signature.")

    async def parse_webhook(self, *, body: bytes) -> ProviderWebhookEvent:
        del body
        raise PaymentProviderGatewayError("MpesaGateway.parse_webhook is not implemented.")

    async def verify_and_parse(self, *, headers: Mapping[str, str], body: bytes) -> ProviderWebhookEvent:
        await self.verify_webhook(headers=headers, body=body)
        return await self.parse_webhook(body=body)

    async def get_payment_status(self, provider_reference: str) -> ProviderPaymentStatus:
        del provider_reference
        raise PaymentProviderGatewayError("MpesaGateway.get_payment_status is not implemented.")

    async def refund(self, payment: Payment) -> ProviderRefund:
        del payment
        raise PaymentProviderGatewayError("MpesaGateway.refund is not implemented.")

    async def cancel(self, provider_reference: str) -> None:
        del provider_reference
        raise PaymentProviderGatewayError("MpesaGateway.cancel is not implemented.")


__all__ = ["MpesaGateway", "MpesaSettings"]
