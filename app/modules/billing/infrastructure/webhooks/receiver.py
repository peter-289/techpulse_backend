"""Webhook receiver: verifies, parses, and dispatches provider webhooks.

This component lives in the infrastructure layer and is the single place that
turns a raw provider callback into a domain side effect. Routers must not
process webhooks themselves; they delegate to this receiver.
"""

from __future__ import annotations

import logging
from typing import Mapping

from app.modules.billing.application.services.checkout_service import CheckoutService
from app.modules.billing.infrastructure.gateways.registry import PaymentGatewayRegistry
from app.modules.billing.infrastructure.webhooks.models import WebhookOutcome
from app.modules.shared.enums import PaymentProvider

logger = logging.getLogger(__name__)


class WebhookReceiver:
    """Receives, verifies, normalizes, and applies provider webhooks.

    Idempotency is guaranteed by the downstream services
    (``CheckoutService.complete_checkout_by_provider_reference`` delegates to
    idempotent confirm/grant steps), so repeated provider retries are safe.
    """

    def __init__(
        self,
        *,
        registry: PaymentGatewayRegistry,
        checkout_service: CheckoutService,
    ) -> None:
        self._registry = registry
        self._checkout_service = checkout_service

    async def receive(
        self,
        *,
        provider: PaymentProvider,
        headers: Mapping[str, str],
        body: bytes,
    ) -> WebhookOutcome:
        """Process a raw webhook and return its normalized outcome.

        Raises:
            PaymentProviderGatewayError: propagated from the gateway on signature
                or payload failures (caller maps to HTTP 400).
            UnsupportedPaymentProviderError: if the provider is not registered.
        """
        gateway = self._registry.resolve(provider)
        event = await gateway.verify_and_parse(headers=headers, body=body)

        if event.outcome is WebhookOutcome.COMPLETED:
            await self._checkout_service.complete_checkout_by_provider_reference(
                provider_reference=event.provider_reference
            )
        elif event.outcome is WebhookOutcome.FAILED:
            logger.warning(
                "Payment provider reported failure provider=%s reference=%s event=%s",
                provider,
                event.provider_reference,
                event.event_type,
            )
        else:
            logger.info(
                "Ignored webhook event provider=%s event=%s",
                provider,
                event.event_type,
            )

        return event.outcome


__all__ = ["WebhookReceiver"]
