"""Composition root for the Billing bounded context.

Centralizes dependency wiring: lazily constructs the payment gateway registry
and exposes FastAPI ``Depends`` factories for repositories, gateways, services,
policies, and the webhook receiver. Keeping wiring here keeps the HTTP adapter
(``api/payment_router.py``) free of construction and bootstrap logic.

Provider adapter construction failures are logged with their concrete exception
type. We never swallow with a bare ``except Exception``; only the specific,
expected adapter-construction failures are caught so a single optional provider
cannot crash bootstrap.
"""

from __future__ import annotations

import logging

from fastapi import Depends

from app.core.config import settings
from app.modules.billing.application.services.checkout_service import CheckoutService
from app.modules.billing.application.services.payment_service import PaymentService
from app.modules.billing.application.services.purchase_service import PurchaseService
from app.modules.billing.infrastructure.gateways.payment_provider_gateway import (
    PaymentProviderGateway,
)
from app.modules.billing.infrastructure.gateways.registry import PaymentGatewayRegistry
from app.modules.billing.infrastructure.webhooks.receiver import WebhookReceiver
from app.modules.shared.dependencies import get_db
from app.modules.shared.enums import PaymentProvider
from app.modules.software_management.policies.software_access_policy import (
    SoftwareAccessPolicy,
)
from app.modules.software_management.software_service import SoftwareService

logger = logging.getLogger(__name__)

# Concrete adapter-construction failures that must not crash bootstrap.
_ADAPTER_CONSTRUCTION_ERRORS = (ImportError, ValueError, TypeError, OSError, RuntimeError)


class PaymentContainer:
    """Lazily-built dependency container for billing.

    Holds the singleton gateway registry; the registry is constructed on first
    access so importing this module is side-effect free (no provider SDK import
    or config validation at import time).
    """

    def __init__(self) -> None:
        self._registry: PaymentGatewayRegistry | None = None

    @property
    def gateway_registry(self) -> PaymentGatewayRegistry:
        if self._registry is None:
            self._registry = build_payment_gateway_registry()
        return self._registry


# Module-level singleton container.
container = PaymentContainer()


def _build_stripe_gateway() -> PaymentProviderGateway | None:
    from app.modules.billing.infrastructure.gateways.stripe_gateway import (
        StripeGateway,
        StripeSettings,
    )

    api_key = getattr(settings, "STRIPE_API_KEY", "") or getattr(
        settings, "PAYMENT_PROVIDER_SECRET_KEY", ""
    )
    webhook_secret = getattr(settings, "STRIPE_WEBHOOK_SECRET", "") or getattr(
        settings, "PAYMENT_WEBHOOK_SECRET", ""
    )
    base_url = getattr(settings, "STRIPE_BASE_URL", "https://api.stripe.com")
    return StripeGateway(
        settings=StripeSettings(api_key=api_key, webhook_secret=webhook_secret, base_url=base_url)
    )


def build_payment_gateway_registry() -> PaymentGatewayRegistry:
    """Construct the payment gateway registry from available provider adapters.

    Only providers that can be constructed from configuration are registered, so
    a missing/optional provider does not crash startup. The registry enforces
    that at least one gateway is registered.
    """
    gateways: dict[PaymentProvider, PaymentProviderGateway] = {}

    try:
        gateway = _build_stripe_gateway()
        if gateway is not None:
            gateways[PaymentProvider.STRIPE] = gateway
    except _ADAPTER_CONSTRUCTION_ERRORS as exc:
        logger.error("Failed to register Stripe payment gateway: %s: %s", type(exc).__name__, exc)

    if not gateways:
        logger.warning(
            "Payment gateway registry built with zero gateways; "
            "webhook and checkout flows will be unavailable until a provider is configured."
        )

    return PaymentGatewayRegistry(gateways=gateways)


# ---------------------------------------------------------------------------
# FastAPI dependency factories
# ---------------------------------------------------------------------------
def get_unit_of_work(session: object = Depends(get_db)) -> "object":
    from app.infrastructure.database.unit_of_work import UnitOfWork

    return UnitOfWork(session=session)


def get_payment_gateway_registry() -> PaymentGatewayRegistry:
    return container.gateway_registry


def get_payment_service(uow: object = Depends(get_unit_of_work)) -> PaymentService:
    return PaymentService(uow)


def get_purchase_service(uow: object = Depends(get_unit_of_work)) -> PurchaseService:
    return PurchaseService(unit_of_work=uow)


def get_software_service(uow: object = Depends(get_unit_of_work)) -> "object":
    from app.modules.software_management.software_service import SoftwareService

    return SoftwareService(unit_of_work=uow)


def get_software_access_policy() -> SoftwareAccessPolicy:
    return SoftwareAccessPolicy()


def get_checkout_service(
    software_service: SoftwareService = Depends(get_software_service),
    payment_service: PaymentService = Depends(get_payment_service),
    purchase_service: PurchaseService = Depends(get_purchase_service),
    payment_gateway_registry: PaymentGatewayRegistry = Depends(get_payment_gateway_registry),
    access_policy: SoftwareAccessPolicy = Depends(get_software_access_policy),
) -> CheckoutService:
    return CheckoutService(
        software_service=software_service,
        payment_service=payment_service,
        purchase_service=purchase_service,
        access_policy=access_policy,
        payment_gateway_registry=payment_gateway_registry,
    )


def get_webhook_receiver(
    payment_gateway_registry: PaymentGatewayRegistry = Depends(get_payment_gateway_registry),
    checkout_service: CheckoutService = Depends(get_checkout_service),
) -> WebhookReceiver:
    return WebhookReceiver(
        registry=payment_gateway_registry,
        checkout_service=checkout_service,
    )


__all__ = [
    "PaymentContainer",
    "container",
    "build_payment_gateway_registry",
    "get_unit_of_work",
    "get_payment_gateway_registry",
    "get_payment_service",
    "get_purchase_service",
    "get_software_service",
    "get_software_access_policy",
    "get_checkout_service",
    "get_webhook_receiver",
]
