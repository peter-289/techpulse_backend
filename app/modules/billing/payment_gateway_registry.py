from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping

from app.modules.billing.payment_provider_gateway import (
    PaymentProviderGateway,
)
from app.modules.shared.enums import PaymentProvider

logger = logging.getLogger(__name__)


class PaymentGatewayRegistryError(Exception):
    """Base exception for gateway registry configuration/lookup errors."""


class UnsupportedPaymentProviderError(PaymentGatewayRegistryError):
    """Raised when attempting to resolve an unsupported payment provider."""


class DuplicateGatewayRegistrationError(PaymentGatewayRegistryError):
    """Raised when duplicate providers are registered."""


class InvalidGatewayConfigurationError(PaymentGatewayRegistryError):
    """Raised when the registry configuration is invalid."""


@dataclass(frozen=True, slots=True)
class PaymentGatewayRegistry:
    """Resolve `PaymentProviderGateway` implementations by `PaymentProvider`.

    Architectural role:
        - Immutable, constant-time gateway resolution.
        - Provides a single integration entry point for Billing.

    Notes:
        - This registry performs no I/O and never instantiates gateways at runtime.
        - Application services/routers depend only on this class.
    """

    _gateways: Mapping[PaymentProvider, PaymentProviderGateway]

    def __init__(
        self,
        *,
        gateways: Mapping[PaymentProvider, PaymentProviderGateway],
    ) -> None:
        if gateways is None or len(gateways) == 0:
            raise InvalidGatewayConfigurationError("Payment gateway registry cannot be empty.")

        if any(provider is None for provider in gateways.keys()):
            raise InvalidGatewayConfigurationError("Payment gateway registry cannot contain a null provider key.")

        # Copy into a new dict to ensure immutability and to validate at construction time.
        copied: dict[PaymentProvider, PaymentProviderGateway] = {}
        for provider, gateway in gateways.items():
            if provider in copied:
                raise DuplicateGatewayRegistrationError(
                    f"Duplicate gateway registration for provider {provider!r}."
                )
            if gateway is None:
                raise InvalidGatewayConfigurationError(
                    f"Gateway implementation cannot be None for provider {provider!r}."
                )
            copied[provider] = gateway

        # Minimal validation that the objects conform to the port.
        # We avoid importing/instantiating concrete adapters.
        for provider, gateway in copied.items():
            # Duck-type check for required methods.
            required = (
                "create_checkout",
                "verify_webhook",
                "parse_webhook",
                "get_payment_status",
                "refund",
                "cancel",
            )
            missing = [name for name in required if not hasattr(gateway, name)]
            if missing:
                raise InvalidGatewayConfigurationError(
                    f"Gateway for provider {provider!r} is missing methods: {', '.join(missing)}"
                )

        object.__setattr__(self, "_gateways", copied)

        logger.info(
            "PaymentGatewayRegistry initialized with providers=%s",
            sorted([p.value for p in copied.keys()])
            if hasattr(next(iter(copied.keys())), "value")
            else list(copied.keys()),
        )

    def resolve(self, provider: PaymentProvider) -> PaymentProviderGateway:
        """Resolve the gateway registered for `provider`.

        Args:
            provider: The payment provider to resolve.

        Returns:
            The registered `PaymentProviderGateway`.

        Raises:
            UnsupportedPaymentProviderError: If no gateway is registered for `provider`.
        """

        try:
            return self._gateways[provider]
        except KeyError as exc:
            logger.warning("Unsupported provider resolution attempt provider=%s", provider)
            raise UnsupportedPaymentProviderError(
                f"Unsupported payment provider: {provider!r}"
            ) from exc

    def supports(self, provider: PaymentProvider) -> bool:
        """Check whether `provider` is supported by the registry."""

        return provider in self._gateways

    @property
    def providers(self) -> frozenset[PaymentProvider]:
        """Return an immutable view of registered providers."""

        return frozenset(self._gateways.keys())


__all__ = [
    "PaymentGatewayRegistry",
    "PaymentGatewayRegistryError",
    "UnsupportedPaymentProviderError",
    "DuplicateGatewayRegistrationError",
    "InvalidGatewayConfigurationError",
]

