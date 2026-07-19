"""Immutable, singleton payment gateway registry.

Resolves concrete gateway adapters by :class:`PaymentProvider`. Performs startup
validation and constant-time lookup. Application services depend only on this
façade; they never import concrete gateways.
"""

from __future__ import annotations

import logging
from types import MappingProxyType
from typing import Mapping

from app.modules.billing.infrastructure.gateways.payment_provider_gateway import (
    PaymentProviderGateway,
)
from app.modules.shared.enums import PaymentProvider
from app.exceptions.exceptions import (
    DuplicateGatewayRegistrationError,
    InvalidGatewayConfigurationError,
    UnsupportedPaymentProviderError,
)

logger = logging.getLogger(__name__)




class PaymentGatewayRegistry:
    """Canonical resolver for registered payment provider gateway adapters.

    Immutable and thread-safe once constructed. Application services depend
    only on this façade and call :meth:`resolve`.
    """

    __slots__ = ("_gateways", "_providers", "_provider_names")

    def __init__(self, *, gateways: Mapping[PaymentProvider, PaymentProviderGateway]) -> None:
        self._validate_gateways_mapping(gateways)
        copied_gateways = self._copy_gateways(gateways)
        self._validate_gateway_implementations(copied_gateways)
        self._gateways = MappingProxyType(copied_gateways)
        self._providers = frozenset(copied_gateways.keys())
        self._provider_names = self._build_supported_provider_names(self._providers)
        self._log_registered_providers()

    def resolve(self, provider: PaymentProvider) -> PaymentProviderGateway:
        if provider is None:
            raise InvalidGatewayConfigurationError("Provider cannot be None.")
        try:
            return self._gateways[provider]
        except KeyError as exc:
            logger.warning("Unsupported payment provider lookup provider=%s", provider)
            raise UnsupportedPaymentProviderError(
                "Unsupported payment provider %r.\nRegistered providers:\n%s"
                % (provider, self._provider_names)
            ) from exc

    def supports(self, provider: PaymentProvider) -> bool:
        return provider in self._gateways

    @property
    def providers(self) -> frozenset[PaymentProvider]:
        return self._providers

    def _validate_gateways_mapping(self, gateways: Mapping[PaymentProvider, PaymentProviderGateway]) -> None:
        if gateways is None:
            raise InvalidGatewayConfigurationError("Payment gateway registry configuration cannot be None.")
        if len(gateways) == 0:
            raise InvalidGatewayConfigurationError("Payment gateway registry must contain at least one gateway.")
        if any(provider is None for provider in gateways):
            raise InvalidGatewayConfigurationError("Payment gateway registry cannot contain None as a provider key.")
        if any(gateway is None for gateway in gateways.values()):
            raise InvalidGatewayConfigurationError(
                "Payment gateway registry cannot contain None gateway implementations."
            )

    def _copy_gateways(
        self, gateways: Mapping[PaymentProvider, PaymentProviderGateway]
    ) -> dict[PaymentProvider, PaymentProviderGateway]:
        copied: dict[PaymentProvider, PaymentProviderGateway] = {}
        for provider, gateway in gateways.items():
            if provider in copied:
                raise DuplicateGatewayRegistrationError(
                    f"Duplicate gateway registration for provider {provider!r}."
                )
            copied[provider] = gateway
        return copied

    def _validate_gateway_implementations(
        self, gateways: Mapping[PaymentProvider, PaymentProviderGateway]
    ) -> None:
        for provider, gateway in gateways.items():
            if not isinstance(gateway, PaymentProviderGateway):
                raise InvalidGatewayConfigurationError(
                    "Gateway for provider %r does not implement PaymentProviderGateway." % provider
                )

    def _build_supported_provider_names(self, providers: frozenset[PaymentProvider]) -> str:
        names = sorted(provider.name for provider in providers)
        return "\n".join(f"- {name}" for name in names)

    def _log_registered_providers(self) -> None:
        logger.info(
            "PaymentGatewayRegistry initialized with providers=%s",
            [provider.name for provider in self._providers],
        )


__all__ = [
    "PaymentGatewayRegistry",
    "PaymentGatewayRegistryError",
    "InvalidGatewayConfigurationError",
    "DuplicateGatewayRegistrationError",
    "UnsupportedPaymentProviderError",
]
