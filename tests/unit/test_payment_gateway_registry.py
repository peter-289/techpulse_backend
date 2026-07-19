from __future__ import annotations

import pytest
from types import SimpleNamespace
from typing import Mapping

from app.modules.billing.payment_gateway_registry import (
    DuplicateGatewayRegistrationError,
    InvalidGatewayConfigurationError,
    PaymentGatewayRegistry,
    UnsupportedPaymentProviderError,
)
from app.modules.shared.enums import PaymentProvider


class StubGateway:
    async def create_checkout(self, payment):
        del payment
        return SimpleNamespace(provider_reference="id", url="https://example.com")

    async def verify_webhook(self, *, headers, body):
        del headers, body
        return SimpleNamespace(provider_reference="id", event_type="checkout.session.completed")

    async def parse_webhook(self, *, body):
        del body
        return SimpleNamespace(provider_reference="id", event_type="checkout.session.completed")

    async def get_payment_status(self, provider_reference: str):
        del provider_reference
        return SimpleNamespace(provider_reference="id", status="completed")

    async def refund(self, payment, *, amount_cents=None):
        del payment, amount_cents
        return SimpleNamespace(provider_reference="id", status="refunded")

    async def cancel(self, provider_reference: str) -> None:
        del provider_reference


    async def verify_and_parse(self, *, headers, body):
        del headers, body
        return SimpleNamespace(
            provider_reference="id",
            event_type="checkout.session.completed",
            outcome="completed",
        )


def test_registry_resolves_registered_gateway() -> None:
    gateway = StubGateway()
    registry = PaymentGatewayRegistry(
        gateways={PaymentProvider.STRIPE: gateway},
    )

    resolved = registry.resolve(PaymentProvider.STRIPE)

    assert resolved is gateway
    assert registry.supports(PaymentProvider.STRIPE)
    assert registry.providers == frozenset({PaymentProvider.STRIPE})


def test_registry_raises_for_unsupported_provider() -> None:
    registry = PaymentGatewayRegistry(
        gateways={PaymentProvider.STRIPE: StubGateway()},
    )

    with pytest.raises(UnsupportedPaymentProviderError) as exc_info:
        registry.resolve(PaymentProvider.PAYPAL)

    assert "PAYPAL" in str(exc_info.value)
    assert "STRIPE" in str(exc_info.value)


def test_registry_rejects_empty_configuration() -> None:
    with pytest.raises(InvalidGatewayConfigurationError):
        PaymentGatewayRegistry(gateways={})


def test_registry_rejects_null_gateway_values() -> None:
    with pytest.raises(InvalidGatewayConfigurationError):
        PaymentGatewayRegistry(gateways={PaymentProvider.STRIPE: None})


class DuplicateProviderMapping(Mapping[PaymentProvider, object]):
    def __init__(self, provider, gateway):
        self._provider = provider
        self._gateway = gateway

    def __iter__(self):
        yield self._provider
        yield self._provider

    def __len__(self):
        return 2

    def __getitem__(self, item):
        if item == self._provider:
            return self._gateway
        raise KeyError(item)


def test_registry_rejects_duplicate_provider_registration() -> None:
    gateway = StubGateway()
    duplicate_mapping = DuplicateProviderMapping(PaymentProvider.STRIPE, gateway)

    with pytest.raises(DuplicateGatewayRegistrationError):
        PaymentGatewayRegistry(gateways=duplicate_mapping)


def test_registry_providers_are_immutable() -> None:
    registry = PaymentGatewayRegistry(
        gateways={PaymentProvider.STRIPE: StubGateway()},
    )

    with pytest.raises(AttributeError):
        registry.providers.add(PaymentProvider.PAYPAL)
