from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from app.core.config import settings


@dataclass(frozen=True, slots=True)
class PaymentIntent:
    provider: str
    provider_reference: str
    status: str
    client_secret: str | None = None
    checkout_url: str | None = None


class PaymentProvider:
    name = "base"

    def create_intent(
        self,
        *,
        payment_id: str,
        amount_cents: int,
        currency: str,
        description: str,
        buyer_id: str,
        owner_id: str,
    ) -> PaymentIntent:
        raise NotImplementedError

    def confirm_intent(self, *, provider_reference: str) -> PaymentIntent:
        raise NotImplementedError


class ManualPaymentProvider(PaymentProvider):
    name = "manual"

    def create_intent(
        self,
        *,
        payment_id: str,
        amount_cents: int,
        currency: str,
        description: str,
        buyer_id: str,
        owner_id: str,
    ) -> PaymentIntent:
        return PaymentIntent(
            provider=self.name,
            provider_reference=f"MANUAL-{payment_id[:8].upper()}-{uuid4().hex[:8].upper()}",
            status="pending",
            client_secret=f"manual_{uuid4().hex}",
        )

    def confirm_intent(self, *, provider_reference: str) -> PaymentIntent:
        return PaymentIntent(
            provider=self.name,
            provider_reference=provider_reference,
            status="completed",
        )


def get_payment_provider() -> PaymentProvider:
    if settings.PAYMENT_PROVIDER == "manual":
        return ManualPaymentProvider()
    raise RuntimeError(f"Unsupported payment provider: {settings.PAYMENT_PROVIDER}")
