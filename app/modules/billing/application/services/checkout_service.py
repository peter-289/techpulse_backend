from __future__ import annotations

import logging
from uuid import UUID

from typing import TYPE_CHECKING

from app.modules.billing.application.mappers.checkout_mapper import CheckoutMapper
from app.modules.billing.application.read_models.checkout_session import CheckoutSession
from app.modules.billing.application.services.payment_service import (
    CreatePaymentCommand,
    PaymentService,
)
from app.modules.billing.application.services.purchase_service import PurchaseService
from app.modules.billing.domain.payment import Payment
from app.modules.billing.domain.value_objects import Currency, Money, PaymentSubject
from app.exceptions.exceptions import PaymentProviderGatewayError
from app.modules.billing.infrastructure.gateways.registry import PaymentGatewayRegistry
from app.modules.billing.api.schemas.payment_schema import CheckoutSessionRead
from app.modules.shared.enums import PaymentProvider, PaymentResourceType
from app.modules.software_management.policies.software_access_policy import SoftwareAccessPolicy

if TYPE_CHECKING:
    from app.modules.software_management.software.software import Software
    from app.modules.software_management.software_service import SoftwareService

logger = logging.getLogger(__name__)


class CheckoutService:
    """Application orchestrator for initiating a software checkout.

    Coordinates the software service, payment service, purchase service, the
    access policy, and the payment gateway registry. Contains no business
    rules of its own; it delegates domain decisions to the appropriate
    policy/aggregate and persistence to the Unit of Work.
    """

    def __init__(
        self,
        *,
        software_service: "SoftwareService",
        payment_service: PaymentService,
        purchase_service: PurchaseService,
        access_policy: SoftwareAccessPolicy,
        payment_gateway_registry: PaymentGatewayRegistry,
    ) -> None:
        self._software_service = software_service
        self._payment_service = payment_service
        self._purchase_service = purchase_service
        self._access_policy = access_policy
        self._payment_gateway_registry = payment_gateway_registry

    async def create_checkout(
        self,
        *,
        software_id: UUID,
        buyer_id: UUID,
        provider: PaymentProvider,
    ) -> CheckoutSessionRead:
        """Create a checkout session for a software purchase."""
        software = await self._load_software(software_id=software_id)
        await self._ensure_checkout_allowed(software=software, buyer_id=buyer_id)

        subject = self._create_payment_subject(software=software)
        payment = await self._create_payment(
            buyer_id=buyer_id, subject=subject, provider=provider, software=software
        )
        checkout_url, client_secret, provider_reference = await self._start_provider_checkout(
            payment=payment, provider=provider
        )

        if provider_reference:
            payment = await self._payment_service.attach_provider_reference(
                payment_id=payment.id, provider_reference=provider_reference
            )

        logger.info(
            "Created checkout for buyer %s and software %s provider %s payment_id %s",
            buyer_id,
            software_id,
            provider,
            payment.id,
        )
        session = CheckoutSession.from_payment(
            payment=payment,
            software_id=software.id,
            owner_id=software.owner_id,
            provider=provider,
            checkout_url=checkout_url,
            client_secret=client_secret,
        )
        return CheckoutMapper.to_checkout_session_read(session)

    async def complete_checkout(self, *, payment_id: UUID) -> None:
        """Complete a checkout after a successful payment (internal call)."""
        payment = await self._payment_service.get(payment_id=payment_id)
        buyer_id = payment.buyer_id
        payment = await self._payment_service.complete(payment_id=payment_id)
        await self._purchase_service.grant_purchase(payment)

        logger.info(
            "Checkout completed: payment=%s buyer=%s software=%s",
            payment.id,
            buyer_id,
            payment.subject.resource_id,
        )

    async def complete_checkout_by_provider_reference(self, *, provider_reference: str) -> None:
        """Complete a checkout from a verified provider webhook event."""
        payment = await self._payment_service.confirm_by_provider_reference(
            provider_reference=provider_reference
        )
        await self._purchase_service.grant_purchase(payment)

        logger.info(
            "Webhook checkout completed: payment=%s buyer=%s software=%s",
            payment.id,
            payment.buyer_id,
            payment.subject.resource_id,
        )

    async def cancel_checkout(self) -> None:
        raise NotImplementedError

    # === HELPERS ===
    async def _load_software(self, *, software_id: UUID) -> "Software":
        return await self._software_service.get(software_id)

    async def _ensure_checkout_allowed(self, *, software: object, buyer_id: UUID) -> None:
        has_purchase = await self._purchase_service.has_purchase(
            software_id=software.id, buyer_id=buyer_id
        )
        self._access_policy.ensure_can_purchase(
            software=software, buyer_id=buyer_id, has_purchase=has_purchase
        )

    def _create_payment_subject(self, *, software: "Software") -> PaymentSubject:
        return PaymentSubject(
            resource_type=PaymentResourceType.SOFTWARE,
            resource_id=software.id,
        )

    async def _create_payment(
        self,
        *,
        buyer_id: UUID,
        subject: PaymentSubject,
        provider: PaymentProvider,
        software: "Software",
    ) -> Payment:
        amount = Money(
            amount_cents=software.price_cents,
            currency=Currency(code=software.currency or "USD"),
        )
        command = CreatePaymentCommand(
            buyer_id=buyer_id, subject=subject, amount=amount, provider=provider
        )
        return await self._payment_service.create(command)

    async def _start_provider_checkout(
        self, *, payment: Payment, provider: PaymentProvider
    ) -> tuple[str | None, str | None, str | None]:
        gateway = self._payment_gateway_registry.resolve(provider)
        try:
            session = await gateway.create_checkout(payment)
        except PaymentProviderGatewayError:
            logger.exception("Provider checkout failed provider=%s payment=%s", provider, payment.id)
            raise
        return session.checkout_url, session.client_secret, session.provider_reference


__all__ = ["CheckoutService"]
