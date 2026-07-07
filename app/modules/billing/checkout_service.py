from __future__ import annotations

import logging
from uuid import UUID

from typing import TYPE_CHECKING

from app.modules.billing.domain.payment_model import Payment
from app.modules.billing.domain.value_objects import CheckoutSession, Currency, Money, PaymentSubject
from app.modules.billing.payment_service import CreatePaymentCommand, PaymentService
from app.modules.shared.enums import PaymentProvider, PaymentResourceType
from app.modules.software_management.policies.software_access_policy import SoftwareAccessPolicy
from app.modules.billing.purchase_service import PurchaseService

if TYPE_CHECKING:
    from app.modules.software_management.software.software import Software
    from app.modules.software_management.software_service import SoftwareService

logger = logging.getLogger(__name__)


class CheckoutService:
    """Application service that initiates a software checkout.

    This service is responsible for orchestrating the checkout use case while
    delegating business rules to the appropriate domain policy and application
    services. It does not own purchase eligibility rules, payment domain rules,
    or persistence concerns.
    """

    def __init__(
        self,
        *,
        software_service: SoftwareService,
        payment_service: PaymentService,
        purchase_service: PurchaseService,
        access_policy: SoftwareAccessPolicy,
    ) -> None:


        self._software_service = software_service
        self._payment_service = payment_service
        self._purchase_service = purchase_service
        self._access_policy = access_policy

    async def create_checkout(
        self,
        *,
        software_id: UUID,
        buyer_id: UUID,
        provider: PaymentProvider,
    ) -> CheckoutSession:
        """Create a checkout session for a software purchase.

        Args:
            software_id: The software aggregate identifier to purchase.
            buyer_id: The buyer attempting to purchase the software.
            provider: The payment provider selected for checkout.

        Returns:
            A fully populated checkout session read model for the frontend.

        Raises:
            SoftwareNotFoundError: If the software aggregate cannot be found.
            OwnerCannotPurchaseError: If the buyer is the software owner.
            DuplicatePurchaseError: If the buyer already owns the software.
            SoftwareAccessDeniedError: If the software is not purchasable.
            RepositoryUnavailableError: If persistence fails.
        """
        software = await self._load_software(software_id=software_id)
        
        await self._ensure_checkout_allowed(
            software=software,
            buyer_id=buyer_id,
        )

        subject = self._create_payment_subject(software=software)
        payment = await self._create_payment(
            buyer_id=buyer_id,
            subject=subject,
            provider=provider,
            software=software,
        )
        checkout_url, client_secret = await self._start_provider_checkout(
            payment=payment,
            provider=provider,
        )

        logger.info(
            "Created checkout for buyer %s and software %s provider %s payment_id %s",
            buyer_id,
            software_id,
            provider,
            payment.id,
        )
        return CheckoutSession.from_payment(
            payment=payment,
            software_id=software.id,
            owner_id=software.owner_id,
            provider=provider,
            checkout_url=checkout_url,
            client_secret=client_secret,
        )

    async def complete_checkout(
        self,
        *,
        payment_id: UUID,
    ) -> None:
        """Complete a checkout after a successful payment.

        This application service is invoked only after the infrastructure layer
        has authenticated and validated the payment provider callback.

        Workflow (orchestration only; no business rules in this service):
            1) Load the payment aggregate via PaymentService.
            2) Mark the payment as succeeded via PaymentService.
            3) Grant software ownership via PurchaseService.
            4) Log successful completion.

        Idempotency:
            Repeated webhook deliveries must not create duplicate purchases.
            PurchaseService.grant_purchase() is responsible for idempotency.

        Transaction boundaries:
            The Unit of Work provided to collaborating services owns commits/
            rollbacks. This method performs no manual transaction handling.

        Args:
            payment_id: Trusted internal payment identifier (provider payload
                has already been verified by the webhook infrastructure).

        Raises:
            PaymentNotFoundError: If the payment does not exist.
            InvalidPaymentStateTransitionError: If payment cannot transition
                to the successful state.
            DuplicatePurchaseError: If purchase creation violates domain
                invariants (PurchaseService is expected to guard idempotency).
            RepositoryUnavailableError: If persistence fails.
        """
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

        return None

    async def cancel_checkout(self) -> None:
        """Placeholder for future checkout cancellation workflow."""
        raise NotImplementedError






    # === HELPERS ===
    async def _load_software(self, *, software_id: UUID) -> Software:
        """Load the software aggregate from the application service."""
        return await self._software_service.get(software_id)

    async def _ensure_checkout_allowed(
        self,
        *,
        software: object,
        buyer_id: UUID,
    ) -> None:
        """Delegate purchase eligibility checks to the domain policy."""
        has_purchase = await self._purchase_service.has_purchase(
            software_id=software.id,
            buyer_id=buyer_id,
        )
        self._access_policy.ensure_can_purchase(
            software=software,
            buyer_id=buyer_id,
            has_purchase=has_purchase,
        )

    def _create_payment_subject(self, *, software: Software) -> PaymentSubject:
        """Create the payment subject for the software purchase."""
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
        software: Software,
    ) -> Payment:
        """Create the payment aggregate using the billing application service."""
        amount = Money(
            amount_cents=software.price_cents,
            currency=Currency(code=software.currency or "USD"),
        )

        command = CreatePaymentCommand(
            buyer_id=buyer_id,
            subject=subject,
            amount=amount,
            provider=provider,
        )
        return await self._payment_service.create(command)

    async def _start_provider_checkout(self, *, payment: Payment, provider: PaymentProvider) -> tuple[str | None, str | None]:
        """Start the provider-specific checkout flow.

        The current implementation keeps the orchestration side-effect free and
        returns the provider metadata expected by the caller. Concrete provider
        integrations can be added here without changing the application service
        contract.
        """
        del payment
        del provider
        return None, None