from __future__ import annotations

from app.modules.billing.domain.payment import Payment
from app.exceptions.exceptions import PurchaseDomainError


class RefundPolicy:
    """Stateless domain policy governing refund eligibility.

    Encapsulates the rules a refund must satisfy. It consults the
    ``Payment`` aggregate for state-dependent checks but holds no data.
    """

    @staticmethod
    def ensure_can_refund(payment: Payment, *, amount_cents: int | None = None) -> None:
        if not payment.can_be_refunded:
            raise PurchaseDomainError("Payment cannot be refunded in its current state.")
        if amount_cents is not None and amount_cents < 0:
            raise PurchaseDomainError("Refund amount cannot be negative.")


class PurchasePolicy:
    """Stateless domain policy governing purchase grants from payments."""

    @staticmethod
    def ensure_can_grant_from_payment(payment: Payment) -> None:
        if not payment.is_successful:
            raise PurchaseDomainError("Cannot grant a purchase for an unsuccessful payment.")


__all__ = ["RefundPolicy", "PurchasePolicy"]
