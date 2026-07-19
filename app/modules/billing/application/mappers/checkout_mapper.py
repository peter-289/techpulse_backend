from __future__ import annotations

from app.modules.billing.application.read_models.checkout_session import CheckoutSession
from app.modules.billing.api.schemas.payment_schema import CheckoutSessionRead


class CheckoutMapper:
    """Maps the checkout read model to its API DTO.

    Pure, side-effect-free transformation. No business logic.
    """

    @staticmethod
    def to_checkout_session_read(session: CheckoutSession) -> CheckoutSessionRead:
        return CheckoutSessionRead(
            id=session.id,
            software_id=session.software_id,
            buyer_id=session.buyer_id,
            owner_id=session.owner_id,
            amount_cents=session.amount.amount_cents,
            currency=str(session.amount.currency),
            provider=session.provider,
            status=session.status,
            created_at=session.created_at,
            completed_at=session.completed_at,
            provider_reference=session.provider_reference,
            client_secret=session.client_secret,
            checkout_url=session.checkout_url,
            expires_at=session.expires_at,
        )


__all__ = ["CheckoutMapper"]
