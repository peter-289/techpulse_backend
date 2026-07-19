from __future__ import annotations

from app.modules.billing.domain.purchase import Purchase
from app.modules.billing.domain.value_objects import PurchaseHistoryCard, PurchaseHistoryPage
from app.modules.billing.api.schemas.purchase_schema import PurchaseResponse
from app.modules.shared.pagination import OffsetPage


class PurchaseMapper:
    """Maps purchase domain objects and read models to API DTOs.

    Pure, side-effect-free transformations. No business logic.
    """

    @staticmethod
    def to_purchase_response(purchase: Purchase) -> PurchaseResponse:
        return PurchaseResponse.model_validate(purchase)

    @staticmethod
    def to_history_page(
        cards: list[PurchaseHistoryCard],
        *,
        total: int,
        limit: int,
        offset: int,
    ) -> PurchaseHistoryPage:
        return PurchaseHistoryPage(items=cards, total=total, limit=limit, offset=offset)

    @staticmethod
    def to_owned_page(
        cards: list[object],
        *,
        total: int,
        limit: int,
        offset: int,
    ) -> OffsetPage:
        items = [
            PurchaseResponse(
                purchase_id=card.purchase_id,
                software_id=card.software_id,
                software_name=card.software_name,
                amount_cents=card.amount.amount_cents,
                currency=card.amount.currency.code if hasattr(card.amount, "currency") else card.currency,
                status=card.status,
                purchased_at=card.purchased_at,
                refunded_at=card.refunded_at,
                revoked_at=card.revoked_at,
                last_activity_at=card.last_activity_at,
            )
            for card in cards
        ]
        has_next = offset + limit < total
        has_prev = offset > 0
        return OffsetPage(items=items, total=total, limit=limit, offset=offset, has_next=has_next, has_prev=has_prev)


__all__ = ["PurchaseMapper", "PurchaseHistoryQuery"]
