from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.billing.purchase_service import PurchaseService
from app.modules.shared.dependencies import get_current_user, get_db, CurrentUser
from app.modules.shared.pagination import OffsetPage
from app.modules.billing.domain.value_objects import PurchaseHistoryPage, PurchaseHistoryQuery

from .purchase_schema import PurchaseResponse

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/purchases",
    tags=["Purchases"],
)


def get_service(session: AsyncSession = Depends(get_db)) -> PurchaseService:
    uow = UnitOfWork(session=session)
    return PurchaseService(unit_of_work=uow)


@router.get(
    "",
    response_model=OffsetPage[PurchaseResponse],
    summary="Get authenticated user's owned software library",
    description="Returns the authenticated user's owned software library with offset-based pagination.",
    status_code=200,
)
async def get_purchases(
    service: PurchaseService = Depends(get_service),
    current_user: CurrentUser = Depends(get_current_user),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> OffsetPage[PurchaseResponse]:
    """Return the authenticated user's owned software library."""

    
    
    buyer_id = current_user.user_id
    owned_cards, total = await service.list_owned(
       buyer_id,
        limit=limit,
        offset=offset,
    )

    items = [
        PurchaseResponse(
            purchase_id=card.purchase_id,
            software_id=card.software_id,
            software_name=card.software_name,
            amount_cents=card.amount_cents,
            currency=card.currency,
            status=card.status,
            purchased_at=card.purchased_at,
            refunded_at=card.refunded_at,
            revoked_at=card.revoked_at,
            last_activity_at=card.last_activity_at,
        )
        for card in owned_cards
    ]

    logger.info(
        "Purchased library fetched successfully",
        extra={
            "authenticated_user_id": str(buyer_id),
            "returned_item_count": len(items),
            "total_records": total,
            "limit": limit,
            "offset": offset,
        },
    )

    has_next = offset + limit < total
    has_prev = offset > 0

    return OffsetPage(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_next=has_next,
        has_prev=has_prev,
    )


# === Get purchase history ===
@router.get(
    "/history",
    response_model=PurchaseHistoryPage,
    summary="Get purchase history",
)
async def get_purchase_history(
    query: PurchaseHistoryQuery = Depends(),
    current_user: CurrentUser = Depends(get_current_user),
    service: PurchaseService = Depends(get_service),
):
    items, total = await service.list_purchase_history(
        buyer_id=current_user.user_id,
        limit=query.limit,
        offset=query.offset,
    )

    logger.info("Fetched purchases successfuly.")

    return PurchaseHistoryPage(
        items=items,
        total=total,
        limit=query.limit,
        offset=query.offset,
    )


# === Get Purchase by id ===
@router.get(
    "/{purchase_id}",
    response_model=PurchaseResponse,
    status_code=status.HTTP_200_OK,
    summary="Get purchase details",
)
async def get_purchase(
    purchase_id: UUID = Path(...),
    current_user: CurrentUser = Depends(get_current_user),
    service: PurchaseService = Depends(get_service),
) -> PurchaseResponse:
    """
    Return a purchase belonging to the authenticated user.
    """

    purchase = await service.get_purchase(
        purchase_id=purchase_id,
    )

    return PurchaseResponse.model_validate(purchase)