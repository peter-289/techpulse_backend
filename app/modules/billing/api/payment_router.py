"""HTTP adapter for the Billing payments API.

This router contains ONLY HTTP concerns: routing, status codes, auth
dependencies, DTO binding, and delegation to application services. It contains
no business logic, no response mapping, no registry construction, no webhook
event classification, and no authorization rules.
"""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status

from app.modules.billing.api.schemas.payment_schema import (
    CheckoutSessionRead,
    CreateCheckoutRequest,
    PaymentRead,
    PaymentSummaryRead,
)
from app.modules.billing.application.services.checkout_service import CheckoutService
from app.modules.billing.application.services.payment_service import PaymentService
from app.modules.billing.domain.exceptions import PaymentAccessDenied
from app.modules.billing.infrastructure.container import (
    get_checkout_service,
    get_payment_service,
    get_webhook_receiver,
)
from app.exceptions.exceptions import (
    InvalidWebhookSignatureError,
    PaymentProviderGatewayError,
)
from app.modules.billing.infrastructure.gateways.registry import PaymentGatewayRegistry
from app.modules.billing.infrastructure.webhooks.receiver import WebhookReceiver
from app.modules.shared.dependencies import CurrentUser, get_current_user
from app.modules.shared.enums import PaymentProvider
from app.modules.shared.pagination import OffsetPage

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/payments",
    tags=["Payments"],
)


@router.post(
    "/checkout",
    response_model=CheckoutSessionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Start a software checkout",
)
async def create_checkout(
    payload: CreateCheckoutRequest,
    checkout_service: CheckoutService = Depends(get_checkout_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> CheckoutSessionRead:
    """Initiate a checkout for a software purchase with the chosen provider."""
    return await checkout_service.create_checkout(
        software_id=payload.software_id,
        buyer_id=current_user.user_id,
        provider=payload.provider,
    )


@router.get(
    "",
    response_model=OffsetPage[PaymentSummaryRead],
    summary="List the authenticated user's payments",
)
async def list_payments(
    service: PaymentService = Depends(get_payment_service),
    current_user: CurrentUser = Depends(get_current_user),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> OffsetPage[PaymentSummaryRead]:
    """Return a paginated list of payments initiated by the current user."""
    summaries, total = await service.list_for_buyer(
        buyer_id=current_user.user_id,
        limit=limit,
        offset=offset,
    )
    has_next = offset + limit < total
    has_prev = offset > 0
    return OffsetPage(
        items=summaries,
        total=total,
        limit=limit,
        offset=offset,
        has_next=has_next,
        has_prev=has_prev,
    )


@router.get(
    "/{payment_id}",
    response_model=PaymentRead,
    summary="Get a single payment",
)
async def get_payment(
    payment_id: UUID = Path(...),
    service: PaymentService = Depends(get_payment_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> PaymentRead:
    """Return a payment owned by the current user.

    Authorization is enforced by the service layer; the router only translates
    the resulting domain exception into an HTTP response.
    """
    try:
        return await service.get_for_buyer(payment_id=payment_id, buyer_id=current_user.user_id)
    except PaymentAccessDenied:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this payment.",
        )


@router.post(
    "/webhooks/{provider}",
    status_code=status.HTTP_200_OK,
    include_in_schema=True,
    tags=["Payments", "Webhooks"],
    summary="Receive a payment provider webhook",
)
async def payment_provider_webhook(
    provider: PaymentProvider,
    request: Request,
    receiver: WebhookReceiver = Depends(get_webhook_receiver),
) -> Response:
    """Handle an (unauthenticated) webhook callback from a payment provider.

    The provider signature is verified and the event normalized by the gateway
    (inside the receiver); the router only reads the body once and delegates.
    """
    body = await request.body()
    headers = dict(request.headers)
    try:
        await receiver.receive(provider=provider, headers=headers, body=body)
    except InvalidWebhookSignatureError:
        logger.warning("Rejected webhook with invalid signature provider=%s", provider)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid webhook signature.",
        )
    except PaymentProviderGatewayError:
        logger.exception("Failed to parse webhook payload provider=%s", provider)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unparseable webhook payload.",
        )
    return Response(status_code=status.HTTP_200_OK)


__all__ = ["router"]
