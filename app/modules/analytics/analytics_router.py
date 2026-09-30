from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.shared.dependencies import get_db
from app.modules.security.dependencies import (
    CurrentUser,
    alert_thresholds,
    get_abuse_protection,
    get_current_user,
)
from app.modules.security.abuse_protection import AbuseProtection
from app.modules.security.application.services.audit_service import AuditService
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.shared.enums import CookieConsent

router = APIRouter(prefix="/api/v1/analytics", tags=["Analytics"])

# Get the audit service. Analytics events are written to the security context's
# audit trail rather than a table of their own, so this is the security
# context's service rather than a second writer with its own idea of the
# schema. Phase 8 moves the composition of both onto shared dependencies.
def get_service(db: AsyncSession = Depends(get_db))->AuditService:
    uow = UnitOfWork(session=db)
    return AuditService(uow=uow, thresholds=alert_thresholds)

class AnalyticsEventRequest(BaseModel):
    event_type: str = Field(..., pattern="^(cookie_consent|user_activity)$")
    action: str = Field(..., min_length=1, max_length=80)
    page: str | None = Field(None, max_length=120)
    client_id: str | None = Field(None, max_length=64)
    metadata: dict = Field(default_factory=dict)


def _safe_metadata(raw: dict | None) -> dict:
    if not isinstance(raw, dict):
        return {}
    safe: dict[str, object] = {}
    for key, value in raw.items():
        key_str = str(key)[:80]
        if isinstance(value, (str, int, float, bool)) or value is None:
           safe[key_str] = value
        else:
            safe[key_str] = str(value)[:500]
    return safe


@router.post("/events", status_code=202)
async def capture_analytics_event(
    payload: AnalyticsEventRequest,
    request: Request,
    service: AuditService=Depends(get_service),
    current_user: CurrentUser = Depends(get_current_user),
    abuse_protection: AbuseProtection = Depends(get_abuse_protection),
):
    is_cookie_event = payload.event_type == "cookie_consent"
    action = payload.action.lower()
    if is_cookie_event and action not in [CookieConsent.ACCEPTED, CookieConsent.DECLINED]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cookie consent action must be accepted or declined.",
        )
    event_type = (
        "cookie.consent.accepted"
        if is_cookie_event and action == CookieConsent.ACCEPTED
        else "cookie.consent.declined"
        if is_cookie_event and action == CookieConsent.DECLINED
        else "client.activity"
    )

    metadata = _safe_metadata(payload.metadata)
    metadata["action"] = payload.action
    if payload.page:
        metadata["page"] = payload.page
    if payload.client_id:
        metadata["client_id"] = payload.client_id

    # Use the shared helper so the recorded address matches what rate limiters enforce.
    ip_address = abuse_protection.get_client_ip(request) or None
    user_agent = request.headers.get("user-agent")

    await service.log_audit_event(
        event_type=event_type,
        actor_user_id=str(current_user.user_id),
        method=request.method,
        path=request.url.path,
        status_code=202,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=getattr(request.state, "request_id", None),
        metadata=metadata,
    )
    return {"detail": "accepted"}
