from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.db_setup import get_db
from app.core.security import get_current_user
from app.services.audit_service import AuditService
from app.core.unit_of_work import UnitOfWork

router = APIRouter(prefix="/api/v1/analytics", tags=["Analytics"])

# Get User Service
def get_service(db: Session = Depends(get_db))->AuditService:
    uow = UnitOfWork(session=db)
    return AuditService(uow=uow)

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
def capture_analytics_event(
    payload: AnalyticsEventRequest,
    request: Request,
    service: AuditService=Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    is_cookie_event = payload.event_type == "cookie_consent"
    action = payload.action.lower()
    if is_cookie_event and action not in {"accepted", "declined"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cookie consent action must be accepted or declined.",
        )
    event_type = (
        "cookie.consent.accepted"
        if is_cookie_event and action == "accepted"
        else "cookie.consent.declined"
        if is_cookie_event and action == "declined"
        else "client.activity"
    )

    metadata = _safe_metadata(payload.metadata)
    metadata["action"] = payload.action
    if payload.page:
        metadata["page"] = payload.page
    if payload.client_id:
        metadata["client_id"] = payload.client_id

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    service.log_audit_event(
        event_type=event_type,
        actor_user_id=int(current_user["user_id"]),
        method=request.method,
        path=request.url.path,
        status_code=202,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=getattr(request.state, "request_id", None),
        metadata=metadata,
    )
    return {"detail": "accepted"}
