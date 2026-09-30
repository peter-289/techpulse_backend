from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.modules.security.dependencies import (
    CurrentUser,
    get_abuse_protection,
    get_audit_service,
    get_current_user,
)
from app.modules.security.abuse_protection import AbuseProtection
from app.modules.security.application.services.audit_service import AuditService
from app.modules.shared.enums import CookieConsent

router = APIRouter(prefix="/api/v1/analytics", tags=["Analytics"])

# The audit service comes from the security context's composition module rather
# than being assembled here. Two reasons, and the first is the interesting one.
#
# First: analytics owns nothing. Cookie-consent decisions and client activity are
# recorded as facts in the security context's audit trail, and this context has no
# domain, no entities and no repositories of its own -- it is a facade over one
# write. There is nothing for it to model, so a service of its own would either
# be a one-line pass-through or a second place where the rules for writing an
# audit event are stated. Asking the owning context for its own service is the
# honest shape for a facade, and it is the only one the rules permit: R2 stops a
# bounded context from importing another context's domain, so analytics could
# never have wrapped `AuditService` in a service of its own without reaching
# through its application layer.
#
# Second: this used to build the service here, from a concrete `UnitOfWork` and
# the thresholds read straight off the composition module. An API router doing
# the wiring is what Phase 7b split the composition root to stop, and no rule
# catches it: `analytics_router.py` sits at its context root, so it is classified
# by none of the eight layer rules.

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
    service: AuditService = Depends(get_audit_service),
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
