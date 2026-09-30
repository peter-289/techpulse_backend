"""The operator's view of the security context: the alert queue, the audit trail
and the application log.

This file was ``app/modules/user/api/router/admin_router.py`` until Phase 8, and
the move is the substance of the phase rather than a tidy-up. Every row these
five endpoints return is a security-context concept -- ``SecurityAlert`` and
``AuditEvent`` -- while the user context owns users and sessions and nothing
else. R2 forbids a context importing another context's domain or ports, so the
router could not ask security for the data it was reading; the only way to reach
those tables was to import the ORM models and build the ``select()`` itself. That
is what the ratchet's single remaining entry was, and it was not a lapse in an
otherwise tidy file: the layering was forcing the query into the transport layer,
and the rule was recording a structural consequence rather than carelessness.

In its own context the router can do what every other router does -- declare what
it wants and let the application layer answer. It now depends on
:class:`AuditService` and :class:`LogTail`, and it is the only place in the
codebase that knows the JSON shape of an alert or an audit event.

What the shape is, is unchanged. Every field, every filter, every ordering, the
``count``-equals-page-size convention and the three 200-with-a-``detail``
outcomes of the acknowledgement endpoint are all as they were;
``tests/unit/test_admin_api.py`` pins them.

One behaviour did change, and it is the phase's finding rather than its intent:
``/alerts``, ``/audit-events`` and ``/cookie-activity`` used to compute ``count``
from a drained result and then iterate that same result to build ``items``, so
``items`` was always ``[]``. They had never returned a row. See ``docs/REVIEW.md``.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi import Path as ApiPath

from app.modules.security.application.services.audit_service import AuditService
from app.modules.security.dependencies import (
    CurrentUser,
    get_audit_service,
    get_log_tail,
    require_role,
)
from app.modules.security.domain.exceptions import AlertAlreadyAcknowledgedError
from app.modules.security.domain.ports.log_tail import LogTail
from app.modules.shared.enums import RoleEnum

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])

#: The event types `/cookie-activity` is defined as tracking: the two consent
#: decisions and the client's own activity reports. Spelled out as a constant
#: because the set *is* the endpoint's contract -- widening it silently would
#: turn a consent-and-activity view into a second audit-trail view, and the two
#: return different fields.
COOKIE_ACTIVITY_EVENT_TYPES = (
    "cookie.consent.accepted",
    "cookie.consent.declined",
    "client.activity",
)


# === ALERTS ===


def _alert_item(alert) -> dict:
    """Render a ``SecurityAlert`` for the triage list.

    Reads only attributes. ``rule_code`` and ``severity`` are ``StrEnum`` members
    on the entity, and the API has always returned their string values, so the
    wire format is unchanged by the entity replacing the ORM row.
    """
    return {
        "id": alert.id,
        "rule_code": alert.rule_code,
        "severity": alert.severity,
        "title": alert.title,
        "description": alert.description,
        "actor_user_id": alert.actor_user_id,
        "ip_address": alert.ip_address,
        "audit_event_id": alert.audit_event_id,
        "acknowledged": alert.acknowledged,
        "acknowledged_at": alert.acknowledged_at,
        "acknowledged_by_user_id": alert.acknowledged_by_user_id,
        "created_at": alert.created_at,
    }


@router.get("/alerts", status_code=200)
async def list_security_alerts(
    only_unacknowledged: bool = Query(True),
    limit: int = Query(100, ge=1, le=500),
    service: AuditService = Depends(get_audit_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    alerts = await service.list_alerts(only_unacknowledged=only_unacknowledged, limit=limit)
    return {
        "count": len(alerts),
        "items": [_alert_item(alert) for alert in alerts],
    }


@router.patch("/alerts/{alert_id}/ack", status_code=200)
async def acknowledge_security_alert(
    alert_id: int = ApiPath(..., ge=1),
    service: AuditService = Depends(get_audit_service),
    admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    """Take responsibility for an alert.

    All three outcomes are ``200`` with a ``detail`` body, which is what this
    endpoint has always done: acknowledged, already acknowledged, and no such
    alert. Turning the last into a 404 would be more conventional and would also
    be a client-visible change, so it happens deliberately or not at all. Note
    that the not-found body carries no ``alert_id``, unlike the other two.

    ``AlertAlreadyAcknowledgedError`` is caught rather than allowed to become a
    409. The aggregate's rule is that a second acknowledgement is a real fact and
    must not restamp the first, and honouring that is the service's job; how
    this particular endpoint chooses to report it is the transport's.
    """
    try:
        alert = await service.acknowledge_alert(
            alert_id=alert_id, acknowledged_by_user_id=str(admin.user_id)
        )
    except AlertAlreadyAcknowledgedError:
        return {"detail": "Alert already acknowledged", "alert_id": alert_id}

    if alert is None:
        return {"detail": "Alert not found"}
    return {"detail": "Alert acknowledged", "alert_id": alert.id}


# === AUDIT TRAIL ===


def _audit_event_item(event, *, full: bool) -> dict:
    """Render an ``AuditEvent``, with or without the request fields.

    ``/audit-events`` returns the whole record; ``/cookie-activity`` returns the
    subset a consent-and-activity view needs. The split is the endpoint's, so the
    ``full`` flag is passed in rather than guessed -- but the shared fields are
    built in one place so the two cannot drift on ``metadata`` handling, which is
    the field most likely to: a NULL column is presented as ``{}`` because the
    consumer is a dashboard, and a nullable field arriving as ``null`` in the
    middle of an otherwise-uniform object is the kind of thing that throws in a
    browser.
    """
    item = {
        "id": event.id,
        "event_type": event.event_type,
        "actor_user_id": event.actor_user_id,
        "ip_address": event.ip_address,
        "user_agent": event.user_agent,
        "metadata": event.metadata or {},
        "occurred_at": event.occurred_at,
    }
    if full:
        item.update(
            {
                "method": event.method,
                "path": event.path,
                "status_code": event.status_code,
                "request_id": event.request_id,
            }
        )
    return item


@router.get("/audit-events", status_code=200)
async def list_audit_events(
    event_type: str | None = Query(None, max_length=120),
    actor_user_id: UUID | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    service: AuditService = Depends(get_audit_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    events = await service.list_events(
        event_types=(event_type,) if event_type else None,
        actor_user_id=str(actor_user_id) if actor_user_id is not None else None,
        limit=limit,
    )
    return {
        "count": len(events),
        "items": [_audit_event_item(event, full=True) for event in events],
    }


@router.get("/cookie-activity", status_code=200)
async def list_cookie_activity(
    actor_user_id: UUID | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    service: AuditService = Depends(get_audit_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    events = await service.list_events(
        event_types=COOKIE_ACTIVITY_EVENT_TYPES,
        actor_user_id=str(actor_user_id) if actor_user_id is not None else None,
        limit=limit,
    )
    return {
        "count": len(events),
        "items": [_audit_event_item(event, full=False) for event in events],
    }


# === APPLICATION LOG ===


@router.get("/logs", status_code=200)
async def get_logs(
    lines: int = Query(200, ge=1, le=1000),
    log_tail: LogTail = Depends(get_log_tail),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    """The tail of the application log, with credentials removed.

    The redaction happens in the adapter, because the port's contract is that what
    comes back is safe to send to a browser. This handler does not see the
    patterns and cannot forget to apply one.
    """
    return {
        "log_file": str(log_tail.path),
        "lines_requested": lines,
        "entries": await log_tail.tail(lines=lines),
    }
