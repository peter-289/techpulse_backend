from __future__ import annotations

import re
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Path as ApiPath, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.modules.shared.dependencies import require_role, get_db
from app.infrastructure.database.models.audit_event import AuditEvent
from app.infrastructure.database.models.security_alert import SecurityAlert

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])

_BEARER_RE = re.compile(r"(bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", flags=re.IGNORECASE)
_PASSWORD_RE = re.compile(r"(password\s*[:=]\s*)\S+", flags=re.IGNORECASE)
_TOKEN_RE = re.compile(r"((?:refresh|access)?_?token\s*[:=]\s*)\S+", flags=re.IGNORECASE)


def _sanitize_log_line(line: str) -> str:
    line = _BEARER_RE.sub(r"\1[REDACTED]", line)
    line = _PASSWORD_RE.sub(r"\1[REDACTED]", line)
    line = _TOKEN_RE.sub(r"\1[REDACTED]", line)
    return line


def _tail_lines(path: Path, lines: int) -> list[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        recent = deque(fh, maxlen=lines)
    return [_sanitize_log_line(line.rstrip("\r\n")) for line in recent]


@router.get("/logs", status_code=200)
def get_logs(
    lines: int = Query(200, ge=1, le=1000),
    _admin: dict = Depends(require_role("admin")),
):
    log_path = Path(settings.LOG_FILE_PATH)
    return {
        "log_file": str(log_path),
        "lines_requested": lines,
        "entries": _tail_lines(log_path, lines),
    }


@router.get("/alerts", status_code=200)
async def list_security_alerts(
    only_unacknowledged: bool = Query(True),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _admin: dict = Depends(require_role("admin")),
):
    stmt = select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(limit)
    if only_unacknowledged:
        stmt = stmt.where(SecurityAlert.acknowledged.is_(False))
    alerts = await db.execute(stmt)

    return {
        "count": len(alerts.scalars().all()),
        "items": [
            {
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
            for alert in alerts
        ],
    }


@router.patch("/alerts/{alert_id}/ack", status_code=200)
async def acknowledge_security_alert(
    alert_id: int = ApiPath(..., ge=1),
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_role("admin")),
):
    alert = await db.get(SecurityAlert, alert_id)
    if not alert:
        return {"detail": "Alert not found"}
    if alert.acknowledged:
        return {"detail": "Alert already acknowledged", "alert_id": alert_id}
    alert.acknowledged = True
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_by_user_id = int(admin["user_id"])
    await db.commit()
    return {"detail": "Alert acknowledged", "alert_id": alert_id}


@router.get("/audit-events", status_code=200)
async def list_audit_events(
    event_type: str | None = Query(None, max_length=120),
    actor_user_id: int | None = Query(None, ge=1),
    limit: int = Query(200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    _admin: dict = Depends(require_role("admin")),
):
    stmt = select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(limit)
    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    if actor_user_id is not None:
        stmt = stmt.where(AuditEvent.actor_user_id == actor_user_id)
    events = await db.execute(stmt)
    return {
        "count": len(events.scalars().all()),
        "items": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "actor_user_id": event.actor_user_id,
                "method": event.method,
                "path": event.path,
                "status_code": event.status_code,
                "ip_address": event.ip_address,
                "user_agent": event.user_agent,
                "request_id": event.request_id,
                "metadata": event.metadata_json or {},
                "occurred_at": event.occurred_at,
            }
            for event in events
        ],
    }


@router.get("/cookie-activity", status_code=200)
async def list_cookie_activity(
    actor_user_id: int | None = Query(None, ge=1),
    limit: int = Query(200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    _admin: dict = Depends(require_role("admin")),
):
    tracked_types = (
        "cookie.consent.accepted",
        "cookie.consent.declined",
        "client.activity",
    )
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.event_type.in_(tracked_types))
        .order_by(AuditEvent.occurred_at.desc())
        .limit(limit)
    )
    if actor_user_id is not None:
        stmt = stmt.where(AuditEvent.actor_user_id == actor_user_id)
    events = await db.execute(stmt)
    return {
        "count": len(events.scalars().all()),
        "items": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "actor_user_id": event.actor_user_id,
                "ip_address": event.ip_address,
                "user_agent": event.user_agent,
                "metadata": event.metadata_json or {},
                "occurred_at": event.occurred_at,
            }
            for event in events
        ],
    }
