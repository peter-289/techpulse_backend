"""Persistence mappers between the security domain and its ORM models.

In infrastructure for the reason ADR 0002 gives: a mapper depends on both the
persistence model and the domain entities of exactly one bounded context, so the
shared kernel has no business importing it. The repository is the only caller.

The mapping is deliberately asymmetric. Reads reconstruct the domain entity, so
nothing outside the repository sees a SQLAlchemy object. Writes truncate to the
column width, because that width is a storage decision the domain should not
know about -- and because getting it wrong is not theoretical: the service used
to truncate ``path`` to 500 characters while the column is ``varchar(255)``, so
a request with a longer path raised a database error and the audit event was
lost rather than recorded.
"""

from __future__ import annotations

from app.infrastructure.database.models.audit_event import AuditEvent as AuditEventModel
from app.infrastructure.database.models.security_alert import SecurityAlert as SecurityAlertModel
from app.modules.security.domain.entities.audit_event import AuditEvent
from app.modules.security.domain.entities.security_alert import SecurityAlert


#: Column widths, mirrored from the ORM models. Kept as named constants so the
#: truncation is visible at the call site rather than a bare ``255``.
_EVENT_TYPE_MAX_LENGTH = 120
_PATH_MAX_LENGTH = 255
_USER_AGENT_MAX_LENGTH = 255
_IP_ADDRESS_MAX_LENGTH = 64
_TITLE_MAX_LENGTH = 255


def _truncate(value: str | None, limit: int) -> str | None:
    """Shorten a value to a column's width, preserving ``None``.

    ``None`` means "not known", and truncating it would turn that into the
    string "None".
    """
    return value[:limit] if value is not None else None


def event_to_model(event: AuditEvent) -> AuditEventModel:
    """Map a domain ``AuditEvent`` to its persistence row."""
    return AuditEventModel(
        event_type=event.event_type[:_EVENT_TYPE_MAX_LENGTH],
        actor_user_id=event.actor_user_id,
        method=event.method[:10],
        path=event.path[:_PATH_MAX_LENGTH],
        status_code=event.status_code,
        ip_address=_truncate(event.ip_address, _IP_ADDRESS_MAX_LENGTH),
        user_agent=_truncate(event.user_agent, _USER_AGENT_MAX_LENGTH),
        request_id=event.request_id,
        metadata_json=event.metadata or {},
        occurred_at=event.occurred_at,
    )


def event_to_entity(model: AuditEventModel) -> AuditEvent:
    """Map a persistence row to a domain ``AuditEvent``."""
    return AuditEvent(
        id=model.id,
        event_type=model.event_type,
        method=model.method,
        path=model.path,
        status_code=model.status_code,
        actor_user_id=model.actor_user_id,
        ip_address=model.ip_address,
        user_agent=model.user_agent,
        request_id=model.request_id,
        metadata=model.metadata_json,
        occurred_at=model.occurred_at,
    )


def alert_to_model(alert: SecurityAlert) -> SecurityAlertModel:
    """Map a domain ``SecurityAlert`` to its persistence row."""
    return SecurityAlertModel(
        rule_code=str(alert.rule_code),
        severity=str(alert.severity),
        title=alert.title[:_TITLE_MAX_LENGTH],
        description=alert.description,
        actor_user_id=alert.actor_user_id,
        ip_address=alert.ip_address,
        audit_event_id=alert.audit_event_id,
        acknowledged=alert.acknowledged,
        acknowledged_at=alert.acknowledged_at,
        acknowledged_by_user_id=alert.acknowledged_by_user_id,
        created_at=alert.created_at,
    )
