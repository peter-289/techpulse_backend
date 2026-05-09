from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.config import settings
from app.core.unit_of_work import UnitOfWork
from app.exceptions.exceptions import DomainError
from app.models.audit_event import AuditEvent
from app.models.security_alert import SecurityAlert
from app.models.enums import AlertRuleCode, AlertSeverity, AuditEventType

logger = logging.getLogger(__name__)


class AuditService:
    """
    Application service responsible for:

    - Persisting audit events
    - Detecting suspicious activity
    - Creating security alerts
    """

    def __init__(self, uow: UnitOfWork) -> None:
        self.uow = uow

    def log_audit_event(
        self,
        *,
        event_type: str,
        actor_user_id: int | None,
        method: str,
        path: str,
        status_code: int,
        ip_address: str | None,
        user_agent: str | None,
        request_id: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Persist an audit event and evaluate alert rules.
        """

        try:
            with self.uow:
                event = AuditEvent(
                    event_type=event_type,
                    actor_user_id=actor_user_id,
                    method=method,
                    path=path,
                    status_code=status_code,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    request_id=request_id,
                    metadata_json=metadata or {},
                )

                self.uow.audit_repo.add_event(event)

                # Ensure DB-generated fields like `id`
                # are available before detection.

                self._detect_and_create_alerts(event)

        except Exception as e:
            logger.exception("Failed to persist audit event.")
            raise DomainError(
                "Failed to persist audit event."
            ) from e

    def _detect_and_create_alerts(
        self,
        event: AuditEvent,
    ) -> None:
        """
        Evaluate alerting rules from audit events.
        """

        now = datetime.now(timezone.utc)

        lookback_from = now - timedelta(
            minutes=settings.ALERT_LOOKBACK_MINUTES
        )

        dedup_from = now - timedelta(
            minutes=settings.ALERT_DEDUP_MINUTES
        )

        #
        # Failed login detection
        #
        if (
            event.event_type == AuditEventType.LOGIN_FAILED
            and event.ip_address
        ):
            failures = self._count_events(
                event_type=AuditEventType.LOGIN_FAILED,
                from_time=lookback_from,
                ip_address=event.ip_address,
            )

            if failures >= settings.ALERT_LOGIN_FAILURE_THRESHOLD:
                self._create_alert(
                    rule_code=AlertRuleCode.AUTH_BRUTE_FORCE_IP,
                    severity=AlertSeverity.HIGH,
                    title="Possible brute force login attempts",
                    description=(
                        f"{failures} failed login attempts "
                        f"from IP {event.ip_address} "
                        f"in the last "
                        f"{settings.ALERT_LOOKBACK_MINUTES} minute(s)."
                    ),
                    actor_user_id=event.actor_user_id,
                    ip_address=event.ip_address,
                    audit_event_id=event.id,
                    dedup_from=dedup_from,
                )

        #
        # Excessive access denied detection
        #
        elif event.event_type == AuditEventType.ACCESS_DENIED:
            denied_count = self._count_events(
                event_type=AuditEventType.ACCESS_DENIED,
                from_time=lookback_from,
                actor_user_id=event.actor_user_id,
                ip_address=event.ip_address,
            )

            if denied_count >= settings.ALERT_ACCESS_DENIED_THRESHOLD:
                self._create_alert(
                    rule_code=AlertRuleCode.EXCESSIVE_FORBIDDEN_REQUESTS,
                    severity=AlertSeverity.MEDIUM,
                    title="Excessive forbidden requests detected",
                    description=(
                        f"{denied_count} forbidden requests detected "
                        f"in the last "
                        f"{settings.ALERT_LOOKBACK_MINUTES} minute(s)."
                    ),
                    actor_user_id=event.actor_user_id,
                    ip_address=event.ip_address,
                    audit_event_id=event.id,
                    dedup_from=dedup_from,
                )

    def _count_events(
        self,
        *,
        event_type: str,
        from_time: datetime,
        actor_user_id: int | None = None,
        ip_address: str | None = None,
    ) -> int:
        """
        Count audit events matching the supplied criteria.
        """

        predicates = [
            AuditEvent.event_type == event_type,
            AuditEvent.occurred_at >= from_time,
        ]

        if actor_user_id is not None:
            predicates.append(
                AuditEvent.actor_user_id == actor_user_id
            )

        if ip_address:
            predicates.append(
                AuditEvent.ip_address == ip_address
            )

        return self.uow.audit_repo.count_events(predicates)

    def _create_alert(
        self,
        *,
        rule_code: str,
        severity: str,
        title: str,
        description: str,
        actor_user_id: int | None,
        ip_address: str | None,
        audit_event_id: int | None,
        dedup_from: datetime,
    ) -> None:
        """
        Create a deduplicated security alert.
        """

        predicates = [
            SecurityAlert.rule_code == rule_code,
            SecurityAlert.acknowledged.is_(False),
            SecurityAlert.created_at >= dedup_from,
        ]

        #
        # Actor matching
        #
        if actor_user_id is not None:
            predicates.append(
                SecurityAlert.actor_user_id == actor_user_id
            )
        else:
            predicates.append(
                SecurityAlert.actor_user_id.is_(None)
            )

        #
        # IP matching
        #
        if ip_address:
            predicates.append(
                SecurityAlert.ip_address == ip_address
            )
        else:
            predicates.append(
                SecurityAlert.ip_address.is_(None)
            )

        existing_alert = (
            self.uow.audit_repo.get_alert(
                predicates
            )
        )

        if existing_alert:
            return

        alert = SecurityAlert(
            rule_code=rule_code,
            severity=severity,
            title=title,
            description=description,
            actor_user_id=actor_user_id,
            ip_address=ip_address,
            audit_event_id=audit_event_id,
        )

        self.uow.audit_repo.add_alert(alert)

        logger.warning(
            "Security alert generated: %s",
            rule_code,
        )