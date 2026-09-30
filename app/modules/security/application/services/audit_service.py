"""Record audit events, and raise a security alert when one is warranted.

Written on every API request, so two things dominate the design. It must not
fail the request it is describing -- the middleware runs it in a background task
precisely for that -- and it must not add per-request query load it cannot
justify.

The second point is why the detection rules are consulted in two steps.
``rules_for`` is a dict lookup and runs for every audited request, including the
overwhelming majority that are ordinary 200s and cannot raise anything. The count
that follows runs only for the event types a rule actually watches. An earlier
version read the thresholds from ``app.core.config.settings`` and built
``AuditEvent.event_type == ...`` SQLAlchemy expressions inline, which put two
queries' worth of shape and a global in the same function; the thresholds are
now an injected value object and the expressions live in the repository.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from app.exceptions.exceptions import DomainError
from app.modules.security.domain.entities.audit_event import AuditEvent, utc_now
from app.modules.security.domain.policies.alert_rules import AlertRule, rules_for
from app.modules.security.domain.ports.unit_of_work import SecurityUnitOfWork
from app.modules.security.domain.ports.alert_thresholds import AlertThresholds

logger = logging.getLogger(__name__)


class AuditService:
    """Application service for the audit trail and the alerts it raises.

    Args:
        uow: The security context's transaction boundary. Only this port, so
            the service cannot reach another context's tables.
        thresholds: How much activity is tolerated before alerting, injected
            rather than read from the environment, so a test can state the rule
            it is exercising.
    """

    def __init__(self, uow: SecurityUnitOfWork, thresholds: AlertThresholds) -> None:
        self.uow = uow
        self.thresholds = thresholds

    async def log_audit_event(
        self,
        *,
        event_type: str,
        actor_user_id: str | None,
        method: str,
        path: str,
        status_code: int,
        ip_address: str | None,
        user_agent: str | None,
        request_id: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record one request fact and evaluate the detection rules against it.

        Raises:
            DomainError: If the event could not be recorded. Any failure is
                reported as one type on purpose: the caller is a background task
                whose only recourse is to log, and an audit trail that fails
                loudly about *why* it failed would tempt a caller into skipping
                it.
        """
        try:
            async with self.uow:
                event = AuditEvent.create(
                    event_type=event_type,
                    actor_user_id=actor_user_id,
                    method=method,
                    path=path,
                    status_code=status_code,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    request_id=request_id,
                    metadata=metadata,
                )

                # The returned entity, not the local one: an alert stores this
                # event's id, and the id is assigned by the insert.
                event = await self.uow.audit_repo.save_event(event)

                await self._raise_alerts_for(event)
        except Exception as exc:
            logger.exception("Failed to persist audit event.")
            raise DomainError("Failed to persist audit event.") from exc

    async def _raise_alerts_for(self, event: AuditEvent) -> None:
        """Raise an alert for every rule this event trips, deduplicated.

        Runs inside the event's transaction on purpose: an alert is a
        consequence of the event that raised it, so a rollback that discarded the
        event must discard the alert too, or the alert would reference an event
        that no one can find.
        """
        now = utc_now()

        for rule in rules_for(event, self.thresholds):
            count = await self._count_matching(rule, event=event, since=now - rule.lookback)
            if not rule.exceeded_by(count):
                continue

            if await self._already_alerted(rule, event=event, since=now - rule.dedup):
                continue

            alert = rule.raise_alert(event=event, count=count)
            await self.uow.audit_repo.save_alert(alert)
            logger.warning("Security alert generated: %s", rule.code)

    async def _count_matching(
        self, rule: AlertRule, *, event: AuditEvent, since: datetime
    ) -> int:
        """Count the recent history a rule counts."""
        return await self.uow.audit_repo.count_events(
            event_type=rule.event_type.value,
            since=since,
            actor_user_id=event.actor_user_id,
            ip_address=event.ip_address,
        )

    async def _already_alerted(
        self, rule: AlertRule, *, event: AuditEvent, since: datetime
    ) -> bool:
        """Whether an open alert for this rule and subject is already in the window.

        The dedup window is what turns a sustained attack into one alert an
        operator can act on, instead of one alert per request for as long as it
        lasts.
        """
        return await self.uow.audit_repo.has_unacknowledged_alert(
            rule_code=rule.code.value,
            since=since,
            actor_user_id=event.actor_user_id,
            ip_address=event.ip_address,
        )
