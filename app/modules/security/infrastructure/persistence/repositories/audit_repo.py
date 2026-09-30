"""SQLAlchemy implementation of the audit repository port.

Every ``SQLAlchemyError`` is translated into ``AuditRepositoryUnavailableError``
here and nowhere else. The application service used to import
``app.core.config`` and build ORM predicates, and the middleware caught
``Exception`` around it; with the translation in one place, a caller that wants
to distinguish "the audit store is down" from "the event was invalid" catches
:class:`AuditRepositoryUnavailableError` and never names the ORM.
"""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.audit_event import AuditEvent as AuditEventModel
from app.infrastructure.database.models.security_alert import SecurityAlert as SecurityAlertModel
from app.modules.security.domain.entities.audit_event import AuditEvent
from app.modules.security.domain.entities.security_alert import SecurityAlert
from app.modules.security.domain.exceptions import AuditRepositoryUnavailableError
from app.modules.security.domain.ports.repositories.audit_repository import AuditRepository
from app.modules.security.infrastructure.persistence.mappers.audit_mapper import (
    alert_to_model,
    event_to_entity,
    event_to_model,
)

logger = logging.getLogger(__name__)


class SQLAlchemyAuditRepository(AuditRepository):
    """Audit persistence over an ``AsyncSession``.

    Never commits or rolls back: the UnitOfWork owns the transaction. ``flush``
    is enough to obtain the autoincrement ids that an alert's foreign key needs,
    and committing here would let an alert outlive the event that raised it.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def save_event(self, event: AuditEvent) -> AuditEvent:
        """Insert an audit event and return it carrying its assigned id."""
        try:
            model = event_to_model(event)
            self.session.add(model)
            await self.session.flush()
            return event_to_entity(model)
        except SQLAlchemyError as exc:
            logger.error(
                "Failed to persist audit event (%s): %s", event.event_type, exc, exc_info=False
            )
            raise AuditRepositoryUnavailableError("Failed to persist audit event.") from exc

    async def count_events(
        self,
        *,
        event_type: str,
        since: datetime,
        actor_user_id: str | None = None,
        ip_address: str | None = None,
    ) -> int:
        """Count matching audit events, honouring only the constraints given."""
        try:
            stmt = select(func.count()).select_from(AuditEventModel).where(
                AuditEventModel.event_type == event_type,
                AuditEventModel.occurred_at >= since,
                *self._count_predicates(actor_user_id=actor_user_id, ip_address=ip_address),
            )
            return await self.session.scalar(stmt) or 0
        except SQLAlchemyError as exc:
            logger.error("Failed to count audit events (%s): %s", event_type, exc, exc_info=False)
            raise AuditRepositoryUnavailableError("Failed to count audit events.") from exc

    async def has_unacknowledged_alert(
        self,
        *,
        rule_code: str,
        since: datetime,
        actor_user_id: str | None = None,
        ip_address: str | None = None,
    ) -> bool:
        """Whether an open alert for this rule and subject exists in the window."""
        try:
            stmt = select(SecurityAlertModel.id).where(
                SecurityAlertModel.rule_code == rule_code,
                SecurityAlertModel.acknowledged.is_(False),
                SecurityAlertModel.created_at >= since,
                *self._alert_predicates(actor_user_id=actor_user_id, ip_address=ip_address),
            ).limit(1)
            return await self.session.scalar(stmt) is not None
        except SQLAlchemyError as exc:
            logger.error("Failed to check for existing alert (%s): %s", rule_code, exc, exc_info=False)
            raise AuditRepositoryUnavailableError("Failed to check for existing alert.") from exc

    async def save_alert(self, alert: SecurityAlert) -> SecurityAlert:
        """Insert a security alert and return it carrying its assigned id."""
        try:
            model = alert_to_model(alert)
            self.session.add(model)
            await self.session.flush()
            alert.id = model.id
            return alert
        except SQLAlchemyError as exc:
            logger.error(
                "Failed to persist security alert (%s): %s", alert.rule_code, exc, exc_info=False
            )
            raise AuditRepositoryUnavailableError("Failed to persist security alert.") from exc

    @staticmethod
    def _count_predicates(*, actor_user_id: str | None, ip_address: str | None) -> tuple:
        """Build the actor and address predicates for counting history.

        A set value must match exactly; an unset one places no constraint at
        all, so the count spans every client. That is correct here because the
        rules narrow before counting -- :func:`rules_for` refuses a
        brute-force candidate with no address, so the only rule that counts by
        address always has one.
        """
        predicates = []
        if actor_user_id is not None:
            predicates.append(AuditEventModel.actor_user_id == actor_user_id)
        if ip_address:
            predicates.append(AuditEventModel.ip_address == ip_address)
        return tuple(predicates)

    @staticmethod
    def _alert_predicates(*, actor_user_id: str | None, ip_address: str | None) -> tuple:
        """Build the actor and address predicates for alert deduplication.

        Deliberately *not* the same as :meth:`_count_predicates`. Here an unset
        value must match only unset, because the question is "has this subject
        already been alerted about?". Treating an anonymous actor as "any actor"
        would let one client's brute-force alert suppress another's for the
        length of the dedup window.
        """
        predicates = [
            SecurityAlertModel.actor_user_id == actor_user_id
            if actor_user_id is not None
            else SecurityAlertModel.actor_user_id.is_(None)
        ]
        predicates.append(
            SecurityAlertModel.ip_address == ip_address
            if ip_address
            else SecurityAlertModel.ip_address.is_(None)
        )
        return tuple(predicates)
