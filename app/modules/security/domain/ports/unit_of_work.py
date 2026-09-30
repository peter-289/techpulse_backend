"""The security context's Unit of Work port.

Declares audit-trail persistence: AuditEvent and SecurityAlert. The security
context *writes* these; it does not own the concepts, which is why they are
reached through a port rather than by importing another context's domain.

See ``app/modules/shared/unit_of_work.py`` and ``docs/adr/0001``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.modules.security.domain.ports.repositories.audit_repository import (
    AuditRepository,
)
from app.modules.shared.unit_of_work import UnitOfWorkPort


@runtime_checkable
class SecurityUnitOfWork(UnitOfWorkPort, Protocol):
    """Transaction boundary for the security context."""

    @property
    def audit_repo(self) -> AuditRepository:
        """Repository for audit events and security alerts.

        ``AuditEvent`` and ``SecurityAlert`` are deliberately exposed through one
        repository rather than two. They are written in a single transaction --
        an alert is a consequence of the event that triggered it, and neither is
        meaningful without the other -- so splitting them would only offer the
        service a way to commit one without the other.
        """
        ...
