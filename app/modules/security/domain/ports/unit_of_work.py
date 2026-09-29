"""The security context's Unit of Work port.

Declares audit-trail persistence: AuditEvent and SecurityAlert. The security
context *writes* these; it does not own the concepts, which is why they are
reached through a port rather than by importing another context's domain.

See ``app/modules/shared/unit_of_work.py`` and ``docs/adr/0001``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.modules.shared.unit_of_work import UnitOfWorkPort


@runtime_checkable
class SecurityUnitOfWork(UnitOfWorkPort, Protocol):
    """Transaction boundary for the security context."""

    @property
    def audit_repo(self) -> object:
        """Repository for AuditEvent and SecurityAlert persistence.

        ``object`` until Phase 4 introduces the AuditEvent domain model and
        the SecurityAlert aggregate.
        """
        ...
