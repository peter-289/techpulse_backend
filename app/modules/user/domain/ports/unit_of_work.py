"""The user context's Unit of Work port.

Declares the three repositories the user context owns: the User aggregate, the
UserSession aggregate, and support ChatMessage persistence. The authentication
context is a *different* bounded context that authenticates users; it reaches
user persistence through this port, never by importing the user module's
repositories directly.

See ``app/modules/shared/unit_of_work.py`` and ``docs/adr/0001``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.modules.user.domain.ports.repository.chat_message_repository import (
    ChatMessageRepository,
)
from app.modules.shared.unit_of_work import UnitOfWorkPort


@runtime_checkable
class UserUnitOfWork(UnitOfWorkPort, Protocol):
    """Transaction boundary for the user context."""

    @property
    def user_repo(self) -> object:
        """Aggregate repository for the User aggregate.

        Still ``object``. Phase 6b introduces the aggregate, and it is not a
        mechanical change: ``auth_service`` and ``verification_recovery`` both
        mutate rows this repository hands them and rely on session autoflush to
        persist the change. Returning detached entities would make those writes
        vanish. See ``docs/REVIEW.md``.
        """
        ...

    @property
    def session_repo(self) -> object:
        """Aggregate repository for UserSession.

        Typed as ``object`` until Phase 7 introduces a UserSession domain
        model; ``auth_service`` mutates these rows the same way it mutates user
        rows.
        """
        ...

    @property
    def chat_message_repo(self) -> ChatMessageRepository:
        """Repository for support ChatMessage."""
        ...
