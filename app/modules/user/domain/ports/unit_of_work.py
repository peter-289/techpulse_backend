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
from app.modules.user.domain.ports.repository.user_repository import UserRepository
from app.modules.shared.unit_of_work import UnitOfWorkPort


@runtime_checkable
class UserUnitOfWork(UnitOfWorkPort, Protocol):
    """Transaction boundary for the user context."""

    @property
    def user_repo(self) -> UserRepository:
        """Aggregate repository for the User aggregate.

        Entities come back detached, so a caller that mutates one must call
        ``save``. ``auth_service``, ``verification_recovery`` and the superuser
        seeder each did this implicitly before; all of them now save explicitly,
        and ``tests/integration/test_user_write_paths.py`` pins every write path
        that was silently lossy.
        """
        ...

    @property
    def session_repo(self) -> object:
        """Aggregate repository for UserSession.

        Still ``object``: Phase 7 introduces the UserSession model and converts
        the remaining implicit-flush writes in ``auth_service``.
        """
        ...

    @property
    def chat_message_repo(self) -> ChatMessageRepository:
        """Repository for support ChatMessage."""
        ...
