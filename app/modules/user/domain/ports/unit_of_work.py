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

from app.modules.shared.unit_of_work import UnitOfWorkPort


@runtime_checkable
class UserUnitOfWork(UnitOfWorkPort, Protocol):
    """Transaction boundary for the user context."""

    @property
    def user_repo(self) -> object:
        """Aggregate repository for the User aggregate.

        ``object`` because the User domain model does not exist yet; the
        concrete repository still returns ORM rows. Phase 6 introduces the
        aggregate and narrows this annotation to a real
        ``UserRepository`` protocol.
        """
        ...

    @property
    def session_repo(self) -> object:
        """Aggregate repository for UserSession.

        Typed as ``object`` for the same reason as ``user_repo``: Phase 6
        introduces a UserSession domain model.
        """
        ...

    @property
    def chat_message_repo(self) -> object:
        """Repository for support ChatMessage.

        Typed as ``object`` until Phase 6 introduces the entity.
        """
        ...
