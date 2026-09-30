"""The session persistence port.

Like :mod:`app.modules.user.domain.ports.repository.user_repository`, reads hand
back detached entities and ``save`` is what persists a mutation. That is not a
style preference here: it is the fix for two write paths that were never
verified against a real database, and both of which returned success whether or
not the write landed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from app.modules.user.domain.entities.user_session import UserSession


@runtime_checkable
class SessionRepository(Protocol):
    """Persistence for :class:`UserSession`.

    Declared in the user context, driven by the authentication context.
    ``auth_service`` reaches it through ``AuthenticationUnitOfWork``, which
    documents why the port is written in the consumer.
    """

    async def open_session(
        self,
        *,
        user_id: str,
        refresh_token_hash: str,
        expires_at: datetime,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> UserSession:
        """Start and persist a new session, returning it with its assigned id.

        Takes the values rather than a constructed entity on purpose. The
        authentication context drives this port but may not import the user
        context's entities (R2), so the only way it can create one is by asking
        the repository to. Phase 6b established the same arrangement for
        ``User``: the consumer calls the methods it gets back without ever
        naming the type.
        """
        ...

    async def get_by_id(self, session_id: int) -> UserSession | None:
        """Return the session with this id, if any.

        How access-token revalidation reaches a session: the token carries the
        session id in its ``sid`` claim, not the refresh-token hash.
        """
        ...

    async def get_by_refresh_hash(self, refresh_hash: str) -> UserSession | None:
        """Return the session holding this refresh-token hash, if any.

        A detached entity: mutating it changes nothing until :meth:`save`.
        """
        ...

    async def save(self, session: UserSession) -> UserSession:
        """Persist a loaded session's changes.

        ``merge``-based, because the entity is detached. Omitting this call after
        a mutation loses the write silently.
        """
        ...

    async def revoke_user_sessions(self, user_id: str, revoked_at: datetime) -> None:
        """Revoke every live session for a user, in one statement.

        Used by password reset, which must invalidate sessions it never loaded.
        """
        ...
