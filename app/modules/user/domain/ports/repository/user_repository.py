"""Persistence port for the User aggregate.

The port has a ``save``, and that is the whole design. Entities are detached, so
mutating one does nothing until it is saved. Six call sites across three modules
previously mutated a row from a read and trusted session autoflush to persist it;
each of those is now an explicit save, and
``tests/integration/test_user_write_paths.py`` is what proves the saves work.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from app.modules.user.domain.entities.user import User


@runtime_checkable
class UserRepository(Protocol):
    """Storage boundary for accounts."""

    async def add_user(self, user: User) -> User:
        """Persist a new account, or raise ``DuplicateUserError``."""
        ...

    async def save(self, user: User) -> User:
        """Persist changes made to a loaded account."""
        ...

    async def get_user_by_id(self, user_id: str) -> User | None:
        """Return the account with this id, or ``None``."""
        ...

    async def get_user_by_username(self, username: str) -> User | None:
        """Return the account with this username, or ``None``.

        The username is matched exactly. Callers that need case-insensitive
        behaviour normalize before calling, which is what the authentication
        context has always done.
        """
        ...

    async def get_user_by_email(self, email: str) -> User | None:
        """Return the account with this email, or ``None``."""
        ...

    async def list_users(self, limit: int = 100, before_id: str | None = None) -> list[User]:
        """Return a page of accounts ordered by id, newest id first.

        Keyset pagination: pass the last id of the previous page as
        ``before_id``. Always returns a list; an earlier implementation returned
        ``None`` whenever no cursor was supplied, which turned a list endpoint
        into a 500.
        """
        ...

    async def list_users_pending_verification_email_retry(
        self,
        now: datetime,
        created_before: datetime,
        max_retry_count: int,
        limit: int = 100,
    ) -> list[User]:
        """Return unverified accounts whose verification email is due a resend."""
        ...
