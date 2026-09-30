"""The UserSession aggregate root.

A session record belongs to the user context even though authentication owns the
decisions made about it. ``auth_service`` creates, rotates and revokes sessions;
the row itself is part of who a user is, and ``revalidate_access_token`` reads it
on every authenticated request. So the record is modelled here and the
authentication context drives it through a port, which is the same arrangement
``AuthenticationUnitOfWork`` already documents.

Why the methods here matter more than the fields
------------------------------------------------
Every mutation of this table used to be a bare attribute assignment at a call
site, and two of them were never verified against a real database:

* rotation rewrote ``refresh_token_hash``, ``last_used_at``, ``user_agent`` and
  ``ip_address`` with no save at all, relying on session autoflush;
* ``revoke_session`` set ``revoked_at`` the same way.

If either write is lost, the client still receives success. A lost rotation means
the *old* refresh token keeps working and the new one is never recognised, so
rotation silently stops guaranteeing anything. A lost revocation means logout
returns 200 and the session stays usable.

``expires_at``, ``revoked_at`` and ``is_usable_at`` are the rules worth having in
one place. The expiry comparison in particular has to tolerate a naive datetime,
because SQLite returns one and the old inline comparison raised on it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(slots=True)
class UserSession:
    """One authenticated session for one user."""

    user_id: str
    refresh_token_hash: str
    expires_at: datetime
    id: int | None = None
    created_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    user_agent: str | None = None
    ip_address: str | None = None

    @classmethod
    def open(
        cls,
        *,
        user_id: str,
        refresh_token_hash: str,
        expires_at: datetime,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> "UserSession":
        """Start a new session.

        Takes an already-hashed refresh token. The caller owns hashing, because
        the plaintext token has to be handed back to the client exactly once and
        never stored -- an entity that hashed internally would be very easy to
        call in a way that persists the plaintext.
        """
        return cls(
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )

    # === lifecycle ===

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def revoke(self, revoked_at: datetime) -> None:
        """Revoke the session.

        Idempotent: a second logout on an already-revoked session leaves the
        original timestamp alone, so the first revocation time stays meaningful.
        """
        if self.revoked_at is None:
            self.revoked_at = revoked_at

    def rotate(
        self,
        *,
        new_refresh_token_hash: str,
        rotated_at: datetime,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Replace the refresh token and stamp the rotation.

        The agent and IP are only overwritten when the caller supplied them. A
        refresh is a background, cookie-less request in a browser, and it has no
        User-Agent to offer; blanking the recorded values there would erase the
        detail that makes a session row useful.

        The id does not change. The access token stays bound to this session, so
        revoking it invalidates both the refresh token and the access token.
        """
        self.refresh_token_hash = new_refresh_token_hash
        self.last_used_at = rotated_at
        if user_agent:
            self.user_agent = user_agent
        if ip_address:
            self.ip_address = ip_address

    # === validity ===

    def is_expired_at(self, now: datetime) -> bool:
        """Whether this session's validity window has closed by ``now``.

        The stored value can be naive: SQLite has no timezone type, so it hands
        back a naive ``datetime`` even for a ``DateTime(timezone=True)`` column.
        Comparing that against an aware ``now`` raises ``TypeError``, which is
        what the old inline comparison did.

        A missing expiry counts as expired. The column is ``NOT NULL``, so a
        detached entity can only reach this state by being hand-built, and a
        session with no stated window has no interval in which it is valid. The
        revalidation path this replaced had the same rule as an explicit
        ``expires_at is None`` check; without it here, the comparison would
        raise ``TypeError`` on ``None`` instead of rejecting the token.
        """
        if self.expires_at is None:
            return True
        return _as_utc(self.expires_at) <= _as_utc(now)

    def is_usable_at(self, now: datetime) -> bool:
        """Whether this session may still be refreshed.

        Revocation wins over expiry so the reason a session stopped working is
        unambiguous.
        """
        return not self.is_revoked and not self.is_expired_at(now)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
