"""Domain <-> ORM mapping for sessions.

Kept separate from the repository so the field-by-field correspondence is
readable on its own, which is where a silently dropped column would otherwise
hide.
"""

from __future__ import annotations

from app.infrastructure.database.models.session import UserSession as SessionModel
from app.modules.user.domain.entities.user_session import UserSession


def to_domain(model: SessionModel) -> UserSession:
    return UserSession(
        id=model.id,
        user_id=model.user_id,
        refresh_token_hash=model.refresh_token_hash,
        created_at=model.created_at,
        last_used_at=model.last_used_at,
        expires_at=model.expires_at,
        revoked_at=model.revoked_at,
        user_agent=model.user_agent,
        ip_address=model.ip_address,
    )


def to_model(session: UserSession) -> SessionModel:
    """Build a transient row for a save.

    ``id`` is passed through so ``Session.merge`` can match the existing row.
    ``created_at`` is left alone: the column has a server default, and copying
    the entity's value over it would overwrite the database's record of when the
    session was actually created with whatever the entity happened to hold.
    """
    return SessionModel(
        id=session.id,
        user_id=session.user_id,
        refresh_token_hash=session.refresh_token_hash,
        last_used_at=session.last_used_at,
        expires_at=session.expires_at,
        revoked_at=session.revoked_at,
        user_agent=session.user_agent,
        ip_address=session.ip_address,
    )
