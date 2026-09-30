"""SQLAlchemy implementation of the session repository port.

Reads return detached :class:`UserSession` entities, so a mutation needs an
explicit :meth:`save`. That is the behaviour the two autoflush-dependent write
paths in ``auth_service`` were silently relying on:

* ``_rotate_session`` rewrote four columns with no save at all, so a lost write
  left the old refresh token valid while the client was handed a new one;
* ``revoke_session`` set ``revoked_at`` the same way, so logout could return 200
  and leave the session usable.

``tests/integration/test_session_write_paths.py`` covers both.
"""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.session import UserSession as SessionModel
from app.modules.user.domain.entities.user_session import UserSession
from app.modules.user.domain.exceptions import SessionRepositoryUnavailableError
from app.modules.user.infrastructure.persistence.mappers.session_mapper import (
    to_domain,
    to_model,
)

logger = logging.getLogger(__name__)


class SQLAlchemySessionRepository:
    """Adapts ``AsyncSession`` to :class:`SessionRepository`."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def open_session(
        self,
        *,
        user_id: str,
        refresh_token_hash: str,
        expires_at: datetime,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> UserSession:
        session = UserSession.open(
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        model = to_model(session)
        try:
            self.db.add(model)
            await self.db.flush()
            await self.db.refresh(model)
        except SQLAlchemyError as exc:
            logger.warning("Session insert failed: %s", exc, exc_info=True)
            raise SessionRepositoryUnavailableError("Session storage unavailable") from exc
        return to_domain(model)

    async def get_by_refresh_hash(self, refresh_hash: str) -> UserSession | None:
        stmt = select(SessionModel).where(SessionModel.refresh_token_hash == refresh_hash)
        try:
            result = await self.db.execute(stmt)
        except SQLAlchemyError as exc:
            logger.warning("Session lookup failed: %s", exc, exc_info=True)
            raise SessionRepositoryUnavailableError("Session storage unavailable") from exc
        model = result.scalar_one_or_none()
        return to_domain(model) if model is not None else None

    async def save(self, session: UserSession) -> UserSession:
        """Persist a loaded session's changes.

        ``merge`` rather than ``add``: the entity is detached, so the session has
        never seen it and ``add`` would attempt an INSERT against an existing
        primary key.

        ``created_at`` is deliberately not copied back onto the entity. It is a
        server default, so the value the row has is the authoritative one; the
        mapper leaves it out of the update and :meth:`refresh` re-reads it.
        """
        try:
            model = await self.db.merge(to_model(session))
            await self.db.flush()
            await self.db.refresh(model)
        except SQLAlchemyError as exc:
            logger.warning("Session save failed: %s", exc, exc_info=True)
            raise SessionRepositoryUnavailableError("Session storage unavailable") from exc
        session.id = model.id
        session.created_at = model.created_at
        return session

    async def revoke_user_sessions(self, user_id: str, revoked_at: datetime) -> None:
        """Revoke every live session for a user in one statement.

        A bulk UPDATE, so it is unaffected by the detached-entity change. It is
        still the right tool here: password reset invalidates sessions it has not
        loaded and would not be written to visit each one.
        """
        stmt = (
            update(SessionModel)
            .where(SessionModel.user_id == user_id)
            .where(SessionModel.revoked_at.is_(None))
            .values(revoked_at=revoked_at)
        )
        try:
            await self.db.execute(stmt)
        except SQLAlchemyError as exc:
            logger.warning("Bulk session revocation failed: %s", exc, exc_info=True)
            raise SessionRepositoryUnavailableError("Session storage unavailable") from exc
