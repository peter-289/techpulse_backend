"""SQLAlchemy implementation of the user repository port.

The notable change from the previous version is that reads return detached domain
entities, so nothing a caller does to one reaches the database until
:meth:`save`. ``add_user`` also translates the driver's ``IntegrityError`` into a
domain error here rather than in the application service, which is what clears
the service's last two R8 entries.
"""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.user import User as UserModel
from app.modules.user.domain.entities.user import User
from app.modules.user.domain.exceptions import (
    DuplicateUserError,
    UserRepositoryUnavailableError,
)
from app.modules.user.infrastructure.persistence.mappers.user_mapper import (
    to_domain,
    to_model,
)
from app.modules.shared.enums import UserStatus

logger = logging.getLogger(__name__)

#: Matches the ``list_users`` limit ceiling the previous implementation applied.
_MAX_PAGE_SIZE = 200


class SQLAlchemyUserRepository:
    """Adapts ``AsyncSession`` to :class:`UserRepository`."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # === writes ===

    async def add_user(self, user: User) -> User:
        model = to_model(user)
        try:
            self.db.add(model)
            await self.db.flush()
            await self.db.refresh(model)
        except IntegrityError as exc:
            raise DuplicateUserError("Email or username already exists!") from exc
        except SQLAlchemyError as exc:
            logger.warning("User insert failed: %s", exc, exc_info=True)
            raise UserRepositoryUnavailableError("User storage unavailable") from exc
        return to_domain(model)

    async def save(self, user: User) -> User:
        """Persist a loaded account's changes.

        ``merge`` rather than ``add``: the entity is detached, so the session has
        never seen it, and ``add`` would try to INSERT a row whose primary key
        already exists. ``merge`` copies the entity's state onto the tracked row,
        and the enclosing Unit of Work commits.

        Returns the entity with database defaults applied, so a caller that
        passes a freshly registered user gets its timestamps back.
        """
        try:
            model = await self.db.merge(to_model(user))
            await self.db.flush()
            await self.db.refresh(model)
        except IntegrityError as exc:
            raise DuplicateUserError("Email or username already exists!") from exc
        except SQLAlchemyError as exc:
            logger.warning("User save failed: %s", exc, exc_info=True)
            raise UserRepositoryUnavailableError("User storage unavailable") from exc
        user.created_at = model.created_at
        user.updated_at = model.updated_at
        return user

    # === reads ===

    async def get_user_by_id(self, user_id: str) -> User | None:
        return to_domain_or_none(await self.db.get(UserModel, str(user_id)))

    async def get_user_by_username(self, username: str) -> User | None:
        stmt = select(UserModel).where(UserModel.username == username)
        return to_domain_or_none(await self._one(stmt))

    async def get_user_by_email(self, email: str) -> User | None:
        stmt = select(UserModel).where(UserModel.email == email)
        return to_domain_or_none(await self._one(stmt))

    async def list_users(self, limit: int = 100, before_id: str | None = None) -> list[User]:
        """Return a page of accounts, highest id first.

        Keyset pagination on the primary key. The previous signature also
        accepted a ``cursor`` datetime used as a ``created_at`` upper bound; it
        had no caller outside this module and is gone, so the two ways of
        paginating the same listing cannot disagree with each other.
        """
        limit = max(1, min(int(limit), _MAX_PAGE_SIZE))
        stmt = select(UserModel).order_by(UserModel.id.desc()).limit(limit)
        if before_id is not None:
            stmt = stmt.where(UserModel.id < before_id)
        try:
            result = await self.db.execute(stmt)
        except SQLAlchemyError as exc:
            logger.warning("User listing failed: %s", exc, exc_info=True)
            raise UserRepositoryUnavailableError("User storage unavailable") from exc
        return [to_domain(model) for model in result.scalars().all()]

    async def list_users_pending_verification_email_retry(
        self,
        now: datetime,
        created_before: datetime,
        max_retry_count: int,
        limit: int = 100,
    ) -> list[User]:
        """Return unverified accounts that are due a verification resend.

        Mirrors :meth:`User.is_due_for_verification_resend` in SQL, plus the
        age and retry ceilings the worker imposes.
        """
        stmt = (
            select(UserModel)
            .where(UserModel.status != UserStatus.VERIFIED)
            .where(UserModel.created_at <= created_before)
            .where(UserModel.verification_email_retry_count < max_retry_count)
            .where(
                or_(
                    UserModel.verification_email_next_retry_at.is_(None),
                    UserModel.verification_email_next_retry_at <= now,
                )
            )
            .order_by(UserModel.created_at.asc())
            .limit(limit)
        )
        try:
            result = await self.db.execute(stmt)
        except SQLAlchemyError as exc:
            logger.warning("User retry listing failed: %s", exc, exc_info=True)
            raise UserRepositoryUnavailableError("User storage unavailable") from exc
        return [to_domain(model) for model in result.scalars().all()]

    async def _one(self, stmt) -> object:
        try:
            result = await self.db.execute(stmt)
        except SQLAlchemyError as exc:
            logger.warning("User lookup failed: %s", exc, exc_info=True)
            raise UserRepositoryUnavailableError("User storage unavailable") from exc
        return result.scalar_one_or_none()


def to_domain_or_none(model: UserModel | None) -> User | None:
    return to_domain(model) if model is not None else None
