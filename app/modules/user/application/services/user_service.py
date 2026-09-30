"""Account use cases.

Every layering violation this service had is gone: no ORM model, no pydantic
model, no FastAPI, no ``run_in_threadpool``, no ``sqlalchemy.exc``. What is left
is orchestration, and the two things that genuinely are not the domain's business
-- the Argon2 hash, and the client IP the abuse guard needs.

The IP is now a plain string rather than a ``Request``. The service never read
anything else from it, and taking the request object is what pulled FastAPI in.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID, uuid4

from app.modules.security.abuse_protection import AbuseProtection
from app.modules.security.password_manager import hash_password
from app.modules.user.application.services.rules import validate_password_strength
from app.modules.user.domain.entities.user import User
from app.modules.user.domain.exceptions import UserNotFoundError
from app.modules.user.domain.ports.unit_of_work import UserUnitOfWork
from app.modules.shared.enums import GenderEnum, RoleEnum, UserStatus

logger = logging.getLogger(__name__)


class SuperuserResult(StrEnum):
    """What ``ensure_superuser`` found."""

    CREATED = "created"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class SuperuserOutcome:
    """Result of ``ensure_superuser``.

    Carries the identifiers rather than the entity so the caller can log without
    holding a whole account, and so ``CONFLICT`` -- which must report the
    username and email that disagree rather than either account -- has a shape
    of its own.
    """

    outcome: SuperuserResult
    username: str
    email: str


class UserService:
    def __init__(self, uow: UserUnitOfWork, abuse_protection: AbuseProtection):
        self.uow = uow
        self._abuse = abuse_protection

    async def create_user(
        self,
        *,
        full_name: str,
        username: str,
        email: str,
        password: str,
        gender,
        client_ip: str,
    ) -> User:
        """Register an account.

        The password is strength-checked and hashed before the transaction opens.
        Hashing is CPU-bound and Argon2 is deliberately slow, so it runs on a
        worker thread via :func:`asyncio.to_thread`; the previous
        ``fastapi.concurrency.run_in_threadpool`` did the same thing through a
        FastAPI import.
        """
        validate_password_strength(password)
        password_hash = await asyncio.to_thread(hash_password, password)

        user = User.register(
            full_name=full_name,
            username=username,
            email=email,
            password_hash=password_hash,
            gender=gender,
        )

        # Guarded before the insert so a rate-limited client costs no write.
        await self._abuse.guard_registration(ip=client_ip)

        async with self.uow:
            return await self.uow.user_repo.add_user(user)

    async def list_users(self, limit: int = 100, before_id: str | None = None) -> list[User]:
        async with self.uow.read_only():
            users = await self.uow.user_repo.list_users(limit=limit, before_id=before_id)
            logger.debug("Fetched users page", extra={"limit": limit, "before_id": before_id})
            return users

    async def get_user_by_id(self, user_id: UUID) -> User:
        async with self.uow.read_only():
            user = await self.uow.user_repo.get_user_by_id(str(user_id))
            if not user:
                raise UserNotFoundError("User not found.")
            return user

    async def ensure_superuser(
        self,
        *,
        username: str,
        email: str,
        full_name: str,
        password: str,
        update_password: bool,
    ) -> SuperuserOutcome:
        """Make sure an administrator account exists with these credentials.

        Lives here rather than in ``superuser_seeder`` for two reasons. The
        seeder is infrastructure, and R2 stops infrastructure importing another
        context's entities, so hand-rolling a ``User`` there is not available any
        more. More importantly, the seeder used to spell out ``status=VERIFIED,
        role=ADMIN`` inline, duplicating the "what does an account start as" rule
        that :meth:`User.register` owns. Two places deciding that is how the two
        drift apart.

        A username and an email that belong to *different* accounts is a
        configuration error rather than something to resolve, so it is reported
        as ``CONFLICT`` and nothing is written.
        """
        password_hash = await asyncio.to_thread(hash_password, password)

        async with self.uow:
            by_username = await self.uow.user_repo.get_user_by_username(username)
            by_email = await self.uow.user_repo.get_user_by_email(email)

            if by_username and by_email and by_username.id != by_email.id:
                return SuperuserOutcome(
                    outcome=SuperuserResult.CONFLICT,
                    username=username,
                    email=email,
                )

            user = by_username or by_email

            if user is None:
                created = User(
                    id=str(uuid4()),
                    full_name=full_name,
                    username=username,
                    email=email,
                    gender=GenderEnum.PREFER_NOT_TO_SAY,
                    password_hash=password_hash,
                    status=UserStatus.UNAPPROVED,
                    role=RoleEnum.USER,
                )
                # Seeding an account is an explicit grant of administrator
                # rights, so it is not a registration and does not go through
                # the registration guard.
                created.verify()
                created.role = RoleEnum.ADMIN
                saved = await self.uow.user_repo.add_user(created)
                return SuperuserOutcome(
                    outcome=SuperuserResult.CREATED, username=username, email=email
                )

            changed = False
            if user.role != RoleEnum.ADMIN:
                user.role = RoleEnum.ADMIN
                changed = True
            if not user.is_verified:
                user.verify()
                changed = True
            if update_password:
                user.set_password_hash(password_hash)
                changed = True

            if not changed:
                return SuperuserOutcome(
                    outcome=SuperuserResult.UNCHANGED,
                    username=user.username,
                    email=user.email,
                )

            saved = await self.uow.user_repo.save(user)
            return SuperuserOutcome(
                outcome=SuperuserResult.UPDATED,
                username=saved.username,
                email=saved.email,
            )
