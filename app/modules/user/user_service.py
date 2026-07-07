## =====================================================
# === New Modular Version ===

import logging
from fastapi.concurrency import run_in_threadpool
from fastapi import Request
import uuid
from datetime import datetime, timezone

from .user_schema import UserCreate
from app.infrastructure.database.models.user import User
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.security.password_manager import hash_password
from .rules import map_integrity_error, validate_password_strength
from app.exceptions.exceptions import ConflictError, NotFoundError
from app.modules.security.abuse_protection import AbuseProtection
from app.modules.shared.dependencies import get_abuse_protection


from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)

class UserService:
    def __init__(self, uow: UnitOfWork, abuse_protection: AbuseProtection):
        self.uow = uow
        self._abuse = abuse_protection

    # Create user
    async def create_user(self, request: Request, payload: UserCreate):
       async with self.uow:
            # Validate password strength
            validate_password_strength(payload.password)
            # Hash password
            pass_hash = await run_in_threadpool(hash_password, payload.password)

            # create user
            user = User(
                id=str(uuid.uuid4()),
                full_name=payload.full_name,
                username=payload.username,
                email=payload.email,
                gender=payload.gender,
                password_hash=pass_hash,
            )
            ip = self._abuse.get_client_ip(request)
            await self._abuse.guard_registration(ip=ip)
            try:
                user = await self.uow.user_repo.add_user(user)
            except IntegrityError as exc:
                raise self._map_user_integrity_error(exc) from exc
            return user

    # List users
    async def list_users(self, limit: int = 100) -> list[User] | None:
       async with self.uow.read_only():
            
            cursor = datetime.now()
            users = await self.uow.user_repo.list_users(cursor=cursor, limit=limit)
            logger.debug("Fetched users page", extra={"cursor": cursor, "limit": limit})
            return users

    # Get user by id
    async def get_user_by_id(self, user_id: uuid.UUID) -> User:
        async with self.uow.read_only():
            user = await self.uow.user_repo.get_user_by_id(str(user_id))
            if not user:
                raise NotFoundError("User not found.")
            return user

    def _map_user_integrity_error(self, exc: IntegrityError) -> ConflictError:
        message = str(getattr(exc, "orig", exc)).lower()
        map_integrity_error(message=message)
        return ConflictError("Username or email already exists.")

