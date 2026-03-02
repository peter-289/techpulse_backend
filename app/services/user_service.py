import logging

from app.schemas.user import UserCreate
from app.exceptions.exceptions import ConflictError
from app.core.hashing import hash_password
from app.models.user import User
from app.core.unit_of_work import UnitOfWork
from app.core.security import validate_password_strength

from sqlalchemy.exc import IntegrityError
from app.exceptions.exceptions import NotFoundError

logger = logging.getLogger(__name__)


class UserService:
    def __init__(self, uow: UnitOfWork):
        self.uow = uow
    
    # Create user
    def create_user(self, payload: UserCreate):
        with self.uow:
            # Validate password strength
            validate_password_strength(payload.password)
            # Hash password
            pass_hash = hash_password(payload.password)
            # Check for existing email
            existing_user = self.uow.user_repo.get_user_by_email(payload.email)
            if not existing_user:
                raise NotFoundError("User not found.")
            if existing_user.email == payload.email:
                raise ConflictError("Email already exists.")
            if existing_user.username == payload.username:
                raise ConflictError("Username already exists.")
            # create user
            user = User(
                full_name=payload.full_name,
                username=payload.username,
                email=payload.email,
                gender=payload.gender,
                password_hash=pass_hash,
            )
            try:
                user = self.uow.user_repo.add_user(user)
            except IntegrityError as exc:
                raise self._map_user_integrity_error(exc) from exc
            return user
        
    # List users
    def list_users(self, cursor: int | None = None, limit: int = 100) -> list[User]:
        with self.uow.read_only():
            users = self.uow.user_repo.list_users(cursor=cursor, limit=limit)
            logger.debug("Fetched users page", extra={"cursor": cursor, "limit": limit, "count": len(users)})
            return users

    # Get user by id
    def get_user_by_id(self, user_id: int) -> User:
        with self.uow.read_only():
            user = self.uow.user_repo.get_user_by_id(user_id)
            if not user:
                raise NotFoundError("User not found")
            return user

    def _map_user_integrity_error(self, exc: IntegrityError) -> ConflictError:
        message = str(getattr(exc, "orig", exc)).lower()
        if "username" in message:
            return ConflictError("Username already exists.")
        if "email" in message:
            return ConflictError("Email already exists.")
        return ConflictError("Username or email already exists.")
