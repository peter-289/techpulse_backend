from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import logging

from app.core.security import (
    create_login_token,
    create_email_verification_token,
    create_password_reset_token,
    consume_password_reset_token,
    get_email_user,
    get_password_reset_user,
    validate_password_strength,
)
from app.core.hashing import hash_password, verify_password
from app.core.unit_of_work import UnitOfWork
from app.exceptions.exceptions import ValidationError, DomainError, NotFoundError
from app.models.enums import UserStatus
from app.models.session import UserSession
from app.services.email_service.email_worker import queue_verification_email
from app.services.email_service.email_service import send_password_reset_email
from app.core.config import settings

from sqlalchemy.exc import SQLAlchemyError

class AuthService:
    def __init__(self, uow: UnitOfWork):
        self.uow = uow # Context manager
    
    # Authenticate user and return a user and a token
    def authenticate_user(self, username: str, password: str):
        normalized_username = (username or "").strip()
        if not normalized_username:
            raise ValidationError("Username is required")
        if not isinstance(password, str) or password == "":
            raise ValidationError("Password is required")

        try:
            with self.uow:
                # Fetch user and perform security checks
                user = self.uow.user_repo.get_user_by_username(normalized_username)
                verified_hash = verify_password(user.password_hash, password) if user else None
                if not user or not verified_hash:
                    raise ValidationError("Invalid username or password")
                logging.warning("Email verification disabled, enable it at auth_service")
                # if user.status != UserStatus.VERIFIED:
                    # raise ValidationError("Email not approved")
             
                # Opportunistically upgrade hash parameters on successful login.
                if verified_hash != user.password_hash:
                    user.password_hash = verified_hash

                payload = {
                    "sub": str(user.id),
                    "role": user.role.value if hasattr(user.role, "value") else str(user.role)
                }
                token = create_login_token(data=payload)
        except RuntimeError:
            raise ValidationError("Invalid username or password")
        except SQLAlchemyError as e: 
            raise DomainError("Database error") from e
        return user, token
    

    # Verify user account by email
    def verify_user_account(self, token: str):
        user = get_email_user(token=token)
        if not user:
            raise ValidationError("Invalid token")
        with self.uow:
            user_acc = self.uow.user_repo.get_user_by_id(user["user_id"])
            if not user_acc:
                raise ValidationError("No account associated with user")
            # Mark as verified
            user_acc.status = UserStatus.VERIFIED
    

    # Enqueue a verification email           
    def enqueue_verification_email(self, background_tasks, payload) -> None:
        try:
            token = create_email_verification_token(payload.id)
            queue_verification_email(
                background_tasks=background_tasks,
                token=token,
                email=payload.email,
                name=payload.full_name,
                user_id=payload.id,
            )
        except DomainError as e:
            raise e

    def create_session(self, user_id: int, user_agent: str | None, ip_address: str | None):
        refresh_token = secrets.token_urlsafe(32)
        refresh_hash = self._hash_refresh_token(refresh_token)
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        session = UserSession( # pragma no cover - not easily testable without DB access
            user_id=user_id,
            refresh_token_hash=refresh_hash,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        with self.uow:
            session = self.uow.session_repo.add_session(session)
        return refresh_token, session

    def request_password_reset(self, email: str, background_tasks) -> str:
        # Intentional generic response to avoid account enumeration.
        normalized_email = (email or "").strip().lower()
        if not normalized_email:
            return "If the e-mail is registered, you will receive a reset link."

        # Placeholder for future email validity integration.
        if not self._is_email_valid_for_delivery(normalized_email):
            return "If the e-mail is registered, you will receive a reset link."

        with self.uow.read_only():
            user = self.uow.user_repo.get_user_by_email(normalized_email)
        if not user:
            return "If the e-mail is registered, you will receive a reset link."

        token = create_password_reset_token(user.id)
        background_tasks.add_task(
            send_password_reset_email,
            token,
            user.email,
            user.full_name,
        )
        return "If the e-mail is registered, you will receive a reset link."

    def reset_password(self, token: str, new_password: str, confirm_password: str) -> None:
        if new_password != confirm_password:
            raise ValidationError("Passwords do not match")
        validate_password_strength(new_password)

        payload = get_password_reset_user(token=token)
        if not consume_password_reset_token(token=token, exp=payload["exp"]):
            raise ValidationError("Reset token has already been used")
        with self.uow:
            user = self.uow.user_repo.get_user_by_id(payload["user_id"])
            if not user:
                raise ValidationError("Invalid token")
            user.password_hash = hash_password(new_password)
            self.uow.session_repo.revoke_user_sessions(
                user_id=user.id,
                revoked_at=datetime.now(timezone.utc),
            )

    def rotate_session(self, refresh_token: str, user_agent: str | None, ip_address: str | None):
        refresh_hash = self._hash_refresh_token(refresh_token)
        now = datetime.now(timezone.utc)
        with self.uow:
            session = self.uow.session_repo.get_by_refresh_hash(refresh_hash)
            expires_at = self._as_utc(session.expires_at) if session else None
            if not session or session.revoked_at or not expires_at or expires_at <= now:
                raise ValidationError("Invalid or expired session")

            user = self.uow.user_repo.get_user_by_id(session.user_id)
            if not user:
                raise NotFoundError("User not found")
            if user.status != UserStatus.VERIFIED:
                raise ValidationError("Email not approved")

            new_refresh = secrets.token_urlsafe(32)
            session.refresh_token_hash = self._hash_refresh_token(new_refresh)
            session.last_used_at = now
            session.user_agent = user_agent or session.user_agent
            session.ip_address = ip_address or session.ip_address

        payload = {"sub": str(user.id), "role": user.role.value if hasattr(user.role, "value") else str(user.role)}
        access_token = create_login_token(data=payload)
        return user, access_token, new_refresh

    def revoke_session(self, refresh_token: str) -> None:
        refresh_hash = self._hash_refresh_token(refresh_token)
        now = datetime.now(timezone.utc)
        with self.uow:
            session = self.uow.session_repo.get_by_refresh_hash(refresh_hash)
            if not session:
                return
            self.uow.session_repo.revoke_session(session=session, revoked_at=now)

    def _hash_refresh_token(self, refresh_token: str) -> str:
        return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()

    @staticmethod
    def _as_utc(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            # Some DB backends (e.g., SQLite) return naive datetimes.
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _is_email_valid_for_delivery(self, email: str) -> bool:
        # SMTP/email legitimacy validation hook can be plugged in here later.
        return bool(email and "@" in email)
