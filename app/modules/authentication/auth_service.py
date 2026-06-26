from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import logging
from fastapi.concurrency import run_in_threadpool

from app.modules.user.rules import validate_password_strength
from app.modules.security.password_manager import hash_password, verify_password
from app.modules.security.token_manager import TokenManager
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.exceptions.exceptions import UnauthorizedError, DomainError, NotFoundError, UnauthorizedError
from app.modules.shared.enums import UserStatus
from app.infrastructure.database.models.session import UserSession
from app.infrastructure.email.email_service.email_worker import queue_verification_email
from app.infrastructure.email.email_service.email_service import send_password_reset_email
from app.core.config import settings
from app.modules.shared.dependencies import get_email_user, get_password_reset_user, get_abuse_protection
from app.infrastructure.database.models.user import User
from app.modules.security.abuse_protection import AbuseProtection

from sqlalchemy.exc import SQLAlchemyError

# Set up logging
logger = logging.getLogger(__name__)

class AuthService:
    def __init__(self, uow: UnitOfWork, abuse_protection: AbuseProtection):
        self.uow = uow # Context manager
        self._abuse = abuse_protection
        self._tokens = TokenManager(abuse_protection=abuse_protection)
    
    # Login API
    async def login(self, username: str, password: str, ip: str):
        """Rate limited login API."""
        await self._abuse.guard_login(ip, username)
        user, token = await self._authenticate(username, password)
        return user, token
    

    # Authenticate user and return a user and a token
    async def _authenticate(self, username: str, password: str):
        # Normalize username and check if the user actually passes it. The same with password.
        normalized_username = (username or "").strip()
        if not normalized_username:
            raise UnauthorizedError("Username is required")
        if not isinstance(password, str) or password == "":
            raise UnauthorizedError("Password is required")

        try:
           async with self.uow:
                # Fetch user and perform security checks
                user = await self.uow.user_repo.get_user_by_username(normalized_username)
                verified_hash =  await run_in_threadpool(verify_password, user.password_hash, password) if user else None
                
                if not user or not verified_hash:
                    raise DomainError("Invalid username or password")
                
                if user.status != UserStatus.VERIFIED:
                    raise UnauthorizedError("Email not approved")
             
                # Opportunistically upgrade hash parameters on successful login.
                if verified_hash != user.password_hash:
                    user.password_hash = verified_hash

                payload = {
                    "sub": str(user.id),
                    "role": user.role.value
                    if hasattr(user.role, "value") 
                    else str(user.role)
                }
                token = self._tokens.create_login_token(data=payload)
        except DomainError:
            raise UnauthorizedError("Invalid username or password")
        except SQLAlchemyError as e: 
            raise DomainError("Database error") from e
        return user, token
    

    # Verify user account by email
    async def verify_user_account(self, token: str):
        """Verify user account."""
        # Get user from email token, raise UnauthorizedError if no user is found
        user = get_email_user(token=token)
        if not user:
            raise UnauthorizedError("Invalid token.")
        async with self.uow:
            # Fetch a user from db
            user_acc = await self.uow.user_repo.get_user_by_id(user["user_id"])
            if not user_acc:
                raise UnauthorizedError("No account associated with this user.")
            # Mark account as verified
            user_acc.status = UserStatus.VERIFIED
    

    # Enqueue a verification email           
    def enqueue_verification_email(self, background_tasks, payload) -> None:
        """Enqueue verification email."""
        try:
            token = self._tokens.create_email_verification_token(payload.id)
            queue_verification_email(
                background_tasks=background_tasks,
                token=token,
                email=payload.email,
                name=payload.full_name,
                user_id=payload.id,
            )
            
            logger.info("Email dispatched.")
        except DomainError as e:
            raise e
    
    # Create session and apply rate limiting
    async def create_session(self, user_id: int, user_agent: str | None, ip_address: str | None):
        """Create session and apply rate limit."""
        await self._abuse.guard_session_refresh(ip=ip_address)
        refresh_token, session = await self._create_session(user_id, user_agent, ip_address)
        return refresh_token, session 
    

    # Create a user session
    async def _create_session(self, user_id: int, user_agent: str | None, ip_address: str | None):
        refresh_token = secrets.token_urlsafe(32)
        refresh_hash = self._hash_refresh_token(refresh_token)
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        session = UserSession(
            user_id=user_id,
            refresh_token_hash=refresh_hash,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        async with self.uow:
            session = await self.uow.session_repo.add_session(session)
        return refresh_token, session

    # Request password reset and apply rate limiting.
    async def request_password_reset(self, email: str, background_tasks) -> str:
          """Request password reset and apply rate limt."""
          await self._abuse.guard_password_reset(email)
          return await self._request_password_reset(email=email, background_tasks=background_tasks)
    
    # Request password reset
    async def _request_password_reset(self, email: str, background_tasks) -> str:
        # Intentional generic response to avoid account enumeration.
        normalized_email = (email or "").strip().lower()
        if not normalized_email:
            return "If the e-mail is registered, you will receive a reset link."

        # Placeholder for future email validity integration.
        if not self._is_email_valid_for_delivery(normalized_email):
          return "If the e-mail is registered, you will receive a reset link."

        async with self.uow.read_only():
            user = await self.uow.user_repo.get_user_by_email(normalized_email)
        if not user:
            return "If the e-mail is registered, you will receive a reset link."
       
        # Create a password reset token
        token = self._tokens.create_password_reset_token(user.id)
        
        
        # add a to send a reset token
        background_tasks.add_task(
            send_password_reset_email,
            token,
            user.email,
            user.full_name,
        )
        logger.info("Email dispatched.")
        return "If email is registered you will recieve an email with a reset link."


    async def reset_password(self, token: str, new_password: str, confirm_password: str) -> User:
        """Reset password."""
        if new_password != confirm_password:
            raise UnauthorizedError("Passwords do not match")
        validate_password_strength(new_password)
       
        payload = get_password_reset_user(token=token)
        if not await self._tokens.consume_password_reset_token(token=token, exp=payload["exp"]):
            raise UnauthorizedError("Reset token has already been used")
        async with self.uow:
            user = await self.uow.user_repo.get_user_by_id(payload["user_id"])
            if not user:
                raise UnauthorizedError("Invalid token")
            user.password_hash = await run_in_threadpool(hash_password, new_password)
            await self.uow.session_repo.revoke_user_sessions(
                user_id=user.id,
                revoked_at=datetime.now(timezone.utc),
            )
        return user

    # Rotate sessions and apply rate limiting
    async def rotate_session(self, refresh_token: str, user_agent: str | None, ip_address: str | None):
           """Rotate session and apply rate limiting."""
           await self._abuse.guard_session_refresh(ip=ip_address)

           user, access_token, new_refresh = await self._rotate_session(refresh_token, user_agent, ip_address)
           return user, access_token, new_refresh

    # Rotate sessions
    async def _rotate_session(self, refresh_token: str, user_agent: str | None, ip_address: str | None):
        refresh_hash = self._hash_refresh_token(refresh_token)
        now = datetime.now(timezone.utc)
        async with self.uow:
            session = await self.uow.session_repo.get_by_refresh_hash(refresh_hash)
            expires_at = self._as_utc(session.expires_at) if session else None
            if not session or session.revoked_at or not expires_at or expires_at <= now:
                raise UnauthorizedError("Invalid or expired session")

            user = await self.uow.user_repo.get_user_by_id(session.user_id)
            if not user:
                raise NotFoundError("User not found")
            if user.status != UserStatus.VERIFIED:
                raise UnauthorizedError("Email not approved")

            new_refresh = secrets.token_urlsafe(32)
            session.refresh_token_hash = self._hash_refresh_token(new_refresh)
            session.last_used_at = now
            session.user_agent = user_agent or session.user_agent
            session.ip_address = ip_address or session.ip_address

        payload = {"sub": str(user.id), "role": user.role.value if hasattr(user.role, "value") else str(user.role)}
        access_token = self._tokens.create_login_token(data=payload)
        return user, access_token, new_refresh
    

    # Revoke a session
    async def revoke_session(self, refresh_token: str) -> None:
        """Revoke user sessions."""
        refresh_hash = self._hash_refresh_token(refresh_token)
        now = datetime.now(timezone.utc)
        async with self.uow:
            session = await self.uow.session_repo.get_by_refresh_hash(refresh_hash)
            if not session:
                return
            await self.uow.session_repo.revoke_session(session=session, revoked_at=now)
    
    # Hash the refresh token
    def _hash_refresh_token(self, refresh_token: str) -> str:
        """Hashes refresh token."""
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
