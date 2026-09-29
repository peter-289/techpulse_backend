from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from fastapi.security import OAuth2PasswordBearer
from fastapi import  HTTPException, status


from app.modules.security.abuse_protection import AbuseProtection
from app.core.config import settings


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

# Credentials exception
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"}
)

# Email verification
EXPECTED_PURPOSE = "email_verification"
EXPECTED_RESET_PURPOSE = "password_reset"
EXPECTED_ISSUER = "Tech_Pulse_Technologies"

# Token types. The ``typ`` claim keeps a token from one flow unusable in another
# even when a deployment has collapsed the signing secrets onto ``SECRET_KEY``,
# which ``EMAIL_VERIFY_SECRET`` and ``PASSWORD_RESET_SECRET`` still do by default.
ACCESS_TOKEN_TYPE = "access"
EMAIL_VERIFICATION_TOKEN_TYPE = "email_verification"
PASSWORD_RESET_TOKEN_TYPE = "password_reset"


class TokenManager:
    def __init__(self, abuse_protection: AbuseProtection):
        self._abuse = abuse_protection

    def create_login_token(self, data: dict, expires_delta: timedelta | None = None) -> str:
        """Creates a login token.

        Always carries ``exp``/``iat``/``iss``/``typ``/``jti`` plus the ``sid``
        of the session the token belongs to, so revoking that session
        invalidates the access token immediately instead of leaving it usable
        until it expires on its own.
        """
        now = datetime.now(timezone.utc)
        expire = now + (expires_delta or timedelta(minutes=settings.LOGIN_TOKEN_EXPIRE_MINUTES))

        to_encode = dict(data)
        to_encode.update(
            {
                "exp": expire,
                "iat": now,
                "iss": EXPECTED_ISSUER,
                "typ": ACCESS_TOKEN_TYPE,
                "jti": secrets.token_urlsafe(16),
            }
        )
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    def create_email_verification_token(self, user_id: str) -> str:
        """Creates an email verification token."""
        now = datetime.now(timezone.utc)
        expire = now + timedelta(minutes=settings.EMAIL_TOKEN_EXPIRE_MINUTES)
        payload = {
            "sub": str(user_id),
            "exp": expire,
            "iat": now,
            "jti": secrets.token_urlsafe(16),
            "typ": EMAIL_VERIFICATION_TOKEN_TYPE,
            "purpose": EXPECTED_PURPOSE,
            "iss": EXPECTED_ISSUER,
        }
        return jwt.encode(payload, settings.EMAIL_VERIFY_SECRET, algorithm=settings.ALGORITHM)

    def create_password_reset_token(self, user_id: str) -> str:
        """Creates a password reset token."""
        now = datetime.now(timezone.utc)
        expire = now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
        payload = {
            "sub": str(user_id),
            "exp": expire,
            "iat": now,
            "jti": secrets.token_urlsafe(16),
            "typ": PASSWORD_RESET_TOKEN_TYPE,
            "purpose": EXPECTED_RESET_PURPOSE,
            "iss": EXPECTED_ISSUER,
        }
        return jwt.encode(payload, settings.PASSWORD_RESET_SECRET, algorithm=settings.ALGORITHM)

    async def consume_password_reset_token(self, token: str, exp: int | float | datetime) -> bool:
        """Marks a reset token as used so it cannot be replayed."""
        return await self._consume_once(
            scope="password_reset_token",
            token=token,
            exp=exp,
        )

    async def consume_email_verification_token(self, token: str, exp: int | float | datetime) -> bool:
        """Marks a verification token as used so a leaked link cannot be replayed."""
        return await self._consume_once(
            scope="email_verification_token",
            token=token,
            exp=exp,
        )

    async def _consume_once(self, scope: str, token: str, exp: int | float | datetime) -> bool:
        """Single-use gate keyed on the token fingerprint, expiring with the token."""
        if isinstance(exp, datetime):
            expiry_ts = int(exp.timestamp())
        else:
            expiry_ts = int(exp)

        now_ts = int(datetime.now(timezone.utc).timestamp())
        ttl_seconds = max(1, expiry_ts - now_ts)
        token_fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return await self._abuse.acquire_once(
            scope=scope,
            identifier=token_fingerprint,
            ttl_seconds=ttl_seconds,
        )
