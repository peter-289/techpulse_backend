from jose import JWTError, jwt
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from uuid import UUID
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

# ``exp``/``iat``/``sub``/``iss``/``jti`` are required on every token this module
# reads back, so a token missing any of them is rejected rather than silently
# accepted -- ``jwt.decode`` only validates ``exp`` when the claim is present.
# Note python-jose spells these ``require_<claim>``; a ``require=[...]`` list is
# silently ignored.
REQUIRED_CLAIMS = {
    "require_exp": True,
    "require_iat": True,
    "require_sub": True,
    "require_iss": True,
    "require_jti": True,
}


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    """What a verified access token asserts, before any database lookup."""

    user_id: UUID
    session_id: int


def decode_access_token(token: str) -> AccessTokenClaims:
    """Verify an access token's signature and shape.

    Returns the subject and the session the token is bound to. It says nothing
    about whether either is still valid: that is a database question, answered by
    the security context's revalidation.

    ``typ`` has no ``require_`` equivalent, so it is checked here.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options=dict(REQUIRED_CLAIMS),
        )
        if payload.get("typ") != ACCESS_TOKEN_TYPE:
            raise credentials_exception
        if payload.get("iss") != EXPECTED_ISSUER:
            raise credentials_exception
        return AccessTokenClaims(
            user_id=UUID(str(payload["sub"])),
            session_id=int(payload["sid"]),
        )
    except (JWTError, ValueError, TypeError, KeyError, AttributeError):
        raise credentials_exception


def decode_email_verification_token(token: str) -> dict:
    """Verify an email-verification token and return the claims it carries.

    Named ``decode_*`` rather than the ``get_email_user`` this replaced because it
    returns the token's claims and never loads an account: reading the account is
    the caller's next step, against the user context's port.
    """
    try:
        payload = jwt.decode(
            token,
            settings.EMAIL_VERIFY_SECRET,
            algorithms=[settings.ALGORITHM],
            options=dict(REQUIRED_CLAIMS),
        )
        user_id: str = payload["sub"]
        purpose: str = payload["purpose"]
        issuer: str = payload["iss"]
        exp = payload["exp"]

        if payload.get("typ") != EMAIL_VERIFICATION_TOKEN_TYPE:
            raise credentials_exception
        if purpose != EXPECTED_PURPOSE:
            raise credentials_exception
        if issuer != EXPECTED_ISSUER:
            raise credentials_exception
    except (JWTError, ValueError, TypeError, KeyError):
        raise credentials_exception
    return {
        "user_id": user_id,
        "purpose": purpose,
        "exp": exp,
    }


def decode_password_reset_token(token: str) -> dict:
    """Verify a password-reset token and return the claims it carries.

    Carries ``jti`` as well, because the reset flow records the token id so a
    second use of the same link can be refused.
    """
    try:
        payload = jwt.decode(
            token,
            settings.PASSWORD_RESET_SECRET,
            algorithms=[settings.ALGORITHM],
            options=dict(REQUIRED_CLAIMS),
        )
        user_id: str = payload["sub"]
        jti: str = payload["jti"]
        purpose: str = payload["purpose"]
        issuer: str = payload["iss"]
        exp = payload["exp"]
        if payload.get("typ") != PASSWORD_RESET_TOKEN_TYPE:
            raise credentials_exception
        if purpose != EXPECTED_RESET_PURPOSE:
            raise credentials_exception
        if issuer != EXPECTED_ISSUER:
            raise credentials_exception
    except (JWTError, ValueError, TypeError, KeyError):
        raise credentials_exception
    return {"user_id": user_id, "jti": jti, "purpose": purpose, "exp": exp}


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
