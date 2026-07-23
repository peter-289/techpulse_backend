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
    headers={"WWW.Authenticate": "Bearer"}
)

# Email verification
EXPECTED_PURPOSE = "email_verification"
EXPECTED_RESET_PURPOSE = "password_reset"
EXPECTED_ISSUER = "Tech_Pulse_Technologies"


class TokenManager:
    def __init__(self, abuse_protection: AbuseProtection):
        self._abuse = abuse_protection

    # Create login token
    def create_login_token(self, data: dict, expires_delta: timedelta | None = None)->str:
        """Creates a login token"""
    
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.LOGIN_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp":expire})
     
        token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return token


# Create email verification token
    def create_email_verification_token(self, user_id: int)->str:
          """Creates an email verification token"""
          now = datetime.now(timezone.utc)
          expire = now + timedelta(minutes=settings.EMAIL_TOKEN_EXPIRE_MINUTES)
          # Payload includes user ID, expiration time, issued at time, purpose, and issuer
          payload = {
              "sub": str(user_id),
              "exp": expire,
              "iat": now,
              "purpose": EXPECTED_PURPOSE,
              "iss": EXPECTED_ISSUER
          }
          token = jwt.encode(payload, settings.EMAIL_VERIFY_SECRET, algorithm=settings.ALGORITHM)
          return token

    # Create password reset token
    def create_password_reset_token(self, user_id: int) -> str:
        """Creates a password reset token."""
        now = datetime.now(timezone.utc)
        expire = now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
        payload = {
        "sub": str(user_id),
        "exp": expire,
        "iat": now,
        "jti": secrets.token_urlsafe(16),
        "purpose": EXPECTED_RESET_PURPOSE,
        "iss": EXPECTED_ISSUER,
          }
        return jwt.encode(payload, settings.PASSWORD_RESET_SECRET, algorithm=settings.ALGORITHM)


    # Consume password reset token to prevent replay attacks
    async def consume_password_reset_token(self, token: str, exp: int | float | datetime) -> bool:
              """Marks a reset token as used so it cannot be replayed."""
              if isinstance(exp, datetime):
                     expiry_ts = int(exp.timestamp())
              else:
                     expiry_ts = int(exp)
        

              now_ts = int(datetime.now(timezone.utc).timestamp())
              ttl_seconds = max(1, expiry_ts - now_ts)
              token_fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
              return await self._abuse.acquire_once(
                      scope="password_reset_token",
                      identifier=token_fingerprint,
                      ttl_seconds=ttl_seconds,
        )




