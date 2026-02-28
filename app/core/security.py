from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status, Request

from app.exceptions.exceptions import DomainError
from app.core.abuse_protection import abuse_protection
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


# Create login token
def create_login_token(data: dict, expires_delta: timedelta | None = None)->str:
    """Creates a login token"""
    
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.LOGIN_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp":expire})

    token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token


# Create email verification token
def create_email_verification_token(user_id: int)->str:
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
def create_password_reset_token(user_id: int) -> str:
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

# Get the current user from the token sent to them in the header or cookie
def get_current_user(
        request: Request,
        token: str = Depends(oauth2_scheme),
):
    try:
        
        if not token:
            token = request.cookies.get(settings.ACCESS_COOKIE_NAME)
        if not token:
            raise credentials_exception
        
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = int(payload.get("sub"))
        role: str = str(payload.get("role"))
        
        if not user_id or not role:
           raise credentials_exception
    except (JWTError, ValueError, TypeError):
        raise credentials_exception
    return {
        "user_id": user_id,
        "role": role
    }

def get_current_user_optional(request: Request) -> dict | None:
    token = request.cookies.get(settings.ACCESS_COOKIE_NAME) if request else None
    if not token:
        auth_header = request.headers.get("authorization") if request else None
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        role = payload.get("role")
        if not user_id or not role:
            return None
        return {"user_id": int(user_id),
                 "role": str(role)
                 }
    except (JWTError, ValueError, TypeError):
        return None


# Get a user assocciated with the token sent to them
def get_email_user(token: str):
    try:
        payload = jwt.decode(
            token, 
            settings.EMAIL_VERIFY_SECRET, 
            algorithms=[settings.ALGORITHM],
            options={"require": ["sub", "exp","iat", "purpose", "iss" ]}
            )
        
        user_id: int = payload["sub"]
        purpose: str = payload["purpose"]
        issuer: str = payload["iss"]

        if purpose != EXPECTED_PURPOSE:
            raise credentials_exception
        if issuer != EXPECTED_ISSUER:
            raise credentials_exception
    except (JWTError, ValueError, TypeError):
        raise credentials_exception 
    return {
        "user_id": int(user_id),
        "purpose": purpose
    }

# Get a user associated with the password reset token sent to them
def get_password_reset_user(token: str):
    try:
        payload = jwt.decode(
            token,
            settings.PASSWORD_RESET_SECRET,
            algorithms=[settings.ALGORITHM],
            options={"require": ["sub", "exp", "iat", "jti", "purpose", "iss"]},
        )
        user_id: int = payload["sub"]
        jti: str = payload["jti"]
        purpose: str = payload["purpose"]
        issuer: str = payload["iss"]
        exp = payload["exp"]
        if purpose != EXPECTED_RESET_PURPOSE:
            raise credentials_exception
        if issuer != EXPECTED_ISSUER:
            raise credentials_exception
    except (JWTError, ValueError, TypeError):
        raise credentials_exception
    return {"user_id": int(user_id), "jti": jti, "purpose": purpose, "exp": exp}

# Consume password reset token to prevent replay attacks
def consume_password_reset_token(token: str, exp: int | float | datetime) -> bool:
    """Marks a reset token as used so it cannot be replayed."""
    if isinstance(exp, datetime):
        expiry_ts = int(exp.timestamp())
    else:
        expiry_ts = int(exp)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    ttl_seconds = max(1, expiry_ts - now_ts)
    token_fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return abuse_protection.set_once(
        scope="password_reset_token",
        key=token_fingerprint,
        ttl_seconds=ttl_seconds,
    )


# Check for admin access
def admin_access(
        current_user: dict = Depends(get_current_user)
)->dict:
    if current_user.get("role") != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required!"
        )
    return current_user

# Password strenght validation
def validate_password_strength(new_password: str) -> None:
    """Validate password strength according to defined criteria.""" 
 # Validate password strength
    if not isinstance(new_password, str):
            raise DomainError("Password must be text")
    if len(new_password) < 8:
            raise DomainError("Password must be at least 8 characters long")
    if not any(char.isdigit() for char in new_password):
            raise DomainError("Password must contain at least one digit")
    if not any(char.isupper() for char in new_password):
            raise DomainError("Password must contain at least one uppercase letter")
    if not any(char.islower() for char in new_password):
            raise DomainError("Password must contain at least one lowercase letter")
