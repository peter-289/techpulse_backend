from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer

from app.core.config import settings

from app.infrastructure.database.db_setup import SessionLocal
from app.modules.security.abuse_protection import abuse_protection
from app.core.config import settings
from app.exceptions.exceptions import PermissionError
from app.infrastructure.database.models.user import User


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


# Email verification
EXPECTED_PURPOSE = "email_verification"
EXPECTED_RESET_PURPOSE = "password_reset"
EXPECTED_ISSUER = "Tech_Pulse_Technologies"


# Credentials exception
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW.Authenticate": "Bearer"}
)


# Get the current user from the token sent to them in the header or cookie
# THIS IS A DEPENDENCY
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


# RBAC
def require_role(role: str):
    """Takes in a role and checks it against present role in User object."""
    def role_checker(user: User = Depends(get_current_user)):
        if user["role"] != role:
            print(f"[Role]: {user['role']}")
            raise HTTPException(status_code=403, detail="Forbidden!")
        return user
    return role_checker


# Database dependency
# Get async database
async def get_db():
    async with SessionLocal() as session:
        yield session