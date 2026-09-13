from jose import JWTError, jwt

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis
from uuid import UUID
from dataclasses import dataclass
from sqlalchemy.ext.asyncio import AsyncSession


from app.core.config import settings

from app.infrastructure.database.db_setup import SessionLocal
from app.infrastructure.redis.client import redis_manager
from .container import storage, signer
from app.modules.security.abuse_protection import AbuseProtection
from app.infrastructure.external_apis.scanner_service.malware_scanner import get_malware_scanner, MalwareScanner
from app.infrastructure.storage.local_storage import DownloadUrlSigner, Storage
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.software_management.application.services.software_service import SoftwareService
from app.modules.software_management.application.services.download_service import DownloadService
from app.modules.software_management.application.services.category_service import CategoryService



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

@dataclass(frozen=True, slots=True)
class CurrentUser:
      user_id: UUID
      role: str


# Get the current user from the token sent to them in the header or cookie
# THIS IS A DEPENDENCY
def get_current_user(
        request: Request,
        token: str = Depends(oauth2_scheme),
) -> CurrentUser:
    try:
        
        if not token:
            token = request.cookies.get(settings.ACCESS_COOKIE_NAME)
        if not token:
            raise credentials_exception
        
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = str(payload.get("sub"))
        role: str = str(payload.get("role"))
        
        if not user_id or not role:
           raise credentials_exception
    except (JWTError, ValueError, TypeError):
        raise credentials_exception
    return CurrentUser(
        user_id=user_id,
        role=role
    )


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
        return {"user_id": user_id,
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
        
        user_id: str = payload["sub"]
        purpose: str = payload["purpose"]
        issuer: str = payload["iss"]

        if purpose != EXPECTED_PURPOSE:
            raise credentials_exception
        if issuer != EXPECTED_ISSUER:
            raise credentials_exception
    except (JWTError, ValueError, TypeError):
        raise credentials_exception 
    return {
        "user_id": user_id,
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
        user_id: str = payload["sub"]
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
    return {"user_id": user_id, "jti": jti, "purpose": purpose, "exp": exp}


# RBAC
def require_role(role: str):
    """Takes in a role and checks it against present role in User object."""
    def role_checker(user: CurrentUser = Depends(get_current_user)):
        if user.role != role:
            print(f"[id]: {user.user_id}")
            print(f"[Role]: {user.role}")
            raise HTTPException(status_code=403, detail="Forbidden!")
        return user
    return role_checker


# Database dependency
async def get_db():
    async with SessionLocal() as session:
        yield session

# === GET REDIS CLIENT ===
def get_redis() -> Redis | None:
    return redis_manager.client

# === GET ABUSE PROTECTION ===
def get_abuse_protection(redis_client=Depends(get_redis)) -> AbuseProtection:
    return AbuseProtection(redis_client)



# === SERVICE DEPENDENCIES ===
def get_scanner() -> MalwareScanner:
    scanner = get_malware_scanner()
    return scanner

# === GET UNIT OF WORK ===
def get_unit_of_work(session: AsyncSession = Depends(get_db)) -> UnitOfWork:
    unit_of_work = UnitOfWork(session=session)
    return unit_of_work

# === GET CATEGORY SERVICE ===
def get_category_service(unit_of_work: UnitOfWork = Depends(get_unit_of_work)) -> CategoryService:
    return CategoryService(unit_of_work=unit_of_work)





# === GET LOCAL STORAGE ===
def get_storage() -> Storage:
    return storage

# === GET HMAC SIGNER ===
def get_signer() -> DownloadUrlSigner:
    return signer

# === GET SOFTWARE SERVICE ===
def get_download_service(
        signer: DownloadUrlSigner = Depends(get_signer),
        unit_of_work: UnitOfWork = Depends(get_unit_of_work),
        storage: Storage = Depends(get_storage),
) -> DownloadService:
    return DownloadService(uow=unit_of_work, url_signer=signer, storage=storage)

# === GET SOFTWARE SERVICE ===
def get_software_service(
        download_service: DownloadService = Depends(get_download_service),
        storage: Storage = Depends(get_storage),
        malware_scanner: MalwareScanner = Depends(get_scanner),
        unit_of_work: UnitOfWork = Depends(get_unit_of_work),
        category_service: CategoryService = Depends(get_category_service),
) -> SoftwareService:
    return SoftwareService(
        download_service=download_service,
        storage=storage, 
        malware_scanner=malware_scanner,
        unit_of_work=unit_of_work,
        category_service=category_service,
        )




