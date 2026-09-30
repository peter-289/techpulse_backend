from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Callable

from jose import JWTError, jwt

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis
from uuid import UUID
from dataclasses import dataclass
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


from app.core.config import settings

from app.infrastructure.database.db_setup import SessionLocal
from app.infrastructure.database.models.session import UserSession
from app.infrastructure.database.models.user import User
from app.infrastructure.redis.client import redis_manager
from .container import storage, signer
from .enums import RoleEnum, UserStatus
from app.modules.security.abuse_protection import AbuseProtection
from app.modules.security.application.services.audit_service import AuditService
from app.modules.security.domain.ports.alert_thresholds import AlertThresholds
from app.infrastructure.external_apis.ai_support.http_support_ai import HttpSupportAI
from app.modules.user.domain.ports.support_ai import SupportAI, SupportAIConfig
from app.modules.security.token_manager import (
    ACCESS_TOKEN_TYPE,
    EMAIL_VERIFICATION_TOKEN_TYPE,
    PASSWORD_RESET_TOKEN_TYPE,
)
from app.infrastructure.external_apis.scanner_service.malware_scanner import get_malware_scanner, MalwareScanner
from app.infrastructure.events.logging_event_publisher import LoggingDomainEventPublisher
from app.infrastructure.storage.local_artifact_stager import LocalArtifactStager
from app.modules.software_management.domain.ports.artifact_stager import ArtifactStager, UploadLimits
from app.modules.software_management.domain.ports.event_publisher import DomainEventPublisher
from app.modules.software_management.domain.ports.download_signer import DownloadSigner
from app.modules.software_management.domain.ports.storage import Storage
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.software_management.application.services.software_service import SoftwareService
from app.modules.software_management.application.services.download_service import DownloadService
from app.modules.software_management.application.services.category_service import CategoryService


logger = logging.getLogger(__name__)


def _normalize_role(role: str | RoleEnum) -> str:
    """Canonicalise a role to its upper-case string form."""
    if isinstance(role, RoleEnum):
        return str(role.value).upper()
    return str(role).strip().upper()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


# Email verification
EXPECTED_PURPOSE = "email_verification"
EXPECTED_RESET_PURPOSE = "password_reset"
EXPECTED_ISSUER = "Tech_Pulse_Technologies"


# Credentials exception
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"}
)


# Database dependency. Declared before the auth dependencies because those take
# it as a sub-dependency and default arguments are evaluated at definition time.
async def get_db():
    async with SessionLocal() as session:
        yield session


@dataclass(frozen=True, slots=True)
class CurrentUser:
      user_id: UUID
      role: str

      @property
      def is_admin(self) -> bool:
            return _normalize_role(self.role) == _normalize_role(RoleEnum.ADMIN)


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    """What a verified access token asserts, before any database lookup."""
    user_id: UUID
    session_id: int


ACCESS_TOKEN_REQUIRED_CLAIMS = {
    "require_exp": True,
    "require_iat": True,
    "require_sub": True,
    "require_iss": True,
    "require_jti": True,
}


def decode_access_token(token: str) -> AccessTokenClaims:
    """Verify an access token's signature and shape.

    ``exp``/``iat``/``sub``/``iss``/``jti`` are required, so a token missing
    them is rejected rather than silently accepted -- ``jwt.decode`` only
    validates ``exp`` when the claim happens to be present. Note python-jose
    spells these ``require_<claim>``; a ``require=[...]`` list is silently
    ignored. ``typ`` has no ``require_`` equivalent, so it is checked here.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options=dict(ACCESS_TOKEN_REQUIRED_CLAIMS),
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


def _bearer_from_request(request: Request) -> str | None:
    if not request:
        return None
    token = request.cookies.get(settings.ACCESS_COOKIE_NAME)
    if token:
        return token
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return None


def _as_utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


async def revalidate_access_token(
    claims: AccessTokenClaims,
    session: AsyncSession,
) -> CurrentUser:
    """Turn verified claims into a principal, using the database as the authority.

    The role and account status are read from ``users`` rather than trusted from
    the token, so a demoted or suspended user loses access on their next request
    instead of keeping whatever the token said until it expired. The session is
    also checked, so a revoked session (logout, password reset) kills its access
    token right away.
    """
    stmt = (
        select(UserSession, User)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.id == claims.session_id)
    )
    row = (await session.execute(stmt)).one_or_none()
    if row is None:
        raise credentials_exception

    user_session, user = row
    if user_session.revoked_at is not None:
        raise credentials_exception

    expires_at = _as_utc(user_session.expires_at)
    if expires_at is None or expires_at <= datetime.now(timezone.utc):
        raise credentials_exception

    if str(user_session.user_id) != str(claims.user_id):
        raise credentials_exception

    if user.status != UserStatus.VERIFIED:
        raise credentials_exception

    return CurrentUser(user_id=UUID(str(user.id)), role=_normalize_role(user.role))


async def resolve_optional_user(request: Request, session: AsyncSession) -> CurrentUser | None:
    """Best-effort principal for attribution. Never use for authorization."""
    token = _bearer_from_request(request)
    if not token:
        return None
    try:
        return await revalidate_access_token(decode_access_token(token), session)
    except HTTPException:
        return None


async def get_current_user_optional(
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> CurrentUser | None:
    return await resolve_optional_user(request, session)


# Get the current user from the token sent to them in the header or cookie
# THIS IS A DEPENDENCY
async def get_current_user(
        request: Request,
        token: str = Depends(oauth2_scheme),
        session: AsyncSession = Depends(get_db),
) -> CurrentUser:
    raw = token or (request.cookies.get(settings.ACCESS_COOKIE_NAME) if request else None)
    if not raw:
        raise credentials_exception
    return await revalidate_access_token(decode_access_token(raw), session)
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        sub = payload.get("sub")
        role = payload.get("role")
        if not sub or not role:
            return None
        return CurrentUser(
            user_id=sub if isinstance(sub, UUID) else UUID(str(sub)),
            role=str(role),
        )
    except (JWTError, ValueError, TypeError, AttributeError):
        return None


# Get a user assocciated with the token sent to them
def get_email_user(token: str):
    try:
        payload = jwt.decode(
            token, 
            settings.EMAIL_VERIFY_SECRET, 
            algorithms=[settings.ALGORITHM],
            options=dict(ACCESS_TOKEN_REQUIRED_CLAIMS)
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
        "exp": exp
    }

# Get a user associated with the password reset token sent to them
def get_password_reset_user(token: str):
    try:
        payload = jwt.decode(
            token,
            settings.PASSWORD_RESET_SECRET,
            algorithms=[settings.ALGORITHM],
            options=dict(ACCESS_TOKEN_REQUIRED_CLAIMS),
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


# RBAC
def require_role(*roles: str | RoleEnum) -> Callable[..., CurrentUser]:
    """Build a dependency that admits only callers holding one of ``roles``.

    Accepts either :class:`RoleEnum` members or strings and normalises both, so
    ``require_role("admin")`` and ``require_role(RoleEnum.ADMIN)`` behave
    identically instead of silently failing on a case mismatch. An unknown role
    raises at import time rather than locking every request out.
    """
    normalized = tuple(_normalize_role(role) for role in roles)
    if not normalized:
        raise ValueError("require_role() requires at least one role")

    def role_checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if _normalize_role(user.role) not in normalized:
            logger.info(
                "Access denied",
                extra={
                    "user_id": str(user.user_id),
                    "role": user.role,
                    "required_roles": list(normalized),
                },
            )
            raise HTTPException(status_code=403, detail="Forbidden!")
        return user

    return role_checker


# === GET REDIS CLIENT ===
def get_redis() -> Redis | None:
    return redis_manager.client

# === GET ABUSE PROTECTION ===
# AbuseProtection keeps rate-limit buckets as instance state, so a per-request
# instance would reset the limiter on every call. A single process-wide instance
# is shared instead; it is rebuilt only if the Redis client is swapped out (e.g.
# the connection is established lazily during startup).
_abuse_protection: AbuseProtection | None = None
_abuse_protection_lock = threading.Lock()


def _get_abuse_protection(redis_client: Redis | None) -> AbuseProtection:
    global _abuse_protection

    current = _abuse_protection
    if current is not None and current.redis_client is redis_client:
        return current

    with _abuse_protection_lock:
        current = _abuse_protection
        if current is None or current.redis_client is not redis_client:
            current = AbuseProtection(redis_client)
            _abuse_protection = current
            logger.debug(
                "Created AbuseProtection instance (redis=%s)",
                "yes" if redis_client is not None else "no",
            )
    return current


def get_abuse_protection(redis_client=Depends(get_redis)) -> AbuseProtection:
    return _get_abuse_protection(redis_client)



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
def get_signer() -> DownloadSigner:
    return signer

# === GET DOMAIN EVENT PUBLISHER ===
event_publisher = LoggingDomainEventPublisher()


def get_event_publisher() -> DomainEventPublisher:
    return event_publisher

# === GET SOFTWARE SERVICE ===
def get_download_service(
        signer: DownloadSigner = Depends(get_signer),
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
        event_publisher: DomainEventPublisher = Depends(get_event_publisher),
) -> SoftwareService:
    return SoftwareService(
        download_service=download_service,
        storage=storage, 
        malware_scanner=malware_scanner,
        unit_of_work=unit_of_work,
        category_service=category_service,
        event_publisher=event_publisher,
        )

# === GET ARTIFACT STAGER ===
# The upload limit is resolved here, at the composition root, rather than read
# out of the environment by the code that enforces it. That is what lets the
# stager take a UploadLimits value object and keeps app.core out of the
# application layer.
upload_limits = UploadLimits(
    max_size_bytes=settings.PACKAGE_UPLOAD_MAX_SIZE_BYTES,
)

stager = LocalArtifactStager()


def get_artifact_stager() -> ArtifactStager:
    return stager


# === ALERT THRESHOLDS ===
# Read from the environment here for the same reason as upload_limits above: the
# detection rules enforce these numbers, and a use-case that reads them from a
# global is a use-case that cannot be told "fail after two attempts".
alert_thresholds = AlertThresholds(
    login_failures=settings.ALERT_LOGIN_FAILURE_THRESHOLD,
    access_denied=settings.ALERT_ACCESS_DENIED_THRESHOLD,
    lookback=timedelta(minutes=settings.ALERT_LOOKBACK_MINUTES),
    dedup=timedelta(minutes=settings.ALERT_DEDUP_MINUTES),
)


def get_audit_thresholds() -> AlertThresholds:
    return alert_thresholds


# === GET AUDIT SERVICE ===
def get_audit_service(
    unit_of_work: UnitOfWork = Depends(get_unit_of_work),
    thresholds: AlertThresholds = Depends(get_audit_thresholds),
) -> AuditService:
    return AuditService(uow=unit_of_work, thresholds=thresholds)


# === GET SUPPORT AI ===
# The only place that reads the AI provider's settings. The service receives a
# ``SupportAI`` and cannot see the endpoint, the key or the model; it supplies
# the system prompt itself, because that is support policy rather than
# configuration.
def get_support_ai() -> SupportAI:
    return HttpSupportAI(
        SupportAIConfig(
            base_url=settings.AI_BASE_URL,
            api_key=settings.AI_API_KEY,
            model=settings.SUPPORT_CHAT_MODEL,
        )
    )




