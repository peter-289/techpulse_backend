"""Wiring for the security context, and the decision an access token still needs.

Everything here used to live in ``app/modules/shared/dependencies.py``, a 474-line
file that resolved the database session, the scanner, the storage signer, the AI
provider and the audit service alongside the token handling. The split followed
the ownership those providers already implied: what the security context answers
for lives here, what software management answers for lives in
``app/modules/software_management/dependencies.py``, and the three genuinely
shared things -- the session, the Redis client, the unit of work -- stayed in
``app/modules/shared/dependencies.py``.

The substantive change is :func:`revalidate_access_token`. It used to build
``select(UserSession, User).join(...)`` itself and read ``revoked_at``,
``expires_at`` and ``status`` off ORM rows, which made the request path the last
place in the codebase with no domain model behind it. It now asks two
repositories and decides using the aggregates: validity is
``UserSession.is_usable_at``, and "may this account act" is ``User.is_verified``.
The rules moved; the answers did not change.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import UUID

from fastapi import Depends, HTTPException, Request
from redis.asyncio import Redis

from app.core.config import settings
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.security.abuse_protection import AbuseProtection
from app.modules.security.application.services.audit_service import AuditService
from app.modules.security.domain.ports.alert_thresholds import AlertThresholds
from app.modules.security.token_manager import (
    AccessTokenClaims,
    credentials_exception,
    decode_access_token,
    oauth2_scheme,
)
from app.modules.shared.dependencies import get_redis, get_unit_of_work
from app.modules.shared.enums import RoleEnum

logger = logging.getLogger(__name__)


def _normalize_role(role: str | RoleEnum) -> str:
    """Canonicalise a role to its upper-case string form."""
    if isinstance(role, RoleEnum):
        return str(role.value).upper()
    return str(role).strip().upper()


@dataclass(frozen=True, slots=True)
class CurrentUser:
    user_id: UUID
    role: str

    @property
    def is_admin(self) -> bool:
        return _normalize_role(self.role) == _normalize_role(RoleEnum.ADMIN)


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


async def revalidate_access_token(
    claims: AccessTokenClaims,
    *,
    session_repo: object,
    user_repo: object,
) -> CurrentUser:
    """Turn verified claims into a principal, using the database as the authority.

    The role and account status are read from ``users`` rather than trusted from
    the token, so a demoted or suspended user loses access on their next request
    instead of keeping whatever the token said until it expired. The session is
    also checked, so a revoked session (logout, password reset) kills its access
    token right away.

    Both repositories are typed ``object``, and the calls below are therefore
    structural. The reason is R2, not convenience: a bounded context may not
    import another context's ``domain`` at all, not even its ports, so this
    module cannot name ``SessionRepository`` or ``UserRepository``. The concrete
    :class:`UnitOfWork` satisfies both. Phase 6b and Phase 7a recorded the same
    gap on the write paths; closing it means capability-shaped ports owned by the
    consuming context, which is Phase 9's decision to make.

    The old version of this function issued one joined query. It now issues two:
    the session, then the account, once the session's own ``user_id`` has been
    checked against the token's ``sub``. That keeps a ``sub``/``sid`` mismatch --
    the only case where the account lookup is wasted -- at a single round trip,
    and a live request at two. The alternative is a port method returning the
    account *behind* a session, which puts an authentication-shaped join inside
    the user context for one query per request. Recorded rather than silently
    chosen.
    """
    session = await session_repo.get_by_id(claims.session_id)
    if session is None:
        raise credentials_exception
    if not session.is_usable_at(datetime.now(timezone.utc)):
        raise credentials_exception
    if str(session.user_id) != str(claims.user_id):
        raise credentials_exception

    user = await user_repo.get_user_by_id(claims.user_id)
    if user is None or not user.is_verified:
        raise credentials_exception

    return CurrentUser(user_id=claims.user_id, role=_normalize_role(user.role))


async def resolve_optional_user(request: Request, uow: UnitOfWork) -> CurrentUser | None:
    """Best-effort principal for attribution. Never use for authorization."""
    token = _bearer_from_request(request)
    if not token:
        return None
    try:
        return await _resolve(token, uow)
    except HTTPException:
        return None


async def _resolve(token: str, uow: UnitOfWork) -> CurrentUser:
    """The one place a raw token is turned into a repository-backed lookup."""
    claims = decode_access_token(token)
    return await revalidate_access_token(
        claims,
        session_repo=uow.session_repo,
        user_repo=uow.user_repo,
    )


async def get_current_user_optional(
    request: Request,
    uow: UnitOfWork = Depends(get_unit_of_work),
) -> CurrentUser | None:
    return await resolve_optional_user(request, uow)


# Get the current user from the token sent to them in the header or cookie
# THIS IS A DEPENDENCY
async def get_current_user(
        request: Request,
        token: str = Depends(oauth2_scheme),
        uow: UnitOfWork = Depends(get_unit_of_work),
) -> CurrentUser:
    raw = token or (request.cookies.get(settings.ACCESS_COOKIE_NAME) if request else None)
    if not raw:
        raise credentials_exception
    return await _resolve(raw, uow)


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


# === ABUSE PROTECTION ===
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


# === ALERT THRESHOLDS ===
# Read from the environment here for the same reason the upload limits are read
# at the composition root rather than inside the code that enforces them: the
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