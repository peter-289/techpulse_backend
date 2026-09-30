"""Access-token validation, session binding and route authorization tests.

The access token used to be the sole source of truth: ``get_current_user``
returned whatever ``role`` the JWT carried and never touched the database, so a
demoted admin kept admin rights until the token expired and logging out did not
invalidate it. These tests pin the replacement behaviour -- the token proves
*which session and which user*, the database decides *whether and as whom*.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from jose import jwt
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import settings
from app.infrastructure.database.db_setup import Base
from app.infrastructure.database.unit_of_work import UnitOfWork
import app.infrastructure.database.models  # noqa: F401  (registers all tables)
from app.infrastructure.database.models.session import UserSession
from app.infrastructure.database.models.user import User
from app.modules.shared.enums import RoleEnum, UserStatus
from app.modules.security.dependencies import (
    CurrentUser,
    get_current_user,
    resolve_optional_user,
)
from app.modules.security.token_manager import (
    ACCESS_TOKEN_TYPE,
    EMAIL_VERIFICATION_TOKEN_TYPE,
    EXPECTED_ISSUER,
    decode_access_token,
)


class _FakeRequest:
    def __init__(self, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None) -> None:
        self.headers = headers or {}
        self.cookies = cookies or {}


def _access_token(user_id: str, session_id: int, **overrides) -> str:
    payload = {
        "sub": user_id,
        "sid": session_id,
        "typ": ACCESS_TOKEN_TYPE,
        "iss": EXPECTED_ISSUER,
        "iat": datetime.now(timezone.utc),
        "jti": "jti-for-tests",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    payload.update(overrides)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def _seed_user(
    factory,
    *,
    role: RoleEnum = RoleEnum.ADMIN,
    status: UserStatus = UserStatus.VERIFIED,
    revoked: bool = False,
    session_expires_in: timedelta = timedelta(days=1),
):
    user = User(
        id=str(uuid4()),
        full_name="Test User",
        username=f"user_{uuid4().hex[:10]}",
        email=f"{uuid4().hex}@example.com",
        password_hash="$argon2id$fake",
        status=status,
        role=role,
    )
    user_session = UserSession(
        user_id=user.id,
        refresh_token_hash=uuid4().hex,
        expires_at=datetime.now(timezone.utc) + session_expires_in,
        revoked_at=datetime.now(timezone.utc) if revoked else None,
    )
    async with factory() as db:
        db.add(user)
        db.add(user_session)
        await db.commit()
        await db.refresh(user_session)
        return user, user_session


# --- token shape ---------------------------------------------------------


def test_decode_access_token_parses_sub_into_a_uuid_and_keeps_sid() -> None:
    # The dataclass declares user_id: UUID, so a raw string subject silently
    # broke callers that did arithmetic or passed it to UUID-typed APIs.
    user_id = uuid4()
    claims = decode_access_token(_access_token(str(user_id), 4242))
    assert isinstance(claims.user_id, UUID)
    assert claims.user_id == user_id
    assert claims.session_id == 4242


@pytest.mark.parametrize("missing", ["exp", "iat", "iss", "typ", "jti", "sid"])
def test_decode_access_token_requires_every_claim(missing) -> None:
    # jwt.decode only validates exp when the claim is present, so a token minted
    # without it would otherwise be accepted forever.
    payload_claims = decode_access_token(_access_token(str(uuid4()), 1))
    assert payload_claims  # sanity: the full token does decode

    token = _access_token(str(uuid4()), 1)
    decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    decoded.pop(missing)
    stripped = jwt.encode(decoded, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(stripped)
    assert exc_info.value.status_code == 401


def test_decode_access_token_rejects_a_token_of_another_type() -> None:
    # Email-verification and password-reset secrets fall back to SECRET_KEY in a
    # default deployment, so `typ` is what keeps the flows apart.
    token = _access_token(str(uuid4()), 1, typ=EMAIL_VERIFICATION_TOKEN_TYPE)
    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(token)
    assert exc_info.value.status_code == 401


def test_decode_access_token_rejects_a_foreign_issuer() -> None:
    token = _access_token(str(uuid4()), 1, iss="SomebodyElse")
    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(token)
    assert exc_info.value.status_code == 401


@pytest.mark.parametrize("sub", ["", None, "not-a-uuid"])
def test_decode_access_token_rejects_unusable_subjects(sub) -> None:
    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(_access_token(str(sub) if sub is not None else "", 1))
    assert exc_info.value.status_code == 401


# --- server-side revalidation --------------------------------------------


@pytest.mark.asyncio
async def test_role_comes_from_the_database_not_the_token(session_factory) -> None:
    # The regression: a token minted while the user was an admin kept saying
    # ADMIN after they were demoted.
    user, user_session = await _seed_user(session_factory, role=RoleEnum.USER)
    token = _access_token(user.id, user_session.id, role="ADMIN")

    async with session_factory() as db:
        resolved = await get_current_user(_FakeRequest(), token, UnitOfWork(session=db))

    assert resolved.is_admin is False
    assert resolved.role == RoleEnum.USER.value.upper()
    assert resolved.user_id == UUID(user.id)


@pytest.mark.asyncio
async def test_promotion_is_picked_up_on_the_next_request(session_factory) -> None:
    user, user_session = await _seed_user(session_factory, role=RoleEnum.USER)
    token = _access_token(user.id, user_session.id, role="USER")

    async with session_factory() as db:
        assert (await get_current_user(_FakeRequest(), token, UnitOfWork(session=db))).is_admin is False

    async with session_factory() as db:
        db_user = await db.get(User, user.id)
        db_user.role = RoleEnum.ADMIN
        await db.commit()

    async with session_factory() as db:
        assert (await get_current_user(_FakeRequest(), token, UnitOfWork(session=db))).is_admin is True


@pytest.mark.asyncio
async def test_logout_invalidates_the_access_token(session_factory) -> None:
    user, user_session = await _seed_user(session_factory)
    token = _access_token(user.id, user_session.id)

    async with session_factory() as db:
        assert (
            await get_current_user(_FakeRequest(), token, UnitOfWork(session=db))
        ).user_id == UUID(user.id)

    async with session_factory() as db:
        row = await db.get(UserSession, user_session.id)
        row.revoked_at = datetime.now(timezone.utc)
        await db.commit()

    async with session_factory() as db:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(_FakeRequest(), token, UnitOfWork(session=db))
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_expired_session_rejects_the_access_token(session_factory) -> None:
    user, user_session = await _seed_user(session_factory, session_expires_in=timedelta(seconds=-1))
    token = _access_token(user.id, user_session.id)
    async with session_factory() as db:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(_FakeRequest(), token, UnitOfWork(session=db))
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_unverified_account_cannot_use_an_old_token(session_factory) -> None:
    user, user_session = await _seed_user(session_factory, status=UserStatus.SUSPENDED)
    token = _access_token(user.id, user_session.id)
    async with session_factory() as db:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(_FakeRequest(), token, UnitOfWork(session=db))
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_token_for_an_unknown_session_is_rejected(session_factory) -> None:
    _user, _session = await _seed_user(session_factory)
    token = _access_token(str(uuid4()), 999_999)
    async with session_factory() as db:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(_FakeRequest(), token, UnitOfWork(session=db))
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_session_belonging_to_another_user_is_rejected(session_factory) -> None:
    # `sid` and `sub` are validated against each other, so a valid session id
    # cannot be paired with someone else's subject.
    #
    # This test previously minted a token with `user_a`'s subject and `session_a`'s
    # id, decoded it, and asserted the two matched -- which is a statement about
    # the token, not about revalidation. The mismatch it describes was never
    # exercised, so the check could be deleted without failing anything.
    user_a, _session_a = await _seed_user(session_factory)
    _user_b, session_b = await _seed_user(session_factory)
    token = _access_token(user_a.id, session_b.id)
    async with session_factory() as db:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(_FakeRequest(), token, UnitOfWork(session=db))
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_without_a_token_is_unauthorized() -> None:
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(_FakeRequest(), None, None)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_reads_the_access_cookie(session_factory) -> None:
    user, user_session = await _seed_user(session_factory)
    request = _FakeRequest(cookies={settings.ACCESS_COOKIE_NAME: _access_token(user.id, user_session.id)})
    async with session_factory() as db:
        assert (
            await get_current_user(request, None, UnitOfWork(session=db))
        ).user_id == UUID(user.id)


# --- optional resolution (audit attribution) -----------------------------


@pytest.mark.asyncio
async def test_resolve_optional_user_returns_a_current_user(session_factory) -> None:
    # The audit middleware indexed this result, so it must stay a CurrentUser
    # and never a dict.
    user, user_session = await _seed_user(session_factory)
    request = _FakeRequest(cookies={settings.ACCESS_COOKIE_NAME: _access_token(user.id, user_session.id)})
    async with session_factory() as db:
        resolved = await resolve_optional_user(request, UnitOfWork(session=db))
    assert isinstance(resolved, CurrentUser)
    assert resolved.user_id == UUID(user.id)


@pytest.mark.asyncio
async def test_resolve_optional_user_returns_none_instead_of_raising(session_factory) -> None:
    async with session_factory() as db:
        uow = UnitOfWork(session=db)
        assert await resolve_optional_user(_FakeRequest(), uow) is None
        assert await resolve_optional_user(
            _FakeRequest(headers={"authorization": "Bearer garbage"}), uow
        ) is None


# --- route wiring ---------------------------------------------------------


def test_admin_summary_route_requires_the_admin_role() -> None:
    # GET /software-management/admin/summary used get_current_user, so any
    # authenticated non-admin could read platform-wide metrics. Assert against
    # the registered route rather than the helper, so the wiring is covered.
    import app.main as main_module

    route = next(
        route
        for route in main_module.app.routes
        if getattr(route, "path", None) == "/api/v1/software-management/admin/summary"
    )
    sub_dependencies = [
        dependency.call
        for dependency in route.dependant.dependencies
        for sub in dependency.dependencies
    ]
    checkers = [call for call in sub_dependencies if getattr(call, "__name__", "") == "role_checker"]
    assert checkers, "admin/summary has no role_checker dependency"

    with pytest.raises(HTTPException) as exc_info:
        checkers[0](CurrentUser(user_id=uuid4(), role="USER"))
    assert exc_info.value.status_code == 403


def test_software_admin_packages_route_still_requires_admin() -> None:
    import app.main as main_module

    route = next(
        route
        for route in main_module.app.routes
        if getattr(route, "path", None) == "/api/v1/software-management/admin/packages"
    )
    sub_dependencies = [
        dependency.call
        for dependency in route.dependant.dependencies
        for sub in dependency.dependencies
    ]
    assert any(getattr(call, "__name__", "") == "role_checker" for call in sub_dependencies)


def test_resource_write_routes_use_the_admin_role() -> None:
    import app.main as main_module

    for method, path in (("POST", "/api/v1/resources"), ("DELETE", "/api/v1/resources/{slug}")):
        route = next(
            route
            for route in main_module.app.routes
            if getattr(route, "path", None) == path and method in route.methods
        )
        sub_dependencies = [
            dependency.call
            for dependency in route.dependant.dependencies
            for sub in dependency.dependencies
        ]
        checkers = [call for call in sub_dependencies if getattr(call, "__name__", "") == "role_checker"]
        assert checkers, f"{method} {path} has no role_checker dependency"
        with pytest.raises(HTTPException) as exc_info:
            checkers[0](CurrentUser(user_id=uuid4(), role="USER"))
        assert exc_info.value.status_code == 403
        assert checkers[0](CurrentUser(user_id=uuid4(), role="ADMIN")).is_admin is True
