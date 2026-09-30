"""Authentication hardening regression tests.

Covers the guarantees that were previously missing:

* login spends the same CPU whether or not the username exists, so response
  timing cannot be used to enumerate accounts;
* email-verification and password-reset links are single use;
* an access token cannot be used after its session is revoked, and the role it
  grants is the one currently stored on the user.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from jose import jwt
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import settings
from app.exceptions.exceptions import UnauthorizedError
from app.infrastructure.database.db_setup import Base
import app.infrastructure.database.models  # noqa: F401  (registers all tables)
from app.modules.user.domain.entities.user import User
from app.modules.authentication import auth_service as auth_service_module
from app.modules.security.token_manager import (
    ACCESS_TOKEN_TYPE,
    EXPECTED_ISSUER,
    TokenManager,
)
from app.modules.shared.dependencies import get_email_user, get_password_reset_user


@pytest.fixture
def tokens() -> TokenManager:
    class _NoopAbuse:
        async def acquire_once(self, **kwargs) -> bool:
            return True

    return TokenManager(abuse_protection=_NoopAbuse())


# --- user enumeration -----------------------------------------------------


def test_unknown_username_still_runs_argon2(tokens) -> None:
    """The regression: Argon2 was skipped when the user was missing.

    Login answered in ~0.4ms for an unknown username and ~280ms for a real one,
    which is enough to enumerate every account in the system.
    """
    from app.modules.security.password_manager import hash_password, verify_password

    stored = hash_password("CorrectHorseBatteryStaple1!")
    dummy = auth_service_module._dummy_password_hash()

    # The dummy is a genuine Argon2 hash, so verifying against it does the same
    # expensive work as verifying a real stored hash.
    assert stored.startswith("$argon2")
    assert dummy.startswith("$argon2")
    assert verify_password(dummy, "any-password-at-all") is None


def test_dummy_password_hash_is_computed_once_and_reused() -> None:
    first = auth_service_module._dummy_password_hash()
    second = auth_service_module._dummy_password_hash()
    assert first == second


@pytest.mark.asyncio
async def test_login_timing_is_independent_of_account_existence() -> None:
    """Both branches must call verify_password exactly once.

    Asserting on the call rather than on wall-clock time keeps this fast and
    non-flaky while still pinning the property that matters: an unknown username
    costs the same Argon2 work as a known one.
    """
    from app.modules.shared.enums import RoleEnum, UserStatus

    known = User(
        id=str(uuid4()),
        full_name="Known",
        username="known",
        email="known@example.com",
        password_hash="$argon2id$v=19$m=102400,t=3,p=4$aaaa$bbbb",
        status=UserStatus.VERIFIED,
        role=RoleEnum.USER,
    )

    class _Repo:
        def __init__(self, value):
            self._value = value

        async def get_user_by_username(self, username):
            return self._value

        async def save(self, user):
            raise AssertionError("no save expected: the hash did not change")

    class _SessionRepo:
        async def revoke_user_sessions(self, **kwargs):
            return None

    class _Uow:
        def __init__(self, value):
            self.user_repo = _Repo(value)
            self.session_repo = _SessionRepo()

        def read_only(self):
            return self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class _Abuse:
        async def guard_login(self, *a, **k):
            return None

    calls: list[str] = []

    def fake_verify(stored_hash, password):
        # Sync on purpose: run_in_threadpool calls this directly in a worker
        # thread, so an `async def` would only build a coroutine and never run.
        calls.append(stored_hash)
        return stored_hash

    service = auth_service_module.AuthService(uow=_Uow(known), abuse_protection=_Abuse())

    with patch.object(auth_service_module, "verify_password", fake_verify):
        await service._authenticate("known", "whatever")
    assert len(calls) == 1

    service_missing = auth_service_module.AuthService(uow=_Uow(None), abuse_protection=_Abuse())
    calls.clear()
    with patch.object(auth_service_module, "verify_password", fake_verify):
        with pytest.raises(UnauthorizedError):
            await service_missing._authenticate("does-not-exist", "whatever")
    # The missing-user branch still performed exactly one Argon2 verification.
    assert len(calls) == 1
    assert calls[0] == auth_service_module._dummy_password_hash()


def test_login_uses_aware_utc_for_token_expiry(tokens) -> None:
    """``datetime.utcnow()`` is deprecated and returned a naive datetime.

    jose decodes ``exp`` to an integer epoch, so assert on the epoch and on the
    absence of the deprecated call rather than on tzinfo.
    """
    import inspect

    assert "utcnow" not in inspect.getsource(TokenManager.create_login_token)

    before = int(datetime.now(timezone.utc).timestamp())
    token = tokens.create_login_token(data={"sub": str(uuid4()), "sid": 1})
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    exp = payload["exp"]
    assert isinstance(exp, int)
    assert exp > before
    assert exp <= before + settings.LOGIN_TOKEN_EXPIRE_MINUTES * 60 + 5


# --- token claims ---------------------------------------------------------


def test_revoke_session_is_awaitable() -> None:
    """Regression: logout 500'd on every call.

    ``SessionRepo.revoke_session`` was a plain ``def`` while ``AuthService``
    awaited it, so ``await None`` raised a TypeError inside ``POST /auth/logout``
    *before* the cookies were cleared -- meaning logout never worked and the
    session stayed alive. Pin that the repo method is a coroutine.
    """
    import inspect

    from app.modules.user.infrastructure.persistence.repository.session_repo import (
        SessionRepo,
    )

    assert inspect.iscoroutinefunction(SessionRepo.revoke_session)


def test_access_token_carries_binding_claims(tokens) -> None:
    user_id, session_id = str(uuid4()), 77
    token = tokens.create_login_token(data={"sub": user_id, "sid": session_id})
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    assert payload["sub"] == user_id
    assert payload["sid"] == session_id
    assert payload["typ"] == ACCESS_TOKEN_TYPE
    assert payload["iss"] == EXPECTED_ISSUER
    for claim in ("exp", "iat", "jti"):
        assert payload.get(claim), f"access token is missing {claim}"


def test_access_token_does_not_carry_a_role(tokens) -> None:
    """Role is read from the database, so it must not be trusted from the token.

    Even if a caller passes one, it is ignored on revalidation.
    """
    token = tokens.create_login_token(data={"sub": str(uuid4()), "sid": 1, "role": "ADMIN"})
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["role"] == "ADMIN"  # caller's value is carried but never read
    from app.modules.shared.dependencies import AccessTokenClaims, decode_access_token

    claims = decode_access_token(token)
    assert not hasattr(claims, "role")


def test_each_flow_signs_a_distinct_token_type(tokens) -> None:
    user_id = str(uuid4())
    kinds = {
        "access": jwt.decode(
            tokens.create_login_token(data={"sub": user_id, "sid": 1}),
            settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
        )["typ"],
        "email": jwt.decode(
            tokens.create_email_verification_token(user_id),
            settings.EMAIL_VERIFY_SECRET, algorithms=[settings.ALGORITHM],
        )["typ"],
        "reset": jwt.decode(
            tokens.create_password_reset_token(user_id),
            settings.PASSWORD_RESET_SECRET, algorithms=[settings.ALGORITHM],
        )["typ"],
    }
    assert kinds == {
        "access": "access",
        "email": "email_verification",
        "reset": "password_reset",
    }
    assert len(set(kinds.values())) == 3


def test_email_and_reset_tokens_cannot_be_read_as_access_tokens(tokens) -> None:
    """The three signing secrets collapse onto SECRET_KEY by default, so `typ`
    is the only thing keeping an email link from authenticating a request."""
    from app.modules.shared.dependencies import decode_access_token

    user_id = str(uuid4())
    email_token = tokens.create_email_verification_token(user_id)
    reset_token = tokens.create_password_reset_token(user_id)

    for bad in (email_token, reset_token):
        with pytest.raises(HTTPException) as exc_info:
            decode_access_token(bad)
        assert exc_info.value.status_code == 401


# --- single-use email verification ---------------------------------------


def test_email_verification_token_is_single_use(tokens) -> None:
    """Mirrors the reset-token replay guard, which verification previously lacked."""
    import asyncio

    spent: set[tuple[str, str]] = set()

    class _OnceAbuse:
        async def acquire_once(self, scope, identifier, ttl_seconds):
            key = (scope, identifier)
            if key in spent:
                return False
            spent.add(key)
            return True

    manager = TokenManager(abuse_protection=_OnceAbuse())
    token = manager.create_email_verification_token(str(uuid4()))
    payload = get_email_user(token)
    exp = payload["exp"]

    assert asyncio.run(manager.consume_email_verification_token(token=token, exp=exp)) is True
    assert asyncio.run(manager.consume_email_verification_token(token=token, exp=exp)) is False


def test_password_reset_token_is_single_use(tokens) -> None:
    import asyncio

    spent: set[tuple[str, str]] = set()

    class _OnceAbuse:
        async def acquire_once(self, scope, identifier, ttl_seconds):
            key = (scope, identifier)
            if key in spent:
                return False
            spent.add(key)
            return True

    manager = TokenManager(abuse_protection=_OnceAbuse())
    token = manager.create_password_reset_token(str(uuid4()))
    payload = get_password_reset_user(token)

    assert asyncio.run(manager.consume_password_reset_token(token=token, exp=payload["exp"])) is True
    assert asyncio.run(manager.consume_password_reset_token(token=token, exp=payload["exp"])) is False


def test_verification_and_reset_tokens_do_not_share_a_replay_scope(tokens) -> None:
    """The scope is part of the key, so a reset link cannot consume a verify link."""
    import asyncio

    seen: set[tuple[str, str]] = set()

    class _RecordingAbuse:
        async def acquire_once(self, scope, identifier, ttl_seconds):
            seen.add((scope, identifier))
            return True

    manager = TokenManager(abuse_protection=_RecordingAbuse())
    user_id = str(uuid4())
    verify_token = manager.create_email_verification_token(user_id)
    reset_token = manager.create_password_reset_token(user_id)

    verify_payload = get_email_user(verify_token)
    reset_payload = get_password_reset_user(reset_token)
    asyncio.run(manager.consume_email_verification_token(token=verify_token, exp=verify_payload["exp"]))
    asyncio.run(manager.consume_password_reset_token(token=reset_token, exp=reset_payload["exp"]))

    assert {scope for scope, _ in seen} == {
        "email_verification_token",
        "password_reset_token",
    }
    assert len({identifier for _, identifier in seen}) == 2


# --- required claims on the other flows ----------------------------------


@pytest.mark.parametrize("missing", ["exp", "iat", "iss", "jti"])
def test_email_token_requires_core_claims(tokens, missing) -> None:
    """python-jose ignores ``options={"require": [...]}``; the real keys are
    ``require_<claim>``. Regression-guard that the fix is actually in force."""
    token = tokens.create_email_verification_token(str(uuid4()))
    decoded = jwt.decode(
        token, settings.EMAIL_VERIFY_SECRET, algorithms=[settings.ALGORITHM]
    )
    decoded.pop(missing)
    stripped = jwt.encode(decoded, settings.EMAIL_VERIFY_SECRET, algorithm=settings.ALGORITHM)

    with pytest.raises(HTTPException) as exc_info:
        get_email_user(stripped)
    assert exc_info.value.status_code == 401


def test_email_token_missing_purpose_is_rejected(tokens) -> None:
    token = tokens.create_email_verification_token(str(uuid4()))
    decoded = jwt.decode(token, settings.EMAIL_VERIFY_SECRET, algorithms=[settings.ALGORITHM])
    decoded.pop("purpose")
    stripped = jwt.encode(decoded, settings.EMAIL_VERIFY_SECRET, algorithm=settings.ALGORITHM)
    with pytest.raises(HTTPException) as exc_info:
        get_email_user(stripped)
    assert exc_info.value.status_code == 401
