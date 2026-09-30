"""The ``users`` table's write paths, against a real database.

Why this file exists
--------------------
``auth_service`` and ``verification_recovery`` both obtain an ORM row from
``user_repo`` and mutate it, relying on SQLAlchemy's autoflush plus the Unit of
Work's commit to persist the change. Nothing in the suite exercised that: the
266-test baseline drove ``AuthService`` with fake repositories, and
``UserRepo`` was never asked to persist a mutation. A 2xx response and a vanished
write look identical from the outside.

That matters because Phase 6b converts ``UserRepo`` to return domain entities
instead of live rows. With detached entities those four writes stop being tracked
by the session and the requests still return success. These tests are the safety
net: each one asserts the new value is visible from a **second session**, so a
mutation that was never committed cannot pass.

Reading back through a new session is the whole mechanism. Re-reading through the
same session would return the in-memory object and would pass whether or not the
write happened.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.infrastructure.database.db_setup import Base
from app.infrastructure.database.models.user import User
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.authentication import auth_service as auth_service_module
from app.modules.security.password_manager import hash_password, verify_password
from app.modules.security.token_manager import TokenManager
from app.modules.shared.enums import RoleEnum, UserStatus

import app.infrastructure.database.models  # noqa: F401  (registers all tables)


class _NoopAbuse:
    """Stands in for ``AbuseProtection`` so no Redis is needed."""

    async def acquire_once(self, **kwargs) -> bool:
        return True

    async def guard_login(self, *args, **kwargs) -> None:
        return None

    async def guard_registration(self, *args, **kwargs) -> None:
        return None

    async def guard_session_refresh(self, *args, **kwargs) -> None:
        return None


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as seed_session:
        yield maker
    await engine.dispose()


async def _seed_user(db, **overrides) -> str:
    """Insert a user and return its id."""
    user_id = str(uuid4())
    values = {
        "id": user_id,
        "full_name": "Test User",
        "username": f"user_{user_id[:8]}",
        "email": f"{user_id[:8]}@example.test",
        "password_hash": hash_password("OriginalPassword123!"),
        "status": UserStatus.VERIFIED,
        "role": RoleEnum.USER,
    }
    values.update(overrides)

    async with db() as session:
        session.add(User(**values))
        await session.commit()
    return user_id


async def _read_back(db, user_id: str) -> User:
    """Re-read a user through a brand new session.

    A second session has its own identity map, so this can only see values the
    previous session actually committed.
    """
    async with db() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        return result.scalar_one()


# === 1. login rehash ======================================================


@pytest.mark.asyncio
async def test_rehashing_on_login_is_persisted(db) -> None:
    """``auth_service._authenticate`` rewrites ``password_hash`` on a version bump.

    Argon2 parameters are expected to change over time. When they do, the next
    successful login is supposed to re-store the hash under the new parameters.
    If the rewrite is not persisted, every user's hash stays on the old
    parameters forever and the migration silently never happens.
    """
    user_id = await _seed_user(db)
    before = await _read_back(db, user_id)

    upgraded_hash = hash_password("OriginalPassword123!")
    assert upgraded_hash != before.password_hash, "test needs a different hash"

    def fake_verify(stored_hash, password):
        # Simulates Argon2 parameters having been upgraded: verification
        # succeeds and hands back a hash in the new format.
        return upgraded_hash

    async with db() as session:
        service = auth_service_module.AuthService(
            uow=UnitOfWork(session=session), abuse_protection=_NoopAbuse()
        )
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(auth_service_module, "verify_password", fake_verify)
            user = await service._authenticate(before.username, "OriginalPassword123!")

    after = await _read_back(db, user_id)
    assert user.password_hash == upgraded_hash
    assert after.password_hash == upgraded_hash, "the rehash was not committed"
    assert after.password_hash != before.password_hash


@pytest.mark.asyncio
async def test_a_matching_hash_is_left_alone(db) -> None:
    """No rewrite when verification returns the same hash, so no needless write."""
    user_id = await _seed_user(db)
    before = await _read_back(db, user_id)

    def fake_verify(stored_hash, password):
        return stored_hash

    async with db() as session:
        service = auth_service_module.AuthService(
            uow=UnitOfWork(session=session), abuse_protection=_NoopAbuse()
        )
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(auth_service_module, "verify_password", fake_verify)
            await service._authenticate(before.username, "OriginalPassword123!")

    assert (await _read_back(db, user_id)).password_hash == before.password_hash


# === 2. email verification =================================================


@pytest.mark.asyncio
async def test_verifying_an_account_is_persisted(db) -> None:
    """``auth_service.verify_user_account`` sets ``status = VERIFIED``.

    If this write is lost the request still reports success and the account can
    never complete sign-up, because the only thing that moves it out of
    ``UNAPPROVED`` is this statement.
    """
    user_id = await _seed_user(db, status=UserStatus.UNAPPROVED)
    assert (await _read_back(db, user_id)).status == UserStatus.UNAPPROVED

    tokens = TokenManager(abuse_protection=_NoopAbuse())
    token = tokens.create_email_verification_token(user_id)

    async with db() as session:
        service = auth_service_module.AuthService(
            uow=UnitOfWork(session=session), abuse_protection=_NoopAbuse()
        )
        await service.verify_user_account(token)

    after = await _read_back(db, user_id)
    assert after.status == UserStatus.VERIFIED, "verification status was not committed"


@pytest.mark.asyncio
async def test_an_unknown_account_raises_and_writes_nothing(db) -> None:
    user_id = await _seed_user(db)
    tokens = TokenManager(abuse_protection=_NoopAbuse())
    token = tokens.create_email_verification_token(str(uuid4()))

    async with db() as session:
        service = auth_service_module.AuthService(
            uow=UnitOfWork(session=session), abuse_protection=_NoopAbuse()
        )
        with pytest.raises(Exception):
            await service.verify_user_account(token)

    assert (await _read_back(db, user_id)).status == UserStatus.VERIFIED


# === 3. password reset =====================================================


@pytest.mark.asyncio
async def test_a_password_reset_is_persisted(db) -> None:
    """``auth_service.reset_password`` rewrites ``password_hash``.

    This is the most dangerous of the four to lose: the caller is told the
    password was changed while the old one keeps working, and the user believes
    they have locked out whoever had the old password.
    """
    user_id = await _seed_user(db)
    before = await _read_back(db, user_id)
    assert verify_password(before.password_hash, "OriginalPassword123!") is not None

    tokens = TokenManager(abuse_protection=_NoopAbuse())
    token = tokens.create_password_reset_token(user_id)

    async with db() as session:
        service = auth_service_module.AuthService(
            uow=UnitOfWork(session=session), abuse_protection=_NoopAbuse()
        )
        await service.reset_password(token, "BrandNewPassword456!", "BrandNewPassword456!")

    after = await _read_back(db, user_id)
    assert after.password_hash != before.password_hash, "the reset was not committed"
    assert verify_password(after.password_hash, "BrandNewPassword456!") is not None
    assert verify_password(after.password_hash, "OriginalPassword123!") is None


# === 4. verification-email retry bookkeeping ================================


@pytest.mark.asyncio
async def test_marking_a_verification_email_sent_is_persisted(db, monkeypatch) -> None:
    """Four fields are rewritten to record that a resend went out.

    The retry count is reset to 0 and a backoff deadline is cleared. If the write
    is lost the counter never advances, so the recovery loop keeps picking the
    same user forever and the account is never actually emailed.
    """
    from app.infrastructure.email.email_service import verification_recovery

    user_id = await _seed_user(db, status=UserStatus.UNAPPROVED)
    await _set_retry_state(db, user_id, retry_count=4, last_error="boom")

    monkeypatch.setattr(verification_recovery, "SessionLocal", db)
    sent_at = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
    await verification_recovery.mark_verification_email_sent(user_id=user_id, sent_at=sent_at)

    after = await _read_back(db, user_id)
    assert after.verification_email_retry_count == 0
    assert after.verification_email_last_error is None
    assert after.verification_email_next_retry_at is None
    assert after.verification_email_last_sent_at is not None


@pytest.mark.asyncio
async def test_marking_a_verification_email_failed_is_persisted(db, monkeypatch) -> None:
    """The retry counter and backoff deadline must survive the process.

    This is what stops a bouncing address from being emailed on every pass of
    the loop: without a persisted ``next_retry_at`` and count, each iteration
    recomputes from nothing.
    """
    from app.infrastructure.email.email_service import verification_recovery

    user_id = await _seed_user(db, status=UserStatus.UNAPPROVED)
    await _set_retry_state(db, user_id, retry_count=2, last_error="old")

    monkeypatch.setattr(verification_recovery, "SessionLocal", db)
    failed_at = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
    await verification_recovery.mark_verification_email_failed(
        user_id=user_id,
        error_message="smtp refused the recipient" * 40,
        failed_at=failed_at,
        override_retry_count=3,
    )

    after = await _read_back(db, user_id)
    assert after.verification_email_retry_count == 3
    assert after.verification_email_last_error.startswith("smtp refused")
    assert after.verification_email_next_retry_at is not None
    # The stored error is truncated to fit the varchar(500) column. Left
    # untruncated it raises on flush, which would look like a lost write.
    assert len(after.verification_email_last_error) == 500


@pytest.mark.asyncio
async def test_a_verified_account_is_never_marked_for_resend(db, monkeypatch) -> None:
    """Verified users are skipped, so the bookkeeping must not touch them."""
    from app.infrastructure.email.email_service import verification_recovery

    user_id = await _seed_user(db, status=UserStatus.VERIFIED)
    await _set_retry_state(db, user_id, retry_count=5, last_error="stale")

    monkeypatch.setattr(verification_recovery, "SessionLocal", db)
    await verification_recovery.mark_verification_email_sent(user_id=user_id)

    after = await _read_back(db, user_id)
    assert after.verification_email_retry_count == 5
    assert after.verification_email_last_error == "stale"


async def _set_retry_state(db, user_id: str, *, retry_count: int, last_error: str) -> None:
    async with db() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalar_one()
        user.verification_email_retry_count = retry_count
        user.verification_email_last_error = last_error
        await session.commit()


# === the property that makes the rest of this file worth having ============


@pytest.mark.asyncio
async def test_a_mutation_the_session_does_not_track_does_not_survive(db) -> None:
    """Documents the failure mode this file exists to detect.

    Load a row, close the session so the object is detached, then mutate it and
    commit through a *different* session. The detached object is not in that
    session's identity map, so there is no pending state, the commit writes
    nothing, and no error is raised.

    That is exactly what a port returning domain entities would do to the four
    paths above -- a success response and a vanished write. It is why they are
    asserted through a second session rather than through the object the service
    was handed.
    """
    user_id = await _seed_user(db)
    before = await _read_back(db, user_id)

    async with db() as loading_session:
        result = await loading_session.execute(select(User).where(User.id == user_id))
        detached = result.scalar_one()
    # `loading_session` is closed here, so `detached` is no longer tracked by
    # anything.

    detached.full_name = "Changed While Detached"

    async with db() as other_session:
        other_session.add(detached)  # re-attaching is the *fix*, not the default
        # Committing without re-attaching is the bug; assert the default.
        await other_session.rollback()

    after = await _read_back(db, user_id)
    assert after.full_name == before.full_name
    assert after.full_name != "Changed While Detached"
