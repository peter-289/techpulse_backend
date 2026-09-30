"""The ``user_sessions`` table's write paths, against a real database.

Why this file exists
--------------------
Phase 6b found that the ``users`` table had write paths which relied on session
autoflush, and nothing in the suite exercised them against a real database. The
same is true of ``user_sessions``, and worse: two of the three mutations are
security-relevant and both are currently silent.

``auth_service._rotate_session`` rewrites ``refresh_token_hash``,
``last_used_at``, ``user_agent`` and ``ip_address`` with no save call at all.
``SessionRepo.revoke_session`` sets ``revoked_at`` the same way. Neither has a
test that would fail if the write were lost.

If a refresh token rotates without persisting, the *old* refresh token keeps
working and the new one handed to the client is never recognised -- rotation
silently stops providing any of its guarantee, and the client cannot tell. If
revocation is lost, logout returns 200 and the session stays usable. Both return
a success response; only a second session can tell the difference.

Every test here reads back through a **new** session, so a mutation that was
never committed cannot pass. Re-reading through the writing session would return
the in-memory object and would pass either way.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.infrastructure.database.db_setup import Base
from app.infrastructure.database.models.session import UserSession as SessionModel
from app.infrastructure.database.models.user import User
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.authentication import auth_service as auth_service_module
from app.modules.security.password_manager import hash_password
from app.modules.shared.enums import RoleEnum, UserStatus

import app.infrastructure.database.models  # noqa: F401  (registers all tables)


class _NoopAbuse:
    """Stands in for ``AbuseProtection`` so no Redis is needed."""

    async def guard_login(self, *args, **kwargs) -> None:
        return None

    async def guard_session_refresh(self, *args, **kwargs) -> None:
        return None

    async def guard_password_reset(self, *args, **kwargs) -> None:
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


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def _seed_user(db, **overrides) -> str:
    from uuid import uuid4

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


async def _seed_session(db, user_id: str, refresh_token: str, **overrides) -> int:
    """Insert a session row directly and return its id."""
    values = {
        "user_id": user_id,
        "refresh_token_hash": _sha(refresh_token),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
    }
    values.update(overrides)

    async with db() as session:
        row = SessionModel(**values)
        session.add(row)
        await session.commit()
        await session.refresh(row)
        return row.id


async def _read_session(db, session_id: int) -> SessionModel:
    """Re-read a session through a brand new session."""
    async with db() as session:
        result = await session.execute(
            select(SessionModel).where(SessionModel.id == session_id)
        )
        return result.scalar_one()


async def _read_sessions_for(db, user_id: str) -> list[SessionModel]:
    async with db() as session:
        result = await session.execute(
            select(SessionModel).where(SessionModel.user_id == user_id)
        )
        return list(result.scalars().all())


def _service(session) -> auth_service_module.AuthService:
    return auth_service_module.AuthService(
        uow=UnitOfWork(session=session), abuse_protection=_NoopAbuse()
    )


# === 1. session creation ===================================================


@pytest.mark.asyncio
async def test_creating_a_session_is_persisted(db) -> None:
    """``_create_session`` is the one path that already committed correctly.

    Pinned anyway: it is the baseline the other two are measured against, and an
    aggregate conversion that broke the working path would otherwise be invisible
    next to the two that were broken.
    """
    user_id = await _seed_user(db)

    async with db() as session:
        service = _service(session)
        refresh_token, created = await service.create_session(
            user_id=user_id, user_agent="pytest", ip_address="203.0.113.5"
        )

    row = await _read_session(db, created.id)
    assert row.user_id == user_id
    assert row.refresh_token_hash == _sha(refresh_token)
    assert row.user_agent == "pytest"
    assert row.ip_address == "203.0.113.5"
    assert row.revoked_at is None
    # The plaintext token must not be stored.
    assert refresh_token not in (row.refresh_token_hash or "")


@pytest.mark.asyncio
async def test_a_created_session_can_be_found_by_its_refresh_hash(db) -> None:
    user_id = await _seed_user(db)

    async with db() as session:
        service = _service(session)
        refresh_token, created = await service.create_session(
            user_id=user_id, user_agent=None, ip_address=None
        )

    async with db() as session:
        found = await UnitOfWork(session=session).session_repo.get_by_refresh_hash(
            _sha(refresh_token)
        )
        assert found is not None
        assert found.id == created.id


# === 2. refresh token rotation =============================================
# The security-relevant one: if this write is lost, the new refresh token is
# never recognised and the old one stays valid forever.


@pytest.mark.asyncio
async def test_rotating_a_session_persists_the_new_refresh_hash(db) -> None:
    user_id = await _seed_user(db)
    old_token = "old-refresh-token"
    session_id = await _seed_session(db, user_id, old_token)

    async with db() as session:
        service = _service(session)
        user, access_token, new_refresh = await service.rotate_session(
            old_token, user_agent="rotated-agent", ip_address="198.51.100.7"
        )

    row = await _read_session(db, session_id)
    assert row.refresh_token_hash == _sha(new_refresh), "the rotation was not committed"
    assert row.refresh_token_hash != _sha(old_token)


@pytest.mark.asyncio
async def test_rotating_persists_last_used_at(db) -> None:
    user_id = await _seed_user(db)
    old_token = "old-refresh-token"
    session_id = await _seed_session(db, user_id, old_token, last_used_at=None)

    async with db() as session:
        service = _service(session)
        before = datetime.now(timezone.utc)
        await service.rotate_session(old_token, user_agent=None, ip_address=None)

    row = await _read_session(db, session_id)
    assert row.last_used_at is not None, "last_used_at was not committed"
    stamp = row.last_used_at
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    assert stamp >= before


@pytest.mark.asyncio
async def test_rotating_updates_the_user_agent_and_ip(db) -> None:
    user_id = await _seed_user(db)
    old_token = "old-refresh-token"
    session_id = await _seed_session(
        db, user_id, old_token, user_agent="original", ip_address="203.0.113.1"
    )

    async with db() as session:
        service = _service(session)
        await service.rotate_session(
            old_token, user_agent="rotated", ip_address="198.51.100.7"
        )

    row = await _read_session(db, session_id)
    assert row.user_agent == "rotated"
    assert row.ip_address == "198.51.100.7"


@pytest.mark.asyncio
async def test_rotating_with_no_agent_keeps_the_previous_value(db) -> None:
    """A rotation without a User-Agent must not blank the recorded one."""
    user_id = await _seed_user(db)
    old_token = "old-refresh-token"
    session_id = await _seed_session(
        db, user_id, old_token, user_agent="original", ip_address="203.0.113.1"
    )

    async with db() as session:
        service = _service(session)
        await service.rotate_session(old_token, user_agent=None, ip_address=None)

    row = await _read_session(db, session_id)
    assert row.user_agent == "original"
    assert row.ip_address == "203.0.113.1"


@pytest.mark.asyncio
async def test_the_rotated_session_keeps_its_id(db) -> None:
    """The access token stays bound to the same session id after rotation."""
    user_id = await _seed_user(db)
    old_token = "old-refresh-token"
    session_id = await _seed_session(db, user_id, old_token)

    async with db() as session:
        service = _service(session)
        _, _, new_refresh = await service.rotate_session(old_token, None, None)

    row = await _read_session(db, session_id)
    assert row.id == session_id
    assert row.refresh_token_hash == _sha(new_refresh)


# === 3. logout revocation ==================================================


@pytest.mark.asyncio
async def test_revoking_a_session_persists_revoked_at(db) -> None:
    """Logout returns 200 whether or not the revocation lands.

    The comment in ``SessionRepo.revoke_session`` records a previous bug where
    logout 500'd before clearing the cookies, leaving the session usable. That
    was fixed. This is the same guarantee from the other side: the write itself
    has never been verified.
    """
    user_id = await _seed_user(db)
    token = "the-refresh-token"
    session_id = await _seed_session(db, user_id, token)

    async with db() as session:
        service = _service(session)
        await service.revoke_session(token)

    row = await _read_session(db, session_id)
    assert row.revoked_at is not None, "the revocation was not committed"


@pytest.mark.asyncio
async def test_a_revoked_session_cannot_be_rotated_afterwards(db) -> None:
    """End-to-end consequence: revocation has to actually take effect."""
    user_id = await _seed_user(db)
    token = "the-refresh-token"
    await _seed_session(db, user_id, token)

    async with db() as session:
        await _service(session).revoke_session(token)

    from app.exceptions.exceptions import UnauthorizedError

    async with db() as session:
        with pytest.raises(UnauthorizedError):
            await _service(session).rotate_session(token, None, None)


@pytest.mark.asyncio
async def test_revoking_an_unknown_session_writes_nothing(db) -> None:
    user_id = await _seed_user(db)
    await _seed_session(db, user_id, "a-real-token")

    async with db() as session:
        await _service(session).revoke_session("never-existed")

    rows = await _read_sessions_for(db, user_id)
    assert len(rows) == 1
    assert rows[0].revoked_at is None


@pytest.mark.asyncio
async def test_revoking_leaves_other_sessions_alone(db) -> None:
    user_id = await _seed_user(db)
    target_id = await _seed_session(db, user_id, "target-token")
    other_id = await _seed_session(db, user_id, "other-token")

    async with db() as session:
        await _service(session).revoke_session("target-token")

    assert (await _read_session(db, target_id)).revoked_at is not None
    assert (await _read_session(db, other_id)).revoked_at is None


# === 4. password reset revokes every session ==============================
# This one is a bulk UPDATE statement, so it was never autoflush-dependent. It is
# covered because a conversion touches this call site too.


@pytest.mark.asyncio
async def test_password_reset_revokes_every_session_for_the_user(db) -> None:
    user_id = await _seed_user(db)
    first = await _seed_session(db, user_id, "first-token")
    second = await _seed_session(db, user_id, "second-token")

    async with db() as session:
        # Through the Unit of Work, as ``reset_password`` does: the bulk UPDATE
        # needs the transaction to commit, and it was never autoflush-dependent.
        async with UnitOfWork(session=session) as uow:
            await uow.session_repo.revoke_user_sessions(
                user_id=user_id, revoked_at=datetime.now(timezone.utc)
            )

    for session_id in (first, second):
        assert (await _read_session(db, session_id)).revoked_at is not None


@pytest.mark.asyncio
async def test_password_reset_does_not_touch_another_users_sessions(db) -> None:
    other_id = await _seed_user(db)
    mine = await _seed_session(db, other_id, "mine")

    async with db() as session:
        async with UnitOfWork(session=session) as uow:
            await uow.session_repo.revoke_user_sessions(
                user_id="somebody-else", revoked_at=datetime.now(timezone.utc)
            )

    assert (await _read_session(db, mine)).revoked_at is None
