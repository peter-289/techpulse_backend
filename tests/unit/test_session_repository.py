"""Tests for the session persistence adapter and its mapper.

Real SQLite rather than a mock session, for the same reason as the user
repository tests: the thing worth checking is SQL-level, namely that ``save``
updates the existing row instead of inserting a second one. Two counts answer
that and a mocked session cannot.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.infrastructure.database.db_setup import Base
from app.infrastructure.database.models.session import UserSession as SessionModel
from app.modules.user.domain.entities.user_session import UserSession
from app.modules.user.domain.exceptions import SessionRepositoryUnavailableError
from app.modules.user.infrastructure.persistence.mappers.session_mapper import (
    to_domain,
    to_model,
)
from app.modules.user.infrastructure.persistence.repository.session_repo import (
    SQLAlchemySessionRepository,
)

import app.infrastructure.database.models  # noqa: F401  (registers all tables)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


def _session(**overrides) -> UserSession:
    base = dict(
        user_id="user-1",
        refresh_token_hash="hash-1",
        expires_at=NOW + timedelta(days=7),
    )
    base.update(overrides)
    return UserSession(**base)


def _repo(session) -> SQLAlchemySessionRepository:
    return SQLAlchemySessionRepository(session)


class TestMapper:
    def test_round_trip_preserves_every_mutable_field(self) -> None:
        original = _session(
            id=7,
            last_used_at=NOW,
            revoked_at=NOW,
            user_agent="agent",
            ip_address="203.0.113.5",
        )
        assert to_domain(to_model(original)) == original

    def test_to_domain_does_not_normalise_a_naive_timestamp(self) -> None:
        """The mapper is a plain field copy; normalising is the entity's job.

        SQLite has no timezone type, so a stored value reads back naive. Passing
        that through unchanged and letting the entity's ``_as_utc`` normalise at
        comparison time is the convention the Phase 6b entities already follow
        (``software.py``, ``audit_event.py``). The consequence worth recording is
        that an entity read from the database can hold a naive ``expires_at``,
        which is why ``is_expired_at`` must not compare raw.
        """
        model = to_model(_session(id=1))
        model.expires_at = datetime(2026, 1, 1, 12, 0)

        entity = to_domain(model)
        assert entity.expires_at.tzinfo is None
        # ...and the entity still answers correctly about it.
        assert entity.is_expired_at(NOW) is True

    def test_to_model_does_not_alias_the_entity(self) -> None:
        entity = _session()
        model = to_model(entity)
        model.user_agent = "changed-in-db"
        assert entity.user_agent is None

    def test_to_model_omits_created_at(self) -> None:
        """The column has a server default; copying it over would overwrite it.

        Copying the entity's ``created_at`` onto a save would replace the
        database's record of when the session was actually created with whatever
        the detached entity happened to hold.
        """
        model = to_model(_session(created_at=NOW))
        assert model.created_at is None

    def test_to_model_carries_the_id_so_merge_can_match(self) -> None:
        assert to_model(_session(id=42)).id == 42


class TestOpenSession:
    @pytest.mark.asyncio
    async def test_persists_and_assigns_an_id(self, db) -> None:
        created = await _repo(db).open_session(
            user_id="user-1",
            refresh_token_hash="hash-1",
            expires_at=NOW + timedelta(days=7),
            user_agent="agent",
            ip_address="203.0.113.5",
        )
        await db.commit()

        assert created.id is not None
        assert created.created_at is not None
        row = await db.get(SessionModel, created.id)
        assert row.user_id == "user-1"
        assert row.user_agent == "agent"

    @pytest.mark.asyncio
    async def test_a_new_session_is_not_revoked(self, db) -> None:
        created = await _repo(db).open_session(
            user_id="user-1",
            refresh_token_hash="hash-1",
            expires_at=NOW,
        )
        assert created.revoked_at is None
        assert created.last_used_at is None

    @pytest.mark.asyncio
    async def test_optional_fields_default_to_none(self, db) -> None:
        created = await _repo(db).open_session(
            user_id="user-1", refresh_token_hash="hash-1", expires_at=NOW
        )
        await db.commit()
        assert created.user_agent is None
        assert created.ip_address is None


class TestGetByRefreshHash:
    @pytest.mark.asyncio
    async def test_finds_a_session(self, db) -> None:
        created = await _repo(db).open_session(
            user_id="user-1", refresh_token_hash="hash-1", expires_at=NOW
        )
        await db.commit()

        found = await _repo(db).get_by_refresh_hash("hash-1")
        assert isinstance(found, UserSession)
        assert found.id == created.id

    @pytest.mark.asyncio
    async def test_returns_none_when_absent(self, db) -> None:
        assert await _repo(db).get_by_refresh_hash("nope") is None

    @pytest.mark.asyncio
    async def test_returns_a_detached_entity(self, db) -> None:
        """A mutation must not persist without a save.

        This is the whole reason Phase 7a exists, so it is asserted rather than
        assumed: if this test starts failing because rows are being written
        implicitly, the property has been lost.
        """
        await _repo(db).open_session(
            user_id="user-1", refresh_token_hash="hash-1", expires_at=NOW
        )
        await db.commit()

        found = await _repo(db).get_by_refresh_hash("hash-1")
        found.user_agent = "edited but not saved"
        await db.commit()

        reloaded = await _repo(db).get_by_refresh_hash("hash-1")
        assert reloaded.user_agent is None


class TestGetById:
    """The lookup access-token revalidation uses.

    An access token carries the session id in its ``sid`` claim and no refresh
    hash, so before Phase 7b the revalidation path joined the two ORM models
    directly and this read did not exist.
    """

    @pytest.mark.asyncio
    async def test_finds_a_session_by_primary_key(self, db) -> None:
        created = await _repo(db).open_session(
            user_id="user-1", refresh_token_hash="hash-1", expires_at=NOW
        )
        await db.commit()

        found = await _repo(db).get_by_id(created.id)
        assert isinstance(found, UserSession)
        assert found.refresh_token_hash == "hash-1"
        assert found.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_returns_none_for_an_unknown_id(self, db) -> None:
        assert await _repo(db).get_by_id(999_999) is None

    @pytest.mark.asyncio
    async def test_returns_a_detached_entity(self, db) -> None:
        created = await _repo(db).open_session(
            user_id="user-1", refresh_token_hash="hash-1", expires_at=NOW
        )
        await db.commit()
        db.expunge_all()

        found = await _repo(db).get_by_id(created.id)
        found.revoke(NOW)
        await db.commit()

        reloaded = await _repo(db).get_by_id(created.id)
        assert reloaded.revoked_at is None


class TestSave:
    @pytest.mark.asyncio
    async def test_updates_in_place_instead_of_inserting(self, db) -> None:
        created = await _repo(db).open_session(
            user_id="user-1", refresh_token_hash="hash-1", expires_at=NOW
        )
        await db.commit()
        db.expunge_all()

        created.rotate(
            new_refresh_token_hash="hash-2", rotated_at=NOW, user_agent="rotated"
        )
        await _repo(db).save(created)
        await db.commit()

        rows = (await db.execute(select(SessionModel))).scalars().all()
        assert len(rows) == 1, "save() inserted a duplicate row instead of updating"
        assert rows[0].refresh_token_hash == "hash-2"
        assert rows[0].user_agent == "rotated"

    @pytest.mark.asyncio
    async def test_works_on_an_entity_from_a_previous_session(self, db) -> None:
        """The Phase 7a case: detached entity, so ``add`` would INSERT."""
        created = await _repo(db).open_session(
            user_id="user-1", refresh_token_hash="hash-1", expires_at=NOW
        )
        await db.commit()
        db.expunge_all()

        created.revoke(NOW)
        await _repo(db).save(created)
        await db.commit()

        found = await _repo(db).get_by_refresh_hash("hash-1")
        assert found.revoked_at is not None

    @pytest.mark.asyncio
    async def test_preserves_the_stored_created_at(self, db) -> None:
        created = await _repo(db).open_session(
            user_id="user-1", refresh_token_hash="hash-1", expires_at=NOW
        )
        await db.commit()
        original_created_at = (await db.get(SessionModel, created.id)).created_at
        db.expunge_all()

        created.revoke(NOW)
        await _repo(db).save(created)
        await db.commit()

        assert (await db.get(SessionModel, created.id)).created_at == original_created_at

    @pytest.mark.asyncio
    async def test_persists_every_rotated_field_together(self, db) -> None:
        created = await _repo(db).open_session(
            user_id="user-1",
            refresh_token_hash="hash-1",
            expires_at=NOW,
            user_agent="original",
            ip_address="203.0.113.1",
        )
        await db.commit()
        db.expunge_all()

        created.rotate(
            new_refresh_token_hash="hash-2",
            rotated_at=NOW,
            user_agent="rotated",
            ip_address="198.51.100.7",
        )
        await _repo(db).save(created)
        await db.commit()

        row = await db.get(SessionModel, created.id)
        assert row.refresh_token_hash == "hash-2"
        assert row.last_used_at is not None
        assert row.user_agent == "rotated"
        assert row.ip_address == "198.51.100.7"


class TestRevokeUserSessions:
    @pytest.mark.asyncio
    async def test_revokes_every_live_session(self, db) -> None:
        repo = _repo(db)
        first = await repo.open_session(
            user_id="user-1", refresh_token_hash="a", expires_at=NOW
        )
        second = await repo.open_session(
            user_id="user-1", refresh_token_hash="b", expires_at=NOW
        )
        await db.commit()

        await repo.revoke_user_sessions(user_id="user-1", revoked_at=NOW)
        await db.commit()

        for session_id in (first.id, second.id):
            assert (await db.get(SessionModel, session_id)).revoked_at is not None

    @pytest.mark.asyncio
    async def test_leaves_other_users_sessions_alone(self, db) -> None:
        repo = _repo(db)
        mine = await repo.open_session(
            user_id="user-1", refresh_token_hash="a", expires_at=NOW
        )
        await db.commit()

        await repo.revoke_user_sessions(user_id="user-2", revoked_at=NOW)
        await db.commit()

        assert (await db.get(SessionModel, mine.id)).revoked_at is None

    @pytest.mark.asyncio
    async def test_does_not_re_revoke_an_already_revoked_session(self, db) -> None:
        """A bulk revoke must not move an existing revocation time.

        The first revocation time is when the session actually died.
        """
        repo = _repo(db)
        created = await repo.open_session(
            user_id="user-1", refresh_token_hash="a", expires_at=NOW
        )
        await db.commit()
        first = NOW
        await repo.revoke_user_sessions(user_id="user-1", revoked_at=first)
        await db.commit()

        await repo.revoke_user_sessions(
            user_id="user-1", revoked_at=NOW + timedelta(hours=1)
        )
        await db.commit()

        # The column is timezone-aware but SQLite stores no offset, so the
        # stored value comes back naive and is compared in that form.
        row = await db.get(SessionModel, created.id)
        assert row.revoked_at == first.replace(tzinfo=None)


class TestErrorTranslation:
    """A driver failure must reach the application as a domain error.

    Forced with a table that does not exist rather than a closed session: closing
    an ``AsyncSession`` does not make it unusable, it begins a new transaction on
    the next use, so that would assert nothing.
    """

    @pytest_asyncio.fixture
    async def tableless_db(self):
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            yield session
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_a_failed_open_surfaces_as_a_domain_error(self, tableless_db) -> None:
        with pytest.raises(SessionRepositoryUnavailableError):
            await _repo(tableless_db).open_session(
                user_id="u", refresh_token_hash="h", expires_at=NOW
            )

    @pytest.mark.asyncio
    async def test_a_failed_lookup_surfaces_as_a_domain_error(self, tableless_db) -> None:
        for call in (
            _repo(tableless_db).get_by_id(1),
            _repo(tableless_db).get_by_id(1),
            _repo(tableless_db).get_by_refresh_hash("h"),
        ):
            with pytest.raises(SessionRepositoryUnavailableError):
                await call

    @pytest.mark.asyncio
    async def test_a_failed_save_surfaces_as_a_domain_error(self, tableless_db) -> None:
        with pytest.raises(SessionRepositoryUnavailableError):
            await _repo(tableless_db).save(_session(id=1))

    @pytest.mark.asyncio
    async def test_a_failed_bulk_revoke_surfaces_as_a_domain_error(self, tableless_db) -> None:
        with pytest.raises(SessionRepositoryUnavailableError):
            await _repo(tableless_db).revoke_user_sessions(user_id="u", revoked_at=NOW)

    @pytest.mark.asyncio
    async def test_no_driver_error_escapes_uncaught(self, tableless_db) -> None:
        for call in (
            _repo(tableless_db).open_session(
                user_id="u", refresh_token_hash="h", expires_at=NOW
            ),
            _repo(tableless_db).get_by_id(1),
            _repo(tableless_db).get_by_refresh_hash("h"),
            _repo(tableless_db).save(_session(id=1)),
            _repo(tableless_db).revoke_user_sessions(user_id="u", revoked_at=NOW),
        ):
            try:
                await call
            except SQLAlchemyError:  # pragma: no cover
                pytest.fail("a driver error escaped the repository")
            except SessionRepositoryUnavailableError:
                pass
            else:  # pragma: no cover
                pytest.fail("expected SessionRepositoryUnavailableError")
