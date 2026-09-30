"""Tests for the User persistence adapter and its mapper.

Runs against real SQLite rather than a mock session, because the two things worth
testing here are SQL-level: that ``save`` updates the *existing* row instead of
inserting a second one, and that the mapper trims the error text to the column
width. A mocked session asserts nothing about either.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.infrastructure.database.db_setup import Base
from app.infrastructure.database.models.user import User as UserModel
from app.modules.shared.enums import GenderEnum, RoleEnum, UserStatus
from app.modules.user.domain.entities.user import User
from app.modules.user.domain.exceptions import (
    DuplicateUserError,
    UserRepositoryUnavailableError,
)
from app.modules.user.infrastructure.persistence.mappers.user_mapper import (
    to_domain,
    to_model,
)
from app.modules.user.infrastructure.persistence.repository.user_repo import (
    SQLAlchemyUserRepository,
)

import app.infrastructure.database.models  # noqa: F401  (registers all tables)

_ERROR_COLUMN_WIDTH = 500


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


def _user(index: int = 1, **overrides) -> User:
    base = dict(
        full_name=f"User {index}",
        username=f"user{index}",
        email=f"user{index}@example.test",
        password_hash="hash",
        gender=GenderEnum.PREFER_NOT_TO_SAY,
    )
    base.update(overrides)
    return User(**base)


class TestMapper:
    def test_round_trip_preserves_every_field(self) -> None:
        sent_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        original = _user(
            status=UserStatus.VERIFIED,
            role=RoleEnum.ADMIN,
            verification_email_last_sent_at=sent_at,
            verification_email_retry_count=3,
            verification_email_next_retry_at=sent_at + timedelta(minutes=5),
            verification_email_last_error="boom",
        )
        assert to_domain(to_model(original)) == original

    def test_optional_verification_fields_default_to_none(self) -> None:
        model = to_model(_user())
        assert model.verification_email_last_sent_at is None
        assert model.verification_email_next_retry_at is None
        assert model.verification_email_last_error is None
        assert model.verification_email_retry_count == 0

    def test_long_error_text_is_trimmed_to_the_column_width(self) -> None:
        """The table's column is String(500); SQLite would not enforce it.

        On Postgres a longer value raises, so trimming here is what keeps a long
        SMTP error from turning a bookkeeping write into a 500.
        """
        model = to_model(_user(verification_email_last_error="x" * 900))
        assert len(model.verification_email_last_error) == _ERROR_COLUMN_WIDTH

    def test_short_error_text_is_left_alone(self) -> None:
        model = to_model(_user(verification_email_last_error="smtp timeout"))
        assert model.verification_email_last_error == "smtp timeout"

    def test_exactly_the_column_width_is_left_alone(self) -> None:
        exact = "x" * _ERROR_COLUMN_WIDTH
        assert to_model(_user(verification_email_last_error=exact)).verification_email_last_error == exact

    def test_to_model_does_not_alias_the_entity(self) -> None:
        """A shared mutable attribute would let a later domain edit leak back."""
        user = _user()
        model = to_model(user)
        model.username = "changed-in-db"
        assert user.username == "user1"


class TestAddUser:
    @pytest.mark.asyncio
    async def test_inserts_and_returns_the_stored_row(self, db) -> None:
        stored = await SQLAlchemyUserRepository(db).add_user(_user())
        await db.commit()
        assert stored.id
        assert stored.status is UserStatus.UNAPPROVED
        assert await db.get(UserModel, stored.id) is not None

    @pytest.mark.asyncio
    async def test_duplicate_username_becomes_a_domain_error(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        await repo.add_user(_user(1))
        await db.commit()
        with pytest.raises(DuplicateUserError):
            await repo.add_user(_user(2, username="user1", email="other@example.test"))

    @pytest.mark.asyncio
    async def test_duplicate_email_becomes_a_domain_error(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        await repo.add_user(_user(1))
        await db.commit()
        with pytest.raises(DuplicateUserError):
            await repo.add_user(_user(2, username="different", email="user1@example.test"))

    @pytest.mark.asyncio
    async def test_a_driver_error_does_not_escape_as_integrity_error(self, db) -> None:
        """The application must never have to import sqlalchemy to be safe."""
        repo = SQLAlchemyUserRepository(db)
        await repo.add_user(_user(1))
        await db.commit()
        try:
            await repo.add_user(_user(2, username="user1", email="other@example.test"))
        except Exception as exc:  # noqa: BLE001 - the point is the exact type
            assert not isinstance(exc, IntegrityError)
            assert isinstance(exc, DuplicateUserError)
        else:  # pragma: no cover
            pytest.fail("expected DuplicateUserError")


class TestSave:
    @pytest.mark.asyncio
    async def test_updates_in_place_instead_of_inserting(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        created = await repo.add_user(_user(1))
        await db.commit()

        created.full_name = "Renamed"
        await repo.save(created)
        await db.commit()

        rows = (await db.execute(_all_users())).scalars().all()
        assert len(rows) == 1, "save() inserted a duplicate row instead of updating"
        assert rows[0].full_name == "Renamed"

    @pytest.mark.asyncio
    async def test_works_on_an_entity_loaded_by_a_previous_session(self, db) -> None:
        """This is the Phase 6b case: detached entity, so ``add`` would INSERT."""
        repo = SQLAlchemyUserRepository(db)
        created = await repo.add_user(_user(1))
        await db.commit()
        db.expunge_all()
        # A domain entity is never session-associated in the first place, which
        # is exactly why ``save`` has to merge rather than add.
        assert isinstance(created, User)

        created.set_password_hash("rehashed")
        await repo.save(created)
        await db.commit()

        reloaded = await SQLAlchemyUserRepository(db).get_user_by_id(created.id)
        assert reloaded is not None
        assert reloaded.password_hash == "rehashed"

    @pytest.mark.asyncio
    async def test_returns_database_assigned_timestamps(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        created = await repo.add_user(_user(1))
        await db.commit()
        db.expunge_all()

        created.full_name = "Renamed"
        saved = await repo.save(created)
        assert saved.created_at is not None
        assert saved.updated_at is not None

    @pytest.mark.asyncio
    async def test_persists_status_role_and_retry_bookkeeping_together(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        created = await repo.add_user(_user(1))
        await db.commit()
        db.expunge_all()

        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        created.verify()
        created.role = RoleEnum.ADMIN
        created.record_verification_email_failure(
            error_message="x" * 900,
            next_retry_at=now + timedelta(minutes=5),
            retry_count=2,
        )
        await repo.save(created)
        await db.commit()

        row = await db.get(UserModel, created.id)
        assert row.status is UserStatus.VERIFIED
        assert row.role is RoleEnum.ADMIN
        assert row.verification_email_retry_count == 2
        # Trimmed on the way in, so the stored value is what fits the column.
        assert len(row.verification_email_last_error) == _ERROR_COLUMN_WIDTH

    @pytest.mark.asyncio
    async def test_a_conflicting_update_becomes_a_domain_error(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        first = await repo.add_user(_user(1))
        second = await repo.add_user(_user(2))
        await db.commit()
        db.expunge_all()

        second.username = first.username
        with pytest.raises(DuplicateUserError):
            await repo.save(second)


class TestReads:
    @pytest.mark.asyncio
    async def test_get_by_id_returns_none_when_absent(self, db) -> None:
        assert await SQLAlchemyUserRepository(db).get_user_by_id("nope") is None

    @pytest.mark.asyncio
    async def test_get_by_username_and_email_return_domain_entities(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        await repo.add_user(_user(1))
        await db.commit()

        by_username = await repo.get_user_by_username("user1")
        by_email = await repo.get_user_by_email("user1@example.test")
        assert isinstance(by_username, User)
        assert by_username.id == by_email.id

    @pytest.mark.asyncio
    async def test_get_by_username_returns_none_when_absent(self, db) -> None:
        assert await SQLAlchemyUserRepository(db).get_user_by_username("ghost") is None

    @pytest.mark.asyncio
    async def test_returned_entities_are_detached(self, db) -> None:
        """Reads must not hand back a live ORM row.

        If they did, a caller's mutation would silently persist, which is the
        behaviour this whole phase removed.
        """
        repo = SQLAlchemyUserRepository(db)
        await repo.add_user(_user(1))
        await db.commit()

        loaded = await repo.get_user_by_id(
            (await repo.get_user_by_username("user1")).id
        )
        loaded.full_name = "Edited but not saved"
        await db.commit()
        assert (await db.get(UserModel, loaded.id)).full_name == "User 1"


class TestListUsers:
    @pytest.mark.asyncio
    async def test_empty_table_returns_an_empty_list(self, db) -> None:
        assert await SQLAlchemyUserRepository(db).list_users() == []

    @pytest.mark.asyncio
    async def test_orders_by_id_descending(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        for i in range(3):
            await repo.add_user(_user(i))
        await db.commit()
        users = await repo.list_users()
        assert [u.id for u in users] == sorted((u.id for u in users), reverse=True)

    @pytest.mark.asyncio
    async def test_clamps_limits_into_range(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        for i in range(2):
            await repo.add_user(_user(i))
        await db.commit()
        assert len(await repo.list_users(limit=0)) == 1
        assert len(await repo.list_users(limit=-5)) == 1
        assert len(await repo.list_users(limit=10_000)) == 2

    @pytest.mark.asyncio
    async def test_keyset_pages_do_not_overlap(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        for i in range(5):
            await repo.add_user(_user(i))
        await db.commit()

        first = await repo.list_users(limit=2)
        second = await repo.list_users(limit=2, before_id=first[-1].id)
        assert len({u.id for u in first} & {u.id for u in second}) == 0


class TestListPendingRetry:
    @pytest.mark.asyncio
    async def test_excludes_verified_accounts(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=1)
        await repo.add_user(_user(1, status=UserStatus.VERIFIED))
        await repo.add_user(_user(2, status=UserStatus.UNAPPROVED))
        await db.commit()
        await _backdate(db)

        found = await repo.list_users_pending_verification_email_retry(
            now=now, created_before=past, max_retry_count=3
        )
        assert [u.username for u in found] == ["user2"]

    @pytest.mark.asyncio
    async def test_excludes_accounts_still_backed_off(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=1)
        await repo.add_user(
            _user(1, verification_email_next_retry_at=now + timedelta(minutes=10))
        )
        await db.commit()
        await _backdate(db)

        found = await repo.list_users_pending_verification_email_retry(
            now=now, created_before=past, max_retry_count=3
        )
        assert found == []

    @pytest.mark.asyncio
    async def test_excludes_accounts_past_the_retry_ceiling(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=1)
        await repo.add_user(_user(1, verification_email_retry_count=3))
        await db.commit()
        await _backdate(db)

        found = await repo.list_users_pending_verification_email_retry(
            now=now, created_before=past, max_retry_count=3
        )
        assert found == []

    @pytest.mark.asyncio
    async def test_includes_a_due_unverified_account(self, db) -> None:
        repo = SQLAlchemyUserRepository(db)
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=1)
        await repo.add_user(_user(1))
        await db.commit()
        await _backdate(db)

        found = await repo.list_users_pending_verification_email_retry(
            now=now, created_before=past, max_retry_count=3
        )
        assert [u.username for u in found] == ["user1"]


class TestErrorTranslation:
    """A driver failure must reach the application as a domain error.

    Forced with a table that does not exist rather than a closed session: closing
    an ``AsyncSession`` does not make it unusable, it just begins a new
    transaction on the next use, so that would assert nothing.
    """

    @pytest_asyncio.fixture
    async def tableless_db(self):
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            yield session
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_a_failed_list_surfaces_as_a_domain_error(self, tableless_db) -> None:
        with pytest.raises(UserRepositoryUnavailableError):
            await SQLAlchemyUserRepository(tableless_db).list_users()

    @pytest.mark.asyncio
    async def test_a_failed_retry_list_surfaces_as_a_domain_error(self, tableless_db) -> None:
        with pytest.raises(UserRepositoryUnavailableError):
            await SQLAlchemyUserRepository(tableless_db).list_users_pending_verification_email_retry(
                now=datetime.now(timezone.utc),
                created_before=datetime(2000, 1, 1),
                max_retry_count=3,
            )

    @pytest.mark.asyncio
    async def test_a_failed_lookup_surfaces_as_a_domain_error(self, tableless_db) -> None:
        repo = SQLAlchemyUserRepository(tableless_db)
        with pytest.raises(UserRepositoryUnavailableError):
            await repo.get_user_by_username("user1")
        with pytest.raises(UserRepositoryUnavailableError):
            await repo.get_user_by_email("user1@example.test")

    @pytest.mark.asyncio
    async def test_a_failed_insert_surfaces_as_a_domain_error(self, tableless_db) -> None:
        with pytest.raises(UserRepositoryUnavailableError):
            await SQLAlchemyUserRepository(tableless_db).add_user(_user())

    @pytest.mark.asyncio
    async def test_a_failed_save_surfaces_as_a_domain_error(self, tableless_db) -> None:
        with pytest.raises(UserRepositoryUnavailableError):
            await SQLAlchemyUserRepository(tableless_db).save(_user())


# === helpers ===


def _all_users():
    from sqlalchemy import select

    return select(UserModel)


async def _backdate(db) -> None:
    """Push ``created_at`` into the past.

    The column is a server default, so SQLite has to be told directly; the retry
    worker's age ceiling cannot otherwise be exercised.
    """
    from sqlalchemy import update

    await db.execute(update(UserModel).values(created_at=datetime(2000, 1, 1)))
    await db.commit()
