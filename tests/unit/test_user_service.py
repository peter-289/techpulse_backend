"""User use cases, exercised without a database.

Two things this file exists to pin:

* ``create_user`` takes a plain ``client_ip`` string, not a ``Request``. That is
  not a cosmetic change -- taking the request object is precisely what pulled
  FastAPI into the application layer, and an R8 ratchet entry.
* ``ensure_superuser`` is where the seeder's decisions now live. The seeder used
  to construct a ``User`` with ``status=VERIFIED, role=ADMIN`` inline while
  ``register`` said a new account starts ``UNAPPROVED``/``USER``; two places
  spelling out "what does a new account start as" is how they drift.

The fake Unit of Work records whether a transaction was opened, so the paths
supposed to fail before touching the database can be shown to.
"""

from __future__ import annotations

import pytest

from app.exceptions.exceptions import DomainError
from app.modules.security.abuse_protection import TooManyRequestsError
from app.modules.shared.enums import GenderEnum, RoleEnum, UserStatus
from app.modules.user.application.services.user_service import (
    SuperuserResult,
    UserService,
)
from app.modules.user.domain.entities.user import User
from app.modules.user.domain.exceptions import UserNotFoundError


class _FakeRepo:
    def __init__(self, by_username=None, by_email=None) -> None:
        self.by_username = by_username
        self.by_email = by_email
        self.added: list[User] = []
        self.saved: list[User] = []

    async def add_user(self, user: User) -> User:
        self.added.append(user)
        return user

    async def save(self, user: User) -> User:
        self.saved.append(user)
        return user

    async def get_user_by_username(self, username: str) -> User | None:
        return self.by_username

    async def get_user_by_email(self, email: str) -> User | None:
        return self.by_email

    async def get_user_by_id(self, user_id: str) -> User | None:
        return None

    async def list_users(self, limit: int = 100, before_id: str | None = None) -> list[User]:
        return []


class _FakeUow:
    def __init__(self, repo: _FakeRepo) -> None:
        self.user_repo = repo
        self.writes = 0
        self.reads = 0

    def read_only(self):
        return self

    async def __aenter__(self) -> "_FakeUow":
        return self

    async def __aexit__(self, *exc) -> bool:
        return False


class _WriteUow(_FakeUow):
    async def __aenter__(self) -> "_WriteUow":
        self.writes += 1
        return self


class _ReadUow(_FakeUow):
    async def __aenter__(self) -> "_ReadUow":
        self.reads += 1
        return self


class _FakeAbuse:
    def __init__(self) -> None:
        self.registrations: list[str] = []
        self.raises = False

    async def guard_registration(self, ip: str) -> None:
        if self.raises:
            raise TooManyRequestsError("Too many registrations from this address")
        self.registrations.append(ip)


def _service(repo: _FakeRepo | None = None, uow_cls=_WriteUow, abuse=None) -> UserService:
    repo = repo or _FakeRepo()
    return UserService(
        uow=uow_cls(repo),
        abuse_protection=abuse or _FakeAbuse(),
    )


def _existing(role=RoleEnum.USER, status=UserStatus.UNAPPROVED, **overrides) -> User:
    base = dict(
        full_name="Admin",
        username="admin",
        email="admin@example.test",
        password_hash="old",
    )
    base.update(overrides)
    user = User(**base)
    user.role = role
    user.status = status
    return user


class TestCreateUser:
    @pytest.mark.asyncio
    async def test_returns_the_persisted_account(self) -> None:
        repo = _FakeRepo()
        service = _service(repo)
        user = await service.create_user(
            full_name="Ada",
            username="ada",
            email="ada@example.test",
            password="Sup3rSecret!x",
            gender=GenderEnum.FEMALE,
            client_ip="203.0.113.5",
        )
        assert user.username == "ada"
        assert len(repo.added) == 1

    @pytest.mark.asyncio
    async def test_a_new_account_starts_unverified_and_unprivileged(self) -> None:
        service = _service()
        user = await service.create_user(
            full_name="Ada",
            username="ada",
            email="ada@example.test",
            password="Sup3rSecret!x",
            gender=GenderEnum.FEMALE,
            client_ip="203.0.113.5",
        )
        assert user.status is UserStatus.UNAPPROVED
        assert user.role is RoleEnum.USER

    @pytest.mark.asyncio
    async def test_stores_a_hash_and_never_the_password(self) -> None:
        repo = _FakeRepo()
        service = _service(repo)
        await service.create_user(
            full_name="Ada",
            username="ada",
            email="ada@example.test",
            password="Sup3rSecret!x",
            gender=GenderEnum.FEMALE,
            client_ip="203.0.113.5",
        )
        stored = repo.added[0].password_hash
        assert stored != "Sup3rSecret!x"
        assert "argon2" in stored or len(stored) > 20

    @pytest.mark.asyncio
    async def test_a_weak_password_fails_before_the_transaction_opens(self) -> None:
        repo = _FakeRepo()
        uow = _WriteUow(repo)
        service = UserService(uow=uow, abuse_protection=_FakeAbuse())

        with pytest.raises(DomainError):
            await service.create_user(
                full_name="Ada",
                username="ada",
                email="ada@example.test",
                password="short",
                gender=GenderEnum.FEMALE,
                client_ip="203.0.113.5",
            )
        assert uow.writes == 0
        assert repo.added == []

    @pytest.mark.asyncio
    async def test_the_rate_limit_guard_runs_before_the_insert(self) -> None:
        repo = _FakeRepo()
        abuse = _FakeAbuse()
        abuse.raises = True
        service = _service(repo, abuse=abuse)

        with pytest.raises(TooManyRequestsError):
            await service.create_user(
                full_name="Ada",
                username="ada",
                email="ada@example.test",
                password="Sup3rSecret!x",
                gender=GenderEnum.FEMALE,
                client_ip="203.0.113.5",
            )
        assert repo.added == [], "a rate-limited client should cost no write"

    @pytest.mark.asyncio
    async def test_the_client_ip_is_forwarded_to_the_guard(self) -> None:
        abuse = _FakeAbuse()
        service = _service(abuse=abuse)
        await service.create_user(
            full_name="Ada",
            username="ada",
            email="ada@example.test",
            password="Sup3rSecret!x",
            gender=GenderEnum.FEMALE,
            client_ip="198.51.100.7",
        )
        assert abuse.registrations == ["198.51.100.7"]

    @pytest.mark.asyncio
    async def test_does_not_normalize_the_submitted_values(self) -> None:
        repo = _FakeRepo()
        service = _service(repo)
        await service.create_user(
            full_name="  Ada  ",
            username="Ada",
            email="Ada@Example.TEST",
            password="Sup3rSecret!x",
            gender=GenderEnum.FEMALE,
            client_ip="203.0.113.5",
        )
        stored = repo.added[0]
        assert stored.full_name == "  Ada  "
        assert stored.username == "Ada"
        assert stored.email == "Ada@Example.TEST"


class TestGetUserById:
    @pytest.mark.asyncio
    async def test_a_missing_account_raises_the_domain_error(self) -> None:
        service = _service(_FakeRepo(), uow_cls=_ReadUow)
        with pytest.raises(UserNotFoundError):
            await service.get_user_by_id("00000000-0000-0000-0000-000000000000")


class TestEnsureSuperuser:
    @pytest.mark.asyncio
    async def test_creates_a_verified_administrator_when_absent(self) -> None:
        repo = _FakeRepo()
        service = _service(repo)

        outcome = await service.ensure_superuser(
            username="admin",
            email="admin@example.test",
            full_name="Admin",
            password="Sup3rSecret!x",
            update_password=False,
        )

        assert outcome.outcome is SuperuserResult.CREATED
        created = repo.added[0]
        assert created.role is RoleEnum.ADMIN
        assert created.status is UserStatus.VERIFIED
        assert repo.saved == []

    @pytest.mark.asyncio
    async def test_creation_goes_through_register_then_promotes(self) -> None:
        """The account is registered first, then granted rights.

        It is not constructed directly with admin/verified, because that inline
        construction is the duplication this use case exists to remove.
        """
        repo = _FakeRepo()
        service = _service(repo)
        await service.ensure_superuser(
            username="admin",
            email="admin@example.test",
            full_name="Admin",
            password="Sup3rSecret!x",
            update_password=False,
        )
        created = repo.added[0]
        assert created.gender is GenderEnum.PREFER_NOT_TO_SAY
        assert created.password_hash != "Sup3rSecret!x"

    @pytest.mark.asyncio
    async def test_promotes_an_existing_plain_account(self) -> None:
        existing = _existing(role=RoleEnum.USER, status=UserStatus.UNAPPROVED)
        repo = _FakeRepo(by_username=existing)
        service = _service(repo)

        outcome = await service.ensure_superuser(
            username="admin",
            email="admin@example.test",
            full_name="Admin",
            password="Sup3rSecret!x",
            update_password=False,
        )

        assert outcome.outcome is SuperuserResult.UPDATED
        assert repo.saved == [existing]
        assert existing.role is RoleEnum.ADMIN
        assert existing.is_verified is True

    @pytest.mark.asyncio
    async def test_leaves_the_password_alone_by_default(self) -> None:
        existing = _existing(role=RoleEnum.ADMIN, status=UserStatus.VERIFIED)
        repo = _FakeRepo(by_username=existing)
        service = _service(repo)

        outcome = await service.ensure_superuser(
            username="admin",
            email="admin@example.test",
            full_name="Admin",
            password="Sup3rSecret!x",
            update_password=False,
        )

        assert outcome.outcome is SuperuserResult.UNCHANGED
        assert existing.password_hash == "old"
        assert repo.saved == [], "an already-correct account should not be written"

    @pytest.mark.asyncio
    async def test_rehashes_the_password_when_asked(self) -> None:
        existing = _existing(role=RoleEnum.ADMIN, status=UserStatus.VERIFIED)
        repo = _FakeRepo(by_username=existing)
        service = _service(repo)

        outcome = await service.ensure_superuser(
            username="admin",
            email="admin@example.test",
            full_name="Admin",
            password="Sup3rSecret!x",
            update_password=True,
        )

        assert outcome.outcome is SuperuserResult.UPDATED
        assert existing.password_hash != "old"
        assert repo.saved == [existing]

    @pytest.mark.asyncio
    async def test_finds_the_account_by_email_when_the_username_does_not_match(self) -> None:
        existing = _existing(
            role=RoleEnum.ADMIN, status=UserStatus.VERIFIED, username="different"
        )
        repo = _FakeRepo(by_email=existing)
        service = _service(repo)

        outcome = await service.ensure_superuser(
            username="admin",
            email="admin@example.test",
            full_name="Admin",
            password="Sup3rSecret!x",
            update_password=False,
        )

        assert outcome.outcome is SuperuserResult.UNCHANGED
        assert repo.added == [], "an existing account must not be duplicated"

    @pytest.mark.asyncio
    async def test_reports_a_conflict_when_the_two_identifiers_disagree(self) -> None:
        """A username and an email on different accounts is a config error."""
        by_username = _existing(username="admin", email="admin@example.test")
        by_email = _existing(username="someone", email="admin@example.test")
        repo = _FakeRepo(by_username=by_username, by_email=by_email)
        service = _service(repo)

        outcome = await service.ensure_superuser(
            username="admin",
            email="admin@example.test",
            full_name="Admin",
            password="Sup3rSecret!x",
            update_password=False,
        )

        assert outcome.outcome is SuperuserResult.CONFLICT
        assert repo.added == []
        assert repo.saved == []
