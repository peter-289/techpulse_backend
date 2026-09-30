"""Tests for the User aggregate.

Every method here replaces a bare attribute assignment that used to live in a
caller. The assertions are mostly about *which* rule moved and not, but two are
load-bearing:

* ``apply_verified_password_hash`` returning a bool, because that return value is
  the only thing stopping a pointless ``UPDATE`` on every single login;
* ``record_verification_email_sent`` clearing the error, because the recovery
  worker reads that field to decide whether an account is stuck.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.modules.shared.enums import GenderEnum, RoleEnum, UserStatus
from app.modules.user.domain.entities.user import User


def _user(**overrides) -> User:
    base = dict(
        full_name="Ada",
        username="ada",
        email="ada@example.test",
        password_hash="hash-1",
        gender=GenderEnum.FEMALE,
    )
    base.update(overrides)
    return User(**base)


class TestRegister:
    def test_new_account_is_unapproved_with_the_default_role(self) -> None:
        user = User.register(
            full_name="Ada",
            username="ada",
            email="ada@example.test",
            password_hash="hash-1",
        )
        assert user.status is UserStatus.UNAPPROVED
        assert user.role is RoleEnum.USER
        assert user.is_verified is False

    def test_gender_defaults_when_registration_omits_it(self) -> None:
        user = User.register(
            full_name="Ada",
            username="ada",
            email="ada@example.test",
            password_hash="hash-1",
        )
        assert user.gender is GenderEnum.PREFER_NOT_TO_SAY

    def test_registration_does_not_normalize_its_inputs(self) -> None:
        """The database has always stored the submitted values verbatim.

        Normalizing here would silently rewrite what existing rows mean, and the
        authentication context normalizes separately for *lookup*. The asymmetry
        is recorded in docs/REVIEW.md rather than fixed.
        """
        user = User.register(
            full_name="  Ada  ",
            username="Ada",
            email="  Ada@Example.TEST ",
            password_hash="hash-1",
        )
        assert user.full_name == "  Ada  "
        assert user.username == "Ada"
        assert user.email == "  Ada@Example.TEST "

    def test_each_registration_gets_a_distinct_id(self) -> None:
        a = User.register(
            full_name="A", username="a", email="a@x.test", password_hash="h"
        )
        b = User.register(
            full_name="B", username="b", email="b@x.test", password_hash="h"
        )
        assert a.id != b.id


class TestVerify:
    def test_verify_marks_the_account_verified(self) -> None:
        user = _user()
        user.verify()
        assert user.is_verified is True
        assert user.status is UserStatus.VERIFIED

    def test_verify_is_idempotent(self) -> None:
        """A reused verification link used to be a no-op write, not a 4xx."""
        user = _user()
        user.verify()
        user.verify()
        assert user.status is UserStatus.VERIFIED

    def test_verify_does_not_touch_the_role(self) -> None:
        user = _user(role=RoleEnum.ADMIN)
        user.verify()
        assert user.role is RoleEnum.ADMIN


class TestApplyVerifiedPasswordHash:
    def test_returns_false_and_keeps_the_hash_when_unchanged(self) -> None:
        user = _user(password_hash="same")
        assert user.apply_verified_password_hash("same") is False
        assert user.password_hash == "same"

    def test_returns_true_and_upgrades_a_stale_hash(self) -> None:
        """This is the login-time Argon2 re-parameterization path."""
        user = _user(password_hash="old-params")
        assert user.apply_verified_password_hash("new-params") is True
        assert user.password_hash == "new-params"

    def test_empty_hash_is_ignored(self) -> None:
        """A falsy hash must never overwrite a real one."""
        user = _user(password_hash="good")
        assert user.apply_verified_password_hash("") is False
        assert user.password_hash == "good"

    def test_apply_twice_is_idempotent(self) -> None:
        user = _user(password_hash="old")
        assert user.apply_verified_password_hash("new") is True
        assert user.apply_verified_password_hash("new") is False


class TestSetPasswordHash:
    def test_replaces_the_stored_hash(self) -> None:
        user = _user(password_hash="old")
        user.set_password_hash("new")
        assert user.password_hash == "new"

    def test_does_not_change_verification_state(self) -> None:
        user = _user()
        user.set_password_hash("new")
        assert user.is_verified is False


class TestVerificationEmailBookkeeping:
    def test_recording_a_success_clears_the_whole_retry_state(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user = _user(
            verification_email_retry_count=4,
            verification_email_next_retry_at=now + timedelta(hours=1),
            verification_email_last_error="smtp timeout",
        )

        user.record_verification_email_sent(now)

        assert user.verification_email_last_sent_at == now
        assert user.verification_email_retry_count == 0
        assert user.verification_email_next_retry_at is None
        # Clearing the error is what stops the worker treating the account as
        # permanently stuck.
        assert user.verification_email_last_error is None

    def test_recording_a_failure_stores_the_error_and_backoff(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user = _user()

        user.record_verification_email_failure(
            error_message="smtp timeout",
            next_retry_at=now + timedelta(seconds=300),
            retry_count=1,
        )

        assert user.verification_email_retry_count == 1
        assert user.verification_email_last_error == "smtp timeout"
        assert user.verification_email_next_retry_at == now + timedelta(seconds=300)

    def test_failure_error_is_stored_whole_for_the_mapper_to_trim(self) -> None:
        """Truncation to the column width belongs to the mapper, not the domain."""
        long_error = "x" * 900
        user = _user()
        user.record_verification_email_failure(
            error_message=long_error,
            next_retry_at=datetime.now(timezone.utc),
            retry_count=1,
        )
        assert len(user.verification_email_last_error) == 900

    def test_a_missing_error_becomes_empty_string_not_none(self) -> None:
        user = _user()
        user.record_verification_email_failure(
            error_message="",
            next_retry_at=datetime.now(timezone.utc),
            retry_count=1,
        )
        assert user.verification_email_last_error == ""


class TestIsDueForVerificationResend:
    def test_a_fresh_unverified_account_is_due(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert _user().is_due_for_verification_resend(now) is True

    def test_a_verified_account_is_never_due(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user = _user(status=UserStatus.VERIFIED)
        assert user.is_due_for_verification_resend(now) is False

    def test_an_account_backed_off_past_is_not_due(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user = _user(verification_email_next_retry_at=now + timedelta(seconds=30))
        assert user.is_due_for_verification_resend(now) is False

    def test_an_account_whose_backoff_expired_is_due(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user = _user(verification_email_next_retry_at=now - timedelta(seconds=1))
        assert user.is_due_for_verification_resend(now) is True

    def test_the_backoff_boundary_is_inclusive(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user = _user(verification_email_next_retry_at=now)
        assert user.is_due_for_verification_resend(now) is True


class TestEntityDefaults:
    """The entity's defaults must match the table's column defaults.

    Otherwise a hand-built ``User`` and a hand-built ``UserModel`` would describe
    different rows, and a test double could register an account the database
    would have stored differently.
    """

    @pytest.mark.parametrize(
        ("field", "expected"),
        [
            ("gender", GenderEnum.PREFER_NOT_TO_SAY),
            ("status", UserStatus.UNAPPROVED),
            ("role", RoleEnum.USER),
            ("verification_email_retry_count", 0),
        ],
    )
    def test_default_matches_the_column_default(self, field: str, expected) -> None:
        user = User(full_name="A", username="a", email="a@x.test", password_hash="h")
        assert getattr(user, field) == expected

    def test_dataclass_defaults_equal_register_defaults(self) -> None:
        """``register`` must not disagree with the dataclass defaults."""
        registered = User.register(
            full_name="A", username="a", email="a@x.test", password_hash="h"
        )
        constructed = User(full_name="A", username="a", email="a@x.test", password_hash="h")
        assert registered.status is constructed.status
        assert registered.role is constructed.role
        assert registered.gender is constructed.gender
