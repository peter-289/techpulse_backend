"""Tests for the UserSession aggregate.

The methods here replace bare attribute assignments in ``auth_service``. Two of
those assignments were never verified against a real database, and both returned
success whether or not the write landed, so the behaviour is pinned here and
end-to-end in ``tests/integration/test_session_write_paths.py``.

The one that needs the most care is the naive-datetime comparison. The column is
``DateTime(timezone=True)`` but SQLite has no timezone type and hands back a naive
``datetime``; comparing that to an aware ``now`` raises ``TypeError``. The old
inline comparison in ``_rotate_session`` did exactly that.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.modules.user.domain.entities.user_session import UserSession

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _session(**overrides) -> UserSession:
    base = dict(
        user_id="user-1",
        refresh_token_hash="hash-1",
        expires_at=NOW + timedelta(days=7),
    )
    base.update(overrides)
    return UserSession(**base)


class TestOpen:
    def test_starts_unrevoked_and_unused(self) -> None:
        session = _session()
        assert session.is_revoked is False
        assert session.last_used_at is None
        assert session.revoked_at is None

    def test_records_the_agent_and_address(self) -> None:
        session = _session(user_agent="pytest", ip_address="203.0.113.5")
        assert session.user_agent == "pytest"
        assert session.ip_address == "203.0.113.5"

    def test_optional_fields_default_to_none(self) -> None:
        session = _session()
        assert session.user_agent is None
        assert session.ip_address is None

    def test_has_no_id_until_persisted(self) -> None:
        assert _session().id is None


class TestRevoke:
    def test_sets_revoked_at(self) -> None:
        session = _session()
        session.revoke(NOW)
        assert session.revoked_at == NOW
        assert session.is_revoked is True

    def test_is_idempotent_and_keeps_the_first_time(self) -> None:
        """A second logout must not move the revocation timestamp.

        The first revocation time is what tells you when a session actually
        died, so overwriting it with a later logout would be a small lie.
        """
        session = _session()
        session.revoke(NOW)
        later = NOW + timedelta(hours=2)
        session.revoke(later)
        assert session.revoked_at == NOW

    def test_revoking_does_not_touch_the_refresh_token(self) -> None:
        session = _session()
        session.revoke(NOW)
        assert session.refresh_token_hash == "hash-1"


class TestRotate:
    def test_replaces_the_refresh_hash(self) -> None:
        session = _session()
        session.rotate(new_refresh_token_hash="hash-2", rotated_at=NOW)
        assert session.refresh_token_hash == "hash-2"

    def test_stamps_last_used_at(self) -> None:
        session = _session()
        session.rotate(new_refresh_token_hash="hash-2", rotated_at=NOW)
        assert session.last_used_at == NOW

    def test_updates_a_supplied_agent_and_address(self) -> None:
        session = _session(user_agent="original", ip_address="203.0.113.1")
        session.rotate(
            new_refresh_token_hash="hash-2",
            rotated_at=NOW,
            user_agent="rotated",
            ip_address="198.51.100.7",
        )
        assert session.user_agent == "rotated"
        assert session.ip_address == "198.51.100.7"

    def test_keeps_the_previous_agent_when_none_is_supplied(self) -> None:
        """A browser refresh is cookie-less and sends no User-Agent.

        Blanking the recorded value there would erase the detail that makes a
        session row worth keeping.
        """
        session = _session(user_agent="original", ip_address="203.0.113.1")
        session.rotate(new_refresh_token_hash="hash-2", rotated_at=NOW)
        assert session.user_agent == "original"
        assert session.ip_address == "203.0.113.1"

    def test_empty_strings_do_not_overwrite(self) -> None:
        session = _session(user_agent="original", ip_address="203.0.113.1")
        session.rotate(
            new_refresh_token_hash="hash-2",
            rotated_at=NOW,
            user_agent="",
            ip_address="",
        )
        assert session.user_agent == "original"
        assert session.ip_address == "203.0.113.1"

    def test_does_not_change_the_id(self) -> None:
        """The access token stays bound to this session across a rotation.

        That is the mechanism by which revoking the session invalidates the
        access token too, so the id must survive.
        """
        session = _session(id=42)
        session.rotate(new_refresh_token_hash="hash-2", rotated_at=NOW)
        assert session.id == 42

    def test_does_not_change_the_expiry(self) -> None:
        expires = NOW + timedelta(days=7)
        session = _session(expires_at=expires)
        session.rotate(new_refresh_token_hash="hash-2", rotated_at=NOW)
        assert session.expires_at == expires

    def test_does_not_unrevoke(self) -> None:
        session = _session()
        session.revoke(NOW)
        session.rotate(new_refresh_token_hash="hash-2", rotated_at=NOW)
        assert session.is_revoked is True


class TestIsExpiredAt:
    def test_a_future_expiry_is_not_expired(self) -> None:
        assert _session(expires_at=NOW + timedelta(seconds=1)).is_expired_at(NOW) is False

    def test_a_past_expiry_is_expired(self) -> None:
        assert _session(expires_at=NOW - timedelta(seconds=1)).is_expired_at(NOW) is True

    def test_the_boundary_is_inclusive(self) -> None:
        assert _session(expires_at=NOW).is_expired_at(NOW) is True

    def test_a_naive_expiry_does_not_raise(self) -> None:
        """SQLite returns naive datetimes even for a timezone-aware column.

        Comparing one to an aware ``now`` raises ``TypeError``, which is what the
        old inline comparison did on SQLite.
        """
        naive_expiry = datetime(2026, 1, 1, 12, 0)
        assert _session(expires_at=naive_expiry).is_expired_at(NOW) is True

    def test_a_naive_expiry_in_the_future_does_not_raise(self) -> None:
        naive_expiry = datetime(2026, 1, 2, 12, 0)
        assert _session(expires_at=naive_expiry).is_expired_at(NOW) is False

    def test_a_naive_now_does_not_raise(self) -> None:
        assert _session(expires_at=datetime(2026, 1, 2, 12, 0)).is_expired_at(
            datetime(2026, 1, 1, 12, 0)
        ) is False

    def test_a_non_utc_expiry_is_normalised(self) -> None:
        from datetime import timezone as tz

        aware = datetime(2026, 1, 1, 12, 0, tzinfo=tz(timedelta(hours=2)))
        # 12:00+02:00 is 10:00Z, which is before NOW at 12:00Z.
        assert _session(expires_at=aware).is_expired_at(NOW) is True


class TestIsUsableAt:
    def test_a_live_session_is_usable(self) -> None:
        assert _session().is_usable_at(NOW) is True

    def test_a_revoked_session_is_not_usable(self) -> None:
        session = _session()
        session.revoke(NOW)
        assert session.is_usable_at(NOW) is False

    def test_an_expired_session_is_not_usable(self) -> None:
        session = _session(expires_at=NOW - timedelta(seconds=1))
        assert session.is_usable_at(NOW) is False

    def test_revocation_wins_over_a_live_expiry(self) -> None:
        """So the reason a session stopped working is unambiguous."""
        session = _session()
        session.revoke(NOW)
        assert session.expires_at > NOW
        assert session.is_usable_at(NOW) is False
