"""The SecurityAlert aggregate's lifecycle.

The aggregate is new in Phase 4, so its behaviour is asserted rather than
inherited from a previous implementation. Acknowledgement in particular had
nowhere to live before: ``admin_router`` set ``acknowledged = True`` on the ORM
row directly, so no invariant could be expressed about it. The rule that
acknowledging twice is an error is the reason this is an aggregate and not a
dictionary.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.modules.shared.enums import AlertRuleCode, AlertSeverity
from app.modules.security.domain.entities.security_alert import SecurityAlert
from app.modules.security.domain.exceptions import AlertAlreadyAcknowledgedError


def _alert(**overrides) -> SecurityAlert:
    kwargs = {
        "rule_code": AlertRuleCode.AUTH_BRUTE_FORCE_IP,
        "severity": AlertSeverity.HIGH,
        "title": "Possible brute force login attempts",
        "description": "5 failed login attempts from IP 203.0.113.9 in the last 15 minute(s).",
        "audit_event_id": 4242,
        "actor_user_id": None,
        "ip_address": "203.0.113.9",
    }
    kwargs.update(overrides)
    return SecurityAlert.raise_alert(**kwargs)


def test_a_new_alert_is_open() -> None:
    alert = _alert()

    assert alert.is_acknowledged() is False
    assert alert.acknowledged_at is None
    assert alert.acknowledged_by_user_id is None


def test_acknowledging_records_who_and_when() -> None:
    alert = _alert()
    before = datetime.now(timezone.utc)

    alert.acknowledge(acknowledged_by_user_id="user-7")

    assert alert.is_acknowledged() is True
    assert alert.acknowledged_by_user_id == "user-7"
    assert alert.acknowledged_at is not None
    assert alert.acknowledged_at >= before


def test_acknowledging_twice_is_an_error() -> None:
    """Silently succeeding would lose the fact that a second operator opened it.

    That is the first question an incident review asks, and it is not
    recoverable from the row afterwards if the second write is a no-op.
    """
    alert = _alert()
    alert.acknowledge(acknowledged_by_user_id="user-7")

    with pytest.raises(AlertAlreadyAcknowledgedError):
        alert.acknowledge(acknowledged_by_user_id="user-9")

    assert alert.acknowledged_by_user_id == "user-7"


def test_an_alert_loaded_as_acknowledged_gets_a_timestamp() -> None:
    """Rows written before this aggregate existed have no ``acknowledged_at``.

    A triage list orders by acknowledgement time, so an acknowledged alert with
    none would sort unpredictably. Backfilling from ``created_at`` is the
    closest true statement available.
    """
    alert = SecurityAlert(
        rule_code=AlertRuleCode.AUTH_BRUTE_FORCE_IP,
        severity=AlertSeverity.HIGH,
        title="t",
        description="d",
        audit_event_id=1,
        acknowledged=True,
        created_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )

    assert alert.acknowledged_at == alert.created_at


def test_naive_timestamps_are_read_as_utc() -> None:
    """The columns are ``timestamptz``; a naive value is ambiguous on read."""
    alert = SecurityAlert(
        rule_code=AlertRuleCode.AUTH_BRUTE_FORCE_IP,
        severity=AlertSeverity.HIGH,
        title="t",
        description="d",
        audit_event_id=1,
        created_at=datetime(2026, 1, 2, 3, 4, 5),
        acknowledged=True,
        acknowledged_at=datetime(2026, 1, 2, 4, 0, 0),
    )

    assert alert.created_at.tzinfo is timezone.utc
    assert alert.acknowledged_at == datetime(2026, 1, 2, 4, 0, 0, tzinfo=timezone.utc)
