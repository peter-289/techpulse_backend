"""The security detection rules, and the thresholds that drive them.

These rules were an ``if`` / ``elif`` chain inside ``AuditService`` that read
their limits from ``app.core.config.settings``. Neither fact is testable without
a database and a process-global, which is why the alerting behaviour had no
coverage at all before Phase 4 -- the part of the security context that decides
when to raise an alert, on the one code path that runs for every API request.

The thresholds here are deliberately not the deployment defaults: the point of
injecting them is that a test can say "two attempts", and a test that used the
configured five would pass or fail depending on the environment.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.modules.shared.enums import AlertRuleCode, AlertSeverity, AuditEventType
from app.modules.security.domain.entities.audit_event import AuditEvent
from app.modules.security.domain.policies.alert_rules import rules_for
from app.modules.security.domain.ports.alert_thresholds import AlertThresholds


def _thresholds(
    *,
    login_failures: int = 2,
    access_denied: int = 3,
    lookback_minutes: int = 15,
    dedup_minutes: int = 15,
) -> AlertThresholds:
    return AlertThresholds(
        login_failures=login_failures,
        access_denied=access_denied,
        lookback=timedelta(minutes=lookback_minutes),
        dedup=timedelta(minutes=dedup_minutes),
    )


def _event(
    event_type: str,
    *,
    ip_address: str | None = "203.0.113.9",
    actor_user_id: str | None = None,
    status_code: int = 401,
) -> AuditEvent:
    event = AuditEvent.create(
        event_type=event_type,
        actor_user_id=actor_user_id,
        method="post",
        path="/api/v1/auth/login",
        status_code=status_code,
        ip_address=ip_address,
    )
    event.id = 4242
    return event


def test_a_failed_login_selects_the_brute_force_rule() -> None:
    rules = rules_for(_event(AuditEventType.LOGIN_FAILED), _thresholds())

    assert len(rules) == 1
    assert rules[0].code is AlertRuleCode.AUTH_BRUTE_FORCE_IP
    assert rules[0].severity is AlertSeverity.HIGH


def test_a_forbidden_request_selects_the_flood_rule() -> None:
    rules = rules_for(
        _event(AuditEventType.ACCESS_DENIED, status_code=403, ip_address=None),
        _thresholds(),
    )

    assert len(rules) == 1
    assert rules[0].code is AlertRuleCode.EXCESSIVE_FORBIDDEN_REQUESTS
    assert rules[0].severity is AlertSeverity.MEDIUM


@pytest.mark.parametrize(
    "event_type",
    ["http.request", "auth.login.success", "cookie.consent.accepted", "client.activity"],
)
def test_event_types_no_rule_watches_select_nothing(event_type: str) -> None:
    """Most audited events are ordinary traffic and must cost one dict lookup.

    Every one of these strings reaches the audit trail in production --
    ``http.request`` and ``auth.login.success`` from the middleware, the cookie
    and activity types from the analytics router -- and only two are members of
    ``AuditEventType``. Looking them up by coercing to that enum would raise
    ``ValueError`` on the common path.
    """
    assert rules_for(_event(event_type), _thresholds()) == ()


def test_a_failed_login_without_an_address_selects_nothing() -> None:
    """Without an address the rule has no subject.

    Counting failed logins across every client would let one attacker's attempts
    raise alerts against unrelated accounts, and would make any user's typo storm
    indistinguishable from an attack.
    """
    assert rules_for(_event(AuditEventType.LOGIN_FAILED, ip_address=None), _thresholds()) == ()


def test_the_threshold_fires_on_the_configured_count_not_the_next_one() -> None:
    """``>=``, so the alert arrives on the attempt the threshold names.

    The alert is the signal an operator acts on; arriving one attempt late is a
    missed attempt against a live credential.
    """
    rule = rules_for(_event(AuditEventType.LOGIN_FAILED), _thresholds(login_failures=5))[0]

    assert rule.exceeded_by(4) is False
    assert rule.exceeded_by(5) is True
    assert rule.exceeded_by(6) is True


def test_each_rule_binds_its_own_threshold() -> None:
    """The two rules read different numbers from the same configuration."""
    thresholds = _thresholds(login_failures=2, access_denied=7)

    brute_force = rules_for(_event(AuditEventType.LOGIN_FAILED), thresholds)[0]
    flood = rules_for(
        _event(AuditEventType.ACCESS_DENIED, status_code=403, ip_address=None), thresholds
    )[0]

    assert brute_force.threshold == 2
    assert flood.threshold == 7


def test_the_window_reaches_the_alert_description_unchanged() -> None:
    """The description is operator-facing text and reads the configured window."""
    rule = rules_for(
        _event(AuditEventType.LOGIN_FAILED), _thresholds(lookback_minutes=30)
    )[0]

    alert = rule.raise_alert(event=_event(AuditEventType.LOGIN_FAILED), count=5)

    assert alert.description == (
        "5 failed login attempts from IP 203.0.113.9 in the last 30 minute(s)."
    )


def test_the_alert_points_at_the_event_that_raised_it() -> None:
    """The foreign key is the reason ``save_event`` returns the saved entity."""
    thresholds = _thresholds()
    event = _event(AuditEventType.LOGIN_FAILED)

    rule = rules_for(event, thresholds)[0]
    alert = rule.raise_alert(event=event, count=2)

    assert alert.audit_event_id == 4242
    assert alert.ip_address == "203.0.113.9"
    assert alert.is_acknowledged() is False


def test_rules_are_not_shared_between_deployments() -> None:
    """Two services with different thresholds must not see each other's numbers.

    The module-level rule declarations say *what* is detected; the window and
    limit are bound per call, so binding them once at import would make the
    second configuration silently keep the first one's numbers.
    """
    strict = rules_for(_event(AuditEventType.LOGIN_FAILED), _thresholds(login_failures=2))[0]
    lenient = rules_for(_event(AuditEventType.LOGIN_FAILED), _thresholds(login_failures=50))[0]

    assert (strict.threshold, lenient.threshold) == (2, 50)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"login_failures": 0}, "login_failures must be at least 1"),
        ({"access_denied": 0}, "access_denied must be at least 1"),
        ({"login_failures": -1}, "login_failures must be at least 1"),
    ],
)
def test_thresholds_reject_values_that_never_alert(kwargs: dict, message: str) -> None:
    """A zero or negative limit fires on every request; that is not a limit.

    Rejecting it at construction means a bad value fails at startup rather than
    quietly turning the detection rules off.
    """
    with pytest.raises(ValueError, match=message):
        _thresholds(**kwargs)


@pytest.mark.parametrize("field", ["lookback_minutes", "dedup_minutes"])
def test_thresholds_reject_a_window_of_zero(field: str) -> None:
    """A zero-length window either counts nothing or deduplicates everything."""
    with pytest.raises(ValueError, match="must be positive"):
        _thresholds(**{field: 0})
