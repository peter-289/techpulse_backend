"""The audit service's read side, with a fake unit of work.

The write path has its own module. This one covers what Phase 8 added, and the
distinction it is really about is *which transaction* each operation opens.

``list_alerts`` and ``list_events`` read, so they must run on
``uow.read_only()``. ``acknowledge_alert`` writes, so it must run on the write
boundary that commits. The fake records both, because "a read that accidentally
commits" and "a write that forgot to" are the two failure modes the ``read_only``
context manager in ``app/modules/shared/unit_of_work.py`` exists to make visible,
and neither shows up in a test that only checks the returned value.

``acknowledge_alert`` is also the first live caller of
``SecurityAlert.acknowledge``. The aggregate has refused a second acknowledgement
since Phase 4 and, until now, only tests had exercised that; the guarantee that a
repeat call neither restamps ``acknowledged_at`` nor overwrites
``acknowledged_by_user_id`` is pinned here rather than in the endpoint module,
because it is a domain rule and the endpoint test would pass either way.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.modules.security.application.services.audit_service import AuditService
from app.modules.security.domain.entities.security_alert import SecurityAlert
from app.modules.security.domain.exceptions import AlertAlreadyAcknowledgedError
from app.modules.security.domain.ports.alert_thresholds import AlertThresholds
from app.modules.shared.enums import AlertRuleCode, AlertSeverity

_RAISED_AT = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


class _FakeAuditRepo:
    def __init__(self, *, alerts: list[SecurityAlert] | None = None) -> None:
        self.alerts = list(alerts or [])
        self.saved: list[SecurityAlert] = []
        self.list_alerts_calls: list[dict] = []
        self.list_events_calls: list[dict] = []

    async def save_alert(self, alert: SecurityAlert) -> SecurityAlert:
        self.saved.append(alert)
        return alert

    async def get_alert(self, alert_id: int) -> SecurityAlert | None:
        return next((a for a in self.alerts if a.id == alert_id), None)

    async def list_alerts(self, **kwargs) -> list[SecurityAlert]:
        self.list_alerts_calls.append(kwargs)
        return list(self.alerts)

    async def list_events(self, **kwargs) -> list[Any]:
        self.list_events_calls.append(kwargs)
        return []


class _FakeUow:
    """Records which boundary each operation opened, and in what order."""

    def __init__(self, repo: _FakeAuditRepo) -> None:
        self.audit_repo = repo
        self.opened: list[str] = []
        self.committed = False
        self.rolled_back = False

    async def __aenter__(self) -> "_FakeUow":
        self.opened.append("write")
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        if exc_type:
            self.rolled_back = True
        else:
            self.committed = True
        return False

    def read_only(self) -> "_ReadOnlyBoundary":
        self.opened.append("read_only")
        return _ReadOnlyBoundary(self)


class _ReadOnlyBoundary:
    def __init__(self, uow: _FakeUow) -> None:
        self._uow = uow

    async def __aenter__(self) -> "_FakeUow":
        return self._uow

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        # A read boundary never commits. If one ever does, the service is using
        # the wrong boundary and this is where the test notices.
        self._uow.rolled_back = exc_type is not None
        return False


def _service(*alerts: SecurityAlert) -> tuple[AuditService, _FakeUow, _FakeAuditRepo]:
    repo = _FakeAuditRepo(alerts=list(alerts))
    uow = _FakeUow(repo)
    return (
        AuditService(
            uow=uow,
            thresholds=AlertThresholds(
                login_failures=2,
                access_denied=3,
                lookback=timedelta(minutes=15),
                dedup=timedelta(minutes=15),
            ),
        ),
        uow,
        repo,
    )


def _alert(alert_id: int = 1, *, acknowledged: bool = False) -> SecurityAlert:
    alert = SecurityAlert.raise_alert(
        rule_code=AlertRuleCode.AUTH_BRUTE_FORCE_IP,
        severity=AlertSeverity.HIGH,
        title="Many failed logins",
        description="20 attempts from one address",
        audit_event_id=1,
        raised_at=_RAISED_AT,
    )
    alert.id = alert_id
    if acknowledged:
        alert.acknowledge(acknowledged_by_user_id="earlier-operator")
    return alert


# === listing ===


@pytest.mark.asyncio
async def test_listing_alerts_reads_and_never_commits() -> None:
    service, uow, repo = _service(_alert())

    listed = await service.list_alerts(only_unacknowledged=True, limit=25)

    assert [a.id for a in listed] == [1]
    assert uow.opened == ["read_only"]
    assert uow.committed is False
    assert repo.list_alerts_calls == [{"only_unacknowledged": True, "limit": 25}]


@pytest.mark.asyncio
async def test_listing_events_passes_the_filters_through_untouched() -> None:
    """The service narrows nothing.

    It is a facade over the repository here on purpose: which event types count as
    cookie activity is the endpoint's definition, and a second place that could
    quietly add a type would be a second answer to the same question.
    """
    service, uow, repo = _service()

    await service.list_events(
        event_types=("cookie.consent.accepted", "client.activity"),
        actor_user_id="actor-1",
        limit=200,
    )

    assert repo.list_events_calls == [
        {
            "event_types": ("cookie.consent.accepted", "client.activity"),
            "actor_user_id": "actor-1",
            "limit": 200,
        }
    ]
    assert uow.committed is False


# === acknowledgement ===


@pytest.mark.asyncio
async def test_acknowledging_delegates_to_the_aggregate_and_saves() -> None:
    service, uow, repo = _service(_alert(alert_id=7))

    saved = await service.acknowledge_alert(
        alert_id=7, acknowledged_by_user_id="operator-1"
    )

    assert saved.acknowledged is True
    assert saved.acknowledged_by_user_id == "operator-1"
    assert saved.acknowledged_at is not None
    assert repo.saved == [saved]
    assert uow.opened == ["write"]
    assert uow.committed is True


@pytest.mark.asyncio
async def test_acknowledging_an_unknown_alert_saves_nothing() -> None:
    """No such alert is an answer, not an error.

    The endpoint reports it as a 200 with a detail body, and inventing a domain
    exception for a case the caller handles as ordinary would add a type whose
    only handler is the thing that was trying to avoid it.
    """
    service, uow, repo = _service()

    assert await service.acknowledge_alert(alert_id=99, acknowledged_by_user_id="op") is None
    assert repo.saved == []
    assert uow.committed is True


@pytest.mark.asyncio
async def test_acknowledging_twice_is_refused_by_the_aggregate() -> None:
    service, uow, repo = _service(_alert(alert_id=3, acknowledged=True))

    with pytest.raises(AlertAlreadyAcknowledgedError):
        await service.acknowledge_alert(alert_id=3, acknowledged_by_user_id="second-operator")

    assert repo.saved == [], "a refused acknowledgement must not reach the repository"
    assert uow.rolled_back is True
    assert uow.committed is False


@pytest.mark.asyncio
async def test_a_refused_acknowledgement_leaves_the_first_operator_in_place() -> None:
    """The domain rule, and the reason it exists.

    ``acknowledged_at`` and ``acknowledged_by_user_id`` record who took
    responsibility and when. A second call that overwrote them would make the
    trail say the later operator responded first, which is the opposite of what
    happened.
    """
    alert = _alert(alert_id=4, acknowledged=True)
    first_seen = alert.acknowledged_at
    service, _uow, _repo = _service(alert)

    with pytest.raises(AlertAlreadyAcknowledgedError):
        await service.acknowledge_alert(alert_id=4, acknowledged_by_user_id="second-operator")

    assert alert.acknowledged_by_user_id == "earlier-operator"
    assert alert.acknowledged_at == first_seen
