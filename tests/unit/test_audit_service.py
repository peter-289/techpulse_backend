"""The audit write path: record the event, then decide whether to alert.

``AuditService.log_audit_event`` had no test. It runs for every API request via
the middleware's background task, so a break in it is not a single broken
endpoint -- it is an audit trail that silently stops recording. It was also the
only place the detection rules lived, expressed as a branch against
``app.core.config.settings``, which is why the alerting behaviour could not be
exercised without mutating a process global.

These tests use a fake Unit of Work, so they run without a database. That is the
point of the phase: the port takes domain arguments now, so the decisions can be
tested directly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.exceptions.exceptions import DomainError
from app.modules.security.application.services.audit_service import AuditService
from app.modules.security.domain.entities.audit_event import AuditEvent
from app.modules.security.domain.ports.alert_thresholds import AlertThresholds


class _FakeAuditRepo:
    """Records what the service asked for, in the order it asked."""

    def __init__(self, *, event_count: int = 0, existing_alert: bool = False) -> None:
        self.event_count = event_count
        self.existing_alert = existing_alert
        self.events: list[AuditEvent] = []
        self.alerts: list = []
        self.count_calls: list[dict] = []
        self.dedup_calls: list[dict] = []
        #: How many alerts existed when the unit of work closed. Asserting on
        #: this rather than on the final list is what distinguishes "written
        #: inside the transaction" from "written inside anyway".
        self.alerts_at_commit = -1

    async def save_event(self, event: AuditEvent) -> AuditEvent:
        event.id = 100 + len(self.events)
        self.events.append(event)
        return event

    async def count_events(self, **kwargs) -> int:
        self.count_calls.append(kwargs)
        return self.event_count

    async def has_unacknowledged_alert(self, **kwargs) -> bool:
        self.dedup_calls.append(kwargs)
        return self.existing_alert

    async def save_alert(self, alert) -> object:
        self.alerts.append(alert)
        return alert


class _FakeUow:
    def __init__(self, repo: _FakeAuditRepo) -> None:
        self.audit_repo = repo
        self.committed = False
        self.rolled_back = False

    async def __aenter__(self) -> "_FakeUow":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        self.audit_repo.alerts_at_commit = len(self.audit_repo.alerts)
        if exc_type:
            self.rolled_back = True
        else:
            self.committed = True
        return False


def _service(
    *,
    event_count: int = 0,
    existing_alert: bool = False,
    thresholds: AlertThresholds | None = None,
) -> tuple[AuditService, _FakeUow, _FakeAuditRepo]:
    repo = _FakeAuditRepo(event_count=event_count, existing_alert=existing_alert)
    uow = _FakeUow(repo)
    service = AuditService(
        uow=uow,
        thresholds=thresholds
        or AlertThresholds(
            login_failures=2,
            access_denied=3,
            lookback=timedelta(minutes=15),
            dedup=timedelta(minutes=15),
        ),
    )
    return service, uow, repo


_BASE_EVENT = {
    "event_type": "http.request",
    "actor_user_id": None,
    "method": "get",
    "path": "/api/v1/software",
    "status_code": 200,
    "ip_address": "203.0.113.9",
    "user_agent": "pytest",
    "request_id": "req-1",
    "metadata": None,
}


async def test_the_event_is_recorded_and_the_transaction_commits() -> None:
    service, uow, repo = _service()

    await service.log_audit_event(**_BASE_EVENT)

    assert len(repo.events) == 1
    assert uow.committed is True
    assert uow.rolled_back is False


async def test_ordinary_traffic_raises_nothing_and_counts_nothing() -> None:
    """A 200 is the overwhelming majority of audited requests.

    It cannot trip any rule, so it must not cost a query. Asserting zero count
    calls is how that stays true: an unconditional count would double the query
    load of the whole application to serve the requests that alert on nothing.
    """
    service, _, repo = _service(event_count=999)

    await service.log_audit_event(**_BASE_EVENT)

    assert repo.count_calls == []
    assert repo.alerts == []


async def test_below_the_threshold_records_the_event_and_no_alert() -> None:
    service, _, repo = _service(event_count=1)

    await service.log_audit_event(
        **{**_BASE_EVENT, "event_type": "auth.login.failed", "status_code": 401}
    )

    assert len(repo.events) == 1
    assert repo.alerts == []


async def test_at_the_threshold_an_alert_is_raised() -> None:
    service, _, repo = _service(event_count=2)

    await service.log_audit_event(
        **{**_BASE_EVENT, "event_type": "auth.login.failed", "status_code": 401}
    )

    assert len(repo.alerts) == 1
    assert repo.alerts[0].rule_code == "AUTH_BRUTE_FORCE_IP"
    assert repo.alerts[0].audit_event_id == repo.events[0].id


async def test_the_alert_is_skipped_when_the_window_already_has_one() -> None:
    """Dedup is what turns a sustained attack into one actionable alert.

    Without it, an attacker producing 500 failed logins would produce 500
    alerts, and the alert list would be unusable exactly when it matters most.
    """
    service, _, repo = _service(event_count=2, existing_alert=True)

    await service.log_audit_event(
        **{**_BASE_EVENT, "event_type": "auth.login.failed", "status_code": 401}
    )

    assert repo.alerts == []
    assert len(repo.dedup_calls) == 1


async def test_deduplication_is_checked_only_after_the_threshold_is_met() -> None:
    """Below the threshold there is nothing to deduplicate, so nothing to ask."""
    service, _, repo = _service(event_count=1, existing_alert=False)

    await service.log_audit_event(
        **{**_BASE_EVENT, "event_type": "auth.login.failed", "status_code": 401}
    )

    assert repo.dedup_calls == []


async def test_the_count_is_scoped_to_the_rule_window() -> None:
    """The repository is asked for a window, not "all history"."""
    service, _, repo = _service(event_count=0)

    await service.log_audit_event(
        **{**_BASE_EVENT, "event_type": "auth.login.failed", "status_code": 401}
    )

    call = repo.count_calls[0]
    assert call["event_type"] == "auth.login.failed"
    assert call["ip_address"] == "203.0.113.9"
    assert call["actor_user_id"] is None


async def test_the_alert_is_written_before_the_transaction_closes() -> None:
    """An alert references the event, so a rollback must take both.

    If the alert were written outside the unit of work, a failed commit would
    leave an alert pointing at an event nobody can find -- a finding with no
    evidence, which is worse than no finding.
    """
    repo = _FakeAuditRepo(event_count=2)
    uow = _FakeUow(repo)
    service = AuditService(
        uow=uow,
        thresholds=AlertThresholds(
            login_failures=2,
            access_denied=3,
            lookback=timedelta(minutes=15),
            dedup=timedelta(minutes=15),
        ),
    )

    await service.log_audit_event(
        **{**_BASE_EVENT, "event_type": "auth.login.failed", "status_code": 401}
    )

    assert repo.alerts_at_commit == 1


async def test_a_repository_failure_becomes_a_domain_error() -> None:
    """One exception type for the caller, which is a background task with no recourse."""

    class _BrokenRepo(_FakeAuditRepo):
        async def save_event(self, event: AuditEvent) -> AuditEvent:
            raise RuntimeError("connection reset")

    service = AuditService(
        uow=_FakeUow(_BrokenRepo()),
        thresholds=AlertThresholds(
            login_failures=2,
            access_denied=3,
            lookback=timedelta(minutes=15),
            dedup=timedelta(minutes=15),
        ),
    )

    with pytest.raises(DomainError):
        await service.log_audit_event(**_BASE_EVENT)


async def test_a_long_path_is_recorded_rather_than_rejected() -> None:
    """The event is built by the domain and truncated by the mapper.

    The service used to truncate ``path`` to 500 characters while the column is
    ``varchar(255)``, so a request with a path between those lengths raised a
    database error and lost the audit event. Truncation is a storage decision, so
    the domain keeps the path whole and the mapper shortens it.
    """
    from app.modules.security.infrastructure.persistence.mappers.audit_mapper import (
        event_to_model,
    )

    long_path = "/api/v1/software/" + "a" * 400
    service, _, repo = _service()

    await service.log_audit_event(**{**_BASE_EVENT, "path": long_path})

    assert repo.events[0].path == long_path
    assert len(event_to_model(repo.events[0]).path) == 255


async def test_the_method_is_normalised_and_metadata_defaults_to_an_empty_dict() -> None:
    service, _, repo = _service()

    await service.log_audit_event(**{**_BASE_EVENT, "method": " get "})

    assert repo.events[0].method == "GET"
    assert repo.events[0].metadata == {}


async def test_a_naive_occurred_at_is_read_as_utc() -> None:
    """The column is ``timestamptz``; a naive value would be ambiguous on read."""
    service, _, repo = _service()

    await service.log_audit_event(**_BASE_EVENT)

    occurred_at: datetime = repo.events[0].occurred_at
    assert occurred_at.tzinfo is timezone.utc
