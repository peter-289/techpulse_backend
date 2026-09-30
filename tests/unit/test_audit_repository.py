"""The audit repository's operator read path, against a real database.

``count_events`` and ``has_unacknowledged_alert`` have been covered by the write
path's tests. The three methods Phase 8 added -- ``get_alert``, ``list_alerts``,
``list_events`` -- arrived with the two admin endpoints that used to issue their
own ``select()`` statements, so nothing about them was tested before the router
moved. These run against SQLite rather than a fake because the thing worth
checking is precisely the part a fake cannot see: that a filter becomes the
``WHERE`` it claims to, and that an update updates.

``test_acknowledging_updates_the_row_instead_of_adding_a_second_one`` is the
reason this file is worth reading. ``alert_to_model`` originally left ``id`` out
on the grounds that the only caller was creating new alerts, so ``merge`` saw a
transient instance and inserted: acknowledging an alert produced a *second* row,
acknowledged, beside the original one, still open. The endpoint test caught it by
noticing the returned id was not the one it asked for; this test pins the
consequence -- the table does not grow.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import app.infrastructure.database.models  # noqa: F401  (registers all tables)
from app.infrastructure.database.db_setup import Base
from app.modules.security.domain.entities.security_alert import SecurityAlert
from app.modules.security.domain.exceptions import AuditRepositoryUnavailableError
from app.modules.security.infrastructure.persistence.repositories.audit_repo import (
    SQLAlchemyAuditRepository,
)
from app.modules.shared.enums import AlertRuleCode, AlertSeverity

_BASE_TIME = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def repo(session_factory):
    async with session_factory() as db:
        yield SQLAlchemyAuditRepository(db)


def _alert_entity(**overrides) -> SecurityAlert:
    """A raised alert, not yet saved -- so ``id`` is still ``None``."""
    return SecurityAlert.raise_alert(
        rule_code=overrides.pop("rule_code", AlertRuleCode.AUTH_BRUTE_FORCE_IP),
        severity=overrides.pop("severity", AlertSeverity.HIGH),
        title=overrides.pop("title", "Many failed logins"),
        description=overrides.pop("description", "20 attempts from one address"),
        audit_event_id=overrides.pop("audit_event_id", 1),
        actor_user_id=overrides.pop("actor_user_id", None),
        ip_address=overrides.pop("ip_address", "203.0.113.9"),
        raised_at=overrides.pop("raised_at", _BASE_TIME),
    )


async def _save_alert(repo, **overrides) -> SecurityAlert:
    return await repo.save_alert(_alert_entity(**overrides))


async def _save_event(repo, **overrides):
    from app.modules.security.domain.entities.audit_event import AuditEvent

    event = AuditEvent.create(
        event_type=overrides.pop("event_type", "http.request"),
        method="GET",
        path="/api/v1/thing",
        status_code=200,
        actor_user_id=overrides.pop("actor_user_id", None),
        ip_address=overrides.pop("ip_address", "198.51.100.1"),
        metadata=overrides.pop("metadata", None),
        occurred_at=overrides.pop("occurred_at", _BASE_TIME),
    )
    return await repo.save_event(event)


# === save_alert: insert and update ===


@pytest.mark.asyncio
async def test_a_new_alert_is_inserted_and_comes_back_with_its_id(repo) -> None:
    saved = await _save_alert(repo)

    assert saved.id is not None
    assert (await repo.get_alert(saved.id)).title == "Many failed logins"


@pytest.mark.asyncio
async def test_acknowledging_updates_the_row_instead_of_adding_a_second_one(repo) -> None:
    saved = await _save_alert(repo)

    saved.acknowledge(acknowledged_by_user_id="operator-1")
    await repo.save_alert(saved)

    listed = await repo.list_alerts(limit=10)
    assert len(listed) == 1, "the table grew: merge inserted rather than updating"
    assert listed[0].id == saved.id
    assert listed[0].acknowledged is True
    assert listed[0].acknowledged_by_user_id == "operator-1"


@pytest.mark.asyncio
async def test_saving_an_update_does_not_move_the_created_timestamp(repo) -> None:
    """``created_at`` is a server default and must survive an update.

    The value is whatever the database recorded at insert; the property under
    test is that an update does not change it. It is the column the triage list
    orders by, and a mapper that copied the entity's value over it would rewrite
    when the alert fired every time an operator opened it.
    """
    saved = await _save_alert(repo, raised_at=_BASE_TIME)
    created_before = (await repo.get_alert(saved.id)).created_at

    saved.acknowledge(acknowledged_by_user_id="operator-1")
    await repo.save_alert(saved)

    assert (await repo.get_alert(saved.id)).created_at == created_before


@pytest.mark.asyncio
async def test_the_column_is_never_written_by_the_mapper() -> None:
    """The invariant behind the test above, stated directly.

    ``alert_to_model`` produces a transient row for ``merge``. If it assigned
    ``created_at`` at all, the value would be the entity's -- and for an entity
    whose ``created_at`` was never set that is ``None``, which a
    ``nullable=False`` column rejects. Asserting on the model rather than on a
    saved row keeps the guarantee independent of which path wrote last.
    """
    from app.modules.security.infrastructure.persistence.mappers.audit_mapper import (
        alert_to_model,
    )

    model = alert_to_model(_alert_entity())

    assert model.created_at is None, "the mapper must leave the server default alone"


# === get_alert ===


@pytest.mark.asyncio
async def test_get_alert_returns_none_for_an_unknown_id(repo) -> None:
    assert await repo.get_alert(4242) is None


@pytest.mark.asyncio
async def test_get_alert_round_trips_the_typed_fields(repo) -> None:
    """The rule code and severity come back as enum members, not strings.

    A caller comparing ``alert.rule_code`` to ``AlertRuleCode.X`` must succeed;
    an equal-but-not-identical string would make that an identity test by
    accident.
    """
    saved = await _save_alert(
        repo, rule_code=AlertRuleCode.EXCESSIVE_FORBIDDEN_REQUESTS, severity=AlertSeverity.CRITICAL
    )

    loaded = await repo.get_alert(saved.id)

    assert loaded.rule_code is AlertRuleCode.EXCESSIVE_FORBIDDEN_REQUESTS
    assert loaded.severity is AlertSeverity.CRITICAL
    assert isinstance(loaded, SecurityAlert)


@pytest.mark.asyncio
async def test_a_load_reconstructs_the_aggregate_rather_than_the_row(repo) -> None:
    """An alert row written before the aggregate existed still loads.

    ``acknowledged`` with no ``acknowledged_at`` is exactly what a row written by
    the pre-Phase-4 router looks like, and the entity supplies the missing
    timestamp so a triage list can order by it.
    """
    from app.infrastructure.database.models.security_alert import SecurityAlert as Model

    row = Model(
        rule_code=AlertRuleCode.AUTH_BRUTE_FORCE_IP.value,
        severity=AlertSeverity.LOW.value,
        title="legacy",
        description="written before the aggregate",
        acknowledged=True,
        acknowledged_at=None,
        created_at=_BASE_TIME,
    )
    repo.session.add(row)
    await repo.session.flush()

    loaded = await repo.get_alert(row.id)

    assert loaded.acknowledged is True
    assert loaded.acknowledged_at == loaded.created_at


# === list_alerts ===


@pytest.mark.asyncio
async def test_list_alerts_is_newest_first(repo) -> None:
    await _save_alert(repo, title="oldest", raised_at=_BASE_TIME - timedelta(hours=2))
    await _save_alert(repo, title="middle", raised_at=_BASE_TIME - timedelta(hours=1))
    await _save_alert(repo, title="newest", raised_at=_BASE_TIME)

    assert [a.title for a in await repo.list_alerts(limit=10)] == ["newest", "middle", "oldest"]


@pytest.mark.asyncio
async def test_list_alerts_can_return_only_the_open_ones(repo) -> None:
    open_alert = await _save_alert(repo, title="open")
    acknowledged = await _save_alert(repo, title="taken", raised_at=_BASE_TIME + timedelta(minutes=1))
    acknowledged.acknowledge(acknowledged_by_user_id="operator-1")
    await repo.save_alert(acknowledged)

    only_open = await repo.list_alerts(only_unacknowledged=True, limit=10)
    assert [a.id for a in only_open] == [open_alert.id]

    everything = await repo.list_alerts(limit=10)
    assert len(everything) == 2


@pytest.mark.asyncio
async def test_list_alerts_honours_the_limit(repo) -> None:
    for n in range(5):
        await _save_alert(repo, title=f"alert-{n}", raised_at=_BASE_TIME + timedelta(minutes=n))

    assert len(await repo.list_alerts(limit=2)) == 2


class _RecordingSession:
    """Passes everything through, keeping the statements it was handed.

    Exists for one assertion. The id tiebreaks in ``list_alerts`` and
    ``list_events`` cannot be observed through their results on SQLite: a
    covering-index scan over ``created_at`` already returns equal keys in
    descending rowid order, so a test that only checked the returned order would
    pass with the tiebreak deleted. That was confirmed by mutation rather than
    assumed. The order the clause produces is a property of the *statement*, so
    the statement is what gets asserted.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.statements: list = []

    async def execute(self, statement, *args, **kwargs):
        self.statements.append(statement)
        return await self._inner.execute(statement, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.mark.asyncio
async def test_a_tied_page_of_alerts_has_a_fixed_order(session_factory) -> None:
    """``ORDER BY created_at DESC, id DESC``.

    ``created_at`` comes from ``server_default=func.now()``, so a burst of
    alerts raised in the same second share a timestamp and the first term cannot
    separate them. Without the second term the order of a page is whatever the
    database returned, which differs between SQLite and PostgreSQL and can
    differ between two identical requests -- so an operator refreshing the
    triage list could see a row move.
    """
    async with session_factory() as db:
        recording = _RecordingSession(db)
        repo = SQLAlchemyAuditRepository(recording)
        await repo.list_alerts(limit=10)

    sql = str(recording.statements[-1]).replace("\n", " ")
    assert "security_alerts.created_at DESC" in sql
    assert "security_alerts.id DESC" in sql


@pytest.mark.asyncio
async def test_a_tied_page_of_events_has_a_fixed_order(session_factory) -> None:
    """The same guarantee for the audit trail, which has no index on
    ``occurred_at`` at all -- so here there is no index scan to fall back on and
    the second term is the only thing making the order reproducible."""
    async with session_factory() as db:
        recording = _RecordingSession(db)
        repo = SQLAlchemyAuditRepository(recording)
        await repo.list_events(limit=10)

    sql = str(recording.statements[-1]).replace("\n", " ")
    assert "audit_events.occurred_at DESC" in sql
    assert "audit_events.id DESC" in sql


# === list_events ===


@pytest.mark.asyncio
async def test_list_events_is_newest_first(repo) -> None:
    await _save_event(repo, event_type="http.request", occurred_at=_BASE_TIME - timedelta(minutes=5))
    await _save_event(repo, event_type="http.request", occurred_at=_BASE_TIME)

    events = await repo.list_events(limit=10)
    assert [e.event_type for e in events] == ["http.request", "http.request"]
    assert events[0].occurred_at > events[1].occurred_at


@pytest.mark.asyncio
async def test_list_events_filters_on_a_set_of_types(repo) -> None:
    await _save_event(repo, event_type="http.request")
    await _save_event(repo, event_type="client.activity")
    await _save_event(repo, event_type="cookie.consent.accepted")

    events = await repo.list_events(event_types=("client.activity", "cookie.consent.accepted"), limit=10)

    assert sorted(e.event_type for e in events) == [
        "client.activity",
        "cookie.consent.accepted",
    ]


@pytest.mark.asyncio
async def test_an_unset_type_set_places_no_constraint(repo) -> None:
    """``None`` means "every type", which is what the unfiltered endpoint wants.

    Distinct from an empty tuple, which would match nothing -- and the two being
    different is the reason the port takes ``None`` rather than defaulting to
    ``()``.
    """
    await _save_event(repo, event_type="http.request")
    await _save_event(repo, event_type="auth.login.success")

    assert len(await repo.list_events(limit=10)) == 2
    assert await repo.list_events(event_types=(), limit=10) == []


@pytest.mark.asyncio
async def test_list_events_filters_by_actor(repo) -> None:
    await _save_event(repo, event_type="http.request", actor_user_id=None)
    await _save_event(repo, event_type="http.request", actor_user_id="actor-1")

    events = await repo.list_events(actor_user_id="actor-1", limit=10)

    assert [e.actor_user_id for e in events] == ["actor-1"]


@pytest.mark.asyncio
async def test_list_events_round_trips_metadata(repo) -> None:
    await _save_event(repo, event_type="http.request", metadata={"page": "/x"})

    assert (await repo.list_events(limit=1))[0].metadata == {"page": "/x"}


# === failure translation ===


@pytest.mark.asyncio
async def test_a_driver_failure_becomes_a_repository_unavailable_error(repo) -> None:
    """Every method here translates, so a caller never names the ORM.

    The port is what makes this checkable: the service catches
    ``AuditRepositoryUnavailableError``, and an escaping ``SQLAlchemyError``
    would reach it as a 500 with no log line naming the store.
    """

    class _Broken:
        def __getattr__(self, name):
            def _fail(*args, **kwargs):
                from sqlalchemy.exc import SQLAlchemyError

                raise SQLAlchemyError("connection reset")

            return _fail

    repo.session = _Broken()

    for call in (
        repo.get_alert(1),
        repo.list_alerts(limit=1),
        repo.list_events(limit=1),
    ):
        with pytest.raises(AuditRepositoryUnavailableError):
            await call
