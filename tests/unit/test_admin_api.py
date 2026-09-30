"""The operator-facing admin endpoints: audit trail, alerts, and the log tail.

Five endpoints under ``/api/v1/admin`` had no test at all before this file. The
router built its ``select()`` statements inline and assembled its response
dictionaries by hand, so nothing pinned what any of them actually returned --
which is what let ``SecurityAlert.acknowledge`` exist as a domain rule that no
live path called.

Every assertion here is a characterisation, not a specification of intent. Each
one was run against the pre-refactor router and kept verbatim through the move to
the security context, so "the response did not change" is a checked claim rather
than an assumed one. Where a behaviour is a wart rather than a design, the test
says so and pins the wart, because the alternative is a silent fix that arrives
with a refactor nobody can review.

The app under test is built here rather than imported from ``app.main``: the real
one installs ``AuditMiddleware``, which writes every request to ``SessionLocal``
-- the configured database, not this test's -- and would make the audit-trail
assertions non-deterministic. ``test_public_http_surface`` already pins the real
registration, so nothing is lost.

**Ten of these tests were red before Phase 8, and the reason is the finding of
the phase.** All three list endpoints computed their count with
``len(result.scalars().all())`` and then iterated the *same* ``result`` to build
``items``. ``Result.all()`` closes the result it drained, so the loop that
followed saw nothing: ``GET /admin/alerts``, ``GET /admin/audit-events`` and
``GET /admin/cookie-activity`` have always answered ``{"count": N, "items":
[]}`` -- a correct count next to an empty list, which reads like a working
endpoint that happens to have no rows. Nothing noticed because nothing tested
them. The assertions below are what the endpoints are supposed to do, and they
now hold; the behaviour change from ``items: []`` to the real rows is Phase 8's
one deliberate client-visible change and is recorded as such in
``docs/REVIEW.md``.

The remaining fourteen -- the two that were already working, plus the
authorisation, validation and redaction checks -- were green against the
pre-refactor router and stayed green, which is the part that makes the move to
the security context a refactor rather than a rewrite.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from jose import jwt
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import app.infrastructure.database.models  # noqa: F401  (registers all tables)
from app.core.config import settings
from app.exceptions.handlers import register_exception_handlers
from app.infrastructure.database.db_setup import Base
from app.infrastructure.database.models.audit_event import AuditEvent
from app.infrastructure.database.models.security_alert import SecurityAlert
from app.infrastructure.database.models.session import UserSession
from app.infrastructure.database.models.user import User

# The router under test. Phase 8 moves this file from the user context to the
# security context; nothing below this line changes when it does.
from app.modules.security.api.router.admin_router import router as admin_router
from app.modules.security.token_manager import (
    ACCESS_TOKEN_TYPE,
    EXPECTED_ISSUER,
)
from app.modules.shared.dependencies import get_db
from app.modules.shared.enums import RoleEnum, UserStatus

#: The event types ``/admin/cookie-activity`` is defined as tracking. Spelled out
#: here rather than imported, because the set is the endpoint's contract.
#: Real UUID strings: ``actor_user_id`` is declared ``UUID | None`` on all three
#: endpoints, so a non-UUID filter value is a 422 rather than an empty result --
#: which is a distinction worth being unable to confuse with "no matches".
_ACTOR_ONE = "11111111-1111-4111-8111-111111111111"
_ACTOR_TWO = "22222222-2222-4222-8222-222222222222"

COOKIE_TRACKED_TYPES = (
    "cookie.consent.accepted",
    "cookie.consent.declined",
    "client.activity",
)


def _access_token(user_id: str, session_id: int) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": user_id,
            "sid": session_id,
            "typ": ACCESS_TOKEN_TYPE,
            "iss": EXPECTED_ISSUER,
            "iat": now,
            "jti": "jti-for-tests",
            "exp": now + timedelta(minutes=30),
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


@pytest_asyncio.fixture
async def session_factory():
    """One in-memory database shared by every session in the test.

    ``StaticPool`` is required, not incidental: without it each connection to
    ``:memory:`` gets its own private database, and the request's session would
    not see the rows the test seeded through another one.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def admin_token(session_factory) -> str:
    """A verified admin with a live session, and a bearer token bound to it."""
    async with session_factory() as db:
        user = User(
            id=str(uuid4()),
            full_name="Admin",
            username=f"admin_{uuid4().hex[:8]}",
            email=f"{uuid4().hex}@example.com",
            password_hash="$argon2id$fake",
            status=UserStatus.VERIFIED,
            role=RoleEnum.ADMIN,
        )
        user_session = UserSession(
            user_id=user.id,
            refresh_token_hash=uuid4().hex,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        db.add_all([user, user_session])
        await db.commit()
        await db.refresh(user_session)
        return _access_token(user.id, user_session.id)


@pytest_asyncio.fixture
async def user_token(session_factory) -> str:
    """A verified non-admin, to pin that the admin routes are actually guarded."""
    async with session_factory() as db:
        user = User(
            id=str(uuid4()),
            full_name="Plain",
            username=f"user_{uuid4().hex[:8]}",
            email=f"{uuid4().hex}@example.com",
            password_hash="$argon2id$fake",
            status=UserStatus.VERIFIED,
            role=RoleEnum.USER,
        )
        user_session = UserSession(
            user_id=user.id,
            refresh_token_hash=uuid4().hex,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        db.add_all([user, user_session])
        await db.commit()
        await db.refresh(user_session)
        return _access_token(user.id, user_session.id)


@pytest_asyncio.fixture
async def client(session_factory):
    """An HTTP client bound to the admin router with a test-scoped database."""
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(admin_router)

    async def _get_db():
        async with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = _get_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _seed_events(session_factory, *specs) -> list[int]:
    """Insert audit events.

    Each spec is ``(event_type, actor_user_id, ip_address, metadata, age)`` where
    ``age`` is how long before now the event happened, so ordering is explicit
    rather than dependent on insertion order.
    """
    now = datetime.now(timezone.utc)
    rows = [
        AuditEvent(
            event_type=event_type,
            actor_user_id=actor,
            method="GET",
            path="/api/v1/thing",
            status_code=200,
            ip_address=ip,
            user_agent="agent/1.0",
            request_id=uuid4().hex,
            metadata_json=metadata,
            occurred_at=now - age,
        )
        for event_type, actor, ip, metadata, age in specs
    ]
    async with session_factory() as db:
        db.add_all(rows)
        await db.commit()
        for row in rows:
            await db.refresh(row)
        return [row.id for row in rows]


async def _seed_alert(
    session_factory,
    *,
    acknowledged: bool = False,
    acknowledged_at: datetime | None = None,
    acknowledged_by: str | None = None,
    age: timedelta = timedelta(minutes=1),
    severity: str = "high",
    rule_code: str = "AUTH_BRUTE_FORCE_IP",
    title: str = "Many failed logins",
) -> SecurityAlert:
    row = SecurityAlert(
        rule_code=rule_code,
        severity=severity,
        title=title,
        description="20 failed logins from one address",
        actor_user_id=None,
        ip_address="203.0.113.9",
        audit_event_id=None,
        acknowledged=acknowledged,
        acknowledged_at=acknowledged_at,
        acknowledged_by_user_id=acknowledged_by,
        created_at=datetime.now(timezone.utc) - age,
    )
    async with session_factory() as db:
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return row


# === authorization ===


@pytest.mark.asyncio
async def test_every_admin_route_rejects_anonymous_callers(client, session_factory) -> None:
    for method, path in (
        ("GET", "/api/v1/admin/alerts"),
        ("GET", "/api/v1/admin/audit-events"),
        ("GET", "/api/v1/admin/cookie-activity"),
        ("GET", "/api/v1/admin/logs"),
    ):
        response = await client.request(method, path)
        assert response.status_code == 401, path
    response = await client.patch("/api/v1/admin/alerts/1/ack")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_every_admin_route_rejects_a_non_admin(client, user_token, session_factory) -> None:
    for method, path in (
        ("GET", "/api/v1/admin/alerts"),
        ("GET", "/api/v1/admin/audit-events"),
        ("GET", "/api/v1/admin/cookie-activity"),
        ("GET", "/api/v1/admin/logs"),
    ):
        response = await client.request(method, path, headers=_auth(user_token))
        assert response.status_code == 403, path
        assert response.json() == {"detail": "Forbidden!"}
    response = await client.patch("/api/v1/admin/alerts/1/ack", headers=_auth(user_token))
    assert response.status_code == 403


# === GET /api/v1/admin/logs ===


@pytest.mark.asyncio
async def test_logs_returns_the_configured_path_and_the_requested_line_count(
    client, admin_token, tmp_path, monkeypatch
) -> None:
    log = tmp_path / "app.log"
    log.write_text("".join(f"line {n}\n" for n in range(10)), encoding="utf-8")
    monkeypatch.setattr(settings, "LOG_FILE_PATH", str(log))

    response = await client.get("/api/v1/admin/logs?lines=3", headers=_auth(admin_token))

    assert response.status_code == 200
    body = response.json()
    assert body["log_file"] == str(log)
    assert body["lines_requested"] == 3
    assert body["entries"] == ["line 7", "line 8", "line 9"]


@pytest.mark.asyncio
async def test_logs_redacts_credentials_before_returning_them(
    client, admin_token, tmp_path, monkeypatch
) -> None:
    """The point of the endpoint: an operator can read the log safely.

    A tail of an application log will contain whatever was logged, and a bearer
    token or a password in it would be handed straight to the browser by an
    endpoint whose whole purpose is to make the log readable. So this is a
    behaviour worth pinning as carefully as the ordering.
    """
    log = tmp_path / "app.log"
    log.write_text(
        "Authorization: Bearer eyJhbGciOi.payload.signature\n"
        "password=hunter2\n"
        'refresh_token: "rt-secret-value"\n'
        "access_token=at-secret-value\n"
        "nothing to see here\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "LOG_FILE_PATH", str(log))

    response = await client.get("/api/v1/admin/logs", headers=_auth(admin_token))

    assert response.status_code == 200
    entries = response.json()["entries"]
    joined = "\n".join(entries)
    assert "hunter2" not in joined
    assert "rt-secret-value" not in joined
    assert "at-secret-value" not in joined
    assert "eyJhbGciOi.payload.signature" not in joined
    assert "nothing to see here" in joined


@pytest.mark.asyncio
async def test_logs_tolerates_a_missing_file(client, admin_token, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "LOG_FILE_PATH", str(tmp_path / "never-written.log"))

    response = await client.get("/api/v1/admin/logs", headers=_auth(admin_token))

    assert response.status_code == 200
    assert response.json()["entries"] == []


@pytest.mark.asyncio
async def test_logs_validates_the_line_count(client, admin_token) -> None:
    assert (await client.get("/api/v1/admin/logs?lines=0", headers=_auth(admin_token))).status_code == 422
    assert (await client.get("/api/v1/admin/logs?lines=1001", headers=_auth(admin_token))).status_code == 422


# === GET /api/v1/admin/alerts ===


@pytest.mark.asyncio
async def test_alerts_hides_acknowledged_ones_by_default(
    client, admin_token, session_factory
) -> None:
    await _seed_alert(session_factory, age=timedelta(minutes=2))
    await _seed_alert(
        session_factory,
        acknowledged=True,
        acknowledged_at=datetime.now(timezone.utc),
        acknowledged_by="someone",
    )

    response = await client.get("/api/v1/admin/alerts", headers=_auth(admin_token))

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert [item["acknowledged"] for item in body["items"]] == [False]


@pytest.mark.asyncio
async def test_alerts_can_include_acknowledged_ones(client, admin_token, session_factory) -> None:
    await _seed_alert(session_factory, age=timedelta(minutes=2))
    await _seed_alert(session_factory, acknowledged=True, age=timedelta(minutes=1))

    response = await client.get(
        "/api/v1/admin/alerts?only_unacknowledged=false", headers=_auth(admin_token)
    )

    assert response.status_code == 200
    assert response.json()["count"] == 2


@pytest.mark.asyncio
async def test_alerts_are_newest_first(client, admin_token, session_factory) -> None:
    await _seed_alert(session_factory, age=timedelta(minutes=5), title="the older one")
    await _seed_alert(session_factory, age=timedelta(minutes=1), title="the newer one")

    response = await client.get("/api/v1/admin/alerts", headers=_auth(admin_token))

    assert [item["title"] for item in response.json()["items"]] == [
        "the newer one",
        "the older one",
    ]


@pytest.mark.asyncio
async def test_alert_items_expose_every_field_the_triage_list_needs(
    client, admin_token, session_factory
) -> None:
    row = await _seed_alert(session_factory, severity="critical")

    response = await client.get("/api/v1/admin/alerts", headers=_auth(admin_token))

    item = response.json()["items"][0]
    assert set(item) == {
        "id",
        "rule_code",
        "severity",
        "title",
        "description",
        "actor_user_id",
        "ip_address",
        "audit_event_id",
        "acknowledged",
        "acknowledged_at",
        "acknowledged_by_user_id",
        "created_at",
    }
    assert item["id"] == row.id
    assert item["severity"] == "critical"
    assert item["ip_address"] == "203.0.113.9"
    assert item["acknowledged"] is False
    assert item["acknowledged_at"] is None
    assert item["audit_event_id"] is None


@pytest.mark.asyncio
async def test_alerts_limit_applies_and_count_is_the_page_size(
    client, admin_token, session_factory
) -> None:
    """``count`` is the number of rows returned, not the number that exist.

    A reader would reasonably take ``count`` for a total. It is not one, and it
    cannot become one without a second query on a list endpoint. Pinned so the
    next reader does not have to rediscover it from the implementation.
    """
    for n in range(5):
        await _seed_alert(session_factory, age=timedelta(minutes=n + 1))

    response = await client.get("/api/v1/admin/alerts?limit=2", headers=_auth(admin_token))

    body = response.json()
    assert body["count"] == 2
    assert len(body["items"]) == 2


@pytest.mark.asyncio
async def test_alerts_validates_the_limit(client, admin_token) -> None:
    assert (await client.get("/api/v1/admin/alerts?limit=0", headers=_auth(admin_token))).status_code == 422
    assert (await client.get("/api/v1/admin/alerts?limit=501", headers=_auth(admin_token))).status_code == 422


# === PATCH /api/v1/admin/alerts/{alert_id}/ack ===


@pytest.mark.asyncio
async def test_acknowledging_an_open_alert_records_who_and_when(
    client, admin_token, session_factory
) -> None:
    row = await _seed_alert(session_factory)
    before = datetime.now(timezone.utc)

    response = await client.patch(
        f"/api/v1/admin/alerts/{row.id}/ack", headers=_auth(admin_token)
    )

    assert response.status_code == 200
    assert response.json() == {"detail": "Alert acknowledged", "alert_id": row.id}
    async with session_factory() as db:
        stored = await db.get(SecurityAlert, row.id)
        assert stored.acknowledged is True
        assert stored.acknowledged_by_user_id is not None
        assert stored.acknowledged_at is not None
        assert stored.acknowledged_at.replace(tzinfo=stored.acknowledged_at.tzinfo or timezone.utc) >= before


@pytest.mark.asyncio
async def test_acknowledging_twice_reports_it_and_does_not_move_the_timestamp(
    client, admin_token, session_factory
) -> None:
    """The second acknowledgement must not restamp the first.

    ``acknowledged_at`` is when a human took responsibility. Overwriting it on a
    repeat call would make the audit trail of *who looked at this, and when* say
    the opposite of what happened, and ``SecurityAlert.acknowledge`` refuses to
    run twice for the same reason.
    """
    first_seen = datetime.now(timezone.utc) - timedelta(hours=3)
    row = await _seed_alert(
        session_factory, acknowledged=True, acknowledged_at=first_seen, acknowledged_by="earlier-operator"
    )

    response = await client.patch(
        f"/api/v1/admin/alerts/{row.id}/ack", headers=_auth(admin_token)
    )

    assert response.status_code == 200
    assert response.json() == {
        "detail": "Alert already acknowledged",
        "alert_id": row.id,
    }
    async with session_factory() as db:
        stored = await db.get(SecurityAlert, row.id)
        assert stored.acknowledged_by_user_id == "earlier-operator"
        assert stored.acknowledged_at.replace(tzinfo=first_seen.tzinfo) == first_seen


@pytest.mark.asyncio
async def test_acknowledging_an_unknown_alert_reports_not_found_and_is_still_a_200(
    client, admin_token, session_factory
) -> None:
    """A missing alert is a 200 with a detail, not a 404.

    Unusual, and pinned deliberately: the acknowledgement endpoint reports all
    three outcomes -- acknowledged, already acknowledged, no such alert -- as
    ``200`` with a ``detail`` body. Changing it to a 404 would be a client-visible
    change, so it happens deliberately or not at all. Note also that the
    not-found body carries no ``alert_id``, unlike the other two.
    """
    response = await client.patch("/api/v1/admin/alerts/99999/ack", headers=_auth(admin_token))

    assert response.status_code == 200
    assert response.json() == {"detail": "Alert not found"}


@pytest.mark.asyncio
async def test_acknowledging_validates_the_alert_id(client, admin_token) -> None:
    assert (
        await client.patch("/api/v1/admin/alerts/0/ack", headers=_auth(admin_token))
    ).status_code == 422


# === GET /api/v1/admin/audit-events ===


@pytest.mark.asyncio
async def test_audit_events_are_newest_first(client, admin_token, session_factory) -> None:
    await _seed_events(
        session_factory,
        ("http.request", _ACTOR_ONE, "198.51.100.1", {"n": 1}, timedelta(minutes=5)),
        ("auth.login.success", _ACTOR_ONE, "198.51.100.1", {"n": 2}, timedelta(minutes=1)),
    )

    response = await client.get("/api/v1/admin/audit-events", headers=_auth(admin_token))

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert [item["event_type"] for item in body["items"]] == [
        "auth.login.success",
        "http.request",
    ]


@pytest.mark.asyncio
async def test_audit_events_filter_by_type_and_actor(client, admin_token, session_factory) -> None:
    await _seed_events(
        session_factory,
        ("http.request", _ACTOR_ONE, "198.51.100.1", {}, timedelta(minutes=3)),
        ("http.request", _ACTOR_TWO, "198.51.100.1", {}, timedelta(minutes=2)),
        ("auth.login.success", _ACTOR_ONE, "198.51.100.1", {}, timedelta(minutes=1)),
    )

    by_type = await client.get(
        "/api/v1/admin/audit-events?event_type=http.request", headers=_auth(admin_token)
    )
    assert by_type.json()["count"] == 2

    by_actor = await client.get(
        f"/api/v1/admin/audit-events?actor_user_id={_ACTOR_ONE}", headers=_auth(admin_token)
    )
    assert [item["event_type"] for item in by_actor.json()["items"]] == [
        "auth.login.success",
        "http.request",
    ]

    both = await client.get(
        f"/api/v1/admin/audit-events?event_type=http.request&actor_user_id={_ACTOR_TWO}",
        headers=_auth(admin_token),
    )
    assert both.json()["count"] == 1


@pytest.mark.asyncio
async def test_audit_event_items_expose_every_field_and_default_metadata(
    client, admin_token, session_factory
) -> None:
    await _seed_events(
        session_factory,
        ("http.request", _ACTOR_ONE, "198.51.100.1", {"page": "/x"}, timedelta(minutes=1)),
    )

    item = (await client.get("/api/v1/admin/audit-events", headers=_auth(admin_token))).json()["items"][0]

    assert set(item) == {
        "id",
        "event_type",
        "actor_user_id",
        "method",
        "path",
        "status_code",
        "ip_address",
        "user_agent",
        "request_id",
        "metadata",
        "occurred_at",
    }
    assert item["metadata"] == {"page": "/x"}
    assert item["method"] == "GET"
    assert item["status_code"] == 200


@pytest.mark.asyncio
async def test_audit_events_expose_null_metadata_as_an_empty_object(
    client, admin_token, session_factory
) -> None:
    """A NULL metadata column is presented as ``{}``, never as ``null``.

    The client is a dashboard, not a log parser: every other item is an object,
    and one nullable field arriving as ``null`` is the kind of thing that throws
    in the browser and is trivial to prevent here.
    """
    await _seed_events(session_factory, ("http.request", None, None, None, timedelta(minutes=1)))

    item = (await client.get("/api/v1/admin/audit-events", headers=_auth(admin_token))).json()["items"][0]

    assert item["metadata"] == {}
    assert item["actor_user_id"] is None


@pytest.mark.asyncio
async def test_audit_events_limit_and_validation(client, admin_token, session_factory) -> None:
    for n in range(4):
        await _seed_events(session_factory, ("http.request", None, None, {}, timedelta(minutes=n + 1)))

    limited = await client.get("/api/v1/admin/audit-events?limit=3", headers=_auth(admin_token))
    assert limited.json()["count"] == 3

    assert (
        await client.get("/api/v1/admin/audit-events?limit=0", headers=_auth(admin_token))
    ).status_code == 422
    assert (
        await client.get("/api/v1/admin/audit-events?limit=1001", headers=_auth(admin_token))
    ).status_code == 422
    assert (
        await client.get(
            "/api/v1/admin/audit-events?event_type=" + "x" * 121, headers=_auth(admin_token)
        )
    ).status_code == 422


# === GET /api/v1/admin/cookie-activity ===


@pytest.mark.asyncio
async def test_cookie_activity_returns_only_the_three_tracked_types(
    client, admin_token, session_factory
) -> None:
    await _seed_events(
        session_factory,
        ("cookie.consent.accepted", _ACTOR_ONE, "198.51.100.1", {"action": "accepted"}, timedelta(minutes=4)),
        ("cookie.consent.declined", _ACTOR_ONE, "198.51.100.1", {"action": "declined"}, timedelta(minutes=3)),
        ("client.activity", _ACTOR_ONE, "198.51.100.1", {"page": "/x"}, timedelta(minutes=2)),
        ("http.request", _ACTOR_ONE, "198.51.100.1", {}, timedelta(minutes=1)),
        ("auth.login.success", _ACTOR_ONE, "198.51.100.1", {}, timedelta(0)),
    )

    response = await client.get("/api/v1/admin/cookie-activity", headers=_auth(admin_token))

    assert response.status_code == 200
    body = response.json()
    assert [item["event_type"] for item in body["items"]] == [
        "client.activity",
        "cookie.consent.declined",
        "cookie.consent.accepted",
    ]
    assert set(body["items"][0]) == {
        "id",
        "event_type",
        "actor_user_id",
        "ip_address",
        "user_agent",
        "metadata",
        "occurred_at",
    }


@pytest.mark.asyncio
async def test_cookie_activity_filters_by_actor(client, admin_token, session_factory) -> None:
    await _seed_events(
        session_factory,
        ("client.activity", _ACTOR_ONE, "198.51.100.1", {}, timedelta(minutes=2)),
        ("client.activity", _ACTOR_TWO, "198.51.100.2", {}, timedelta(minutes=1)),
    )

    response = await client.get(
        f"/api/v1/admin/cookie-activity?actor_user_id={_ACTOR_TWO}", headers=_auth(admin_token)
    )

    assert response.json()["count"] == 1
    assert response.json()["items"][0]["actor_user_id"] == _ACTOR_TWO


@pytest.mark.asyncio
async def test_cookie_activity_limit_and_validation(client, admin_token) -> None:
    assert (
        await client.get("/api/v1/admin/cookie-activity?limit=0", headers=_auth(admin_token))
    ).status_code == 422
    assert (
        await client.get("/api/v1/admin/cookie-activity?limit=1001", headers=_auth(admin_token))
    ).status_code == 422
