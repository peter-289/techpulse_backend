"""Rate-limiter wiring regression tests.

Guards two bugs: ``get_abuse_protection`` built a new instance per request (so
the in-memory buckets were never shared and the limiter reset on every call),
and the software download endpoints called the ``async``
``AbuseProtection.guard_download`` without awaiting it (so it never ran).
"""

from __future__ import annotations

import inspect

import pytest

from app.exceptions.exceptions import TooManyRequestsError
from app.modules.security.abuse_protection import DOWNLOAD_POLICY, AbuseProtection
from app.modules.shared.dependencies import get_abuse_protection


def test_get_abuse_protection_returns_a_shared_instance() -> None:
    assert get_abuse_protection(redis_client=None) is get_abuse_protection(redis_client=None)


def test_singleton_is_rebuilt_when_the_redis_client_changes(monkeypatch) -> None:
    import app.modules.shared.dependencies as deps

    monkeypatch.setattr(deps, "_abuse_protection", None, raising=False)

    first = deps.get_abuse_protection(redis_client=None)
    assert deps.get_abuse_protection(redis_client=None) is first

    sentinel = object()
    rebuilt = deps.get_abuse_protection(redis_client=sentinel)
    assert rebuilt is not first
    # And it stays stable again once the client stops changing.
    assert deps.get_abuse_protection(redis_client=sentinel) is rebuilt


def test_exposes_the_redis_client_it_was_built_with() -> None:
    assert AbuseProtection(None).redis_client is None
    sentinel = object()
    assert AbuseProtection(sentinel).redis_client is sentinel


def test_guard_download_is_a_coroutine_function() -> None:
    # The download endpoints previously called it without await, so the limit
    # was never applied and the coroutine was silently discarded.
    assert inspect.iscoroutinefunction(AbuseProtection.guard_download)


def test_router_awaits_guard_download() -> None:
    from pathlib import Path

    router_path = (
        Path(__file__).resolve().parents[2]
        / "app/modules/software_management/api/routers/software_router.py"
    )
    source = router_path.read_text(encoding="utf-8")
    assert "abuse_protection.guard_download" in source
    unawaited = [
        line.strip()
        for line in source.splitlines()
        if "abuse_protection.guard_download" in line and "await" not in line
    ]
    assert unawaited == [], f"guard_download called without await: {unawaited}"


@pytest.mark.asyncio
async def test_in_memory_download_limiter_actually_blocks() -> None:
    protection = AbuseProtection(None)
    await protection.guard_download(ip="1.2.3.4")

    with pytest.raises(TooManyRequestsError):
        await protection.guard_download(ip="1.2.3.4")


@pytest.mark.asyncio
async def test_limiter_is_scoped_per_ip() -> None:
    protection = AbuseProtection(None)
    await protection.guard_download(ip="1.2.3.4")

    with pytest.raises(TooManyRequestsError):
        await protection.guard_download(ip="1.2.3.4")

    await protection.guard_download(ip="5.6.7.8")


@pytest.mark.asyncio
async def test_in_memory_buckets_persist_across_calls() -> None:
    protection = AbuseProtection(None)
    assert protection.redis_client is None
    for _ in range(DOWNLOAD_POLICY.capacity):
        await protection.guard_download(ip="9.9.9.9")
    with pytest.raises(TooManyRequestsError):
        await protection.guard_download(ip="9.9.9.9")


@pytest.mark.asyncio
async def test_acquire_once_expires_entries() -> None:
    protection = AbuseProtection(None)
    assert await protection.acquire_once("scope", "id@example.test", ttl_seconds=0) is True
    # ttl_seconds=0 means already expired, so the lock is released.
    assert await protection.acquire_once("scope", "id@example.test", ttl_seconds=0) is True
