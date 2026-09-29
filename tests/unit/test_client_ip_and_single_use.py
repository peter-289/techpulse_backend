"""Tests for client-IP derivation and single-use (replay) protection.

Both behaviours are security controls that fail *open* if regressed, so they
are pinned here explicitly.
"""

from __future__ import annotations

import pytest
from starlette.requests import Request

from app.core.config import settings
from app.modules.security.abuse_protection import LOGIN_POLICY, AbuseProtection


def _request(headers: dict[str, str] | None = None, peer: str = "198.51.100.7") -> Request:
    raw = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": raw,
            "client": (peer, 51234),
            "scheme": "http",
            "server": ("testserver", 80),
            "query_string": b"",
        }
    )


class _ExplodingRedis:
    async def set(self, *args, **kwargs):
        raise ConnectionError("redis is down")

    async def hgetall(self, *args, **kwargs):
        raise ConnectionError("redis is down")

    async def expire(self, *args, **kwargs):
        raise ConnectionError("redis is down")

    async def hset(self, *args, **kwargs):
        raise ConnectionError("redis is down")


class TestClientIp:
    def test_forwarded_headers_ignored_by_default(self, monkeypatch) -> None:
        """Spoofed X-Forwarded-For must not be able to choose the rate-limit bucket."""
        monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", False)
        protection = AbuseProtection(redis_client=None)

        spoofed = _request({"x-forwarded-for": "203.0.113.9"})
        assert protection.get_client_ip(spoofed) == "198.51.100.7"

    def test_real_ip_header_also_ignored_by_default(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", False)
        protection = AbuseProtection(redis_client=None)
        assert protection.get_client_ip(_request({"x-real-ip": "203.0.113.9"})) == "198.51.100.7"

    def test_forwarded_headers_honoured_when_proxy_trusted(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
        protection = AbuseProtection(redis_client=None)
        assert protection.get_client_ip(_request({"x-forwarded-for": "203.0.113.9"})) == "203.0.113.9"

    def test_forwarded_chain_uses_leftmost_hop(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
        protection = AbuseProtection(redis_client=None)
        request = _request({"x-forwarded-for": "203.0.113.9, 70.41.3.18, 150.172.238.178"})
        assert protection.get_client_ip(request) == "203.0.113.9"

    async def test_spoofing_cannot_reset_login_limiter(self, monkeypatch) -> None:
        """Regression: 12 spoofed attempts all bypassed the login rate limit."""
        monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", False)
        protection = AbuseProtection(redis_client=None)

        allowed = 0
        for index in range(LOGIN_POLICY.capacity * 2):
            request = _request({"x-forwarded-for": f"203.0.113.{index}"})
            ip = protection.get_client_ip(request)
            if await protection._allow(protection._login_key(ip, "admin"), LOGIN_POLICY):
                allowed += 1

        assert allowed == LOGIN_POLICY.capacity

    async def test_limiter_blocks_repeated_attempts_from_one_ip(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", False)
        protection = AbuseProtection(redis_client=None)

        allowed = 0
        for _ in range(LOGIN_POLICY.capacity * 2):
            request = _request()
            ip = protection.get_client_ip(request)
            if await protection._allow(protection._login_key(ip, "admin"), LOGIN_POLICY):
                allowed += 1

        assert allowed == LOGIN_POLICY.capacity


class TestSingleUse:
    async def test_second_acquire_is_denied(self) -> None:
        protection = AbuseProtection(redis_client=None)
        assert await protection.acquire_once("email_verify", "user-1", 3600) is True
        assert await protection.acquire_once("email_verify", "user-1", 3600) is False

    async def test_scopes_are_independent(self) -> None:
        protection = AbuseProtection(redis_client=None)
        assert await protection.acquire_once("email_verify", "user-1", 3600) is True
        assert await protection.acquire_once("password_reset", "user-1", 3600) is True

    async def test_expired_entries_can_be_reacquired(self) -> None:
        protection = AbuseProtection(redis_client=None)
        assert await protection.acquire_once("email_verify", "user-1", 0) is True
        assert await protection.acquire_once("email_verify", "user-1", 0) is True

    async def test_redis_failure_fails_closed(self) -> None:
        """A Redis outage must not downgrade replay protection to per-process state.

        Denying is recoverable (the user retries); silently accepting a replayed
        token is not.
        """
        protection = AbuseProtection(redis_client=_ExplodingRedis())
        assert await protection.acquire_once("email_verify", "user-1", 3600) is False

    async def test_rate_limit_still_degrades_to_memory(self) -> None:
        """Throttling may fall back to memory on a Redis outage; that is acceptable."""
        protection = AbuseProtection(redis_client=_ExplodingRedis())
        first = await protection._allow(protection._login_key("198.51.100.7", "admin"), LOGIN_POLICY)
        second = await protection._allow(protection._login_key("198.51.100.7", "admin"), LOGIN_POLICY)

        assert first is True
        assert second is True  # memory fallback still working, no exception
