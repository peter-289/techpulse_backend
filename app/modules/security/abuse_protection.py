from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from typing import Optional

from fastapi import Request
from redis.asyncio import Redis

from app.exceptions.exceptions import TooManyRequestsError

logger = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class Bucket:
    tokens: float
    last_refill: float


@dataclass(frozen=True)
class RateLimitPolicy:
    capacity: int
    refill_rate: float


LOGIN_POLICY = RateLimitPolicy(capacity=5, refill_rate=1 / 12)
REGISTRATION_POLICY = RateLimitPolicy(capacity=3, refill_rate=1 / 300)
PASSWORD_RESET_POLICY = RateLimitPolicy(capacity=2, refill_rate=1 / 300)
OTP_POLICY = RateLimitPolicy(capacity=1, refill_rate=1 / 3600)
SESSION_POLICY = RateLimitPolicy(capacity=1, refill_rate=1 / 300)


class AbuseProtection:
    def __init__(self, redis_client: Optional[Redis]) -> None:
        self._redis = redis_client
        self._memory_buckets: dict[str, Bucket] = {}
        self._one_time_memory: dict[str, int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _login_key(self, ip: str, username: str) -> str:
        return f"abuse:login:{self._hash(ip)}:{self._hash(username.lower())}"

    def _registration_key(self, ip: str) -> str:
        return f"abuse:registration:{self._hash(ip)}"

    def _password_reset_key(self, email: str) -> str:
        return f"abuse:password_reset:{self._hash(email)}"

    def _otp_key(self, email: str) -> str:
        return f"abuse:otp:{self._hash(email)}"

    def _session_key(self, ip: str) -> str:
        return f"abuse:session_refresh:{self._hash(ip)}"

    async def _allow(self, key: str, policy: RateLimitPolicy) -> bool:
        if self._redis is not None:
            try:
                return await self._allow_redis(key=key, policy=policy)
            except Exception as exc:
                logger.warning("Redis rate limiting failed: %s", exc)

        try:
            return await self._allow_memory(key=key, policy=policy)
        except Exception as exc:
            logger.warning("Memory rate limiting failed: %s", exc)
            return False

    async def _allow_memory(self, key: str, policy: RateLimitPolicy) -> bool:
        now = time.monotonic()
        bucket = self._memory_buckets.get(key)
        if bucket is None:
            bucket = Bucket(tokens=float(policy.capacity), last_refill=now)
            self._memory_buckets[key] = bucket

        elapsed = now - bucket.last_refill
        bucket.tokens = min(float(policy.capacity), bucket.tokens + elapsed * policy.refill_rate)
        bucket.last_refill = now

        if bucket.tokens < 1:
            return False

        bucket.tokens -= 1
        return True

    async def _allow_redis(self, key: str, policy: RateLimitPolicy) -> bool:
        now = time.monotonic()
        data = await self._redis.hgetall(key)
        if not data:
            tokens = float(policy.capacity)
            last_refill = now
        else:
            tokens = float(data["tokens"])
            last_refill = float(data["last_refill"])

        elapsed = now - last_refill
        tokens = min(float(policy.capacity), tokens + elapsed * policy.refill_rate)

        ttl = max(1, int(policy.capacity / policy.refill_rate))
        if tokens < 1:
            await self._redis.expire(key, ttl)
            return False

        tokens -= 1
        await self._redis.hset(key, mapping={"tokens": tokens, "last_refill": now})
        await self._redis.expire(key, ttl)
        return True

    async def guard_login(self, ip: str, username: str) -> None:
        if not await self._allow(self._login_key(ip, username), LOGIN_POLICY):
            raise TooManyRequestsError("Too many login attempts! Please try again later.")

    async def guard_registration(self, ip: str) -> None:
        if not await self._allow(self._registration_key(ip), REGISTRATION_POLICY):
            raise TooManyRequestsError("Too many registration attempts! Please try again later.")

    async def guard_password_reset(self, email: str) -> None:
        if not await self._allow(self._password_reset_key(email), PASSWORD_RESET_POLICY):
            raise TooManyRequestsError("Too many password reset requests! Try again later.")

    async def guard_session_refresh(self, ip: str) -> None:
        if not await self._allow(self._session_key(ip), SESSION_POLICY):
            raise TooManyRequestsError("Too many session refresh requests! Please try again later.")

    async def guard_otp_resend(self, email: str) -> None:
        if not await self._allow(self._otp_key(email), OTP_POLICY):
            raise TooManyRequestsError("Too many OTP resend requests! Please try again later.")

    def _once_key(self, scope: str, identifier: str) -> str:
        return f"abuse.once:{scope}:{self._hash(identifier.lower())}"

    async def acquire_once(self, scope: str, identifier: str, ttl_seconds: int) -> bool:
        """Acquires a lock and prevents the same event from executing twice."""
        key = self._once_key(scope=scope, identifier=identifier)

        if self._redis is not None:
            try:
                acquired = await self._redis.set(key, "1", ex=ttl_seconds, nx=True)
                return bool(acquired)
            except Exception as exc:
                logger.warning("Redis acquire_once() failed: %s", exc)

        now = int(time.time())
        expires_at = now + ttl_seconds
        with self._lock:
            existing = self._one_time_memory.get(key)
            if existing is not None and existing > now:
                return False
            self._one_time_memory[key] = expires_at
            return True

    def get_client_ip(self, request: Request) -> str:
        """
        Extract the client IP from a request.

        Priority:
        1. X-Forwarded-For
        2. X-Real-IP
        3. request.client.host
        """
        x_forwarded_for: Optional[str] = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
            if ip:
                return ip

        x_real_ip: Optional[str] = request.headers.get("x-real-ip")
        if x_real_ip:
            return x_real_ip.strip()

        return request.client.host if request.client else ""
