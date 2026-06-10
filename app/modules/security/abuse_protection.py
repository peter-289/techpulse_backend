from __future__ import annotations

import hashlib
import logging
import threading
import time

from app.core.config import settings

try:
    from redis import Redis
    from redis.exceptions import RedisError
except Exception:  # pragma: no cover - fallback path if redis package is unavailable
    Redis = None

    class RedisError(Exception):
        pass


logger = logging.getLogger(__name__)


class AbuseProtection:
    """Provides rate limiting and one-time token markers with Redis fallback."""

    def __init__(self) -> None:
        self._redis = None
        self._redis_checked = False
        self._lock = threading.Lock()
        self._rate_window: dict[str, tuple[int, int]] = {}
        self._one_time: dict[str, int] = {}

    def _get_redis(self):
        if self._redis_checked:
            return self._redis
        self._redis_checked = True
        if Redis is None:
            return None
        try:
            self._redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
            self._redis.ping()
        except Exception as exc:
            logger.warning("Redis unavailable for abuse protection, using memory fallback: %s", exc)
            self._redis = None
        return self._redis

    @staticmethod
    def _bucket(scope: str, key: str) -> str:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"abuse:{scope}:{digest}"

    def hit_rate_limit(self, *, scope: str, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        if limit <= 0 or window_seconds <= 0:
            return False, 0
        bucket = self._bucket(scope, key)
        redis_client = self._get_redis()
        if redis_client is not None:
            try:
                with redis_client.pipeline() as pipe:
                    pipe.incr(bucket)
                    pipe.ttl(bucket)
                    count, ttl = pipe.execute()
                count = int(count or 0)
                ttl = int(ttl or -1)
                if ttl < 0:
                    redis_client.expire(bucket, window_seconds)
                    ttl = window_seconds
                return count > limit, max(1, ttl)
            except RedisError:
                  pass

        now = int(time.time())
        with self._lock:
            count, reset_at = self._rate_window.get(bucket, (0, now + window_seconds))
            if now >= reset_at:
                count = 0
                reset_at = now + window_seconds
            count += 1
            self._rate_window[bucket] = (count, reset_at)
            retry_after = max(1, reset_at - now)
        return count > limit, retry_after

    def set_once(self, *, scope: str, key: str, ttl_seconds: int) -> bool:
        ttl_seconds = max(1, int(ttl_seconds))
        bucket = self._bucket(scope, key)
        redis_client = self._get_redis()
        if redis_client is not None:
            try:
                return bool(redis_client.set(bucket, "1", ex=ttl_seconds, nx=True))
            except RedisError:
                pass

        now = int(time.time())
        expires_at = now + ttl_seconds
        with self._lock:
            existing = self._one_time.get(bucket)
            if existing and existing > now:
                return False
            self._one_time[bucket] = expires_at
            stale_keys = [k for k, v in self._one_time.items() if v <= now]
            for stale_key in stale_keys:
                del self._one_time[stale_key]
        return True


abuse_protection = AbuseProtection()
