from __future__ import annotations

import logging
import hashlib
import time
from dataclasses import dataclass
from typing import Optional
import threading
from fastapi import Request



from redis.asyncio import Redis

from app.exceptions.exceptions import TooManyRequestsError


logger = logging.getLogger(__name__)

# === IN-MEMORY FALLBACK BUCKET ===
@dataclass(slots=True, frozen=True)
class Bucket:
    tokens: float
    last_refill: float


# === RATE LIMIT POLICY === 
@dataclass(frozen=True)
class RateLimitPolicy:
     capacity: int
     refill_rate: float


# === LOGIN POLICY ===
LOGIN_POLICY = RateLimitPolicy(
     capacity=5,
     refill_rate=1/12
)
# === REGISTRATION POLICY === 
REGISTRATION_POLICY = RateLimitPolicy(
     capacity=3,
     refill_rate=1/300
)
# === PASSWORD RESET POLICY ===
PASSWORD_RESET_POLICY = RateLimitPolicy(
     capacity=2,
     refill_rate=1/300
)
# === OTP POLICY ===
OTP_POLICY = RateLimitPolicy(
     capacity=1,
     refill_rate=1/3600
)
# === SESSION POLICY ===
SESSION_POLICY = RateLimitPolicy(
     capacity=1,
     refill_rate=1/300
)


# === ABUSE-PROTECTION ===
class AbuseProtection:
      def __init__(self, redis_client: Optional[Redis]) -> None:
           self._redis = redis_client

           # Memory fallback
           self._memory_buckets: dict[str, Bucket] = {}
           self._one_time_memory = {}
           self._lock = threading.Lock()
      
      @staticmethod
      def _hash(value: str) -> str:
           val_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
           return val_hash 
      
      # === GENERATE LOGIN KEY ===
      def _login_key(self, ip: str, username: str) -> str:
           return (
                f"abuse:login"
                f"{self._hash(ip)}"
                f"{self._hash(username.lower())}"
           )
      
      # === GENERATE REGISTRATION KEY ===
      def _registration_key(self, ip: str) -> str:
           return (
                f"abuse:registration"
                f"{self._hash(ip)}"
           )
      
      # === GENERATE PASSWORD RESET KEY ===
      def _password_reset_key(self, email: str) -> str:
           return (
                f"abuse:password_reset"
                f"{self._hash(email)}"
           )
      
      # === GENERATE OTP KEY ===
      def _otp_key(self, email: str) -> str:
           return (
                f"abuse:otp"
                f"{self._hash(email)}"
           )
      
      # === GENERATE SESSION KEY ===
      def _session_key(self, ip: str) -> str:
            return (
                f"abuse:session_refresh"
                f"{self._hash(ip)}"
           )
        
      # Allow memory fallback if redis is None
      async def _allow(self, key: str, policy: RateLimitPolicy,) -> bool:
           if self._redis is not None:
                try:
                   return await self._allow_redis(key=key, policy=policy)
                except Exception as exc:
                     logger.warning("Redis rate limiting failed!: %s", exc)
           else:
                try:
                     return await self._allow_memory(key=key, policy=policy)
                except Exception as exc:
                     logger.warning("Memory rate limiting failed!: %s", exc)
      

      # Allowed memory fallback 
      async def _allow_memory(self, key: str, policy: RateLimitPolicy,) -> bool:
           """Used only when Redis is unavailable."""
           now = time.monotonic()

           bucket = self._memory_buckets.get(key)
           if bucket is None:
                bucket = Bucket(
                     tokens=float(policy.capacity),
                     last_refill=now,
                )
                self._memory_buckets[key] = bucket
           elapsed = now - bucket.last_refill
           
           bucket.tokens = min(float(policy.capacity), bucket.tokens + elapsed * policy.refill_rate,)
           bucket.last_refill = now

           if bucket.tokens < 1:
                return False
           
           bucket.tokens -= 1
           return True

      async def _allow_redis(self, key: str, policy: RateLimitPolicy) -> bool:
           """Redis implementation."""
           now = time.monotonic()

           data = await self._redis.hgetall(key)
           if not data:
                tokens = float(policy.capacity)
                last_refill = now
           else:
                tokens = float(data["tokens"])
                last_refill = float(data["last_refill"])
           
           elapsed = now - last_refill

           tokens = min(
                float(policy.capacity),
                tokens + elapsed * policy.refill_rate,
           )

           if tokens < 1:
                ttl = int(policy.capacity / policy.refill_rate)
                await self._redis.expire(key, ttl)
                return False
           tokens -= 1
           ttl = int(policy.capacity / policy.refill_rate)

           await self._redis.hset(
                key,
                mapping={
                     "tokens": tokens,
                     "last_refill": now
                },
           )
           await self._redis.expire(key, ttl)
           return True

      # === GUARD LOGIN ===
      async def guard_login(self, ip: str, username: str) -> None:
           key = self._login_key(ip, username)

           allowed = await self._allow(
                key,
                LOGIN_POLICY
           )
           if not allowed:
                raise TooManyRequestsError(
                     "Too many login attempts!"
                     " Please try again later!"
                )
           
      
      # === GUARD REGISTRATION ===
      async def guard_registration(self, ip: str) -> None:
           key = self._registration_key(ip=ip)

           allowed = await self._allow(key, REGISTRATION_POLICY)
           if not allowed:
                raise TooManyRequestsError(
                     "Too many registration attempt!"
                     "Please try again later."
                )
           
      
      # === GUARD PASSWORD RESET ===
      async def guard_password_reset(self, email: str) -> None:
           key = self._password_reset_key(email)

           allowed = await self._allow(key, PASSWORD_RESET_POLICY)
           if not allowed:
                raise TooManyRequestsError(
                     "Too many password reset requests!"
                     "Try again later."
                )

      # === GUARD SESSION REFRESH ===
      async def guard_session_refresh(self, ip: str) -> None:
            key = self._session_key(ip)

            allowed = await self._allow(key, SESSION_POLICY)
            if not allowed:
                 raise TooManyRequestsError(
                      "Too many session refresh requests!"
                      "Please try again later."
                 )
            
      # === GUARD OTP RESEND === 
      async def guard_otp_resend(self, email: str) -> None:
           key = self._otp_key(email)

           allowed = self._allow(key, OTP_POLICY)
           if not allowed:
               raise TooManyRequestsError(
                    "Too many OTP resend requests!"
                    "Please try again later."
               )
           

      # === ONCE KEY ===  
      def _once_key(self, scope: str, identifier: str) -> str:
           return (
                f"abuse.once: {scope}"
                f"{self._hash(identifier.lower())}"
           )
     
      # === ACQUIRE ONCE ===
      async def acquire_once(self, scope: str, identifier: str, ttl_seconds: str) -> bool:
            """Acquires a lock and prevents any event before ttl from executing."""
            key = self._once_key(scope=scope, identifier=identifier)

            # Redis implementation
            if self._redis is not None:
                 try:
                      acquired = await self._redis.set(key, "1", ex=ttl_seconds, nx=True)
                      return bool(acquired)
                 except Exception as exc:
                      logger.warning("Redis acquire_once() failed: %s", exc)

            # Memory fallback
            now = int(time.time())
            expires_at = now + ttl_seconds

            with self._lock:
                 existing = self._one_time_memory.get(key)

                 if existing is not None and existing > now:
                      return False
                 self._one_time_memory[key] = expires_at
                 return True
            
            if len(self._one_time_memory) % 100 == 0:
                 stale = [k for k, expiry in self._one_time_memory.items() if expiry <= now]

                 for k in stale:
                    del self._one_time_memory[k]

                    
      # === GET CLIENT IP ===
      def get_client_ip(self, request: Request)->str:
           """
            Extracts real client IP from requests.
            Priority:
            1. X-Forwarded-For (proxy-aware)
            2. X-Real-IP
            3. request.client.host(fallback)
           """
           # Forwaded For
           x_forwarded_for: Optional[str] = request.headers.get("x-forwaded-for")
           if x_forwarded_for:
                # Format client, proxy_1, proxy_2
                ip = x_forwarded_for.split(",")[0].strip()
                if ip:
                     return ip
          # X-Real-Ip
           x_real_ip: Optional[str] = request.headers.get("x-real-ip")
           if x_real_ip:
               return x_real_ip.strip()
                
          # Fallback
           return request.client.host








