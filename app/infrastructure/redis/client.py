from typing import Optional

import redis.asyncio as redis
from redis.asyncio import Redis

from app.core.config import settings
import logging


logger = logging.getLogger(__name__)


class RedisManager:
    def __init__(self) -> None:
        self._client: Optional[Redis] = None

    async def connect(self) -> None:
        """ Establish Redis connection during application startup."""
        try:
            client = redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
            )

            await client.ping()

            self._client = client
            logger.info("Redis connected successfully.")

        except Exception as exc:
            logger.warning("Redis unavailable. Falling back to memory: %s", exc,)
            self._client = None
        
    
    async def disconnect(self) -> None:
        """ Close Redis connections."""
        if self._client is not None:
            await self._client.close()
            logger.info("Redis connection closed.")

    
    @property
    def client(self) -> Optional[Redis]:
        return self._client
    
    @property
    def available(self) -> bool:
        return self._client is not None
    

redis_manager = RedisManager()
