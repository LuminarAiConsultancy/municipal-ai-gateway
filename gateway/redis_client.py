"""Redis client for the Municipal AI Gateway.

Provides a shared Redis connection pool used by:
  - Rate limiter (sliding window counters)
  - Admin session store (JWT session tracking)

Falls back gracefully when Redis is unavailable — the gateway can still
function with degraded rate limiting (in-memory fallback).
"""

import os

import redis.asyncio as redis

from logging_config import get_logger

logger = get_logger("redis")

REDIS_URL = os.getenv("RATE_LIMIT_REDIS_URL", "redis://redis:6379/0")

_pool: redis.Redis | None = None


async def get_redis() -> redis.Redis:
    """Return the shared async Redis client, creating it on first call."""
    global _pool
    if _pool is None:
        _pool = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )
        logger.info("redis_connected", url=REDIS_URL.split("@")[-1])
    return _pool


async def close_redis() -> None:
    """Close the Redis connection pool."""
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None
        logger.info("redis_closed")


async def ping_redis() -> bool:
    """Return True if Redis is reachable."""
    try:
        r = await get_redis()
        return await r.ping()
    except Exception:
        return False
