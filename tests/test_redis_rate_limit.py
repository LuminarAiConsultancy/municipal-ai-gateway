"""Tests for Redis-backed sliding window rate limiter.

Uses fakeredis to simulate a Redis server without requiring Docker.
"""

import pytest
import pytest_asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock
from fastapi import HTTPException

# Ensure gateway is on sys.path (conftest handles this, but be explicit).
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import fakeredis.aioredis

from policies import RedisRateLimiter, check_rate_limit, DEFAULT_RPM_PER_KEY


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def fake_redis():
    """Create a fakeredis async client for testing."""
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


def _mock_session_factory(policy=None):
    """Create a mock session factory that behaves like async_sessionmaker.

    session_factory() returns an async context manager yielding a mock session.
    """
    mock_session = MagicMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = policy
    mock_session.execute = AsyncMock(return_value=mock_result)

    @asynccontextmanager
    async def _factory():
        yield mock_session

    return _factory


# ── RedisRateLimiter unit tests ──────────────────────────────────────────────


class TestRedisRateLimiter:
    @pytest.mark.asyncio
    async def test_under_limit_passes(self, fake_redis):
        """Requests under the per-key rate limit pass without error."""
        limiter = RedisRateLimiter(fake_redis)
        # Should not raise
        await limiter.check_and_record(
            key_id=1, department="Planning", rpm_key=10, rpm_dept=100
        )

    @pytest.mark.asyncio
    async def test_per_key_limit_exceeded(self, fake_redis):
        """Exceeding the per-key rate limit raises HTTPException 429."""
        limiter = RedisRateLimiter(fake_redis)

        # Fill up to the limit
        for i in range(5):
            await limiter.check_and_record(
                key_id=1, department="Planning", rpm_key=5, rpm_dept=100
            )

        # Next request should be rejected
        with pytest.raises(HTTPException) as exc_info:
            await limiter.check_and_record(
                key_id=1, department="Planning", rpm_key=5, rpm_dept=100
            )
        assert exc_info.value.status_code == 429
        assert "per key" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_per_department_limit_exceeded(self, fake_redis):
        """Exceeding the per-department rate limit raises HTTPException 429."""
        limiter = RedisRateLimiter(fake_redis)

        # Use different keys but same department to hit department limit
        for i in range(3):
            await limiter.check_and_record(
                key_id=i + 100, department="Finance", rpm_key=100, rpm_dept=3
            )

        # Next request from a new key in the same department should be rejected
        with pytest.raises(HTTPException) as exc_info:
            await limiter.check_and_record(
                key_id=200, department="Finance", rpm_key=100, rpm_dept=3
            )
        assert exc_info.value.status_code == 429
        assert "department" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_different_keys_independent(self, fake_redis):
        """Requests from different keys have independent per-key limits."""
        limiter = RedisRateLimiter(fake_redis)

        # Key 1: hit the limit
        for i in range(3):
            await limiter.check_and_record(
                key_id=1, department="Planning", rpm_key=3, rpm_dept=100
            )

        # Key 2: should still pass (independent bucket)
        await limiter.check_and_record(
            key_id=2, department="Planning", rpm_key=3, rpm_dept=100
        )

    @pytest.mark.asyncio
    async def test_different_departments_independent(self, fake_redis):
        """Requests from different departments have independent department limits."""
        limiter = RedisRateLimiter(fake_redis)

        # Department A: hit the limit
        for i in range(3):
            await limiter.check_and_record(
                key_id=1, department="DeptA", rpm_key=100, rpm_dept=3
            )

        # Department B: should still pass
        await limiter.check_and_record(
            key_id=2, department="DeptB", rpm_key=100, rpm_dept=3
        )

    @pytest.mark.asyncio
    async def test_redis_sets_expire_on_buckets(self, fake_redis):
        """Rate limiter sets TTL on Redis keys so they auto-clean."""
        limiter = RedisRateLimiter(fake_redis)
        await limiter.check_and_record(
            key_id=1, department="Planning", rpm_key=10, rpm_dept=100
        )

        # Check that TTL was set on the bucket keys
        key_ttl = await fake_redis.ttl("ratelimit:key:1")
        dept_ttl = await fake_redis.ttl("ratelimit:dept:Planning")
        assert key_ttl > 0
        assert dept_ttl > 0

    @pytest.mark.asyncio
    async def test_rejected_request_not_counted(self, fake_redis):
        """A rejected request (429) does not increase the counter."""
        limiter = RedisRateLimiter(fake_redis)

        # Fill to the limit
        for i in range(2):
            await limiter.check_and_record(
                key_id=1, department="Planning", rpm_key=2, rpm_dept=100
            )

        # This should be rejected
        with pytest.raises(HTTPException):
            await limiter.check_and_record(
                key_id=1, department="Planning", rpm_key=2, rpm_dept=100
            )

        # Check that the count is still 2 (rejected request wasn't recorded)
        count = await fake_redis.zcard("ratelimit:key:1")
        assert count == 2


# ── Integration: check_rate_limit with Redis ─────────────────────────────────


class TestCheckRateLimitWithRedis:
    @pytest.mark.asyncio
    async def test_uses_redis_when_available(self, fake_redis):
        """check_rate_limit uses Redis when a client is provided."""
        factory = _mock_session_factory(policy=None)

        # Should not raise — uses Redis with default limits
        await check_rate_limit(
            key_id=1, department="Planning",
            session_factory=factory,
            redis_client=fake_redis,
        )

        # Verify data was written to Redis
        count = await fake_redis.zcard("ratelimit:key:1")
        assert count == 1

    @pytest.mark.asyncio
    async def test_falls_back_to_memory_on_redis_error(self):
        """check_rate_limit falls back to in-memory when Redis errors."""
        # Create a Redis client that raises on pipeline execute
        broken_redis = AsyncMock()
        broken_pipe = AsyncMock()
        broken_pipe.execute.side_effect = ConnectionError("Redis down")
        broken_redis.pipeline.return_value = broken_pipe

        factory = _mock_session_factory(policy=None)

        # Should not raise — falls back to in-memory
        await check_rate_limit(
            key_id=999, department="FallbackTest",
            session_factory=factory,
            redis_client=broken_redis,
        )

    @pytest.mark.asyncio
    async def test_works_without_redis(self):
        """check_rate_limit works when redis_client is None."""
        factory = _mock_session_factory(policy=None)

        # Should not raise — uses in-memory limiter
        await check_rate_limit(
            key_id=1, department="NoRedis",
            session_factory=factory,
            redis_client=None,
        )
