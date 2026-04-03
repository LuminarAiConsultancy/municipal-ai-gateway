"""Department policy enforcement for the Municipal AI Gateway.

Handles rate limiting (Redis-backed with in-memory fallback), model
allowlisting, and monthly budget enforcement. Policies are stored
per-department in PostgreSQL.
"""

from __future__ import annotations

import json
import os
import time
import datetime as dt
from collections import defaultdict, deque

from sqlalchemy import Column, Integer, String, DateTime, Text, func, select
from sqlalchemy.orm import Session
from fastapi import HTTPException

from models import Base
from logging_config import get_logger

logger = get_logger("policies")


# ── Database model ───────────────────────────────────────────────────────────


class DepartmentPolicy(Base):
    __tablename__ = "department_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    department = Column(String(128), unique=True, nullable=False, index=True)
    requests_per_minute_per_key = Column(Integer, default=60)
    requests_per_minute_department = Column(Integer, default=200)
    allowed_models = Column(Text)  # JSON array, e.g. '["gpt-4o","gpt-4o-mini"]'
    monthly_cost_limit_cents = Column(Integer)  # null = unlimited
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.timezone.utc),
        onupdate=lambda: dt.datetime.now(dt.timezone.utc),
    )


# ── Rate limiter configuration ───────────────────────────────────────────────

DEFAULT_RPM_PER_KEY = int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))
DEFAULT_RPM_DEPARTMENT = 200

WINDOW_SECONDS = 60


# ── Redis-backed sliding window rate limiter ─────────────────────────────────


class RedisRateLimiter:
    """Sliding-window rate limiter backed by Redis sorted sets.

    Each rate-limit bucket is a sorted set where:
      - Member: ``{timestamp_ns}:{random}`` (unique per request)
      - Score: Unix timestamp in seconds (float)

    On each check we:
      1. ZREMRANGEBYSCORE to prune entries older than the window.
      2. ZCARD to count current entries in the window.
      3. ZADD to record the new request (only after check passes).

    All operations use a Redis pipeline for atomicity and performance.
    """

    def __init__(self, redis_client):
        self._redis = redis_client

    def _key_bucket(self, key_id: int) -> str:
        return f"ratelimit:key:{key_id}"

    def _dept_bucket(self, department: str) -> str:
        return f"ratelimit:dept:{department}"

    async def check_and_record(
        self,
        *,
        key_id: int,
        department: str,
        rpm_key: int,
        rpm_dept: int,
    ) -> None:
        """Check rate limits and record the request if within limits.

        Raises HTTPException 429 if either per-key or per-department
        limit is exceeded. The request is only recorded after passing
        both checks.
        """
        now = time.time()
        cutoff = now - WINDOW_SECONDS
        key_bucket = self._key_bucket(key_id)
        dept_bucket = self._dept_bucket(department)

        # Phase 1: check both buckets in a single pipeline
        pipe = self._redis.pipeline(transaction=False)
        pipe.zremrangebyscore(key_bucket, "-inf", cutoff)
        pipe.zcard(key_bucket)
        pipe.zremrangebyscore(dept_bucket, "-inf", cutoff)
        pipe.zcard(dept_bucket)
        results = await pipe.execute()

        key_count = results[1]
        dept_count = results[3]

        if key_count >= rpm_key:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {rpm_key} requests/min per key.",
                headers={"Retry-After": "60"},
            )

        if dept_count >= rpm_dept:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {rpm_dept} requests/min for department '{department}'.",
                headers={"Retry-After": "60"},
            )

        # Phase 2: record the request in both buckets
        # Use nanosecond timestamp + key_id to ensure uniqueness
        member_key = f"{now}:{key_id}"
        member_dept = f"{now}:{key_id}:{department}"

        pipe2 = self._redis.pipeline(transaction=False)
        pipe2.zadd(key_bucket, {member_key: now})
        pipe2.expire(key_bucket, WINDOW_SECONDS + 10)
        pipe2.zadd(dept_bucket, {member_dept: now})
        pipe2.expire(dept_bucket, WINDOW_SECONDS + 10)
        await pipe2.execute()


# ── In-memory fallback rate limiter ──────────────────────────────────────────


class RateLimiter:
    """Sliding-window rate limiter using in-memory deques.

    Used as a fallback when Redis is unavailable. Counters reset on
    gateway restart.
    """

    def __init__(
        self,
        requests_per_minute_per_key: int = DEFAULT_RPM_PER_KEY,
        requests_per_minute_department: int = DEFAULT_RPM_DEPARTMENT,
    ):
        self.rpm_key = requests_per_minute_per_key
        self.rpm_dept = requests_per_minute_department
        self._key_windows: dict[int, deque] = defaultdict(deque)
        self._dept_windows: dict[str, deque] = defaultdict(deque)

    def record(self, *, key_id: int, department: str) -> None:
        """Record a request timestamp for both the key and department."""
        now = time.monotonic()
        self._key_windows[key_id].append(now)
        self._dept_windows[department].append(now)

    def check(self, *, key_id: int, department: str) -> None:
        """Raise HTTPException 429 if either limit is exceeded."""
        now = time.monotonic()
        cutoff = now - 60.0

        # Per-key check.
        kw = self._key_windows[key_id]
        while kw and kw[0] < cutoff:
            kw.popleft()
        if len(kw) >= self.rpm_key:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {self.rpm_key} requests/min per key.",
                headers={"Retry-After": "60"},
            )

        # Per-department check.
        dw = self._dept_windows[department]
        while dw and dw[0] < cutoff:
            dw.popleft()
        if len(dw) >= self.rpm_dept:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {self.rpm_dept} requests/min for department '{department}'.",
                headers={"Retry-After": "60"},
            )


_limiters: dict[str, RateLimiter] = {}


# ── Shared helpers for fetching policy limits ────────────────────────────────


async def _get_policy_limits(department: str, session_factory):
    """Fetch per-key and per-department RPM limits from the database."""
    async with session_factory() as session:
        result = await session.execute(
            select(DepartmentPolicy).filter(DepartmentPolicy.department == department)
        )
        policy = result.scalars().first()

    rpm_key = policy.requests_per_minute_per_key or DEFAULT_RPM_PER_KEY if policy else DEFAULT_RPM_PER_KEY
    rpm_dept = policy.requests_per_minute_department or DEFAULT_RPM_DEPARTMENT if policy else DEFAULT_RPM_DEPARTMENT
    return rpm_key, rpm_dept


async def _get_or_create_limiter(department: str, session_factory) -> RateLimiter:
    """Return a per-department in-memory RateLimiter, creating or updating as needed."""
    rpm_key, rpm_dept = await _get_policy_limits(department, session_factory)

    limiter = _limiters.get(department)
    if limiter is None:
        limiter = RateLimiter(
            requests_per_minute_per_key=rpm_key,
            requests_per_minute_department=rpm_dept,
        )
        _limiters[department] = limiter
    else:
        limiter.rpm_key = rpm_key
        limiter.rpm_dept = rpm_dept

    return limiter


def _get_or_create_limiter_sync(department: str, engine) -> RateLimiter:
    """Synchronous version for use in tests."""
    with Session(engine) as session:
        policy = (
            session.query(DepartmentPolicy)
            .filter(DepartmentPolicy.department == department)
            .first()
        )

    rpm_key = policy.requests_per_minute_per_key or DEFAULT_RPM_PER_KEY if policy else DEFAULT_RPM_PER_KEY
    rpm_dept = policy.requests_per_minute_department or DEFAULT_RPM_DEPARTMENT if policy else DEFAULT_RPM_DEPARTMENT

    limiter = _limiters.get(department)
    if limiter is None:
        limiter = RateLimiter(
            requests_per_minute_per_key=rpm_key,
            requests_per_minute_department=rpm_dept,
        )
        _limiters[department] = limiter
    else:
        limiter.rpm_key = rpm_key
        limiter.rpm_dept = rpm_dept

    return limiter


# ── Rate limit check entry points ────────────────────────────────────────────


async def check_rate_limit(key_id: int, department: str, session_factory, redis_client=None) -> None:
    """Check rate limits for a request. Raises 429 if exceeded.

    Uses Redis when available (sliding window with sorted sets).
    Falls back to per-department in-memory limiters when Redis is
    unavailable. Checks BEFORE recording so rejected requests are
    not counted.
    """
    if redis_client is not None:
        try:
            rpm_key, rpm_dept = await _get_policy_limits(department, session_factory)
            redis_limiter = RedisRateLimiter(redis_client)
            await redis_limiter.check_and_record(
                key_id=key_id,
                department=department,
                rpm_key=rpm_key,
                rpm_dept=rpm_dept,
            )
            return
        except HTTPException:
            raise  # Re-raise 429s
        except Exception:
            logger.warning("redis_rate_limit_fallback", department=department)
            # Fall through to in-memory limiter

    limiter = await _get_or_create_limiter(department, session_factory)
    limiter.check(key_id=key_id, department=department)
    limiter.record(key_id=key_id, department=department)


def check_rate_limit_sync(key_id: int, department: str, engine) -> None:
    """Synchronous version for tests."""
    limiter = _get_or_create_limiter_sync(department, engine)
    limiter.check(key_id=key_id, department=department)
    limiter.record(key_id=key_id, department=department)


# ── Model allowlisting ──────────────────────────────────────────────────────


async def check_model_allowed(model: str, department: str, session_factory) -> None:
    """Raise HTTPException 403 if *model* is not in the department's allowed list.

    No policy row or empty/null allowed_models means all models are permitted.
    """
    if not model:
        return  # No model in request (e.g., GET request) — skip check.

    async with session_factory() as session:
        result = await session.execute(
            select(DepartmentPolicy).filter(DepartmentPolicy.department == department)
        )
        policy = result.scalars().first()

    if not policy or not policy.allowed_models:
        return  # No restrictions.

    try:
        allowed = json.loads(policy.allowed_models)
    except (json.JSONDecodeError, TypeError):
        return  # Malformed — allow all rather than block.

    if not allowed:
        return

    if model not in allowed:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Model '{model}' is not permitted for department '{department}'. "
                f"Allowed: {', '.join(allowed)}"
            ),
        )


def check_model_allowed_sync(model: str, department: str, engine) -> None:
    """Synchronous version for tests."""
    if not model:
        return
    with Session(engine) as session:
        policy = (
            session.query(DepartmentPolicy)
            .filter(DepartmentPolicy.department == department)
            .first()
        )
    if not policy or not policy.allowed_models:
        return
    try:
        allowed = json.loads(policy.allowed_models)
    except (json.JSONDecodeError, TypeError):
        return
    if not allowed:
        return
    if model not in allowed:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Model '{model}' is not permitted for department '{department}'. "
                f"Allowed: {', '.join(allowed)}"
            ),
        )


# ── Budget enforcement ───────────────────────────────────────────────────────


async def check_budget(department: str, session_factory) -> None:
    """Raise HTTPException 429 if the department's monthly cost exceeds its limit.

    Requires the RequestLog.estimated_cost_cents column.
    """
    from main import RequestLog

    async with session_factory() as session:
        result = await session.execute(
            select(DepartmentPolicy).filter(DepartmentPolicy.department == department)
        )
        policy = result.scalars().first()

    if not policy or policy.monthly_cost_limit_cents is None:
        return  # No budget cap set.

    # Sum costs for the current calendar month.
    now = dt.datetime.now(dt.timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    async with session_factory() as session:
        result = await session.execute(
            select(func.coalesce(func.sum(RequestLog.estimated_cost_cents), 0))
            .filter(
                RequestLog.department == department,
                RequestLog.timestamp >= month_start,
            )
        )
        total = result.scalar()

    if total >= policy.monthly_cost_limit_cents:
        limit_dollars = policy.monthly_cost_limit_cents / 100
        used_dollars = total / 100
        raise HTTPException(
            status_code=429,
            detail=(
                f"Monthly budget exceeded for department '{department}'. "
                f"Limit: ${limit_dollars:.2f}, used: ${used_dollars:.2f}."
            ),
        )


def check_budget_sync(department: str, engine) -> None:
    """Synchronous version for tests."""
    from main import RequestLog

    with Session(engine) as session:
        policy = (
            session.query(DepartmentPolicy)
            .filter(DepartmentPolicy.department == department)
            .first()
        )

    if not policy or policy.monthly_cost_limit_cents is None:
        return

    now = dt.datetime.now(dt.timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    with Session(engine) as session:
        total = (
            session.query(func.coalesce(func.sum(RequestLog.estimated_cost_cents), 0))
            .filter(
                RequestLog.department == department,
                RequestLog.timestamp >= month_start,
            )
            .scalar()
        )

    if total >= policy.monthly_cost_limit_cents:
        limit_dollars = policy.monthly_cost_limit_cents / 100
        used_dollars = total / 100
        raise HTTPException(
            status_code=429,
            detail=(
                f"Monthly budget exceeded for department '{department}'. "
                f"Limit: ${limit_dollars:.2f}, used: ${used_dollars:.2f}."
            ),
        )
