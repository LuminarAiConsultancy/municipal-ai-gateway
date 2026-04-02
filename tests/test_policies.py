"""Tests for rate limiting, model allowlisting, and budget enforcement.

NOTE: gateway/policies.py does not exist yet. These tests will be SKIPPED
automatically until the module is implemented. They serve as a spec for
the expected API.

Assumed API:

  policies.RateLimiter(requests_per_minute_per_key=int, requests_per_minute_department=int)
      .record(key_id: int, department: str) -> None
      .check(key_id: int, department: str) -> None  (raises HTTPException 429)

  policies.check_model_allowed(model: str, department: str, engine) -> None
      Raises HTTPException 403 if model not in department's allowed list.
      No policy row or empty allowed_models means all models allowed.

  policies.check_budget(department: str, engine) -> None
      Raises HTTPException 429 if department's monthly cost exceeds limit.

  policies.DepartmentPolicy(Base)
      SQLAlchemy model with: department, allowed_models (JSON text),
      monthly_cost_limit_cents, requests_per_minute_per_key,
      requests_per_minute_department.
"""

import json

import pytest
from fastapi import HTTPException

policies = pytest.importorskip("policies", reason="gateway/policies.py not yet implemented")


# ── Rate limiting ────────────────────────────────────────────────────────────


class TestRateLimiting:
    def test_under_limit_passes(self):
        """Requests under the per-key rate limit pass without error."""
        limiter = policies.RateLimiter(
            requests_per_minute_per_key=10,
            requests_per_minute_department=100,
        )
        limiter.record(key_id=1, department="Planning")
        # Should not raise.
        limiter.check(key_id=1, department="Planning")

    def test_over_limit_returns_429(self):
        """Exceeding the per-key rate limit raises HTTPException 429."""
        limiter = policies.RateLimiter(
            requests_per_minute_per_key=2,
            requests_per_minute_department=100,
        )
        limiter.record(key_id=1, department="Planning")
        limiter.record(key_id=1, department="Planning")
        limiter.record(key_id=1, department="Planning")

        with pytest.raises(HTTPException) as exc_info:
            limiter.check(key_id=1, department="Planning")
        assert exc_info.value.status_code == 429


# ── Model allowlisting ───────────────────────────────────────────────────────


class TestModelAllowlist:
    def _create_policy(self, db_engine, department, allowed_models):
        """Helper: insert a DepartmentPolicy row."""
        from sqlalchemy.orm import Session
        from models import Base

        # Ensure the policies table exists.
        Base.metadata.create_all(db_engine)

        with Session(db_engine) as session:
            session.add(
                policies.DepartmentPolicy(
                    department=department,
                    allowed_models=json.dumps(allowed_models),
                )
            )
            session.commit()

    def test_allowed_model_passes(self, db_engine):
        """Model in the department's allowed list passes without error."""
        self._create_policy(db_engine, "Planning", ["gpt-4o", "gpt-4o-mini"])
        # Should not raise.
        policies.check_model_allowed("gpt-4o", "Planning", db_engine)

    def test_disallowed_model_returns_403(self, db_engine):
        """Model NOT in the allowed list raises HTTPException 403."""
        self._create_policy(db_engine, "Finance", ["gpt-4o-mini"])

        with pytest.raises(HTTPException) as exc_info:
            policies.check_model_allowed("gpt-4o", "Finance", db_engine)

        assert exc_info.value.status_code == 403
        # Error message should mention the rejected model and the allowed list.
        assert "gpt-4o" in str(exc_info.value.detail)
        assert "gpt-4o-mini" in str(exc_info.value.detail)

    def test_no_policy_allows_all(self, db_engine):
        """Department with no policy row allows all models."""
        # No DepartmentPolicy row for "Engineering" — should not raise.
        policies.check_model_allowed("gpt-4o", "Engineering", db_engine)


# ── Budget enforcement ───────────────────────────────────────────────────────


class TestBudgetEnforcement:
    def _create_policy_with_budget(self, db_engine, department, limit_cents):
        """Helper: insert a DepartmentPolicy with a monthly cost limit."""
        from sqlalchemy.orm import Session
        from models import Base

        Base.metadata.create_all(db_engine)

        with Session(db_engine) as session:
            session.add(
                policies.DepartmentPolicy(
                    department=department,
                    monthly_cost_limit_cents=limit_cents,
                )
            )
            session.commit()

    def test_under_budget_passes(self, db_engine):
        """Department under its monthly cost limit passes without error."""
        self._create_policy_with_budget(db_engine, "Planning", 10000)
        # No requests logged yet → cost is 0 → under limit.
        policies.check_budget("Planning", db_engine)

    def test_over_budget_returns_429(self, db_engine):
        """Department over its monthly cost limit raises HTTPException 429."""
        self._create_policy_with_budget(db_engine, "Finance", 100)  # $1 limit

        # Insert request logs that exceed the budget.
        # NOTE: Requires RequestLog.estimated_cost_cents column (added with costs feature).
        from sqlalchemy.orm import Session
        from main import RequestLog

        with Session(db_engine) as session:
            for i in range(5):
                session.add(
                    RequestLog(
                        provider="openai",
                        method="POST",
                        path="v1/chat/completions",
                        response_status=200,
                        source_ip="10.0.0.1",
                        duration_ms=50,
                        department="Finance",
                        estimated_cost_cents=50,  # 50¢ each → 250¢ total > 100¢ limit
                    )
                )
            session.commit()

        with pytest.raises(HTTPException) as exc_info:
            policies.check_budget("Finance", db_engine)
        assert exc_info.value.status_code == 429
        assert "budget" in str(exc_info.value.detail).lower()
