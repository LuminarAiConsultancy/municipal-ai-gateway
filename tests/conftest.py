"""Shared test fixtures for the Municipal AI Gateway test suite.

Requirements:
  - Python packages: pytest, httpx, respx, fastapi, sqlalchemy,
    presidio-analyzer, presidio-anonymizer, spacy
  - spacy model: python -m spacy download en_core_web_lg

All tests use an in-memory SQLite database (no Docker or PostgreSQL needed).
"""

import os
import sys

# ── Environment (must be set before any gateway imports) ─────────────────────

os.environ.setdefault("GATEWAY_SECRET", "test-secret")
os.environ.setdefault("OPENAI_API_KEY", "test-openai-key")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-anthropic-key")
os.environ.setdefault("GOOGLE_API_KEY", "test-google-key")
os.environ.setdefault("DATABASE_URL", "sqlite://")

# Add gateway/ to sys.path so bare imports (from models import Base) work.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

# ── Imports ──────────────────────────────────────────────────────────────────

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session

from models import Base
from auth import ApiKey, generate_key

# Import main so that RequestLog is registered on Base before create_all().
from main import RequestLog  # noqa: F401


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def db_engine():
    """In-memory SQLite engine with all tables created.

    Uses StaticPool so every Session(engine) shares the same connection,
    making data visible across the app and the test code.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def db_session(db_engine):
    """SQLAlchemy session bound to the in-memory test database."""
    with Session(db_engine) as session:
        yield session


@pytest.fixture
def test_client(db_engine, monkeypatch):
    """FastAPI TestClient with the test database injected via monkeypatch.

    Replaces main._init_db so the app lifespan uses our in-memory SQLite
    engine instead of connecting to PostgreSQL.
    """
    import main

    monkeypatch.setattr(main, "_init_db", lambda: db_engine)

    from fastapi.testclient import TestClient

    with TestClient(main.app) as client:
        yield client


@pytest.fixture
def admin_headers():
    """Authorization headers for admin endpoints."""
    return {"Authorization": "Bearer test-secret"}


@pytest.fixture
def valid_api_key(db_engine):
    """Create an active API key for department 'Planning'.

    Returns the raw 64-char hex key string.
    """
    raw_key = generate_key()
    with Session(db_engine) as session:
        session.add(
            ApiKey(
                key=raw_key,
                department="Planning",
                description="Test user - Planning Dept",
                active=True,
            )
        )
        session.commit()
    return raw_key


@pytest.fixture(scope="session")
def scrubber():
    """Instantiate the PII Scrubber once per test session.

    Uses the module-level singleton so the spacy model is loaded only once,
    even if test_client's lifespan also calls get_scrubber().
    """
    from scrubber import get_scrubber

    return get_scrubber()
