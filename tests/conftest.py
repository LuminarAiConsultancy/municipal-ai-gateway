"""Shared test fixtures for the Municipal AI Gateway test suite.

Requirements:
  - Python packages: pytest, httpx, respx, fastapi, sqlalchemy,
    presidio-analyzer, presidio-anonymizer, spacy, aiosqlite
  - spacy model: python -m spacy download en_core_web_lg

All tests use a file-based SQLite database (no Docker or PostgreSQL needed).
A sync engine is used for data setup/assertions; an async engine powers the app.
"""

import os
import sys
import tempfile

# ── Environment (must be set before any gateway imports) ─────────────────────

os.environ.setdefault("GATEWAY_SECRET", "test-secret")
os.environ.setdefault("OPENAI_API_KEY", "test-openai-key")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-anthropic-key")
os.environ.setdefault("GOOGLE_API_KEY", "test-google-key")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")

# Add gateway/ to sys.path so bare imports (from models import Base) work.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

# ── Imports ──────────────────────────────────────────────────────────────────

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from models import Base
from auth import ApiKey, generate_key, hash_key

# Import main so that RequestLog is registered on Base before create_all().
from main import RequestLog  # noqa: F401


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def db_engine(tmp_path):
    """File-based SQLite engine for tests.

    Creates both a sync engine (for data setup/assertions) and an async
    engine (for the app). Both share the same database file.
    """
    db_path = tmp_path / "test.db"

    # Sync engine for test data setup.
    sync_engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(sync_engine)

    # Store async engine info for test_client fixture.
    sync_engine._test_db_path = str(db_path)

    yield sync_engine

    Base.metadata.drop_all(sync_engine)
    sync_engine.dispose()


@pytest.fixture
def db_session(db_engine):
    """SQLAlchemy session bound to the test database."""
    with Session(db_engine) as session:
        yield session


@pytest.fixture
def test_client(db_engine, monkeypatch):
    """FastAPI TestClient with the async test database injected.

    Patches the lifespan to use an async SQLite engine backed by the
    same database file as db_engine.
    """
    import main
    from contextlib import asynccontextmanager

    db_path = db_engine._test_db_path

    @asynccontextmanager
    async def test_lifespan(app):
        async_engine = create_async_engine(
            f"sqlite+aiosqlite:///{db_path}",
            connect_args={"check_same_thread": False},
        )
        session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
        app.state.engine = async_engine
        app.state.session_factory = session_factory
        app.state.http_client = __import__("httpx").AsyncClient(timeout=120.0)
        app.state.scrubber = __import__("scrubber").get_scrubber()
        yield
        await app.state.http_client.aclose()
        await async_engine.dispose()

    original_lifespan = main.app.router.lifespan_context
    main.app.router.lifespan_context = test_lifespan

    from fastapi.testclient import TestClient

    with TestClient(main.app) as client:
        yield client

    main.app.router.lifespan_context = original_lifespan


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
                key_hash=hash_key(raw_key),
                key_prefix=raw_key[:8],
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
