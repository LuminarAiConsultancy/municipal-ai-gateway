"""Async database engine and session factory for the Municipal AI Gateway."""

import os

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession, AsyncEngine

from models import Base


def create_db_engine(url: str) -> AsyncEngine:
    """Create an async SQLAlchemy engine with connection pooling.

    Pool settings are sized for a small municipality (50-500 staff).
    Configurable via DB_POOL_SIZE, DB_MAX_OVERFLOW, DB_POOL_TIMEOUT
    env vars. Connections recycle every 30 minutes to avoid stale
    connections behind firewalls.
    """
    return create_async_engine(
        url,
        echo=False,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
        pool_recycle=1800,
        pool_pre_ping=True,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory bound to the given engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_db(engine: AsyncEngine) -> None:
    """Create all tables via the async engine."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
