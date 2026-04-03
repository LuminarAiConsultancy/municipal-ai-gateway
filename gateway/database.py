"""Async database engine and session factory for the Municipal AI Gateway."""

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession, AsyncEngine

from models import Base


def create_db_engine(url: str) -> AsyncEngine:
    """Create an async SQLAlchemy engine."""
    return create_async_engine(url, echo=False)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory bound to the given engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_db(engine: AsyncEngine) -> None:
    """Create all tables via the async engine."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
