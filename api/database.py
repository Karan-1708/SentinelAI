from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from api.config import settings


class Base(DeclarativeBase):
    pass


# Lazily created so that asyncpg is not required at import time.
# This allows test collection to work without the full PostgreSQL + asyncpg stack.
_engine = None
_session_factory = None


def get_engine():
    global _engine
    if _engine is None:
        url = settings.database_url
        # SQLite (used in tests) does not accept the async connection-pool
        # tuning kwargs — they only apply to real network drivers like asyncpg.
        kwargs: dict = {"pool_pre_ping": True, "echo": False}
        if not url.startswith("sqlite"):
            kwargs.update(pool_size=10, max_overflow=20)
        _engine = create_async_engine(url, **kwargs)
    return _engine


def get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with get_session_factory()() as session:
        yield session
