#!/usr/bin/env python
"""
PostgreSQL schema setup script.
Creates the database schema via Alembic migrations.
Run this once after starting the Docker stack.

Usage:
    python scripts/seed_postgres.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


async def create_tables() -> None:
    from api.database import Base, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()
    print("Database tables created successfully.")


async def verify_connection() -> None:
    from sqlalchemy import text
    from api.database import engine

    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT version()"))
            version = result.scalar()
            print(f"PostgreSQL connected: {version}")
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)


async def main() -> None:
    await verify_connection()
    await create_tables()


if __name__ == "__main__":
    asyncio.run(main())
