#!/usr/bin/env python
"""
PostgreSQL bootstrap.

Two modes:
  1. ``python scripts/seed_postgres.py``               → verify connection + create tables
  2. ``python scripts/seed_postgres.py --admin EMAIL`` → also seed an admin user
     interactively (password is read from stdin, never a CLI arg).

Run this once after starting the Docker stack. Safe to re-run — table creation
is idempotent, and admin-seed skips if the email already exists.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


async def verify_connection() -> None:
    from sqlalchemy import text

    from api.database import get_engine

    engine = get_engine()
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT version()"))
            version = result.scalar()
            print(f"PostgreSQL connected: {version}")
    except Exception as exc:
        print(f"Connection failed: {exc}")
        sys.exit(1)


async def create_tables() -> None:
    from api.database import Base, get_engine

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database tables created.")


async def create_admin(email: str) -> None:
    from sqlalchemy import select

    from api.auth.security import hash_password
    from api.database import get_session_factory
    from api.models.user import User

    password = getpass.getpass(f"Password for {email}: ")
    if len(password) < 12:
        print("Password must be at least 12 characters.")
        sys.exit(2)

    async with get_session_factory()() as session:
        existing = await session.execute(select(User).where(User.email == email))
        if existing.scalar_one_or_none() is not None:
            print(f"User {email} already exists; leaving unchanged.")
            return
        session.add(
            User(
                email=email.lower(),
                hashed_password=hash_password(password),
                role="admin",
                is_active=True,
            )
        )
        await session.commit()
    print(f"Admin user {email} seeded.")


async def main(email: str | None) -> None:
    await verify_connection()
    await create_tables()
    if email:
        await create_admin(email)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PostgreSQL bootstrap for SentinelAI")
    parser.add_argument(
        "--admin",
        metavar="EMAIL",
        help="Also seed an initial admin user with the given email (password read from stdin).",
    )
    args = parser.parse_args()
    asyncio.run(main(args.admin))
