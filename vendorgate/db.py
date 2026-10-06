"""Async engine / session plumbing."""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .config import Settings
from .models import Base

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def init_engine(settings: Settings) -> AsyncEngine:
    global _engine, _sessionmaker
    kwargs: dict[str, object] = {"echo": False, "future": True}
    if settings.database_url.startswith("sqlite"):
        # One file, many coroutines: the default pool is fine for the demo, but
        # SQLite needs a generous lock timeout while the expiry job is writing.
        kwargs["connect_args"] = {"timeout": 30}
    else:
        kwargs["pool_pre_ping"] = True
    _engine = create_async_engine(settings.database_url, **kwargs)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    return _engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("engine not initialised -- call init_engine() first")
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        raise RuntimeError("engine not initialised -- call init_engine() first")
    return _sessionmaker


def alembic_head_revision() -> str | None:
    """The newest revision id in ``migrations/``, or ``None`` if unavailable."""
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory
    except ImportError:  # pragma: no cover -- alembic is in requirements.txt
        return None
    ini = Path(__file__).resolve().parent.parent / "alembic.ini"
    if not ini.is_file():
        return None
    try:
        return ScriptDirectory.from_config(Config(str(ini))).get_current_head()
    except Exception:  # noqa: BLE001 -- a missing script dir is not fatal here
        return None


async def create_all() -> None:
    """Create the tables for a fresh database, and stamp the Alembic revision.

    Stamping matters: without it, a database created straight from the models
    would later make ``alembic upgrade head`` try to create tables that already
    exist.  Creating and stamping together keeps the two paths interchangeable.
    """
    async with get_engine().begin() as conn:
        had_version = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).has_table("alembic_version")
        )
        await conn.run_sync(Base.metadata.create_all)
        if had_version:
            return
        head = alembic_head_revision()
        if head is None:
            return
        await conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS alembic_version "
                "(version_num VARCHAR(32) NOT NULL, "
                "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
            )
        )
        await conn.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:rev)"), {"rev": head}
        )


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Standalone session for background jobs and the CLI."""
    async with get_sessionmaker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with get_sessionmaker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
