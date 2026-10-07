"""Audit log writing and reading -- section 10 of the plan."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Sequence

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Event, EventType, Grant, utcnow

#: Substrings that must never reach the audit log, as a last line of defence
#: behind "no raw tokens, passwords or session ids in logs" (section 6.7).
_FORBIDDEN_DETAIL_KEYS = ("password=", "token=", "session=")

MAX_DETAIL = 512
MAX_UA = 512


def _scrub(detail: str | None) -> str | None:
    if detail is None:
        return None
    text = " ".join(str(detail).split())
    lowered = text.lower()
    for key in _FORBIDDEN_DETAIL_KEYS:
        if key in lowered:
            return "[redacted]"
    return text[:MAX_DETAIL]


async def log_event(
    db: AsyncSession,
    *,
    type: EventType | str,
    actor: str,
    grant: Grant | None = None,
    grant_id: int | None = None,
    grant_public_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    detail: str | None = None,
) -> Event:
    """Append one audit row.  Call sites pass human-readable, secret-free detail."""
    event = Event(
        ts=utcnow(),
        grant_id=grant.id if grant is not None else grant_id,
        grant_public_id=grant.public_id if grant is not None else grant_public_id,
        actor=actor,
        type=type.value if isinstance(type, EventType) else str(type),
        ip=(ip or None),
        user_agent=(" ".join((user_agent or "").split())[:MAX_UA] or None),
        detail=_scrub(detail),
    )
    db.add(event)
    await db.flush()
    return event


async def recent_events(
    db: AsyncSession,
    *,
    days: int,
    limit: int = 500,
    type_filter: str | None = None,
    grant_public_id: str | None = None,
    actor: str | None = None,
) -> Sequence[Event]:
    since = utcnow() - timedelta(days=days)
    stmt = select(Event).where(Event.ts >= since)
    if type_filter:
        stmt = stmt.where(Event.type == type_filter)
    if grant_public_id:
        stmt = stmt.where(Event.grant_public_id == grant_public_id)
    if actor:
        stmt = stmt.where(Event.actor == actor)
    stmt = stmt.order_by(Event.ts.desc(), Event.id.desc()).limit(limit)
    return (await db.execute(stmt)).scalars().all()


async def prune_events(db: AsyncSession, *, retention_days: int) -> int:
    """Delete rows older than the retention window.  Returns the row count."""
    cutoff: datetime = utcnow() - timedelta(days=retention_days)
    result = await db.execute(delete(Event).where(Event.ts < cutoff))
    return int(result.rowcount or 0)
