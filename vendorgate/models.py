"""Database models -- section 7 of the plan."""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


def UTCDateTime() -> DateTime:
    """Timezone-aware column type.  SQLite drops the tzinfo on the way out, so
    every read goes through :func:`as_utc` before it is compared or formatted."""
    return DateTime(timezone=True)


def as_utc(value: datetime | None) -> datetime | None:
    """Return *value* as an aware UTC datetime (SQLite returns naive values)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class GrantStatus(str, enum.Enum):
    pending = "pending"
    active = "active"
    expired = "expired"
    expired_unused = "expired_unused"
    revoked = "revoked"
    locked = "locked"


#: Statuses a grant can never leave (section 4: a grant never moves backwards).
FINAL_STATUSES = frozenset(
    {
        GrantStatus.expired,
        GrantStatus.expired_unused,
        GrantStatus.revoked,
        GrantStatus.locked,
    }
)


class EventType(str, enum.Enum):
    grant_created = "grant_created"
    email_sent = "email_sent"
    email_failed = "email_failed"
    link_viewed = "link_viewed"
    login_ok = "login_ok"
    login_failed = "login_failed"
    grant_locked = "grant_locked"
    device_refused = "device_refused"
    page_viewed = "page_viewed"
    page_blocked = "page_blocked"
    grant_revoked = "grant_revoked"
    grant_expired = "grant_expired"
    link_expired_unused = "link_expired_unused"
    admin_login_ok = "admin_login_ok"
    admin_login_failed = "admin_login_failed"
    vendor_logout = "vendor_logout"
    rate_limited = "rate_limited"
    retention_pruned = "retention_pruned"


class Admin(Base):
    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    totp_secret_enc: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class Grant(Base):
    __tablename__ = "grants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)

    vendor_email: Mapped[str] = mapped_column(String(320), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)

    allowed_paths: Mapped[list[str]] = mapped_column(JSON, default=list)
    duration_minutes: Mapped[int] = mapped_column(Integer)

    status: Mapped[str] = mapped_column(
        String(20), default=GrantStatus.pending.value, index=True
    )

    created_by: Mapped[int | None] = mapped_column(ForeignKey("admins.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    link_expires_at: Mapped[datetime] = mapped_column(UTCDateTime())

    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)

    activated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    access_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_by: Mapped[int | None] = mapped_column(ForeignKey("admins.id"), nullable=True)

    bound_device_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    sessions: Mapped[list["Session"]] = relationship(
        back_populates="grant", cascade="all, delete-orphan", lazy="selectin"
    )

    # -- derived helpers -------------------------------------------------------

    @property
    def status_enum(self) -> GrantStatus:
        return GrantStatus(self.status)

    @property
    def is_final(self) -> bool:
        return self.status_enum in FINAL_STATUSES

    def seconds_left(self, now: datetime | None = None) -> int | None:
        """Seconds of access remaining, or ``None`` when no access clock runs."""
        expires = as_utc(self.access_expires_at)
        if self.status != GrantStatus.active.value or expires is None:
            return None
        delta = (expires - (now or utcnow())).total_seconds()
        return max(0, int(delta))

    def link_seconds_left(self, now: datetime | None = None) -> int | None:
        expires = as_utc(self.link_expires_at)
        if self.status != GrantStatus.pending.value or expires is None:
            return None
        return max(0, int((expires - (now or utcnow())).total_seconds()))


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    grant_id: Mapped[int] = mapped_column(
        ForeignKey("grants.id", ondelete="CASCADE"), index=True
    )
    session_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    grant: Mapped[Grant] = relationship(back_populates="sessions", lazy="joined")


class Event(Base):
    """Audit log.  Never holds tokens, passwords or session ids."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    grant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    grant_public_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    actor: Mapped[str] = mapped_column(String(16))  # admin | vendor | system
    type: Mapped[str] = mapped_column(String(32), index=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(512), nullable=True)


Index("ix_events_ts_type", Event.ts, Event.type)
