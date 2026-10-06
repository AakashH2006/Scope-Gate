"""Grant life cycle -- section 4 of the plan.

Every state change for a grant goes through this module, so the rule "a grant
never moves backwards" is enforced in one place.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .connections import LiveConnections
from .events import log_event
from .models import (
    FINAL_STATUSES,
    Event,
    EventType,
    Grant,
    GrantStatus,
    Session,
    as_utc,
    utcnow,
)
from .security import (
    device_fingerprint,
    generate_link_token,
    generate_password,
    generate_public_id,
    generate_session_id,
    hash_password,
    hash_session,
    hash_token,
    verify_password,
)

log = logging.getLogger("vendorgate.grants")


class GrantError(Exception):
    """A grant operation the caller asked for is not allowed."""


@dataclass(frozen=True)
class NewGrant:
    """Result of creating a grant.  ``token`` and ``password`` exist only here
    and in the email -- the database holds hashes."""

    grant: Grant
    token: str
    password: str


@dataclass(frozen=True)
class LoginResult:
    grant: Grant
    session_id: str


# --------------------------------------------------------------------------- #
# creation
# --------------------------------------------------------------------------- #

def normalise_email(email: str) -> str:
    return (email or "").strip().lower()


def validate_allowed_paths(requested: list[str], settings: Settings) -> list[str]:
    """Keep only paths the configured ``ALLOWED_PAGES`` list offers.

    The admin picks from a fixed list; a crafted form post cannot widen it.
    """
    configured = set(settings.allowed_pages)
    chosen = {p.strip() for p in requested if p and p.strip() in configured}
    # Keep the configured order, and only pages that were actually offered.
    ordered = [p for p in settings.allowed_pages if p in chosen]
    if not ordered:
        raise GrantError("Select at least one allowed page.")
    return ordered


async def create_grant(
    db: AsyncSession,
    settings: Settings,
    *,
    vendor_email: str,
    duration_minutes: int,
    allowed_paths: list[str],
    admin_id: int | None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> NewGrant:
    email = normalise_email(vendor_email)
    if "@" not in email or email.startswith("@") or email.endswith("@") or " " in email:
        raise GrantError("Enter a valid vendor email address.")
    if duration_minutes < 1:
        raise GrantError("Access duration must be at least 1 minute.")
    if duration_minutes > settings.max_access_minutes:
        raise GrantError(
            f"Access duration may not exceed {settings.max_access_minutes} minutes."
        )
    paths = validate_allowed_paths(allowed_paths, settings)

    token = generate_link_token()
    password = generate_password(settings.vendor_password_length)
    now = utcnow()

    grant = Grant(
        public_id=generate_public_id(),
        vendor_email=email,
        token_hash=hash_token(settings.secret_key, token),
        password_hash=hash_password(password),
        allowed_paths=paths,
        duration_minutes=duration_minutes,
        status=GrantStatus.pending.value,
        created_by=admin_id,
        created_at=now,
        link_expires_at=now + timedelta(minutes=settings.link_ttl_minutes),
        failed_attempts=0,
    )
    db.add(grant)
    await db.flush()

    await log_event(
        db,
        type=EventType.grant_created,
        actor="admin",
        grant=grant,
        ip=ip,
        user_agent=user_agent,
        detail=(
            f"vendor={email} duration={duration_minutes}m "
            f"pages={','.join(paths)} link_ttl={settings.link_ttl_minutes}m"
        ),
    )
    return NewGrant(grant=grant, token=token, password=password)


def build_link(settings: Settings, token: str) -> str:
    return f"{settings.public_url}/{token}"


# --------------------------------------------------------------------------- #
# lookup
# --------------------------------------------------------------------------- #

async def grant_by_token(db: AsyncSession, settings: Settings, token: str) -> Grant | None:
    if not token or len(token) < 20 or len(token) > 128:
        return None
    digest = hash_token(settings.secret_key, token)
    stmt = select(Grant).where(Grant.token_hash == digest)
    return (await db.execute(stmt)).scalar_one_or_none()


async def grant_by_public_id(db: AsyncSession, public_id: str) -> Grant | None:
    stmt = select(Grant).where(Grant.public_id == public_id)
    return (await db.execute(stmt)).scalar_one_or_none()


async def session_by_id(db: AsyncSession, settings: Settings, session_id: str) -> Session | None:
    digest = hash_session(settings.secret_key, session_id)
    stmt = select(Session).where(Session.session_hash == digest)
    return (await db.execute(stmt)).scalar_one_or_none()


async def list_grants(db: AsyncSession, limit: int = 200) -> list[Grant]:
    stmt = select(Grant).order_by(Grant.created_at.desc(), Grant.id.desc()).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


# --------------------------------------------------------------------------- #
# usability of a link
# --------------------------------------------------------------------------- #

def link_is_openable(grant: Grant, now: datetime | None = None) -> bool:
    """Whether the login page should be shown for this grant.

    ``pending`` within the link window, or ``active`` (the bound browser coming
    back to the link URL).  Everything else gets the neutral page.
    """
    now = now or utcnow()
    if grant.status == GrantStatus.pending.value:
        expires = as_utc(grant.link_expires_at)
        return expires is not None and now < expires
    return grant.status == GrantStatus.active.value


# --------------------------------------------------------------------------- #
# vendor login
# --------------------------------------------------------------------------- #

async def attempt_login(
    db: AsyncSession,
    settings: Settings,
    *,
    grant: Grant,
    email: str,
    password: str,
    ip: str | None,
    user_agent: str | None,
) -> LoginResult:
    """Verify credentials and activate the grant.

    Raises :class:`GrantError` with a deliberately generic message on any
    failure, so the page never says which half was wrong (section 6.2).
    """
    generic = GrantError("Those details are incorrect.")
    now = utcnow()

    if grant.status != GrantStatus.pending.value:
        # Already used, revoked, expired or locked: no second login, ever.
        # An attempt against a still-active grant is a second device knocking.
        await log_event(
            db,
            type=(
                EventType.device_refused
                if grant.status == GrantStatus.active.value
                else EventType.login_failed
            ),
            actor="vendor",
            grant=grant,
            ip=ip,
            user_agent=user_agent,
            detail=f"login refused: grant status is {grant.status}",
        )
        raise generic

    link_expires = as_utc(grant.link_expires_at)
    if link_expires is not None and now >= link_expires:
        await expire_unused(db, grant)
        raise generic

    email_ok = normalise_email(email) == grant.vendor_email
    password_ok = verify_password(grant.password_hash, password or "")

    if not (email_ok and password_ok):
        grant.failed_attempts = (grant.failed_attempts or 0) + 1
        remaining = settings.max_login_attempts - grant.failed_attempts
        await log_event(
            db,
            type=EventType.login_failed,
            actor="vendor",
            grant=grant,
            ip=ip,
            user_agent=user_agent,
            detail=f"attempt {grant.failed_attempts}/{settings.max_login_attempts}",
        )
        if grant.failed_attempts >= settings.max_login_attempts:
            grant.status = GrantStatus.locked.value
            await log_event(
                db,
                type=EventType.grant_locked,
                actor="system",
                grant=grant,
                ip=ip,
                user_agent=user_agent,
                detail=f"locked after {grant.failed_attempts} failed attempts",
            )
            await db.flush()
            raise GrantError("This link is locked. Ask for a new one.")
        await db.flush()
        if remaining <= 2:
            raise GrantError(
                f"Those details are incorrect. {max(remaining, 0)} attempt(s) left."
            )
        raise generic

    # Success: start the access clock and bind the grant to this browser.
    session_id = generate_session_id()
    grant.status = GrantStatus.active.value
    grant.activated_at = now
    grant.access_expires_at = now + timedelta(minutes=grant.duration_minutes)
    grant.bound_device_hash = device_fingerprint(settings.secret_key, user_agent)
    grant.failed_attempts = 0

    db.add(
        Session(
            grant_id=grant.id,
            session_hash=hash_session(settings.secret_key, session_id),
            created_at=now,
            last_seen_at=now,
            ip=ip,
            user_agent=(" ".join((user_agent or "").split())[:512] or None),
        )
    )
    await log_event(
        db,
        type=EventType.login_ok,
        actor="vendor",
        grant=grant,
        ip=ip,
        user_agent=user_agent,
        detail=f"access window {grant.duration_minutes}m started",
    )
    await db.flush()
    return LoginResult(grant=grant, session_id=session_id)


# --------------------------------------------------------------------------- #
# state transitions
# --------------------------------------------------------------------------- #

async def _drop_sessions(db: AsyncSession, grant_id: int) -> None:
    await db.execute(delete(Session).where(Session.grant_id == grant_id))


async def revoke(
    db: AsyncSession,
    grant: Grant,
    *,
    admin_id: int | None,
    live: LiveConnections | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> Grant:
    if grant.status_enum in FINAL_STATUSES:
        raise GrantError(f"This grant is already {grant.status} and cannot be revoked.")
    previous = grant.status
    grant.status = GrantStatus.revoked.value
    grant.revoked_at = utcnow()
    grant.revoked_by = admin_id
    await _drop_sessions(db, grant.id)
    await log_event(
        db,
        type=EventType.grant_revoked,
        actor="admin",
        grant=grant,
        ip=ip,
        user_agent=user_agent,
        detail=f"revoked from {previous}",
    )
    await db.flush()
    if live is not None:
        await live.close_grant(grant.id)
    return grant


async def expire_access(
    db: AsyncSession, grant: Grant, *, live: LiveConnections | None = None
) -> Grant:
    if grant.status != GrantStatus.active.value:
        return grant
    grant.status = GrantStatus.expired.value
    await _drop_sessions(db, grant.id)
    await log_event(
        db,
        type=EventType.grant_expired,
        actor="system",
        grant=grant,
        detail=f"access window of {grant.duration_minutes}m ended",
    )
    await db.flush()
    if live is not None:
        await live.close_grant(grant.id)
    return grant


async def expire_unused(db: AsyncSession, grant: Grant) -> Grant:
    if grant.status != GrantStatus.pending.value:
        return grant
    grant.status = GrantStatus.expired_unused.value
    await _drop_sessions(db, grant.id)
    await log_event(
        db,
        type=EventType.link_expired_unused,
        actor="system",
        grant=grant,
        detail="link window passed without a successful login",
    )
    await db.flush()
    return grant


async def vendor_logout(
    db: AsyncSession,
    settings: Settings,
    *,
    session: Session,
    live: LiveConnections | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Vendor ends their own session early.

    The grant does not get extra life from this: the link is already used up, so
    an early logout is effectively the end of the access window.
    """
    grant = session.grant
    await db.execute(delete(Session).where(Session.id == session.id))
    if grant is not None and grant.status == GrantStatus.active.value:
        grant.status = GrantStatus.expired.value
    await log_event(
        db,
        type=EventType.vendor_logout,
        actor="vendor",
        grant=grant,
        ip=ip,
        user_agent=user_agent,
        detail="vendor ended the session",
    )
    await db.flush()
    if live is not None and grant is not None:
        await live.close_grant(grant.id)


# --------------------------------------------------------------------------- #
# the sweep used by the background job
# --------------------------------------------------------------------------- #

@dataclass
class SweepResult:
    expired: int = 0
    expired_unused: int = 0
    connections_closed: int = 0

    @property
    def total(self) -> int:
        return self.expired + self.expired_unused


async def sweep_expired(
    db: AsyncSession, *, live: LiveConnections | None = None, now: datetime | None = None
) -> SweepResult:
    """Move finished grants to their final state (section 6.5)."""
    now = now or utcnow()
    result = SweepResult()

    stmt = select(Grant).where(
        Grant.status.in_([GrantStatus.pending.value, GrantStatus.active.value])
    )
    for grant in (await db.execute(stmt)).scalars().all():
        if grant.status == GrantStatus.active.value:
            expires = as_utc(grant.access_expires_at)
            if expires is not None and now >= expires:
                before = live.count(grant.id) if live else 0
                await expire_access(db, grant, live=live)
                result.expired += 1
                result.connections_closed += before
        else:
            link_expires = as_utc(grant.link_expires_at)
            if link_expires is not None and now >= link_expires:
                await expire_unused(db, grant)
                result.expired_unused += 1
    return result


async def count_events(db: AsyncSession) -> int:
    from sqlalchemy import func as sa_func

    return int((await db.execute(select(sa_func.count(Event.id)))).scalar() or 0)
