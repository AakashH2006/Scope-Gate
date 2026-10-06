"""Request-scoped helpers: client address, cookies, admin sessions, CSRF."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock

from fastapi import Request

from .config import Settings
from .security import (
    constant_time_equals,
    generate_session_id,
    keyed_hash,
    sign_cookie,
    unsign_cookie,
)

ADMIN_COOKIE = "vg_admin"
VENDOR_COOKIE = "vg_session"
ADMIN_COOKIE_SALT = "vg-admin-cookie"
VENDOR_COOKIE_SALT = "vg-vendor-cookie"

#: The admin session is confirmed as "fresh" for this long after a successful
#: master-password step-up, so creating several grants in a row is not painful
#: while a stolen idle session still cannot issue one (section 6.4).
STEPUP_FRESHNESS_SECONDS = 120


# --------------------------------------------------------------------------- #
# client address
# --------------------------------------------------------------------------- #

def client_ip(request: Request, settings: Settings) -> str:
    """Best-known client address.

    Caddy sits in front and sets ``X-Forwarded-For``.  That header is only
    trusted when ``TRUST_FORWARDED_FOR`` says a trusted proxy is really there;
    otherwise a client could forge its own address into the audit log.
    """
    if settings.trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # Left-most entry is the original client; Caddy appends, so the last
            # hop we added is right-most. One proxy => take the first.
            first = forwarded.split(",")[0].strip()
            if first:
                return first[:64]
    if request.client is not None and request.client.host:
        return request.client.host[:64]
    return "unknown"


def user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:512]


# --------------------------------------------------------------------------- #
# admin sessions (server-side, so logout and idle timeout are real)
# --------------------------------------------------------------------------- #

@dataclass
class AdminSession:
    sid: str
    admin_id: int
    admin_email: str
    created_at: float
    last_seen: float
    csrf_token: str
    last_stepup: float = 0.0
    #: One-shot message carried across a redirect (never holds a secret after
    #: it has been read once).
    flash: dict | None = None

    @property
    def stepup_is_fresh(self) -> bool:
        return (time.time() - self.last_stepup) <= STEPUP_FRESHNESS_SECONDS

    def take_flash(self) -> dict | None:
        flash, self.flash = self.flash, None
        return flash


@dataclass
class AdminSessionStore:
    """In-memory admin sessions.

    A restart signs admins out, which is acceptable (and arguably correct) for a
    single-process gateway.  Several workers would need this in the database;
    that is noted in deploy/README.md.
    """

    idle_timeout_seconds: int = 1200
    _sessions: dict[str, AdminSession] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def create(self, *, admin_id: int, admin_email: str, stepped_up: bool = True) -> AdminSession:
        now = time.time()
        session = AdminSession(
            sid=generate_session_id(),
            admin_id=admin_id,
            admin_email=admin_email,
            created_at=now,
            last_seen=now,
            csrf_token=generate_session_id(),
            last_stepup=now if stepped_up else 0.0,
        )
        with self._lock:
            self._gc(now)
            self._sessions[session.sid] = session
        return session

    def get(self, sid: str | None) -> AdminSession | None:
        if not sid:
            return None
        now = time.time()
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None
            if now - session.last_seen > self.idle_timeout_seconds:
                self._sessions.pop(sid, None)
                return None
            session.last_seen = now
            return session

    def drop(self, sid: str | None) -> None:
        if not sid:
            return
        with self._lock:
            self._sessions.pop(sid, None)

    def drop_admin(self, admin_id: int) -> None:
        with self._lock:
            for sid in [s for s, v in self._sessions.items() if v.admin_id == admin_id]:
                self._sessions.pop(sid, None)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def _gc(self, now: float) -> None:
        for sid in [
            s for s, v in self._sessions.items() if now - v.last_seen > self.idle_timeout_seconds
        ]:
            self._sessions.pop(sid, None)


# --------------------------------------------------------------------------- #
# cookies
# --------------------------------------------------------------------------- #

def set_admin_cookie(response, settings: Settings, sid: str) -> None:
    response.set_cookie(
        ADMIN_COOKIE,
        sign_cookie(settings.secret_key, ADMIN_COOKIE_SALT, {"sid": sid}),
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        path="/admin",
        max_age=settings.admin_idle_timeout_minutes * 60,
    )


def clear_admin_cookie(response, settings: Settings) -> None:
    response.delete_cookie(ADMIN_COOKIE, path="/admin", samesite="strict")


def read_admin_sid(request: Request, settings: Settings) -> str | None:
    raw = request.cookies.get(ADMIN_COOKIE)
    if not raw:
        return None
    data = unsign_cookie(settings.secret_key, ADMIN_COOKIE_SALT, raw)
    if not data:
        return None
    sid = data.get("sid")
    return sid if isinstance(sid, str) else None


def set_vendor_cookie(
    response, settings: Settings, session_id: str, grant_public_id: str
) -> None:
    """Vendor session cookie.

    ``SameSite=Lax`` rather than ``Strict``: the vendor arrives from a link in
    their mail client, and a Strict cookie would not be sent on that first
    cross-site navigation back to ``/s/``.

    The grant's public id rides along so that once the session row is gone --
    revoke and expiry both delete it -- the gateway can still tell the vendor
    *why* they are out.  The public id is a dashboard label, not a secret, and
    the cookie is signed, so it cannot be swapped for another grant's.
    """
    response.set_cookie(
        VENDOR_COOKIE,
        sign_cookie(
            settings.secret_key,
            VENDOR_COOKIE_SALT,
            {"sid": session_id, "g": grant_public_id},
        ),
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )


def clear_vendor_cookie(response, settings: Settings) -> None:
    response.delete_cookie(VENDOR_COOKIE, path="/", samesite="lax")


def read_vendor_cookie(request: Request, settings: Settings) -> tuple[str | None, str | None]:
    """Return ``(session_id, grant_public_id)`` from the signed cookie."""
    raw = request.cookies.get(VENDOR_COOKIE)
    if not raw:
        return None, None
    data = unsign_cookie(settings.secret_key, VENDOR_COOKIE_SALT, raw)
    if not data:
        return None, None
    sid = data.get("sid")
    grant = data.get("g")
    return (
        sid if isinstance(sid, str) else None,
        grant if isinstance(grant, str) else None,
    )


def read_vendor_session_id(request: Request, settings: Settings) -> str | None:
    return read_vendor_cookie(request, settings)[0]


# --------------------------------------------------------------------------- #
# CSRF
# --------------------------------------------------------------------------- #

def admin_csrf_ok(session: AdminSession, submitted: str | None) -> bool:
    return bool(submitted) and constant_time_equals(session.csrf_token, submitted or "")


def vendor_csrf_token(settings: Settings, session_id: str) -> str:
    """Derived from the vendor's session id, so no extra state is needed."""
    return keyed_hash(settings.secret_key, "vendor-csrf", session_id)


def vendor_csrf_ok(settings: Settings, session_id: str, submitted: str | None) -> bool:
    if not submitted:
        return False
    return constant_time_equals(vendor_csrf_token(settings, session_id), submitted)
