"""Admin routes -- section 8 of the plan.

Every route below the sign-in page requires a valid admin session; every state
change requires a CSRF token; creating a grant additionally requires the master
password to be re-entered (section 6.4).
"""
from __future__ import annotations

import logging
import time
from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .deps import (
    AdminSession,
    admin_csrf_ok,
    clear_admin_cookie,
    client_ip,
    read_admin_sid,
    set_admin_cookie,
    user_agent,
)
from .events import log_event, recent_events
from .grants import (
    GrantError,
    build_link,
    create_grant,
    grant_by_public_id,
    list_grants,
    revoke,
)
from .mailer import VendorInvite
from .models import Admin, EventType, GrantStatus, as_utc, utcnow
from .security import needs_rehash, hash_password, verify_password

log = logging.getLogger("scopegate.admin")

router = APIRouter(prefix="/admin")

DASHBOARD_EVENT_PREVIEW = 25
LOG_ROW_LIMIT = 500


def _templates(request: Request):
    return request.app.state.templates


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _fmt(dt) -> str:
    value = as_utc(dt)
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else ""


def _fmt_left(seconds: int | None) -> str:
    if seconds is None:
        return ""
    minutes, secs = divmod(max(0, seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}:{secs:02d}"


def _current_session(request: Request) -> AdminSession | None:
    settings = _settings(request)
    return request.app.state.admin_sessions.get(read_admin_sid(request, settings))


def _login_redirect() -> RedirectResponse:
    return RedirectResponse("/admin/login", status_code=303)


# --------------------------------------------------------------------------- #
# sign in / out
# --------------------------------------------------------------------------- #

@router.get("/login")
async def login_form(request: Request) -> Response:
    if _current_session(request) is not None:
        return RedirectResponse("/admin", status_code=303)
    return _templates(request).TemplateResponse(
        request, "admin/login.html", {"error": None, "email": ""}
    )


@router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(default=""),
    password: str = Form(default=""),
    totp: str = Form(default=""),
) -> Response:
    settings = _settings(request)
    ip = client_ip(request, settings)
    limiter = request.app.state.admin_limiter

    def deny(message: str, status: int = 401) -> Response:
        return _templates(request).TemplateResponse(
            request,
            "admin/login.html",
            {"error": message, "email": email},
            status_code=status,
        )

    if not limiter.check(ip):
        async with request.app.state.sessionmaker() as db:
            await log_event(
                db,
                type=EventType.rate_limited,
                actor="admin",
                ip=ip,
                user_agent=user_agent(request),
                detail="too many admin sign-in attempts from this address",
            )
            await db.commit()
        return deny("Too many attempts. Wait a minute and try again.", status=429)

    async with request.app.state.sessionmaker() as db:
        admin = await _admin_by_email(db, email)
        ok = admin is not None and verify_password(admin.password_hash, password)
        totp_ok = False
        if ok and admin is not None:
            totp_ok = _verify_admin_totp(settings, admin, totp)

        if not (ok and totp_ok):
            await log_event(
                db,
                type=EventType.admin_login_failed,
                actor="admin",
                ip=ip,
                user_agent=user_agent(request),
                detail=(
                    "password or account incorrect"
                    if not ok
                    else "authenticator code incorrect"
                ),
            )
            await db.commit()
            # One message for both halves, so the page reveals nothing.
            return deny("Sign-in failed. Check your password and code.")

        assert admin is not None
        if needs_rehash(admin.password_hash):
            admin.password_hash = hash_password(password)
        admin.last_login_at = utcnow()
        await log_event(
            db,
            type=EventType.admin_login_ok,
            actor="admin",
            ip=ip,
            user_agent=user_agent(request),
            detail=f"admin {admin.email} signed in",
        )
        admin_id, admin_email = admin.id, admin.email
        await db.commit()

    session = request.app.state.admin_sessions.create(
        admin_id=admin_id, admin_email=admin_email, stepped_up=True
    )
    response = RedirectResponse("/admin", status_code=303)
    set_admin_cookie(response, settings, session.sid)
    return response


@router.post("/logout")
async def logout(request: Request, csrf: str = Form(default="")) -> Response:
    settings = _settings(request)
    session = _current_session(request)
    if session is not None and admin_csrf_ok(session, csrf):
        request.app.state.admin_sessions.drop(session.sid)
    response = _login_redirect()
    clear_admin_cookie(response, settings)
    return response


async def _admin_by_email(db: AsyncSession, email: str) -> Admin | None:
    cleaned = (email or "").strip().lower()
    if not cleaned:
        return None
    return (
        await db.execute(select(Admin).where(Admin.email == cleaned))
    ).scalar_one_or_none()


def _verify_admin_totp(settings: Settings, admin: Admin, code: str) -> bool:
    from .security import decrypt_totp_secret, verify_totp

    secret = decrypt_totp_secret(settings.totp_enc_key, admin.totp_secret_enc)
    if not secret:
        log.error("cannot decrypt the TOTP secret for %s -- is TOTP_ENC_KEY right?", admin.email)
        return False
    return verify_totp(secret, code)


# --------------------------------------------------------------------------- #
# dashboard
# --------------------------------------------------------------------------- #

@router.get("")
@router.get("/")
async def dashboard(request: Request) -> Response:
    session = _current_session(request)
    if session is None:
        return _login_redirect()
    settings = _settings(request)

    async with request.app.state.sessionmaker() as db:
        grants = await list_grants(db)
        events = await recent_events(
            db, days=settings.log_dashboard_days, limit=DASHBOARD_EVENT_PREVIEW
        )
        mail_failures = len(
            await recent_events(
                db,
                days=settings.log_dashboard_days,
                limit=100,
                type_filter=EventType.email_failed.value,
            )
        )
        await db.commit()

    now = utcnow()
    counts = {"active": 0, "pending": 0, "locked": 0, "finished": 0}
    rows = []
    for grant in grants:
        status = grant.status
        if status == GrantStatus.active.value:
            counts["active"] += 1
            time_left = _fmt_left(grant.seconds_left(now))
        elif status == GrantStatus.pending.value:
            counts["pending"] += 1
            time_left = f"link {_fmt_left(grant.link_seconds_left(now))}"
        elif status == GrantStatus.locked.value:
            counts["locked"] += 1
            time_left = ""
        else:
            counts["finished"] += 1
            time_left = ""
        rows.append({"grant": grant, "time_left": time_left, "created": _fmt(grant.created_at)})

    flash = session.take_flash()
    context = {
        "page": "dashboard",
        "admin_email": session.admin_email,
        "csrf_token": session.csrf_token,
        "grants": rows,
        "counts": counts,
        "events": [{"event": e, "when": _fmt(e.ts)} for e in events],
        "allowed_pages": settings.allowed_pages,
        "allowed_methods": settings.allowed_methods,
        "max_access_minutes": settings.max_access_minutes,
        "link_ttl_minutes": settings.link_ttl_minutes,
        "log_dashboard_days": settings.log_dashboard_days,
        "log_retention_days": settings.log_retention_days,
        "upstream_url": settings.upstream_url,
        "live_connections": request.app.state.live.count(),
        "mail_failures": mail_failures,
        "issued": (flash or {}).get("issued"),
        "notice": (flash or {}).get("notice"),
        "error": (flash or {}).get("error"),
    }
    return _templates(request).TemplateResponse(request, "admin/dashboard.html", context)


# --------------------------------------------------------------------------- #
# create a grant
# --------------------------------------------------------------------------- #

@router.post("/grants")
async def create_grant_route(
    request: Request,
    csrf: str = Form(default=""),
    vendor_email: str = Form(default=""),
    duration_minutes: int = Form(default=0),
    master_password: str = Form(default=""),
    allowed_paths: list[str] = Form(default=[]),
) -> Response:
    session = _current_session(request)
    if session is None:
        return _login_redirect()
    settings = _settings(request)

    if not admin_csrf_ok(session, csrf):
        session.flash = {"error": "That request could not be verified. Try again."}
        return RedirectResponse("/admin", status_code=303)

    ip = client_ip(request, settings)
    ua = user_agent(request)

    async with request.app.state.sessionmaker() as db:
        admin = (
            await db.execute(select(Admin).where(Admin.id == session.admin_id))
        ).scalar_one_or_none()
        if admin is None:
            request.app.state.admin_sessions.drop(session.sid)
            await db.commit()
            return _login_redirect()

        # Step-up: a stolen open session cannot issue access on its own.
        if not verify_password(admin.password_hash, master_password):
            await log_event(
                db,
                type=EventType.admin_login_failed,
                actor="admin",
                ip=ip,
                user_agent=ua,
                detail="master password re-entry failed while creating a grant",
            )
            await db.commit()
            session.flash = {"error": "Your password was not correct. No grant was created."}
            return RedirectResponse("/admin", status_code=303)
        session.last_stepup = time.time()

        try:
            new = await create_grant(
                db,
                settings,
                vendor_email=vendor_email,
                duration_minutes=duration_minutes,
                allowed_paths=allowed_paths,
                admin_id=admin.id,
                ip=ip,
                user_agent=ua,
            )
        except GrantError as exc:
            await db.commit()
            session.flash = {"error": str(exc)}
            return RedirectResponse("/admin", status_code=303)

        link = build_link(settings, new.token)
        grant = new.grant
        invite = VendorInvite(
            vendor_email=grant.vendor_email,
            link=link,
            password=new.password,
            link_expires_at=as_utc(grant.link_expires_at) or utcnow(),
            duration_minutes=grant.duration_minutes,
            allowed_paths=list(grant.allowed_paths or []),
            public_url=settings.public_url,
        )
        grant_id, public_id, vendor = grant.id, grant.public_id, grant.vendor_email
        await db.commit()

    mail_detail = await _send_invite(request, invite, grant_id=grant_id, public_id=public_id)

    session.flash = {
        "issued": {
            "public_id": public_id,
            "vendor_email": vendor,
            "link": link,
            "password": new.password,
            "mail_detail": mail_detail,
        }
    }
    return RedirectResponse("/admin", status_code=303)


async def _send_invite(
    request: Request, invite: VendorInvite, *, grant_id: int, public_id: str
) -> str:
    """Hand the invite to the mailer and record the outcome.

    The send itself runs on a worker thread; the audit row is written from the
    callback, which hops back onto the event loop.
    """
    import asyncio

    loop = asyncio.get_running_loop()
    mailer = request.app.state.mailer
    sessionmaker = request.app.state.sessionmaker
    done: asyncio.Future[str] = loop.create_future()

    async def record(ok: bool, detail: str) -> None:
        async with sessionmaker() as db:
            await log_event(
                db,
                type=EventType.email_sent if ok else EventType.email_failed,
                actor="system",
                grant_id=grant_id,
                grant_public_id=public_id,
                detail=(f"invite to {invite.vendor_email} via {detail}" if ok else detail),
            )
            await db.commit()
        if not done.done():
            done.set_result(detail if ok else f"send failed: {detail}")

    def on_done(ok: bool, detail: str) -> None:
        asyncio.run_coroutine_threadsafe(record(ok, detail), loop)

    mailer.send_invite_async(invite, on_done)
    try:
        return await asyncio.wait_for(asyncio.shield(done), timeout=5.0)
    except asyncio.TimeoutError:
        # A slow mail server must not hold up the response; the audit row still
        # lands when the thread finishes.
        return "still sending"


# --------------------------------------------------------------------------- #
# revoke
# --------------------------------------------------------------------------- #

@router.post("/grants/{public_id}/revoke")
async def revoke_route(
    request: Request, public_id: str, csrf: str = Form(default="")
) -> Response:
    session = _current_session(request)
    if session is None:
        return _login_redirect()
    settings = _settings(request)

    if not admin_csrf_ok(session, csrf):
        session.flash = {"error": "That request could not be verified. Try again."}
        return RedirectResponse("/admin", status_code=303)

    async with request.app.state.sessionmaker() as db:
        grant = await grant_by_public_id(db, public_id)
        if grant is None:
            await db.commit()
            session.flash = {"error": "No such grant."}
            return RedirectResponse("/admin", status_code=303)
        try:
            await revoke(
                db,
                grant,
                admin_id=session.admin_id,
                live=request.app.state.live,
                ip=client_ip(request, settings),
                user_agent=user_agent(request),
            )
        except GrantError as exc:
            await db.commit()
            session.flash = {"error": str(exc)}
            return RedirectResponse("/admin", status_code=303)
        await db.commit()

    session.flash = {"notice": f"Grant {public_id} revoked. The vendor is out on their next click."}
    return RedirectResponse("/admin", status_code=303)


# --------------------------------------------------------------------------- #
# logs
# --------------------------------------------------------------------------- #

@router.get("/logs")
async def logs(request: Request) -> Response:
    session = _current_session(request)
    if session is None:
        return _login_redirect()
    settings = _settings(request)

    type_filter = (request.query_params.get("type") or "").strip() or None
    actor_filter = (request.query_params.get("actor") or "").strip() or None
    grant_filter = (request.query_params.get("grant") or "").strip() or None

    valid_types = {e.value for e in EventType}
    if type_filter and type_filter not in valid_types:
        type_filter = None
    if actor_filter and actor_filter not in {"admin", "vendor", "system"}:
        actor_filter = None

    async with request.app.state.sessionmaker() as db:
        events = await recent_events(
            db,
            days=settings.log_dashboard_days,
            limit=LOG_ROW_LIMIT,
            type_filter=type_filter,
            actor=actor_filter,
            grant_public_id=grant_filter,
        )
        await db.commit()

    context = {
        "page": "logs",
        "admin_email": session.admin_email,
        "csrf_token": session.csrf_token,
        "events": [{"event": e, "when": _fmt(e.ts)} for e in events],
        "event_types": sorted(valid_types),
        "type_filter": type_filter,
        "actor_filter": actor_filter,
        "grant_filter": grant_filter,
        "truncated": len(events) >= LOG_ROW_LIMIT,
        "log_dashboard_days": settings.log_dashboard_days,
        "log_retention_days": settings.log_retention_days,
    }
    return _templates(request).TemplateResponse(request, "admin/logs.html", context)
