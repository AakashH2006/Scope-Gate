"""Vendor-facing routes -- section 8 of the plan.

Route order matters: the reserved paths (``/static``, ``/admin``, ``/s/...``) are
declared before the catch-all ``/{token}``, so a token can never shadow them.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass

import httpx
from fastapi import APIRouter, Form, Request, Response, WebSocket
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from sqlalchemy.ext.asyncio import AsyncSession

from . import proxy
from .config import Settings
from .deps import (
    clear_vendor_cookie,
    client_ip,
    read_vendor_cookie,
    set_vendor_cookie,
    user_agent,
    vendor_csrf_ok,
    vendor_csrf_token,
)
from .events import log_event
from .grants import (
    GrantError,
    attempt_login,
    expire_access,
    grant_by_public_id,
    grant_by_token,
    link_is_openable,
    session_by_id,
    vendor_logout,
)
from .models import EventType, Grant, GrantStatus, Session, as_utc, utcnow

log = logging.getLogger("vendorgate.vendor")

router = APIRouter()

#: Shape of a link token: url-safe base64, 32 bytes -> 43 chars.  Anything else
#: is not a token and gets the same neutral page as a dead one.
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")

#: Bodies larger than this are streamed through without URL rewriting.
MAX_REWRITE_BYTES = 8 * 1024 * 1024

#: Reserved under /s/ -- the gateway's own endpoints, never proxied.
RESERVED_PROXY_PATHS = frozenset({"logout", "_status"})


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #

def _templates(request: Request):
    return request.app.state.templates


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _neutral(request: Request, status: int = 404) -> HTMLResponse:
    """The one page every unusable link gets (expired, revoked, unknown, locked)."""
    return _templates(request).TemplateResponse(
        request, "vendor/invalid.html", {}, status_code=status
    )


def _ended(
    request: Request, reason: str, *, status: int = 403, clear_cookie: bool = True
) -> HTMLResponse:
    response = _templates(request).TemplateResponse(
        request, "vendor/ended.html", {"reason": reason}, status_code=status
    )
    if clear_cookie:
        clear_vendor_cookie(response, _settings(request))
    return response


@dataclass
class VendorContext:
    session: Session
    grant: Grant
    session_id: str


class NotAuthorised(Exception):
    def __init__(self, reason: str, *, neutral: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.neutral = neutral


def _status_reason(status: str) -> str:
    return {
        GrantStatus.revoked.value: "This access was withdrawn.",
        GrantStatus.expired.value: "The access window has ended.",
        GrantStatus.expired_unused.value: "This link was never used and has expired.",
        GrantStatus.locked.value: "This access is locked.",
    }.get(status, "This access is no longer available.")


async def _reason_for_missing_session(db: AsyncSession, grant_public_id: str | None) -> str:
    if not grant_public_id:
        return "Your session is no longer valid."
    grant = await grant_by_public_id(db, grant_public_id)
    if grant is None:
        return "Your session is no longer valid."
    return _status_reason(grant.status)


async def resolve_vendor(
    request: Request, db: AsyncSession, settings: Settings
) -> VendorContext:
    """Authorise one vendor request.

    Checked in this order, every single request, on the server (section 6.5):
    session valid -> grant is active -> clock has time left -> same device.
    """
    session_id, cookie_grant_id = read_vendor_cookie(request, settings)
    if not session_id:
        raise NotAuthorised("No active session.", neutral=True)

    session = await session_by_id(db, settings, session_id)
    if session is None:
        # Revoke and expiry both delete the session row.  The signed cookie
        # still names the grant, so the vendor gets the real reason.
        raise NotAuthorised(await _reason_for_missing_session(db, cookie_grant_id))

    grant = session.grant
    if grant is None:
        raise NotAuthorised("Your session is no longer valid.")

    if grant.status != GrantStatus.active.value:
        raise NotAuthorised(_status_reason(grant.status))

    expires = as_utc(grant.access_expires_at)
    if expires is None or utcnow() >= expires:
        # The clock ran out between ticks of the expiry job: finish it here and
        # now, so the vendor never gets one request past the deadline.
        await expire_access(db, grant, live=request.app.state.live)
        raise NotAuthorised("The access window has ended.")

    from .security import device_fingerprint

    if grant.bound_device_hash and grant.bound_device_hash != device_fingerprint(
        settings.secret_key, user_agent(request)
    ):
        await log_event(
            db,
            type=EventType.device_refused,
            actor="vendor",
            grant=grant,
            ip=client_ip(request, settings),
            user_agent=user_agent(request),
            detail="session presented from a different device",
        )
        raise NotAuthorised("This link is tied to the device that first signed in.")

    session.last_seen_at = utcnow()
    session.ip = client_ip(request, settings)
    return VendorContext(session=session, grant=grant, session_id=session_id)


# --------------------------------------------------------------------------- #
# the proxied area
# --------------------------------------------------------------------------- #

@router.get("/s/_status")
async def vendor_status(request: Request) -> Response:
    """Seconds remaining, for the countdown bar.  Convenience only."""
    settings = _settings(request)
    async with request.app.state.sessionmaker() as db:
        try:
            ctx = await resolve_vendor(request, db, settings)
        except NotAuthorised:
            await db.commit()
            return JSONResponse({"seconds_left": 0}, status_code=401)
        payload = {
            "seconds_left": ctx.grant.seconds_left() or 0,
            "grant": ctx.grant.public_id,
        }
        await db.commit()
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


@router.post("/s/logout")
async def vendor_logout_route(request: Request, csrf: str = Form(default="")) -> Response:
    settings = _settings(request)
    async with request.app.state.sessionmaker() as db:
        try:
            ctx = await resolve_vendor(request, db, settings)
        except NotAuthorised:
            await db.commit()
            return _ended(request, "Your session is already closed.", status=200)
        if not vendor_csrf_ok(settings, ctx.session_id, csrf):
            await db.commit()
            # A forged logout must not end a legitimate session, so the cookie
            # stays where it is.
            return _ended(
                request,
                "That request could not be verified. Your session is unchanged.",
                status=400,
                clear_cookie=False,
            )
        await vendor_logout(
            db,
            settings,
            session=ctx.session,
            live=request.app.state.live,
            ip=client_ip(request, settings),
            user_agent=user_agent(request),
        )
        await db.commit()
    return _ended(request, "You signed out. Thank you.", status=200)


@router.api_route(
    "/s/{upstream_path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy_request(request: Request, upstream_path: str) -> Response:
    settings = _settings(request)

    async with request.app.state.sessionmaker() as db:
        try:
            ctx = await resolve_vendor(request, db, settings)
        except NotAuthorised as exc:
            await db.commit()
            if exc.neutral:
                return _neutral(request, status=401)
            return _ended(request, exc.reason)

        grant = ctx.grant
        allowed = list(grant.allowed_paths or [])
        requested = "/" + (upstream_path or "").lstrip("/")

        if requested.strip("/").split("/", 1)[0] in RESERVED_PROXY_PATHS:
            # /s/logout and /s/_status are handled above; anything else that
            # collides with them is not an upstream page.
            await db.commit()
            return _neutral(request, status=404)

        try:
            decision = proxy.check_request(
                method=request.method,
                path=requested,
                allowed_prefixes=allowed,
                settings=settings,
            )
        except proxy.ProxyDenied as denied:
            await log_event(
                db,
                type=EventType.page_blocked,
                actor="vendor",
                grant=grant,
                ip=client_ip(request, settings),
                user_agent=user_agent(request),
                detail=f"{request.method} {proxy.normalise_path(requested)}: {denied.reason}",
            )
            await db.commit()
            response = _templates(request).TemplateResponse(
                request,
                "vendor/blocked.html",
                {
                    "reason": "That page is not part of your access."
                    if denied.status == 403
                    else "Only read-only requests are permitted.",
                    "allowed_paths": allowed,
                    "first_page": allowed[0] if allowed else None,
                },
                status_code=denied.status,
            )
            return response

        csrf_token = vendor_csrf_token(settings, ctx.session_id)
        grant_id = grant.id
        seconds_left = grant.seconds_left() or 0
        await log_event(
            db,
            type=EventType.page_viewed,
            actor="vendor",
            grant=grant,
            ip=client_ip(request, settings),
            user_agent=user_agent(request),
            detail=f"{request.method} {decision.upstream_path}",
        )
        await db.commit()

    return await _forward(
        request,
        settings=settings,
        upstream_path=decision.upstream_path,
        grant_id=grant_id,
        csrf_token=csrf_token,
        seconds_left=seconds_left,
        allowed_paths=allowed,
    )


async def _forward(
    request: Request,
    *,
    settings: Settings,
    upstream_path: str,
    grant_id: int,
    csrf_token: str,
    seconds_left: int,
    allowed_paths: list[str],
) -> Response:
    """Send the request upstream and sanitise what comes back."""
    client: httpx.AsyncClient = request.app.state.upstream

    body = b""
    if request.method not in ("GET", "HEAD"):
        body = await request.body()
        if len(body) > settings.max_request_bytes:
            return Response("Request too large.", status_code=413)

    query = request.url.query
    url = upstream_path + (f"?{query}" if query else "")
    headers = proxy.filter_request_headers(dict(request.headers))

    upstream_request = client.build_request(
        request.method, url, headers=headers, content=body or None
    )
    # httpx keeps a cookie jar on the client.  The gateway must look like a fresh,
    # anonymous client on every request, or a cookie the internal site set for one
    # vendor would ride along on the next vendor's request.
    client.cookies.clear()
    try:
        upstream = await client.send(upstream_request, stream=True)
    except httpx.TimeoutException:
        log.warning("upstream timeout for %s", upstream_path)
        return _upstream_error(request, "The internal page took too long to answer.", 504)
    except httpx.HTTPError as exc:
        log.warning("upstream error for %s: %s", upstream_path, exc)
        return _upstream_error(request, "The internal page could not be reached.", 502)

    content_type = upstream.headers.get("content-type", "")
    out_headers = proxy.filter_response_headers(
        upstream.headers, is_html=proxy.is_html(content_type)
    )

    if "location" in upstream.headers:
        out_headers["location"] = proxy.rewrite_location(
            upstream.headers["location"], upstream_url=settings.upstream_url
        )

    rewritable = proxy.is_rewritable(content_type)
    declared_length = upstream.headers.get("content-length")
    too_big = declared_length is not None and int(declared_length) > MAX_REWRITE_BYTES

    if rewritable and not too_big and request.method != "HEAD":
        try:
            raw = await upstream.aread()
        finally:
            await upstream.aclose()
        charset = proxy.response_charset(content_type)
        out = proxy.rewrite_body(raw, upstream_url=settings.upstream_url, charset=charset)
        if proxy.is_html(content_type):
            # Take out the navigation the grant does not cover, before the
            # banner is added, so the banner's own controls are never judged.
            out = proxy.hide_blocked_links(
                out,
                allowed_prefixes=allowed_paths,
                mode=settings.blocked_links,
                charset=charset,
            )
            if settings.inject_banner:
                out = proxy.inject_banner(out, csrf_token=csrf_token, charset=charset)
        out_headers["X-VendorGate-Seconds-Left"] = str(seconds_left)
        return Response(
            content=out,
            status_code=upstream.status_code,
            headers=out_headers,
            media_type=content_type or None,
        )

    # Anything else (downloads, images, large files) is streamed, and the stream
    # is cut the moment the grant ends -- section 6.5.
    kill = await request.app.state.live.register(grant_id)

    async def stream():
        try:
            async for chunk in upstream.aiter_raw():
                if kill.is_set():
                    log.info("stream for grant %s cut by expiry/revoke", grant_id)
                    break
                yield chunk
        finally:
            await upstream.aclose()
            await request.app.state.live.unregister(grant_id, kill)

    return StreamingResponse(
        stream(),
        status_code=upstream.status_code,
        headers=out_headers,
        media_type=content_type or None,
    )


def _upstream_error(request: Request, reason: str, status: int) -> HTMLResponse:
    return _templates(request).TemplateResponse(
        request,
        "vendor/blocked.html",
        {"reason": reason, "allowed_paths": [], "first_page": None},
        status_code=status,
    )


# --------------------------------------------------------------------------- #
# websocket proxy
# --------------------------------------------------------------------------- #

@router.websocket("/s/{upstream_path:path}")
async def proxy_websocket(websocket: WebSocket, upstream_path: str) -> None:
    """Proxy a websocket, and close it when the grant ends.

    Same allowlist as HTTP.  The handshake is a GET, so a grant restricted to
    ``GET``/``HEAD`` may still open a socket on an allowed page.
    """
    import websockets
    from websockets.exceptions import WebSocketException

    settings = websocket.app.state.settings
    request_like = _FakeRequest(websocket)

    async with websocket.app.state.sessionmaker() as db:
        try:
            ctx = await resolve_vendor(request_like, db, settings)  # type: ignore[arg-type]
        except NotAuthorised:
            await db.commit()
            await websocket.close(code=4401)
            return

        grant = ctx.grant
        grant_id = grant.id
        requested = "/" + (upstream_path or "").lstrip("/")
        normalised = proxy.normalise_path(requested)
        if proxy.path_allowed(normalised, list(grant.allowed_paths or [])) is None:
            await log_event(
                db,
                type=EventType.page_blocked,
                actor="vendor",
                grant=grant,
                ip=client_ip(request_like, settings),  # type: ignore[arg-type]
                user_agent=websocket.headers.get("user-agent", ""),
                detail=f"WS {normalised}: path is not in this grant",
            )
            await db.commit()
            await websocket.close(code=4403)
            return

        await log_event(
            db,
            type=EventType.page_viewed,
            actor="vendor",
            grant=grant,
            ip=client_ip(request_like, settings),  # type: ignore[arg-type]
            user_agent=websocket.headers.get("user-agent", ""),
            detail=f"WS {normalised}",
        )
        await db.commit()

    scheme = "wss" if settings.upstream_url.startswith("https") else "ws"
    base = settings.upstream_url.split("://", 1)[-1]
    query = websocket.url.query
    target = f"{scheme}://{base}{normalised}" + (f"?{query}" if query else "")

    await websocket.accept()
    kill = await websocket.app.state.live.register(grant_id)
    try:
        async with websockets.connect(target, open_timeout=10) as upstream:
            await _pump_websocket(websocket, upstream, kill)
    except (WebSocketException, OSError, asyncio.TimeoutError) as exc:
        log.warning("websocket upstream failed for %s: %s", normalised, exc)
    finally:
        await websocket.app.state.live.unregister(grant_id, kill)
        try:
            await websocket.close()
        except RuntimeError:
            pass


async def _pump_websocket(client: WebSocket, upstream, kill: asyncio.Event) -> None:
    """Copy frames both ways until either side closes or the grant ends."""

    async def client_to_upstream() -> None:
        while True:
            message = await client.receive()
            if message["type"] == "websocket.disconnect":
                return
            if (text := message.get("text")) is not None:
                await upstream.send(text)
            elif (data := message.get("bytes")) is not None:
                await upstream.send(data)

    async def upstream_to_client() -> None:
        async for frame in upstream:
            if isinstance(frame, bytes):
                await client.send_bytes(frame)
            else:
                await client.send_text(frame)

    async def watch_kill() -> None:
        await kill.wait()
        log.info("websocket cut by expiry/revoke")

    tasks = [
        asyncio.create_task(client_to_upstream()),
        asyncio.create_task(upstream_to_client()),
        asyncio.create_task(watch_kill()),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class _FakeRequest:
    """Adapter so :func:`resolve_vendor` works for a websocket handshake."""

    def __init__(self, websocket: WebSocket) -> None:
        self._ws = websocket
        self.app = websocket.app
        self.headers = websocket.headers
        self.cookies = websocket.cookies
        self.client = websocket.client
        self.url = websocket.url
        self.method = "GET"


# --------------------------------------------------------------------------- #
# the link itself
# --------------------------------------------------------------------------- #

@router.get("/{token}")
async def link_page(request: Request, token: str) -> Response:
    """Show the login page for a link.

    A GET never consumes the link (section 6.3): mail security scanners follow
    links automatically and must not burn a vendor's access.
    """
    settings = _settings(request)
    if not TOKEN_RE.match(token):
        return _neutral(request)

    async with request.app.state.sessionmaker() as db:
        grant = await grant_by_token(db, settings, token)
        if grant is None or not link_is_openable(grant):
            await db.commit()
            return _neutral(request)

        if grant.status == GrantStatus.active.value:
            # Already signed in. The bound browser gets sent on to its pages;
            # anybody else holding the same link is refused.
            session_id, _ = read_vendor_cookie(request, settings)
            session = (
                await session_by_id(db, settings, session_id) if session_id else None
            )
            if session is not None and session.grant_id == grant.id:
                first = (grant.allowed_paths or ["/"])[0]
                await db.commit()
                return RedirectResponse(f"/s{first}", status_code=303)
            await log_event(
                db,
                type=EventType.device_refused,
                actor="vendor",
                grant=grant,
                ip=client_ip(request, settings),
                user_agent=user_agent(request),
                detail="link opened from another device after sign-in",
            )
            await db.commit()
            return _neutral(request)

        await log_event(
            db,
            type=EventType.link_viewed,
            actor="vendor",
            grant=grant,
            ip=client_ip(request, settings),
            user_agent=user_agent(request),
            detail="login page shown (link not consumed)",
        )
        await db.commit()

    return _templates(request).TemplateResponse(
        request, "vendor/login.html", {"token": token, "error": None, "email": ""}
    )


@router.post("/{token}/login")
async def link_login(
    request: Request,
    token: str,
    email: str = Form(default=""),
    password: str = Form(default=""),
) -> Response:
    settings = _settings(request)
    if not TOKEN_RE.match(token):
        return _neutral(request)

    ip = client_ip(request, settings)
    limiter = request.app.state.vendor_limiter
    if not limiter.check(ip):
        async with request.app.state.sessionmaker() as db:
            await log_event(
                db,
                type=EventType.rate_limited,
                actor="vendor",
                ip=ip,
                user_agent=user_agent(request),
                detail="too many vendor sign-in attempts from this address",
            )
            await db.commit()
        return _templates(request).TemplateResponse(
            request,
            "vendor/login.html",
            {
                "token": token,
                "email": email,
                "error": "Too many attempts. Wait a minute and try again.",
            },
            status_code=429,
            headers={"Retry-After": str(limiter.retry_after(ip))},
        )

    async with request.app.state.sessionmaker() as db:
        grant = await grant_by_token(db, settings, token)
        if grant is None or not link_is_openable(grant):
            await db.commit()
            return _neutral(request)

        if grant.status == GrantStatus.active.value:
            # Someone else holding the same link, after it was signed in on
            # another browser.  No form, no error detail: the neutral page.
            await log_event(
                db,
                type=EventType.device_refused,
                actor="vendor",
                grant=grant,
                ip=ip,
                user_agent=user_agent(request),
                detail="sign-in attempted after the link was already used",
            )
            await db.commit()
            return _neutral(request)

        try:
            result = await attempt_login(
                db,
                settings,
                grant=grant,
                email=email,
                password=password,
                ip=ip,
                user_agent=user_agent(request),
            )
        except GrantError as exc:
            await db.commit()
            return _templates(request).TemplateResponse(
                request,
                "vendor/login.html",
                {"token": token, "email": email, "error": str(exc)},
                status_code=401,
            )

        first_page = (result.grant.allowed_paths or ["/"])[0]
        session_id = result.session_id
        grant_public_id = result.grant.public_id
        await db.commit()

    # Off the token URL immediately, so it never reaches a log or a Referer
    # header from here on (section 6.6).
    response = RedirectResponse(f"/s{first_page}", status_code=303)
    set_vendor_cookie(response, settings, session_id, grant_public_id)
    return response
