"""Application factory and startup wiring."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import routes_admin, routes_vendor
from .config import Settings, get_settings
from .connections import LiveConnections
from .db import create_all, dispose_engine, get_sessionmaker, init_engine
from .deps import AdminSessionStore
from .expiry import ExpiryWorker
from .mailer import Mailer
from .ratelimit import SlidingWindowLimiter
from .security import derive_fernet_key_from_secret

log = logging.getLogger("scopegate")

HERE = Path(__file__).parent


def _configure_logging() -> None:
    if logging.getLogger().handlers:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
    )


def _startup_checks(settings: Settings) -> None:
    """Refuse to run with a configuration that would be unsafe in the open."""
    problems: list[str] = []
    public_is_remote = not (
        settings.public_url.startswith("http://127.0.0.1")
        or settings.public_url.startswith("http://localhost")
    )
    import os

    if public_is_remote:
        if not os.getenv("SECRET_KEY"):
            problems.append("SECRET_KEY must be set (sessions and token hashes depend on it)")
        if not os.getenv("TOTP_ENC_KEY"):
            problems.append("TOTP_ENC_KEY must be set (admin TOTP secrets are stored encrypted)")
        if not settings.public_url.startswith("https://"):
            problems.append("PUBLIC_URL should be https:// behind Caddy")
    if problems:
        raise RuntimeError(
            "Refusing to start:\n  - " + "\n  - ".join(problems)
        )


def create_app(
    settings: Settings | None = None,
    *,
    upstream_client: httpx.AsyncClient | None = None,
    start_worker: bool = True,
    create_tables: bool = True,
    strict_startup_checks: bool | None = None,
) -> FastAPI:
    _configure_logging()
    if strict_startup_checks is None:
        strict_startup_checks = settings is None
    settings = settings or get_settings()
    if strict_startup_checks:
        _startup_checks(settings)

    if not settings.totp_enc_key:
        # Local development only: a derived key keeps TOTP working without an
        # extra env var.  _startup_checks refuses this for a public PUBLIC_URL.
        settings = replace(
            settings, totp_enc_key=derive_fernet_key_from_secret(settings.secret_key)
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_engine(settings)
        if create_tables:
            await create_all()
        app.state.sessionmaker = get_sessionmaker()
        app.state.upstream = upstream_client or httpx.AsyncClient(
            base_url=settings.upstream_url,
            timeout=httpx.Timeout(settings.upstream_timeout_seconds),
            follow_redirects=False,
        )
        app.state.worker = ExpiryWorker(settings, app.state.live)
        if start_worker:
            app.state.worker.start()
        log.info(
            "ScopeGate ready: public=%s upstream=%s pages=%s",
            settings.public_url,
            settings.upstream_url,
            ",".join(settings.allowed_pages),
        )
        try:
            yield
        finally:
            await app.state.worker.stop()
            await app.state.live.close_all()
            # Short wait on purpose: it only has to let a thread out of a retry
            # gap.  The threads are daemons, so an attempt still on the wire
            # cannot hold the process open.
            app.state.mailer.close(timeout=2.0)
            if upstream_client is None:
                await app.state.upstream.aclose()
            await dispose_engine()

    app = FastAPI(
        title="ScopeGate",
        description="Restricted vendor access gateway (demo build)",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,       # no interactive docs on an internet-facing gateway
        redoc_url=None,
        openapi_url=None,
    )

    app.state.settings = settings
    app.state.templates = Jinja2Templates(directory=str(HERE / "templates"))
    app.state.templates.env.autoescape = True
    app.state.live = LiveConnections()
    app.state.mailer = Mailer(settings)
    app.state.admin_sessions = AdminSessionStore(
        idle_timeout_seconds=settings.admin_idle_timeout_minutes * 60
    )
    app.state.admin_limiter = SlidingWindowLimiter(settings.admin_rate_per_minute)
    app.state.vendor_limiter = SlidingWindowLimiter(settings.login_rate_per_minute)

    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    @app.middleware("http")
    async def baseline_headers(request: Request, call_next):
        response = await call_next(request)
        # The proxy sets its own; these cover the gateway's own pages.
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
        if request.url.path.startswith(("/admin", "/s/")) or request.url.path == "/":
            response.headers.setdefault("Cache-Control", "no-store, max-age=0")
        return response

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Response:
        return PlainTextResponse("ok")

    @app.get("/robots.txt", include_in_schema=False)
    async def robots() -> Response:
        return PlainTextResponse("User-agent: *\nDisallow: /\n")

    @app.get("/", include_in_schema=False)
    async def root(request: Request) -> Response:
        """Nothing lives at the root: a bare visit tells a stranger nothing."""
        return HTMLResponse(
            "<!doctype html><title>Gateway</title>"
            "<p style=\"font:15px system-ui;margin:3rem\">Nothing to see here.</p>",
            status_code=404,
        )

    # Admin first, then the vendor router whose catch-all /{token} must come last.
    app.include_router(routes_admin.router)
    app.include_router(routes_vendor.router)

    return app


app_factory = create_app
