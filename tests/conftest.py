"""Shared fixtures.

Each test gets its own SQLite file, its own settings, and a gateway whose
upstream is the mock internal site mounted in-process over ASGI, so no sockets
are needed except in the explicitly marked integration tests.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

import httpx
import pyotp
import pytest
from fastapi.testclient import TestClient

from mocksite.app import create_app as create_mocksite
from scopegate.app import create_app
from scopegate.config import Settings
from scopegate.db import create_all, dispose_engine, init_engine, session_scope
from scopegate.models import Admin, utcnow
from scopegate.security import (
    encrypt_totp_secret,
    generate_totp_enc_key,
    generate_totp_secret,
    hash_password,
)

UPSTREAM = "http://internal.test"
ADMIN_EMAIL = "admin@company.example"
ADMIN_PASSWORD = "AdminPassw0rd!2026"
VENDOR_EMAIL = "vendor@partner.example"

ALLOWED_PAGES = ["/dashboard/overview", "/dashboard/reports", "/dashboard/tickets"]


@dataclass
class AdminCreds:
    email: str
    password: str
    totp_secret: str

    def code(self) -> str:
        return pyotp.TOTP(self.totp_secret).now()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    db_path = (tmp_path / "scopegate.db").as_posix()
    return Settings(
        public_url="http://testserver",
        database_url=f"sqlite+aiosqlite:///{db_path}",
        secret_key="test-secret-key-not-for-real-use-0123456789",
        totp_enc_key=generate_totp_enc_key(),
        link_ttl_minutes=180,
        max_access_minutes=480,
        expiry_tick_seconds=1,
        max_login_attempts=5,
        vendor_password_length=16,
        login_rate_per_minute=50,
        admin_idle_timeout_minutes=20,
        admin_rate_per_minute=50,
        upstream_url=UPSTREAM,
        allowed_pages=list(ALLOWED_PAGES),
        allowed_methods=["GET", "HEAD"],
        max_request_bytes=1_048_576,
        upstream_timeout_seconds=10,
        inject_banner=True,
        log_dashboard_days=7,
        log_retention_days=365,
        mail_backend="file",
        mail_outbox_dir=(tmp_path / "outbox").as_posix(),
        mail_from="gateway@company.example",
        secure_cookies=False,
        trust_forwarded_for=False,
    )


@pytest.fixture
def admin_creds(settings: Settings) -> AdminCreds:
    """Create the tables and one admin account before the app starts."""
    secret = generate_totp_secret()

    async def seed() -> None:
        init_engine(settings)
        try:
            await create_all()
            async with session_scope() as db:
                db.add(
                    Admin(
                        email=ADMIN_EMAIL,
                        password_hash=hash_password(ADMIN_PASSWORD),
                        totp_secret_enc=encrypt_totp_secret(settings.totp_enc_key, secret),
                        created_at=utcnow(),
                    )
                )
        finally:
            await dispose_engine()

    asyncio.run(seed())
    return AdminCreds(email=ADMIN_EMAIL, password=ADMIN_PASSWORD, totp_secret=secret)


@pytest.fixture
def upstream_client() -> httpx.AsyncClient:
    """The mock internal site, reachable only through this in-process client."""
    mock = create_mocksite(self_url=UPSTREAM)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock),
        base_url=UPSTREAM,
        follow_redirects=False,
    )


@pytest.fixture
def app(settings: Settings, admin_creds: AdminCreds, upstream_client: httpx.AsyncClient):
    return create_app(settings, upstream_client=upstream_client, start_worker=False)


@pytest.fixture
def client(app):
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client


@pytest.fixture
def other_device(app, client):
    """A second browser against the same running app.

    Deliberately not a context manager: entering a second TestClient would run
    the app's lifespan again and, on exit, dispose the engine the first client
    is still using.
    """

    def _make(user_agent: str = "Mozilla/5.0 (SecondDevice)") -> TestClient:
        return TestClient(
            app, base_url="http://testserver", headers={"User-Agent": user_agent}
        )

    return _make


@pytest.fixture
def admin(client, admin_creds: AdminCreds):
    """A signed-in admin client, plus the CSRF token for its session."""
    response = client.post(
        "/admin/login",
        data={
            "email": admin_creds.email,
            "password": admin_creds.password,
            "totp": admin_creds.code(),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    store = client.app.state.admin_sessions
    session = next(iter(store._sessions.values()))
    return session


@dataclass
class IssuedGrant:
    public_id: str
    vendor_email: str
    link: str
    token: str
    password: str


@pytest.fixture
def issue_grant(client, admin):
    """Create a grant through the admin UI and hand back its secrets."""

    def _issue(
        *,
        vendor_email: str = VENDOR_EMAIL,
        duration_minutes: int = 60,
        pages: list[str] | None = None,
    ) -> IssuedGrant:
        response = client.post(
            "/admin/grants",
            data={
                "csrf": admin.csrf_token,
                "vendor_email": vendor_email,
                "duration_minutes": str(duration_minutes),
                "master_password": ADMIN_PASSWORD,
                "allowed_paths": pages if pages is not None else ALLOWED_PAGES[:2],
            },
            follow_redirects=False,
        )
        assert response.status_code == 303, response.text
        flash = admin.flash or {}
        issued = flash.get("issued")
        assert issued, f"no grant was issued: {flash}"
        return IssuedGrant(
            public_id=issued["public_id"],
            vendor_email=issued["vendor_email"],
            link=issued["link"],
            token=issued["link"].rsplit("/", 1)[-1],
            password=issued["password"],
        )

    return _issue


@pytest.fixture
def vendor_in(client, issue_grant):
    """Issue a grant and sign the vendor in, returning the issued grant."""

    def _login(**kwargs) -> IssuedGrant:
        grant = issue_grant(**kwargs)
        response = client.post(
            f"/{grant.token}/login",
            data={"email": grant.vendor_email, "password": grant.password},
            follow_redirects=False,
        )
        assert response.status_code == 303, response.text
        return grant

    return _login


