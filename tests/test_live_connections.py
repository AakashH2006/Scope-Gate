"""Cutting connections that are already open (section 6.5).

These tests need real sockets.  The websocket proxy reaches upstream with the
``websockets`` client, which speaks TCP rather than ASGI; and a streamed
download can only be observed being cut mid-flight over a real connection,
because ``TestClient`` buffers a response body before handing it back.

So: the mock internal site always runs under uvicorn here, and the streaming
test runs the gateway under uvicorn too.
"""
from __future__ import annotations

import asyncio
import socket
import threading
import time
from dataclasses import replace

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from mocksite.app import create_app as create_mocksite
from tests.conftest import ADMIN_PASSWORD
from vendorgate.app import create_app

pytestmark = pytest.mark.integration

PAGES = ["/dashboard/overview", "/dashboard/reports"]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class ThreadedServer:
    """An ASGI app under uvicorn on a loopback port, in a background thread."""

    def __init__(self, app, port: int | None = None) -> None:
        self.port = port or _free_port()
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=self.port,
                log_level="error",
                access_log=False,
                server_header=False,
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "ThreadedServer":
        self.thread.start()
        deadline = time.monotonic() + 20
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError(f"server on port {self.port} did not start")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=15)


# --------------------------------------------------------------------------- #
# shared sign-in flow, usable with any http client
# --------------------------------------------------------------------------- #

def sign_in_everything(client, app, admin_creds, pages=PAGES, duration_minutes=60):
    """Admin signs in, issues a grant, vendor signs in.

    Returns ``(admin_session, grant_public_id)``.  The admin session object is
    read straight from the app, which is in this process either way, because the
    CSRF token is not exposed anywhere else.
    """
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

    admin_session = next(iter(app.state.admin_sessions._sessions.values()))
    created = client.post(
        "/admin/grants",
        data={
            "csrf": admin_session.csrf_token,
            "vendor_email": "vendor@partner.example",
            "duration_minutes": str(duration_minutes),
            "master_password": ADMIN_PASSWORD,
            "allowed_paths": pages,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text
    issued = (admin_session.flash or {})["issued"]
    token = issued["link"].rsplit("/", 1)[-1]

    login = client.post(
        f"/{token}/login",
        data={"email": issued["vendor_email"], "password": issued["password"]},
        follow_redirects=False,
    )
    assert login.status_code == 303, login.text
    return admin_session, issued["public_id"]


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def live_site():
    port = _free_port()
    with ThreadedServer(create_mocksite(self_url=f'http://127.0.0.1:{port}'), port) as server:
        yield server


@pytest.fixture
def live_app(settings, admin_creds, live_site):
    return create_app(
        replace(settings, upstream_url=live_site.url), start_worker=False
    )


@pytest.fixture
def live_client(live_app):
    """Gateway in-process (real upstream socket), good for websockets."""
    with TestClient(live_app, base_url="http://testserver") as client:
        yield client


@pytest.fixture
def signed_in(live_client, live_app, admin_creds):
    return sign_in_everything(live_client, live_app, admin_creds)


@pytest.fixture
def served_gateway(settings, admin_creds, live_site):
    """Gateway under uvicorn, reached over a real socket by a real httpx client."""
    app = create_app(
        replace(
            settings,
            upstream_url=live_site.url,
            public_url=f"http://127.0.0.1:{_free_port()}",
        ),
        start_worker=False,
    )
    with ThreadedServer(app) as server:
        with httpx.Client(base_url=server.url, timeout=30) as client:
            yield client, app


# --------------------------------------------------------------------------- #
# plain proxying over a real socket
# --------------------------------------------------------------------------- #

def test_a_page_loads_through_a_real_socket(live_client, signed_in, live_site):
    response = live_client.get("/s/dashboard/overview")
    assert response.status_code == 200
    assert "Acme Internal" in response.text
    # Neither the upstream address nor its server banner survives the hop.
    assert "127.0.0.1" not in response.text
    assert str(live_site.port) not in response.text
    assert "server" not in {k.lower() for k in response.headers}


# --------------------------------------------------------------------------- #
# websockets
# --------------------------------------------------------------------------- #

def test_websocket_is_proxied_and_cut_when_access_is_revoked(live_client, signed_in):
    admin_session, public_id = signed_in

    with live_client.websocket_connect("/s/dashboard/overview/ws") as ws:
        assert ws.receive_text().startswith("tick 1")

        revoked = live_client.post(
            f"/admin/grants/{public_id}/revoke",
            data={"csrf": admin_session.csrf_token},
            follow_redirects=False,
        )
        assert revoked.status_code == 303

        # The socket was already open, so only the kill switch can end it.
        with pytest.raises(WebSocketDisconnect):
            for _ in range(20):
                ws.receive_text()


def test_expiry_also_cuts_a_live_websocket(live_client, live_app, signed_in):
    from datetime import timedelta

    from sqlalchemy import select

    from vendorgate.db import session_scope
    from vendorgate.grants import sweep_expired
    from vendorgate.models import Grant

    _, public_id = signed_in

    async def expire_now():
        async with session_scope() as db:
            grant = (
                await db.execute(select(Grant).where(Grant.public_id == public_id))
            ).scalar_one()
            grant.access_expires_at = grant.access_expires_at - timedelta(hours=2)
        async with session_scope() as db:
            return await sweep_expired(db, live=live_app.state.live)

    with live_client.websocket_connect("/s/dashboard/overview/ws") as ws:
        assert ws.receive_text().startswith("tick 1")
        assert asyncio.run(expire_now()).expired == 1
        with pytest.raises(WebSocketDisconnect):
            for _ in range(20):
                ws.receive_text()


def test_websocket_on_a_page_outside_the_grant_is_refused(live_client, signed_in):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with live_client.websocket_connect("/s/dashboard/finance/ws") as ws:
            ws.receive_text()
    assert excinfo.value.code == 4403


def test_websocket_without_a_session_is_refused(live_client, signed_in):
    live_client.cookies.clear()
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with live_client.websocket_connect("/s/dashboard/overview/ws") as ws:
            ws.receive_text()
    assert excinfo.value.code == 4401


# --------------------------------------------------------------------------- #
# streamed downloads
# --------------------------------------------------------------------------- #

def test_a_streamed_download_is_cut_when_access_is_revoked(served_gateway, admin_creds):
    client, app = served_gateway
    admin_session, public_id = sign_in_everything(client, app, admin_creds)

    revoke_sent = False
    chunks: list[bytes] = []
    with client.stream("GET", "/s/dashboard/reports/export.csv") as response:
        assert response.status_code == 200
        for chunk in response.iter_bytes():
            chunks.append(chunk)
            if not revoke_sent and b"5,service-005" in b"".join(chunks):
                # A second client, so the stream's own connection is untouched.
                with httpx.Client(base_url=str(client.base_url), timeout=30) as admin:
                    admin.cookies.update(client.cookies)
                    assert (
                        admin.post(
                            f"/admin/grants/{public_id}/revoke",
                            data={"csrf": admin_session.csrf_token},
                            follow_redirects=False,
                        ).status_code
                        == 303
                    )
                revoke_sent = True
            if len(b"".join(chunks)) > 100_000:
                pytest.fail("the stream was never cut")

    body = b"".join(chunks)
    assert revoke_sent
    assert body.startswith(b"row,service,uptime")
    # The file is 199 rows and takes ~10s; the cut must land long before the end.
    assert b"199,service-199" not in body

    # And the next request is refused outright.
    assert client.get("/s/dashboard/overview").status_code == 403


def test_a_normal_page_is_unaffected_by_the_kill_switch(served_gateway, admin_creds):
    client, app = served_gateway
    sign_in_everything(client, app, admin_creds)
    for _ in range(3):
        assert client.get("/s/dashboard/overview").status_code == 200
    assert app.state.live.count() == 0
