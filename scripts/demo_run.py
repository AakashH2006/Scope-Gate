"""Drive the demo script from section 12 of the plan, end to end, headlessly.

    python scripts/demo_run.py

It starts a throwaway gateway and mock site on loopback ports, creates an admin,
and walks all ten steps over real HTTP, printing a pass/fail line for each. This
is build-plan step 11: the end-to-end run, in a form that can be repeated before
a pitch without clicking through a browser.

Nothing here touches an existing database: it uses a temporary directory and
deletes it on the way out.
"""
from __future__ import annotations

import asyncio
import socket
import sys
import tempfile
import threading
import time
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
import pyotp  # noqa: E402
import uvicorn  # noqa: E402
from sqlalchemy import select  # noqa: E402

from mocksite.app import create_app as create_mocksite  # noqa: E402
from scopegate.app import create_app  # noqa: E402
from scopegate.config import Settings  # noqa: E402
from scopegate.db import create_all, dispose_engine, init_engine, session_scope  # noqa: E402
from scopegate.grants import sweep_expired  # noqa: E402
from scopegate.models import Admin, Event, Grant, utcnow  # noqa: E402
from scopegate.security import (  # noqa: E402
    encrypt_totp_secret,
    generate_totp_enc_key,
    generate_totp_secret,
    hash_password,
)

ADMIN_EMAIL = "admin@company.example"
ADMIN_PASSWORD = "DemoAdminPassw0rd!"
PAGES = ["/dashboard/overview", "/dashboard/reports", "/dashboard/tickets"]

PASS, FAIL = "  PASS", "  FAIL"
_results: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> bool:
    _results.append((ok, label))
    print(f"{PASS if ok else FAIL}  {label}")
    return ok


def step(number: int, title: str) -> None:
    print(f"\n{number:>2}. {title}")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Server:
    def __init__(self, app, port: int) -> None:
        self.port = port
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                log_level="error",
                access_log=False,
                server_header=False,
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 20
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError(f"server on {self.port} did not start")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=15)


def build_settings(tmp: Path, *, upstream: str, gateway_port: int) -> tuple[Settings, str]:
    secret = generate_totp_secret()
    settings = Settings(
        public_url=f"http://127.0.0.1:{gateway_port}",
        database_url=f"sqlite+aiosqlite:///{(tmp / 'demo.db').as_posix()}",
        secret_key="demo-run-secret-key-0123456789abcdef",
        totp_enc_key=generate_totp_enc_key(),
        link_ttl_minutes=180,
        max_access_minutes=480,
        expiry_tick_seconds=1,
        max_login_attempts=5,
        upstream_url=upstream,
        allowed_pages=list(PAGES),
        allowed_methods=["GET", "HEAD"],
        mail_backend="file",
        mail_outbox_dir=(tmp / "outbox").as_posix(),
        mail_from="gateway@company.example",
        secure_cookies=False,
        trust_forwarded_for=False,
    )

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
    return settings, secret


# --------------------------------------------------------------------------- #
# helpers that read the database the gateway is using
# --------------------------------------------------------------------------- #

async def _grant_status(public_id: str) -> str:
    async with session_scope() as db:
        grant = (
            await db.execute(select(Grant).where(Grant.public_id == public_id))
        ).scalar_one()
        return grant.status


async def _event_types(public_id: str) -> list[str]:
    async with session_scope() as db:
        rows = (
            await db.execute(
                select(Event).where(Event.grant_public_id == public_id).order_by(Event.id)
            )
        ).scalars().all()
        return [r.type for r in rows]


async def _wind_clock_back(public_id: str, **delta) -> None:
    async with session_scope() as db:
        grant = (
            await db.execute(select(Grant).where(Grant.public_id == public_id))
        ).scalar_one()
        shift = timedelta(**delta)
        if grant.access_expires_at is not None:
            grant.access_expires_at = grant.access_expires_at - shift
        grant.link_expires_at = grant.link_expires_at - shift


async def _sweep(live) -> object:
    async with session_scope() as db:
        return await sweep_expired(db, live=live)


# --------------------------------------------------------------------------- #

def issue(admin_client: httpx.Client, app, csrf: str, **form) -> dict:
    payload = {
        "csrf": csrf,
        "vendor_email": form.get("vendor_email", "vendor@partner.example"),
        "duration_minutes": str(form.get("duration_minutes", 10)),
        "master_password": ADMIN_PASSWORD,
        "allowed_paths": form.get("pages", PAGES),
    }
    response = admin_client.post("/admin/grants", data=payload, follow_redirects=False)
    assert response.status_code == 303, response.text
    session = next(iter(app.state.admin_sessions._sessions.values()))
    return (session.flash or {})["issued"]


def run() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="scopegate-demo-"))
    mock_port, gateway_port = free_port(), free_port()
    settings, totp_secret = build_settings(
        tmp, upstream=f"http://127.0.0.1:{mock_port}", gateway_port=gateway_port
    )
    app = create_app(settings, start_worker=False)

    print("ScopeGate demo run")
    print(f"  gateway        http://127.0.0.1:{gateway_port}")
    print(f"  internal site  http://127.0.0.1:{mock_port}  (private)")
    print(f"  scratch        {tmp}")

    with Server(create_mocksite(self_url=f'http://127.0.0.1:{mock_port}'), mock_port), Server(app, gateway_port) as gw:
        base = gw.url
        admin = httpx.Client(base_url=base, timeout=30)
        vendor = httpx.Client(base_url=base, timeout=30)

        # 1 -----------------------------------------------------------------
        step(1, "Admin signs in with password + authenticator code")
        no_code = admin.post(
            "/admin/login",
            data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "totp": ""},
            follow_redirects=False,
        )
        check(no_code.status_code == 401, "sign-in without a TOTP code is refused")
        signed_in = admin.post(
            "/admin/login",
            data={
                "email": ADMIN_EMAIL,
                "password": ADMIN_PASSWORD,
                "totp": pyotp.TOTP(totp_secret).now(),
            },
            follow_redirects=False,
        )
        check(signed_in.status_code == 303, "sign-in with the code succeeds")
        session = next(iter(app.state.admin_sessions._sessions.values()))
        csrf = session.csrf_token
        check(admin.get("/admin").status_code == 200, "dashboard loads")

        # 2 -----------------------------------------------------------------
        step(2, "Admin creates a grant: 10 minutes, three allowed pages")
        refused = admin.post(
            "/admin/grants",
            data={
                "csrf": csrf,
                "vendor_email": "vendor@partner.example",
                "duration_minutes": "10",
                "master_password": "wrong-password",
                "allowed_paths": PAGES,
            },
            follow_redirects=False,
        )
        check(
            refused.status_code == 303 and "not correct" in (session.flash or {}).get("error", ""),
            "a grant without the master password is refused",
        )
        issued = issue(admin, app, csrf, duration_minutes=10, pages=PAGES)
        token = issued["link"].rsplit("/", 1)[-1]
        check(len(token) == 43, f"link token is {len(token)} random characters")
        check(
            asyncio.run(_grant_status(issued["public_id"])) == "pending",
            "grant starts in pending",
        )

        # 3 -----------------------------------------------------------------
        step(3, "The vendor email arrives with the link and password")
        import email as email_mod

        outbox = sorted(Path(settings.mail_outbox_dir).glob("*.eml"))
        body = ""
        if outbox:
            body = (
                email_mod.message_from_string(outbox[-1].read_text(encoding="utf-8"))
                .get_payload(decode=True)
                .decode("utf-8")
            )
        check(bool(outbox), f"invite written to {settings.mail_outbox_dir}/")
        check(issued["link"] in body and issued["password"] in body, "link and password in the mail")
        check("email_sent" in asyncio.run(_event_types(issued["public_id"])), "email_sent logged")

        # 4 -----------------------------------------------------------------
        step(4, "Vendor opens the link and signs in; the countdown starts")
        scanner = httpx.Client(base_url=base, timeout=30)
        for _ in range(2):
            scanner.get(f"/{token}")
        check(
            asyncio.run(_grant_status(issued["public_id"])) == "pending",
            "a scanner opening the link does not consume it",
        )
        wrong = vendor.post(
            f"/{token}/login",
            data={"email": issued["vendor_email"], "password": "not-it"},
        )
        check(
            wrong.status_code == 401 and "incorrect" in wrong.text,
            "a wrong password gives a generic error",
        )
        login = vendor.post(
            f"/{token}/login",
            data={"email": issued["vendor_email"], "password": issued["password"]},
            follow_redirects=False,
        )
        check(login.status_code == 303, "sign-in succeeds")
        check(
            login.headers.get("location") == f"/s{PAGES[0]}",
            "vendor is moved off the token URL to /s/",
        )
        check(
            asyncio.run(_grant_status(issued["public_id"])) == "active",
            "access clock started at sign-in, not at email send",
        )
        status = vendor.get("/s/_status")
        left = status.json()["seconds_left"]
        check(9 * 60 <= left <= 10 * 60, f"countdown reports {left}s left of 600s")

        # 5 -----------------------------------------------------------------
        step(5, "Vendor browses the allowed pages")
        page = None
        for path in PAGES:
            page = vendor.get(f"/s{path}")
            if not check(page.status_code == 200, f"{path} loads"):
                break
        if page is not None:
            check("Acme Internal" in page.text, "the internal page really rendered")
            check(
                f"127.0.0.1:{mock_port}" not in page.text,
                "no internal address leaks into the page",
            )
            check(
                "server" not in {k.lower() for k in page.headers}
                and "set-cookie" not in {k.lower() for k in page.headers},
                "no internal server banner or cookie reaches the vendor",
            )
            check('href="/s/dashboard/reports"' in page.text, "links rewritten to stay inside")
            check('id="sg-bar"' in page.text, "countdown banner injected")

        # 6 -----------------------------------------------------------------
        step(6, "Vendor tries a locked page -> blocked and logged")
        blocked = vendor.get("/s/dashboard/finance")
        check(blocked.status_code == 403, "/dashboard/finance is refused")
        check("Invoices" not in blocked.text, "none of the locked page is shown")
        traversal = vendor.get("/s/dashboard/overview/../finance")
        check(traversal.status_code in (403, 404), "path traversal does not get around it")
        write = vendor.post(f"/s{PAGES[2]}/comment", data={"text": "x"})
        check(write.status_code == 405, "a POST is refused (read-only grant)")
        check(
            asyncio.run(_event_types(issued["public_id"])).count("page_blocked") >= 3,
            "every refusal is in the audit log",
        )
        logs = admin.get("/admin/logs?type=page_blocked")
        check("page_blocked" in logs.text, "the block shows in the admin log view")

        # 7 -----------------------------------------------------------------
        step(7, "The same link on a second device -> refused")
        other = httpx.Client(base_url=base, timeout=30)
        second_get = other.get(f"/{token}")
        check(second_get.status_code == 404, "the link shows the neutral page elsewhere")
        second_login = other.post(
            f"/{token}/login",
            data={"email": issued["vendor_email"], "password": issued["password"]},
        )
        check(second_login.status_code == 404, "and cannot be signed in a second time")
        check(
            "device_refused" in asyncio.run(_event_types(issued["public_id"])),
            "device_refused logged",
        )
        check(vendor.get(f"/s{PAGES[0]}").status_code == 200, "the first browser still works")

        # 8 -----------------------------------------------------------------
        step(8, "Admin revokes -> vendor is out on the next click")
        revoked = admin.post(
            f"/admin/grants/{issued['public_id']}/revoke",
            data={"csrf": csrf},
            follow_redirects=False,
        )
        check(revoked.status_code == 303, "revoke accepted")
        after = vendor.get(f"/s{PAGES[0]}")
        check(after.status_code == 403, "the very next request is refused")
        check("withdrawn" in after.text, "the vendor is told the access was withdrawn")
        check(
            asyncio.run(_grant_status(issued["public_id"])) == "revoked",
            "grant is revoked and final",
        )

        # 9 -----------------------------------------------------------------
        step(9, "A second grant is left to run out -> automatic logout")
        second = issue(
            admin, app, csrf, vendor_email="second@partner.example", duration_minutes=5,
            pages=[PAGES[0]],
        )
        second_token = second["link"].rsplit("/", 1)[-1]
        runner = httpx.Client(base_url=base, timeout=30)
        runner.post(
            f"/{second_token}/login",
            data={"email": second["vendor_email"], "password": second["password"]},
            follow_redirects=False,
        )
        check(runner.get(f"/s{PAGES[0]}").status_code == 200, "second vendor is in")
        asyncio.run(_wind_clock_back(second["public_id"], minutes=6))
        result = asyncio.run(_sweep(app.state.live))
        check(getattr(result, "expired", 0) == 1, "the expiry job closed the finished grant")
        timed_out = runner.get(f"/s{PAGES[0]}")
        check(timed_out.status_code == 403, "the vendor is logged out automatically")
        check("ended" in timed_out.text, "and told the window ended")

        # 10 ----------------------------------------------------------------
        step(10, "A third grant is never opened -> the link dies")
        third = issue(
            admin, app, csrf, vendor_email="third@partner.example", duration_minutes=30,
            pages=[PAGES[0]],
        )
        third_token = third["link"].rsplit("/", 1)[-1]
        asyncio.run(_wind_clock_back(third["public_id"], minutes=181))
        result = asyncio.run(_sweep(app.state.live))
        check(
            getattr(result, "expired_unused", 0) == 1,
            "the unused link expired after the link window",
        )
        dead = httpx.Client(base_url=base, timeout=30)
        neutral_dead = dead.get(f"/{third_token}")
        unknown = dead.get("/" + "z" * 43)
        check(neutral_dead.status_code == 404, "the dead link shows the neutral page")
        check(
            neutral_dead.text == unknown.text,
            "a dead link and an unknown link are indistinguishable",
        )

        # closing checks ----------------------------------------------------
        step(11, "Audit log hygiene")
        async def all_events():
            async with session_scope() as db:
                rows = (await db.execute(select(Event))).scalars().all()
                return " | ".join(
                    f"{r.type} {r.detail or ''} {r.ip or ''} {r.user_agent or ''}" for r in rows
                )

        blob = asyncio.run(all_events())
        check(token not in blob, "no link token in the audit log")
        check(issued["password"] not in blob, "no vendor password in the audit log")
        check(
            (vendor.cookies.get("sg_session") or "no-cookie") not in blob,
            "no session id in the audit log",
        )

        for client in (admin, vendor, scanner, other, runner, dead):
            client.close()

    passed = sum(1 for ok, _ in _results if ok)
    failed = [label for ok, label in _results if not ok]
    print(f"\n{'-' * 64}")
    print(f"{passed}/{len(_results)} checks passed")
    if failed:
        print("\nfailed:")
        for label in failed:
            print(f"  - {label}")
    import shutil

    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())
