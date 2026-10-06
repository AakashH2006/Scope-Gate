"""A small stand-in for a real internal web application (section 12).

It exists to be proxied, so it deliberately does the awkward things a real
internal app does:

* links pages with **absolute** URLs as well as root-relative ones, so the
  gateway's rewriting has something to chew on
* sets a cookie, which must never reach the vendor's browser
* returns ``Server`` and ``X-Internal-Host`` headers, which must be stripped
* has pages the vendor is **not** allowed to see
* has a redirect and a websocket, to exercise those paths

It must listen on a private address only.  Nothing here is security-relevant;
the gateway in front of it is.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse

SELF_URL = os.getenv("MOCKSITE_SELF_URL", "http://127.0.0.1:9000")

ALLOWED_DEMO_PAGES = [
    ("/dashboard/overview", "Overview"),
    ("/dashboard/reports", "Reports"),
    ("/dashboard/tickets", "Tickets"),
]
LOCKED_DEMO_PAGES = [
    ("/dashboard/finance", "Finance"),
    ("/dashboard/users", "Users"),
    ("/dashboard/settings", "Settings"),
]

PAGE_CSS = """
:root { color-scheme: light dark; }
body { font: 15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif;
       margin: 0; background: Canvas; color: CanvasText; }
.top { background: #22303f; color: #eef2f7; padding: 12px 20px; display: flex;
       align-items: center; gap: 18px; }
.top b { letter-spacing: -.01em; }
.top a { color: #c9d6e4; text-decoration: none; font-size: 14px; }
.top a:hover { color: #fff; text-decoration: underline; }
main { max-width: 860px; margin: 0 auto; padding: 24px 18px 60px; }
h1 { font-size: 21px; margin: 0 0 6px; }
.sub { color: #70798a; margin: 0 0 22px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #0001; }
th { font-size: 11.5px; text-transform: uppercase; letter-spacing: .05em; color: #70798a; }
.box { border: 1px solid #0002; border-radius: 8px; padding: 16px; margin: 18px 0; }
.locked { color: #b3261e; }
code { font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
"""


def _chrome(active: str) -> str:
    links = []
    for path, label in ALLOWED_DEMO_PAGES:
        # Root-relative links: the gateway must prefix these with /s.
        mark = ' style="color:#fff;font-weight:600"' if path == active else ""
        links.append(f'<a href="{path}"{mark}>{label}</a>')
    for path, label in LOCKED_DEMO_PAGES:
        # Absolute links to the internal host: the gateway must rewrite the
        # host away, and then block the page itself.
        links.append(f'<a href="{SELF_URL}{path}">{label}</a>')
    return (
        '<div class="top"><b>Acme Internal</b>'
        + "".join(links)
        + '<span style="margin-left:auto;font-size:12px;color:#8ea0b4">'
        "internal use only</span></div>"
    )


def _page(title: str, active: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{title} &middot; Acme Internal</title>"
        f"<style>{PAGE_CSS}</style></head><body>"
        f"{_chrome(active)}<main>{body}</main></body></html>"
    )


def create_app() -> FastAPI:
    app = FastAPI(title="Acme Internal (mock)", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def internal_fingerprints(request: Request, call_next):
        """Add exactly the headers and cookies a real internal app would, so the
        gateway can be seen stripping them."""
        response = await call_next(request)
        response.headers["Server"] = "internal-nginx/1.21.6"
        response.headers["X-Internal-Host"] = "app01.corp.internal"
        response.headers["X-Powered-By"] = "Acme Platform 4.2"
        response.set_cookie("acme_session", "internal-session-value", path="/")
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index() -> Response:
        return RedirectResponse("/dashboard/overview", status_code=302)

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard_root() -> Response:
        # An absolute redirect to itself: the gateway must rewrite Location.
        return RedirectResponse(f"{SELF_URL}/dashboard/overview", status_code=302)

    @app.get("/dashboard/overview", response_class=HTMLResponse)
    async def overview() -> HTMLResponse:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        body = f"""
        <h1>Overview</h1>
        <p class="sub">Service health at {now}</p>
        <div class="box">
          <table>
            <tr><th>Service</th><th>State</th><th>Last check</th></tr>
            <tr><td>Billing API</td><td>healthy</td><td>2 min ago</td></tr>
            <tr><td>Document store</td><td>healthy</td><td>1 min ago</td></tr>
            <tr><td>Mail relay</td><td>degraded</td><td>4 min ago</td></tr>
            <tr><td>Batch runner</td><td>healthy</td><td>just now</td></tr>
          </table>
        </div>
        <div class="box">
          <h2 style="font-size:15px;margin:0 0 8px">Live ticker</h2>
          <p class="sub" style="margin:0 0 8px">
            A websocket, so the gateway can be seen cutting it when access ends.</p>
          <code id="tick">connecting&hellip;</code>
          <script>
          (function(){{
            var proto = location.protocol === 'https:' ? 'wss' : 'ws';
            var ws = new WebSocket(proto + '://' + location.host +
                                   location.pathname.replace(/\\/$/, '') + '/ws');
            var el = document.getElementById('tick');
            ws.onmessage = function(e) {{ el.textContent = e.data; }};
            ws.onclose = function() {{ el.textContent = 'ticker closed'; }};
            ws.onerror = function() {{ el.textContent = 'ticker unavailable'; }};
          }})();
          </script>
        </div>
        <p class="sub">Try <a href="/dashboard/finance">Finance</a> &mdash; it is not
        part of a vendor grant and the gateway should refuse it.</p>
        """
        return HTMLResponse(_page("Overview", "/dashboard/overview", body))

    @app.websocket("/dashboard/overview/ws")
    async def ticker(websocket: WebSocket) -> None:
        await websocket.accept()
        count = 0
        try:
            while True:
                count += 1
                stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
                await websocket.send_text(f"tick {count} at {stamp} UTC")
                await asyncio.sleep(1)
        except (WebSocketDisconnect, RuntimeError):
            return

    @app.get("/dashboard/reports", response_class=HTMLResponse)
    async def reports() -> HTMLResponse:
        rows = "".join(
            f"<tr><td>{name}</td><td>{period}</td><td>{size}</td></tr>"
            for name, period, size in [
                ("Uptime summary", "September 2026", "412 KB"),
                ("Incident review", "Q3 2026", "1.1 MB"),
                ("Capacity forecast", "2027", "860 KB"),
                ("Vendor SLA report", "September 2026", "230 KB"),
            ]
        )
        body = f"""
        <h1>Reports</h1>
        <p class="sub">Generated nightly. Read-only for vendor accounts.</p>
        <div class="box"><table>
          <tr><th>Report</th><th>Period</th><th>Size</th></tr>{rows}
        </table></div>
        <p class="sub">Need the raw numbers? That lives in
        <a href="{SELF_URL}/dashboard/finance">Finance</a>, which vendors cannot open.</p>
        """
        return HTMLResponse(_page("Reports", "/dashboard/reports", body))

    @app.get("/dashboard/reports/export.csv")
    async def export_csv() -> Response:
        """A slow, streamed, non-HTML download.

        It is here so the gateway can be seen cutting a transfer that is already
        in flight when access ends -- a plain page would have finished first.
        """

        async def rows():
            yield b"row,service,uptime\n"
            for i in range(1, 200):
                yield f"{i},service-{i:03d},99.9\n".encode()
                await asyncio.sleep(0.05)

        return StreamingResponse(rows(), media_type="text/csv")

    @app.get("/dashboard/tickets", response_class=HTMLResponse)
    async def tickets() -> HTMLResponse:
        rows = "".join(
            f"<tr><td><code>{ref}</code></td><td>{subject}</td><td>{state}</td></tr>"
            for ref, subject, state in [
                ("INC-4411", "Mail relay queue backing up", "open"),
                ("INC-4408", "Nightly batch slower than usual", "investigating"),
                ("REQ-2291", "Add read-only access for auditor", "done"),
                ("INC-4399", "Certificate renewal warning", "closed"),
            ]
        )
        body = f"""
        <h1>Tickets</h1>
        <p class="sub">Open and recent items.</p>
        <div class="box"><table>
          <tr><th>Ref</th><th>Subject</th><th>State</th></tr>{rows}
        </table></div>
        <div class="box">
          <p style="margin:0 0 8px">Comment on a ticket:</p>
          <form method="post" action="/dashboard/tickets/comment">
            <input name="text" placeholder="A write, which the gateway blocks"
                   style="padding:7px;width:60%">
            <button style="padding:7px 12px">Post</button>
          </form>
          <p class="sub" style="margin:8px 0 0">The gateway allows GET and HEAD only,
          so this POST should be refused before it ever reaches this app.</p>
        </div>
        """
        return HTMLResponse(_page("Tickets", "/dashboard/tickets", body))

    @app.post("/dashboard/tickets/comment", response_class=HTMLResponse)
    async def ticket_comment() -> HTMLResponse:
        # Reachable from inside the network; a vendor's POST never gets here.
        return HTMLResponse(
            _page("Tickets", "/dashboard/tickets", "<h1>Comment saved</h1>")
        )

    def _locked(title: str, path: str, blurb: str):
        async def view() -> HTMLResponse:
            body = f"""
            <h1 class="locked">{title}</h1>
            <p class="sub">{blurb}</p>
            <div class="box">
              <p style="margin:0">If a vendor is reading this page, the gateway
              failed. It should never be forwarded.</p>
            </div>
            """
            return HTMLResponse(_page(title, path, body))

        return view

    app.get("/dashboard/finance", response_class=HTMLResponse)(
        _locked("Finance", "/dashboard/finance", "Invoices, margins and payroll totals.")
    )
    app.get("/dashboard/users", response_class=HTMLResponse)(
        _locked("Users", "/dashboard/users", "Staff accounts and permissions.")
    )
    app.get("/dashboard/settings", response_class=HTMLResponse)(
        _locked("Settings", "/dashboard/settings", "Integration keys and system configuration.")
    )

    @app.get("/healthz")
    async def healthz() -> Response:
        return Response("ok", media_type="text/plain")

    return app


app = create_app()


def main() -> None:
    import uvicorn

    host = os.getenv("MOCKSITE_HOST", "127.0.0.1")
    port = int(os.getenv("MOCKSITE_PORT", "9000"))
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"WARNING: the mock internal site is binding to {host}. It is meant to be "
            "reachable only through the gateway.",
        )
    uvicorn.run(app, host=host, port=port, access_log=False)


if __name__ == "__main__":
    main()
