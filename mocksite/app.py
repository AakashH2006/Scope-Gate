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

#: How this app refers to itself in absolute links.  A real internal site is
#: reached at exactly the address the gateway has as UPSTREAM_URL, so tests and
#: the live demo pass that same value in -- otherwise the absolute links it
#: emits would not match what the gateway rewrites, and the test suite would
#: only ever exercise the root-relative half of the rewriting.
DEFAULT_SELF_URL = os.getenv("MOCKSITE_SELF_URL", "http://127.0.0.1:9000")

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
:root {
  --ink:#10151D; --soft:#5A6775; --dim:#8A95A3;
  --line:#E3E8EF; --bg:#F6F8FB; --card:#FFFFFF;
  --brand:#5B3DF5; --ok:#0F8A4D; --warn:#B8740A; --bad:#C2342B;
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font:15px/1.55 'Inter', system-ui, -apple-system, "Segoe UI", sans-serif;
  -webkit-font-smoothing:antialiased; }
.top { background:#141B27; color:#E8ECF2; padding:0 28px; display:flex;
  align-items:center; gap:4px; height:56px; }
.top b { font-weight:650; font-size:15px; letter-spacing:-.01em; margin-right:20px;
  display:flex; align-items:center; gap:9px; }
.top b::before { content:""; width:9px; height:9px; border-radius:2px; background:var(--brand); }
.top a { color:#9FACBD; text-decoration:none; font-size:14px; padding:7px 13px;
  border-radius:7px; }
.top a:hover { color:#fff; background:rgba(255,255,255,.07); }
main { max-width:1000px; margin:0 auto; padding:30px 28px 70px; }
.head { display:flex; align-items:flex-end; gap:16px; margin-bottom:24px; }
h1 { font-size:25px; margin:0 0 4px; letter-spacing:-.02em; font-weight:650; }
.sub { color:var(--soft); margin:0; font-size:14px; }
.spacer { flex:1; }
.stamp { font-size:12.5px; color:var(--dim); background:var(--card);
  border:1px solid var(--line); border-radius:999px; padding:5px 13px; }
.tiles { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:22px; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:11px; padding:16px 18px; }
.tile .k { font-size:11.5px; text-transform:uppercase; letter-spacing:.07em;
  color:var(--dim); font-weight:600; margin-bottom:7px; }
.tile .v { font-size:28px; font-weight:650; letter-spacing:-.02em; line-height:1; }
.tile .d { font-size:12.5px; color:var(--soft); margin-top:6px; }
.box { background:var(--card); border:1px solid var(--line); border-radius:11px;
  padding:18px 20px; margin:0 0 18px; }
.box h2 { font-size:14px; margin:0 0 14px; font-weight:650; letter-spacing:-.01em; }
table { width:100%; border-collapse:collapse; font-size:14px; }
th,td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); }
th { font-size:11px; text-transform:uppercase; letter-spacing:.07em; color:var(--dim); font-weight:600; }
tr:last-child td { border-bottom:0; }
tbody tr:hover { background:#FAFBFD; }
.pill { display:inline-block; padding:2px 9px; border-radius:999px; font-size:11.5px;
  font-weight:600; border:1px solid currentColor; }
.pill.ok { color:var(--ok); background:rgba(15,138,77,.08); }
.pill.warn { color:var(--warn); background:rgba(184,116,10,.08); }
.pill.bad { color:var(--bad); background:rgba(194,52,43,.08); }
.bars { display:flex; align-items:flex-end; gap:7px; height:88px; margin:4px 0 10px; }
.bars i { flex:1; background:linear-gradient(180deg,#7C63F7,#5B3DF5);
  border-radius:4px 4px 0 0; display:block; }
.axis { display:flex; gap:7px; font-size:11px; color:var(--dim); }
.axis span { flex:1; text-align:center; }
code { font-family:'JetBrains Mono', ui-monospace, Consolas, monospace; font-size:13px;
  background:#F0F3F8; border:1px solid var(--line); border-radius:5px; padding:2px 7px; }
.locked h1 { color:var(--bad); }
input[type=text] { padding:9px 12px; border:1px solid var(--line); border-radius:8px;
  font:inherit; background:var(--bg); }
button { padding:9px 16px; border-radius:8px; border:0; background:var(--brand);
  color:#fff; font:inherit; font-weight:600; cursor:pointer; }
"""


def _chrome(active: str, self_url: str) -> str:
    links = []
    for path, label in ALLOWED_DEMO_PAGES:
        # Root-relative links: the gateway must prefix these with /s.
        mark = ' style="color:#fff;font-weight:600"' if path == active else ""
        links.append(f'<a href="{path}"{mark}>{label}</a>')
    for path, label in LOCKED_DEMO_PAGES:
        # Absolute links to the internal host: the gateway must rewrite the
        # host away, and then block the page itself.
        links.append(f'<a href="{self_url}{path}">{label}</a>')
    return (
        '<div class="top"><b>Acme Internal</b>'
        + "".join(links)
        + '<span style="margin-left:auto;font-size:12px;color:#8ea0b4">'
        "internal use only</span></div>"
    )


def _page(title: str, active: str, body: str, self_url: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{title} &middot; Acme Internal</title>"
        f"<style>{PAGE_CSS}</style></head><body>"
        f"{_chrome(active, self_url)}<main>{body}</main></body></html>"
    )


def create_app(self_url: str | None = None) -> FastAPI:
    SELF_URL = self_url or DEFAULT_SELF_URL
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
        bars = "".join(
            f'<i style="height:{h}%"></i>'
            for h in (52, 61, 48, 74, 69, 83, 58, 77, 91, 66, 72, 88)
        )
        axis = "".join(
            f"<span>{m}</span>"
            for m in ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
        )
        body = f"""
        <div class="head">
          <div><h1>Overview</h1><p class="sub">Platform health and this month's load</p></div>
          <div class="spacer"></div>
          <div class="stamp">{now}</div>
        </div>
        <div class="tiles">
          <div class="tile"><div class="k">Uptime</div><div class="v">99.94%</div>
            <div class="d">30-day rolling</div></div>
          <div class="tile"><div class="k">Open incidents</div><div class="v">2</div>
            <div class="d">1 degraded service</div></div>
          <div class="tile"><div class="k">Requests</div><div class="v">4.1M</div>
            <div class="d">+6.2% on last month</div></div>
          <div class="tile"><div class="k">P95 latency</div><div class="v">182<span
            style="font-size:15px;color:var(--soft)">ms</span></div>
            <div class="d">within target</div></div>
        </div>
        <div class="box">
          <h2>Requests per month</h2>
          <div class="bars">{bars}</div>
          <div class="axis">{axis}</div>
        </div>
        <div class="box">
          <h2>Service status</h2>
          <table>
            <tr><th>Service</th><th>State</th><th>Owner</th><th>Last check</th></tr>
            <tr><td>Billing API</td><td><span class="pill ok">healthy</span></td>
              <td>Payments</td><td>2 min ago</td></tr>
            <tr><td>Document store</td><td><span class="pill ok">healthy</span></td>
              <td>Platform</td><td>1 min ago</td></tr>
            <tr><td>Mail relay</td><td><span class="pill warn">degraded</span></td>
              <td>Platform</td><td>4 min ago</td></tr>
            <tr><td>Batch runner</td><td><span class="pill ok">healthy</span></td>
              <td>Data</td><td>just now</td></tr>
            <tr><td>Search index</td><td><span class="pill ok">healthy</span></td>
              <td>Data</td><td>3 min ago</td></tr>
          </table>
        </div>
        <div class="box">
          <h2>Live ticker</h2>
          <p class="sub" style="margin:0 0 10px">
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
        return HTMLResponse(_page("Overview", "/dashboard/overview", body, SELF_URL))

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
            f"<tr><td><b>{name}</b></td><td>{period}</td><td>{size}</td>"
            f"<td><span class='pill ok'>PDF</span></td></tr>"
            for name, period, size in [
                ("Uptime summary", "September 2026", "412 KB"),
                ("Incident review", "Q3 2026", "1.1 MB"),
                ("Capacity forecast", "2027", "860 KB"),
                ("Vendor SLA report", "September 2026", "230 KB"),
            ]
        )
        body = f"""
        <div class="head">
          <div><h1>Reports</h1><p class="sub">Generated nightly. Read-only for vendor accounts.</p></div>
          <div class="spacer"></div>
          <div class="stamp">4 available</div>
        </div>
        <div class="box"><h2>Published reports</h2><table>
          <tr><th>Report</th><th>Period</th><th>Size</th><th>Format</th></tr>{rows}
        </table></div>
        <p class="sub">Need the raw numbers? That lives in
        <a href="{SELF_URL}/dashboard/finance">Finance</a>, which vendors cannot open.</p>
        """
        return HTMLResponse(_page("Reports", "/dashboard/reports", body, SELF_URL))

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
            f"<tr><td><code>{ref}</code></td><td>{subject}</td>"
            f"<td><span class='pill {cls}'>{state}</span></td></tr>"
            for ref, subject, state, cls in [
                ("INC-4411", "Mail relay queue backing up", "open", "bad"),
                ("INC-4408", "Nightly batch slower than usual", "investigating", "warn"),
                ("REQ-2291", "Add read-only access for auditor", "done", "ok"),
                ("INC-4399", "Certificate renewal warning", "closed", "ok"),
            ]
        )
        body = f"""
        <div class="head">
          <div><h1>Tickets</h1><p class="sub">Open and recent items.</p></div>
          <div class="spacer"></div>
          <div class="stamp">2 open</div>
        </div>
        <div class="box"><h2>Queue</h2><table>
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
        return HTMLResponse(_page("Tickets", "/dashboard/tickets", body, SELF_URL))

    @app.post("/dashboard/tickets/comment", response_class=HTMLResponse)
    async def ticket_comment() -> HTMLResponse:
        # Reachable from inside the network; a vendor's POST never gets here.
        return HTMLResponse(
            _page("Tickets", "/dashboard/tickets", "<h1>Comment saved</h1>", SELF_URL)
        )

    def _locked(title: str, path: str, blurb: str):
        async def view() -> HTMLResponse:
            body = f"""
            <div class="head locked">
              <div><h1>{title}</h1><p class="sub">{blurb}</p></div>
            </div>
            <div class="box">
              <p style="margin:0">If a vendor is reading this page, the gateway
              failed. It should never be forwarded.</p>
            </div>
            """
            return HTMLResponse(_page(title, path, body, SELF_URL))

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
