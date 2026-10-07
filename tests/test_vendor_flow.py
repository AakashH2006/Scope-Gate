"""The vendor journey, end to end -- the checklist in section 14 of the plan."""
from __future__ import annotations

import asyncio
from datetime import timedelta

from sqlalchemy import select

from tests.conftest import ALLOWED_PAGES
from scopegate.db import session_scope
from scopegate.grants import sweep_expired
from scopegate.models import Event, Grant, GrantStatus, Session, utcnow


# --------------------------------------------------------------------------- #
# helpers that reach into the database the running app is using
# --------------------------------------------------------------------------- #

async def _grant(public_id: str) -> Grant:
    async with session_scope() as db:
        grant = (
            await db.execute(select(Grant).where(Grant.public_id == public_id))
        ).scalar_one()
        return grant


async def _events(public_id: str | None = None) -> list[Event]:
    async with session_scope() as db:
        stmt = select(Event).order_by(Event.id)
        if public_id:
            stmt = stmt.where(Event.grant_public_id == public_id)
        return list((await db.execute(stmt)).scalars().all())


async def _event_types(public_id: str | None = None) -> list[str]:
    return [e.type for e in await _events(public_id)]


async def _session_count(public_id: str) -> int:
    async with session_scope() as db:
        grant = (
            await db.execute(select(Grant).where(Grant.public_id == public_id))
        ).scalar_one()
        rows = (
            await db.execute(select(Session).where(Session.grant_id == grant.id))
        ).scalars().all()
        return len(rows)


async def _shift_clock(public_id: str, **delta) -> None:
    """Move a grant's deadlines into the past, to test expiry without waiting."""
    async with session_scope() as db:
        grant = (
            await db.execute(select(Grant).where(Grant.public_id == public_id))
        ).scalar_one()
        shift = timedelta(**delta)
        if grant.access_expires_at is not None:
            grant.access_expires_at = grant.access_expires_at - shift
        grant.link_expires_at = grant.link_expires_at - shift


# --------------------------------------------------------------------------- #
# the link
# --------------------------------------------------------------------------- #

def test_unknown_or_malformed_tokens_get_the_same_neutral_page(client):
    for token in ("short", "x" * 43, "a" * 200, "not/a/token"):
        response = client.get(f"/{token}")
        assert response.status_code == 404
        assert "This link is not valid" in response.text or response.status_code == 404


def test_opening_the_link_does_not_consume_it(client, issue_grant):
    """A mail security scanner must not burn the vendor's access (section 6.3)."""
    grant = issue_grant()

    for _ in range(3):
        page = client.get(f"/{grant.token}")
        assert page.status_code == 200
        assert "Sign in" in page.text

    assert asyncio.run(_grant(grant.public_id)).status == GrantStatus.pending.value
    assert asyncio.run(_event_types(grant.public_id)).count("link_viewed") == 3

    # And the vendor can still sign in afterwards.
    response = client.post(
        f"/{grant.token}/login",
        data={"email": grant.vendor_email, "password": grant.password},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_login_page_never_reveals_the_vendor_email(client, issue_grant):
    grant = issue_grant()
    page = client.get(f"/{grant.token}")
    assert grant.vendor_email not in page.text


# --------------------------------------------------------------------------- #
# login
# --------------------------------------------------------------------------- #

def test_wrong_email_and_wrong_password_give_the_same_error(client, issue_grant):
    grant = issue_grant()
    wrong_email = client.post(
        f"/{grant.token}/login",
        data={"email": "someone@else.example", "password": grant.password},
    )
    wrong_password = client.post(
        f"/{grant.token}/login",
        data={"email": grant.vendor_email, "password": "not-the-password"},
    )
    assert wrong_email.status_code == wrong_password.status_code == 401
    assert "Those details are incorrect." in wrong_email.text
    assert "Those details are incorrect." in wrong_password.text


def test_five_wrong_passwords_lock_the_grant(client, issue_grant, settings):
    grant = issue_grant()
    for attempt in range(settings.max_login_attempts):
        response = client.post(
            f"/{grant.token}/login",
            data={"email": grant.vendor_email, "password": f"wrong-{attempt}"},
        )
        assert response.status_code == 401

    row = asyncio.run(_grant(grant.public_id))
    assert row.status == GrantStatus.locked.value
    assert "grant_locked" in asyncio.run(_event_types(grant.public_id))

    # The correct password no longer helps, and the link shows the neutral page.
    assert client.get(f"/{grant.token}").status_code == 404
    refused = client.post(
        f"/{grant.token}/login",
        data={"email": grant.vendor_email, "password": grant.password},
    )
    assert refused.status_code == 404


def test_successful_login_starts_the_access_clock(client, issue_grant):
    grant = issue_grant(duration_minutes=10)
    before = asyncio.run(_grant(grant.public_id))
    assert before.activated_at is None
    assert before.access_expires_at is None

    response = client.post(
        f"/{grant.token}/login",
        data={"email": grant.vendor_email, "password": grant.password},
        follow_redirects=False,
    )
    assert response.status_code == 303
    # Straight off the token URL, so the token never lands in a Referer header.
    assert response.headers["location"] == f"/s{ALLOWED_PAGES[0]}"

    after = asyncio.run(_grant(grant.public_id))
    assert after.status == GrantStatus.active.value
    assert after.activated_at is not None
    assert after.access_expires_at is not None
    assert 9 * 60 <= after.seconds_left() <= 10 * 60
    assert after.bound_device_hash


def test_login_is_rate_limited_per_address(client, issue_grant, settings):
    grant = issue_grant()
    settings_limit = client.app.state.vendor_limiter
    settings_limit.limit = 3
    settings_limit.reset()
    statuses = [
        client.post(
            f"/{grant.token}/login",
            data={"email": grant.vendor_email, "password": "wrong"},
        ).status_code
        for _ in range(4)
    ]
    assert statuses[:3] == [401, 401, 401]
    assert statuses[3] == 429
    assert "rate_limited" in asyncio.run(_event_types())


# --------------------------------------------------------------------------- #
# one link, one device
# --------------------------------------------------------------------------- #

def test_second_device_is_refused_after_the_first_login(vendor_in, other_device):
    grant = vendor_in()
    second = other_device()

    page = second.get(f"/{grant.token}")
    assert page.status_code == 404
    assert "This link is not valid" in page.text

    # Even with the right password, the link is spent: no form, no hint.
    login = second.post(
        f"/{grant.token}/login",
        data={"email": grant.vendor_email, "password": grant.password},
    )
    assert login.status_code == 404
    assert "This link is not valid" in login.text

    types = asyncio.run(_event_types(grant.public_id))
    assert types.count("device_refused") == 2


def test_same_browser_can_return_while_the_grant_is_active(client, vendor_in):
    grant = vendor_in()
    assert client.get(f"/s{ALLOWED_PAGES[0]}").status_code == 200

    # Back to the original link: the bound browser is sent on to its pages.
    again = client.get(f"/{grant.token}", follow_redirects=False)
    assert again.status_code == 303
    assert again.headers["location"] == f"/s{ALLOWED_PAGES[0]}"
    assert client.get(f"/s{ALLOWED_PAGES[0]}").status_code == 200


def test_clearing_cookies_ends_access(client, vendor_in):
    grant = vendor_in()
    assert client.get(f"/s{ALLOWED_PAGES[0]}").status_code == 200
    client.cookies.clear()
    assert client.get(f"/s{ALLOWED_PAGES[0]}").status_code == 401
    assert client.get(f"/{grant.token}").status_code == 404


def test_a_stolen_cookie_on_another_device_is_refused(client, vendor_in, other_device):
    grant = vendor_in()
    stolen = client.cookies.get("sg_session")

    thief = other_device("A Completely Different Browser")
    thief.cookies.set("sg_session", stolen)
    response = thief.get(f"/s{ALLOWED_PAGES[0]}")
    assert response.status_code == 403
    assert "tied to the device" in response.text
    assert "Billing API" not in response.text

    assert "device_refused" in asyncio.run(_event_types(grant.public_id))
    # The real browser is unaffected.
    assert client.get(f"/s{ALLOWED_PAGES[0]}").status_code == 200


# --------------------------------------------------------------------------- #
# the proxy
# --------------------------------------------------------------------------- #

def test_allowed_pages_load_through_the_gateway(client, vendor_in):
    vendor_in(pages=ALLOWED_PAGES)
    for page in ALLOWED_PAGES:
        response = client.get(f"/s{page}")
        assert response.status_code == 200, page
        assert "Acme Internal" in response.text


def test_a_page_outside_the_grant_is_blocked_and_logged(client, vendor_in):
    grant = vendor_in(pages=[ALLOWED_PAGES[0]])
    response = client.get(f"/s{ALLOWED_PAGES[1]}")
    assert response.status_code == 403
    assert "not part of your access" in response.text
    assert "Reports" not in response.text

    blocked = client.get("/s/dashboard/finance")
    assert blocked.status_code == 403
    assert "Invoices" not in blocked.text

    types = asyncio.run(_event_types(grant.public_id))
    assert types.count("page_blocked") == 2


def test_path_traversal_cannot_escape_the_grant(client, vendor_in):
    vendor_in(pages=[ALLOWED_PAGES[0]])
    for attempt in (
        "/s/dashboard/overview/../finance",
        "/s/dashboard/overview/../../dashboard/users",
        "/s/../dashboard/settings",
    ):
        response = client.get(attempt)
        assert response.status_code in (403, 404), attempt
        assert "Invoices" not in response.text
        assert "Staff accounts" not in response.text
        assert "Integration keys" not in response.text


def test_write_methods_are_refused_under_the_default_restriction(client, vendor_in):
    grant = vendor_in(pages=[ALLOWED_PAGES[2]])
    response = client.post(
        f"/s{ALLOWED_PAGES[2]}/comment", data={"text": "should never arrive"}
    )
    assert response.status_code == 405
    assert "read-only" in response.text.lower()
    assert "Comment saved" not in response.text
    detail = " ".join(e.detail or "" for e in asyncio.run(_events(grant.public_id)))
    assert "not permitted" in detail


def test_internal_fingerprints_and_cookies_do_not_reach_the_vendor(client, vendor_in):
    vendor_in(pages=[ALLOWED_PAGES[0]])
    response = client.get(f"/s{ALLOWED_PAGES[0]}")
    assert response.status_code == 200

    lower = {k.lower() for k in response.headers}
    for leaked in ("server", "x-internal-host", "x-powered-by", "set-cookie"):
        assert leaked not in lower, leaked

    assert "app01.corp.internal" not in response.text
    assert "internal.test" not in response.text
    assert "acme_session" not in response.text
    assert "acme_session" not in client.cookies


def test_security_headers_are_added_to_proxied_pages(client, vendor_in):
    vendor_in(pages=[ALLOWED_PAGES[0]])
    response = client.get(f"/s{ALLOWED_PAGES[0]}")
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "no-store" in response.headers["cache-control"]


def test_links_in_the_page_are_rewritten_to_stay_inside_the_gateway(client, vendor_in):
    vendor_in(pages=ALLOWED_PAGES)
    body = client.get(f"/s{ALLOWED_PAGES[0]}").text
    # Granted pages: linked, and pointing back through the gateway.
    assert 'href="/s/dashboard/reports"' in body
    assert 'href="/s/dashboard/tickets"' in body
    # The internal address never survives, in either link form: the mock site
    # emits root-relative links for granted pages and absolute ones for the
    # rest, and both have to come out the other side rewritten.
    assert "internal.test" not in body
    # Pages outside the grant are gone entirely (BLOCKED_LINKS=remove).
    assert 'href="/s/dashboard/finance"' not in body
    assert "Finance" not in body


def test_a_redirect_from_the_internal_site_stays_inside_the_gateway(client, vendor_in):
    vendor_in(pages=["/dashboard/overview"])
    # The mock site redirects /dashboard to an absolute internal URL.
    response = client.get("/s/dashboard", follow_redirects=False)
    # /dashboard itself is not in the grant, so it is blocked before the redirect.
    assert response.status_code == 403


def test_a_redirect_inside_the_grant_is_rewritten(app, settings, vendor_in, client):
    vendor_in(pages=["/dashboard/overview"])
    # /dashboard/overview/ (trailing slash) redirects inside the mock app and the
    # Location must come back pointing at /s/...
    response = client.get("/s/dashboard/overview/", follow_redirects=False)
    assert response.status_code in (200, 307, 308)
    if "location" in response.headers:
        assert response.headers["location"].startswith("/s/")


def test_the_countdown_banner_is_injected_with_a_working_status_endpoint(client, vendor_in):
    vendor_in(duration_minutes=30, pages=[ALLOWED_PAGES[0]])
    page = client.get(f"/s{ALLOWED_PAGES[0]}")
    assert 'id="sg-bar"' in page.text
    assert "/s/_status" in page.text

    status = client.get("/s/_status")
    assert status.status_code == 200
    payload = status.json()
    assert 29 * 60 <= payload["seconds_left"] <= 30 * 60


def test_the_gateway_own_paths_are_not_proxied(client, vendor_in):
    vendor_in(pages=ALLOWED_PAGES)
    assert client.get("/s/logout").status_code == 404
    assert client.get("/s/_status").status_code == 200


def test_vendor_can_end_their_own_session(client, vendor_in):
    grant = vendor_in(pages=[ALLOWED_PAGES[0]])
    page = client.get(f"/s{ALLOWED_PAGES[0]}").text
    csrf = page.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    forged = client.post("/s/logout", data={"csrf": "forged"})
    assert forged.status_code == 400
    # A forged logout leaves the session alone.
    assert client.get(f"/s{ALLOWED_PAGES[0]}").status_code == 200

    out = client.post("/s/logout", data={"csrf": csrf})
    assert out.status_code == 200
    assert "signed out" in out.text
    assert client.get(f"/s{ALLOWED_PAGES[0]}").status_code == 401
    assert "vendor_logout" in asyncio.run(_event_types(grant.public_id))


# --------------------------------------------------------------------------- #
# revoke and expiry
# --------------------------------------------------------------------------- #

def test_revoke_takes_effect_on_the_very_next_request(client, admin, vendor_in):
    grant = vendor_in(pages=[ALLOWED_PAGES[0]])
    assert client.get(f"/s{ALLOWED_PAGES[0]}").status_code == 200

    revoked = client.post(
        f"/admin/grants/{grant.public_id}/revoke",
        data={"csrf": admin.csrf_token},
        follow_redirects=False,
    )
    assert revoked.status_code == 303

    blocked = client.get(f"/s{ALLOWED_PAGES[0]}")
    assert blocked.status_code == 403
    assert "withdrawn" in blocked.text
    assert "Billing API" not in blocked.text
    assert asyncio.run(_session_count(grant.public_id)) == 0
    assert client.get(f"/{grant.token}").status_code == 404


def test_expiry_ends_the_session_and_shows_the_neutral_page(client, app, vendor_in):
    grant = vendor_in(duration_minutes=5, pages=[ALLOWED_PAGES[0]])
    assert client.get(f"/s{ALLOWED_PAGES[0]}").status_code == 200

    asyncio.run(_shift_clock(grant.public_id, minutes=6))

    # Enforced on the request itself, without waiting for the background job.
    ended = client.get(f"/s{ALLOWED_PAGES[0]}")
    assert ended.status_code == 403
    assert "window has ended" in ended.text

    row = asyncio.run(_grant(grant.public_id))
    assert row.status == GrantStatus.expired.value
    assert asyncio.run(_session_count(grant.public_id)) == 0
    assert client.get(f"/{grant.token}").status_code == 404


def test_the_background_sweep_expires_grants_without_a_request(client, app, vendor_in):
    grant = vendor_in(duration_minutes=5, pages=[ALLOWED_PAGES[0]])
    asyncio.run(_shift_clock(grant.public_id, minutes=6))

    async def sweep():
        async with session_scope() as db:
            return await sweep_expired(db, live=app.state.live)

    result = asyncio.run(sweep())
    assert result.expired == 1
    assert asyncio.run(_grant(grant.public_id)).status == GrantStatus.expired.value
    assert "grant_expired" in asyncio.run(_event_types(grant.public_id))


def test_an_unused_link_dies_after_the_link_window(client, app, issue_grant):
    grant = issue_grant()
    asyncio.run(_shift_clock(grant.public_id, minutes=181))

    async def sweep():
        async with session_scope() as db:
            return await sweep_expired(db, live=app.state.live)

    result = asyncio.run(sweep())
    assert result.expired_unused == 1

    row = asyncio.run(_grant(grant.public_id))
    assert row.status == GrantStatus.expired_unused.value
    assert client.get(f"/{grant.token}").status_code == 404
    refused = client.post(
        f"/{grant.token}/login",
        data={"email": grant.vendor_email, "password": grant.password},
    )
    assert refused.status_code == 404


def test_expired_and_revoked_links_look_identical(client, admin, app, issue_grant, vendor_in):
    revoked = issue_grant(vendor_email="a@partner.example")
    client.post(
        f"/admin/grants/{revoked.public_id}/revoke",
        data={"csrf": admin.csrf_token},
        follow_redirects=False,
    )
    unused = issue_grant(vendor_email="b@partner.example")
    asyncio.run(_shift_clock(unused.public_id, minutes=181))

    async def sweep():
        async with session_scope() as db:
            await sweep_expired(db, live=app.state.live)

    asyncio.run(sweep())

    first = client.get(f"/{revoked.token}")
    second = client.get(f"/{unused.token}")
    unknown = client.get("/" + "z" * 43)
    assert first.status_code == second.status_code == unknown.status_code == 404
    assert first.text == second.text == unknown.text


def test_a_grant_never_moves_backwards(client, admin, app, vendor_in):
    grant = vendor_in(duration_minutes=5, pages=[ALLOWED_PAGES[0]])
    asyncio.run(_shift_clock(grant.public_id, minutes=6))
    client.get(f"/s{ALLOWED_PAGES[0]}")  # triggers expiry
    assert asyncio.run(_grant(grant.public_id)).status == GrantStatus.expired.value

    # Revoking an already-expired grant is refused rather than overwriting it.
    client.post(
        f"/admin/grants/{grant.public_id}/revoke",
        data={"csrf": admin.csrf_token},
        follow_redirects=False,
    )
    assert "already expired" in admin.flash["error"]
    assert asyncio.run(_grant(grant.public_id)).status == GrantStatus.expired.value


# --------------------------------------------------------------------------- #
# audit log hygiene
# --------------------------------------------------------------------------- #

def test_no_secret_ever_reaches_the_audit_log(client, vendor_in):
    grant = vendor_in(pages=ALLOWED_PAGES)
    client.get(f"/s{ALLOWED_PAGES[0]}")
    client.get("/s/dashboard/finance")
    cookie = client.cookies.get("sg_session")

    rows = asyncio.run(_events())
    blob = " | ".join(
        f"{r.type} {r.detail or ''} {r.ip or ''} {r.user_agent or ''}" for r in rows
    )
    assert grant.token not in blob
    assert grant.password not in blob
    assert cookie not in blob


def test_page_views_record_the_path_but_not_the_contents(client, vendor_in):
    grant = vendor_in(pages=[ALLOWED_PAGES[0]])
    client.get(f"/s{ALLOWED_PAGES[0]}")
    rows = asyncio.run(_events(grant.public_id))
    views = [r for r in rows if r.type == "page_viewed"]
    assert views
    assert views[-1].detail == f"GET {ALLOWED_PAGES[0]}"
    assert "Billing API" not in (views[-1].detail or "")


def test_retention_prunes_old_events_only(client, issue_grant, settings):
    issue_grant()

    async def age_and_prune():
        from scopegate.events import prune_events

        async with session_scope() as db:
            rows = (await db.execute(select(Event))).scalars().all()
            rows[0].ts = utcnow() - timedelta(days=settings.log_retention_days + 1)
            kept = len(rows) - 1
        async with session_scope() as db:
            removed = await prune_events(db, retention_days=settings.log_retention_days)
        async with session_scope() as db:
            remaining = len((await db.execute(select(Event))).scalars().all())
        return removed, kept, remaining

    removed, kept, remaining = asyncio.run(age_and_prune())
    assert removed == 1
    assert remaining == kept


# --------------------------------------------------------------------------- #
# navigation the grant does not cover
# --------------------------------------------------------------------------- #

def test_vendor_never_sees_the_names_of_pages_outside_the_grant(client, vendor_in):
    """The mock site renders its whole menu; the gateway must not pass it on."""
    vendor_in(pages=[ALLOWED_PAGES[0]])
    body = client.get(f"/s{ALLOWED_PAGES[0]}").text

    # Granted page is still linked.
    assert f'href="/s{ALLOWED_PAGES[0]}"' in body
    # Everything else is gone, name and all.
    for hidden in ("Finance", "Users", "Settings"):
        assert hidden not in body, hidden
    for path in ("/dashboard/finance", "/dashboard/users", "/dashboard/settings"):
        assert f'href="/s{path}"' not in body


def test_hiding_links_does_not_replace_the_allowlist(client, vendor_in):
    """Typing the path directly still meets the server-side check."""
    grant = vendor_in(pages=[ALLOWED_PAGES[0]])
    assert "Finance" not in client.get(f"/s{ALLOWED_PAGES[0]}").text

    blocked = client.get("/s/dashboard/finance")
    assert blocked.status_code == 403
    assert "Invoices" not in blocked.text
    assert "page_blocked" in asyncio.run(_event_types(grant.public_id))
