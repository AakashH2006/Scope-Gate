"""Admin authentication, grant creation and the log views (sections 6.4, 8, 10)."""
from __future__ import annotations

import asyncio
from datetime import timedelta

from sqlalchemy import select

from scopegate.db import session_scope
from scopegate.models import Event, Grant
from tests.conftest import ADMIN_PASSWORD, ALLOWED_PAGES, AdminCreds


async def _grant(public_id: str) -> Grant:
    async with session_scope() as db:
        return (
            await db.execute(select(Grant).where(Grant.public_id == public_id))
        ).scalar_one()


async def _close_link_window(public_id: str) -> None:
    """Push a grant's link deadline into the past without waiting for it."""
    async with session_scope() as db:
        grant = (
            await db.execute(select(Grant).where(Grant.public_id == public_id))
        ).scalar_one()
        grant.link_expires_at = grant.link_expires_at - timedelta(hours=4)


async def _event_types(public_id: str) -> list[str]:
    async with session_scope() as db:
        rows = (
            await db.execute(
                select(Event).where(Event.grant_public_id == public_id).order_by(Event.id)
            )
        ).scalars().all()
        return [e.type for e in rows]


def test_admin_pages_require_a_session(client):
    for path in ("/admin", "/admin/logs"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/admin/login"


def test_admin_login_needs_the_totp_code(client, admin_creds: AdminCreds):
    response = client.post(
        "/admin/login",
        data={"email": admin_creds.email, "password": admin_creds.password, "totp": ""},
        follow_redirects=False,
    )
    assert response.status_code == 401
    assert "Sign-in failed" in response.text

    response = client.post(
        "/admin/login",
        data={
            "email": admin_creds.email,
            "password": admin_creds.password,
            "totp": "000000",
        },
        follow_redirects=False,
    )
    assert response.status_code == 401


def test_admin_login_failure_message_is_the_same_for_both_halves(client, admin_creds):
    wrong_password = client.post(
        "/admin/login",
        data={"email": admin_creds.email, "password": "nope", "totp": admin_creds.code()},
        follow_redirects=False,
    )
    wrong_code = client.post(
        "/admin/login",
        data={
            "email": admin_creds.email,
            "password": admin_creds.password,
            "totp": "000000",
        },
        follow_redirects=False,
    )
    assert wrong_password.status_code == wrong_code.status_code == 401
    assert "Sign-in failed. Check your password and code." in wrong_password.text
    assert "Sign-in failed. Check your password and code." in wrong_code.text


def test_admin_login_succeeds_and_reaches_the_dashboard(client, admin_creds):
    response = client.post(
        "/admin/login",
        data={
            "email": admin_creds.email,
            "password": admin_creds.password,
            "totp": admin_creds.code(),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/admin"

    dashboard = client.get("/admin")
    assert dashboard.status_code == 200
    assert "New grant" in dashboard.text
    for page in ALLOWED_PAGES:
        assert page in dashboard.text


def test_grant_creation_requires_the_master_password(client, admin):
    response = client.post(
        "/admin/grants",
        data={
            "csrf": admin.csrf_token,
            "vendor_email": "vendor@partner.example",
            "duration_minutes": "30",
            "master_password": "the-wrong-password",
            "allowed_paths": ALLOWED_PAGES[:1],
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert admin.flash == {"error": "Your password was not correct. No grant was created."}

    dashboard = client.get("/admin")
    assert "No grants yet" in dashboard.text


def test_grant_creation_requires_a_csrf_token(client, admin):
    response = client.post(
        "/admin/grants",
        data={
            "csrf": "forged",
            "vendor_email": "vendor@partner.example",
            "duration_minutes": "30",
            "master_password": ADMIN_PASSWORD,
            "allowed_paths": ALLOWED_PAGES[:1],
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "could not be verified" in admin.flash["error"]
    assert "No grants yet" in client.get("/admin").text


def test_grant_creation_rejects_a_page_that_was_not_offered(client, admin):
    response = client.post(
        "/admin/grants",
        data={
            "csrf": admin.csrf_token,
            "vendor_email": "vendor@partner.example",
            "duration_minutes": "30",
            "master_password": ADMIN_PASSWORD,
            "allowed_paths": ["/dashboard/finance"],
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "Select at least one allowed page" in admin.flash["error"]


def test_grant_creation_caps_the_duration(client, admin, settings):
    response = client.post(
        "/admin/grants",
        data={
            "csrf": admin.csrf_token,
            "vendor_email": "vendor@partner.example",
            "duration_minutes": str(settings.max_access_minutes + 1),
            "master_password": ADMIN_PASSWORD,
            "allowed_paths": ALLOWED_PAGES[:1],
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "may not exceed" in admin.flash["error"]


def test_grant_creation_sends_the_invite_and_shows_it_once(client, admin, issue_grant, settings):
    import email
    import html
    import pathlib

    grant = issue_grant()
    assert grant.link.startswith("http://testserver/")
    assert len(grant.token) == 43
    assert len(grant.password) == settings.vendor_password_length

    outbox = sorted(pathlib.Path(settings.mail_outbox_dir).glob("*.eml"))
    assert len(outbox) == 1
    message = email.message_from_string(outbox[0].read_text(encoding="utf-8"))
    assert message["To"] == grant.vendor_email
    assert message["Subject"] == "Your temporary access link"
    # The body is quoted-printable on the wire; check what the vendor will read.
    body = message.get_payload(decode=True).decode("utf-8")
    assert grant.link in body
    assert grant.password in body
    assert grant.vendor_email in body
    # Plain text only: no tracking pixel, no remote image (section 9).
    assert message.get_content_type() == "text/plain"
    assert "<img" not in body
    assert "http" not in body.replace(grant.link, "")

    # The link and password appear on the dashboard once, then never again.
    shown = html.escape(grant.password)
    first = client.get("/admin")
    assert shown in first.text
    second = client.get("/admin")
    assert shown not in second.text


def test_dashboard_shows_the_grant_and_an_audit_trail(client, admin, issue_grant):
    grant = issue_grant()
    dashboard = client.get("/admin")
    assert grant.public_id in dashboard.text
    assert grant.vendor_email in dashboard.text
    assert "pending" in dashboard.text
    assert "grant_created" in dashboard.text
    assert "email_sent" in dashboard.text


def test_logs_filter_by_event_type_and_grant(client, admin, issue_grant):
    grant = issue_grant()
    logs = client.get("/admin/logs?type=grant_created")
    assert logs.status_code == 200
    # Check the table cells, not the filter dropdown that lists every type.
    assert ">grant_created</td>" in logs.text
    assert ">admin_login_ok</td>" not in logs.text
    assert ">grant_created</td>" not in client.get("/admin/logs?type=admin_login_ok").text

    by_grant = client.get(f"/admin/logs?grant={grant.public_id}")
    assert grant.public_id in by_grant.text

    nonsense = client.get("/admin/logs?type=not-a-real-type")
    assert nonsense.status_code == 200  # filter is ignored, not an error


def test_logs_never_contain_the_token_or_the_password(client, admin, issue_grant):
    import html

    grant = issue_grant()
    logs = client.get("/admin/logs").text
    assert grant.token not in logs
    assert grant.password not in logs
    assert html.escape(grant.password) not in logs


def test_admin_logout_kills_the_session(client, admin):
    response = client.post(
        "/admin/logout", data={"csrf": admin.csrf_token}, follow_redirects=False
    )
    assert response.status_code == 303
    assert client.get("/admin", follow_redirects=False).status_code == 303


def test_admin_logout_needs_a_csrf_token(client, admin):
    client.post("/admin/logout", data={"csrf": "forged"}, follow_redirects=False)
    # The session survives a forged logout; the cookie was cleared, so restore it
    # by checking the store directly.
    assert client.app.state.admin_sessions.get(admin.sid) is not None


def test_revoke_needs_csrf_and_an_existing_grant(client, admin, issue_grant):
    grant = issue_grant()
    client.post(
        f"/admin/grants/{grant.public_id}/revoke",
        data={"csrf": "forged"},
        follow_redirects=False,
    )
    assert "could not be verified" in admin.flash["error"]

    client.post(
        "/admin/grants/g-NOPE00/revoke",
        data={"csrf": admin.csrf_token},
        follow_redirects=False,
    )
    assert admin.flash["error"] == "No such grant."

    client.post(
        f"/admin/grants/{grant.public_id}/revoke",
        data={"csrf": admin.csrf_token},
        follow_redirects=False,
    )
    assert "revoked" in admin.flash["notice"]

    # A grant in a final state cannot be revoked twice.
    client.post(
        f"/admin/grants/{grant.public_id}/revoke",
        data={"csrf": admin.csrf_token},
        follow_redirects=False,
    )
    assert "already revoked" in admin.flash["error"]


# --------------------------------------------------------------------------- #
# resending an invite.  The link and the password are stored only as hashes, so
# a resend replaces them rather than repeating them.
# --------------------------------------------------------------------------- #

def _resend(client, admin, public_id, *, password=ADMIN_PASSWORD, csrf=None):
    return client.post(
        f"/admin/grants/{public_id}/resend",
        data={
            "csrf": admin.csrf_token if csrf is None else csrf,
            "master_password": password,
        },
        follow_redirects=False,
    )


def test_resend_button_appears_only_while_the_link_is_unused(client, admin, issue_grant):
    grant = issue_grant()
    link = f"/admin/grants/{grant.public_id}/resend"
    assert link in client.get("/admin").text

    client.post(
        f"/admin/grants/{grant.public_id}/revoke",
        data={"csrf": admin.csrf_token},
        follow_redirects=False,
    )
    assert link not in client.get("/admin").text


def test_resend_confirm_page_states_what_it_costs(client, admin, issue_grant):
    grant = issue_grant()
    page = client.get(f"/admin/grants/{grant.public_id}/resend")
    assert page.status_code == 200
    assert grant.vendor_email in page.text
    assert "stops working immediately" in page.text
    assert "not extended" in page.text
    for path in ALLOWED_PAGES[:2]:
        assert path in page.text
    # Confirming is not a second chance to read the secret that was sent.
    assert grant.token not in page.text
    assert grant.password not in page.text


def test_resend_replaces_the_link_and_the_password(client, admin, issue_grant):
    grant = issue_grant()

    assert _resend(client, admin, grant.public_id).status_code == 303
    issued = admin.flash["issued"]
    assert issued["resent"] is True
    assert issued["public_id"] == grant.public_id
    assert issued["vendor_email"] == grant.vendor_email
    assert issued["link"] != grant.link
    assert issued["password"] != grant.password

    new_token = issued["link"].rsplit("/", 1)[-1]

    # The link already sent is now indistinguishable from an unknown one.
    assert client.get(f"/{grant.token}").status_code == 404
    old = client.post(
        f"/{grant.token}/login",
        data={"email": grant.vendor_email, "password": grant.password},
        follow_redirects=False,
    )
    assert old.status_code == 404

    # Nor does the old password work on the new link.
    stale = client.post(
        f"/{new_token}/login",
        data={"email": grant.vendor_email, "password": grant.password},
        follow_redirects=False,
    )
    assert stale.status_code == 401

    fresh = client.post(
        f"/{new_token}/login",
        data={"email": grant.vendor_email, "password": issued["password"]},
        follow_redirects=False,
    )
    assert fresh.status_code == 303


def test_resend_changes_nothing_else_about_the_grant(client, admin, issue_grant):
    grant = issue_grant(duration_minutes=45, pages=ALLOWED_PAGES[:1])
    before = asyncio.run(_grant(grant.public_id))

    assert _resend(client, admin, grant.public_id).status_code == 303
    after = asyncio.run(_grant(grant.public_id))

    assert after.allowed_paths == before.allowed_paths
    assert after.duration_minutes == before.duration_minutes
    assert after.link_expires_at == before.link_expires_at
    assert after.vendor_email == before.vendor_email
    assert after.status == before.status
    assert after.token_hash != before.token_hash
    assert after.password_hash != before.password_hash


def test_resend_requires_the_master_password(client, admin, issue_grant):
    grant = issue_grant()

    response = _resend(client, admin, grant.public_id, password="the-wrong-password")
    assert response.status_code == 303
    assert admin.flash == {
        "error": "Your password was not correct. The link was not changed."
    }

    # The link the vendor already has still works, so nothing was rotated.
    assert client.get(f"/{grant.token}").status_code == 200
    assert "invite_resent" not in asyncio.run(_event_types(grant.public_id))


def test_resend_requires_a_csrf_token(client, admin, issue_grant):
    grant = issue_grant()
    assert _resend(client, admin, grant.public_id, csrf="forged").status_code == 303
    assert "could not be verified" in admin.flash["error"]
    assert client.get(f"/{grant.token}").status_code == 200
    assert "invite_resent" not in asyncio.run(_event_types(grant.public_id))


def test_resend_is_refused_once_the_vendor_has_signed_in(client, admin, vendor_in):
    grant = vendor_in()

    form = client.get(f"/admin/grants/{grant.public_id}/resend", follow_redirects=False)
    assert form.status_code == 303
    assert "is active" in admin.flash["error"]

    assert _resend(client, admin, grant.public_id).status_code == 303
    assert "This grant is active" in admin.flash["error"]
    assert "invite_resent" not in asyncio.run(_event_types(grant.public_id))


def test_resend_is_refused_once_the_link_window_has_closed(client, admin, issue_grant):
    """The window the admin chose is not reopened -- that would be extending time."""
    grant = issue_grant()
    asyncio.run(_close_link_window(grant.public_id))

    form = client.get(f"/admin/grants/{grant.public_id}/resend", follow_redirects=False)
    assert form.status_code == 303
    assert admin.flash["error"] == (
        "The link window for this grant has closed. Issue a new grant."
    )

    assert _resend(client, admin, grant.public_id).status_code == 303
    assert "link window for this grant has closed" in admin.flash["error"]
    assert "invite_resent" not in asyncio.run(_event_types(grant.public_id))
    # Refusing it also settles the grant, so the dashboard stops saying pending.
    assert asyncio.run(_grant(grant.public_id)).status == "expired_unused"


def test_resend_is_refused_for_a_revoked_grant(client, admin, issue_grant):
    grant = issue_grant()
    client.post(
        f"/admin/grants/{grant.public_id}/revoke",
        data={"csrf": admin.csrf_token},
        follow_redirects=False,
    )
    assert _resend(client, admin, grant.public_id).status_code == 303
    assert "This grant is revoked" in admin.flash["error"]


def test_resend_does_not_hand_back_lock_out_budget(client, admin, issue_grant):
    """New credentials, same failed-attempt count: a resend buys no extra tries."""
    grant = issue_grant()
    client.post(
        f"/{grant.token}/login",
        data={"email": grant.vendor_email, "password": "wrong"},
        follow_redirects=False,
    )
    assert asyncio.run(_grant(grant.public_id)).failed_attempts == 1

    assert _resend(client, admin, grant.public_id).status_code == 303
    assert asyncio.run(_grant(grant.public_id)).failed_attempts == 1


def test_resend_shows_the_new_secret_once_on_the_dashboard(client, admin, issue_grant):
    import html

    grant = issue_grant()
    client.get("/admin")  # clear the creation flash
    assert _resend(client, admin, grant.public_id).status_code == 303
    password = admin.flash["issued"]["password"]

    first = client.get("/admin")
    assert "new link sent" in first.text
    assert "previous ones stopped working" in first.text
    assert html.escape(password) in first.text
    assert html.escape(grant.password) not in first.text

    assert html.escape(password) not in client.get("/admin").text


def test_resend_mails_a_second_invite_and_logs_it(client, admin, issue_grant, settings):
    import email
    import pathlib

    grant = issue_grant()
    assert _resend(client, admin, grant.public_id).status_code == 303
    new_password = admin.flash["issued"]["password"]
    new_link = admin.flash["issued"]["link"]

    outbox = sorted(pathlib.Path(settings.mail_outbox_dir).glob("*.eml"))
    assert len(outbox) == 2
    message = email.message_from_string(outbox[-1].read_text(encoding="utf-8"))
    assert message["To"] == grant.vendor_email
    body = message.get_payload(decode=True).decode("utf-8")
    assert new_link in body
    assert new_password in body
    assert grant.password not in body

    types = asyncio.run(_event_types(grant.public_id))
    assert types.count("invite_resent") == 1
    assert types.count("email_sent") == 2

    logs = client.get("/admin/logs").text
    assert ">invite_resent</td>" in logs
    assert new_password not in logs
    assert new_link.rsplit("/", 1)[-1] not in logs


def test_resend_needs_an_admin_session(client):
    for method in ("get", "post"):
        response = getattr(client, method)(
            "/admin/grants/g-NOPE00/resend", follow_redirects=False
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/admin/login"


def test_resend_of_an_unknown_grant_says_so(client, admin):
    form = client.get("/admin/grants/g-NOPE00/resend", follow_redirects=False)
    assert form.status_code == 303
    assert admin.flash["error"] == "No such grant."

    assert _resend(client, admin, "g-NOPE00").status_code == 303
    assert admin.flash["error"] == "No such grant."


def test_no_openapi_or_docs_are_exposed(client):
    for path in ("/openapi.json", "/docs", "/redoc"):
        assert client.get(path).status_code == 404


def test_root_and_robots_reveal_nothing(client):
    root = client.get("/")
    assert root.status_code == 404
    assert "ScopeGate" not in root.text
    robots = client.get("/robots.txt")
    assert "Disallow: /" in robots.text
