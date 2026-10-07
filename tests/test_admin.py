"""Admin authentication, grant creation and the log views (sections 6.4, 8, 10)."""
from __future__ import annotations

from tests.conftest import ADMIN_PASSWORD, ALLOWED_PAGES, AdminCreds


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


def test_no_openapi_or_docs_are_exposed(client):
    for path in ("/openapi.json", "/docs", "/redoc"):
        assert client.get(path).status_code == 404


def test_root_and_robots_reveal_nothing(client):
    root = client.get("/")
    assert root.status_code == 404
    assert "ScopeGate" not in root.text
    robots = client.get("/robots.txt")
    assert "Disallow: /" in robots.text
