"""Unit tests for the pieces that do not need a database."""
from __future__ import annotations

import pyotp
import pytest

from vendorgate import proxy, security
from vendorgate.config import Settings
from vendorgate.events import _scrub
from vendorgate.ratelimit import SlidingWindowLimiter


# --- tokens and hashing ----------------------------------------------------- #

def test_link_token_is_long_and_random():
    tokens = {security.generate_link_token() for _ in range(200)}
    assert len(tokens) == 200
    for token in tokens:
        # 32 bytes url-safe base64 -> 43 characters, far beyond guessing range.
        assert len(token) == 43
        assert proxy and all(c.isalnum() or c in "-_" for c in token)


def test_token_is_stored_only_as_a_keyed_hash():
    key = "k" * 40
    token = security.generate_link_token()
    digest = security.hash_token(key, token)
    assert token not in digest
    assert len(digest) == 64
    assert security.hash_token(key, token) == digest
    assert security.hash_token("other-key", token) != digest


def test_password_hash_roundtrip():
    pw = security.generate_password(16)
    assert len(pw) == 16
    digest = security.hash_password(pw)
    assert pw not in digest
    assert security.verify_password(digest, pw)
    assert not security.verify_password(digest, pw + "x")
    assert not security.verify_password("not-a-hash", pw)


def test_generated_password_has_a_floor_on_length():
    assert len(security.generate_password(4)) == 12


def test_device_fingerprint_is_keyed_and_normalised():
    key = "k" * 40
    a = security.device_fingerprint(key, "Mozilla/5.0  (X11)")
    b = security.device_fingerprint(key, "Mozilla/5.0 (X11)")
    c = security.device_fingerprint(key, "Mozilla/5.0 (Windows)")
    assert a == b          # whitespace-insensitive
    assert a != c
    assert security.device_fingerprint("other", "Mozilla/5.0 (X11)") != a


def test_totp_secret_is_encrypted_at_rest_and_verifies():
    key = security.generate_totp_enc_key()
    secret = security.generate_totp_secret()
    blob = security.encrypt_totp_secret(key, secret)
    assert secret not in blob
    assert security.decrypt_totp_secret(key, blob) == secret
    assert security.decrypt_totp_secret(security.generate_totp_enc_key(), blob) is None
    assert security.verify_totp(secret, pyotp.TOTP(secret).now())
    assert not security.verify_totp(secret, "000000")
    assert not security.verify_totp(secret, "abc")
    assert not security.verify_totp(secret, "")


def test_cookie_signature_is_rejected_when_tampered():
    key = "k" * 40
    value = security.sign_cookie(key, "salt", {"sid": "abc"})
    assert security.unsign_cookie(key, "salt", value) == {"sid": "abc"}
    assert security.unsign_cookie(key, "other-salt", value) is None
    assert security.unsign_cookie("other-key", "salt", value) is None
    assert security.unsign_cookie(key, "salt", value[:-2] + "xx") is None


# --- path handling ---------------------------------------------------------- #

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/dashboard/overview", "/dashboard/overview"),
        ("dashboard/overview", "/dashboard/overview"),
        ("//dashboard//reports/", "/dashboard/reports/"),
        ("/dashboard/overview/../finance", "/dashboard/finance"),
        ("/dashboard/./overview", "/dashboard/overview"),
        ("/../../etc/passwd", "/etc/passwd"),
        ("", "/"),
        ("/", "/"),
    ],
)
def test_path_normalisation(raw, expected):
    assert proxy.normalise_path(raw) == expected


def test_allowlist_matches_page_and_children_only():
    allowed = ["/dashboard/reports"]
    assert proxy.path_allowed("/dashboard/reports", allowed) == "/dashboard/reports"
    assert proxy.path_allowed("/dashboard/reports/q3", allowed) == "/dashboard/reports"
    assert proxy.path_allowed("/dashboard/reports/", allowed) == "/dashboard/reports"
    # A sibling that merely starts with the same characters is not covered.
    assert proxy.path_allowed("/dashboard/reports-secret", allowed) is None
    assert proxy.path_allowed("/dashboard/finance", allowed) is None
    assert proxy.path_allowed("/", allowed) is None


def test_traversal_cannot_reach_a_blocked_page():
    allowed = ["/dashboard/overview"]
    sneaky = proxy.normalise_path("/dashboard/overview/../finance")
    assert proxy.path_allowed(sneaky, allowed) is None


def test_method_allowlist(settings: Settings):
    for method in ("GET", "HEAD"):
        decision = proxy.check_request(
            method=method,
            path="/dashboard/overview",
            allowed_prefixes=["/dashboard/overview"],
            settings=settings,
        )
        assert decision.upstream_path == "/dashboard/overview"
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(proxy.ProxyDenied) as excinfo:
            proxy.check_request(
                method=method,
                path="/dashboard/overview",
                allowed_prefixes=["/dashboard/overview"],
                settings=settings,
            )
        assert excinfo.value.status == 405


# --- header and body sanitising -------------------------------------------- #

def test_request_headers_drop_browser_state():
    filtered = proxy.filter_request_headers(
        {
            "Cookie": "vg_session=abc",
            "Authorization": "Bearer x",
            "Referer": "http://testserver/TOKEN",
            "Origin": "http://testserver",
            "User-Agent": "test-agent",
            "Accept": "text/html",
            "X-Forwarded-For": "1.2.3.4",
        }
    )
    lower = {k.lower() for k in filtered}
    assert "cookie" not in lower
    assert "authorization" not in lower
    assert "referer" not in lower
    assert "origin" not in lower
    assert "x-forwarded-for" not in lower
    assert filtered["User-Agent"] == "test-agent"


def test_response_headers_drop_internal_fingerprints():
    import httpx

    headers = httpx.Headers(
        {
            "Server": "internal-nginx/1.21.6",
            "X-Internal-Host": "app01.corp.internal",
            "X-Powered-By": "Acme Platform 4.2",
            "Set-Cookie": "acme_session=internal",
            "Content-Type": "text/html",
            "Date": "Mon, 01 Jan 2026 00:00:00 GMT",
            "Via": "1.1 corp-proxy",
            "X-Request-Id": "internal-trace-id",
            "Content-Encoding": "gzip",
        }
    )
    out = proxy.filter_response_headers(headers, is_html=True)
    lower = {k.lower() for k in out}
    for leak in (
        "server",
        "x-internal-host",
        "x-powered-by",
        "set-cookie",
        "via",
        "x-request-id",
        # Our own server adds these; forwarding them duplicates or lies.
        "date",
        "content-encoding",
        "content-length",
    ):
        assert leak not in lower
    assert out["X-Frame-Options"] == "DENY"
    assert out["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in out["Content-Security-Policy"]


def test_body_rewriting_keeps_links_inside_the_gateway():
    body = (
        b'<html><body><a href="/dashboard/finance">f</a>'
        b'<a href="http://internal.test/dashboard/users">u</a>'
        b'<img src="http://internal.test/static/logo.png">'
        b'<a href="https://cdn.example/x.js">cdn</a>'
        b"<style>body{background:url(/bg.png)}</style></body></html>"
    )
    out = proxy.rewrite_body(body, upstream_url="http://internal.test").decode()
    assert 'href="/s/dashboard/finance"' in out
    assert 'href="/s/dashboard/users"' in out
    assert 'src="/s/static/logo.png"' in out
    assert "url(/s/bg.png)" in out
    assert "internal.test" not in out
    # A genuinely external asset is left alone rather than pointed at /s.
    assert 'href="https://cdn.example/x.js"' in out


def test_body_rewriting_is_not_applied_twice():
    body = b'<a href="/s/dashboard/overview">already mounted</a>'
    out = proxy.rewrite_body(body, upstream_url="http://internal.test").decode()
    assert out.count("/s/") == 1


@pytest.mark.parametrize(
    "location,expected",
    [
        ("http://internal.test/dashboard/reports", "/s/dashboard/reports"),
        ("http://internal.test", "/s/"),
        ("/dashboard/reports", "/s/dashboard/reports"),
        ("https://evil.example/phish", "/s/"),
        ("//evil.example/phish", "/s/"),
        ("reports", "reports"),
        ("", ""),
    ],
)
def test_location_rewriting(location, expected):
    assert proxy.rewrite_location(location, upstream_url="http://internal.test") == expected


def test_banner_goes_inside_body_and_carries_the_csrf_token():
    out = proxy.inject_banner(
        b"<html><body><h1>hi</h1></body></html>", csrf_token="csrf-value"
    ).decode()
    assert out.index("vg-bar") > out.index("<body>")
    assert out.index("vg-bar") < out.index("<h1>")
    assert 'value="csrf-value"' in out


# --- audit log scrubbing ---------------------------------------------------- #

def test_audit_detail_refuses_anything_that_looks_like_a_secret():
    assert _scrub("GET /dashboard/overview") == "GET /dashboard/overview"
    assert _scrub("password=hunter2") == "[redacted]"
    assert _scrub("token=abc") == "[redacted]"
    assert _scrub(None) is None
    assert len(_scrub("x" * 900)) == 512


# --- rate limiting ---------------------------------------------------------- #

def test_rate_limiter_allows_then_blocks():
    limiter = SlidingWindowLimiter(limit=3, window_seconds=60)
    assert [limiter.check("1.2.3.4") for _ in range(4)] == [True, True, True, False]
    assert limiter.check("5.6.7.8") is True
    assert limiter.retry_after("1.2.3.4") > 0
    limiter.reset("1.2.3.4")
    assert limiter.check("1.2.3.4") is True
