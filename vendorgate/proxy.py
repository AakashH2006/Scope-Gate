"""Reverse proxy -- section 6.6 of the plan.

Rules enforced here, in this order:

1. method allowlist (default ``GET``/``HEAD`` -- read only)
2. path allowlist from the grant (prefix match, after normalisation)
3. nothing of the vendor's browser state reaches the internal site
4. nothing about the internal site reaches the vendor's browser

The caller has already checked session, grant status and the clock.
"""
from __future__ import annotations

import logging
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .config import Settings

log = logging.getLogger("vendorgate.proxy")

#: Where the proxied area lives in the gateway's own URL space.
MOUNT = "/s"

#: Never forwarded in either direction (RFC 9110 connection-specific headers).
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

#: Stripped from the vendor's request: browser state and anything that would
#: tell the internal site about the gateway's own session or the token URL.
REQUEST_DROP = HOP_BY_HOP | {
    "cookie",
    "cookie2",
    "authorization",
    "referer",
    "origin",
    "host",
    "content-length",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "forwarded",
}

#: Stripped from the internal site's response: anything that leaks the internal
#: stack, and any attempt to set a cookie in the vendor's browser.
RESPONSE_DROP = HOP_BY_HOP | {
    "set-cookie",
    "set-cookie2",
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "via",
    "x-served-by",
    "x-backend-server",
    "x-upstream",
    "x-internal-host",
    "x-request-id",
    "alt-svc",
    "public-key-pins",
    "content-encoding",  # httpx hands us decoded bytes
    "content-length",    # recomputed after rewriting
    "date",              # our own server sets this; forwarding it duplicates it
    "strict-transport-security",  # the gateway's own front door owns HSTS
}

#: Added to every proxied response.
SECURITY_HEADERS = {
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
}

#: Content types whose bodies get URL rewriting.
REWRITABLE_TYPES = ("text/html", "text/css", "application/javascript", "text/javascript")

CSP_FOR_HTML = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "object-src 'none'"
)


class ProxyDenied(Exception):
    """The request is outside what this grant may reach."""

    def __init__(self, reason: str, *, status: int = 403) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class ProxyDecision:
    """Outcome of the allowlist check for one request."""

    upstream_path: str   # normalised path to request from the internal site
    matched_prefix: str


# --------------------------------------------------------------------------- #
# the allowlist
# --------------------------------------------------------------------------- #

def normalise_path(raw: str) -> str:
    """Collapse ``.``/``..``/duplicate slashes and guarantee a leading slash.

    Done before the allowlist check so ``/dashboard/overview/../finance`` cannot
    sneak past a prefix match.
    """
    path = raw or "/"
    if not path.startswith("/"):
        path = "/" + path
    # POSIX keeps a leading "//" meaningful and normpath preserves it; for a URL
    # path it is just a duplicate separator, so collapse it first.
    path = "/" + path.lstrip("/")
    # normpath removes a trailing slash; keep the caller's intent.
    trailing = path.endswith("/") and len(path) > 1
    path = posixpath.normpath(path)
    if path == "." or not path.startswith("/"):
        path = "/"
    path = "/" + path.lstrip("/")
    if trailing and not path.endswith("/"):
        path += "/"
    return path


def path_allowed(path: str, allowed_prefixes: list[str]) -> str | None:
    """Return the matching prefix, or ``None``.

    A prefix matches the page itself and anything below it, but never a sibling
    whose name merely starts with the same characters -- ``/dashboard/report``
    does not open ``/dashboard/reports-secret``.
    """
    for prefix in allowed_prefixes:
        clean = "/" + (prefix or "").strip("/")
        if path == clean:
            return prefix
        if path.startswith(clean + "/"):
            return prefix
    return None


def check_request(
    *, method: str, path: str, allowed_prefixes: list[str], settings: Settings
) -> ProxyDecision:
    upper = method.upper()
    if upper not in settings.allowed_methods:
        raise ProxyDenied(f"method {upper} is not permitted (read-only access)", status=405)

    normalised = normalise_path(path)
    matched = path_allowed(normalised, allowed_prefixes)
    if matched is None:
        raise ProxyDenied(f"path {normalised} is not in this grant")
    return ProxyDecision(upstream_path=normalised, matched_prefix=matched)


# --------------------------------------------------------------------------- #
# header handling
# --------------------------------------------------------------------------- #

def filter_request_headers(headers: dict[str, str] | httpx.Headers) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in dict(headers).items():
        if name.lower() in REQUEST_DROP:
            continue
        out[name] = value
    # The internal site sees a plain, anonymous client.
    out.setdefault("Accept-Encoding", "identity")
    return out


def filter_response_headers(headers: httpx.Headers, *, is_html: bool) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in headers.multi_items():
        if name.lower() in RESPONSE_DROP:
            continue
        out[name] = value
    out.update(SECURITY_HEADERS)
    if is_html:
        out["Content-Security-Policy"] = CSP_FOR_HTML
    return out


# --------------------------------------------------------------------------- #
# body / URL rewriting
# --------------------------------------------------------------------------- #

def _upstream_variants(upstream_url: str) -> list[str]:
    """Spellings of the internal site that might appear in a response body."""
    split = urlsplit(upstream_url)
    host = split.hostname or ""
    port = f":{split.port}" if split.port else ""
    variants = [upstream_url.rstrip("/")]
    if host:
        for scheme in ("http", "https"):
            variants.append(f"{scheme}://{host}{port}")
            variants.append(f"{scheme}://{host}")
        variants.append(f"//{host}{port}")
    # Longest first, so the fuller spelling is replaced before its prefix.
    return sorted({v for v in variants if v}, key=len, reverse=True)


_ATTR_RE = re.compile(
    r"""(?P<attr>\b(?:href|src|action|poster|formaction|data|srcset)\s*=\s*)(?P<q>["'])(?P<url>/(?!/)[^"']*)(?P=q)""",
    re.IGNORECASE,
)
_CSS_URL_RE = re.compile(
    r"""url\(\s*(?P<q>["']?)(?P<url>/(?!/)[^"')]*)(?P=q)\s*\)""", re.IGNORECASE
)


def _already_mounted(url: str) -> bool:
    return url == MOUNT or url.startswith(MOUNT + "/")


def _prefix_attr(m: re.Match[str]) -> str:
    url = m.group("url")
    if _already_mounted(url):
        return m.group(0)
    return f"{m.group('attr')}{m.group('q')}{MOUNT}{url}{m.group('q')}"


def _prefix_css_url(m: re.Match[str]) -> str:
    url = m.group("url")
    if _already_mounted(url):
        return m.group(0)
    return f"url({m.group('q')}{MOUNT}{url}{m.group('q')})"


def rewrite_body(body: bytes, *, upstream_url: str, charset: str = "utf-8") -> bytes:
    """Keep every link inside the gateway and strip internal addresses.

    Root-relative references get the ``/s`` prefix first, then absolute
    references to the internal site are collapsed onto ``/s/...``.  That order
    matters: rewriting the absolute form first would leave a ``/s/...`` path for
    the second pass to prefix a second time.  Relative links ("reports") already
    resolve inside ``/s/`` and need nothing.
    """
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        charset = "utf-8"
        text = body.decode("utf-8", errors="replace")

    text = _ATTR_RE.sub(_prefix_attr, text)
    text = _CSS_URL_RE.sub(_prefix_css_url, text)

    for variant in _upstream_variants(upstream_url):
        text = text.replace(variant + "/", MOUNT + "/")
        text = text.replace(variant, MOUNT + "/")

    return text.encode(charset, errors="replace")


#: An anchor with an href, captured so the link can be judged against the grant.
#: Nesting an <a> inside an <a> is invalid HTML, so the first </a> really is the
#: matching one and a non-greedy body is safe.
_ANCHOR_RE = re.compile(
    r"""<a\b(?P<pre>[^>]*?)href\s*=\s*(?P<q>["'])(?P<url>[^"']*)(?P=q)"""
    r"""(?P<post>[^>]*)>(?P<inner>.*?)</a\s*>""",
    re.IGNORECASE | re.DOTALL,
)

#: A link whose body holds one of these is unwrapped rather than deleted, so a
#: logo or icon does not vanish along with the link around it.
_KEEP_INNER_RE = re.compile(r"<(?:img|svg|picture|video)\b", re.IGNORECASE)

BLOCKED_LINK_MODES = ("remove", "disable", "keep")


def hide_blocked_links(
    body: bytes,
    *,
    allowed_prefixes: list[str],
    mode: str = "remove",
    charset: str = "utf-8",
) -> bytes:
    """Take the links a vendor may not follow out of a proxied page.

    The internal site renders its whole navigation, so a vendor granted one
    page still reads the names of every other one -- "Finance", "Users" --
    which is information the grant never meant to hand over.

    ``remove``   drop the link and its text entirely (the default)
    ``disable``  keep the text, drop the href, grey it out
    ``keep``     leave it alone, and let the allowlist refuse the click

    This is defence in depth and nothing more.  It reduces what a vendor
    learns and what they click by accident; it is **not** the control.  A
    vendor who types the path still meets :func:`check_request`, which is
    where access is actually decided.

    Only absolute ``/s/...`` targets are judged -- that is what
    :func:`rewrite_body` produces from root-relative and absolute upstream
    links.  A relative href is left alone, because resolving it needs the
    current request path and getting that wrong would break a working link.
    """
    if mode not in BLOCKED_LINK_MODES or mode == "keep":
        return body
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        charset = "utf-8"
        text = body.decode("utf-8", errors="replace")

    def judge(m: re.Match[str]) -> str:
        url = m.group("url")
        if not (url == MOUNT or url.startswith(MOUNT + "/")):
            return m.group(0)  # external, relative, or an anchor/mailto link
        path = normalise_path(url[len(MOUNT) :] or "/")
        # Drop a query or fragment before matching the prefix.
        path = path.split("?", 1)[0].split("#", 1)[0]
        if path_allowed(path, allowed_prefixes) is not None:
            return m.group(0)
        inner = m.group("inner")
        if mode == "disable":
            return (
                '<span style="opacity:.45;cursor:not-allowed" '
                'title="Not part of your access">' + inner + "</span>"
            )
        if _KEEP_INNER_RE.search(inner):
            # Keep the picture, lose the link.
            return inner
        return ""

    return _ANCHOR_RE.sub(judge, text).encode(charset, errors="replace")


def rewrite_location(location: str, *, upstream_url: str) -> str:
    """Rewrite a ``Location`` header so a redirect stays inside the gateway.

    Anything pointing somewhere other than the internal site is dropped: a
    redirect to a third-party host would take the vendor out of the gateway and
    carry the referrer with them.
    """
    if not location:
        return location
    for variant in _upstream_variants(upstream_url):
        if location.startswith(variant):
            rest = location[len(variant) :] or "/"
            if not rest.startswith("/"):
                rest = "/" + rest
            return MOUNT + rest
    if location.startswith("//"):
        # Protocol-relative URL to some other host: refuse to follow it.
        return MOUNT + "/"
    if location.startswith("/"):
        return MOUNT + location
    split = urlsplit(location)
    if split.scheme or split.netloc:
        # Absolute URL to some other host: refuse to follow it.
        return MOUNT + "/"
    return location  # relative -- already resolves inside /s/


def response_charset(content_type: str) -> str:
    for part in content_type.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "charset":
            return value.strip().strip('"') or "utf-8"
    return "utf-8"


def is_rewritable(content_type: str) -> bool:
    base = content_type.split(";")[0].strip().lower()
    return any(base == t or base.endswith("+" + t.split("/")[-1]) for t in REWRITABLE_TYPES)


def is_html(content_type: str) -> bool:
    return content_type.split(";")[0].strip().lower() in ("text/html", "application/xhtml+xml")


# --------------------------------------------------------------------------- #
# the countdown banner (convenience only -- section 6.5)
# --------------------------------------------------------------------------- #

BANNER_TEMPLATE = """
<div id="vg-bar" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;
 font:13px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:#111827;color:#f9fafb;
 padding:7px 14px;display:flex;gap:14px;align-items:center;box-shadow:0 1px 4px rgba(0,0,0,.3)">
  <strong style="font-weight:600">Temporary vendor access</strong>
  <span id="vg-left" style="font-variant-numeric:tabular-nums">--:--</span>
  <span style="flex:1"></span>
  <form method="post" action="/s/logout" style="margin:0">
    <input type="hidden" name="csrf" value="__CSRF__">
    <button style="background:#374151;color:#f9fafb;border:1px solid #4b5563;border-radius:4px;
     padding:3px 10px;cursor:pointer;font:inherit">End session</button>
  </form>
</div>
<div style="height:34px"></div>
<script>
(function(){
  var el=document.getElementById('vg-left');
  function fmt(s){var m=Math.floor(s/60),x=s%60;return m+':'+(x<10?'0':'')+x;}
  function tick(){
    fetch('/s/_status',{cache:'no-store'}).then(function(r){
      if(!r.ok){location.reload();return;}
      return r.json();
    }).then(function(d){
      if(!d)return;
      if(d.seconds_left<=0){location.reload();return;}
      el.textContent=fmt(d.seconds_left)+' left';
    }).catch(function(){});
  }
  tick();setInterval(tick,5000);
})();
</script>
"""


def inject_banner(body: bytes, *, csrf_token: str, charset: str = "utf-8") -> bytes:
    """Put the countdown bar just inside ``<body>``.

    If there is no ``<body>`` the bar is prepended; a page that is not really
    HTML never reaches here (the content type is checked first).
    """
    banner = BANNER_TEMPLATE.replace("__CSRF__", csrf_token)
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        charset = "utf-8"
        text = body.decode("utf-8", errors="replace")

    match = re.search(r"<body[^>]*>", text, re.IGNORECASE)
    if match:
        at = match.end()
        text = text[:at] + banner + text[at:]
    else:
        text = banner + text
    return text.encode(charset, errors="replace")
