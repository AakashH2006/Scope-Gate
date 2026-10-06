"""Configuration: everything comes from the environment (section 11 of the plan).

A ``.env`` file in the working directory is loaded first, for convenience during
local development.  Real deployments set real environment variables; secrets are
never read from the repository.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


def load_dotenv(path: str | os.PathLike[str] = ".env") -> None:
    """Minimal ``.env`` loader.  Existing environment variables always win."""
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _csv(name: str, default: str) -> list[str]:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        raw = default
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    # --- identity / front door -------------------------------------------------
    public_url: str = ""
    database_url: str = ""
    secret_key: str = ""
    totp_enc_key: str = ""

    # --- clocks ---------------------------------------------------------------
    link_ttl_minutes: int = 180          # link validity before the first login
    max_access_minutes: int = 480        # upper bound on what an admin may grant
    expiry_tick_seconds: int = 2         # how often the expiry job runs

    # --- vendor login ---------------------------------------------------------
    max_login_attempts: int = 5
    vendor_password_length: int = 16
    login_rate_per_minute: int = 10      # per client IP

    # --- admin ----------------------------------------------------------------
    admin_idle_timeout_minutes: int = 20
    admin_rate_per_minute: int = 10

    # --- proxy ----------------------------------------------------------------
    upstream_url: str = "http://127.0.0.1:9000"
    allowed_pages: list[str] = field(default_factory=list)
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "HEAD"])
    max_request_bytes: int = 1_048_576
    upstream_timeout_seconds: int = 20
    inject_banner: bool = True

    # --- logging --------------------------------------------------------------
    log_dashboard_days: int = 7
    log_retention_days: int = 365

    # --- email ----------------------------------------------------------------
    mail_backend: str = "file"           # file | console | smtp
    mail_outbox_dir: str = "outbox"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    mail_from: str = ""

    # --- runtime flags --------------------------------------------------------
    secure_cookies: bool = True          # False only for plain-HTTP local runs
    trust_forwarded_for: bool = True     # we sit behind Caddy

    @property
    def is_postgres(self) -> bool:
        return self.database_url.startswith("postgresql")


def build_settings() -> Settings:
    """Read settings from the environment, filling safe local defaults."""
    load_dotenv()
    load_dotenv("mail.env")

    secret_key = os.getenv("SECRET_KEY") or ""
    if not secret_key:
        # Ephemeral key: fine for a dev run (sessions die on restart), never for
        # a deployment -- the startup check in app.py refuses this in production.
        secret_key = secrets.token_urlsafe(48)

    return Settings(
        public_url=os.getenv("PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/"),
        database_url=os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./vendorgate.db"),
        secret_key=secret_key,
        totp_enc_key=os.getenv("TOTP_ENC_KEY", ""),
        link_ttl_minutes=_int("LINK_TTL_MINUTES", 180),
        max_access_minutes=_int("MAX_ACCESS_MINUTES", 480),
        expiry_tick_seconds=_int("EXPIRY_TICK_SECONDS", 2),
        max_login_attempts=_int("MAX_LOGIN_ATTEMPTS", 5),
        vendor_password_length=_int("VENDOR_PASSWORD_LENGTH", 16),
        login_rate_per_minute=_int("LOGIN_RATE_PER_MINUTE", 10),
        admin_idle_timeout_minutes=_int("ADMIN_IDLE_TIMEOUT_MINUTES", 20),
        admin_rate_per_minute=_int("ADMIN_RATE_PER_MINUTE", 10),
        upstream_url=os.getenv("UPSTREAM_URL", "http://127.0.0.1:9000").rstrip("/"),
        allowed_pages=_csv(
            "ALLOWED_PAGES",
            "/dashboard/overview,/dashboard/reports,/dashboard/tickets",
        ),
        allowed_methods=[m.upper() for m in _csv("ALLOWED_METHODS", "GET,HEAD")],
        max_request_bytes=_int("MAX_REQUEST_BYTES", 1_048_576),
        upstream_timeout_seconds=_int("UPSTREAM_TIMEOUT_SECONDS", 20),
        inject_banner=_bool("INJECT_BANNER", True),
        log_dashboard_days=_int("LOG_DASHBOARD_DAYS", 7),
        log_retention_days=_int("LOG_RETENTION_DAYS", 365),
        mail_backend=os.getenv("MAIL_BACKEND", "file").strip().lower(),
        mail_outbox_dir=os.getenv("MAIL_OUTBOX_DIR", "outbox"),
        smtp_host=os.getenv("SMTP_HOST", ""),
        smtp_port=_int("SMTP_PORT", 587),
        smtp_user=os.getenv("SMTP_USER", ""),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        mail_from=os.getenv("MAIL_FROM", os.getenv("SMTP_USER", "vendorgate@localhost")),
        secure_cookies=_bool("SECURE_COOKIES", not os.getenv("PUBLIC_URL", "").startswith("http://")),
        trust_forwarded_for=_bool("TRUST_FORWARDED_FOR", True),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return build_settings()
