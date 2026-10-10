"""Operator commands.

    python -m scopegate.cli init-db
    python -m scopegate.cli migrate
    python -m scopegate.cli create-admin --email you@company.example
    python -m scopegate.cli keys
    python -m scopegate.cli show-config
    python -m scopegate.cli check-mail
    python -m scopegate.cli reset-admin-totp --email you@company.example

``create-admin`` prints the generated password and the authenticator secret once.
They are not stored in the clear and cannot be shown again.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from dataclasses import replace
from pathlib import Path

from sqlalchemy import select

from .config import Settings, get_settings
from .db import (
    alembic_head_revision,
    create_all,
    dispose_engine,
    init_engine,
    session_scope,
)
from .mailer import verify_smtp_login
from .models import Admin, utcnow
from .security import (
    derive_fernet_key_from_secret,
    encrypt_totp_secret,
    generate_password,
    generate_totp_enc_key,
    generate_totp_secret,
    hash_password,
    totp_provisioning_uri,
)


def _with_dev_totp_key(settings: Settings) -> Settings:
    if settings.totp_enc_key:
        return settings
    return replace(
        settings, totp_enc_key=derive_fernet_key_from_secret(settings.secret_key)
    )


async def _init_db(settings: Settings) -> None:
    """Create the schema for a fresh database and stamp the Alembic revision."""
    init_engine(settings)
    try:
        await create_all()
        head = alembic_head_revision()
        print(f"Tables created or already present in {settings.database_url}")
        if head:
            print(f"Schema is at Alembic revision {head}")
    finally:
        await dispose_engine()


def _migrate() -> None:
    """Apply any pending migrations -- the path for an existing database."""
    from alembic import command
    from alembic.config import Config

    ini = Path(__file__).resolve().parent.parent / "alembic.ini"
    if not ini.is_file():
        print(f"No alembic.ini at {ini}", file=sys.stderr)
        raise SystemExit(1)
    command.upgrade(Config(str(ini)), "head")
    print("Migrations applied.")


async def _create_admin(settings: Settings, email: str, password: str | None) -> None:
    init_engine(settings)
    try:
        await create_all()
        email = email.strip().lower()
        async with session_scope() as db:
            existing = (
                await db.execute(select(Admin).where(Admin.email == email))
            ).scalar_one_or_none()
            if existing is not None:
                print(f"An admin with the email {email} already exists.", file=sys.stderr)
                raise SystemExit(1)

            generated = password is None
            password = password or generate_password(18)
            secret = generate_totp_secret()
            admin = Admin(
                email=email,
                password_hash=hash_password(password),
                totp_secret_enc=encrypt_totp_secret(settings.totp_enc_key, secret),
                created_at=utcnow(),
            )
            db.add(admin)

        print()
        print("Admin created.")
        print(f"  email            {email}")
        if generated:
            print(f"  password         {password}")
        else:
            print("  password         (the one you typed)")
        print(f"  TOTP secret      {secret}")
        print(f"  provisioning URI {totp_provisioning_uri(secret, email)}")
        print()
        print("Add the provisioning URI (or the secret) to an authenticator app now.")
        print("Neither the password nor the secret can be shown again.")
        import os

        if not os.getenv("TOTP_ENC_KEY"):
            print("WARNING: TOTP_ENC_KEY was not set; a development key was derived")
            print("         from SECRET_KEY. Set both before deploying, and create")
            print("         the admin again -- this secret cannot be decrypted with")
            print("         a different SECRET_KEY.")
    finally:
        await dispose_engine()


async def _reset_totp(settings: Settings, email: str) -> None:
    init_engine(settings)
    try:
        email = email.strip().lower()
        async with session_scope() as db:
            admin = (
                await db.execute(select(Admin).where(Admin.email == email))
            ).scalar_one_or_none()
            if admin is None:
                print(f"No admin with the email {email}.", file=sys.stderr)
                raise SystemExit(1)
            secret = generate_totp_secret()
            admin.totp_secret_enc = encrypt_totp_secret(settings.totp_enc_key, secret)
        print(f"New TOTP secret for {email}: {secret}")
        print(f"Provisioning URI: {totp_provisioning_uri(secret, email)}")
    finally:
        await dispose_engine()


def _keys() -> None:
    from secrets import token_urlsafe

    print("# Paste these into your .env (or the service environment):")
    print(f"SECRET_KEY={token_urlsafe(48)}")
    print(f"TOTP_ENC_KEY={generate_totp_enc_key()}")


def _show_config(settings: Settings) -> None:
    print("PUBLIC_URL        ", settings.public_url)
    print("DATABASE_URL      ", settings.database_url)
    print("UPSTREAM_URL      ", settings.upstream_url)
    print("ALLOWED_PAGES     ", ", ".join(settings.allowed_pages))
    print("ALLOWED_METHODS   ", ", ".join(settings.allowed_methods))
    print("LINK_TTL_MINUTES  ", settings.link_ttl_minutes)
    print("MAX_ACCESS_MINUTES", settings.max_access_minutes)
    print("MAX_LOGIN_ATTEMPTS", settings.max_login_attempts)
    print("MAIL_BACKEND      ", settings.mail_backend)
    if settings.mail_backend == "smtp":
        # Enough to tell a loaded SMTP block from a missing one, and to show which
        # address Gmail will rewrite From to.  The password is never printed.
        print("SMTP_HOST         ", settings.smtp_host or "(not set)")
        print("SMTP_PORT         ", settings.smtp_port)
        print("SMTP_USER         ", settings.smtp_user or "(not set)")
        print("SMTP_PASSWORD set  ", "yes" if settings.smtp_password else "no")
        print("MAIL_FROM         ", settings.mail_from or "(not set)")
    else:
        print("MAIL_OUTBOX_DIR   ", settings.mail_outbox_dir)
    print("MAIL_RETRY        ", f"{settings.mail_retry_attempts} attempts, "
          f"first gap {settings.mail_retry_backoff_seconds}s")
    print("LOG_DASHBOARD_DAYS", settings.log_dashboard_days)
    print("LOG_RETENTION_DAYS", settings.log_retention_days)
    print("SECURE_COOKIES    ", settings.secure_cookies)
    print("SECRET_KEY set     ", "yes" if settings.secret_key else "no")
    print("TOTP_ENC_KEY set   ", "yes" if settings.totp_enc_key else "no (dev key derived)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scopegate", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create the database tables for a fresh database")
    sub.add_parser("migrate", help="apply pending migrations (alembic upgrade head)")
    sub.add_parser("keys", help="print fresh SECRET_KEY and TOTP_ENC_KEY values")
    sub.add_parser("show-config", help="print the effective configuration")
    sub.add_parser(
        "check-mail",
        help="verify the SMTP credentials without sending a message",
    )

    create = sub.add_parser("create-admin", help="create the admin account")
    create.add_argument("--email", required=True)
    create.add_argument(
        "--ask-password",
        action="store_true",
        help="type the password instead of generating one",
    )

    reset = sub.add_parser("reset-admin-totp", help="issue a new authenticator secret")
    reset.add_argument("--email", required=True)

    args = parser.parse_args(argv)

    if args.command == "keys":
        _keys()
        return 0

    settings = _with_dev_totp_key(get_settings())

    if args.command == "show-config":
        _show_config(settings)
        return 0
    if args.command == "check-mail":
        ok, detail = verify_smtp_login(settings)
        print(detail)
        if not ok:
            # The two that actually happen, worth naming rather than looking up.
            print(
                "\n535 means the credentials are not valid for this account. A Gmail "
                "app\npassword only works for the account that created it, and that "
                "account needs\n2-Step Verification on. Signed in to several Google "
                "accounts at once? The app\npassword page acts on the default one, "
                "which may not be the one you meant."
            )
        return 0 if ok else 1
    if args.command == "init-db":
        asyncio.run(_init_db(settings))
        return 0
    if args.command == "migrate":
        _migrate()
        return 0
    if args.command == "create-admin":
        password = None
        if args.ask_password:
            password = getpass.getpass("Password: ")
            if password != getpass.getpass("Repeat: "):
                print("Passwords did not match.", file=sys.stderr)
                return 1
            if len(password) < 12:
                print("Use at least 12 characters.", file=sys.stderr)
                return 1
        asyncio.run(_create_admin(settings, args.email, password))
        return 0
    if args.command == "reset-admin-totp":
        asyncio.run(_reset_totp(settings, args.email))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
