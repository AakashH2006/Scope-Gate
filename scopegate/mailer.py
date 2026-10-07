"""Email sending -- section 9 of the plan.

Three backends, chosen with ``MAIL_BACKEND``:

``smtp``     real delivery over TLS (Gmail app password for the demo, SES later)
``file``     writes the message to ``outbox/`` as an ``.eml`` file (default for
             local runs, so the whole flow is demonstrable without a mail server)
``console``  prints the message

Sending always happens on a worker thread: a slow mail server must never hold up
a request.  The result comes back through a callback that writes the
``email_sent`` / ``email_failed`` audit event.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Callable

from .config import Settings

log = logging.getLogger("scopegate.mail")

#: Called as ``callback(ok, detail)`` once the send attempt finishes.
SendCallback = Callable[[bool, str], None]


@dataclass(frozen=True)
class VendorInvite:
    vendor_email: str
    link: str
    password: str
    link_expires_at: datetime
    duration_minutes: int
    allowed_paths: list[str]
    public_url: str


def _format_duration(minutes: int) -> str:
    if minutes < 60:
        return f"{minutes} minutes"
    hours, rest = divmod(minutes, 60)
    if rest == 0:
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    return f"{hours}h {rest}m"


def render_invite(invite: VendorInvite) -> EmailMessage:
    """Plain-text only: no tracking pixels, no external images (section 9)."""
    pages = "\n".join(f"  - {p}" for p in invite.allowed_paths)
    expires = invite.link_expires_at.strftime("%Y-%m-%d %H:%M UTC")
    body = f"""Hello,

You have been given temporary access to a small number of pages of an internal
web application. You do not need to install anything -- a browser is enough.

Your link:
  {invite.link}

Your password:
  {invite.password}

How it works:
  - Open the link and sign in with your email address ({invite.vendor_email})
    and the password above.
  - The link must be used before {expires}. After that it stops working.
  - Once you sign in, your access lasts {_format_duration(invite.duration_minutes)}.
    The clock starts at sign-in, not now.
  - The link works on one device only: whichever browser signs in first.
  - You will be able to reach these pages and nothing else:
{pages}

If the link has expired or you need more time, reply to the person who arranged
this access and they can issue a new link.

-- ScopeGate
"""
    msg = EmailMessage()
    msg["Subject"] = "Your temporary access link"
    msg["To"] = invite.vendor_email
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="scopegate.local")
    msg.set_content(body)
    return msg


class Mailer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.backend = settings.mail_backend
        self._threads: list[threading.Thread] = []

    # -- public API ------------------------------------------------------------

    def send_invite_async(self, invite: VendorInvite, on_done: SendCallback) -> None:
        msg = render_invite(invite)
        msg["From"] = self.settings.mail_from or "scopegate@localhost"
        thread = threading.Thread(
            target=self._send_and_report,
            args=(msg, on_done),
            name="scopegate-mail",
            daemon=True,
        )
        self._threads.append(thread)
        thread.start()

    def send_invite_blocking(self, invite: VendorInvite) -> tuple[bool, str]:
        """Same send, inline.  Used by the tests and the CLI."""
        msg = render_invite(invite)
        msg["From"] = self.settings.mail_from or "scopegate@localhost"
        return self._send(msg)

    def join(self, timeout: float = 10.0) -> None:
        for thread in list(self._threads):
            thread.join(timeout)
        self._threads = [t for t in self._threads if t.is_alive()]

    # -- internals -------------------------------------------------------------

    def _send_and_report(self, msg: EmailMessage, on_done: SendCallback) -> None:
        ok, detail = self._send(msg)
        try:
            on_done(ok, detail)
        except Exception:  # pragma: no cover -- never let the thread die loudly
            log.exception("mail callback failed")

    def _send(self, msg: EmailMessage) -> tuple[bool, str]:
        try:
            if self.backend == "smtp":
                return self._send_smtp(msg)
            if self.backend == "console":
                print("----- ScopeGate outgoing mail -----")
                print(msg.get_content())
                print("-----------------------------------")
                return True, "console backend"
            return self._send_file(msg)
        except Exception as exc:  # noqa: BLE001 -- the reason goes to the audit log
            log.warning("mail send failed: %s: %s", type(exc).__name__, exc)
            return False, f"{type(exc).__name__}: {exc}"

    def _send_file(self, msg: EmailMessage) -> tuple[bool, str]:
        outbox = Path(self.settings.mail_outbox_dir)
        outbox.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        safe_to = "".join(c if c.isalnum() or c in "._-@" else "_" for c in msg["To"])
        path = outbox / f"{stamp}-{safe_to}.eml"
        path.write_text(msg.as_string(), encoding="utf-8")
        log.info("invite written to %s", path)
        return True, f"file backend: {path.name}"

    def _send_smtp(self, msg: EmailMessage) -> tuple[bool, str]:
        s = self.settings
        if not s.smtp_host:
            raise RuntimeError("SMTP_HOST is not configured")
        context = ssl.create_default_context()
        if s.smtp_port == 465:
            with smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, context=context, timeout=30) as smtp:
                if s.smtp_user:
                    smtp.login(s.smtp_user, s.smtp_password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                if s.smtp_user:
                    smtp.login(s.smtp_user, s.smtp_password)
                smtp.send_message(msg)
        return True, f"smtp {s.smtp_host}:{s.smtp_port}"
