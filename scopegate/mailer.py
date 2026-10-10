"""Email sending -- section 9 of the plan.

Three backends, chosen with ``MAIL_BACKEND``:

``smtp``     real delivery over TLS (Gmail app password for the demo, SES later)
``file``     writes the message to ``outbox/`` as an ``.eml`` file (default for
             local runs, so the whole flow is demonstrable without a mail server)
``console``  prints the message

Sending always happens on a worker thread: a slow mail server must never hold up
a request.  The result comes back through a callback that writes the
``email_sent`` / ``email_failed`` audit event.

A failed send is retried on that same thread, up to ``MAIL_RETRY_ATTEMPTS``
times with a doubling gap, and only the final outcome is reported -- one audit
row per invite, whatever happened in between.  The retry deliberately keeps the
rendered message in memory and nowhere else: it holds the vendor's password, so
a durable queue would put a live credential at rest.  The cost is that a restart
mid-retry forgets the invite, which is what the admin's Resend button is for.
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
    """Plain-text only: no tracking pixels, no external images (section 9).

    Laid out for a mail client that renders text/plain in a proportional font,
    which Gmail does: upper-case section headings and one fact per line, rather
    than space-aligned columns that would come out ragged.  The link sits alone
    on its line so clients auto-link it without swallowing punctuation.
    """
    pages = "\n".join(f"  - {p}" for p in invite.allowed_paths)
    expires = invite.link_expires_at.strftime("%Y-%m-%d %H:%M UTC")
    duration = _format_duration(invite.duration_minutes)
    body = f"""Hello,

You have been given access to a few pages of an internal web application, for
a limited time. There is nothing to install -- a browser is all you need.


YOUR LINK

{invite.link}


SIGNING IN

Email address: {invite.vendor_email}
Password: {invite.password}

Open the link before {expires}, or it stops working and you
will need a new one.

Your access then lasts {duration}, counted from the moment you sign in
rather than from now.

The first browser to sign in keeps the access. A later sign-in from anywhere
else is refused, so use the device you mean to work on.


WHAT YOU CAN REACH

{pages}

Nothing else is reachable, and this is not network or VPN access.


If the link has expired, or you need more time or another page, reply to the
person who arranged this access -- they can issue a new one.

-- ScopeGate
"""
    msg = EmailMessage()
    msg["Subject"] = "Your temporary access link"
    msg["To"] = invite.vendor_email
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="scopegate.local")
    msg.set_content(body)
    return msg


def verify_smtp_login(settings: Settings) -> tuple[bool, str]:
    """Check the SMTP credentials without sending a message.

    Pins a single auth mechanism deliberately.  ``smtplib.login`` walks the
    server's advertised list, so a PLAIN rejected with 535 is retried as LOGIN,
    Gmail hangs up, and the useful reason is replaced by a bare
    ``SMTPServerDisconnected``.  One mechanism keeps the server's own text --
    and unlike ``set_debuglevel``, nothing here logs the credentials.
    """
    if settings.mail_backend != "smtp":
        return False, f"MAIL_BACKEND is {settings.mail_backend!r}, not 'smtp': nothing to check"
    if not settings.smtp_host:
        return False, "SMTP_HOST is not set"
    if not settings.smtp_user:
        return False, "SMTP_USER is not set"
    if not settings.smtp_password:
        return False, "SMTP_PASSWORD is not set"

    target = f"{settings.smtp_host}:{settings.smtp_port} as {settings.smtp_user}"
    context = ssl.create_default_context()
    try:
        if settings.smtp_port == 465:
            smtp = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, context=context, timeout=30
            )
        else:
            smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30)
        with smtp:
            smtp.ehlo()
            if settings.smtp_port != 465:
                smtp.starttls(context=context)
                smtp.ehlo()
            smtp.user, smtp.password = settings.smtp_user, settings.smtp_password
            try:
                smtp.auth("PLAIN", smtp.auth_plain)
            except smtplib.SMTPResponseException as exc:
                reason = exc.smtp_error
                if isinstance(reason, bytes):
                    reason = reason.decode(errors="replace")
                return False, f"{target}: rejected {exc.smtp_code}: {reason}"
    except Exception as exc:  # noqa: BLE001 -- the reason is the whole point
        return False, f"{target}: {type(exc).__name__}: {exc}"
    return True, f"{target}: login accepted, nothing was sent"


class Mailer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.backend = settings.mail_backend
        self._threads: list[threading.Thread] = []
        # Set at shutdown so a thread waiting out a retry gap stops waiting.
        self._shutdown = threading.Event()

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
        """Same send, inline, retries included.  Used by the tests and the CLI."""
        msg = render_invite(invite)
        msg["From"] = self.settings.mail_from or "scopegate@localhost"
        return self._send_with_retries(msg)

    def join(self, timeout: float = 10.0) -> None:
        """Wait for sends in flight without cutting their retries short."""
        for thread in list(self._threads):
            thread.join(timeout)
        self._threads = [t for t in self._threads if t.is_alive()]

    def close(self, timeout: float = 10.0) -> None:
        """Abandon pending retries and wait for the threads to notice."""
        self._shutdown.set()
        self.join(timeout)

    # -- internals -------------------------------------------------------------

    def _send_and_report(self, msg: EmailMessage, on_done: SendCallback) -> None:
        ok, detail = self._send_with_retries(msg)
        try:
            on_done(ok, detail)
        except Exception:  # pragma: no cover -- never let the thread die loudly
            log.exception("mail callback failed")

    def _send_with_retries(self, msg: EmailMessage) -> tuple[bool, str]:
        """Attempt the send until it works or the attempts run out.

        Reports once, so the dashboard's mail-failure count stays a count of
        invites nobody received rather than of attempts.  The gap doubles
        because the usual causes (a rate limit, a mail server restarting) clear
        on their own given a little more time.
        """
        attempts = max(1, self.settings.mail_retry_attempts)
        for attempt in range(1, attempts + 1):
            ok, detail = self._send(msg)
            if ok:
                if attempt > 1:
                    return True, f"{detail} (attempt {attempt} of {attempts})"
                return True, detail
            if attempt == attempts:
                if attempts == 1:
                    return False, detail
                return False, f"{detail} (gave up after {attempts} attempts)"
            delay = self.settings.mail_retry_backoff_seconds * 2 ** (attempt - 1)
            log.warning(
                "mail attempt %d of %d failed, retrying in %ds: %s",
                attempt,
                attempts,
                delay,
                detail,
            )
            if self._shutdown.wait(delay):
                return False, f"{detail} (attempt {attempt} of {attempts}, shutting down)"
        raise AssertionError("unreachable")  # pragma: no cover

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
