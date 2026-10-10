"""Automatic mail retry -- section 9.

The retry lives on the sending thread and holds the rendered invite in memory
only, so most of this drives the ``Mailer`` directly; the last two tests go
through the admin UI to pin down what reaches the audit log.
"""
from __future__ import annotations

import asyncio
import pathlib
import threading
import time
from dataclasses import replace
from datetime import timedelta

from sqlalchemy import select

from scopegate.config import Settings
from scopegate.db import session_scope
from scopegate.mailer import Mailer, VendorInvite
from scopegate.models import Event, utcnow


def _invite() -> VendorInvite:
    return VendorInvite(
        vendor_email="vendor@partner.example",
        link="http://testserver/" + "t" * 43,
        password="Vendor-Password-1",
        link_expires_at=utcnow() + timedelta(hours=3),
        duration_minutes=60,
        allowed_paths=["/dashboard/overview"],
        public_url="http://testserver",
    )


class _FlakyMailer(Mailer):
    """A mailer whose send fails the first ``failures`` times it is called."""

    def __init__(self, settings: Settings, *, failures: int) -> None:
        super().__init__(settings)
        self.failures = failures
        self.attempts = 0
        self.delivered: list[str] = []

    def _send(self, msg):  # type: ignore[override]
        self.attempts += 1
        if self.attempts <= self.failures:
            return False, f"ConnectionRefusedError: attempt {self.attempts}"
        self.delivered.append(msg["To"])
        return True, "stub backend"


async def _events(public_id: str) -> list[Event]:
    async with session_scope() as db:
        return list(
            (
                await db.execute(
                    select(Event)
                    .where(Event.grant_public_id == public_id)
                    .order_by(Event.id)
                )
            )
            .scalars()
            .all()
        )


# --------------------------------------------------------------------------- #
# the retry loop
# --------------------------------------------------------------------------- #

def test_a_failed_send_is_retried_and_succeeds(settings: Settings) -> None:
    mailer = _FlakyMailer(replace(settings, mail_retry_backoff_seconds=0), failures=1)

    ok, detail = mailer.send_invite_blocking(_invite())

    assert ok, detail
    assert mailer.attempts == 2
    assert mailer.delivered == ["vendor@partner.example"]
    # The report names the attempt, so the audit row says the first one failed.
    assert "attempt 2 of 3" in detail


def test_a_send_that_keeps_failing_gives_up_after_the_configured_attempts(
    settings: Settings,
) -> None:
    mailer = _FlakyMailer(replace(settings, mail_retry_backoff_seconds=0), failures=99)

    ok, detail = mailer.send_invite_blocking(_invite())

    assert not ok
    assert mailer.attempts == settings.mail_retry_attempts == 3
    assert mailer.delivered == []
    assert "gave up after 3 attempts" in detail


def test_one_attempt_configured_means_no_retry(settings: Settings) -> None:
    """``MAIL_RETRY_ATTEMPTS=1`` has to reproduce the old single-shot behaviour."""
    mailer = _FlakyMailer(
        replace(settings, mail_retry_attempts=1, mail_retry_backoff_seconds=0),
        failures=99,
    )

    ok, detail = mailer.send_invite_blocking(_invite())

    assert not ok
    assert mailer.attempts == 1
    # The backend's own reason, with nothing the retry loop added to it.
    assert detail == "ConnectionRefusedError: attempt 1"


def test_shutdown_interrupts_the_retry_gap(settings: Settings) -> None:
    """A thread waiting out a 30s gap must not hold shutdown for 30s."""
    mailer = _FlakyMailer(replace(settings, mail_retry_backoff_seconds=30), failures=99)
    reported: list[tuple[bool, str]] = []
    finished = threading.Event()

    def on_done(ok: bool, detail: str) -> None:
        reported.append((ok, detail))
        finished.set()

    started = time.monotonic()
    mailer.send_invite_async(_invite(), on_done)
    while mailer.attempts < 1:  # wait until the thread is inside the gap
        time.sleep(0.01)

    mailer.close(timeout=5.0)

    assert finished.wait(5.0), "the sending thread never reported"
    assert time.monotonic() - started < 10.0, "close() did not cut the retry gap short"
    ok, detail = reported[0]
    assert not ok
    assert "shutting down" in detail
    assert mailer.attempts == 1


# --------------------------------------------------------------------------- #
# what reaches the audit log
# --------------------------------------------------------------------------- #

def test_a_retried_invite_logs_one_sent_row_and_mails_once(
    client, admin, issue_grant, settings: Settings, monkeypatch
) -> None:
    mailer = client.app.state.mailer
    real_send = mailer._send
    calls = {"n": 0}

    def flaky(msg):
        calls["n"] += 1
        if calls["n"] == 1:
            return False, "ConnectionRefusedError: first attempt"
        return real_send(msg)

    monkeypatch.setattr(mailer, "_send", flaky)

    grant = issue_grant()
    mailer.join(timeout=5.0)

    types = [e.type for e in asyncio.run(_events(grant.public_id))]
    assert types.count("email_sent") == 1
    assert types.count("email_failed") == 0
    assert calls["n"] == 2
    # One message, not one per attempt.
    outbox = sorted(pathlib.Path(settings.mail_outbox_dir).glob("*.eml"))
    assert len(outbox) == 1


def test_a_send_that_keeps_failing_logs_exactly_one_failure(
    client, admin, issue_grant, settings: Settings, monkeypatch
) -> None:
    mailer = client.app.state.mailer
    monkeypatch.setattr(
        mailer, "_send", lambda msg: (False, "ConnectionRefusedError: nothing listening")
    )

    grant = issue_grant()
    mailer.join(timeout=5.0)

    events = asyncio.run(_events(grant.public_id))
    types = [e.type for e in events]
    assert types.count("email_failed") == 1, "one invite nobody received, one row"
    assert types.count("email_sent") == 0
    assert any("gave up after 3 attempts" in (e.detail or "") for e in events)
    # Nothing of the invite is written anywhere between attempts (section 6.7).
    assert all(grant.password not in (e.detail or "") for e in events)
    assert sorted(pathlib.Path(settings.mail_outbox_dir).glob("*.eml")) == []
