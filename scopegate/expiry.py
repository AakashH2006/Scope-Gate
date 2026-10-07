"""Background jobs -- section 6.5 (expiry) and section 10 (retention).

One asyncio task, started with the app and cancelled on shutdown.  It does two
things on different cadences:

* every ``EXPIRY_TICK_SECONDS``: move finished grants to their final state, drop
  their sessions, and close any connection that is still open
* once an hour: delete audit rows past ``LOG_RETENTION_DAYS``
"""
from __future__ import annotations

import asyncio
import logging
import time

from .config import Settings
from .connections import LiveConnections
from .db import session_scope
from .events import log_event, prune_events
from .grants import sweep_expired
from .models import EventType

log = logging.getLogger("scopegate.expiry")

RETENTION_INTERVAL_SECONDS = 3600


class ExpiryWorker:
    def __init__(self, settings: Settings, live: LiveConnections) -> None:
        self.settings = settings
        self.live = live
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._last_retention = 0.0
        self.ticks = 0

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop = asyncio.Event()
            self._task = asyncio.create_task(self._run(), name="scopegate-expiry")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _run(self) -> None:
        log.info("expiry worker started (tick=%ss)", self.settings.expiry_tick_seconds)
        while not self._stop.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 -- a bad tick must not kill the loop
                log.exception("expiry tick failed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self.settings.expiry_tick_seconds
                )
            except asyncio.TimeoutError:
                continue
        log.info("expiry worker stopped")

    async def run_once(self) -> None:
        self.ticks += 1
        async with session_scope() as db:
            result = await sweep_expired(db, live=self.live)
        if result.total:
            log.info(
                "swept grants: %d expired, %d unused links, %d connection(s) closed",
                result.expired,
                result.expired_unused,
                result.connections_closed,
            )
        await self._maybe_prune()

    async def _maybe_prune(self) -> None:
        now = time.monotonic()
        if now - self._last_retention < RETENTION_INTERVAL_SECONDS:
            return
        self._last_retention = now
        async with session_scope() as db:
            removed = await prune_events(db, retention_days=self.settings.log_retention_days)
            if removed:
                await log_event(
                    db,
                    type=EventType.retention_pruned,
                    actor="system",
                    detail=(
                        f"removed {removed} event row(s) older than "
                        f"{self.settings.log_retention_days} days"
                    ),
                )
        if removed:
            log.info("retention job removed %d event row(s)", removed)
