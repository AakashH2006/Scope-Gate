"""Registry of live vendor connections, so expiry and revoke can cut them off.

Section 6.5 requires that the expiry job "closes open websocket / streaming
connections".  A streaming HTTP response or a websocket can outlive the
per-request authorisation check, so each one registers itself here and watches
an :class:`asyncio.Event` that the expiry job sets.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

log = logging.getLogger("vendorgate.connections")


class LiveConnections:
    """Per-grant kill switches for connections that are already open."""

    def __init__(self) -> None:
        self._events: dict[int, set[asyncio.Event]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def register(self, grant_id: int) -> asyncio.Event:
        event = asyncio.Event()
        async with self._lock:
            self._events[grant_id].add(event)
        return event

    async def unregister(self, grant_id: int, event: asyncio.Event) -> None:
        async with self._lock:
            bucket = self._events.get(grant_id)
            if bucket is None:
                return
            bucket.discard(event)
            if not bucket:
                self._events.pop(grant_id, None)

    async def close_grant(self, grant_id: int) -> int:
        """Signal every live connection for *grant_id*.  Returns how many."""
        async with self._lock:
            bucket = self._events.pop(grant_id, set())
        for event in bucket:
            event.set()
        if bucket:
            log.info("closed %d live connection(s) for grant %s", len(bucket), grant_id)
        return len(bucket)

    async def close_all(self) -> None:
        async with self._lock:
            buckets = list(self._events.values())
            self._events.clear()
        for bucket in buckets:
            for event in bucket:
                event.set()

    def count(self, grant_id: int | None = None) -> int:
        if grant_id is None:
            return sum(len(b) for b in self._events.values())
        return len(self._events.get(grant_id, ()))
