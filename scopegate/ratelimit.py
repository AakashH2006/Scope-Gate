"""In-process rate limiting for the login endpoints (section 6.2).

A single gateway process is the demo topology, so an in-memory sliding window is
enough.  More than one worker means this should move to the database or Redis;
that is noted in the deployment README.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: int = 60, max_keys: int = 20_000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        hits = self._hits[key]
        cutoff = now - self.window
        while hits and hits[0] < cutoff:
            hits.popleft()
        if not hits:
            self._hits.pop(key, None)
            return self._hits[key]
        return hits

    def check(self, key: str) -> bool:
        """Record an attempt.  Returns ``True`` when it is within the limit."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > self.max_keys:
                self._gc(now)
            hits = self._prune(key, now)
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def retry_after(self, key: str) -> int:
        now = time.monotonic()
        with self._lock:
            hits = self._hits.get(key)
            if not hits:
                return 0
            return max(0, int(self.window - (now - hits[0])) + 1)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)

    def _gc(self, now: float) -> None:
        cutoff = now - self.window
        for key in list(self._hits):
            hits = self._hits[key]
            while hits and hits[0] < cutoff:
                hits.popleft()
            if not hits:
                self._hits.pop(key, None)
