"""In-process sliding-window rate limiter (per process; use a reverse proxy / Redis for clusters)."""

from __future__ import annotations

import threading
import time

from app.detection.window import SlidingWindow


class RateLimiter:
    def __init__(self) -> None:
        self._w: dict[tuple[str, int], SlidingWindow] = {}
        self._lock = threading.Lock()

    def hit(self, bucket: str, key: str, limit: int, window: float = 60.0) -> tuple[bool, int]:
        """Record a hit; returns (allowed, retry_after_seconds)."""
        with self._lock:
            w = self._w.setdefault((bucket, int(window)), SlidingWindow(window, max_keys=50_000))
            now = time.monotonic()
            if len(w.items(key, now)) >= limit:
                return False, int(window)
            w.add(key, now)
            return True, 0
