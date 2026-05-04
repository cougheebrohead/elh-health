"""In-process rate limiter — fixed-window, per-key. Same as CoachHQ."""

from __future__ import annotations

import threading
import time

_LOCK = threading.Lock()
_BUCKETS: dict[str, tuple[int, float]] = {}


def allow(key: str, limit: int, window_sec: int) -> bool:
    now = time.time()
    with _LOCK:
        count, window_start = _BUCKETS.get(key, (0, now))
        if now - window_start >= window_sec:
            count = 0
            window_start = now
        if count >= limit:
            return False
        _BUCKETS[key] = (count + 1, window_start)
    return True
