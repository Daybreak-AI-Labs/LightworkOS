"""Provider rate-limit predictor: how long until the next call is safe.

The rate limiter (``safety/rate_limiter.py``) is *reactive* — it errors once a
window is exceeded. This is the *proactive* complement: record each provider call
and predict the wait (ms) before another call would fit inside the limit, so a
caller can pace itself instead of hitting a 429. Pure, dependency-free
sliding-window math over per-provider timestamps; bounded memory. ``record`` /
``predict_wait_ms`` take an injectable ``now`` so they're deterministically
unit-tested.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

_MAX_SAMPLES = 4096
_lock = threading.Lock()
_calls: dict[str, deque] = defaultdict(lambda: deque(maxlen=_MAX_SAMPLES))


def record(provider: str, *, now: float | None = None) -> None:
    """Record one call to ``provider`` at ``now`` (default: wall clock)."""
    t = time.time() if now is None else now
    with _lock:
        _calls[str(provider)].append(t)


def predict_wait_ms(provider: str, *, limit: int, window_s: float,
                    now: float | None = None) -> float:
    """Milliseconds to wait before a new call to ``provider`` fits the limit.

    Returns 0.0 when fewer than ``limit`` calls fall in the trailing
    ``window_s``. Otherwise returns the time until the oldest in-window call ages
    out (so the (limit)-th-from-newest call leaves the window).
    """
    if limit <= 0 or window_s <= 0:
        return 0.0
    t = time.time() if now is None else now
    cutoff = t - window_s
    with _lock:
        in_window = [ts for ts in _calls.get(provider, ()) if ts > cutoff]
    if len(in_window) < limit:
        return 0.0
    in_window.sort()
    # The call that must expire for a new one to fit is the (len-limit+1)-th
    # oldest; once it ages past the window, capacity frees up.
    expires_at = in_window[len(in_window) - limit] + window_s
    return max(0.0, (expires_at - t) * 1000.0)


def report() -> list[dict]:
    """Per-provider recent-call counts (diagnostics)."""
    with _lock:
        return sorted(
            ({"provider": p, "recorded": len(d)} for p, d in _calls.items() if d),
            key=lambda r: -r["recorded"],
        )


def reset() -> None:
    with _lock:
        _calls.clear()


__all__ = ["record", "predict_wait_ms", "report", "reset"]
