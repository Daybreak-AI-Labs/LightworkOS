"""Smart notification batching.

A long run can fire a flurry of low-priority pushes ("step 3 done", "step 4
done", …) and turn a phone into a slot machine. Batching coalesces the
low/normal-priority stream into a single digest — "5 updates" with the lines
folded in — while letting **high / urgent** notifications cut the line and
deliver immediately (and flush whatever was pending, so order is preserved).

A batch flushes when ANY of: the window elapses, the pending count hits the
cap, or a high-priority notification arrives. The window dimension is driven
by a lazy daemon flusher on the process-shared batcher; the bookkeeping here
is deterministic (injected clock + send) so the policy is unit-tested without
threads or real pushes.

Opt-in via ``[notifications] batch_window_seconds`` (+ optional ``batch_max``);
``0``/unset means **no batching** and ``notify()`` behaves exactly as before.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger(__name__)

# Priorities that never wait in a batch (delivered immediately).
_BYPASS = {"high", "max", "urgent"}
DEFAULT_MAX_BATCH = 10


@dataclass(frozen=True)
class BatchPolicy:
    window_seconds: float = 0.0
    max_batch: int = DEFAULT_MAX_BATCH

    def is_active(self) -> bool:
        return self.window_seconds > 0


def policy_from_config() -> BatchPolicy:
    import os

    def _f(name: str) -> float | None:
        v = os.environ.get(name, "").strip()
        try:
            return float(v) if v else None
        except ValueError:
            return None

    window = _f("MAVERICK_NOTIFY_BATCH_WINDOW")
    cap = _f("MAVERICK_NOTIFY_BATCH_MAX")
    if window is None or cap is None:
        try:
            from .config import load_config
            cfg = (load_config() or {}).get("notifications") or {}
            if window is None:
                window = _num(cfg.get("batch_window_seconds"))
            if cap is None:
                cap = _num(cfg.get("batch_max"))
        except Exception:  # pragma: no cover -- config never blocks a notify
            pass
    return BatchPolicy(
        window_seconds=window if window and window > 0 else 0.0,
        max_batch=int(cap) if cap and cap > 0 else DEFAULT_MAX_BATCH,
    )


def _num(v) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v) if v > 0 else None


def _default_send(title: str, body: str, priority: str, category: str | None) -> int:
    from .notifications import notify as _notify
    return _notify(body, title=title, priority=priority, category=category,
                   async_dispatch=False)


class NotificationBatcher:
    """Coalesce low-priority notifications into windowed digests.

    ``send(title, body, priority, category) -> int`` is the real delivery
    (defaults to a synchronous :func:`maverick.notifications.notify`); ``clock``
    is injected so the window is tested deterministically.
    """

    def __init__(self, policy: BatchPolicy, *,
                 send: Callable[[str, str, str, str | None], int] | None = None,
                 clock: Callable[[], float] = time.time):
        self.policy = policy
        self._send = send or _default_send
        self._clock = clock
        self._pending: list[tuple[str, str, str]] = []
        self._first_ts: float | None = None
        self._lock = threading.Lock()

    def submit(self, body: str, *, title: str = "Lightwork",
               priority: str = "default", category: str | None = None) -> int:
        """Queue or deliver a notification. Returns backends fired *now*
        (0 when the item was queued for a later batch)."""
        if not self.policy.is_active() or priority in _BYPASS:
            # Bypass: flush anything pending first (preserve order), then send.
            flushed = self.flush()
            return flushed + self._send(title, body, priority, category)
        with self._lock:
            if not self._pending:
                self._first_ts = self._clock()
            self._pending.append((title, body, priority))
            due = (len(self._pending) >= self.policy.max_batch
                   or self._window_elapsed_locked())
            items = self._take_locked() if due else None
        return self._emit(items)

    def maybe_flush(self) -> int:
        """Flush iff the window has elapsed since the first pending item.
        Drives the time dimension (called by the daemon flusher / a run tick)."""
        with self._lock:
            items = self._take_locked() if self._window_elapsed_locked() else None
        return self._emit(items)

    def flush(self) -> int:
        """Flush any pending notifications immediately."""
        with self._lock:
            items = self._take_locked()
        return self._emit(items)

    # -- internals (call holding the lock for the *_locked helpers) --------

    def _window_elapsed_locked(self) -> bool:
        return (self._pending and self._first_ts is not None
                and (self._clock() - self._first_ts) >= self.policy.window_seconds)

    def _take_locked(self) -> list[tuple[str, str, str]]:
        items = self._pending
        self._pending = []
        self._first_ts = None
        return items

    def _emit(self, items: list[tuple[str, str, str]] | None) -> int:
        if not items:
            return 0
        title, body = _coalesce(items)
        return self._send(title, body, "default", "batch")


def _coalesce(items: list[tuple[str, str, str]]) -> tuple[str, str]:
    if len(items) == 1:
        title, body, _ = items[0]
        return title, body
    title = f"{len(items)} notifications"
    body = "\n".join(f"• {t}: {b}" if b else f"• {t}" for t, b, _ in items)
    return title, body


_shared: NotificationBatcher | None = None
_shared_lock = threading.Lock()


def shared() -> NotificationBatcher | None:
    """The process-wide batcher, or None when batching is off.

    Starts a daemon flusher on first use so the window fires even if no further
    notifications arrive (otherwise the last item in a batch could sit forever).
    """
    global _shared
    with _shared_lock:
        if _shared is None:
            policy = policy_from_config()
            if not policy.is_active():
                return None
            _shared = NotificationBatcher(policy)
            _start_flusher(_shared)
        return _shared


def reset_shared() -> None:
    global _shared
    with _shared_lock:
        _shared = None


def _start_flusher(batcher: NotificationBatcher) -> None:  # pragma: no cover -- timing
    interval = max(0.5, min(batcher.policy.window_seconds, 30.0))

    def _loop() -> None:
        while True:
            time.sleep(interval)
            try:
                batcher.maybe_flush()
            except Exception:
                log.debug("notification flusher tick failed", exc_info=True)

    threading.Thread(target=_loop, name="mvk-notify-batch", daemon=True).start()


__all__ = ["BatchPolicy", "NotificationBatcher", "policy_from_config",
           "shared", "reset_shared"]
