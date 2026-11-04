"""Multi-agent observation channel.

The blackboard is a *pull* model — agents post events, readers walk the list.
This is the *push* counterpart: a read-only broadcast an external observer
subscribes to and receives the swarm's event stream **live** — a monitoring
agent, a dashboard, a supervisor watching its fleet — without joining the
control flow (unlike :mod:`maverick.agent_bus`, point-to-point and consuming).

Each subscriber gets every event published after it subscribed, in its own
bounded buffer; a slow observer drops its oldest events rather than ever
stalling the swarm (observation is best-effort). It is **no-op when unused**:
``maybe_publish`` returns immediately when there are no subscribers, so the
``blackboard.post`` tee that feeds it costs nothing on a run nobody is
watching.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

_DEFAULT_BUFFER = 1000


@dataclass(frozen=True)
class ObservationEvent:
    ts: float
    kind: str
    agent: str
    content: str = ""
    meta: dict = field(default_factory=dict)


class Subscription:
    """One observer's view: a bounded buffer of events, drained on demand."""

    def __init__(self, channel: ObservationChannel, capacity: int):
        self._channel = channel
        self._buf: deque[ObservationEvent] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._closed = False

    def _offer(self, event: ObservationEvent) -> None:
        with self._lock:
            self._buf.append(event)  # deque(maxlen) drops the oldest when full

    def drain(self) -> list[ObservationEvent]:
        """Return and clear all buffered events (non-blocking)."""
        with self._lock:
            out = list(self._buf)
            self._buf.clear()
            return out

    def pending(self) -> int:
        with self._lock:
            return len(self._buf)

    def close(self) -> None:
        self._channel._unsubscribe(self)
        self._closed = True

    def __enter__(self) -> Subscription:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


class ObservationChannel:
    def __init__(self):
        self._subs: list[Subscription] = []
        self._lock = threading.Lock()

    def subscribe(self, *, capacity: int = _DEFAULT_BUFFER) -> Subscription:
        sub = Subscription(self, capacity)
        with self._lock:
            self._subs.append(sub)
        return sub

    def _unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def has_subscribers(self) -> bool:
        with self._lock:
            return bool(self._subs)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

    def publish(self, kind: str, agent: str, content: str = "", **meta) -> None:
        event = ObservationEvent(time.time(), kind, agent, content, meta)
        with self._lock:
            subs = list(self._subs)
        for sub in subs:
            sub._offer(event)

    def maybe_publish(self, kind: str, agent: str, content: str = "", **meta) -> None:
        """Publish only if someone is observing — the cheap hot-path entry."""
        if not self._subs:           # lock-free fast path: nothing to do
            return
        self.publish(kind, agent, content, **meta)


_shared: ObservationChannel | None = None
_shared_lock = threading.Lock()


def shared() -> ObservationChannel:
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = ObservationChannel()
        return _shared


def reset_shared() -> None:
    global _shared
    with _shared_lock:
        _shared = None


def subscribe(*, capacity: int = _DEFAULT_BUFFER) -> Subscription:
    return shared().subscribe(capacity=capacity)


def maybe_publish(kind: str, agent: str, content: str = "", **meta) -> None:
    """Module-level tee target for the swarm (no-op when unobserved)."""
    shared().maybe_publish(kind, agent, content, **meta)


__all__ = ["ObservationEvent", "Subscription", "ObservationChannel",
           "shared", "reset_shared", "subscribe", "maybe_publish"]
