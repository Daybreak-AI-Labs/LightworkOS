"""Per-key circuit breaker.

Lets callers wrap an external call site with a circuit that opens
after N consecutive failures and stays open for a cooldown window
before letting a single probe through.

Goal: when a provider is having an outage, fail fast (no 30-second
timeouts on every call) AND don't hammer the dead service with
retry storms.

Three states (classic):
  - CLOSED:   all calls go through
  - OPEN:     calls short-circuit and raise CircuitOpen until cooldown
  - HALF_OPEN: one probe call gets through; if it succeeds we close,
              if it fails we re-open with the cooldown reset

The breaker is **per-key** (one breaker per provider, per tool, etc.)
managed by a global registry so independent call sites don't share
state by accident. Thread-safe.

Wire it as a decorator OR call ``call()`` manually:

    from maverick.circuit_breaker import get
    br = get("anthropic")
    try:
        result = br.call(lambda: client.complete(...))
    except CircuitOpen:
        # fast-fail; let the caller fall back to another provider

Defaults: 5 consecutive failures opens; 30-second cooldown.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TypeVar

log = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpen(Exception):
    """Raised by ``call()`` when the breaker is open."""


T = TypeVar("T")


@dataclass
class _Stats:
    consecutive_failures: int = 0
    total_failures: int = 0
    total_successes: int = 0
    last_failure_at: float = 0.0
    opened_at: float = 0.0          # wall clock, for snapshot/display only
    opened_mono: float = 0.0        # monotonic, for the cooldown duration math


class CircuitBreaker:
    """One breaker per key. Defaults are aggressive enough for live use."""

    def __init__(
        self,
        key: str,
        *,
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
    ) -> None:
        self.key = key
        self.failure_threshold = int(failure_threshold)
        self.cooldown_seconds = float(cooldown_seconds)
        self._state = CircuitState.CLOSED
        self._stats = _Stats()
        self._lock = threading.Lock()
        # HALF_OPEN admits exactly one probe at a time; concurrent callers
        # fast-fail until it resolves (cleared by record_success/failure).
        self._probe_in_flight = False
        self._probe_started_mono: float | None = None

    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._tick()
            return self._state

    def _tick(self) -> None:
        # If we're OPEN and cooldown has elapsed, drop to HALF_OPEN so the very
        # next call() probes the dependency. Measured on the monotonic clock so
        # an NTP/DST step can't keep the breaker OPEN forever (backward jump) or
        # trip it HALF_OPEN early and re-storm a dead service (forward jump).
        if (
            self._state is CircuitState.OPEN
            and time.monotonic() - self._stats.opened_mono >= self.cooldown_seconds
        ):
            self._state = CircuitState.HALF_OPEN

    def record_success(self) -> None:
        with self._lock:
            self._stats.total_successes += 1
            self._tick()
            if self._state is CircuitState.OPEN:
                # A call admitted before the breaker opened that completes
                # inside the cooldown must not reopen traffic early.
                return
            self._stats.consecutive_failures = 0
            self._state = CircuitState.CLOSED
            self._probe_in_flight = False

    def record_failure(self) -> None:
        with self._lock:
            now = time.time()
            now_mono = time.monotonic()
            self._probe_in_flight = False
            self._stats.consecutive_failures += 1
            self._stats.total_failures += 1
            self._stats.last_failure_at = now
            if self._state is CircuitState.HALF_OPEN:
                # Probe failed → reopen with fresh cooldown.
                self._state = CircuitState.OPEN
                self._stats.opened_at = now
                self._stats.opened_mono = now_mono
                return
            if self._stats.consecutive_failures >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._stats.opened_at = now
                self._stats.opened_mono = now_mono

    def admit(self) -> bool:
        """Admit one manually observed call; return whether it owns the probe."""
        probe_started = False
        with self._lock:
            self._tick()
            if self._state is CircuitState.OPEN:
                raise CircuitOpen(
                    f"circuit {self.key!r} OPEN "
                    f"(opened {time.time() - self._stats.opened_at:.1f}s ago, "
                    f"cooldown {self.cooldown_seconds:.0f}s)"
                )
            if self._state is CircuitState.HALF_OPEN:
                # Let exactly ONE caller probe the dependency; everyone else
                # fast-fails (admitting ALL concurrent callers in HALF_OPEN
                # would re-storm the dead service on cooldown expiry).
                # Zero cooldown permits immediate recovery, not concurrent
                # probes. Use the normal cooldown as its bounded probe lease.
                # A missing timestamp is not proof that a legacy probe expired.
                probe_timeout = self.cooldown_seconds if self.cooldown_seconds > 0 else _DEFAULT_COOLDOWN
                if (self._probe_in_flight and self._probe_started_mono is not None
                        and time.monotonic() - self._probe_started_mono >= probe_timeout):
                    self._probe_in_flight = False
                if self._probe_in_flight:
                    raise CircuitOpen(
                        f"circuit {self.key!r} HALF_OPEN: a probe is already in flight"
                    )
                self._probe_in_flight = True
                self._probe_started_mono = time.monotonic()
                probe_started = True
        return probe_started

    def release_probe(self) -> None:
        """Abandon an owned probe after a local refusal, without a health result."""
        with self._lock:
            self._probe_in_flight = False

    def call(self, fn: Callable[[], T]) -> T:
        """Run ``fn`` if allowed; raise ``CircuitOpen`` otherwise."""
        probe_started = self.admit()
        try:
            result = fn()
        except Exception:
            self.record_failure()
            raise
        except BaseException:
            if probe_started:
                self.record_failure()
            raise
        self.record_success()
        return result

    def reset(self) -> None:
        with self._lock:
            self._stats = _Stats()
            self._state = CircuitState.CLOSED
            self._probe_in_flight = False

    def snapshot(self) -> dict:
        with self._lock:
            self._tick()
            return {
                "key": self.key,
                "state": self._state.value,
                "consecutive_failures": self._stats.consecutive_failures,
                "total_failures": self._stats.total_failures,
                "total_successes": self._stats.total_successes,
                "last_failure_at": self._stats.last_failure_at,
                "opened_at": self._stats.opened_at,
                "cooldown_seconds": self.cooldown_seconds,
            }


@dataclass
class _Registry:
    breakers: dict[str, CircuitBreaker] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


_REG = _Registry()


_DEFAULT_THRESHOLD = 5
_DEFAULT_COOLDOWN = 30.0


def get(
    key: str,
    *,
    failure_threshold: int = _DEFAULT_THRESHOLD,
    cooldown_seconds: float = _DEFAULT_COOLDOWN,
) -> CircuitBreaker:
    """Return the breaker for ``key``, creating it on first call.

    If the breaker already exists and the caller passes *non-default*
    config that differs from the live breaker, the new thresholds are
    applied in place (without resetting the breaker's state) — so a
    later ``get("x", cooldown_seconds=120)`` isn't silently ignored
    just because something touched ``"x"`` earlier with defaults. A
    debug line records the change.
    """
    with _REG.lock:
        br = _REG.breakers.get(key)
        if br is None:
            br = CircuitBreaker(
                key,
                failure_threshold=failure_threshold,
                cooldown_seconds=cooldown_seconds,
            )
            _REG.breakers[key] = br
            return br
        # Existing breaker: honor an explicit, differing override.
        changed = False
        if (failure_threshold != _DEFAULT_THRESHOLD
                and failure_threshold != br.failure_threshold):
            br.failure_threshold = int(failure_threshold)
            changed = True
        if (cooldown_seconds != _DEFAULT_COOLDOWN
                and cooldown_seconds != br.cooldown_seconds):
            br.cooldown_seconds = float(cooldown_seconds)
            changed = True
        if changed:
            log.debug("circuit %r reconfigured: threshold=%s cooldown=%s",
                      key, br.failure_threshold, br.cooldown_seconds)
    return br


def snapshot() -> list[dict]:
    """Snapshot every breaker for dashboards / debugging."""
    with _REG.lock:
        return [b.snapshot() for b in _REG.breakers.values()]


def reset_all() -> None:
    with _REG.lock:
        _REG.breakers.clear()


__all__ = [
    "CircuitBreaker", "CircuitOpen", "CircuitState",
    "get", "snapshot", "reset_all",
]
