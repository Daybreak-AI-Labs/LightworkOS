"""Process-local auth-failure counter, surfaced on ``/metrics``.

A 401 response and (sometimes) a log line alone would leave a
credential-stuffing or misconfigured-client flood invisible to Prometheus and
unalertable. This keeps a small
per-reason tally that the dashboard ``/metrics`` endpoint emits as
``maverick_auth_failures_total{reason="..."}``, so an alert rule can fire on a
spike.

Process-local by design: each worker keeps its own counter and Prometheus
scrapes per instance (same model as the hand-rolled gauges already on
``/metrics``). Standalone module so both the app middleware and the SCIM router
can increment it without an import cycle.
"""
from __future__ import annotations

import threading

_LOCK = threading.Lock()
_FAILURES: dict[str, int] = {}


def record_auth_failure(reason: str) -> None:
    """Increment the failure tally for ``reason`` (a short, bounded label such
    as ``bad_token`` / ``scim_bad_token``). Never raises."""
    r = (reason or "unknown").strip() or "unknown"
    with _LOCK:
        _FAILURES[r] = _FAILURES.get(r, 0) + 1


def auth_failure_counts() -> dict[str, int]:
    """A snapshot of ``{reason: count}`` for the metrics endpoint."""
    with _LOCK:
        return dict(_FAILURES)


def reset() -> None:
    """Clear the counter (tests only)."""
    with _LOCK:
        _FAILURES.clear()


__all__ = ["record_auth_failure", "auth_failure_counts", "reset"]
