"""Adaptive thinking-budget controller (opt-in, default OFF).

Closed loop over real run outcomes: when a thinking role (orchestrator/revisor)
has been succeeding, trim its thinking budget (cheaper); when it's been failing,
raise it (more reasoning) — clamped to a sane band. Off by default
(``[thinking] adaptive = true`` to enable). Pure + thread-safe; needs a few
samples before it adjusts, and disabled/insufficient-data both return the base
budget unchanged (so the wire-ins are no-ops until earned).
"""
from __future__ import annotations

import threading

_lock = threading.Lock()
_stats: dict[str, list[int]] = {}  # role -> [successes, total]

_MIN_BUDGET = 2000
_MAX_BUDGET = 16000
_MIN_SAMPLES = 3
_HIGH = 0.8   # success rate at/above which we trim
_LOW = 0.4    # at/below which we raise


def _enabled() -> bool:
    try:
        from .config import load_config
        return bool(((load_config() or {}).get("thinking") or {}).get("adaptive", False))
    except Exception:  # pragma: no cover -- never block on a config error
        return False


def record(role: str, success: bool) -> None:
    """Record a finished run's outcome for ``role`` (drives the adjustment)."""
    with _lock:
        st = _stats.setdefault(role, [0, 0])
        st[0] += 1 if success else 0
        st[1] += 1


def reset(role: str | None = None) -> None:
    with _lock:
        if role is None:
            _stats.clear()
        else:
            _stats.pop(role, None)


def adjust(
    role: str, base: int | None, *,
    enabled: bool | None = None,
    min_budget: int = _MIN_BUDGET, max_budget: int = _MAX_BUDGET,
) -> int | None:
    """Adjusted thinking budget for ``role`` given its recent success rate.

    ``base`` None (role doesn't think) stays None. Disabled, or fewer than
    ``_MIN_SAMPLES`` outcomes, returns ``base`` unchanged. High success → trim
    toward ``min_budget``; low success → raise toward ``max_budget``."""
    if base is None:
        return None
    on = _enabled() if enabled is None else enabled
    if not on:
        return base
    with _lock:
        succ, total = _stats.get(role, [0, 0])
    if total < _MIN_SAMPLES:
        return base
    rate = succ / total
    if rate >= _HIGH:
        adj = int(base * 0.75)
    elif rate <= _LOW:
        adj = int(base * 1.5)
    else:
        return base
    return max(min_budget, min(max_budget, adj))


__all__ = ["record", "reset", "adjust"]
