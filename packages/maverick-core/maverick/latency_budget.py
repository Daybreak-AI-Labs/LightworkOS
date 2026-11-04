"""Per-tool latency budget: warn (fail-open) when a tool call runs too long.

Default OFF. Set a wall-clock budget — ``MAVERICK_TOOL_LATENCY_BUDGET_MS`` or
``[tools] latency_budget_ms`` — and every tool call that exceeds it records a
breach the dashboard / a test can inspect via ``breaches()`` and emits a metric.
The tool still runs to completion (fail-open) — this is an observability signal,
not a kill switch. ``note_elapsed`` is wired into ``ToolRegistry.run``'s timing
``finally`` so it covers both success and error paths. Recording never raises.
"""
from __future__ import annotations

import os
import threading
from collections import deque

_MAX_BREACHES = 256
_lock = threading.Lock()
_breaches: deque = deque(maxlen=_MAX_BREACHES)


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def budget_ms() -> float:
    """Configured budget in ms (0 = disabled). Env wins over config."""
    env = os.environ.get("MAVERICK_TOOL_LATENCY_BUDGET_MS", "").strip()
    if env:
        try:
            return max(0.0, float(env))
        except ValueError:
            return 0.0
    try:
        from .config import load_config
        v = (load_config() or {}).get("tools", {}).get("latency_budget_ms", 0)
        return max(0.0, float(v))
    except Exception:  # pragma: no cover -- config never blocks the tool path
        return 0.0


def note_elapsed(tool: str, ms: float) -> str | None:
    """Record a breach if ``ms`` exceeds the budget; return a warning or None.

    No-op when the budget is 0 (default) so the hot path pays nothing when the
    feature is off.
    """
    budget = budget_ms()
    if budget <= 0 or ms is None or ms <= budget:
        return None
    over = round(ms - budget, 3)
    with _lock:
        _breaches.append({"tool": tool, "elapsed_ms": round(ms, 3),
                          "budget_ms": budget, "over_ms": over})
    try:
        from .observability import record_metric
        record_metric("tool_latency_budget_exceeded", labels={"tool": tool})
    except Exception:  # pragma: no cover -- metrics optional
        pass
    return (f"latency budget exceeded: {tool} took {ms:.1f}ms "
            f"(budget {budget:.0f}ms, over by {over:.1f}ms)")


def breaches() -> list[dict]:
    """Recorded budget breaches, oldest first."""
    with _lock:
        return list(_breaches)


def reset() -> None:
    with _lock:
        _breaches.clear()


__all__ = ["budget_ms", "note_elapsed", "breaches", "reset"]
