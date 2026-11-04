"""Per-tool latency profile: bounded, in-memory p50/p95/p99 per tool.

Complements the OTel tool spans (which only surface when an exporter is
configured) with an always-on, dependency-free, in-process profile that a
long-running process (``maverick serve`` / the dashboard) or a test can read via
``report()``. A bounded ring buffer per tool keeps memory flat under sustained
load. Thread-safe; recording never raises into the tool path.
"""
from __future__ import annotations

import threading
from collections import defaultdict, deque

_MAX_SAMPLES = 1024
_MAX_TOOLS = 128
_OVERFLOW_TOOL = "__other__"
_lock = threading.Lock()
_samples: dict[str, deque] = defaultdict(lambda: deque(maxlen=_MAX_SAMPLES))


def record(tool: str, ms: float) -> None:
    """Record one tool call's wall-clock duration (milliseconds)."""
    if ms is None or ms < 0:
        return
    with _lock:
        key = str(tool or "?")
        if key not in _samples and len(_samples) >= max(1, _MAX_TOOLS - 1):
            key = _OVERFLOW_TOOL
        _samples[key].append(float(ms))


def _percentile(sorted_vals: list[float], q: float) -> float:
    """Nearest-rank percentile of an already-sorted list."""
    if not sorted_vals:
        return 0.0
    idx = max(0, min(len(sorted_vals) - 1, round(q * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


def report() -> list[dict]:
    """Per-tool ``{tool, count, p50_ms, p95_ms, p99_ms, max_ms}``, slowest p95 first."""
    with _lock:
        snapshot = {t: list(d) for t, d in _samples.items() if d}
    out = []
    for tool, vals in snapshot.items():
        sv = sorted(vals)
        out.append({
            "tool": tool,
            "count": len(sv),
            "p50_ms": round(_percentile(sv, 0.50), 3),
            "p95_ms": round(_percentile(sv, 0.95), 3),
            "p99_ms": round(_percentile(sv, 0.99), 3),
            "max_ms": round(sv[-1], 3),
        })
    out.sort(key=lambda r: -r["p95_ms"])
    return out


def _mean(vals: list[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def _stdev(vals: list[float], mean: float) -> float:
    if len(vals) < 2:
        return 0.0
    var = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)  # sample stdev
    return var ** 0.5


def extended_report() -> list[dict]:
    """Richer per-tool stats: ``{tool, count, min, mean, stdev, p50, p90, p95,
    p99, max}`` (ms), slowest p95 first.

    Complements ``report()`` (kept byte-stable for its callers) with the extra
    moments — mean/stdev/min/p90 — useful for spotting variance, not just tails.
    """
    with _lock:
        snapshot = {t: list(d) for t, d in _samples.items() if d}
    out = []
    for tool, vals in snapshot.items():
        sv = sorted(vals)
        mean = _mean(sv)
        out.append({
            "tool": tool,
            "count": len(sv),
            "min_ms": round(sv[0], 3),
            "mean_ms": round(mean, 3),
            "stdev_ms": round(_stdev(sv, mean), 3),
            "p50_ms": round(_percentile(sv, 0.50), 3),
            "p90_ms": round(_percentile(sv, 0.90), 3),
            "p95_ms": round(_percentile(sv, 0.95), 3),
            "p99_ms": round(_percentile(sv, 0.99), 3),
            "max_ms": round(sv[-1], 3),
        })
    out.sort(key=lambda r: -r["p95_ms"])
    return out


def reset() -> None:
    """Clear all recorded samples (mainly for tests / a fresh run)."""
    with _lock:
        _samples.clear()


__all__ = ["record", "report", "extended_report", "reset"]
