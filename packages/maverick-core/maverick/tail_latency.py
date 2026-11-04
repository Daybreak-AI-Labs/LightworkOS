"""Tail-latency hunting.

:mod:`maverick.tool_latency` already computes per-tool p50/p95/p99. The slowest
tool by p95 isn't necessarily the one to *hunt*, though — the interesting bug
is the tool that is usually fast but occasionally terrible (a fat tail): most
calls fine, a few pathological. This flags those by the **tail ratio**
(p99 ÷ p50): a high ratio means the tail is far worse than the typical case, so
that's where to look (a retry storm, a cold cache, a lock).

Pure over a latency report (the live one or one passed in), so it's tested with
synthetic numbers; surfaced via the dashboard ``/api/v1/diag/tail-latency``,
which runs in the long-lived serving process where the samples actually
accumulate.
"""
from __future__ import annotations

DEFAULT_RATIO_THRESHOLD = 3.0   # p99 >= 3x p50 == a tail worth hunting
DEFAULT_MIN_COUNT = 20          # need enough samples for p99 to mean anything


def hunt(report=None, *, ratio_threshold: float = DEFAULT_RATIO_THRESHOLD,
         min_count: int = DEFAULT_MIN_COUNT) -> list[dict]:
    """Flag tools with a fat latency tail. Returns rows sorted by tail ratio.

    Each row: ``{tool, count, p50_ms, p99_ms, tail_ratio, tail_gap_ms}``. Tools
    with fewer than ``min_count`` samples or a non-positive p50 are skipped (no
    trustworthy tail).
    """
    if report is None:
        from .tool_latency import extended_report
        report = extended_report()
    out: list[dict] = []
    for r in report:
        count = int(r.get("count", 0) or 0)
        p50 = float(r.get("p50_ms", 0.0) or 0.0)
        p99 = float(r.get("p99_ms", 0.0) or 0.0)
        if count < min_count or p50 <= 0:
            continue
        ratio = p99 / p50
        if ratio >= ratio_threshold:
            out.append({
                "tool": r.get("tool"),
                "count": count,
                "p50_ms": round(p50, 3),
                "p99_ms": round(p99, 3),
                "tail_ratio": round(ratio, 2),
                "tail_gap_ms": round(p99 - p50, 3),
            })
    out.sort(key=lambda x: -x["tail_ratio"])
    return out


__all__ = ["hunt", "DEFAULT_RATIO_THRESHOLD", "DEFAULT_MIN_COUNT"]
