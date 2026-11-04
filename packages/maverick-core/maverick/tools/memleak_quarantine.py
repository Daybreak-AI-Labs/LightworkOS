"""Memory-leak quarantine.

Over a long run, a leaking component's RSS climbs without bound while a healthy
one oscillates around a flat mean. Given an RSS time series per component, this
fits a least-squares line and QUARANTINEs components whose memory grows
monotonically (a positive slope with a good linear fit). Deterministic and
offline: slope and R² are computed by hand (no numpy).

A component is QUARANTINEd when both:
  - slope > ``min_slope`` MB/sample (default 0.0 — any positive growth), and
  - R² >= ``min_r2`` (default 0.8 — the growth is a real trend, not noise).

ops:
  - scan(components, [min_slope], [min_r2])  — per-component OK/QUARANTINE + slope.

Components: ``[{"name", "series": [{"t", "rss_mb"}, ...]}]``.
"""
from __future__ import annotations

import statistics
from typing import Any

from . import Tool


def _fit(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Least-squares slope and R² for ys ~ a + b*xs. Hand-rolled, no numpy."""
    mx = statistics.fmean(xs)
    my = statistics.fmean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=False))
    syy = sum((y - my) ** 2 for y in ys)
    # Degenerate x (all samples at one t): slope undefined -> 0, no trend.
    if sxx == 0:
        return 0.0, 0.0
    slope = sxy / sxx
    # R^2 = (Sxy^2) / (Sxx * Syy). Flat y (Syy == 0) is a perfect flat fit.
    r2 = 1.0 if syy == 0 else (sxy * sxy) / (sxx * syy)
    return slope, r2


def _scan(components: list, min_slope: float, min_r2: float) -> str:
    lines: list[str] = []
    quarantined: list[str] = []
    for c in components:
        if not isinstance(c, dict):
            return "ERROR: each component must be an object"
        name = c.get("name")
        if name is None:
            return "ERROR: each component needs a 'name'"
        name = str(name)
        series = c.get("series")
        if not isinstance(series, list) or len(series) < 2:
            return f"ERROR: component {name!r} needs a series of >= 2 samples"
        xs: list[float] = []
        ys: list[float] = []
        for pt in series:
            if not isinstance(pt, dict):
                return f"ERROR: component {name!r} series items must be objects"
            try:
                xs.append(float(pt.get("t")))
                ys.append(float(pt.get("rss_mb")))
            except (TypeError, ValueError):
                return f"ERROR: component {name!r} samples need numeric t and rss_mb"

        slope, r2 = _fit(xs, ys)
        leaking = slope > min_slope and r2 >= min_r2
        status = "QUARANTINE" if leaking else "OK"
        if leaking:
            quarantined.append(name)
        lines.append(
            f"  {name}: {status} slope={slope:.4f}MB/sample r2={r2:.4f}"
        )

    n_q = len(quarantined)
    verdict = "LEAK" if n_q else "CLEAN"
    shown = ", ".join(sorted(quarantined)) if quarantined else "(none)"
    head = (
        f"{verdict} quarantine={n_q}/{len(components)} "
        f"(min_slope={min_slope:g}, min_r2={min_r2:g})\n"
        f"  quarantined: [{shown}]"
    )
    return head + "\n" + "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "scan"):
        return f"ERROR: unknown op {args.get('op')!r}"
    components = args.get("components")
    if not isinstance(components, list) or not components:
        return "ERROR: components (non-empty list of {name, series}) is required"
    min_slope = args.get("min_slope", 0.0)
    min_r2 = args.get("min_r2", 0.8)
    try:
        min_slope = float(min_slope)
        min_r2 = float(min_r2)
    except (TypeError, ValueError):
        return "ERROR: min_slope and min_r2 must be numbers"
    if not 0 <= min_r2 <= 1:
        return "ERROR: min_r2 must be in [0, 1]"
    return _scan(components, min_slope, min_r2)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["scan"]},
        "components": {
            "type": "array",
            "description": "Per-component RSS series: {name, series:[{t, rss_mb}]}",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": ["string", "number"]},
                    "series": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "t": {"type": "number"},
                                "rss_mb": {"type": "number"},
                            },
                            "required": ["t", "rss_mb"],
                        },
                    },
                },
                "required": ["name", "series"],
            },
        },
        "min_slope": {"type": "number", "description": "Min MB/sample slope to flag (default 0.0)"},
        "min_r2": {"type": "number", "description": "Min R^2 fit quality to flag (default 0.8)"},
    },
    "required": ["components"],
}


def memleak_quarantine() -> Tool:
    return Tool(
        name="memleak_quarantine",
        description=(
            "Memory-leak quarantine. op=scan with 'components' ({name, series:"
            "[{t, rss_mb}]}) and optional 'min_slope' (default 0.0) / 'min_r2' "
            "(default 0.8). Fits a least-squares line per component and "
            "QUARANTINEs those with positive slope and a good fit (real growth, "
            "not noise); the rest are OK. Returns the slope and R² per component. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
