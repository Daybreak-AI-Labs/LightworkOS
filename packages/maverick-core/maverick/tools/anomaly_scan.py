"""Cross-run anomaly scanner.

Flags outliers in a metric tracked across runs (latency, cost, tool-call count,
refusal rate, ...) using the robust **median / MAD modified z-score**
(Iglewicz-Hoaglin): far less fooled by the very outliers it's hunting than a
mean/stddev rule. A point is anomalous when its modified z-score exceeds the
threshold (default 3.5). When MAD is zero it falls back to mean-absolute-
deviation; if every value is identical, nothing is flagged. Pure arithmetic —
deterministic and offline.

ops:
  - scan(series, [labels], [threshold])  — ``series`` is a list of numbers.
    Reports CLEAN or the ANOMALY points (label/index, value, score), with the
    median and dispersion used.
"""
from __future__ import annotations

from typing import Any

from . import Tool

_DEFAULT_THRESHOLD = 3.5


def _median(xs: list[float]) -> float:
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def _scan(series: list[float], labels: list[str], threshold: float) -> str:
    median = _median(series)
    deviations = [abs(x - median) for x in series]
    mad = _median(deviations)

    if mad > 0:
        disp_label = f"MAD {mad:g}"
        scores = [0.6745 * (x - median) / mad for x in series]
    else:
        mean_ad = sum(deviations) / len(deviations)
        if mean_ad == 0:  # every value identical -> no dispersion, no anomalies
            return f"CLEAN: no anomalies in {len(series)} points (all equal, threshold {threshold:g})"
        disp_label = f"meanAD {mean_ad:g}"
        scores = [(x - median) / (1.253314 * mean_ad) for x in series]

    flagged = [
        (labels[i], series[i], scores[i])
        for i in range(len(series))
        if abs(scores[i]) > threshold
    ]
    flagged.sort(key=lambda t: -abs(t[2]))

    header = f"median {median:g}, {disp_label}, threshold {threshold:g}"
    if not flagged:
        return f"CLEAN: no anomalies in {len(series)} points ({header})"
    lines = [f"ANOMALY: {len(flagged)} of {len(series)} points ({header}):"]
    for label, value, score in flagged:
        lines.append(f"  [{label}] {value:g} (score {score:+.2f})")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "scan"):
        return f"ERROR: unknown op {args.get('op')!r}"
    series = args.get("series")
    if not isinstance(series, list) or len(series) < 3:
        return "ERROR: series must be a list of >=3 numbers"
    try:
        nums = [float(x) for x in series]
    except (TypeError, ValueError):
        return "ERROR: series must contain only numbers"

    labels_arg = args.get("labels")
    if labels_arg is not None:
        if not isinstance(labels_arg, list) or len(labels_arg) != len(series):
            return "ERROR: labels must be a list the same length as series"
        labels = [str(label) for label in labels_arg]
    else:
        labels = [str(i) for i in range(len(series))]

    threshold = args.get("threshold", _DEFAULT_THRESHOLD)
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        return "ERROR: threshold must be a number"
    if threshold <= 0:
        return "ERROR: threshold must be > 0"

    return _scan(nums, labels, threshold)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["scan"]},
        "series": {
            "type": "array",
            "description": "metric values across runs (>=3 numbers)",
            "items": {"type": "number"},
        },
        "labels": {
            "type": "array",
            "description": "optional labels parallel to series (e.g. run ids)",
            "items": {"type": "string"},
        },
        "threshold": {
            "type": "number",
            "description": f"modified z-score cutoff (default {_DEFAULT_THRESHOLD})",
        },
    },
    "required": ["series"],
}


def anomaly_scan() -> Tool:
    return Tool(
        name="anomaly_scan",
        description=(
            "Flag cross-run outliers in a metric series via the robust median/MAD "
            "modified z-score. op=scan with 'series' (>=3 numbers), optional "
            "'labels' and 'threshold' (default 3.5). Reports CLEAN or the ANOMALY "
            "points (label, value, score) with the median and dispersion used; "
            "falls back to mean-absolute-deviation when MAD is zero. Deterministic, "
            "offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
