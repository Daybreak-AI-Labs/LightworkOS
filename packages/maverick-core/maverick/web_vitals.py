"""Optional field Core Web Vitals: how fast pages load and respond for real visitors.

Off unless ``[analytics] web_vitals = true``. When on, the dashboard measures a
sample of page loads in the visitor's browser (:func:`sample_rate`) with the
web-vitals method -- Largest Contentful Paint (LCP), Interaction to Next Paint
(INP) and Cumulative Layout Shift (CLS) -- and sends the three numbers for the
page's route ("/chat/goal/{goal_id}", never the address itself) and a device
class ("phone" or "desktop") to this server.

Privacy: nothing about the visitor is kept. Each number is added to a count in
a fixed histogram bucket for that route, device and UTC day, and the raw value
is dropped; the store (``~/.maverick/web-vitals.json``, 0600, locked) holds only
those counts, for the last :data:`WINDOW_DAYS` days, and never leaves the
installation.

The report gives the 75th percentile per route and device over the window, the
statistic and thresholds web.dev uses (https://web.dev/articles/vitals): LCP at
most 2.5 s, INP at most 200 ms, CLS at most 0.1. A percentile is the upper edge
of the bucket that holds it, so it never understates; a route with fewer than
:data:`MIN_SAMPLES` measurements reports only its count.
"""
from __future__ import annotations

import json
import math
import re
import threading
import time
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()
SAMPLE_RATE = 0.5          # default share of page loads measured ([analytics] web_vitals_sample_rate)
WINDOW_DAYS = 28           # web.dev's field window (CrUX reports 28 days)
MIN_SAMPLES = 20           # below this, a route reports only its count
MAX_ROUTES_PER_DAY = 500   # bounds the file; further routes that day are refused
DEVICES = ("phone", "desktop")
# metric: (bucket width, number of buckets before the overflow one, good-at-most threshold, largest accepted value)
METRICS: dict[str, tuple[float, int, float, float]] = {
    "lcp": (100.0, 100, 2500.0, 600_000.0),   # milliseconds; 10 s and above share the overflow bucket
    "inp": (8.0, 125, 200.0, 600_000.0),      # milliseconds; 1 s and above overflow
    "cls": (0.005, 200, 0.1, 100.0),          # unitless; 1.0 and above overflow
}
_ROUTE = re.compile(r"/[A-Za-z0-9/_{}.\-]{0,199}")


class VitalsError(ValueError):
    """A measurement this store will not keep."""


def enabled() -> bool:
    """``[analytics] web_vitals``; off unless set to true."""
    try:
        from .config import load_config

        section = (load_config() or {}).get("analytics")
    except Exception:  # noqa: BLE001 -- an unreadable config keeps measurement off
        return False
    return isinstance(section, dict) and section.get("web_vitals") is True


def sample_rate() -> float:
    """``[analytics] web_vitals_sample_rate``, the share of page loads measured.

    A number from 0 to 1; anything else keeps :data:`SAMPLE_RATE`.
    """
    try:
        from .config import load_config

        section = (load_config() or {}).get("analytics")
    except Exception:  # noqa: BLE001 -- an unreadable config keeps the default
        return SAMPLE_RATE
    value = section.get("web_vitals_sample_rate") if isinstance(section, dict) else None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        return SAMPLE_RATE
    return float(value)


def store_path() -> Path:
    from .paths import maverick_home

    return maverick_home() / "web-vitals.json"


def _day(now: float | None) -> int:
    return int((time.time() if now is None else now) // 86_400)


def _bucket(metric: str, value: float) -> int:
    width, buckets, _good, _largest = METRICS[metric]
    return min(buckets + 1, max(1, math.ceil(round(value / width, 9))))


def _check(route: object, device: object, metrics: object) -> dict[str, float]:
    if not isinstance(route, str) or not _ROUTE.fullmatch(route):
        raise VitalsError("the page must be a route such as /goals")
    if device not in DEVICES:
        raise VitalsError("the device must be phone or desktop")
    if not isinstance(metrics, dict) or not metrics:
        raise VitalsError("nothing was measured")
    clean: dict[str, float] = {}
    for name, value in metrics.items():
        if name not in METRICS:
            raise VitalsError("only LCP, INP and CLS are kept")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise VitalsError("each measurement must be a number")
        if not 0 <= value <= METRICS[name][3]:
            raise VitalsError("a measurement is out of range")
        clean[name] = float(value)
    return clean


def _locked():
    from contextlib import ExitStack

    from .file_lock import cross_process_lock, ensure_private_directory
    from .paths import maverick_home

    ensure_private_directory(maverick_home())
    with ExitStack() as stack:
        stack.enter_context(_LOCK)
        stack.enter_context(cross_process_lock(store_path()))
        return stack.pop_all()


def _load() -> dict[str, Any]:
    from .file_lock import atomic_read_text, ensure_private_file

    path = store_path()
    data: Any = {}
    if path.exists():
        ensure_private_file(path)
        try:
            data = json.loads(atomic_read_text(path))
        except (OSError, ValueError):
            data = {}
    if not isinstance(data, dict) or not isinstance(data.get("days"), dict):
        data = {"days": {}}
    data["version"] = 1
    return data


def record(route: str, device: str, metrics: dict[str, float], now: float | None = None) -> None:
    """Add one page load's measurements to today's counts for ``route`` and ``device``."""
    if not enabled():
        raise VitalsError("page speed measurement is turned off")
    clean = _check(route, device, metrics)
    today = _day(now)
    with _locked():
        data = _load()
        days = {key: value for key, value in data["days"].items()
                if isinstance(value, dict) and key.isdigit() and int(key) > today - WINDOW_DAYS}
        routes = days.setdefault(str(today), {})
        key = route + "|" + device
        if key not in routes and len(routes) >= MAX_ROUTES_PER_DAY:
            raise VitalsError("too many different pages were measured today")
        counts = routes.setdefault(key, {})
        for name, value in clean.items():
            buckets = counts.setdefault(name, {})
            index = str(_bucket(name, value))
            buckets[index] = int(buckets.get(index, 0)) + 1
        data["days"] = days
        from .file_lock import atomic_write_text

        atomic_write_text(store_path(), json.dumps(data, sort_keys=True))


def _p75(metric: str, buckets: dict[int, int]) -> dict[str, Any]:
    n = sum(buckets.values())
    out: dict[str, Any] = {"n": n}
    if n < MIN_SAMPLES:
        return out
    width, last, good, _largest = METRICS[metric]
    rank, seen = math.ceil(0.75 * n), 0
    for index in sorted(buckets):
        seen += buckets[index]
        if seen >= rank:
            break
    value = round(min(index, last) * width, 3)
    out.update(p75=value, above=index > last, threshold=good, good=index <= last and value <= good)
    return out


def report(now: float | None = None) -> dict[str, Any]:
    """p75 per route and device over the last :data:`WINDOW_DAYS` days, worst first."""
    today = _day(now)
    data = _load() if store_path().exists() else {"days": {}}
    totals: dict[str, dict[str, dict[int, int]]] = {}
    for day, routes in data["days"].items():
        if not (day.isdigit() and today - WINDOW_DAYS < int(day) <= today and isinstance(routes, dict)):
            continue
        for key, counts in routes.items():
            if not isinstance(counts, dict):
                continue
            merged = totals.setdefault(key, {})
            for metric, buckets in counts.items():
                if metric in METRICS and isinstance(buckets, dict):
                    target = merged.setdefault(metric, {})
                    for index, count in buckets.items():
                        if str(index).isdigit() and isinstance(count, int) and count > 0:
                            target[int(index)] = target.get(int(index), 0) + count
    rows = []
    for key, metrics in totals.items():
        route, _, device = key.rpartition("|")
        row: dict[str, Any] = {"route": route, "device": device}
        for metric in METRICS:
            row[metric] = _p75(metric, metrics.get(metric, {}))
        judged = [row[m] for m in METRICS if "good" in row[m]]
        row["enough"] = bool(judged)
        row["passes"] = (False if any(not m["good"] for m in judged)
                         else True if len(judged) == len(METRICS) else None)
        rows.append(row)
    order = {False: 0, None: 1, True: 2}
    rows.sort(key=lambda r: (order[r["passes"]], r["route"], r["device"]))
    return {"window_days": WINDOW_DAYS, "minimum": MIN_SAMPLES, "sample_rate": sample_rate(),
            "thresholds": {name: spec[2] for name, spec in METRICS.items()}, "rows": rows}


__all__ = [
    "DEVICES",
    "METRICS",
    "MIN_SAMPLES",
    "SAMPLE_RATE",
    "WINDOW_DAYS",
    "VitalsError",
    "enabled",
    "record",
    "sample_rate",
    "report",
    "store_path",
]
