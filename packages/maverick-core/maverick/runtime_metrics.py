"""Always-on, dependency-free runtime counters for Lightwork itself.

The platform ingests everyone else's telemetry; this is its own. A
thread-safe in-process registry with Prometheus text-format rendering
(format 0.0.4) and zero dependencies, so ``GET /metrics`` works on every
install — the opt-in :mod:`maverick.observability` exporter stays the
richer path when ``prometheus_client`` is present, and nothing here
duplicates its computed collectors: these are the platform's raw
operational counters (HTTP traffic, governed-record operations, gateway
decisions), which that module does not carry.

Cardinality is bounded per metric: past the cap, new label combinations
are dropped and the drop is itself counted — a runaway label can cost a
series, never the process.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable

#: Distinct label combinations retained per metric.
MAX_SERIES_PER_METRIC = 200

_LOCK = threading.Lock()
_COUNTERS: dict[str, dict[str, object]] = {}
_GAUGES: dict[str, dict[str, object]] = {}
_DROPPED = 0
_STARTED_AT = time.time()


def _series_key(labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(
        (str(key), str(value)[:120]) for key, value in labels.items()
    ))


def _escape_label_value(text: str) -> str:
    """Escape a label value as the Prometheus text exposition format requires."""

    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def increment(
    name: str, *, amount: float = 1.0, help_text: str = "", **labels: str,
) -> None:
    """Add to a counter series, creating metric and series on first use."""

    global _DROPPED
    with _LOCK:
        metric = _COUNTERS.setdefault(
            name, {"help": help_text, "series": {}},
        )
        if help_text and not metric["help"]:
            metric["help"] = help_text
        series: dict = metric["series"]  # type: ignore[assignment]
        key = _series_key(labels)
        if key not in series and len(series) >= MAX_SERIES_PER_METRIC:
            _DROPPED += 1
            return
        series[key] = float(series.get(key, 0.0)) + float(amount)


def register_gauge(
    name: str, callback: Callable[[], float], *, help_text: str = "",
) -> None:
    """Register a gauge whose value is computed at render time.

    A callback that raises renders as no sample — a broken gauge never
    breaks the scrape.
    """

    with _LOCK:
        _GAUGES[name] = {"help": help_text, "callback": callback}


def render() -> str:
    """The registry in Prometheus text format 0.0.4."""

    lines: list[str] = []
    with _LOCK:
        counters = {
            name: {"help": metric["help"],
                   "series": dict(metric["series"])}  # type: ignore[index]
            for name, metric in sorted(_COUNTERS.items())
        }
        gauges = dict(_GAUGES)
        dropped = _DROPPED
    for name, metric in counters.items():
        if metric["help"]:
            lines.append(f"# HELP {name} {metric['help']}")
        lines.append(f"# TYPE {name} counter")
        for key, value in sorted(metric["series"].items()):
            label_text = ",".join(
                f'{label}="{_escape_label_value(text)}"' for label, text in key
            )
            suffix = f"{{{label_text}}}" if label_text else ""
            lines.append(f"{name}{suffix} {value}")
    for name, gauge in sorted(gauges.items()):
        try:
            value = float(gauge["callback"]())  # type: ignore[operator]
        except Exception:
            continue
        if gauge["help"]:
            lines.append(f"# HELP {name} {gauge['help']}")
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {value}")
    lines.append("# TYPE lightwork_metrics_dropped_series_total counter")
    lines.append(f"lightwork_metrics_dropped_series_total {float(dropped)}")
    lines.append("# TYPE lightwork_uptime_seconds gauge")
    lines.append(f"lightwork_uptime_seconds {time.time() - _STARTED_AT}")
    return "\n".join(lines) + "\n"


def reset_for_tests() -> None:
    """Empty the registry; tests only."""

    global _DROPPED
    with _LOCK:
        _COUNTERS.clear()
        _GAUGES.clear()
        _DROPPED = 0


__all__ = [
    "MAX_SERIES_PER_METRIC",
    "increment",
    "register_gauge",
    "render",
    "reset_for_tests",
]
