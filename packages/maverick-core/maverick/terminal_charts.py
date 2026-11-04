"""Augmented terminal — inline sparklines and bar charts for run telemetry.

Three data views, each a pure function over injected data:

* **spend per day** from the usage ledger (``maverick.quotas.UsageLedger``),
* **goal throughput** (done / failed per day) from the world model — "failed"
  means status ``blocked``, the vocabulary the orchestrator actually writes,
* **tool latency percentiles** from ``maverick.tool_latency.report()``.

The pure-ASCII renderer (block chars ▁▂▃▄▅▆▇█) is the tested core. When
``rich`` is importable (it is a dev/installer dependency, never required by
the kernel) :func:`render_dashboard_rich` wraps the same strings in panels;
when it isn't, it falls back to the plain text — a thin wrapper, no second
rendering path.

``render_dashboard(world)`` composes the three sections and shows an honest
empty-state line for any section with no data.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

BLOCKS = "▁▂▃▄▅▆▇█"
DEFAULT_DAYS = 14
MAX_LATENCY_ROWS = 10


# ----- ASCII core -----

def sparkline(values: list[float]) -> str:
    """Map values onto ▁..█. Empty -> "". A flat series renders as all-▁ when
    zero, all-▄ otherwise (deterministic; tested)."""
    if not values:
        return ""
    vals = [max(0.0, float(v)) for v in values]
    lo, hi = min(vals), max(vals)
    if hi == lo:
        ch = BLOCKS[0] if hi == 0 else BLOCKS[3]
        return ch * len(vals)
    span = hi - lo
    out = []
    for v in vals:
        idx = int((v - lo) / span * (len(BLOCKS) - 1))
        out.append(BLOCKS[idx])
    return "".join(out)


def bar_chart(
    rows: list[tuple[str, float]],
    *,
    width: int = 30,
    fmt: Callable[[float], str] = lambda v: f"{v:g}",
) -> str:
    """Horizontal bar chart: one ``label  ████ value`` line per row.

    Bars scale to the max value across ``width`` columns; any nonzero value
    shows at least one block. Empty rows -> "".
    """
    if not rows:
        return ""
    labw = max(len(str(label)) for label, _ in rows)
    vmax = max(max(0.0, float(v)) for _, v in rows)
    lines = []
    for label, value in rows:
        v = max(0.0, float(value))
        n = 0 if vmax == 0 else max(1, round(v / vmax * width)) if v > 0 else 0
        lines.append(f"{label!s:<{labw}}  {'█' * n}{' ' if n else ''}{fmt(v)}")
    return "\n".join(lines)


# ----- data assemblers (pure over injected sources) -----

def _day_keys(days: int, today: str | None = None) -> list[str]:
    """The last ``days`` UTC day keys (YYYY-MM-DD), oldest first, ending at
    ``today`` (injectable for tests; default: now)."""
    if today is not None:
        end = datetime.strptime(today, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    else:
        end = datetime.now(timezone.utc)
    return [
        (end - timedelta(days=i)).strftime("%Y-%m-%d")
        for i in range(max(1, int(days)) - 1, -1, -1)
    ]


def spend_per_day(
    ledger: Any = None, *, days: int = DEFAULT_DAYS, today: str | None = None,
) -> list[tuple[str, float]]:
    """``(day, dollars)`` for the last ``days`` UTC days, summed across
    principals, from the usage ledger (default: the active tenant's)."""
    if ledger is None:
        from .quotas import UsageLedger
        ledger = UsageLedger()
    # Same intentional read of the persisted tally billing.rate_ledger does.
    data = ledger._load()  # noqa: SLF001
    keys = _day_keys(days, today)
    totals = dict.fromkeys(keys, 0.0)
    for per_day in data.values():
        for day, cell in (per_day or {}).items():
            if day in totals:
                totals[day] += float((cell or {}).get("dollars", 0.0))
    return [(day, round(totals[day], 6)) for day in keys]


def goal_throughput(
    world: Any, *, days: int = DEFAULT_DAYS, today: str | None = None,
) -> list[tuple[str, int, int]]:
    """``(day, done, failed)`` for the last ``days`` UTC days, bucketed by each
    goal's terminal-transition time (``updated_at``). Failed = ``blocked``."""
    keys = _day_keys(days, today)
    done = dict.fromkeys(keys, 0)
    failed = dict.fromkeys(keys, 0)
    for status, counter in (("done", done), ("blocked", failed)):
        for g in world.list_goals(status=status, limit=1000, order="desc"):
            day = datetime.fromtimestamp(g.updated_at, timezone.utc).strftime("%Y-%m-%d")
            if day in counter:
                counter[day] += 1
    return [(day, done[day], failed[day]) for day in keys]


def latency_rows(report: list[dict] | None = None) -> list[tuple[str, float, float, float]]:
    """``(tool, p50_ms, p95_ms, p99_ms)`` from a ``tool_latency.report()``-shaped
    list (default: the live in-process profile), slowest first, top 10."""
    if report is None:
        from . import tool_latency
        report = tool_latency.report()
    return [
        (r["tool"], float(r["p50_ms"]), float(r["p95_ms"]), float(r["p99_ms"]))
        for r in report[:MAX_LATENCY_ROWS]
    ]


# ----- section renderers (ASCII; empty-state honest) -----

def render_spend(per_day: list[tuple[str, float]]) -> str:
    total = sum(v for _, v in per_day)
    if not per_day or total == 0:
        return "Spend per day\n  no spend recorded in this window"
    spark = sparkline([v for _, v in per_day])
    days = len(per_day)
    return (
        f"Spend per day (last {days}d, total ${total:.2f})\n"
        f"  {spark}  {per_day[0][0]} .. {per_day[-1][0]}\n"
        f"  today: ${per_day[-1][1]:.2f}"
    )


def render_throughput(rows: list[tuple[str, int, int]]) -> str:
    total_done = sum(d for _, d, _ in rows)
    total_failed = sum(f for _, _, f in rows)
    if not rows or (total_done == 0 and total_failed == 0):
        return "Goal throughput\n  no finished goals in this window"
    done_spark = sparkline([d for _, d, _ in rows])
    fail_spark = sparkline([f for _, _, f in rows])
    days = len(rows)
    return (
        f"Goal throughput (last {days}d: {total_done} done, {total_failed} failed)\n"
        f"  done   {done_spark}\n"
        f"  failed {fail_spark}  {rows[0][0]} .. {rows[-1][0]}"
    )


def render_latency(rows: list[tuple[str, float, float, float]]) -> str:
    if not rows:
        return "Tool latency\n  no tool latency samples yet"
    chart = bar_chart(
        [(tool, p95) for tool, _, p95, _ in rows],
        fmt=lambda v: f"{v:.0f}ms p95",
    )
    detail = "\n".join(
        f"  {tool}: p50 {p50:.0f}ms / p95 {p95:.0f}ms / p99 {p99:.0f}ms"
        for tool, p50, p95, p99 in rows[:3]
    )
    return "Tool latency (slowest p95 first)\n" + _indent(chart) + "\n" + detail


def _indent(text: str, pad: str = "  ") -> str:
    return "\n".join(pad + line for line in text.split("\n"))


def render_dashboard(
    world: Any,
    ledger: Any = None,
    latency_report: list[dict] | None = None,
    *,
    days: int = DEFAULT_DAYS,
    today: str | None = None,
) -> str:
    """Compose the three sections into one plain-text dashboard. Sections with
    no data render their honest empty-state line rather than disappearing."""
    sections = [
        render_spend(spend_per_day(ledger, days=days, today=today)),
        render_throughput(goal_throughput(world, days=days, today=today)),
        render_latency(latency_rows(latency_report)),
    ]
    return "\n\n".join(sections)


def render_dashboard_rich(
    world: Any,
    ledger: Any = None,
    latency_report: list[dict] | None = None,
    *,
    days: int = DEFAULT_DAYS,
    today: str | None = None,
):
    """The same dashboard wrapped in rich panels when ``rich`` is importable
    (lazy import — the kernel never requires it); otherwise returns the plain
    ASCII string from :func:`render_dashboard` unchanged."""
    try:
        from rich.console import Group
        from rich.panel import Panel
    except ImportError:
        return render_dashboard(
            world, ledger, latency_report, days=days, today=today,
        )
    return Group(
        Panel(render_spend(spend_per_day(ledger, days=days, today=today)),
              title="spend"),
        Panel(render_throughput(goal_throughput(world, days=days, today=today)),
              title="goals"),
        Panel(render_latency(latency_rows(latency_report)), title="latency"),
    )


__all__ = [
    "BLOCKS",
    "sparkline",
    "bar_chart",
    "spend_per_day",
    "goal_throughput",
    "latency_rows",
    "render_spend",
    "render_throughput",
    "render_latency",
    "render_dashboard",
    "render_dashboard_rich",
]
