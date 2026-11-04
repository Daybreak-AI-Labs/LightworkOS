"""Cross-run spend rollup for the ``maverick costs`` CLI report.

A pure aggregator/formatter over priced-run rows so it's testable without a DB.
``aggregate`` groups spend along one dimension (day / tag / principal / model)
and reports the total plus each group's share; ``daily_series`` gives a
chronological per-day spend curve; ``format_report`` renders a compact text
table. Rows come from the world model's episodes elsewhere — here every input is
a plain dict and dollars are coerced defensively (non-numeric -> 0.0).
"""
from __future__ import annotations

from dataclasses import dataclass

_BY_FIELDS = ("day", "tag", "principal", "model")


@dataclass
class SpendRow:
    dollars: float
    day: str  # "YYYY-MM-DD" or ""
    tag: str = ""
    principal: str = ""
    model: str = ""


def _num(v) -> float:
    try:
        return float(v) if v is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def _key(row: dict, by: str) -> str:
    return str(row.get(by) or "").strip()


def aggregate(rows: list[dict], *, by: str = "day", top: int = 20) -> dict:
    """Group ``rows`` by one of {day, tag, principal, model} and total spend.

    Returns ``{"total", "n", "groups": [(key, dollars, share), ...]}`` sorted by
    dollars descending and trimmed to ``top``; ``share`` is each group's fraction
    of the total (0.0 when total is 0). An unknown ``by`` returns
    ``{"error": "..."}`` instead of raising.
    """
    if by not in _BY_FIELDS:
        return {"error": f"unknown group-by {by!r}; choose from {', '.join(_BY_FIELDS)}"}
    sums: dict[str, float] = {}
    total = 0.0
    n = 0
    for row in rows or []:
        d = _num(row.get("dollars"))
        sums[_key(row, by)] = sums.get(_key(row, by), 0.0) + d
        total += d
        n += 1
    ordered = sorted(sums.items(), key=lambda kv: -kv[1])[: max(top, 0)]
    groups = [
        (k, round(v, 4), (v / total) if total else 0.0) for k, v in ordered
    ]
    return {"total": round(total, 4), "n": n, "groups": groups}


def daily_series(rows: list[dict]) -> list[tuple[str, float]]:
    """Spend per day as ``(day, dollars)`` pairs, chronological by day string."""
    sums: dict[str, float] = {}
    for row in rows or []:
        day = str(row.get("day") or "").strip()
        sums[day] = sums.get(day, 0.0) + _num(row.get("dollars"))
    return [(day, round(sums[day], 4)) for day in sorted(sums)]


def format_report(rows: list[dict], *, by: str = "day", top: int = 20) -> str:
    """Compact text table: a total line, then ``key  $x.xxxx  (yy.y%)`` per group.

    Renders the ``aggregate`` error for an unknown ``by`` and a friendly message
    for empty input.
    """
    agg = aggregate(rows, by=by, top=top)
    if "error" in agg:
        return agg["error"]
    if not agg["groups"]:
        return "no spend recorded"
    width = max(len(k) for k, _, _ in agg["groups"])
    lines = [f"total  ${agg['total']:.4f}  ({agg['n']} run(s), by {by})"]
    for key, dollars, share in agg["groups"]:
        lines.append(f"{key.ljust(width)}  ${dollars:.4f}  ({share * 100:.1f}%)")
    return "\n".join(lines)


__all__ = ["SpendRow", "aggregate", "daily_series", "format_report"]
