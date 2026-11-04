"""What practice runs cost, for the views that report real cost.

AI answers in practice come from the real AI service, so they cost real
provider money. Practice runs are kept in the practice world database
(:mod:`maverick.practice`), apart from the real run record, and their usage
is kept on the practice ledger, apart from real limits and quotas. Billing,
Spend, Savings, Budget, Provider spending, Compare cost records and the cost
exports therefore show practice as its own labelled line ("Practice: $0.42
today (not counted against limits)"), never inside the real totals.

Provider spending is different: its ledger is what the provider charged, so it
already contains practice calls; the practice line there says how much of
the total was practice, and the reconciliation still adds up.

Reading never creates the practice database, and a page that is itself in
practice gets no line (its main numbers already are practice).
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)

NOT_COUNTED = "not counted against limits"


def _money(value: float) -> str:
    return f"${value:,.2f}"


def practice_world():
    """The practice world database, or ``None`` when nothing was practised
    (it is never created by reading) or practice is unavailable."""
    from . import practice
    from .world_model import default_db_path, open_world

    with practice.scope(True):
        try:
            if not default_db_path().exists():
                return None
            return open_world()
        except practice.PracticeUnavailable:
            return None


def summary(owner: str | None = None, *, since: float | None = None, until: float | None = None) -> dict | None:
    """Practice runs finished in ``[since, until)`` (all time by default) for
    ``owner`` (everyone when ``None``), or ``None`` when there are none."""
    from . import practice
    from .episode_reporting import iter_episodes

    if practice.active():
        return None
    try:
        world = practice_world()
        if world is None:
            return None
        midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        dollars = today = 0.0
        runs = unknown = input_tokens = output_tokens = 0
        with practice.scope(True):
            for episode in iter_episodes(world, owner=owner, since=since, until=until, finished_only=True):
                runs += 1
                input_tokens += episode.input_tokens or 0
                output_tokens += episode.output_tokens or 0
                if episode.cost_dollars is None:
                    unknown += 1
                    continue
                dollars += episode.cost_dollars
                if episode.started_at >= midnight:
                    today += episode.cost_dollars
    except Exception:  # noqa: BLE001 -- an unreadable practice record shows no line, never breaks a cost view
        log.debug("practice costs unavailable", exc_info=True)
        return None
    if not runs:
        return None
    line = {"dollars": round(dollars, 6), "today": round(today, 6), "runs": runs, "unknown_runs": unknown,
            "input_tokens": input_tokens, "output_tokens": output_tokens, "counted_against_limits": False}
    line["text"] = f"Practice: {_money(today)} today ({NOT_COUNTED})"
    return line


def label(line: dict, when: str) -> str:
    """``line``'s total for the period ``when`` names, e.g. "this month"."""
    unknown = line.get("unknown_runs") or 0
    extra = f"; {unknown} practice run{'s' if unknown != 1 else ''} with unknown cost" if unknown else ""
    return f"Practice: {_money(line['dollars'])} {when} ({NOT_COUNTED}{extra})"


def month_bounds(period: str | None = None) -> tuple[float, float]:
    """UTC start and end of ``period`` (``YYYY-MM``, this month by default)."""
    start = (datetime.strptime(period, "%Y-%m").replace(tzinfo=timezone.utc) if period
             else datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0))
    end = start.replace(year=start.year + 1, month=1) if start.month == 12 else start.replace(month=start.month + 1)
    return start.timestamp(), end.timestamp()


def period_bounds(period: str) -> tuple[float, float]:
    """UTC bounds of a ``YYYY-MM`` month or a ``YYYY-MM-DD`` day."""
    if len(period) == 7:
        return month_bounds(period)
    start = datetime.strptime(period, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
    return start, start + 86400


def provider_share(period: str) -> dict | None:
    """How much of a provider-spending period was practice. The provider
    ledger already holds these real charges, so this explains part of the
    total and is never added to it."""
    since, until = period_bounds(period)
    line = summary(None, since=since, until=until)
    if not line:
        return None
    return {**line, "text": (f"Of this, practice: {_money(line['dollars'])} in {period} (real provider charges "
                             f"already in the totals; {NOT_COUNTED})")}


def window(days: int) -> float:
    return time.time() - max(1, int(days)) * 86400


def export_row(line: dict | None, width: int) -> list[str] | None:
    """One clearly labelled practice row for a cost spreadsheet ``width`` wide."""
    if not line:
        return None
    row = ["practice", "", "", "", f"Practice runs ({NOT_COUNTED})", f"{line['dollars']:.6f}",
           str(line["input_tokens"]), str(line["output_tokens"])]
    return (row + [""] * width)[:width]


__all__ = ["NOT_COUNTED", "export_row", "label", "month_bounds", "period_bounds", "practice_world", "provider_share",
           "summary", "window"]
