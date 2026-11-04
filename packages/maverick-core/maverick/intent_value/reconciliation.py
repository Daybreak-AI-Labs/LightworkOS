"""Explain the numeric bridge to the existing process/episode Savings scenario."""
from __future__ import annotations

from ..config import get_value
from ..cost_provenance import amount
from ..episode_reporting import iter_episodes
from ..workforce_value import _is_done


def bridge(world, records, report):
    selected = {row["id"] for row in report["rows"]}
    goal_ids = {gid for row in records if row["id"] in selected for gid in row["source"]["goal_ids"]}
    cfg = get_value()
    attempts, gross, cost, missing = 0, 0.0, 0.0, 0
    done = []
    for episode in iter_episodes(world, since=report["start"], until=report["end"], finished_only=True):
        if episode.goal_id not in goal_ids:
            continue
        dollars = amount(episode.cost_dollars)
        cost += dollars or 0
        missing += int(dollars is None)
        if _is_done(episode.outcome):
            done.append(episode.goal_id)
    # One batched goal read for the completed attempts, summed in episode order.
    goals = world.get_goals(done) if done else {}
    for goal_id in done:
        assumed = cfg["departments"].get(goals.get(goal_id).domain, cfg)
        attempts += 1
        gross += assumed["hourly_rate"] * assumed["hours_per_task"]
    total = report["totals"]
    new_gross = total["gross_estimated_labor_value"]
    return {"scope": "The same contributing goals and UTC window, using the existing Savings completed-episode rule and configured hours/rates.",
        "legacy_completed_attempts": attempts, "legacy_assumed_labor_value": round(gross, 2),
        "legacy_labor_currency": cfg["currency"], "legacy_runtime_cost_usd": round(cost, 6),
        "legacy_missing_costs": missing, "unique_audited_work": total["performed_work"],
        "labor_estimate_difference": round(new_gross - gross, 2) if new_gross is not None and cfg["currency"] == total["currency"] else None,
        "known_usd_cost_difference": round(total["known_execution_costs"].get("USD", 0) - cost, 6),
        "explanation": "Savings uses finished episodes by start date and whole-task hours. Work value groups attempts, requires audit completion, credits attributable business components, and dates costs by completion or allocated provider month. Provider receipts replace overlapping runtime estimates. These are alternative scenarios, never additive."}
