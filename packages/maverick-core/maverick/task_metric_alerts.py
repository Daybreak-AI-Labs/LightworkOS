"""Current-account operational thresholds using recorded native run history.

These are finish-rate and recorded-usage alerts, never answer-accuracy checks
or an invoice. The existing personal inbox owns delivery, timing and dedupe.
No extra history or alert journal is maintained here.
"""
from __future__ import annotations

import math
import time
from collections.abc import Callable
from datetime import datetime, timezone

HISTORY_LIMIT = 5000
WINDOW_DAYS = 7
DEFAULTS = {"metric_alerts": False, "metric_min_runs": 10,
            "metric_finish_below": 80, "metric_spend_above": 0.0,
            "metric_tokens_above": 0}


class MetricAlertUnavailable(ValueError):
    """An unreadable rule or recorded value cannot become an empty success."""


def _settings() -> dict:
    from . import config

    if config.config_source_errors(include_tenant=True):
        raise MetricAlertUnavailable("Task alert settings could not be read.")
    section = config.load_config().get("notifications") or {}
    if not isinstance(section, dict):
        raise MetricAlertUnavailable("Task alert settings could not be read.")
    result = {key: section.get(key, default) for key, default in DEFAULTS.items()}
    if type(result["metric_alerts"]) is not bool:
        raise MetricAlertUnavailable("Choose whether to show task performance alerts.")
    limits = {"metric_min_runs": (1, 1000), "metric_finish_below": (0, 100),
              "metric_spend_above": (0, 1000000), "metric_tokens_above": (0, 10000000000)}
    for key, (low, high) in limits.items():
        value = result[key]
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or not low <= value <= high
                or (key != "metric_spend_above" and int(value) != value)):
            raise MetricAlertUnavailable("A task performance alert threshold is unavailable. Review All settings.")
    return result


def _number(value: object) -> float:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0):
        raise MetricAlertUnavailable("Recorded task usage could not be read completely.")
    return float(value)


def sources(actor: str, world, *, can_read_goal: Callable[[object], bool],
            now: float | None = None) -> tuple[list[dict], bool]:
    """Thresholds over the latest 5,000 own runs completed in the last week.

    Ownership and current per-goal visibility are checked again after the
    owner-scoped native read. A truncated read remains explicitly partial.
    Each threshold alerts at most once per UTC day for an unchanged rule;
    refreshing measurements never creates another inbox event that day.
    """
    rules = _settings()
    if not rules["metric_alerts"]:
        return [], False
    if not actor.startswith("user:") or not actor[5:]:
        raise PermissionError("Sign in with your own account to see task performance alerts.")
    clock = time.time() if now is None else now
    cutoff = clock - WINDOW_DAYS * 86400
    episodes = world.list_episodes(limit=HISTORY_LIMIT + 1, owner=actor)
    partial = len(episodes) > HISTORY_LIMIT
    goals, rows = {}, []
    for episode in episodes[:HISTORY_LIMIT]:
        ended = _number(episode.ended_at) if episode.ended_at is not None else 0
        if not ended or not cutoff <= ended <= clock:
            continue
        if episode.goal_id not in goals:
            goal = world.get_goal(episode.goal_id)
            goals[episode.goal_id] = (goal is not None and goal.owner == actor and can_read_goal(goal))
        if goals[episode.goal_id]:
            rows.append(episode)
    output = _evaluate(rows, rules, clock, partial)
    for goal_id, admitted in goals.items():
        if admitted:
            current = world.get_goal(goal_id)
            if current is None or current.owner != actor or not can_read_goal(current):
                raise MetricAlertUnavailable("Task access changed while performance alerts were checked.")
    if _settings() != rules:
        raise MetricAlertUnavailable("Task alert thresholds changed while history was checked.")
    return output, partial


def _evaluate(rows: list, rules: dict, now: float, partial: bool) -> list[dict]:
    from .workforce_value import _is_done

    count = len(rows)
    done = sum(_is_done(row.outcome) for row in rows)
    dollars = sum(_number(row.cost_dollars) for row in rows)
    tokens = sum(_number(row.input_tokens) + _number(row.output_tokens) for row in rows)
    day = datetime.fromtimestamp(now, timezone.utc).date().isoformat()
    coverage = ("Based on up to 5,000 of your latest recorded runs completed in the last seven days. "
                + ("Older history was not included. " if partial else "")
                + "Only work you can currently open is included. Recorded usage may not include every provider charge.")
    output = []

    def add(key, threshold, label, href):
        output.append({"ref": f"task-metric:{day}:{key}", "version": str(threshold),
                       "category": "blocked", "title": "Task performance and usage",
                       "label": label, "href": href, "goal_id": None, "project_id": None,
                       "occurred_at": now, "reason": "Your recorded runs reached an organization alert threshold. " + coverage,
                       "action": "Review your work and usage; an administrator can change alert thresholds in All settings",
                       "no_due": "No deadline; this alert does not change a spending limit"})

    floor = rules["metric_finish_below"]
    if floor and count >= rules["metric_min_runs"] and 100 * done / count < floor:
        add("finish", f"{floor}:{rules['metric_min_runs']}",
            f"{done} of {count} recorded runs finished successfully ({100 * done / count:.0f}%), below the {floor:g}% alert threshold. This measures completion, not answer accuracy.", "/my-work")
    if rules["metric_spend_above"] and dollars >= rules["metric_spend_above"]:
        add("spend", rules["metric_spend_above"],
            f"Your included runs recorded ${dollars:,.2f}, reaching the ${rules['metric_spend_above']:,.2f} usage alert threshold.", "/budget")
    if rules["metric_tokens_above"] and tokens >= rules["metric_tokens_above"]:
        add("tokens", rules["metric_tokens_above"],
            f"Your included runs recorded {tokens:,.0f} text units, reaching the {rules['metric_tokens_above']:,.0f} usage alert threshold.", "/budget")
    return output
