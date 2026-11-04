"""What a policy change would do, before it is saved.

Report only: every function here reads the record and returns counts; none
of them changes anything or enforces anything. Each preview names where its
counts come from, and says so plainly when the record is too short or empty
instead of estimating.

* :func:`tool_block` -- blocking tools (for everyone or for one agent or
  specialist), from the tool calls written to the activity record in the last
  30 days.
* :func:`retention` -- a shorter keep period, from a dry run of the same
  clean-up that would delete the records.
* :func:`data_use_rule` -- a data use rule, from the requests to use data
  recorded in the last 30 days, matched by what each request asked for.

The approval threshold (``maverick_dashboard.approval_threshold_preview``)
and spending limits (``maverick_dashboard.admin_pages``) have their own.
"""
from __future__ import annotations

import datetime as _dt
import time
from collections.abc import Iterable, Mapping
from typing import Any

DAYS = 30
RETENTION_KEYS = ("audit_days", "episodes_days", "events_days", "messages_days", "usage_days")


def _day(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d")


def _owners(goal_ids: Iterable[int]) -> set[str]:
    """The people who started these tasks (owners only, never task content)."""
    from .world_model import close_world_if_owned, open_world

    owners: set[str] = set()
    world = open_world()
    try:
        for goal_id in goal_ids:
            goal = world.get_goal(int(goal_id))
            if goal is not None and getattr(goal, "owner", ""):
                owners.add(goal.owner)
    finally:
        close_world_if_owned(world)
    return owners


def tool_block(tools: Iterable[str], *, agent: str = "", now: float | None = None,
               events: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """What blocking ``tools`` would have stopped in the last 30 days.

    Counted from the ``tool_call`` rows in the activity record (tool name,
    agent or specialist and task only). ``agent`` limits it to one agent or
    specialist. ``events`` replaces the record (tests).
    """
    from .audit.reader import iter_events

    names = {str(t) for t in tools if str(t)}
    if not names:
        raise ValueError("Choose at least one tool.")
    current = time.time() if now is None else float(now)
    since = current - DAYS * 86_400.0
    rows = events if events is not None else iter_events(since=_day(since), until=_day(current))
    calls, first = 0, None
    goals: set[int] = set()
    agents: set[str] = set()
    seen_any = False
    for event in rows:
        if event.get("kind") != "tool_call":
            continue
        ts = float(event.get("ts") or 0)
        if ts < since or ts > current:
            continue
        seen_any = True
        first = ts if first is None else min(first, ts)
        if event.get("name") not in names or (agent and event.get("agent") != agent):
            continue
        calls += 1
        if isinstance(event.get("goal_id"), int):
            goals.add(event["goal_id"])
        if event.get("agent"):
            agents.add(str(event["agent"]))
    result: dict[str, Any] = {"kind": "tool_block", "days": DAYS, "tools": sorted(names),
                              "agent": agent, "recorded": seen_any,
                              "recorded_since": first}
    if not seen_any:
        return {**result, "calls": 0, "tasks": 0, "agents": 0, "people": 0,
                "basis": "No tool use is in the activity record for the last 30 days, so there is nothing to count."}
    people = _owners(goals) if goals else set()
    return {**result, "calls": calls, "tasks": len(goals), "agents": len(agents), "people": len(people),
            "basis": "Counted from the tool use written to the activity record."}


def retention(key: str, days: object) -> dict[str, Any]:
    """What a keep period of ``days`` would delete at the next clean-up (a dry run)."""
    from .audit import retention as clean

    if key not in RETENTION_KEYS:
        raise ValueError("Choose one of the data retention settings.")
    if days in (None, ""):
        return {"kind": "retention", "key": key, "days": None, "count": 0, "unit": "",
                "basis": "Records are kept forever, so nothing would be deleted."}
    try:
        value = int(str(days).strip())
    except ValueError as exc:
        raise ValueError("Enter a whole number of days.") from exc
    if not 1 <= value <= 3650:
        raise ValueError("Choose between 1 and 3,650 days.")
    if key == "audit_days":
        report = clean.purge_audit_files(days=value, dry_run=True)
        count, unit = len(report.get("removed") or []), ("day of activity record", "days of activity record")
    elif key == "usage_days":
        report = clean.purge_usage_ledger(days=value, dry_run=True)
        count, unit = int(report.get("removed_buckets") or 0), ("daily usage tally", "daily usage tallies")
    else:
        purge = {"episodes_days": clean.purge_world_episodes, "events_days": clean.purge_world_events,
                 "messages_days": clean.purge_world_messages}[key]
        report = purge(days=value, dry_run=True)
        count = int(report.get("deleted") or 0)
        unit = {"episodes_days": ("finished work record", "finished work records"),
                "events_days": ("task progress update", "task progress updates"),
                "messages_days": ("message", "messages")}[key]
    return {"kind": "retention", "key": key, "days": value, "count": count,
            "unit": unit[0] if count == 1 else unit[1],
            "basis": "Counted by a trial run of the clean-up that deletes them. Nothing was deleted."}


def _matches(scope: Mapping[str, Any], request: Mapping[str, Any]) -> list[str]:
    """The requested fields this rule's scope covers ([] when it does not apply)."""
    for key, value in (("asset_ids", request.get("asset_id")), ("project_ids", request.get("project_id")),
                       ("actions", request.get("action"))):
        allowed = scope.get(key) or []
        if allowed and value not in allowed:
            return []
    fields = [str(f) for f in request.get("field_ids") or []]
    wanted = scope.get("field_ids") or []
    return [f for f in fields if not wanted or f in wanted]


def data_use_rule(document: Mapping[str, Any], requests: Iterable[Mapping[str, Any]],
                  *, now: float | None = None) -> dict[str, Any]:
    """Which recorded requests to use data a rule would have covered.

    Matched by what each request asked for (data set, fields, project and
    action). Conditions on reasons and labels are checked when a request is
    decided, so a rule with conditions may cover fewer; the result says so.
    """
    from .data_use_governance import normalize_policy_document

    rule = normalize_policy_document(document)
    current = time.time() if now is None else float(now)
    since = current - DAYS * 86_400.0
    recent = [r for r in requests if float(r.get("created_at") or 0) >= since]
    effects = {c["effect"] for c in rule["controls"]}
    covered = [r for r in recent if _matches(rule["scope"], r)]
    conditional = any(rule["conditions"].get(k) for k in rule["conditions"])
    return {"kind": "data_use_rule", "days": DAYS, "considered": len(recent), "requests": len(covered),
            "projects": len({r.get("project_id") for r in covered}),
            "people": len({r.get("requester_id") for r in covered}),
            "data_sets": len({r.get("asset_id") for r in covered}),
            "effects": sorted(effects), "conditional": conditional,
            "basis": "Matched by what each recorded request asked for."
                     + (" This rule also depends on the reasons for using the data, which are checked "
                        "when a request is decided, so it may cover fewer." if conditional else "")}


__all__ = ["DAYS", "RETENTION_KEYS", "data_use_rule", "retention", "tool_block"]
