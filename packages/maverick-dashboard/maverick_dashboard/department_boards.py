"""Owned board projections for current department grants; no company rollups."""
from __future__ import annotations

import hmac
import math
import time
from collections import Counter
from types import SimpleNamespace

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import auth
from ._shared import _world
from .draft_api import context_for

SCOPED_BOARDS = frozenset({"overview", "spend", "workforce", "savings", "oversight"})
_DAYS = (30, 90, 180, 365)
_LIMIT = 100_000
SCOPE_NOTICE = (
    "Your own tasks in the departments you can access, plus your general tasks. "
    "Other people's work and inaccessible departments are excluded. These are not company totals."
)
COST_NOTICE = (
    "Known runtime prices only; missing or unsupported prices are counted separately, not treated as free. "
    "Runtime prices can be measured, estimated or bounded. They are not verified provider invoices "
    "and exclude subscriptions, taxes, outside tools and unreconciled adjustments."
)
SAVINGS_NOTICE = (
    "Comparisons use your recorded baseline and hands-on, review and rework observations, "
    "checked against current task results. They are operator reports, not verified invoices "
    "or proof that AI caused savings. Incomplete comparisons remain visible."
)
OVERSIGHT_NOTICE = (
    "Your readable task requests and your recorded stop requests only. An approval is not an execution receipt. "
    "A stop request does not prove cleanup or reversal of outside effects. This is not a company audit or stop-state report. "
    "Review workflow pauses separately in Approvals."
)


def scoped(request) -> bool:
    return auth.caller_suites(request) is not None


def context(request) -> str:
    allowed = auth.caller_suites(request)
    key_permissions, key_scopes = auth.api_key_permissions(request), auth.api_key_scopes(request)
    return digest({"account_workspace": context_for(request), "role": auth.caller_role(request),
                   "departments": sorted(allowed) if allowed is not None else None,
                   "key_permissions": sorted(key_permissions) if key_permissions is not None else None,
                   "key_scopes": sorted(key_scopes) if key_scopes is not None else None})


def _oversight_allowed(request):
    return (auth.has_permission(request, "operate", api_scope="approvals:decide")
            if auth.api_key_permissions(request) is not None else auth.has_permission(request, "operate"))


def _require_oversight(request):
    if auth.api_key_permissions(request) is not None:
        auth.require_permission(request, "operate", api_scope="approvals:decide")
    else:
        auth.require_permission(request, "operate")


def check_context(request) -> str:
    auth.require_permission(request, "view")
    current = context(request)
    supplied = request.headers.get("X-Lightwork-Board-Context")
    if supplied is not None and not auth.constant_time_equals(supplied, current):
        raise HTTPException(409, "Your account, workspace or department access changed. Reload this page before reading this board.")
    return current


def _permitted(request, row, cache):
    # Exact owner is already in the SQL predicate. Use the native content gate
    # as well, including inherited and removed-pack department restrictions.
    domain = str(row["domain"] or "")
    if domain not in cache:
        cache[domain] = auth.can_access_goal(request, SimpleNamespace(
            id=row["id"], owner=row["owner"], domain=domain))
    return cache[domain]


def _rows(world, sql, values):
    rows = world.query(sql + " LIMIT ?", (*values, _LIMIT + 1))
    if len(rows) > _LIMIT:
        raise HTTPException(503, "This board is too large to read safely right now. Your permitted tasks remain available in Chat.")
    return rows


def _population(request, world, owner):
    columns = ("id", "status", "created_at", "updated_at", "domain", "owner")
    # The backend's typed listing applies its tenant boundary; raw SQL on the
    # shared PostgreSQL store does not automatically scope the query.
    goals = world.list_goals(owner=owner, limit=_LIMIT + 1, strict_tenant=True)
    if len(goals) > _LIMIT:
        raise HTTPException(503, "This board is too large to read safely right now. Your permitted tasks remain available in Chat.")
    rows = [{name: getattr(goal, name) for name in columns} for goal in goals]
    cache = {}
    return [row for row in rows if _permitted(request, row, cache)]


def _recent(request, world, goals):
    rows = []
    for source in sorted(goals, key=lambda row: row["id"], reverse=True)[:12]:
        goal = world.get_goal(source["id"])
        if goal and goal.owner == auth.goal_owner_filter(request) and auth.can_access_goal(request, goal):
            rows.append({"id": goal.id, "title": goal.title, "status": goal.status, "updated_at": goal.updated_at})
    return rows


def _overview(request, world, goals, days):
    from maverick.departments import department_title
    from maverick.domain import suites_for_domain

    from .board_data import _board_day_list

    dates, since, previous = _board_day_list(days)
    daily = {day.isoformat(): {"d": day.isoformat(), "started": 0, "delivered": 0} for day in dates}
    by_status = dict(Counter(row["status"] for row in goals))
    now = time.time()
    def count(column, lo, hi, done=False):
        return sum(lo <= row[column] < hi and (not done or row["status"] == "done") for row in goals)
    domains = {}
    from datetime import datetime, timezone
    for row in goals:
        for column, key in (("created_at", "started"), ("updated_at", "delivered")):
            if key == "delivered" and row["status"] != "done":
                continue
            day = datetime.fromtimestamp(row[column], timezone.utc).date().isoformat()
            if day in daily:
                daily[day][key] += 1
        suites = suites_for_domain(row["domain"]) if row["domain"] else frozenset()
        label = ", ".join(department_title(key) for key in sorted(suites)) if suites else "General work"
        group = domains.setdefault(label, {"label": label, "total": 0, "done": 0})
        group["total"] += 1
        group["done"] += row["status"] == "done"
    return {"totals": {"total": len(goals), "active": by_status.get("active", 0),
                       "done": by_status.get("done", 0), "blocked": by_status.get("blocked", 0)},
            "by_status": by_status,
            "window": {"started": count("created_at", since, now), "delivered": count("updated_at", since, now, True),
                       "started_prev": count("created_at", previous, since), "delivered_prev": count("updated_at", previous, since, True)},
            "daily": list(daily.values()), "domains": sorted(domains.values(), key=lambda row: row["total"], reverse=True),
            "recent": _recent(request, world, goals)}


def _spend(request, world, owner, days, goals=None):
    from datetime import datetime, timezone

    from maverick.workforce_value import _is_done
    from maverick.world_model import _dec_field

    from .board_data import _board_day_list

    dates, since, previous = _board_day_list(days)
    columns = ("episode_id", "goal_id", "started_at", "ended_at", "outcome", "cost_dollars",
               "input_tokens", "output_tokens", "tool_calls", "domain", "owner")
    if goals is None:
        goals = _population(request, world, owner)
    cache, episodes = {}, []
    permitted_ids = {goal["id"] for goal in goals}
    # Filter before applying the row cap, so another workspace's episodes for
    # the same owner cannot exhaust this workspace's reporting budget.
    rows = []
    identifiers = sorted(permitted_ids)
    for start in range(0, len(identifiers), 400):
        batch = identifiers[start:start + 400]
        marks = ",".join("?" for _ in batch)
        rows.extend(_rows(world, "SELECT e.id,e.goal_id,e.started_at,e.ended_at,e.outcome,e.cost_dollars,"
                          "e.input_tokens,e.output_tokens,e.tool_calls,g.domain,g.owner "
                          "FROM episodes e JOIN goals g ON e.goal_id=g.id WHERE g.owner=? "
                          f"AND g.id IN ({marks}) ORDER BY e.id", (owner, *batch)))
        if len(rows) > _LIMIT:
            raise HTTPException(503, "This board is too large to read safely right now. Your permitted tasks remain available in Chat.")
    rows.sort(key=lambda values: values[0])
    for values in rows:
        row = dict(zip(columns, values, strict=True))
        if row["goal_id"] in permitted_ids and _permitted(request, {**row, "id": row["goal_id"]}, cache):
            row["outcome"] = _dec_field(row["outcome"])
            try:
                price = float(row["cost_dollars"])
                row["cost_dollars"] = price if math.isfinite(price) and price >= 0 else None
            except (TypeError, ValueError, OverflowError):
                row["cost_dollars"] = None
            episodes.append(row)
    now = time.time()
    finished = [row for row in episodes if row["ended_at"] is not None]
    selected = [row for row in finished if since <= row["started_at"] < now]
    def add_price(left, right):
        value = left + right
        if not math.isfinite(value):
            raise HTTPException(503, "These recorded prices cannot be totaled safely. Review the task cost records before using this report.")
        return value
    def total(values):
        amount = 0.0
        for row in values:
            amount = add_price(amount, row["cost_dollars"] or 0)
        return {"dollars": amount,
                "runs": len(values), "unknown_prices": sum(row["cost_dollars"] is None for row in values),
                **{key: sum(int(row[key] or 0) for row in values) for key in ("input_tokens", "output_tokens", "tool_calls")}}
    daily = {day.isoformat(): {"d": day.isoformat(), "cost": 0.0, "runs": 0, "unknown_prices": 0} for day in dates}
    top, domain_prices = {}, {}
    for row in selected:
        day = datetime.fromtimestamp(row["started_at"], timezone.utc).date().isoformat()
        bucket = daily.get(day)
        if bucket is not None:
            bucket["runs"] += 1
            bucket["cost"] = add_price(bucket["cost"], row["cost_dollars"] or 0)
            bucket["unknown_prices"] += row["cost_dollars"] is None
        group = top.setdefault(row["goal_id"], {"goal_id": row["goal_id"], "cost": 0.0, "runs": 0, "unknown_prices": 0})
        group["cost"] = add_price(group["cost"], row["cost_dollars"] or 0)
        group["runs"] += 1
        group["unknown_prices"] += row["cost_dollars"] is None
        domain_group = domain_prices.setdefault(row["domain"] or "", {"cost": 0.0, "runs": 0, "unknown_prices": 0})
        domain_group["cost"] = add_price(domain_group["cost"], row["cost_dollars"] or 0)
        domain_group["runs"] += 1
        domain_group["unknown_prices"] += row["cost_dollars"] is None
    top_rows = []
    for row in sorted(top.values(), key=lambda value: value["cost"], reverse=True)[:8]:
        goal = world.get_goal(row["goal_id"])
        if goal and goal.owner == owner and auth.can_access_goal(request, goal):
            top_rows.append({**row, "title": goal.title})
    outcomes = {"success": 0, "failed": 0, "running": 0}
    for row in episodes:
        if since <= row["started_at"] < now:
            outcomes["running" if row["ended_at"] is None else "success" if _is_done(row["outcome"]) else "failed"] += 1
    recent = [{key: row[key] for key in columns[:9]} for row in sorted(episodes, key=lambda row: row["episode_id"], reverse=True)[:50]]
    for row in recent:
        row["id"] = row.pop("episode_id")
    return {"totals": total(selected), "all_time": total(finished),
            "prev": total([row for row in finished if previous <= row["started_at"] < since]),
            "daily": list(daily.values()), "outcomes": outcomes,
            "outcomes_population": "Your permitted attempts started in this period. A task can have several attempts; running attempts are excluded from finished-attempt cost totals.",
            "per_run": [{"id": row["id"], "goal_id": row["goal_id"], "cost": row["cost_dollars"]} for row in recent],
            "top_goals": top_rows, "by_platform": [], "episodes": recent, "cost_notice": COST_NOTICE,
            "_domain_prices": domain_prices,
            "_read_domains": [domain for domain, admitted in cache.items() if admitted]}


def _practice_line(request, owner, days):
    """Practice runs cost real provider money: the same permitted-own,
    department-checked population as the real figures, read from the practice
    world and reported on its own line, never inside the board's totals."""
    from maverick import practice, practice_costs

    if practice.active():
        return None  # a practising person's board already is practice
    try:
        world = practice_costs.practice_world()
        if world is None:
            return None
        with practice.scope():
            totals = _spend(request, world, owner, days)["totals"]
    except Exception:  # noqa: BLE001 -- the board stays readable without the practice line
        return None
    if not totals["runs"]:
        return None
    line = {"dollars": totals["dollars"], "runs": totals["runs"], "unknown_runs": totals["unknown_prices"],
            "input_tokens": totals["input_tokens"], "output_tokens": totals["output_tokens"],
            "counted_against_limits": False}
    line["text"] = practice_costs.label(line, f"in the last {days} days")
    return line


def _workforce(request, world, goals, prices):
    from maverick.domain import available_domains
    profiles = available_domains()
    groups = {}
    for goal in goals:
        domain = goal["domain"] or ""
        profile = profiles.get(domain)
        label = (getattr(profile, "description", "") or "Your specialist").split("\n")[0][:180] if domain else "General work"
        row = groups.setdefault(domain, {"label": label, "total": 0, "active": 0, "done": 0,
                                        **prices["_domain_prices"].get(domain, {"cost": 0.0, "runs": 0, "unknown_prices": 0})})
        row["total"] += 1
        row["active"] += goal["status"] == "active"
        row["done"] += goal["status"] == "done"
    return {"totals": {"specialists": sum(bool(key) for key in groups), "tasks": len(goals),
                       "active": sum(row["status"] == "active" for row in goals),
                       "done": sum(row["status"] == "done" for row in goals)},
            "specialists": sorted(groups.values(), key=lambda row: row["total"], reverse=True),
            "recent": _recent(request, world, goals), "cost_notice": COST_NOTICE,
            "totals_price": prices["totals"],
            "source_notice": "Specialists observed on your permitted tasks, not company headcount or available capacity. Task status counts are all time; attempt prices use the selected period."}


def _savings(request, world, owner, goals, prices):
    from maverick import config

    from . import outcome_pilots
    from .outcome_pilot_sources import goal_source

    permitted = {row["id"]: row for row in goals}
    accepted = 0
    identifiers = sorted(permitted)
    count = 0
    for start in range(0, len(identifiers), 400):
        batch = identifiers[start:start + 400]
        marks = ",".join("?" for _ in batch)
        rows = _rows(world, "SELECT s.goal_id,s.decision,s.decided_by FROM signoffs s "
                     "JOIN goals g ON s.goal_id=g.id WHERE g.owner=? "
                     f"AND g.id IN ({marks})", (owner, *batch))
        count += len(rows)
        if count > _LIMIT:
            raise HTTPException(503, "This board is too large to read safely right now. Your permitted tasks remain available in Chat.")
        for goal_id, decision, reviewer in rows:
            if goal_id in permitted and permitted[goal_id]["status"] == "done" and decision == "approved" and str(reviewer or "").startswith("user:"):
                accepted += 1
    comparisons, source_state = [], "current"
    enabled = not config.config_source_errors(include_tenant=True) and config.get_features().get("outcome_measurement") is True
    if not auth.has_permission(request, "operate") or not enabled:
        source_state = "unavailable"
        source_notice = "Recorded comparison access requires permission to operate and Outcome measurement enabled in Settings. Your current task results are shown below."
    else:
        source_notice = "Recent comparisons containing only your currently permitted tasks. Mixed-owner, inaccessible or non-task comparisons are excluded; open Workflow pilots to review the full permitted list."
        try:
            listing = outcome_pilots.listing(context_for(request), limit=20)
            source_state = "partial" if listing["partial"] else "current"
            for item in listing["items"]:
                record = outcome_pilots.get(item["id"], context_for(request))
                cases = record["cases"]
                if not cases or any(case["kind"] != "goal" or int(case["reference"]) not in permitted for case in cases):
                    continue
                def resolve(kind, reference):
                    goal = world.get_goal(int(reference))
                    if kind != "goal" or not goal or goal.owner != owner or not auth.can_access_goal(request, goal):
                        raise LookupError("Task unavailable.")
                    return goal_source(request, reference)
                report = outcome_pilots.report(record, resolve=resolve)
                if any(row["status"] == "unavailable" for row in report["cases"]):
                    continue
                group = report["groups"]["all"]
                comparisons.append({"title": report["title"], "planned": group["planned"], "paired": group["paired"],
                                    "accepted": group["accepted"], "minutes_difference": group["reported_minutes_difference"],
                                    "cost_difference": group["reported_cost_difference"] if report["evidence_readiness"]["reported_cost_comparison_ready"] else None,
                                    "currency": group["currency"],
                                    "missing": group["planned"] - group["paired"],
                                    "ready": report["evidence_readiness"]["reported_effort_comparison_ready"],
                                    "next_steps": report["evidence_readiness"]["next_steps"]})
        except Exception:
            comparisons, source_state = [], "unavailable"
            source_notice = "Recorded comparisons could not be read. Refresh to check again; no savings estimate has been substituted."
    return {"totals": {"finished": sum(row["status"] == "done" for row in goals), "accepted": accepted,
                       "comparisons": len(comparisons), "paired": sum(row["paired"] for row in comparisons)},
            "comparisons": comparisons, "comparison_source": source_state, "source_notice": source_notice,
            "totals_price": prices["totals"], "cost_notice": COST_NOTICE, "savings_notice": SAVINGS_NOTICE,
            "recent": _recent(request, world, goals)}


def _oversight(request, world, owner, goals):
    from maverick.channel_approvals import card_content

    from .approval_queue_operations import safe
    from .content_access import can_read_approval

    _require_oversight(request)
    permitted = {row["id"]: row for row in goals}
    requests, bindings = [], []
    approval_ids = world.pending_unattached_approval_ids(owner, limit=_LIMIT + 1)
    identifiers = sorted(permitted)
    for start in range(0, len(identifiers), 400):
        approval_ids.extend(world.pending_goal_approval_ids(identifiers[start:start + 400], limit=_LIMIT + 1))
        if len(approval_ids) > _LIMIT:
            raise HTTPException(503, "This board is too large to read safely right now. Your permitted tasks remain available in Chat.")
    if len(approval_ids) > _LIMIT:
        raise HTTPException(503, "This board is too large to read safely right now. Your permitted tasks remain available in Chat.")
    for approval_id in sorted(approval_ids, reverse=True):
        row = world.get_approval(approval_id, strict_tenant=True)
        if not row or row.status != "pending" or not can_read_approval(request, row, world) or not auth.domain_suites_allowed(request, row.department):
            continue
        if row.goal_id:
            goal = world.get_goal(row.goal_id)
            if row.goal_id not in permitted or not goal or goal.owner != owner or not auth.can_access_goal(request, goal):
                continue
        elif row.requested_by != owner:
            continue
        card = card_content(row)
        requests.append({"label": safe(card["summary"]), "detail": safe(card["risk_label"]) + " · " +
                        {"current": "Ready for review", "expired": "Needs a fresh review", "legacy": "Needs a fresh review"}.get(card["status"], "Open full review"),
                         "href": f"/approvals#approval-{row.id}"})
        bindings.append((row.id, digest(vars(row))))
    stops = []
    stop_rows = []
    identifiers = sorted(permitted)
    for start in range(0, len(identifiers), 400):
        batch = identifiers[start:start + 400]
        marks = ",".join("?" for _ in batch)
        stop_rows.extend(_rows(world, "SELECT r.goal_id,r.created_at FROM goal_mutation_receipts r "
                               "JOIN goals g ON r.goal_id=g.id WHERE r.kind='stop' AND r.actor=? "
                               f"AND g.owner=? AND g.id IN ({marks}) ORDER BY r.created_at DESC", (owner, owner, *batch)))
        if len(stop_rows) > _LIMIT:
            raise HTTPException(503, "This board is too large to read safely right now. Your permitted tasks remain available in Chat.")
    stop_rows.sort(key=lambda row: row[1], reverse=True)
    for goal_id, created_at in stop_rows:
        goal = world.get_goal(goal_id)
        if goal_id in permitted and goal and goal.owner == owner and auth.can_access_goal(request, goal):
            stops.append({"title": goal.title, "href": f"/chat/goal/{goal.id}", "recorded_at": created_at,
                          "status": goal.status, "detail": "Your stop request was recorded. Cleanup and outside-effect reversal are not verified here."})
    active = []
    for row in sorted(goals, key=lambda value: value["updated_at"], reverse=True):
        if row["status"] != "active":
            continue
        goal = world.get_goal(row["id"])
        if goal and goal.owner == owner and goal.status == "active" and auth.can_access_goal(request, goal):
            active.append({"id": goal.id, "title": goal.title, "status": goal.status, "updated_at": goal.updated_at, "activity": ""})
    return {"totals": {"pending": len(requests), "active": len(active), "stop_requests": len(stops)},
            "requests": requests[:20], "stop_requests": stops[:12], "active_goals": active,
            "oversight_notice": OVERSIGHT_NOTICE, "_approval_bindings": bindings}


def build(request, board: str, days: int | None = None) -> dict:
    original_context = check_context(request)
    if board not in SCOPED_BOARDS or not scoped(request):
        raise HTTPException(403, "This department board is unavailable for your current access. Reload to open your current board.")
    owner = auth.goal_owner_filter(request)
    if owner is None:
        raise HTTPException(403, "Sign in to read your permitted work.")
    days = days if days in _DAYS else 90
    world = _world()
    goals = _population(request, world, owner)
    if board == "overview":
        payload = _overview(request, world, goals, days)
    elif board == "oversight":
        payload = _oversight(request, world, owner, goals)
    else:
        prices = _spend(request, world, owner, days, goals)
        payload = prices if board == "spend" else _workforce(request, world, goals, prices) if board == "workforce" else _savings(request, world, owner, goals, prices)
        prices.pop("_domain_prices", None)
        prices.pop("_read_domains", None)
        payload["practice"] = _practice_line(request, owner, days)
    admitted_domains = {row["domain"] or "" for row in goals}
    # A fork can acquire an inherited department or a pack can disappear while
    # the grants remain unchanged. Check the native mapping again at release.
    if any(not auth.domain_suites_allowed(request, domain) for domain in admitted_domains):
        raise HTTPException(409, "A specialist's department access changed while this report was read. Reload this page to read current permitted work.")
    current = {row["id"]: row["domain"] for row in _population(request, world, owner)}
    if any(row["id"] not in current or current[row["id"]] != row["domain"] for row in goals):
        raise HTTPException(409, "Task ownership or department access changed while this report was read. Reload to read current permitted work.")
    for approval_id, identity in payload.pop("_approval_bindings", []):
        row = world.get_approval(approval_id, strict_tenant=True)
        if not row or digest(vars(row)) != identity or not auth.domain_suites_allowed(request, row.department):
            raise HTTPException(409, "A request changed while this report was read. Refresh to read the current requests.")
    if not hmac.compare_digest(original_context, check_context(request)):
        raise HTTPException(409, "Your account, workspace or department access changed. Reload this page.")
    payload.update(board=board, days=days, scope="permitted_own", scope_notice=SCOPE_NOTICE,
                   context=original_context, generated_at=time.time())
    return payload


def page(request, board: str):
    from .app import templates
    if board not in SCOPED_BOARDS or not scoped(request):
        raise HTTPException(404, "This board is unavailable.")
    if board == "oversight":
        _require_oversight(request)
    return templates.TemplateResponse(request, "department_board.html",
        {"board": board, "board_context": check_context(request), "scope_notice": SCOPE_NOTICE,
         "cost_notice": COST_NOTICE, "savings_notice": SAVINGS_NOTICE, "oversight_notice": OVERSIGHT_NOTICE,
         "can_operate": _oversight_allowed(request), "can_compare": auth.has_permission(request, "operate")})
