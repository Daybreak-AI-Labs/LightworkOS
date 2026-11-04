"""Bounded current-owner specialist activity from the native task records."""
from __future__ import annotations

import math
import re
import time
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from maverick import domain_edit
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.stop_reasons import stop_payload

from . import auth
from .draft_api import context_for
from .plain_labels import pack_display_name
from .run_status import status_label

HEADER = "X-Lightwork-Agent-Activity-Context"
SCOPE = ("The newest 50 recorded tasks available to this account for this specialist, limited to the chosen period and tasks you can currently open. "
         "Counts describe their current state; the trend counts when these tasks were created, not past success rates. "
         "Recorded run cost is not a provider invoice. Finishing or approving an answer does not prove accuracy or business value.")


def authority(request, context=None):
    from .app import require_page_visible

    with auth.fresh_configuration():
        principal = getattr(request.state, "principal", None)
        if principal is not None:
            via = (principal.claims or {}).get("via")
            resolver = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                        "proxy": auth._proxy_principal}.get(via)
            fresh = resolver(request) if resolver else principal
            if fresh is None or fresh.principal != principal.principal:
                raise HTTPException(401, "Sign in again before reading specialist work.")
            request.state.principal = fresh
            expiry = (fresh.claims or {}).get("exp")
            if expiry is not None and (type(expiry) not in {int, float} or not time.time() < expiry < math.inf):
                raise HTTPException(401, "Sign in again before reading specialist work.")
            auth._enforce_scim_active(fresh)
            auth._enforce_workspace_policies(request, fresh)
        auth.require_permission(request, "view")
        auth.require_page_permission(request, "/agents")
        require_page_visible(request, "/agents")
        current = context_for(request)
        if context is not None and current != context:
            raise HTTPException(409, "Your account or workspace changed. Reload this page before reading private work.")
        return current


def _view(request, name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", name):
        raise HTTPException(404, "Choose a current specialist on Agent Factory.")
    view = domain_edit.resolved_view(name)
    if view is None:
        raise HTTPException(404, "This specialist is unavailable.")
    for suite in view["suites"]:
        auth.require_suite(request, suite)
    return view


def _cost(world, goal_id):
    # The native query keeps NULL prices distinct from an actually recorded zero.
    rows = world.query("SELECT COUNT(*) AS runs, SUM(cost_dollars) AS cost, "
                       "SUM(CASE WHEN cost_dollars IS NULL OR ended_at IS NULL THEN 1 ELSE 0 END) AS unknown "
                       "FROM episodes WHERE goal_id=?", (goal_id,))
    row = rows[0]
    value = row["cost"]
    if (not row["runs"] or row["unknown"] or value is None
            or not math.isfinite(float(value)) or float(value) < 0):
        return None, dict(row)
    return float(value), dict(row)


def _material(request, world, name, days, now):
    view = _view(request, name)
    owner = auth.goal_owner_filter(request)
    goals = world.list_goals(owner=owner, domain=name, limit=51, order="desc")
    cutoff = now - days * 86400
    tasks, bindings = [], []
    counts = {"finished": 0, "waiting": 0, "stopped": 0, "working": 0, "queued": 0, "other": 0, "approved": 0}
    for goal in goals[:50]:
        if not auth.can_access_goal(request, goal) or not cutoff <= goal.created_at <= now:
            continue
        # Native sources retain the complete answer. This read emits no answer or question body.
        waiting = bool(world.query("SELECT id FROM questions WHERE goal_id=? AND answer IS NULL LIMIT 1", (goal.id,))) if goal.status == "blocked" else False
        stop = None if waiting else stop_payload(goal.status, goal.result)
        status = "Waiting for your answer" if waiting else status_label(goal.status, stop["kind"] if stop else None) or "State unavailable"
        group = ("waiting" if waiting else "finished" if goal.status in {"done", "completed"}
                 else "stopped" if goal.status in {"blocked", "failed", "error", "cancelled"}
                 else "working" if goal.status in {"active", "running", "in_progress"}
                 else "queued" if goal.status in {"pending", "draft"} else "other")
        price, cost_source = _cost(world, goal.id)
        signoff = world.signoff_for(goal.id)
        approved = bool(goal.status == "done" and signoff and signoff.get("decision") == "approved")
        counts[group] += 1
        counts["approved"] += int(approved)
        tasks.append({"id": goal.id, "title": goal.title, "href": f"/chat/goal/{goal.id}",
                      "status": status, "group": group, "created_at": goal.created_at, "updated_at": goal.updated_at,
                      "reason": "An answer is needed before work can continue." if waiting else stop["message"] if stop else "",
                      "next_step": "Open the task and answer its question." if waiting else stop["action"] if stop else "",
                      "cost": price, "approved": approved})
        bindings.append([goal.id, goal.owner, goal.title, goal.description, goal.domain, goal.status,
                         goal.created_at, goal.updated_at, goal.result, waiting, signoff, cost_source])
    return {"view": view, "tasks": tasks, "counts": counts, "more": len(goals) > 50,
            "binding": digest([owner, view, bindings, [goal.id for goal in goals]])}


def read(request, name, days=30, *, context=None):
    if type(days) is not int or days not in {7, 30, 90}:
        raise HTTPException(422, "Choose 7, 30 or 90 days.")
    from .app import _world

    with authority_effect_fence(), auth.fresh_configuration():
        current = authority(request, context)
        world = _world()
        now = time.time()
        try:
            material = _material(request, world, name, days, now)
            authority(request, current)
            repeated = _material(request, world, name, days, now)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(503, "Recent specialist work could not be read. Refresh this view; no work was changed.") from exc
        if material["binding"] != repeated["binding"]:
            raise HTTPException(409, "The specialist or its recorded tasks changed while loading. Refresh recent work again.")
        authority(request, current)
        start = datetime.fromtimestamp(now - days * 86400, timezone.utc).date()
        today = datetime.fromtimestamp(now, timezone.utc).date()
        span = (today - start).days + 1
        width = 1 if days == 7 else 7
        trend = []
        for offset in range(0, span, width):
            first, last = start + timedelta(days=offset), min(start + timedelta(days=offset + width - 1), today)
            trend.append({"from": first.isoformat(), "to": last.isoformat(), "tasks": sum(
                first <= datetime.fromtimestamp(task["created_at"], timezone.utc).date() <= last for task in material["tasks"])})
        return {"context": current, "revision": digest([current, days, material["binding"]]), "name": name,
                "label": pack_display_name(name, material["view"].get("persona", ""), material["view"].get("description", "")), "days": days, "tasks": material["tasks"],
                "trend": trend, "counts": material["counts"], "scope": SCOPE, "more": material["more"],
                "cost_unknown": sum(task["cost"] is None for task in material["tasks"])}
