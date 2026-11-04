"""A private composition of native work projections; no duplicate work state."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from urllib.parse import quote

from maverick import config

from . import auth

CARDS = {"tasks": "In-flight work", "decisions": "Pending decisions", "recent": "Recently changed results",
         "schedules": "Upcoming occurrences", "templates": "Pinned templates"}


def template_choices(request):
    from maverick.templates import can_read_template, list_templates, load_template
    principal = auth.caller_principal(request)
    result = {}
    if not auth.has_permission(request, "operate"):
        return result
    for name in list_templates():
        template = load_template(name)
        if not can_read_template(template, principal):
            continue
        result[name] = {"name": name, "title": template.title, "href": "/templates#template-" + quote(name, safe="")}
    return result


def _tasks(request, world, principal, since):
    active, recent, complete = [], [], True
    for status in ("pending", "active", "running", "blocked", "done"):
        rows = world.list_goals(owner=principal, status=status, limit=101, order="desc")
        complete = complete and len(rows) <= 100
        for goal in rows[:100]:
            if goal.owner != principal or not auth.domain_suites_allowed(request, goal.domain) or not auth.can_access_goal(request, goal):
                continue
            row = {"title": goal.title, "href": f"/chat/goal/{goal.id}", "status": goal.status, "updated_at": goal.updated_at}
            if status == "done":
                if goal.updated_at >= since:
                    recent.append(row)
            else:
                active.append(row)
    return {"active": sorted(active, key=lambda row: row["updated_at"], reverse=True)[:20],
            "recent": sorted(recent, key=lambda row: row["updated_at"], reverse=True)[:20],
            "coverage": "Current owned work, up to 100 tasks per state; cards show the latest 20." + (" More records exist; open Tasks for the full list." if not complete else "")}


_DECISION_SOURCES = {"approval": "Approvals", "flow_approval": "Flow approvals", "signoff": "Result approvals",
                     "assessment": "Assessments", "project_review": "Project reviews",
                     "vendor_reconciliation": "Vendor checks"}


def _decisions(request):
    from .action_center_api import _model, require_enabled
    require_enabled(request)
    value = _model(request)
    rows = [row for row in value["items"] if row["kind"] in {"approval", "signoff", "assessment", "project_review", "vendor_reconciliation"}]
    # Today is personal: it lists what waits on this person. Work anyone on the
    # team may pick up (an unassigned assessment, an unclaimed approval) stays
    # in Action Center and is only counted here, so nobody reads other
    # people's queues by default.
    mine = [row for row in rows if row["assignment"] == "mine"]
    # Report only real problems with the decision sources: a module that is
    # turned off, or a source that loaded fine, is not a load error.
    problems = [{**source, "label": _DECISION_SOURCES[source["kind"]]}
                for source in value["coverage"]
                if source["kind"] in _DECISION_SOURCES and source["status"] in ("partial", "unavailable")]
    return {"items": mine[:20], "count": len(mine), "available": len(rows) - len(mine),
            "coverage": problems, "observed_at": value["generated_at"]}


def _schedules(principal, until):
    from maverick.job_queue import JobQueue
    from maverick.schedule_definitions import list_definitions
    if not config.get_features().get("scheduling", True):
        return {"items": [], "state": "disabled", "message": "Scheduling is disabled by your administrator."}
    rows = [row for row in list_definitions(JobQueue(), owner=principal)
            if row.get("owner") == principal and row["state"] == "active" and 0 < row["next_run"] <= until]
    rows.sort(key=lambda row: row["next_run"])
    return {"items": [{"title": row["title"], "href": "/automations", "due": datetime.fromtimestamp(row["next_run"], timezone.utc).isoformat(),
                       "zone": row["zone"] or "UTC"} for row in rows[:20]],
            "state": "available", "message": f"Next occurrences of {len(rows)} owned active schedules in this period; showing up to 20. Open schedules for occurrence history."}


def project(request, world, preferences):
    auth.require_permission(request, "view")
    principal = auth.caller_principal(request)
    if not principal:
        raise ValueError("A named account is required.")
    now = time.time()
    days = preferences["values"].get("today_days", "7")
    days = int(days) if days in {"1", "7", "30"} else 7
    result = {"observed_at": datetime.fromtimestamp(now, timezone.utc).isoformat(), "period_days": days, "errors": {},
              "tasks": {"active": [], "recent": [], "coverage": "Unavailable"},
              "decisions": {"items": [], "count": None, "coverage": []},
              "schedules": {"items": [], "state": "unavailable", "message": "Upcoming schedules unavailable."},
              "template_choices": {}, "templates": []}
    readers = {"tasks": lambda: _tasks(request, world, principal, now - days * 86400),
               "schedules": lambda: _schedules(principal, now + days * 86400),
               "template_choices": lambda: template_choices(request)}
    if auth.has_permission(request, "operate"):
        readers["decisions"] = lambda: _decisions(request)
    for key, read in readers.items():
        try:
            result[key] = read()
        except Exception:
            result["errors"][key] = "This source could not be read. Open its native page to check its current state."
    result["templates"] = [result["template_choices"][name] for name in preferences["values"].get("template_favorites", []) if name in result["template_choices"]]
    auth.require_permission(request, "view")
    if principal != auth.caller_principal(request):
        raise ValueError("Your account changed. Refresh Today.")
    return result
