"""An employee's private background work; source coverage is never inferred."""
from __future__ import annotations

import time
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, Response

from .auth import assert_goal_access, caller_principal, has_permission, require_permission
from .draft_api import context_for
from .run_status import status_label

router = APIRouter(tags=["my-work"])
LIMIT = 200


def _task_source(request, world, owner):
    rows, coverage = [], []
    try:
        goals = world.list_goals(owner=owner, order="desc", limit=LIMIT + 1)
        for goal in goals[:LIMIT]:
            if (goal.owner or "") != owner:
                continue
            try:
                assert_goal_access(request, goal)
            except HTTPException:
                continue
            status = goal.status
            detail = {"draft": "Prepared; review and explicitly start when ready.",
                      "pending": "Waiting to start.", "active": "Work is running.", "running": "Work is running.",
                      "blocked": "Waiting for an answer or another prerequisite. Open the task for the current blocker.",
                      "failed": "Stopped with a problem. Review its evidence before choosing whether to retry.",
                      "cancelled": "Stopped. Cleanup may still be finishing; earlier external changes are not undone.",
                      "done": "Saved result is ready for review. This alone does not verify external delivery."}.get(status, "Open the task to review its current state.")
            # The same words the task page and the chat list use (run_status.py).
            rows.append({"kind": "task", "id": str(goal.id), "title": goal.title,
                         "state": status_label(status) or status,
                         "detail": detail, "updated_at": goal.updated_at,
                         "href": f"/chat/goal/{goal.id}", "action": "Open result" if status == "done" else "Open task controls"})
        coverage.append({"source": "Tasks and saved outcomes", "state": "partial" if len(goals) > LIMIT else "current"})
    except Exception:
        coverage.append({"source": "Tasks and saved outcomes", "state": "unavailable"})
    return rows, coverage


def _schedule_source(owner):
    rows, coverage = [], []
    try:
        from maverick.job_queue import JobQueue
        from maverick.schedule_definitions import list_definitions

        schedules = list_definitions(JobQueue(), owner=owner)
        for schedule in schedules[:LIMIT]:
            if (schedule.get("owner") or "") != owner:
                continue
            history = schedule.get("history") or []
            occurrence = history[0] if history else None
            detail = "Schedule " + schedule["state"] + "."
            if schedule.get("running"):
                detail += " An occurrence is still running; pausing stops future starts."
            if occurrence:
                detail += " Latest recorded occurrence: " + str(occurrence.get("status", "unknown")) + "."
                if occurrence.get("recurrence_reconcile_required"):
                    detail += " Recurrence recovery needs review."
            rows.append({"kind": "schedule", "id": str(schedule["definition_id"]), "title": schedule["title"],
                         "state": schedule["state"], "detail": detail, "updated_at": occurrence.get("updated_at", 0) if occurrence else 0,
                         "href": "/automations", "action": "Review schedule and occurrences"})
        coverage.append({"source": "Schedule occurrences", "state": "partial" if len(schedules) > LIMIT else "current"})
    except Exception:
        coverage.append({"source": "Schedule occurrences", "state": "unavailable"})
    return rows, coverage


def _workflow_source(request, owner):
    rows, coverage = [], []
    try:
        from maverick import flow
        from maverick.flow import store

        from .flows_api import _assert_flow_access

        if not flow.enabled():
            coverage.append({"source": "Workflow runs", "state": "disabled"})
        else:
            runs = store.list_run_metadata(owner=owner, limit=LIMIT + 1)
            source_state = "partial" if len(runs) > LIMIT else "current"
            for run in runs[:LIMIT]:
                if (run.owner or "") != owner:
                    continue
                try:
                    definition = store.load_flow_snapshot(run.definition_digest) if run.definition_digest else store.load_flow(run.flow_id)
                    if definition is None:
                        source_state = "unavailable"
                        continue
                    if (definition.owner or "") != owner:
                        continue
                    _assert_flow_access(request, definition)
                except HTTPException:
                    continue
                except Exception:
                    source_state = "unavailable"
                    continue
                rows.append({"kind": "workflow", "id": run.run_id, "title": definition.name,
                             "state": run.status, "detail": "Recorded workflow state. Open its receipts to distinguish authorized, executed and externally verified actions.",
                             "updated_at": run.updated, "href": f"/flows/{quote(run.flow_id, safe='')}/runs/{quote(run.run_id, safe='')}",
                             "action": "Review workflow controls and receipts"})
            coverage.append({"source": "Workflow runs", "state": source_state})
    except Exception:
        coverage.append({"source": "Workflow runs", "state": "unavailable"})
    return rows, coverage


def _connection_source(request):
    rows, coverage = [], []
    try:
        from .connection_dependencies import connection_attention

        connections = connection_attention(request)
        for item in connections["items"][:LIMIT]:
            rows.append({"kind": "connection", "id": item["name"], "title": item["title"], "state": "needs attention",
                         "detail": item["reason"], "updated_at": 0, "href": item["href"], "action": "Review your connection"})
        coverage.append({"source": "Connection dependencies", "state": "partial" if len(connections["items"]) > LIMIT else connections["coverage"]})
    except Exception:
        coverage.append({"source": "Connection dependencies", "state": "unavailable"})
    return rows, coverage

def _model(request):
    from .app import _world

    owner = caller_principal(request) or ""
    rows, coverage = _task_source(request, _world(), owner)
    if has_permission(request, "operate"):
        for items, source_coverage in (_schedule_source(owner), _workflow_source(request, owner), _connection_source(request)):
            rows.extend(items)
            coverage.extend(source_coverage)
    else:
        coverage.extend({"source": source, "state": "not permitted"} for source in ("Schedule occurrences", "Workflow runs", "Connection dependencies"))
    rows.sort(key=lambda row: (-float(row["updated_at"] or 0), row["kind"], row["id"]))
    return {"items": rows, "coverage": coverage, "context": context_for(request), "generated_at": time.time()}


@router.get("/api/v1/my-work")
def my_work(request: Request, response: Response):
    require_permission(request, "view")
    response.headers["Cache-Control"] = "private, no-store"
    return _model(request)


@router.get("/my-work")
def my_work_page(request: Request):
    from .app import templates
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)  # areas mode: Tasks with background work
    if moved is not None:
        return moved
    require_permission(request, "view")
    return templates.TemplateResponse(request, "my_work.html", {"work_context": context_for(request)},
                                      headers={"Cache-Control": "private, no-store"})
