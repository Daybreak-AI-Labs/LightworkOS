"""Bounded, authorized answers to concrete live Copilot questions.

This is a read path, not a model tool. It never sends task or decision records
to an AI provider, and it uses the same projections and content checks as the
native pages. An incomplete source never becomes a claim that nothing is due.
"""
from __future__ import annotations

import hmac
import re
from datetime import datetime, timezone

from fastapi import HTTPException
from maverick import config

from . import auth
from .draft_api import context_for

_APPROVAL = re.compile(
    r"(?:what (?:needs|requires) (?:my |your )?approval|(?:show(?: me)?|list) (?:my )?(?:pending )?approvals|do i have (?:any )?(?:pending )?approvals)(?: please)?\Z"
)
_RUNNING = re.compile(
    r"(?:(?:show(?: me)?|list) my (?:running|active|in.progress) tasks|(?:what|which) (?:of my )?tasks are (?:running|active|in.progress))(?: please)?\Z"
)
_FAILURE = re.compile(
    r"why (?:did|has|is) (?:my|this|the|goal|task|run|goal \d+|task \d+|run \d+) (?:goal |task |run )?(?:fail|failed|stop|stopped|blocked)(?: please)?\Z"
)
_STATUS = re.compile(
    r"(?:what is (?:the status of )?(?:my |this |the )?(?:goal|task)(?: \d{1,18})?(?: status)?|(?:show|check) (?:my|this) (?:goal|task) status|how is (?:my|this) (?:goal|task) doing)(?: please)?\Z"
)
_FIND = re.compile(r"(?:find|search for|look up) my task(?: called| named)? (.{2,100})\Z")
_EXPLICIT_TASK = re.compile(r"\b(?:goal|task|run)\s*#?(\d{1,18})\b")
_PAGE_TASK = re.compile(r"^/(?:chat/goal|goals|tasks)/(\d{1,18})(?:/|$)")
_DECISIONS = frozenset({"approval", "signoff", "assessment", "project_review", "vendor_reconciliation"})


def intent(message: str) -> str | None:
    """Only exact read requests bypass the action classifier and model path."""
    normalized = " ".join(message.casefold().strip().rstrip("?!. ").split())
    if _APPROVAL.fullmatch(normalized):
        return "approvals"
    if _RUNNING.fullmatch(normalized):
        return "running_tasks"
    if _FAILURE.fullmatch(normalized):
        return "task_failure"
    if _STATUS.fullmatch(normalized):
        return "task_status"
    if _FIND.fullmatch(normalized):
        return "task_find"
    return None


def _checked_at() -> str:
    from .plain_labels import datetime_text

    return "on " + datetime_text(datetime.now(timezone.utc).timestamp())


def _answer(reply: str, href: str, label: str, source: str) -> dict:
    return {"reply": reply, "mode": "live", "source": source,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "action_link": {"href": href, "label": label}}


def _bounded(value, length=140):
    text = " ".join(str(value or "").split())
    return text if len(text) <= length else text[:length - 1] + "…"


def _decisions(request):
    from fastapi import Response

    from . import action_center_api
    from .api import list_approvals

    if not auth.has_permission(request, "operate"):
        return _answer("Your role cannot view the approval queue. Ask a workspace operator to review it with you.",
                       "/approvals", "Open approvals", "Approval access")
    if config.get_features().get("action_center") is True:
        action_center_api.require_enabled(request)
        value = action_center_api._model(request)
        rows = [row for row in value["items"] if row["kind"] in _DECISIONS]
        coverage = [row for row in value["coverage"] if row["kind"] in _DECISIONS or row["kind"] == "flow_approval"]
        uncertain = any(row["status"] != "current" for row in coverage) or len(rows) > 8
        if rows:
            shown = "; ".join(f"{i}. {_bounded(row['title'])} ({row['kind'].replace('_', ' ')})"
                              for i, row in enumerate(rows[:8], 1))
            reply = f"Checked your Action Center {_checked_at()}. I found {len(rows)} accessible decisions: {shown}."
        else:
            reply = f"Checked your Action Center {_checked_at()}. No accessible decisions were returned."
        if uncertain:
            reply += " Some sources were unavailable or the list is shortened; open Action Center to check the full current view."
        return _answer(reply, "/action-center", "Open Action Center", "Action Center")

    value = list_approvals(request, Response())
    rows = value["approvals"] + value["flow_approvals"]
    if rows:
        shown = "; ".join(f"{i}. {_bounded(row.get('action') or row.get('title'))}"
                          for i, row in enumerate(rows[:8], 1))
        reply = f"Checked the pending approvals inbox {_checked_at()}. I found {len(rows)} approvals you can access: {shown}."
    else:
        reply = f"Checked the pending approvals inbox {_checked_at()}. No accessible approvals were returned."
    reply += " This inbox does not include every other kind of decision."
    if len(rows) > 8 or value.get("flow_approval_coverage") != "current":
        reply += " The displayed list may be incomplete; open Approvals to review current records."
    return _answer(reply, "/approvals", "Open approvals", "Approvals")


def _running_tasks(request):
    from .app import _world

    auth.require_permission(request, "view")
    owner = auth.goal_owner_filter(request)
    world = _world()
    rows, partial = [], False
    for state in ("running", "active"):
        found = world.list_goals(owner=owner, status=state, limit=51, order="desc")
        partial = partial or len(found) > 50
        for goal in found[:50]:
            if (goal.owner == owner and auth.domain_suites_allowed(request, goal.domain)
                    and auth.can_access_goal(request, goal)):
                rows.append(goal)
    rows.sort(key=lambda goal: goal.updated_at, reverse=True)
    if rows:
        shown = "; ".join(f"{i}. {_bounded(goal.title)} ({goal.status})"
                          for i, goal in enumerate(rows[:8], 1))
        reply = f"Checked your Tasks {_checked_at()}. I found {len(rows)} running or active tasks I can show: {shown}."
    else:
        reply = f"Checked your Tasks {_checked_at()}. I found no running or active tasks I can show for your account."
    if partial or len(rows) > 8:
        reply += " This is a shortened list; open Tasks for the current full view."
    return _answer(reply, "/goals", "Open Tasks", "Tasks")


def _task_id(message: str, page: str, selected_goal_id: int | None) -> int | None:
    explicit = _EXPLICIT_TASK.search(message.casefold())
    if explicit:
        return int(explicit.group(1))
    if selected_goal_id:
        return selected_goal_id
    selected_page = _PAGE_TASK.fullmatch(page)
    return int(selected_page.group(1)) if selected_page else None


def _task_failure(request, message: str, page: str, selected_goal_id: int | None):
    from maverick.stop_reasons import stop_payload

    from .app import _world
    from .goal_waiting import open_question_ids

    auth.require_permission(request, "view")
    identifier = _task_id(message, page, selected_goal_id)
    if identifier is None:
        return _answer("Open the task you mean, then ask why it stopped. I need a specific task to check its current reason.",
                       "/goals", "Open Tasks", "Tasks")
    world = _world()
    goal = world.get_goal(identifier)
    if goal is None:
        return _answer("I can't access that task in this account and workspace.",
                       "/goals", "Open Tasks", "Tasks")
    try:
        auth.assert_goal_access(request, goal)
    except HTTPException:
        return _answer("I can't access that task in this account and workspace.",
                       "/goals", "Open Tasks", "Tasks")
    href = f"/chat/goal/{identifier}"
    open_ids = open_question_ids(world, goal) if goal.status == "blocked" else []
    stop = stop_payload(goal.status, goal.result)
    fresh = world.get_goal(identifier)
    if (fresh is None or fresh.status != goal.status or fresh.updated_at != goal.updated_at
            or fresh.result != goal.result):
        return _answer("This task changed while I checked it. Open its current progress and ask again.",
                       href, "Open task progress", "Task progress")
    auth.assert_goal_access(request, fresh)
    title = _bounded(goal.title)
    if open_ids:
        reply = f"Checked task ‘{title}’ {_checked_at()}. It is waiting for an answer from you. Open the task to read and answer the current question."
    elif stop:
        reply = f"Checked task ‘{title}’ {_checked_at()}. {stop['message']} {stop['action']}"
    else:
        reply = f"Checked task ‘{title}’ {_checked_at()}. Its current state is {goal.status}; no failure reason is recorded for that state."
    return _answer(reply, href, "Open task progress", "Task progress")


def _find_tasks(request, message: str):
    from .app import _world

    auth.require_permission(request, "view")
    match = _FIND.fullmatch(" ".join(message.casefold().strip().rstrip("?!. ").split()))
    if match is None:
        raise ValueError("a bounded search term is required")
    query = match.group(1).strip()
    owner = auth.goal_owner_filter(request)
    found = _world().search_goals(query, owner=owner, limit=21)
    rows = [goal for goal in found if goal.owner == owner
            and auth.domain_suites_allowed(request, goal.domain)
            and auth.can_access_goal(request, goal)]
    if rows:
        shown = "; ".join(f"{i}. {_bounded(goal.title)} ({goal.status})"
                          for i, goal in enumerate(rows[:8], 1))
        reply = f"Searched your Tasks {_checked_at()}. I found {len(rows)} accessible matches: {shown}."
    else:
        reply = f"Searched your Tasks {_checked_at()}. I found no accessible matches for that title or text."
    if len(found) > 20 or len(rows) > 8:
        reply += " This is a shortened list; open Tasks to search the full current view."
    return _answer(reply, "/goals", "Open Tasks", "Tasks")


def answer(request, message: str, page: str, selected_goal_id: int | None) -> dict | None:
    selected = intent(message)
    if selected is None:
        return None
    before = context_for(request)
    try:
        if selected == "approvals":
            value = _decisions(request)
        elif selected == "running_tasks":
            value = _running_tasks(request)
        elif selected == "task_find":
            value = _find_tasks(request, message)
        else:
            value = _task_failure(request, message, page, selected_goal_id)
    except HTTPException:
        raise
    except Exception:
        value = _answer("I couldn't confirm the current records. Open the native page to check their status before acting.",
                        "/approvals" if selected == "approvals" else "/goals",
                        "Open approvals" if selected == "approvals" else "Open Tasks", "Source unavailable")
    if not hmac.compare_digest(before, context_for(request)):
        raise HTTPException(409, "Your account or workspace changed. Reopen Copilot before using this answer.")
    return value
