"""Request-authorized, read-only context for Copilot on record pages.

Record text is returned only to the same caller who can read the native record.
The caller of this module must keep it out of model prompts and guide history.
"""

from __future__ import annotations

from dataclasses import replace
from unicodedata import category

from fastapi import HTTPException, Request

from .copilot_context import CopilotPageContext, record_detail_for_page


def _label(value: object, fallback: str) -> str:
    """Bound record labels for the text-only panel, without changing their meaning."""

    text = " ".join(str(value or "").split())
    text = "".join(char for char in text if not category(char).startswith("C"))
    return text[:80] if text else fallback


def _status(value: object) -> str:
    labels = {
        "pending": "waiting to start", "queued": "waiting to start",
        "running": "running", "completed": "complete", "complete": "complete",
        "done": "complete", "failed": "failed", "blocked": "blocked",
        "cancelled": "cancelled", "canceled": "cancelled", "paused": "paused",
        "paused_approval": "waiting for a person's decision",
        "paused_event": "waiting for an event", "rejected": "rejected",
    }
    return labels.get(str(value or "").casefold(), "status unavailable")


def _read_request(request: Request) -> Request:
    """Use the native GET read rule even when the guide question uses POST.

An approved content reader may view a task but cannot mutate it. Copilot only
reads, so it must use that same GET permission rather than the POST mutation
rule that the guide's transport method would otherwise trigger.
"""

    return Request({**request.scope, "method": "GET"})


def authorized_detail_context(
    request: Request, page: object, context: CopilotPageContext,
) -> tuple[CopilotPageContext, bool]:
    """Return a caller-visible detail context and whether it contains record data."""

    detail = record_detail_for_page(page)
    if detail is None:
        return context, False
    kind, parts = detail
    if kind in {"task", "task_chat"}:
        from maverick.stop_reasons import stop_payload

        from .app import _world
        from .auth import assert_goal_access

        goal = _world().get_goal(int(parts[0]))
        if goal is None:
            raise HTTPException(404, "no such task")
        assert_goal_access(_read_request(request), goal)
        title = _label(goal.title, "Untitled task")
        status = _status(goal.status)
        section = parts[1] if kind == "task" else ""
        opening = f"Task ‘{title}’ has status: {status}."
        stop = stop_payload(goal.status, getattr(goal, "result", None))
        reason = _label(stop.get("message"), "") if stop and stop.get("kind") != "other" else ""
        current = f"{opening} {reason}".strip()
        if section == "errors":
            next_step = "Review this task's error list and current result before retrying."
        elif section == "trajectory":
            next_step = "Review the timeline to see how this task reached its current state."
        elif section == "plan":
            next_step = "Review the plan and check which steps have finished."
        else:
            next_step = "Review the result and use the task tabs for its plan, timeline, or errors."
        return replace(
            context, title=context.title, summary=f"{current} {next_step}",
            next_steps=(current, next_step),
            capabilities=(f"Review the current result and status of task {title}.", *context.capabilities),
        ), True

    # The native flow APIs require operator access and a running flow feature.
    from maverick import flow as flow_engine

    from .auth import has_permission
    from .flows_api import _assert_flow_access, _load_owned_run

    if not has_permission(request, "operate"):
        return replace(
            context,
            summary=f"{context.summary} You need operator access to read this flow's details.",
        ), False
    if not flow_engine.enabled():
        return replace(context, summary=f"{context.summary} Flows are turned off in this installation."), False
    if kind == "flow_designer":
        from maverick.flow import store

        flow = store.load_flow(parts[0])
        if flow is None:
            raise HTTPException(404, "no such flow")
        _assert_flow_access(request, flow)
        name = _label(flow.name, "Untitled flow")
        opening = f"You are editing flow {name}."
        return replace(
            context, summary=f"{opening} Review its steps and inputs before saving or running it.",
            next_steps=(opening, "Review the steps and inputs, then check setup and access before running it."),
            capabilities=(f"Review and edit flow {name} in the designer.", *context.capabilities),
        ), True

    run = _load_owned_run(request, parts[1], allow_assignee=True)
    if run.flow_id != parts[0]:
        raise HTTPException(404, "no such run")
    opening = f"This flow run is {_status(run.status)}."
    return replace(
        context, summary=f"{opening} Review the step timeline and any pause or failure in the native run view.",
        next_steps=(opening, "Review the step timeline before approving, rejecting, or retrying."),
        capabilities=("Review this run's current state and its visible step timeline.", *context.capabilities),
    ), True
