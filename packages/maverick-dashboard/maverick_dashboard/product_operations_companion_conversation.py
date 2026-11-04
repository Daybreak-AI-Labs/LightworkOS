"""Selected private companion work checks and the existing bounded draft turn."""
from __future__ import annotations

import secrets
import time
from decimal import Decimal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field
from starlette.background import BackgroundTask

from . import employee_companion_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

_PAGE = "/companion"
_TASK_STATES = {"active": "Running", "pending": "Waiting", "blocked": "Needs attention",
                "failed": "Failed", "error": "Needs attention", "draft": "Awaiting submission"}


class DraftInput(StrictInput):
    message: str = Field(min_length=1, max_length=4000)


def _state(request, selection):
    if selection != {"kind": "own_companion"}:
        raise HTTPException(404, "Choose Ask Copilot in Your companion first.")
    return native.conversation_review(request)


def _work(state):
    return [{"task": row["title"], "status": _TASK_STATES.get(row["status"], "Needs review"),
             "open_task": {"href": row["href"], "label": "Open task"}} for row in state["tasks"]]


def work_snapshot(request, selection):
    state = _state(request, selection)
    return Snapshot(state["revision"], "Your current private companion and own work",
        "Check your own current tasks without an AI charge. Your conversation text is not shared with this control.",
        blocked="Task checks are not allowed by your current companion policy." if not state["status_available"] else "")


def work_prepare(request, selection, _arguments):
    state = _state(request, selection)
    return Preview("Your current accessible work, including at most 50 tasks. Open a task for its latest details.",
        native={"current_work": _work(state), "reply": "Being prepared" if state["active_turn"] else "No reply in progress",
                "open_companion": {"href": _PAGE, "label": "Open your companion"}})


def _draft_state(request, selection):
    state = _state(request, selection)
    blocked = ""
    route, limits = None, None
    if not state["conversation_available"]:
        blocked = "AI conversation is not allowed by your current companion policy."
    elif state["policy"]["retention_days"] == 0:
        blocked = "Your policy does not save answers. Use Ask companion on this page to read a reply immediately, or ask your administrator to allow saved conversation before using Copilot drafts."
    elif state["active_turn"]:
        blocked = "A reply is already being prepared. Check its status in Your companion before starting another."
    else:
        try:
            route = vars(native.companion_model.prepare_route())
            limits = native.companion_model.draft_limits()
        except Exception:
            blocked = "Your configured AI or allowance is unavailable. Check Your companion or ask your administrator."
    return state, route, limits, blocked


def draft_snapshot(request, selection):
    state, route, limits, blocked = _draft_state(request, selection)
    return Snapshot(digest([state["revision"], route, limits, blocked]), "Your private companion conversation",
        "Review one draft request before sending it to your configured AI. No messages are sent and no tasks are changed.",
        fields=[{"name": "message", "label": "What would you like help with?", "kind": "textarea",
                 "required": True, "max_length": 4000}], blocked=blocked)


def draft_prepare(request, selection, arguments):
    state, route, limits, blocked = _draft_state(request, selection)
    if blocked:
        raise HTTPException(409, blocked)
    message = arguments["message"].strip()
    if not message:
        raise HTTPException(422, "Write what you would like help with before reviewing.")
    retention = state["policy"]["retention_days"]
    maximum = Decimal(str(limits["max_dollars"]))
    spend = format(maximum, ".2f") if maximum == maximum.quantize(Decimal("0.01")) else format(maximum, "f")
    return Preview(
        "Send this message, up to six eligible saved exchanges and your permitted task context to your configured AI. "
        "The answer is a draft to review. No external action is taken. Provider retention is separate. "
        "An interrupted request is checked by its saved receipt and is never automatically sent again. "
        + (f"The answer can be kept for {retention} days, subject to your access and the latest 50 exchanges."
           if retention else "Your policy does not save answers; leaving before reading the reply can make it unrecoverable."),
        [{"label": "Your message", "after": message},
         {"label": "Maximum AI spend", "after": "$" + spend},
         {"label": "Reply", "after": "A bounded draft, with no external actions"},
         {"label": "Task context", "after": f"Up to {len(state['tasks'])} of your permitted tasks"}],
        {"context": state["context"], "owner": state["owner"], "state": state["revision"],
         "policy_revision": state["policy"]["revision"], "history_generation": state["history_generation"],
         "route": route, "limits": limits,
         "request_id": f"{int(time.time() * 1000)}.{secrets.token_hex(16)}"})


def _body(arguments, prepared):
    return native.MessageIn(message=arguments["message"], mode="conversation",
        expected_revision=prepared["policy_revision"], expected_history_generation=prepared["history_generation"],
        request_id=prepared["request_id"])


def _result(request, selection, arguments, prepared):
    state = _state(request, selection)
    if state["context"] != prepared["context"] or state["owner"] != prepared["owner"]:
        raise HTTPException(409, "Your account or workspace changed. Reopen your companion to check its reply.")
    result = native.conversation_request(request, prepared["request_id"])
    binding = result["binding"]
    if binding is not None:
        actor, tenant, _context = native._authority(request)
        if binding != {"revision": prepared["policy_revision"], "history_generation": prepared["history_generation"],
                       "fingerprint": native._turn_fingerprint(actor, tenant, _body(arguments, prepared))}:
            raise HTTPException(409, "This saved request does not match the reviewed conversation. Open your companion.")
    return result


def _outcome(result, prepared, *, recovered=False):
    status = result["request"]["state"]
    details = {"open_reply": {"href": _PAGE + "?reply=" + prepared["request_id"], "label": "Open this reply"}}
    if status == "completed":
        if result["reply"] is not None:
            details["draft_to_review"] = result["reply"]["response"]
            return Outcome("replayed" if recovered else "confirmed",
                "This exact request completed. Its retained draft is shown; review it before using it. No task or external action was performed.", details)
        return Outcome("unconfirmed", "This exact request completed, but its answer is no longer retained or currently accessible. "
            "No further AI request was sent. Check your companion before deciding whether to start a separate paid reply.", details)
    if status == "pending":
        return Outcome("queued", "Your exact draft request is being prepared. Check its saved status; no additional AI request was sent.", details)
    return Outcome("unconfirmed", "This request stopped without a recoverable saved answer. The provider may already have processed it. "
        "No additional request was sent. Check your companion before starting a separate paid reply.", details)


def draft_recover(request, selection, arguments, prepared, _operation_id):
    result = _result(request, selection, arguments, prepared)
    if result["request"]["state"] == "not_started":
        return None
    return _outcome(result, prepared, recovered=True)


def draft_execute(request, selection, arguments, prepared, _operation_id):
    _result(request, selection, arguments, prepared)
    body = _body(arguments, prepared)
    admitted = native.admit_reviewed_draft(request, body, reviewed_context=prepared["context"],
        expected_state=prepared["state"], expected_route=prepared["route"], expected_limits=prepared["limits"])
    if "duplicate" in admitted:
        return _outcome(_result(request, selection, arguments, prepared), prepared, recovered=True)
    return Outcome("queued", "Your reviewed draft request was accepted. Open this reply to check its saved status. "
        "No task or external action was performed.",
        {"open_reply": {"href": _PAGE + "?reply=" + prepared["request_id"], "label": "Open this reply"}},
        background=BackgroundTask(native.continue_reviewed_draft, request, body, admitted, prepared["context"]))


def entries():
    return (
        Adapter("companion.work", "Check my companion's current work", "preferences", _PAGE, (_PAGE,),
            EmptyInput, work_snapshot, work_prepare, aliases=("what is running", "what needs attention")),
        Adapter("companion.draft", "Prepare a draft with my companion", "preferences", _PAGE, (_PAGE,),
            DraftInput, draft_snapshot, draft_prepare, draft_execute, draft_recover,
            aliases=("ask my companion", "write a draft with my companion")),
    )
