"""Existing companion policy controls, without administrator content access."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import employee_companion_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

_PAGE = "/companion/admin"
_ACTIVITIES = {"policy_updated": "Policy changed", "reply": "Task question answered",
    "history_cleared": "Conversation history cleared", "history_expired": "Expired history removed",
    "turn_started": "AI reply started", "draft_reply": "AI draft prepared",
    "turn_failed": "AI reply failed", "turn_expired": "AI reply expired", "turn_cancelled": "AI reply cancelled"}


class PolicyOptions(StrictInput):
    enabled: bool
    own_tasks: bool
    task_status: bool
    draft_reply: bool
    retention_days: Literal["0", "1", "7", "30"]


def _owner(selection):
    if (set(selection) != {"kind", "id"} or selection.get("kind") != "companion_employee"
            or not isinstance(selection.get("id"), str) or not selection["id"].startswith("user:")):
        raise HTTPException(404, "Choose an employee in Companion policies first.")
    return selection["id"]


def _state(request, selection):
    return native.administration_employee(request, _owner(selection))


def _retention(days):
    return "Do not save" if days == 0 else f"{days} day{'s' if days != 1 else ''}"


def _policy_details(state):
    policy = state["policy"]
    return {"employee": state["employee"]["label"], "companion": "Enabled" if policy["enabled"] else "Disabled",
        "own_task_information": "Allowed" if "own_tasks" in policy["allowed_sources"] else "Not allowed",
        "task_status_questions": "Allowed" if "task_status" in policy["allowed_tools"] else "Not allowed",
        "conversation_and_drafts": "Allowed" if "draft_reply" in policy["allowed_tools"] else "Not allowed",
        "keep_conversation_history": _retention(policy["retention_days"]),
        "installation": "Preview enabled" if state["available"] else "Preview off; policies can be prepared",
        "open_employee_policy": {"href": _PAGE, "label": "Open Companion policies"}}


def _snapshot(request, selection, *, change=False):
    state = _state(request, selection)
    policy = state["policy"]
    fields = []
    if change:
        for name, label, value in (
            ("enabled", "Enable this employee's companion", policy["enabled"]),
            ("own_tasks", "Allow the employee's own tasks as a source", "own_tasks" in policy["allowed_sources"]),
            ("task_status", "Allow task-status questions", "task_status" in policy["allowed_tools"]),
            ("draft_reply", "Allow AI conversation and drafts", "draft_reply" in policy["allowed_tools"]),
        ):
            fields.append({"name": name, "label": label, "kind": "boolean", "value": value})
        fields.append({"name": "retention_days", "label": "Keep conversation history", "kind": "select", "required": True,
            "value": str(policy["retention_days"]), "choices": [{"value": str(days), "label": _retention(days)} for days in (0, 1, 7, 30)]})
    binding = [state["context"], state["employee"], state["available"], policy]
    if not change:
        binding.append(state["events"])
    return Snapshot(digest(binding), "Current selected employee's companion policy",
        "Policy and activity metadata only. Employee prompts, answers and task titles remain private.",
        _policy_details(state), fields)


def read_snapshot(request, selection):
    return _snapshot(request, selection)


def read_prepare(request, selection, _arguments):
    state = _state(request, selection)
    activities = [{"when": datetime.fromtimestamp(event["time"], timezone.utc).strftime("%d %b %Y at %H:%M UTC"),
                   "activity": _ACTIVITIES.get(event["action"], "Companion activity recorded"),
                   "by": event["actor_label"]}
                  for event in reversed(state["events"])]
    return Preview("Current policy and recorded activity for this employee. No conversation content was read or shared with Copilot.",
        native={**_policy_details(state), "recent_activity": activities,
                "activity_coverage": "Matching entries from the latest 200 workspace activity records; this is not a complete archive."})


def change_snapshot(request, selection):
    return _snapshot(request, selection, change=True)


def _body(owner, revision, args):
    return native.PolicyIn(owner=owner, expected_revision=revision, enabled=args["enabled"],
        allowed_sources=["own_tasks"] if args["own_tasks"] else [],
        allowed_tools=(["task_status"] if args["task_status"] else []) + (["draft_reply"] if args["draft_reply"] else []),
        retention_days=int(args["retention_days"]))


def change_prepare(request, selection, args):
    state = _state(request, selection)
    policy = state["policy"]
    proposed = _body(_owner(selection), policy["revision"], args).model_dump()
    after = _policy_details({**state, "policy": proposed})
    before = _policy_details(state)
    labels = {"companion": "Companion", "own_task_information": "Own task information",
        "task_status_questions": "Task-status questions", "conversation_and_drafts": "AI conversation and drafts",
        "keep_conversation_history": "Keep conversation history"}
    return Preview("Save this employee's reviewed policy. Disabling the companion or choosing Do not save removes its saved conversation from the active store. Shorter retention can remove older history. A pending reply is cancelled; earlier provider processing may still be billed. Provider retention, backups and activity records are managed separately. This grants no external actions, private-content access, voice or learned memory.",
        [{"label": "Employee", "after": state["employee"]["label"]}] +
        [{"label": label, "before": before[key], "after": after[key]} for key, label in labels.items()],
        {"owner": _owner(selection), "revision": policy["revision"], "context": state["context"]})


def _reviewed(selection, prepared):
    if (prepared.get("owner") != _owner(selection) or type(prepared.get("revision")) is not int
            or not isinstance(prepared.get("context"), str)):
        raise HTTPException(409, "The selected employee changed. Review their current policy again.")


def change_recover(request, selection, _args, prepared, _operation_id):
    _reviewed(selection, prepared)
    state = _state(request, selection)
    if state["context"] != prepared["context"]:
        raise HTTPException(409, "Your account or workspace changed. Review the current policy again.")
    if state["policy"]["revision"] != prepared["revision"]:
        return Outcome("unconfirmed", "The saved policy changed after this review. Current settings are shown; no policy change was repeated. This does not identify which request changed them. Review the saved policy before deciding what to do next.", _policy_details(state))
    return None


def change_execute(request, selection, args, prepared, _operation_id):
    _reviewed(selection, prepared)
    try:
        result = native.administration_update(request, _body(_owner(selection), prepared["revision"], args),
                                              reviewed_context=prepared["context"])
    except HTTPException as exc:
        if exc.status_code != 503:
            raise
        state = _state(request, selection)
        return Outcome("unconfirmed", "The save response could not be confirmed. Current settings are shown; no additional policy update was sent. Check the saved policy before deciding what to do next.", _policy_details(state))
    state = _state(request, selection)
    if state["policy"] != result["policy"]:
        return Outcome("unconfirmed", "The policy was saved, then changed again. Current settings are shown. Review them before continuing.", _policy_details(state))
    return Outcome("confirmed", "The reviewed employee policy was saved. Current settings are shown; no employee conversation content was shared with Copilot.", _policy_details(state))


def entries():
    return (
        Adapter("companion.admin.read", "Review this employee's companion policy and activity", "preferences", _PAGE, (_PAGE,),
            EmptyInput, read_snapshot, read_prepare, aliases=("check employee companion policy", "show employee companion activity")),
        Adapter("companion.admin.policy", "Change this employee's companion policy", "preferences", _PAGE, (_PAGE,),
            PolicyOptions, change_snapshot, change_prepare, change_execute, change_recover,
            aliases=("enroll this employee's companion", "restrict this employee's companion")),
    )
