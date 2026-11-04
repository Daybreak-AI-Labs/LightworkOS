"""Owner-bound instruction recording through the same native controls as the page."""
from __future__ import annotations

from functools import partial

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import instruction_capture_api as native
from .draft_api import context_for
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput

_PAGE = "/learning/instructions"


class TaskInput(StrictInput):
    task: int = Field(ge=1, le=2**63 - 1)


class RecordInput(StrictInput):
    record: str = Field(pattern=r"^ISC-[a-f0-9]{32}$")


class SetupInput(StrictInput):
    enabled: bool


def snapshot(request, selection, *, action):
    if selection:
        raise HTTPException(422, "Choose a task or instruction record in this review.")
    value = native._call(lambda: native.choices(request))
    records = value["records"]
    fields, blocked = [], ""
    if action == "start":
        fields = [{"name": "task", "label": "Your task", "kind": "select", "required": True, "choices": value["tasks"]}]
        blocked = "Turn on instruction recording first." if not value["enabled"] else "No available owned task is waiting for work." if not value["tasks"] else ""
    elif action in {"withdraw", "finish", "review"}:
        offered = [row for row in records if action == "review" or action == "withdraw" and row["can_withdraw"]
                   or action == "finish" and row["can_finish"]]
        fields = [{"name": "record", "label": "Saved instruction record", "kind": "select", "required": True,
                   "choices": [{"value": row["id"], "label": row["title"] + " · " + row["when"] + " · " + row["status"]} for row in offered]}]
        if not offered:
            blocked = "No instruction record currently offers this action."
    elif action == "setup":
        auth.require_global_permission(request, "admin")
        fields = [{"name": "enabled", "label": "Allow instruction recording", "kind": "boolean", "value": value["enabled"]}]
    details = {"recording": "On" if value["enabled"] else "Off", "records": [
        {"task": row["title"], "when": row["when"], "status": row["status"], "model": row["model"], "explanation": row["explanation"]}
        for row in records[:20]], "open": {"label": "Open instruction records", "href": _PAGE}}
    return Snapshot(digest([value["context"], value["enabled"], value["tasks"], records]),
                    "Your current instruction recording permission, owned tasks and saved records",
                    "Record one real call with separate task consent. This does not start work, spend extra model money or establish improvement.",
                    details, fields, blocked)


def prepare(request, selection, arguments, *, action):
    snapshot(request, selection, action=action)
    value = native.choices(request)
    if action == "start":
        task = next((row for row in value["tasks"] if row["value"] == arguments["task"]), None)
        if not value["enabled"] or task is None:
            raise HTTPException(409, "This task no longer offers instruction recording. Refresh and choose again.")
        return Preview("Authorize only this task's next successful AI call started after your consent, within 24 hours. A call already in progress cannot be recorded. Instructions, including your preferences and guidance learned from permitted earlier work, may be kept locally. The conversation, answers and action results are not recorded separately. No work or learning starts.",
                       [{"label": "Your task", "after": task["label"]}], {"task": task["value"]})
    if action == "setup":
        return Preview("Allow local private instruction recording, with separate consent for every task. No work or learning starts." if arguments["enabled"] else
                       "Stop retaining instructions from new calls. Existing records remain reviewable and can be withdrawn.",
                       [{"label": "Instruction recording", "before": "On" if value["enabled"] else "Off", "after": "On" if arguments["enabled"] else "Off"}],
                       {"previous": value["enabled"]})
    row = next((item for item in value["records"] if item["id"] == arguments["record"]), None)
    if row is None or action == "withdraw" and not row["can_withdraw"] or action == "finish" and not row["can_finish"]:
        raise HTTPException(409, "This instruction record changed. Refresh and review it again.")
    if action == "review":
        # Private text is read in the native page under current source authority.
        # It never enters the Copilot operation catalog or model proposal prompt.
        return Preview("Open this selected record to review and download its exact instructions under your current source permission. This earlier record does not prove that the instructions are still in use or that results improved.",
                       native={"task": row["title"], "when": row["when"], "status": row["status"], "model": row["model"],
                               "open": {"label": "Review this instruction record", "href": _PAGE + "?record=" + row["id"]}})
    summary = "Withdraw this capture and make its instruction text unavailable here. The decision record remains; previously downloaded files are not recalled." if action == "withdraw" else (
        "Resolve the completed call as withheld. No instruction text is available, no call is repeated, and no later call is captured." if row["result_pending"] else
        "Finish this original capture request. It will wait for one successful call started afterwards, within its original 24-hour limit. No work starts.")
    return Preview(summary,
                   [{"label": "Your task", "after": row["title"]}, {"label": "Current record", "after": row["status"]}],
                   {"record": row["id"], "revision": row["revision"]})


def execute(request, _selection, arguments, prepared, operation, *, action):
    context = context_for(request)
    if action == "start":
        if prepared != {"task": arguments["task"]}:
            raise HTTPException(409, "The selected task changed. Review it again.")
        result = native.authorize(request, native.Capture(context=context, confirm=True, task=arguments["task"], operation=operation))
    elif action == "setup":
        result = native.setup(request, native.Setup(context=context, confirm=True, previous=prepared["previous"], enabled=arguments["enabled"]))
    else:
        if prepared["record"] != arguments["record"]:
            raise HTTPException(409, "The selected instruction record changed. Review it again.")
        body = native.Withdraw(context=context, confirm=True, revision=prepared["revision"])
        result = (native.withdraw if action == "withdraw" else native.finish)(request, prepared["record"], body)
    return Outcome("confirmed", result["detail"], {"open": {"label": "Open current instruction records", "href": _PAGE}})


def recover(request, _selection, arguments, _prepared, operation, *, action):
    _tenant, actor, _context, world = native._bound(request)
    if action == "setup":
        auth.require_global_permission(request, "admin")
        if native.source.enabled() != arguments["enabled"]:
            return None
        return Outcome("unconfirmed", "The current recording setting matches this review. The original change is not confirmed. No setting change was repeated.")
    identity = "ISC-" + operation if action == "start" else arguments["record"]
    row = native.source.records().get(identity)
    if not row or row.get("owner") != actor or action == "start" and row.get("goal_id") != arguments["task"]:
        return None
    if action == "withdraw" and row["state"] != "withdrawn" or action == "finish" and (row["state"] == "prepared" or native.source.result_pending(row)):
        return None
    try:
        native.source.visible(world, identity, actor)
    except ValueError:
        return None
    if action in {"withdraw", "finish"}:
        return Outcome("unconfirmed", native._plain(row)["status"] +
            ". This is current status; it does not identify which request changed the record. No action was repeated.",
            {"open": {"label": "Review current instruction record", "href": _PAGE + "?record=" + identity}})
    description = "The original request is recorded but needs completion on the instruction records page." if row["state"] == "prepared" else native._plain(row)["status"]
    return Outcome("replayed", description + " No action was repeated.", {"open": {"label": "Review current instruction record", "href": _PAGE + "?record=" + identity}})


def entries():
    result = []
    for action, label, model, aliases in (
        ("start", "Record instructions from a task", TaskInput, ("record instructions", "capture real instructions")),
        ("review", "Review recorded instructions", RecordInput, ("show recorded instructions", "download instruction file")),
        ("withdraw", "Withdraw an instruction capture", RecordInput, ("withdraw instruction capture",)),
        ("finish", "Finish an instruction capture request", RecordInput, ("finish instruction recording request",)),
        ("setup", "Change instruction recording permission", SetupInput, ("turn instruction recording on", "turn instruction recording off")),
    ):
        result.append(Adapter("learning.instructions_" + action, label, "learning", _PAGE, (_PAGE, "/learned"), model,
            partial(snapshot, action=action), partial(prepare, action=action),
            None if action == "review" else partial(execute, action=action),
            None if action == "review" else partial(recover, action=action), aliases))
    return tuple(result)
