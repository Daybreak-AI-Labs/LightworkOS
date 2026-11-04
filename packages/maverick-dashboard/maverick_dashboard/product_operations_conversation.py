"""Typed reviewed conversation operations over the same durable native inbox."""
from __future__ import annotations

from dataclasses import replace
from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import conversation_inbox_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class Send(StrictInput):
    mode: Literal["guidance", "queue", "independent"]
    text: str = Field(min_length=1, max_length=12000)
    independent_context: Literal["none", "conversation_snapshot"] = "none"


class Change(StrictInput):
    item: str = Field(pattern=r"^turn-[a-f0-9]{32}$")
    action: Literal["cancel", "approve_guidance", "retry_dispatch"]
    decision: Literal["append", "replace_pending"] = "append"


class Edit(StrictInput):
    item: str = Field(pattern=r"^turn-[a-f0-9]{32}$")
    text: str = Field(min_length=1, max_length=12000)


def _goal(selection):
    goal = selection.get("id", selection.get("goal_id"))
    if selection.get("kind") != "goal" or type(goal) is not int or goal < 1:
        raise HTTPException(404, "Open your conversation to review its pending messages")
    return goal


def snapshot(request, selection):
    value = native._translate(lambda: native.state(request, _goal(selection)))
    return Snapshot(digest([value["revision"], value["guidance_review_version"], value["policy"], value["context"]]),
                    "Current owned conversation inbox and administrator policy", "Review durable messages separately from task execution.", value)


def status_preview(request, selection, args):
    return Preview("Read pending-message, guidance checkpoint and task admission receipts.", native=snapshot(request, selection).details)


def send_snapshot(request, selection):
    current = snapshot(request, selection)
    return replace(current, fields=[
        {"name": "mode", "label": "Execution boundary", "kind": "select", "required": True,
         "choices": [{"value": mode, "label": {"guidance": "Review guidance for this task", "queue": "Queue the next message", "independent": "Start a separate task"}[mode]} for mode in current.details["policy"]["modes"]]},
        {"name": "text", "label": "Message", "kind": "textarea", "required": True, "max_length": 12000},
        {"name": "independent_context", "label": "Context for a separate task", "kind": "select", "value": "none",
         "choices": [{"value": "none", "label": "No previous task content"}, {"value": "conversation_snapshot", "label": "Explicit current task snapshot"}]}],
        blocked="This task was handed off and cannot admit further work" if current.details["execution_closed"] else
                "Conversation inbox is disabled by administrator policy" if not current.details["enabled"] else "")


def send_preview(request, selection, args):
    current = send_snapshot(request, selection)
    if args["mode"] not in current.details["policy"]["modes"] or current.blocked:
        raise HTTPException(409, current.blocked or "This execution boundary is disabled")
    summary = {"guidance": "Save guidance for a separate explicit decision. It will not create another task.",
               "queue": "Save the next message for admission after the current conversation becomes idle.",
               "independent": "Admit an independent task under current permissions, concurrency and spending limits."}[args["mode"]]
    return Preview(summary, [{"label": "Exact message", "after": args["text"]}, {"label": "Files", "after": "None. Use the conversation composer to attach files."},
                             {"label": "Selected context", "after": current.details["target"] if args["independent_context"] == "conversation_snapshot" else "No prior task content"}],
                   {"context": current.details["context"], "expected_generation": current.details["generation"],
                    "expected_snapshot": current.details["target"]["snapshot_version"] if args["independent_context"] == "conversation_snapshot" else ""})


def _outcome(value, replay=False):
    return Outcome("unconfirmed" if value.get("audit_pending") else "replayed" if replay else "confirmed",
                   "The message operation is saved. Review the inbox for checkpoint delivery or governed task execution.", value)


def send_execute(request, selection, args, prepared, operation_id):
    return _outcome(native._translate(lambda: native.submit_native(request, _goal(selection), operation_id=operation_id, **prepared, **args)))


def recover(request, selection, args, prepared, operation_id):
    value = native._translate(lambda: native.get_receipt(request, _goal(selection), operation_id))
    return _outcome(value, True) if value["received"] else None


def change_snapshot(request, selection):
    current = snapshot(request, selection)
    from maverick.conversation_inbox import EDITABLE
    choices = [{"value": item["id"], "label": item["text"][:100] + " (" + item["state"].replace("_", " ") + ")"}
               for item in current.details["items"] if item["state"] in EDITABLE]
    return replace(current, fields=[{"name": "item", "label": "Pending message", "kind": "select", "required": True, "choices": choices},
        {"name": "action", "label": "Action", "kind": "select", "choices": [{"value": value, "label": label} for value, label in
            (("cancel", "Cancel pending message"), ("approve_guidance", "Approve guidance after reviewing current instructions"), ("retry_dispatch", "Explicitly retry blocked admission"))]},
        {"name": "decision", "label": "Guidance decision", "kind": "select", "choices": [{"value": "append", "label": "Add to existing guidance"},
            {"value": "replace_pending", "label": "Replace other unconsumed guidance"}]}], blocked="There are no editable pending messages" if not choices else "")


def change_preview(request, selection, args):
    current = change_snapshot(request, selection)
    item = next((item for item in current.details["items"] if item["id"] == args["item"]), None)
    if item is None:
        raise HTTPException(409, "The selected pending message is unavailable")
    return Preview("Review the exact message and original task. Guidance cannot undo completed actions or widen policy; conflicts need an explicit decision.",
        [{"label": "Original task", "after": current.details["target"]}, {"label": "Selected message", "after": item},
         {"label": "Already delivered guidance", "after": [row["acknowledgement"] for row in current.details["items"] if row.get("acknowledgement")]},
         {"label": "Decision", "after": args}],
        {"context": current.details["context"], "expected_revision": item["revision"], "expected_review": current.details["guidance_review_version"]})


def change_execute(request, selection, args, prepared, operation_id):
    body = native.Change(**prepared, operation_id=operation_id, **{key: value for key, value in args.items() if key != "item"})
    return _outcome(native._translate(lambda: native.change_native(request, _goal(selection), args["item"], body)))


def edit_snapshot(request, selection):
    current = change_snapshot(request, selection)
    choices = [{"value": item["id"], "label": item["text"][:100]} for item in current.details["items"] if item.get("may_edit")]
    return replace(current, blocked="There are no editable messages before task admission" if not choices else "", fields=[{**current.fields[0], "choices": choices}, {"name": "text", "label": "Revised message", "kind": "textarea", "required": True, "max_length": 12000}])


def edit_preview(request, selection, args):
    current = edit_snapshot(request, selection)
    item = next((item for item in current.details["items"] if item["id"] == args["item"]), None)
    if not item:
        raise HTTPException(409, "Choose a current pending message")
    return Preview("Revise this pending message and retain its exact selected files. Guidance changes require a new decision.",
        [{"label": "Message", "before": item["text"], "after": args["text"]}, {"label": "Retained files", "after": item["files"]}],
        {"context": current.details["context"], "expected_revision": item["revision"], "expected_generation": current.details["generation"],
         "mode": item["mode"], "keep_files": [file["id"] for file in item["files"]], "independent_context": item["independent_context"],
         "expected_snapshot": item["snapshot_version"]})


def edit_execute(request, selection, args, prepared, operation_id):
    return _outcome(native._translate(lambda: native.submit_native(request, _goal(selection), item_id=args["item"], text=args["text"],
                                                        operation_id=operation_id, **prepared)))


def entries():
    shared = ("tasks", "/chat", ("/chat/goal/*",))
    return (
        Adapter("conversation.inbox", "Review queued messages and guidance receipts", *shared, EmptyInput, snapshot, status_preview),
        Adapter("conversation.send", "Save guidance, queue a message or start separately", *shared, Send, send_snapshot, send_preview, send_execute, recover),
        Adapter("conversation.decide", "Review, cancel or explicitly retry a pending message", *shared, Change, change_snapshot, change_preview, change_execute, recover),
        Adapter("conversation.edit", "Edit a pending message while retaining its selected files", *shared, Edit, edit_snapshot, edit_preview, edit_execute, recover),
    )
