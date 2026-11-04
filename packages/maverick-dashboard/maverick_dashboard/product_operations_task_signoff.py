"""Ordinary task-result review forms using the native finished-result contract."""
from __future__ import annotations

from functools import partial

from fastapi import HTTPException
from pydantic import Field

from . import task_signoff_operations as native
from .api_schemas import SignoffIn
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class ReviewInput(StrictInput):
    acknowledged: bool = False
    note: str = Field(default="", max_length=2000)


def snapshot(request, selection, *, decision=None):
    revision, details, _review, gate, status = native.snapshot(request, native.selected(selection), write=decision is not None)
    blocked = ""
    if decision is not None:
        if gate is None:
            blocked = "This result has no sign-off requirement. You can give ordinary feedback in the conversation."
        elif status != "done":
            blocked = "Wait for this task to finish before deciding on its result."
        elif details["Current decision"] == decision:
            blocked = "This result was already " + decision + " by " + details["Reviewer"] + ". Read the recorded review; another identical decision would not add your own review."
    fields = [{"name": "acknowledged", "label": "I have reviewed the complete saved result", "kind": "boolean", "required": True},
              {"name": "note", "label": "Review note (optional)", "kind": "textarea", "max_length": 2000}] if decision is not None else []
    return Snapshot(revision, "Current saved result and its recorded human review", details["Task"], details, fields, blocked)


def read_prepare(request, selection, _arguments):
    state = snapshot(request, selection)
    return Preview("Read the current saved result review. A review decision does not prove external delivery or training.",
                   [{"label": "Result review", "after": state.details}])


def prepare(request, selection, arguments, *, decision):
    if arguments["acknowledged"] is not True:
        raise HTTPException(422, "Review the complete saved result and acknowledge it before deciding.")
    state = snapshot(request, selection, decision=decision)
    if state.blocked:
        raise HTTPException(409, state.blocked)
    _revision, _details, review, _gate, _status = native.snapshot(request, native.selected(selection), write=True)
    changes = [{"label": "Result review", "after": state.details},
               {"label": "Your decision", "after": "Approve" if decision == "approved" else "Reject"},
               {"label": "Your review note", "after": arguments["note"] or "No note"}]
    return Preview("Record your decision on this exact finished result. Approval opens its governed handoff; learning and any configured handoff are separate best-effort work.", changes, review)


def outcome(receipt, *, replayed=False):
    pending = receipt["changed"] and receipt["follow_through"] in {"not_started", "started"}
    message = receipt["message"]
    if pending:
        message += " Learning or a configured handoff may not have completed. Readback does not run them again."
    return Outcome("unconfirmed" if pending else "replayed" if replayed else "confirmed", message,
                   {"Recorded decision": receipt["decision"].capitalize(), "Reviewer": receipt["reviewer"],
                    "Recorded": receipt["recorded_at"], "Review note": receipt["review_note"] or "No note",
                    "Result": "The reviewed result is still current" if receipt["current_result"] else "Historical result review",
                    "Follow-through": "Not repeated" if receipt["follow_through"] == "not_repeated" else "Attempted; delivery and training are not proven" if receipt["follow_through"] == "attempted" else "Needs outcome review; never automatically repeated"})


def execute(request, selection, arguments, review, operation_id, *, decision):
    result = native.decide(request, native.selected(selection), SignoffIn(
        decision=decision, expected_updated_at=review["expected_updated_at"],
        note=arguments["note"] or None, operation_id=operation_id, expected_context=review["context"]),
        expected_owner=review["owner"])
    return outcome(result["receipt"], replayed=result["replayed"])


def recover(request, selection, _arguments, review, operation_id):
    receipt = native.recover(request, native.selected(selection), operation_id, review)
    return outcome(receipt, replayed=True) if receipt is not None else None


def entries():
    pages = ("/chat/goal/*", "/goals/*")
    return (Adapter("reviews.result_read", "Read this result's recorded review", "reviews", "/chat", pages,
                    EmptyInput, snapshot, read_prepare, aliases=("read this result review", "check this result signoff")),
            Adapter("reviews.result_approve", "Approve this finished result", "reviews", "/chat", pages,
                    ReviewInput, partial(snapshot, decision="approved"), partial(prepare, decision="approved"),
                    partial(execute, decision="approved"), recover, aliases=("approve this result",), read_recovery=recover),
            Adapter("reviews.result_reject", "Reject this finished result", "reviews", "/chat", pages,
                    ReviewInput, partial(snapshot, decision="rejected"), partial(prepare, decision="rejected"),
                    partial(execute, decision="rejected"), recover, aliases=("reject this result",), read_recovery=recover))
