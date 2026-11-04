"""Native reviewed viewpoints and named original readback in Copilot."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import viewpoints_requests as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput
from .viewpoints_api import ViewpointsIn


class OriginalIn(StrictInput):
    request: str = Field(pattern=r"^[a-f0-9]{32}$")


def snapshot(request, _selection):
    row = native.listing(request)
    return Snapshot(row.get("revision") or digest([row["context"], "unavailable"]), "Current viewpoints AI connection and spending limits", native.NOTICE,
                    fields=[{"name": "question", "label": "Question or decision", "kind": "textarea", "required": True, "max_length": 2000},
                            {"name": "rounds", "label": "Arguments per side", "kind": "select", "value": 2,
                             "choices": [{"value": i, "label": str(i)} for i in (1, 2, 3)]},
                            {"name": "for_side", "label": "The side for argues that (optional)", "kind": "text", "max_length": 300},
                            {"name": "against_side", "label": "The side against argues that (optional)", "kind": "text", "max_length": 300}],
                    blocked="" if row["ready"] else row.get("message", "Connect AI in Settings before starting. Original history remains available."))


def prepare(request, _selection, arguments):
    prepared = native.prepare(request, arguments)
    return Preview(native.NOTICE, changes=native.review_rows(prepared), native=prepared)


def checked(arguments, prepared):
    if ViewpointsIn.model_validate(arguments).model_dump() != prepared["body"]:
        raise HTTPException(409, "Your question or positions changed after review. Review them again.")


def outcome(value):
    result = value.get("result")
    details = {"Original status": value["message"], "Open original viewpoints": {"href": "/chat?viewpoints_request=" + value["operation"] + "#viewpoints", "label": "Open saved viewpoints"}}
    if result and result.get("ran"):
        details["Question"] = value["question"]
        details["Judge's view"] = {"Conclusion": {"for": "The case for is stronger", "against": "The case against is stronger", "draw": "Neither side is stronger"}[result["verdict"]],
                                  "Reason": result["reason"], "Deciding point": result["key_point"], "Cost": f"${result['cost']:.4f}"}
        details["Arguments"] = [{"Side": "For" if turn["side"] == "for" else "Against", "Answer": turn["text"]} for turn in result["turns"]]
    elif result:
        details["Original result"] = result["message"]
    state = "confirmed" if value["confirmed"] else "queued" if value["worker"] == "running" else "unconfirmed"
    return Outcome(state, value["message"], details=details)


def execute(request, _selection, arguments, prepared, operation):
    checked(arguments, prepared)
    return outcome(native.start(request, prepared, operation))


def recover(request, _selection, arguments, prepared, operation, *, read_only=False):
    checked(arguments, prepared)
    row = native.owned(request, operation)
    if row is None and not read_only:
        return None
    if row is not None and row["binding"] != digest([row["owner"], row["tenant"], prepared["state"]["context"], operation, prepared]):
        raise HTTPException(409, "This request belongs to a different viewpoints review. Read its original result.")
    return outcome(native.original(request, operation))


def original_snapshot(request, selection):
    state = native.history(request)
    choices = [{"value": row["value"], "label": row["label"]} for row in state["requests"]]
    selected = selection.get("operation") if selection.get("kind") == "viewpoints" else ""
    return Snapshot(digest(state), "Your retained original viewpoints requests", "Read saved original answers or current work without another AI request.",
                    fields=[{"name": "request", "label": "Original question", "kind": "select", "required": True,
                             "value": selected if any(c["value"] == selected for c in choices) else "", "choices": choices}],
                    blocked="" if choices else "No original viewpoints requests are retained for this account and workspace.")


def original_prepare(request, _selection, arguments):
    result = native.original(request, arguments["request"])
    return Preview(result["message"], native=outcome(result).details)


def entries():
    common = {"family": "tasks", "pages": ("/chat",), "direct_ui": native.PAGE}
    return (Adapter("tasks.get_viewpoints", "Get two viewpoints on a decision", input_model=ViewpointsIn, snapshot=snapshot,
                    prepare=prepare, execute=execute, recover=recover,
                    read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
            Adapter("tasks.viewpoints_original", "Read original viewpoints", input_model=OriginalIn,
                    snapshot=original_snapshot, prepare=original_prepare, **common))
