"""Typed Copilot decisions share the native complete example review and receipt."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import learning_example_decisions as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class ReasonIn(StrictInput):
    reason: str = Field(min_length=1, max_length=2000)


class GrantIn(ReasonIn):
    use_until: str = Field(min_length=1, max_length=64)
    retain_copies: bool


class OriginalIn(StrictInput):
    request: str = Field(pattern=r"^[a-f0-9]{32}$")


def selected(selection):
    if (not isinstance(selection, dict) or selection.get("kind") != "flow_run"
            or any(not isinstance(selection.get(key), str) or not 1 <= len(selection[key]) <= 256 for key in ("flow_id", "id"))):
        raise HTTPException(409, "Open a saved workflow run before reviewing its learning example.")
    return selection["flow_id"], selection["id"]


def snapshot(request, selection, *, kind):
    flow, run = selected(selection)
    scope, row = native.current(request, flow, run)
    ready = row["status"] == ("accepted" if kind == "grant" else "awaiting_review") and not row.get("grant_sha256")
    fields = [{"name": "reason", "label": "Why this example may be used" if kind == "grant" else "Why this example is or is not right", "kind": "textarea", "required": True, "max_length": 2000}]
    if kind == "grant":
        fields.extend([{"name": "use_until", "label": "Allow learning until", "kind": "datetime-local", "required": True},
                       {"name": "retain_copies", "label": "Keep derived copies until that date", "kind": "boolean", "required": True}])
    return Snapshot(digest([scope, native._source(row)]), "The current retained example and separate learning permission", native.NOTICE,
                    details={"State": row["status"].replace("_", " ")}, fields=fields,
                    blocked="This example cannot receive this decision. Check current status on its run page." if not ready else "")


def prepare(request, selection, arguments, *, kind):
    deadline = None
    if kind == "grant":
        from datetime import datetime
        try:
            date = datetime.fromisoformat(arguments["use_until"].replace("Z", "+00:00"))
            if date.tzinfo is None:
                raise ValueError
            deadline = date.timestamp()
        except ValueError as exc:
            raise HTTPException(422, "Choose a valid date for the learning permission.") from exc
    prepared, changes = native.prepare(request, *selected(selection), kind, arguments["reason"],
        use_until=deadline, retain_copies=arguments.get("retain_copies", False))
    return Preview("Review every retained value and your decision before confirming. No workflow runs or AI calls are started.", changes, prepared)


def outcome(row, flow, run):
    from urllib.parse import quote
    return Outcome("confirmed" if row["confirmed"] else "unconfirmed", row["message"],
                   {"Current example": row["current_status"].replace("_", " "), "Scope": row["notice"],
                    "Original decision": {"href": "/flows/" + quote(flow, safe="") + "/runs/" + quote(run, safe="") + "?example_decision=" + row["operation"] + "#lx-card", "label": "Read original decision"}})


def execute(request, selection, arguments, prepared, operation):
    flow, run = selected(selection)
    if (prepared["flow"], prepared["run"], prepared["reason"]) != (flow, run, arguments["reason"].strip()):
        raise HTTPException(409, "The selected example or reason changed after review.")
    return outcome(native.apply(request, prepared, operation), flow, run)


def recover(request, selection, _arguments, prepared, operation, *, read_only=False):
    flow, run = selected(selection)
    row = native.original(request, flow, run, operation, prepared=prepared)
    if row["kind"] is None and not read_only:
        return None
    return outcome(row, flow, run)


def original_snapshot(request, selection):
    flow, run = selected(selection)
    scope, service, ctx = native.authority(request, flow, receipt=True)
    value = native._call(lambda: service.original_decision(ctx, flow, run, operation="", context=scope))
    choices = [{"value": item["operation"], "label": "Learning permission" if item["action"] == "flow.episode.grant" else "Example acceptance" if item["accepted"] else "Example rejection"}
               for item in value["decisions"]]
    native.authority(request, flow, scope, receipt=True)
    return Snapshot(digest([scope, choices]), "Your original example decisions", "Read the original decision without making it again.",
                    fields=[{"name": "request", "label": "Original decision", "kind": "select", "choices": choices, "required": True}],
                    blocked="No original decision is recorded for this account and workspace." if not choices else "")


def entries():
    common = {"family": "learning", "pages": ("/flows/*/runs/*",), "direct_ui": "/flows"}
    result = []
    for kind, label in (("accept", "Accept this learning example"), ("reject", "Do not use this learning example"), ("grant", "Allow learning from this example")):
        result.append(Adapter("learning.example_" + kind, label, input_model=GrantIn if kind == "grant" else ReasonIn,
            snapshot=lambda r, s, k=kind: snapshot(r, s, kind=k), prepare=lambda r, s, a, k=kind: prepare(r, s, a, kind=k),
            execute=execute, recover=recover, read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common))
    result.append(Adapter("learning.example_original", "Read an original learning example decision", input_model=OriginalIn,
        snapshot=original_snapshot, prepare=lambda r, s, a: Preview("Original result; no decision is repeated.", native=outcome(native.original(r, *selected(s), a["request"]), *selected(s)).details), **common))
    return tuple(result)
