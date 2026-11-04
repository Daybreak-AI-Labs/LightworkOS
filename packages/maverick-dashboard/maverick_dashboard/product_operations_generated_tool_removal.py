"""Typed Copilot uses the same generated-tool review and original custody."""
from __future__ import annotations

import json

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick.governed_operations import digest
from pydantic import Field

from . import generated_tool_removal as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class ToolInput(StrictInput):
    tool: str = Field(pattern=r"^[a-f0-9]{64}$")


class CleanupInput(ToolInput):
    acknowledge_unknown: bool


class OriginalInput(StrictInput):
    original: str = Field(pattern=r"^GTR-[a-f0-9]{48}\|[a-f0-9]{32}$")


def snapshot(request, _selection, action):
    state = native.listing(request)
    choices = [row for row in state["choices"] if row["pending"] == (action == "cleanup")]
    fields = [{"name": "tool", "label": "Owned tool", "kind": "select", "required": True,
               "choices": [{"value": row["value"], "label": row["label"] + " · " + row["state"]} for row in choices]}]
    if action == "cleanup":
        fields.append({"name": "acknowledge_unknown", "label": "The earlier original stays unknown; this is a separate intentional cleanup", "kind": "boolean", "required": True})
    return Snapshot(digest(state), "Current owned generated-tool files and permission", native.NOTICE, fields=fields,
                    blocked="No eligible owned tool is currently available for this change." if not choices else "")


def prepare(request, _selection, arguments, action):
    if action == "cleanup" and arguments["acknowledge_unknown"] is not True:
        raise HTTPException(422, "Acknowledge the earlier unknown result before reviewing a separate cleanup.")
    prepared = native.prepare(request, arguments["tool"], action, acknowledge_unknown=arguments.get("acknowledge_unknown", False))
    custody = crypto_at_rest.seal_to_str(json.dumps({"purpose": "generated-tool-removal-copilot", "prepared": prepared}, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(custody):
        raise HTTPException(503, "Private tool custody could not be protected. Nothing was admitted.")
    return Preview("Review the complete current tool state and stopping consequences.", changes=native.changes(prepared), native={"custody": custody})


def _prepared(value):
    if set(value) != {"custody"} or not crypto_at_rest.is_sealed_str(value["custody"]):
        raise HTTPException(409, "This complete private review is unavailable.")
    material = json.loads(crypto_at_rest.unseal_from_str(value["custody"]))
    if set(material) != {"purpose", "prepared"} or material["purpose"] != "generated-tool-removal-copilot":
        raise HTTPException(409, "This private review could not be verified.")
    return material["prepared"]


def outcome(value):
    return Outcome("confirmed" if value["confirmed"] else "unconfirmed", value["message"],
                   {"Original outcome": value["message"],
                    "Recorded stopping": "Stopped by this original" if value["stopped"] else "This original does not confirm stopping",
                    "Current observation": value.get("current", "Current files are unavailable."), "Effect and limits": native.NOTICE,
                    "Open original": {"href": "/learned?generated_tool_original=" + value["reference"] + "#generated-tools", "label": "Read this exact original"}})


def execute(request, _selection, arguments, prepared, operation):
    prepared = _prepared(prepared)
    if arguments["tool"] != prepared["key"]:
        raise HTTPException(409, "The selected tool changed. Review current files again.")
    return outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation, *, pure=False):
    native.authority(request)
    prepared = _prepared(prepared)
    row = native.STORE.get(prepared["id"])
    if row is None or operation not in native._open(row)["operations"]:
        if pure:
            return Outcome("unconfirmed", "This original has no confirmed native result. Nothing was repeated.")
        return None
    return outcome(native.original(request, prepared["id"] + "|" + operation, prepared=prepared))


def history_snapshot(request, _selection):
    state = native.history(request)
    return Snapshot(digest(state), "Your retained original tool decisions", "Read original outcomes without repeating any change.",
                    fields=[{"name": "original", "label": "Original decision", "kind": "select", "required": True, "choices": state["choices"]}],
                    blocked="No original tool decision is retained for this account and workspace." if not state["choices"] else "")


def entries():
    common = {"family": "learning", "pages": ("/learned",), "direct_ui": native.PAGE}
    return (
        Adapter("learning.generated_tool_remove", "Stop and remove an owned generated tool", input_model=ToolInput,
                snapshot=lambda r, s: snapshot(r, s, "remove"), prepare=lambda r, s, a: prepare(r, s, a, "remove"), execute=execute, recover=recover,
                read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, pure=True), **common),
        Adapter("learning.generated_tool_cleanup", "Review separate cleanup after an unknown tool removal", input_model=CleanupInput,
                snapshot=lambda r, s: snapshot(r, s, "cleanup"), prepare=lambda r, s, a: prepare(r, s, a, "cleanup"), execute=execute, recover=recover,
                read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, pure=True), **common),
        Adapter("learning.generated_tool_original", "Read an original generated-tool stopping decision", input_model=OriginalInput,
                snapshot=history_snapshot, prepare=lambda r, s, a: Preview("Read this original without another change.", native=outcome(native.original(r, a["original"])).details), **common),
        Adapter("learning.generated_tool_history", "Read my generated-tool stopping history", input_model=EmptyInput,
                snapshot=lambda r, s: Snapshot(digest(native.history(r)), "Your original stopping decisions", "No source body or withdrawn name is disclosed."),
                prepare=lambda r, s, a: Preview("Every retained original decision for this account and workspace.", native={"Original decisions": native.history(r)["choices"]}), **common),
    )
