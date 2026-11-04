"""Typed structural release, local answers, protected authoring and custody."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import competence_transport as native
from . import local_flow_promotions as release
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class ShareIn(StrictInput):
    workflow: str = Field(min_length=1, max_length=128)
    evidence: list[str] = Field(min_length=2, max_length=8)


class FormIn(StrictInput):
    workflow: str = Field(min_length=1, max_length=128)


class OriginalIn(StrictInput):
    request: str = Field(pattern=r"^PCR-[a-f0-9]{32}$")


class RunIn(OriginalIn):
    first: bool | int | str | None = None
    second: bool | int | str | None = None
    third: bool | int | str | None = None


def share_snapshot(request, selection):
    value = release._native_call(lambda: native.listing(request))
    flow = selection.get("id") if selection.get("kind") == "flow" else ""
    selected = release._native_call(lambda: native.listing(request, flow)) if flow else value
    choices = [item for item in value["flows"] if item["value"] == flow]
    return Snapshot(digest(selected), "Current owned local rule source", native.NOTICE, fields=[
        {"name": "workflow", "label": "Selected published rule", "kind": "select", "required": True, "choices": choices, "value": flow},
        {"name": "evidence", "label": "Original cases with current reuse permission", "kind": "multiselect", "presentation": "checkboxes", "required": True, "max_selections": 8, "choices": [{"value": item["value"], "label": item["label"]} for item in selected["cases"]]}],
        blocked="Choose a named published local rule on the sharing page first." if not choices else "Retain two distinct current original cases first." if len(selected["cases"]) < 2 else "")


def _preview(request, choices, arguments):
    value, changes = release._native_call(lambda: native.prepare(request, choices))
    return Preview(native.NOTICE, changes=changes, native={"choices": choices, "binding": digest(value), "expires": value["expires"], "preparation_ms": value["preparation_ms"], "arguments": arguments})


def share_prepare(request, _selection, arguments):
    return _preview(request, {"kind": "share", "flow": arguments["workflow"], "evidence": arguments["evidence"]}, arguments)


def outcome(row, replay=False):
    details = {"Exact original outcome retained": row["confirmed"], "Current source permission": row["current"], "Full retained local result": {"label": "Read the original result and supported input bounds", "href": native.PAGE + "?original=" + row["id"]}}
    if row.get("kind") == "share" and row["confirmed"] and row["current"]:
        details["Shared structural file"] = {"label": "Download the confirmed anonymous rule structure", "href": native.API + "/download/" + row["id"]}
    result = row.get("result", {})
    if row.get("kind") == "run" and result:
        details["Local rule answer"] = result.get("answer")
        details["Native local execution finished"] = result.get("complete")
    return Outcome("replayed" if replay and row["confirmed"] else "confirmed" if row["confirmed"] else "unconfirmed", row["message"], details)


def checked(arguments, prepared):
    if arguments != prepared["arguments"]:
        raise HTTPException(409, "The local rule choices changed after their complete review.")


def execute(request, _selection, arguments, prepared, operation):
    checked(arguments, prepared)
    prior = native.owned(request, "PCR-" + operation)
    if prior:
        if prior["binding"] != prepared["binding"]:
            raise HTTPException(409, "The original request belongs to another complete review.")
        return outcome(release._native_call(lambda: native.original(request, prior["id"])), replay=True)
    value = release._native_call(lambda: native.material(request, prepared["choices"]))
    value.update(expires=prepared["expires"], preparation_ms=prepared["preparation_ms"])
    if digest(value) != prepared["binding"]:
        raise HTTPException(409, "The reviewed rules, case permission or local values changed. Review current choices.")
    return outcome(release._native_call(lambda: native.apply(request, value, operation)))


def recover(request, _selection, arguments, prepared, operation, *, read_only=False):
    checked(arguments, prepared)
    identifier = "PCR-" + operation
    row = native.owned(request, identifier)
    if row and row["binding"] != prepared["binding"]:
        raise HTTPException(409, "The original request belongs to another complete review.")
    if row is None and not read_only:
        return None
    return outcome(release._native_call(lambda: native.original(request, identifier)), replay=True)


def original_snapshot(request, _selection):
    value = native.history(request)
    return Snapshot(digest(value), "Your original structural learning requests", "Read exact original custody without repeating any calculation.", fields=[
        {"name": "request", "label": "Original structural learning request", "kind": "select", "required": True, "choices": [{"value": item["value"], "label": item["label"]} for item in value["choices"]]}], blocked="No original structural learning request is retained for this account and workspace." if not value["choices"] else "")


def original_prepare(request, _selection, arguments):
    value = release._native_call(lambda: native.original(request, arguments["request"]))
    return Preview(value["message"], native=outcome(value, replay=True).details)


def form_snapshot(request, selection):
    value = release._native_call(lambda: native.listing(request))
    selected = selection.get("id") if selection.get("kind") == "flow" else ""
    return Snapshot(digest(value), "Qualify a shared rule in your own setting", "Open the protected ordinary file chooser, local case picker and expected-answer controls. No source accuracy is inherited.", fields=[
        {"name": "workflow", "label": "Your published target rule", "kind": "select", "required": True, "choices": value["target_flows"], "value": selected}], blocked="Sharing and qualifying local rules is off. An administrator can enable Share and qualify local rule structures in Settings." if not value["enabled"] else "Publish a supported owned local rule with bounded yes/no or whole-number inputs first." if not value["target_flows"] else "")


def form_prepare(request, _selection, arguments):
    value = release._native_call(lambda: native.listing(request, arguments["workflow"]))
    if not any(item["value"] == arguments["workflow"] for item in value["target_flows"]):
        raise HTTPException(409, "Choose a currently supported published target rule with bounded yes/no or whole-number inputs.")
    return Preview("Choose a structural file and enter expected answers for your permitted local cases in the protected form. Current entered work is kept until you explicitly replace it.", native={"portable_rule_form": {"context": value["context"], "flow": arguments["workflow"], "view": "qualify"}})


def run_snapshot(request, selection):
    identifier = selection.get("id") if selection.get("kind") == "portable_rule" else ""
    value = release._native_call(lambda: native.original(request, identifier)) if identifier else {}
    ready = value.get("confirmed") and value.get("current") and value.get("kind") == "qualify" and value.get("result", {}).get("qualified")
    fields = [{"name": "request", "label": "Selected qualified local rule", "kind": "select", "required": True, "choices": [{"value": identifier, "label": "Current confirmed local qualification"}] if ready else [], "value": identifier}]
    if ready:
        for field, (name, declaration) in zip(("first", "second", "third"), value["inputs"].items(), strict=False):
            item = {"name": field, "label": name.replace("_", " "), "required": True}
            if declaration["type"] == "boolean":
                item.update(kind="select", choices=[{"value": True, "label": "Yes"}, {"value": False, "label": "No"}])
            else:
                item.update(kind="number", min=declaration["min"], max=declaration["max"], step=1)
            fields.append(item)
    return Snapshot(digest(value), "Run your unpublished qualified local rule", "Use only the displayed finite input bounds. This calls the existing local rule executor, with no AI, outside action or publication.", fields=fields, blocked="Read and select your confirmed current local qualification on the sharing page first." if not ready else "")


def run_prepare(request, _selection, arguments):
    value = release._native_call(lambda: native.original(request, arguments["request"]))
    if not value.get("inputs"):
        raise HTTPException(409, "Choose a current confirmed local qualification first.")
    inputs = {name: arguments.get(field) for field, name in zip(("first", "second", "third"), value["inputs"], strict=False)}
    return _preview(request, {"kind": "run", "original": arguments["request"], "inputs": inputs}, arguments)


def entries():
    common = {"family": "learning", "pages": (native.PAGE, "/learning", "/learning/recheck-rules"), "direct_ui": native.PAGE}
    return (Adapter("learning.share_rule_structure", "Review and share an anonymous rule structure", input_model=ShareIn, snapshot=share_snapshot, prepare=share_prepare, execute=execute, recover=recover, read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
            Adapter("learning.qualify_rule_form", "Open local qualification with ordinary answers", input_model=FormIn, snapshot=form_snapshot, prepare=form_prepare, **common),
            Adapter("learning.run_qualified_local_rule", "Run a qualified local rule", input_model=RunIn, snapshot=run_snapshot, prepare=run_prepare, execute=execute, recover=recover, read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
            Adapter("learning.portable_rule_original", "Read an original structural learning result", input_model=OriginalIn, snapshot=original_snapshot, prepare=original_prepare, **common))
