"""Protected full authoring, guarded combined runs and pure original reads."""
from __future__ import annotations

from fastapi import HTTPException
from pydantic import Field

from . import local_flow_promotions as release
from . import procedure_interactions as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class FormIn(StrictInput):
    first: str = Field(min_length=1, max_length=128)
    second: str = Field(min_length=1, max_length=128)


class OriginalIn(StrictInput):
    request: str = Field(pattern=r"^PJI-[a-f0-9]{32}$")


class RunIn(OriginalIn):
    first: bool | int | None = None
    second: bool | int | None = None
    third: bool | int | None = None


def form_snapshot(request, _selection):
    value = release._native_call(lambda: native.listing(request))
    return Snapshot(native.engine.digest(value), "Your published local rules", native.NOTICE, fields=[
        {"name": name, "label": label, "kind": "select", "required": True, "choices": value["flows"]}
        for name, label in (("first", "First published local rule"), ("second", "Second published local rule"))],
        blocked="Checking local rules together is off. An administrator can enable Check local rules together in Settings." if not value["enabled"] else "Publish two supported owned local rules first." if len(value["flows"]) < 2 else "")


def form_prepare(request, _selection, arguments):
    native.available(request)
    if arguments["first"] == arguments["second"]:
        raise HTTPException(422, "Choose two different published local rules.")
    value = release._native_call(lambda: native.listing(request, arguments["first"], arguments["second"]))
    flows = [native._flow(request, arguments[name])[1] for name in ("first", "second")]
    native.domain(flows)
    return Preview("Open the full original-case controls. Entered selections are preserved until you explicitly replace them.",
        native={"procedure_interaction_form": {"context": value["context"], "first": arguments["first"], "second": arguments["second"]}})


def outcome(value, replay=False):
    details = {"Exact original complete result retained": value["confirmed"], "Current source permission": value["current"],
        "Full original local comparison": {"label": "Read every checked starting state and separate result", "href": native.PAGE + "?original=" + value["id"]}}
    if value.get("kind") == "run" and value.get("result"):
        details["Combined local execution finished"] = value["result"]["complete"]
        for index, rule in enumerate(value.get("rules", [])):
            values = value["result"]["results"].get(str(index), {})
            details[rule + " / complete local result"] = native.source._display({name: item["value"] if item["present"] else "Not produced" for name, item in values.items()})
    return Outcome("replayed" if replay and value["confirmed"] else "confirmed" if value["confirmed"] else "unconfirmed", value["message"], details)


def run_snapshot(request, selection):
    identifier = selection.get("id") if selection.get("kind") == "joint_rule" else ""
    value = release._native_call(lambda: native.original(request, identifier)) if identifier else {}
    ready = value.get("confirmed") and value.get("current") and value.get("kind") == "qualify" and value.get("result", {}).get("qualified")
    fields = [{"name": "request", "label": "Selected combined rule check", "kind": "select", "required": True,
               "choices": [{"value": identifier, "label": "Current confirmed local combination"}] if ready else [], "value": identifier}]
    if ready:
        for name, (label, declaration) in zip(("first", "second", "third"), value["result"]["inputs"].items(), strict=False):
            item = {"name": name, "label": label.replace("_", " "), "required": True}
            if declaration["type"] == "boolean":
                item.update(kind="select", choices=[{"value": True, "label": "Yes"}, {"value": False, "label": "No"}])
            else:
                item.update(kind="number", min=declaration["min"], max=declaration["max"], step=1)
            fields.append(item)
    return Snapshot(native.engine.digest(value), "Your checked local combination", "Both rules run with fresh source checks and a separate complete reference. Some starting values can remain unresolved.",
        fields=fields, blocked="Select your confirmed current combined rule check on the native page first." if not ready else "")


def run_prepare(request, _selection, arguments):
    original = release._native_call(lambda: native.original(request, arguments["request"]))
    if not original.get("result", {}).get("qualified") or not original["current"]:
        raise HTTPException(409, "Choose your current confirmed combined rule check first.")
    choices = {"kind": "run", "original": arguments["request"], "inputs": {key: arguments.get(field) for field, key in zip(("first", "second", "third"), original["result"]["inputs"], strict=False)}}
    value, changes = release._native_call(lambda: native.prepare(request, choices))
    return Preview(native.NOTICE, changes=changes, native={"arguments": arguments, "choices": choices, "expires": value["expires"], "binding": native.engine.digest(value)})


def checked(arguments, prepared):
    if arguments != prepared["arguments"]:
        raise HTTPException(409, "The combined starting values changed after review.")


def execute(request, _selection, arguments, prepared, operation):
    checked(arguments, prepared)
    prior = native.owned(request, "PJI-" + operation)
    if prior:
        if prior["binding"] != prepared["binding"]:
            raise HTTPException(409, "The original request belongs to another complete review.")
        return outcome(native.original(request, prior["id"]), replay=True)
    value = release._native_call(lambda: native.material(request, prepared["choices"]))
    value["expires"] = prepared["expires"]
    if native.engine.digest(value) != prepared["binding"]:
        raise HTTPException(409, "The source rules, starting values or existing case permissions changed.")
    return outcome(release._native_call(lambda: native.apply(request, value, operation)))


def recover(request, _selection, arguments, prepared, operation, *, read_only=False):
    checked(arguments, prepared)
    identifier = "PJI-" + operation
    prior = native.owned(request, identifier)
    if prior and prior["binding"] != prepared["binding"]:
        raise HTTPException(409, "The original request belongs to another complete review.")
    if prior is None and not read_only:
        return None
    return outcome(release._native_call(lambda: native.original(request, identifier)), replay=True)


def original_snapshot(request, _selection):
    value = native.history(request)
    return Snapshot(native.engine.digest(value), "Your original combined rule requests", "Read original custody without repeating any calculation.", fields=[
        {"name": "request", "label": "Original combined rule request", "kind": "select", "required": True, "choices": [{"value": row["value"], "label": row["label"]} for row in value["choices"]]}],
        blocked="No combined rule request is retained for this current account and workspace." if not value["choices"] else "")


def original_prepare(request, _selection, arguments):
    value = release._native_call(lambda: native.original(request, arguments["request"]))
    return Preview(value["message"], native=outcome(value, replay=True).details)


def entries():
    common = {"family": "learning", "pages": (native.PAGE, "/learning"), "direct_ui": native.PAGE}
    return (Adapter("learning.joint_rules_form", "Open complete joint rule controls", input_model=FormIn, snapshot=form_snapshot, prepare=form_prepare, **common),
            Adapter("learning.run_joint_rules", "Run checked local rules together", input_model=RunIn, snapshot=run_snapshot, prepare=run_prepare, execute=execute, recover=recover,
                read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
            Adapter("learning.joint_rules_original", "Read an original combined rule result", input_model=OriginalIn, snapshot=original_snapshot, prepare=original_prepare, **common))
