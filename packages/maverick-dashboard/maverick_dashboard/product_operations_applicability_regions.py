"""Copilot shares exact answer-region admission, complete review and originals."""
from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from pydantic import Field

from . import applicability_regions as native
from . import local_flow_promotions as release
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class FormIn(StrictInput):
    flow: str = Field(min_length=1, max_length=128)


class QualifyIn(StrictInput):
    comparisons: list[str] = Field(min_length=1, max_length=20)
    seconds: Literal[30, 60, 120] = 30


class OriginalIn(StrictInput):
    request: str = Field(pattern=r"^APR-[a-f0-9]{32}$")


class LabelIn(OriginalIn):
    expected: str | int | bool | None = None
    empty_answer: bool = False
    seconds: Literal[30, 60, 120] = 30


class RunIn(OriginalIn):
    first: bool | int | None = None
    second: bool | int | None = None
    third: bool | int | None = None
    seconds: Literal[30, 60, 120] = 30


def time_field():
    return {"name": "seconds", "label": "Total time for this check", "kind": "select", "required": True, "value": 30,
            "choices": [{"value": 30, "label": "30 seconds"}, {"value": 60, "label": "1 minute"}, {"value": 120, "label": "2 minutes"}],
            "help": "Includes waiting, current permission checks and all local work. Larger ranges may need more time. Work never restarts when the limit is reached."}


def outcome(value, replay=False):
    details = {"Exact original complete result retained": value["confirmed"], "Current source permission": value["current"],
               "Complete answer-region result": {"label": "Open every checked situation and answer", "href": native.PAGE + "?original=" + value["id"]}}
    result = value.get("result", {})
    if "cells" in result:
        details["Starting situations checked"] = len(result["cells"])
        details["Situations still needing review"] = sum(cell["route"] == "review" for cell in result["cells"])
    if value.get("kind") == "run" and result:
        details["Routing decision"] = {"baseline": "Current version", "candidate": "Proposed version", "review": "Needs review"}[result["route"]]
        if result.get("complete"):
            details["Actual supplied-values answer"] = native.source._display(result["value"])
    return Outcome("replayed" if replay and value["confirmed"] else "confirmed" if value["confirmed"] else "unconfirmed", value["message"], details)


def form_snapshot(request, _selection):
    value = release._native_call(lambda: native.listing(request))
    return Snapshot(native.engine.digest(value), "Your compatible current and proposed local rules", native.NOTICE,
        fields=[{"name": "flow", "label": "Local rule", "kind": "select", "required": True, "choices": value["flows"]}],
        blocked="Checked answer routing is off. Enable it in Settings; original history remains available." if not value["enabled"] else "Publish a compatible current version and save a changed one-step taught draft first." if not value["flows"] else "")


def form_prepare(request, _selection, arguments):
    value = release._native_call(lambda: native.listing(request, arguments["flow"]))
    if not value["enabled"] or not any(item["value"] == arguments["flow"] for item in value["flows"]):
        raise HTTPException(409, "Choose a currently supported owned local rule.")
    return Preview("Open the complete ordinary controls without losing entered selections.", native={
        "applicability_form": {"context": value["context"], "flow": arguments["flow"], "original": ""}})


def qualify_snapshot(request, selection):
    flow = selection.get("id") if selection.get("kind") == "applicability_flow" else ""
    value = release._native_call(lambda: native.listing(request, flow))
    return Snapshot(native.engine.digest(value), "Current known-case comparisons", native.NOTICE, fields=[
        {"name": "comparisons", "label": "Complete comparisons with separately retained case permission", "kind": "multiselect", "presentation": "checkboxes",
         "required": True, "max_selections": 20, "choices": value["comparisons"]}, time_field()],
        blocked="Select a named local rule on Answer regions first." if not flow else "Choose currently permitted complete known-case comparisons first." if not value["comparisons"] else "")


def _selected(request, selection):
    identifier = selection.get("id") if selection.get("kind") == "applicability_request" else ""
    return release._native_call(lambda: native.original(request, identifier)) if identifier else {}


def action_snapshot(kind, request, selection):
    value = _selected(request, selection)
    ready = value.get("current") and value.get("confirmed") and value.get("kind") in {"qualify", "label"}
    result = value.get("result", {})
    ready = ready and (result.get("next_question") is not None if kind == "label" else "tree" in result)
    fields = [{"name": "request", "label": "Selected checked answer regions", "kind": "select", "required": True,
               "choices": [{"value": value["id"], "label": value["name"] + " / current checked result"}] if ready else [], "value": value.get("id", "")}]
    fields.append(time_field())
    description = "Use the current checked result. Every answer needs current sources and a separate local check."
    if ready and kind == "label":
        question = result["next_question"]
        description = "Hypothetical starting situation: " + native.source._display(question["inputs"]) + ". Current answer: " + native.source._display(question["arms"][0]["value"]) + "; proposed answer: " + native.source._display(question["arms"][1]["value"]) + ". This is a local test, not a real customer outcome."
        item = {"name": "expected", "label": "Your reviewed expected answer", "required": True, "kind": "text"}
        if result["output_kind"] == "boolean":
            item.update(kind="select", choices=[{"value": True, "label": "Yes"}, {"value": False, "label": "No"}])
        elif result["output_kind"] == "integer":
            item["help"] = "Enter the complete whole number, up to twenty-five digits with an optional minus sign."
        else:
            item.update(required=False, max_length=2048, help="Use up to 1,024 characters. Spaces and line breaks are retained exactly.")
            fields.append({"name": "empty_answer", "label": "The expected answer is empty text", "kind": "boolean", "value": False})
        fields.append(item)
    elif ready:
        for name, (label, declaration) in zip(("first", "second", "third"), result["inputs"].items(), strict=False):
            item = {"name": name, "label": label.replace("_", " "), "required": True}
            if declaration["type"] == "boolean":
                item.update(kind="select", choices=[{"value": True, "label": "Yes"}, {"value": False, "label": "No"}])
            else:
                item.update(kind="number", min=declaration["min"], max=declaration["max"], step=1)
            fields.append(item)
    return Snapshot(native.engine.digest(value), "Your current checked answer regions", description, fields=fields,
                    blocked="Select a current complete region check with an unanswered situation." if not ready and kind == "label" else "Select a current complete region check first." if not ready else "")


def prepare(kind, request, selection, arguments):
    if kind == "qualify":
        if selection.get("kind") != "applicability_flow":
            raise HTTPException(409, "Select the local rule first.")
        choices = {"kind": kind, "flow": selection["id"], "comparisons": arguments["comparisons"], "seconds": arguments["seconds"]}
    elif kind == "run":
        prior = release._native_call(lambda: native.original(request, arguments["request"]))
        if not prior.get("current") or "inputs" not in prior.get("result", {}):
            raise HTTPException(409, "Choose a current complete checked result.")
        choices = {"kind": kind, "original": arguments["request"], "seconds": arguments["seconds"], "inputs": {
            key: arguments.get(field) for field, key in zip(("first", "second", "third"), prior["result"]["inputs"], strict=False)}}
        if any(arguments.get(field) is not None for field in ("first", "second", "third")[len(prior["result"]["inputs"]):]):
            raise HTTPException(422, "Use only the displayed starting fields.")
    else:
        choices = {"kind": kind, "original": arguments["request"]}
        if kind == "label":
            choices["seconds"] = arguments["seconds"]
            prior = release._native_call(lambda: native.original(request, arguments["request"]))
            string = prior.get("result", {}).get("output_kind") == "string"
            if arguments["empty_answer"]:
                if not string or arguments["expected"] not in {None, ""}:
                    raise HTTPException(422, "Choose an empty text answer only when no other expected text is entered.")
                choices["expected"] = ""
            else:
                if string and arguments["expected"] in {None, ""}:
                    raise HTTPException(422, "Enter the expected text or explicitly choose an empty text answer.")
                choices["expected"] = arguments["expected"]
    value, changes = release._native_call(lambda: native.prepare(request, choices))
    return Preview(native.NOTICE, changes=changes, native={"choices": choices, "binding": native.engine.digest(value),
        "expires": value["expires"], "arguments": arguments})


def checked(arguments, prepared):
    if arguments != prepared["arguments"]:
        raise HTTPException(409, "The entered choices changed after complete review.")


def execute(request, _selection, arguments, prepared, operation):
    checked(arguments, prepared)
    row = native.owned(request, "APR-" + operation)
    if row:
        if row["binding"] != prepared["binding"]:
            raise HTTPException(409, "This original request belongs to another complete review.")
        return outcome(release._native_call(lambda: native.original(request, row["id"])), replay=True)
    value = release._native_call(lambda: native.material(request, prepared["choices"]))
    value["expires"] = prepared["expires"]
    if native.engine.digest(value) != prepared["binding"]:
        raise HTTPException(409, "The rules, expected answers or source reuse permission changed after review.")
    return outcome(release._native_call(lambda: native.apply(request, value, operation)))


def recover(request, _selection, arguments, prepared, operation, *, read_only=False):
    checked(arguments, prepared)
    row = native.owned(request, "APR-" + operation)
    if row and row["binding"] != prepared["binding"]:
        raise HTTPException(409, "This original request belongs to another complete review.")
    if row is None and not read_only:
        return None
    return outcome(release._native_call(lambda: native.original(request, "APR-" + operation)), replay=True)


def original_snapshot(request, _selection, *, only_labels=False):
    value = native.history(request)
    choices = [{"value": item["value"], "label": item["label"]} for item in value["choices"] if not only_labels or item["kind"] == "label"]
    return Snapshot(native.engine.digest(value), "Your retained original answer-region requests", "Read original custody without repeating calculations. Expected answers can be withdrawn separately.",
        fields=[{"name": "request", "label": "Reviewed hypothetical answer" if only_labels else "Original answer-region request", "kind": "select", "required": True, "choices": choices}],
        blocked="No matching original request is retained for your current account and workspace." if not choices else "")


def original_prepare(request, _selection, arguments):
    value = release._native_call(lambda: native.original(request, arguments["request"]))
    return Preview(value["message"], native=outcome(value, replay=True).details)


def entries():
    common = {"family": "learning", "pages": (native.PAGE, "/learning"), "direct_ui": native.PAGE}
    mutable = {"execute": execute, "recover": recover,
               "read_recovery": lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True)}
    return (Adapter("learning.applicability_form", "Open complete answer-region controls", input_model=FormIn, snapshot=form_snapshot, prepare=form_prepare, **common),
        Adapter("learning.qualify_answer_regions", "Check the complete answer regions", input_model=QualifyIn, snapshot=qualify_snapshot, prepare=lambda r, s, a: prepare("qualify", r, s, a), **mutable, **common),
        Adapter("learning.answer_region_question", "Answer a hypothetical local test", input_model=LabelIn, snapshot=lambda r, s: action_snapshot("label", r, s), prepare=lambda r, s, a: prepare("label", r, s, a), **mutable, **common),
        Adapter("learning.withdraw_region_answer", "Withdraw a reviewed hypothetical answer", input_model=OriginalIn, snapshot=lambda r, s: original_snapshot(r, s, only_labels=True), prepare=lambda r, s, a: prepare("withdraw", r, s, a), **mutable, **common),
        Adapter("learning.run_answer_regions", "Try checked answer routing", input_model=RunIn, snapshot=lambda r, s: action_snapshot("run", r, s), prepare=lambda r, s, a: prepare("run", r, s, a), **mutable, **common),
        Adapter("learning.answer_regions_original", "Read an original answer-region result", input_model=OriginalIn, snapshot=original_snapshot, prepare=original_prepare, **common))
