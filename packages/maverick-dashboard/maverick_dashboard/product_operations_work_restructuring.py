"""Copilot uses the same complete local-work review and original custody."""
from __future__ import annotations

import time

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import local_flow_promotions as release
from . import work_restructuring as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class Inputs(StrictInput):
    workflow: str = Field(min_length=1, max_length=128)
    evidence: list[str] = Field(min_length=2, max_length=8)
    share: bool = False
    minutes: int = Field(default=10, ge=1, le=50)
    max_steps: int = Field(default=512, ge=4, le=1024)
    max_seconds: int = Field(default=15, ge=1, le=30)


class OriginalIn(StrictInput):
    request: str = Field(pattern=r"^FWR-[a-f0-9]{32}$")


class FormIn(StrictInput):
    workflow: str = Field(min_length=1, max_length=128)


def snapshot(request, selection):
    value = release._native_call(lambda: native.listing(request))
    workflow = selection.get("id") if selection.get("kind") == "flow" else ""
    selected = release._native_call(lambda: native.listing(request, workflow)) if workflow else value
    flows = [item for item in value["flows"] if item["value"] == workflow]
    return Snapshot(digest(selected), "Current owned local case evidence", native.NOTICE, fields=[
        {"name": "workflow", "label": "Selected published workflow", "kind": "select", "required": True, "choices": flows, "value": workflow},
        {"name": "evidence", "label": "Original cases with current reuse permission", "kind": "multiselect", "presentation": "checkboxes", "required": True,
         "max_selections": 8, "choices": [{"value": item["value"], "label": item["label"]} for item in selected["cases"]]},
        {"name": "share", "label": "Allow these selected cases to share exact local preparation", "kind": "boolean", "value": False,
         "help": "Leave off to keep every case separate. Turn on only if their information may share this one private local calculation group."},
        {"name": "minutes", "label": "Finish each local case check within this many minutes", "kind": "number", "value": 10, "min": 1, "max": 50, "step": 1},
        {"name": "max_steps", "label": "Total calculation steps, including all separate comparisons", "kind": "number", "value": 512, "min": 4, "max": 1024, "step": 1},
        {"name": "max_seconds", "label": "Total local calculation time in seconds", "kind": "number", "value": 15, "min": 1, "max": 30, "step": 1}],
        blocked="Grouping local work is off. An administrator can enable Share preparation safely in Settings." if not selected["enabled"] else "Choose a named published workflow in Share preparation safely first." if not flows else
        "Retain at least two different original cases with current reuse permission first." if len(selected["cases"]) < 2 else "")


def prepare(request, _selection, arguments):
    deadline = time.time() + arguments["minutes"] * 60
    choices = {"flow": arguments["workflow"], "cases": [{"evidence": item, "group": "Shared selected cases" if arguments["share"] else "", "deadline": deadline} for item in arguments["evidence"]],
               "authorize_sharing": arguments["share"], "max_steps": arguments["max_steps"], "max_seconds": arguments["max_seconds"]}
    value, changes = release._native_call(lambda: native.prepare(request, choices))
    # The sealed Copilot review retains only an exact source binding and choices,
    # not another copy of private original inputs or component bodies.
    return Preview(native.NOTICE, changes=changes, native={"choices": choices, "binding": digest(value), "expires": value["expires"], "arguments": arguments})


def checked(arguments, prepared):
    if arguments != prepared["arguments"]:
        raise HTTPException(409, "The selected cases or local work choices changed after review.")


def outcome(row, replay=False):
    summary = row.get("summary", {})
    work = {"Preparation calculated": summary.get("computed_components"), "Successful preparation shared": summary.get("reused_components"),
            "Ordinary batching comparison": summary.get("same_information_baseline"), "Total local calculation steps": summary.get("native_steps"),
            "Observed local work time": str(round(summary.get("calculation_ms", 0))) + " ms, including current-source checks and intermediate case receipts",
            "All separate complete results matched": summary.get("all_agreed")} if summary else {}
    return Outcome("replayed" if replay and row["confirmed"] else "confirmed" if row["confirmed"] else "unconfirmed", row["message"],
        {"Complete original check": row["confirmed"], "Current source permission": row["current"], "Retained case receipts": row["completed_cases"],
         "Work and comparison": work, "Full original results": {"label": "Read each original case and both results", "href": native.PAGE + "?original=" + row["id"]}})


def execute(request, _selection, arguments, prepared, operation):
    checked(arguments, prepared)
    existing = native.owned(request, "FWR-" + operation)
    if existing:
        if existing["binding"] != prepared["binding"]:
            raise HTTPException(409, "The original request belongs to another reviewed plan.")
        return outcome(release._native_call(lambda: native.original(request, existing["id"])), replay=True)
    value = release._native_call(lambda: native.material(request, prepared["choices"]))
    value["expires"] = prepared["expires"]
    if digest(value) != prepared["binding"]:
        raise HTTPException(409, "The selected source, permission or workflow changed. Review current choices.")
    return outcome(release._native_call(lambda: native.apply(request, value, operation)))


def recover(request, _selection, arguments, prepared, operation, *, read_only=False):
    checked(arguments, prepared)
    identifier = "FWR-" + operation
    row = native.owned(request, identifier)
    if row is not None and row["binding"] != prepared["binding"]:
        raise HTTPException(409, "The original request belongs to another reviewed plan.")
    if row is None and not read_only:
        return None
    return outcome(release._native_call(lambda: native.original(request, identifier)), replay=True)


def original_snapshot(request, _selection):
    value = native.history(request)
    return Snapshot(digest(value), "Your original local grouping requests", "Read the retained original without resuming any calculation.",
        fields=[{"name": "request", "label": "Original local grouping check", "kind": "select", "required": True, "choices": value["choices"]}],
        blocked="No original local grouping check is retained for this account and workspace." if not value["choices"] else "")


def original_prepare(request, _selection, arguments):
    row = release._native_call(lambda: native.original(request, arguments["request"]))
    return Preview(row["message"], native=outcome(row, replay=True).details)


def form_snapshot(request, selection):
    value = release._native_call(lambda: native.listing(request))
    workflow = selection.get("id") if selection.get("kind") == "flow" else ""
    return Snapshot(digest(value), "Choose separate case groups and deadlines", "Open the complete protected form. Each case can have its own confidentiality group and local check deadline; current entered work is preserved.",
        fields=[{"name": "workflow", "label": "Published workflow", "kind": "select", "required": True, "choices": value["flows"], "value": workflow}],
        blocked="Grouping local work is off. An administrator can enable Share preparation safely in Settings." if not value["enabled"] else "")


def form_prepare(request, _selection, arguments):
    value = release._native_call(lambda: native.listing(request, arguments["workflow"]))
    return Preview("Choose the current cases, a confidentiality group and a local deadline for each on the complete protected form.", native={"work_grouping_form": {"context": value["context"], "flow": arguments["workflow"]}})


def entries():
    common = {"family": "learning", "pages": (native.PAGE, "/learning/recheck-rules", "/learning", "/flows/designer/*"), "direct_ui": native.PAGE}
    return (Adapter("learning.restructure_local_work", "Review and check grouped local work", input_model=Inputs, snapshot=snapshot, prepare=prepare,
        execute=execute, recover=recover, read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
        Adapter("learning.restructure_local_work_original", "Read an original grouped-work check", input_model=OriginalIn,
            snapshot=original_snapshot, prepare=original_prepare, **common),
        Adapter("learning.restructure_local_work_form", "Open complete case groups and deadlines", input_model=FormIn,
            snapshot=form_snapshot, prepare=form_prepare, **common))
