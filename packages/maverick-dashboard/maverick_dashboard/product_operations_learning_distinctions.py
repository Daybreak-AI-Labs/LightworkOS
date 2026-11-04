"""Copilot shares native complete reviews, package custody and observed cells."""
from __future__ import annotations

import time

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import BaseModel, ConfigDict, Field

from . import learning_distinctions as native
from . import learning_distinctions_api as api
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot


class Inputs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    run_ids: list[str] = Field(min_length=4, max_length=32)
    base_fields: list[str] = Field(default_factory=list, max_length=6)


class CellInputs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    comparisons: list[str] = Field(min_length=1, max_length=20)


def flow_id(selection):
    if selection.get("kind") != "flow" or not selection.get("id"):
        raise HTTPException(409, "Choose a named workflow on Distinctions first.")
    return selection["id"]


def snapshot(request, selection):
    selected = api.call(lambda: native.options(request, flow_id(selection)))
    runs = selected["runs"]
    observations = []
    if len(runs) >= 4:
        chosen = selection.get("run_ids") or [row["value"] for row in runs[:4]]
        try:
            state = native.source(request, {"flow_id": flow_id(selection), "run_ids": chosen, "base_fields": []})
            observations = native.preview(state)["observations"]
        except (ValueError, HTTPException):
            pass
    return Snapshot(selected["revision"], "Current accepted teaching examples", native.NOTICE, fields=[
        {"name": "run_ids", "label": "Accepted examples", "kind": "multiselect", "presentation": "checkboxes", "required": True, "max_selections": 32,
         "choices": [{"value": row["value"], "label": row["label"]} for row in runs], "value": selection.get("run_ids", [])},
        {"name": "base_fields", "label": "Observations currently used to tell cases apart", "kind": "multiselect", "presentation": "checkboxes", "choices": observations,
         "value": selection.get("base_fields", []), "help": "Leave empty to begin with no distinguishing observations. All selected source fields remain available to the comparator."}],
        blocked="Choose at least four accepted examples, with two different observations for each demonstrated action, from their Learning example cards." if len(runs) < 4 else
                "Use the native Distinctions form to choose matching examples before asking Copilot to prepare them." if not observations else "")


def prepare(request, selection, arguments):
    state = api.call(lambda: native.source(request, {"flow_id": flow_id(selection), **arguments}))
    if state["fields"] is None:
        raise HTTPException(409, native.preview(state)["qualification"])
    return Preview(native.NOTICE, changes=native.changes(state), native={"prepared": state, "expires": time.time() + native.TTL})


def checked(selection, arguments, prepared):
    if prepared["prepared"]["body"] != {"flow_id": flow_id(selection), **arguments}:
        raise HTTPException(409, "The examples or observations changed after review.")


def outcome(row, replay=False):
    details = {"Original request": row["message"]}
    if row.get("currently_usable"):
        details["Review and save separately"] = {"href": row["teach_href"], "label": "Open Teach, then choose the saved package below"}
        details["Saved package"] = {"href": row["download_href"], "label": "Download the original learning package"}
    return Outcome("replayed" if replay and row["confirmed"] else "confirmed" if row["confirmed"] else "unconfirmed", row["message"], details)


def execute(request, selection, arguments, prepared, operation):
    checked(selection, arguments, prepared)
    return outcome(api.call(lambda: native.build(request, prepared["prepared"], operation, expires=prepared["expires"])))


def recover(request, selection, arguments, prepared, operation, *, read_only=False):
    checked(selection, arguments, prepared)
    if api.call(lambda: native.owned(request, operation, prepared["prepared"])) is None and not read_only:
        return None
    return outcome(api.call(lambda: native.original(request, operation, prepared["prepared"])), replay=True)


def read_snapshot(request, selection):
    native.authority(request)
    if selection.get("kind") != "distinction_request" or not selection.get("operation"):
        return Snapshot(digest(selection), "Original distinction package", "Read an original saved result without preparing another package.", blocked="Choose an original distinction review first.")
    row = api.call(lambda: native.original(request, selection["operation"]))
    return Snapshot(digest(row), "Original distinction package", row["message"])


def read_prepare(request, selection, _arguments):
    return Preview("Read the original request only. Nothing is repeated.", native=outcome(api.call(lambda: native.original(request, selection["operation"])), replay=True).details)


def cells_snapshot(request, selection):
    state = api.call(lambda: native.comparisons.history(request, flow_id(selection)))
    return Snapshot(digest(state), "Retained native paired comparisons", "Inspect observed full-input cells from actual immutable rule comparisons, using their existing exact release-review authorization.", fields=[
        {"name": "comparisons", "label": "Recorded comparisons", "kind": "multiselect", "presentation": "checkboxes", "required": True, "max_selections": 20,
         "choices": [{"value": row["id"], "label": "Comparison / " + native.datetime_text(row["when"], seconds=True)} for row in state["comparisons"]]}],
         blocked="Compare real cases first. Uploaded scores cannot supply this evidence." if not state["comparisons"] else "")


def cells_prepare(request, selection, arguments):
    row = api.call(lambda: native.regions(request, flow_id(selection), arguments["comparisons"]))
    # Full exact evidence belongs to the native protected form, not a clipped
    # generic result renderer or model conversation history.
    return Preview(row["scope"] + " " + row["meaning"], native={"Observed cells": len(row["cells"]),
                   "distinction_cells": {"flow": flow_id(selection), "comparisons": arguments["comparisons"], "context": row["context"]}})


def entries():
    common = {"family": "learning", "pages": (native.PAGE,), "direct_ui": native.PAGE}
    return (Adapter("learning.discover_distinctions", "Find and prepare missing distinctions", input_model=Inputs, snapshot=snapshot, prepare=prepare,
                    execute=execute, recover=recover, read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
            Adapter("learning.read_distinction_package", "Read the selected original distinction package", input_model=EmptyInput,
                    snapshot=read_snapshot, prepare=read_prepare, **common),
            Adapter("learning.read_observed_cells", "Read boundaries from native paired comparisons", input_model=CellInputs,
                    snapshot=cells_snapshot, prepare=cells_prepare, **common))
