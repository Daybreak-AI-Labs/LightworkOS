"""Copilot uses the same reviewed native pass and pure original readback."""
from __future__ import annotations

import time

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import learning_passes as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot


class PassInput(native.Choices):
    instructions: str = Field(default="", max_length=4000)


def snapshot(request, _selection):
    state = native.catalog(request)
    return Snapshot(state["revision"], "Current self-coaching models and shareable work", native.NOTICE,
                    fields=[{"name": "scope", "label": "Models to review", "kind": "select", "required": True,
                             "choices": [{"value": "main", "label": "The main assistant"}, {"value": "all", "label": "Every model in use"},
                                         {"value": "chosen", "label": "One model chosen below"}]},
                            {"name": "model_id", "label": "One model", "kind": "select", "choices": [{"value": "", "label": "Use the selection above"}, *state["models"]]},
                            {"name": "trial", "label": "Put new lessons on trial first", "kind": "boolean", "value": False},
                            {"name": "retire", "label": "Also retire lessons not confirmed lately", "kind": "boolean", "value": True},
                            {"name": "instructions", "label": "Standing instructions for this test", "kind": "textarea", "max_length": 4000,
                             "help": "Enter a reviewed copy. For a longer copy, use Run a reviewed learning pass on the Learned page."}])


def prepare(request, _selection, arguments):
    prepared = native.prepare(request, arguments)
    return Preview(native.NOTICE, changes=native.review_rows(prepared), native={"prepared": prepared, "expires": time.time() + native.TTL})


def _checked(arguments, prepared):
    if arguments != prepared["prepared"]["body"]:
        raise HTTPException(409, "The learning choices changed after review. Review current work again.")


def _outcome(row, replay=False):
    state = "replayed" if replay and row["confirmed"] else "queued" if row.get("job", {}).get("worker_available") else "confirmed" if row["confirmed"] else "unconfirmed"
    details = {"Original request": row["message"], "Meaning": native.NOTICE,
               "Original learning pass": {"href": "/learned?learning_pass=" + row["operation"] + "#learning-passes", "label": "Check original learning pass"}}
    if row.get("task_href"):
        details["Progress and stop"] = {"href": row["task_href"], "label": "Read current progress and stop controls"}
    if row.get("result"):
        details["Recorded result"] = row["result"]
    if row.get("job", {}).get("problem"):
        details["Task problem"] = row["job"]["problem"]
    return Outcome(state, row["message"], details)


def execute(request, _selection, arguments, prepared, operation):
    _checked(arguments, prepared)
    return _outcome(native.start(request, prepared["prepared"], operation, expires=prepared["expires"]))


def recover(request, _selection, arguments, prepared, operation, *, read_only=False):
    _checked(arguments, prepared)
    row = native.owned(request, operation, prepared["prepared"])
    if row is None and not read_only:
        return None
    return _outcome(native.original(request, operation, prepared["prepared"]), replay=True)


def read_snapshot(request, selection):
    state = native.questions._authority(request)
    if selection.get("kind") != "learning_pass" or not selection.get("operation"):
        return Snapshot(digest([state, "none"]), "Your original learning pass", "Read the retained original request without repeating work.",
                        blocked="Choose an original learning pass on the Learned page first.")
    row = native.original(request, selection["operation"])
    return Snapshot(digest(row), "Your original learning pass", row["message"])


def read_prepare(request, selection, _arguments):
    row = native.original(request, selection["operation"])
    return Preview(row["message"], native=_outcome(row, replay=True).details)


def entries():
    common = {"family": "learning", "pages": ("/learned",), "direct_ui": native.PAGE}
    return (Adapter("learning.start_reviewed_pass", "Run a reviewed self-coaching pass", input_model=PassInput,
                    snapshot=snapshot, prepare=prepare, execute=execute, recover=recover,
                    read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
            Adapter("learning.read_original_pass", "Read the selected original learning pass", input_model=EmptyInput,
                    snapshot=read_snapshot, prepare=read_prepare, **common))
