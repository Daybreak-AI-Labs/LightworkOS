"""Copilot shares the native reviewed meaning-check admission and original read."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import learning_conflicts as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class CheckInput(StrictInput):
    model: str = Field(default="", max_length=200)


class OriginalInput(StrictInput):
    request: str = Field(pattern=r"^[a-f0-9]{32}$")


def snapshot(request, _selection):
    state = native.catalog(request)
    return Snapshot(digest(state), "Current shared lessons, current models and original meaning-check requests", native.NOTICE,
                    fields=[{"name": "model", "label": "Lessons for", "kind": "select", "required": True,
                             "choices": [{"value": "", "label": "Every model"}, *state["models"]]}])


def prepare(request, _selection, arguments):
    state = native.prepare(request, arguments["model"] or None)
    return Preview("Review all listed lessons and current spending before starting. No instruction is changed.",
                   changes=native.changes(request, state), native=state)


def outcome(result, *, replay=False):
    details = {"Original request": result["message"], "Scope": native.NOTICE, "Original result": {"href": "/learned?meaning_check=" + result["operation"] + "#lpo-clash-h",
                                                             "label": "Open this original check"}}
    if result.get("job_id"):
        details["Recorded task"] = {"href": result["task_href"], "label": "Open progress and stop controls"}
    for key, label in (("checked", "AI judgments received"), ("unknown", "AI judgments unavailable"),
                       ("flagged", "Possible conflicts flagged by AI"), ("wording_flags", "Wording flags without an AI judgment"),
                       ("spent", "Recorded AI cost"), ("pairs", "Currently readable original pairs")):
        if key in result:
            details[label] = result[key]
    if result.get("problem"):
        details["Task result"] = result["problem"]
    return Outcome("replayed" if replay and result["confirmed"] else "confirmed" if result["confirmed"] else "unconfirmed",
                   result["message"], details)


def execute(request, _selection, arguments, prepared, operation):
    if prepared["model"] != (arguments["model"] or None):
        raise HTTPException(409, "The selected model changed. Review the current guidance again.")
    return outcome(native.start(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation, *, read_only=False):
    if not read_only and native.owned(request, operation, prepared=prepared) is None:
        return None
    return outcome(native.original(request, operation, prepared=prepared), replay=True)


def original_snapshot(request, _selection):
    state = native.catalog(request)
    return Snapshot(digest(state), "Your exact original meaning-check requests", "Read the original admission and retained task without another AI call.",
                    fields=[{"name": "request", "label": "Original check", "kind": "select", "required": True, "choices": state["requests"]}],
                    blocked="No original meaning-check request is recorded for this account and workspace." if not state["requests"] else "")


def read_prepare(request, _selection, arguments):
    native.owned(request, arguments["request"])
    return Preview("Read this exact original check; no work will be repeated.", native=outcome(native.original(request, arguments["request"]), replay=True).details)


def entries():
    common = {"family": "learning", "direct_ui": native.PAGE, "pages": ("/learned", "/learning")}
    return (
        Adapter("learning.check_lesson_meaning", "Check lessons for possible conflicts by meaning", input_model=CheckInput,
                snapshot=snapshot, prepare=prepare, execute=execute, recover=recover,
                read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
        Adapter("learning.read_meaning_check", "Read an original lesson meaning check", input_model=OriginalInput,
                snapshot=original_snapshot, prepare=read_prepare, **common),
    )
