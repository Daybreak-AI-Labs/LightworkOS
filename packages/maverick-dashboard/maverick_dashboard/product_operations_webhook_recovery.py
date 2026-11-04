"""Copilot uses the exact same reviewed signing-secret recovery as Settings."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import webhook_settings_recovery_api as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput

_PAGE = "/settings"


class ChangeInput(StrictInput):
    change: str = Field(pattern=r"^[a-f0-9]{32}$")


def snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Choose a saved signing-secret change in this review.")
    value = native._call(lambda: native.choices(request))
    pending = [row for row in value["records"] if row["can_reconcile"]]
    # Public status metadata is stable. Encrypted review tokens contain private
    # current-state bindings and are never used as catalog revision material.
    public = [{key: item for key, item in row.items() if key != "review"} for row in value["records"]]
    return Snapshot(digest([value["context"], public]), "Your original reviewed signing-secret changes",
        "Verify an interrupted change and add its current-state check to activity history. No secret is saved or sent again.",
        {"records": [{"change": row["label"], "status": row["status"], "explanation": row["explanation"] or row["summary"]} for row in public[:20]],
         "open": {"label": "Open saved change history", "href": _PAGE + "#settings-integrations"}},
        [{"name": "change", "label": "Saved change to check", "kind": "select", "required": True,
          "choices": [{"value": row["id"], "label": row["label"]} for row in pending]}],
        "No saved change currently offers an exact recovery check." if not pending else "")


def prepare(request, selection, arguments):
    snapshot(request, selection)
    value = native._call(lambda: native.choices(request))
    row = next((row for row in value["records"] if row["id"] == arguments["change"] and row["can_reconcile"]), None)
    if row is None:
        raise HTTPException(409, "This change no longer offers the reviewed check. Refresh its saved history.")
    return Preview(row["summary"], [{"label": "Original change", "after": row["label"]},
        {"label": "Current record", "after": row["status"]}], {"change": row["id"], "review": row["review"]})


def execute(request, _selection, arguments, prepared, _operation):
    if prepared["change"] != arguments["change"]:
        raise HTTPException(409, "The selected change differs from the review. Review it again.")
    result = native._call(lambda: native.reconcile(request, arguments["change"], native.Check(
        context=native.context_for(request), review=prepared["review"], confirm=True)))
    return Outcome("confirmed", result["detail"], {"open": {"label": "Open saved change history", "href": _PAGE + "#settings-integrations"}})


def recover(request, _selection, arguments, _prepared, _operation):
    value = native._call(lambda: native.choices(request))
    row = next((row for row in value["records"] if row["id"] == arguments["change"]), None)
    if row is None or not row["completed"]:
        return None
    return Outcome("replayed", row["status"] + ". This is the original historical outcome. No secret or activity row was repeated.",
                   {"open": {"label": "Open saved change history", "href": _PAGE + "#settings-integrations"}})


def entries():
    return (Adapter("connections.webhook_change_recovery", "Verify a signing-secret change", "connections", _PAGE + "#settings-integrations",
        (_PAGE, "/settings/all", "/settings/webhooks/manage"), ChangeInput, snapshot, prepare, execute, recover,
        ("recover signing secret change", "finish webhook change history", "check interrupted signing secret change")),)
