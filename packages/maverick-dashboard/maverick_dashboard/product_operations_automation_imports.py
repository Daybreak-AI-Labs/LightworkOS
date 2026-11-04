"""Copilot opens the protected full import form and reads exact original results."""
from __future__ import annotations

from fastapi import HTTPException
from pydantic import Field

from . import automation_imports as native
from .product_operations import Adapter, Preview, Snapshot, StrictInput


class Empty(StrictInput):
    pass


class OriginalIn(StrictInput):
    request: str = Field(pattern=r"^AIR-[a-f0-9]{32}$")


def form_snapshot(request, _selection):
    value = native.native_call(lambda: native.catalog(request))
    return Snapshot(native.digest(value), "Current automation import choices", native.NOTICE,
                    blocked="Automation import is off. Original history remains available; an administrator can enable it in All settings." if not value["enabled"] else "")


def form_prepare(request, _selection, _arguments):
    value = native.native_call(lambda: native.catalog(request))
    if not value["enabled"]:
        raise HTTPException(409, "Enable Automation import in All settings before importing.")
    return Preview("Open the complete protected file or connected-account import controls. No file is uploaded, account is read, draft is replaced or schedule activated by opening them.", native={
        "automation_import_form": {"context": value["context"], "original": ""}})


def original_snapshot(request, selection):
    value = native.native_call(lambda: native.history(request))
    selected = selection.get("id") if selection.get("kind") == "automation_import_request" else ""
    return Snapshot(native.digest(value), "Your retained original automation imports", native.NOTICE, fields=[
        {"name": "request", "label": "Original import", "kind": "select", "required": True, "choices": value["choices"], "value": selected}],
        blocked="No original import requests are retained for this account and workspace." if not value["choices"] else "")


def original_prepare(request, _selection, arguments):
    value = native.native_call(lambda: native.original(request, arguments["request"]))
    return Preview(value["message"], native={"Original save confirmed": value["confirmed"],
        "Saved items": [{"Name": item["title"], "Result": item["status"]} for item in value["items"]],
        "automation_import_form": {"context": native.authority(request)[2], "original": arguments["request"]}})


def entries():
    common = {"family": "schedules", "direct_ui": native.PAGE, "pages": ("/automations", "/learning")}
    return (Adapter("automations.import_form", "Open automation import", input_model=Empty, snapshot=form_snapshot, prepare=form_prepare, **common),
            Adapter("automations.import_original", "Read an original automation import", input_model=OriginalIn, snapshot=original_snapshot, prepare=original_prepare, **common))
