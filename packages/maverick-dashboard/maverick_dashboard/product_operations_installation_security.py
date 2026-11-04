"""Typed Copilot uses the identical reviewed installation settings journey."""
from __future__ import annotations

from functools import partial

from fastapi import HTTPException
from pydantic import Field

from . import installation_security as service
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class ChoiceInput(StrictInput):
    setting: str = Field(min_length=3, max_length=120)
    value: str = Field(max_length=255)
    inherit: bool = False


class LimitInput(StrictInput):
    setting: str = Field(min_length=3, max_length=120)
    value: float | int | None
    inherit: bool = False


class TextInput(ChoiceInput):
    value: str = Field(max_length=512)


class RecoverInput(StrictInput):
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")


def _eligible(row, kind):
    return not row["locked"] and row["control"] in {"choice": {"toggle", "select"}, "limit": {"number"}, "text": {"text"}}[kind]


def snapshot(request, _selection, *, kind=None):
    value = service.state(request)
    fields = []
    if kind in {"choice", "limit", "text"}:
        rows = [row for row in value["rows"] if _eligible(row, kind)]
        fields = [{"name": "setting", "label": "Installation policy", "kind": "select", "required": True,
                   "choices": [{"value": row["id"], "label": row["label"]} for row in rows]}]
        if kind == "choice":
            fields += [{"name": "value", "label": "Reviewed choice", "kind": "select", "required": True,
                "depends_on": "setting", "choices_by": {row["id"]: [{"value": "true", "label": "On"}, {"value": "false", "label": "Off"}]
                    if row["control"] == "toggle" else row["choices"] for row in rows}}]
        else:
            fields += [{"name": "value", "label": "Reviewed amount" if kind == "limit" else "Reviewed value", "kind": "number" if kind == "limit" else "text", "required": kind != "limit"}]
        fields += [{"name": "inherit", "label": "Use the inherited installation choice instead", "kind": "boolean", "value": False}]
    elif kind == "recover":
        previous = service.receipts().get(service._identity(request))
        fields = [{"name": "operation", "label": "Your latest installation-policy attempt", "kind": "select", "required": True,
                   "choices": [{"value": previous["operation"], "label": previous["label"]}] if previous else []}]
    details = {"current_policy": [{"policy": row["label"], "value": row["value_text"], "source": row["source_text"], "editable": not row["locked"]} for row in value["rows"]],
               "readiness": value["summary"], "notice": value["notice"]}
    return Snapshot(value["revision"], "Current installation settings and controlling sources", value["notice"], details, fields)


def preview(request, _selection, args, *, kind):
    if kind == "status":
        return Preview("Read current installation policy. Nothing changed.", native=snapshot(request, {}).details)
    if kind == "recover":
        return Preview("Record that you reviewed current policy and this uncertain attempt. This does not assert that the earlier change succeeded or repeat it.",
                       native={"operation": args["operation"]})
    value = service.state(request)
    row = next((row for row in value["rows"] if row["id"] == args["setting"]), None)
    if row is None or not _eligible(row, kind):
        raise HTTPException(422, "Choose a supported policy of this kind. Credentials, file choices and lists use the protected administration form.")
    desired = args["value"]
    if row["control"] == "toggle":
        if desired not in {"true", "false"}:
            raise HTTPException(422, "Choose On or Off.")
        desired = desired == "true"
    body, changes, warnings = service._change(request, row["id"], desired, value["revision"], inherit=args["inherit"])
    return Preview("Apply this reviewed installation policy with the existing sign-in, approval and activity safeguards. " + " ".join(warnings),
                   changes, {"revision": value["revision"], "change": body.changes[0].model_dump()})


def execute(request, _selection, _args, prepared, operation, *, kind):
    result = service.acknowledge(request, prepared["operation"]) if kind == "recover" else service.apply_change(request, prepared["change"], prepared["revision"], operation)
    status = result["status"]
    return Outcome("queued" if status == "queued" else "confirmed" if status in {"confirmed", "reviewed_unknown"} else "unconfirmed", result["message"], result)


def recover(request, _selection, _args, _prepared, operation, *, kind):
    if kind == "recover":
        return None  # receipt retry is itself safe; it never repeats policy effects
    value = service.readback(request, operation)
    if value["status"] != "not_found":
        return Outcome("queued" if value["status"] == "queued" else "replayed" if value["status"] == "confirmed" else "unconfirmed", value["message"], value)
    return None


def check_preview(request, _selection, _args, *, kind):
    result = service.check(request, kind)
    return Preview(result["message"], native={"connection_answered": result["ok"], "notice": "A connection check does not prove a successful sign-in or complete task isolation. No policy changed."})


def entries():
    pages = (service.PAGE, "/settings", "/settings/all", "/permissions")
    result = [Adapter("installation.security.status", "Show installation protection and sign-in", "connections", service.PAGE, pages,
                      EmptyInput, snapshot, partial(preview, kind="status"), aliases=("show company sign in", "show work area policy", "installation protection"))]
    for kind, model, label in (("choice", ChoiceInput, "Change an installation protection choice"), ("limit", LimitInput, "Change a protected work area limit"),
                               ("text", TextInput, "Change a sign-in or work area detail"), ("recover", RecoverInput, "Review an interrupted installation-policy attempt")):
        result.append(Adapter("installation.security." + kind, label, "connections", service.PAGE, pages, model,
            partial(snapshot, kind=kind), partial(preview, kind=kind), partial(execute, kind=kind), partial(recover, kind=kind),
            read_recovery=partial(recover, kind=kind) if kind != "recover" else None))
    for kind, label in (("work-area", "Check the work area connection"), ("company-signin", "Check the company sign-in connection"), ("single-signon", "Check the single sign-on connection")):
        result.append(Adapter("installation.security.check." + kind, label, "connections", service.PAGE, pages,
                              EmptyInput, snapshot, partial(check_preview, kind=kind)))
    return tuple(result)
