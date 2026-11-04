"""Authorized native-form handoff and original component-check readback."""
from __future__ import annotations

from datetime import datetime, timezone

from maverick.governed_operations import digest
from pydantic import Field

from . import flow_requalification as native
from . import local_flow_promotions as release
from .product_operations import Adapter, Preview, Snapshot, StrictInput


class WorkflowIn(StrictInput):
    workflow: str = Field(min_length=1, max_length=128)


class OriginalIn(StrictInput):
    request: str = Field(pattern=r"^FRQ-[a-f0-9]{32}$")


def snapshot(request, _selection):
    value = release._native_call(lambda: native.listing(request))
    return Snapshot(digest([value["context"], value["flows"]]), "Current owned rule workflows", native.NOTICE,
        fields=[{"name": "workflow", "label": "Saved workflow", "kind": "select", "required": True, "choices": value["flows"]}],
        blocked="Save and independently publish a taught-rule workflow before retaining real-case component evidence." if not value["flows"] else "")


def prepare(request, _selection, arguments):
    value = release._native_call(lambda: native.listing(request, arguments["workflow"]))
    return Preview("Choose original business values, review the complete component scope and authorize the local work in the protected native controls. Nothing ran from this handoff.",
        native={"Workflow": value["name"], "Scope": native.NOTICE,
            "rule_requalification": {"context": value["context"], "workflow": arguments["workflow"]},
            "open": {"label": "Review component evidence and changed rules", "href": native.PAGE + "?workflow=" + arguments["workflow"]}})


def original_snapshot(request, _selection):
    value = native.history(request)
    choices = [{"value": row["value"], "label": row["name"] + " · " + datetime.fromtimestamp(row["when"], timezone.utc).strftime("%d %b, %H:%M UTC")} for row in value["choices"]]
    return Snapshot(digest(value), "Your original local rule-check requests", "Read the original stored outcome without running either path again.",
        fields=[{"name": "request", "label": "Original rule check", "kind": "select", "required": True,
            "choices": choices}],
        blocked="No original rule-check request is retained for this account and workspace." if not value["choices"] else "")


def original_prepare(request, _selection, arguments):
    row = release._native_call(lambda: native.original(request, arguments["request"]))
    # Case bodies and component outputs stay in the protected human page.
    result = {key: value for key, value in row["result"].items() if key not in {"selective_result", "complete_result"}}
    return Preview(row["message"], native={"Workflow": row["name"], "Complete original result": row["confirmed"],
        "Current source permission": row["current"], "Result": result, "Scope": native.NOTICE,
        "open": {"label": "Read original protected result", "href": native.PAGE + "?original=" + row["id"]}})


def entries():
    common = {"family": "learning", "pages": (native.PAGE, "/research", "/learning/flow-checks", "/flows/designer/*"), "direct_ui": native.PAGE}
    return (Adapter("learning.rule_requalification", "Recheck affected learned rules", input_model=WorkflowIn,
        snapshot=snapshot, prepare=prepare, aliases=("selective rule repair", "requalify changed workflow"), **common),
        Adapter("learning.rule_requalification_original", "Read an original rule recheck", input_model=OriginalIn,
            snapshot=original_snapshot, prepare=original_prepare, **common))
