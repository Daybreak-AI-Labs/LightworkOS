"""Typed protected author handoff and original request-local result reader."""
from __future__ import annotations

from maverick.governed_operations import digest
from pydantic import Field

from . import request_program as native
from .product_operations import Adapter, Preview, Snapshot, StrictInput


class EmptyIn(StrictInput):
    pass


class OriginalIn(StrictInput):
    request: str = Field(pattern=r"^RSP-[a-f0-9]{32}$")


def snapshot(request, _selection):
    value = native.call(lambda: native.listing(request))
    return Snapshot(digest([value["context"], value["enabled"], value["flows"]]), "Current owned checked-rule workflows", native.NOTICE,
                    blocked="Request-specific answers are off. An administrator can enable them in Settings." if not value["enabled"] else "")


def prepare(request, _selection, _arguments):
    value = native.call(lambda: native.listing(request))
    if not value["enabled"]:
        from fastapi import HTTPException
        raise HTTPException(409, "Request-specific answers are off. Original results remain readable.")
    return Preview("Choose checked steps, original case answers and current request values in the protected native form. This handoff performs no calculation and relays no private values to a model.",
        native={"request_program_form": {"context": value["context"]},
                "open": {"label": "Prepare an answer for this request", "href": native.PAGE}})


def original_snapshot(request, _selection):
    value = native.call(lambda: native.listing(request))
    return Snapshot(digest([value["context"], value["history"]]), "Your original request-specific answers", "Read the accepted original outcome without repeating calculation.",
        fields=[{"name": "request", "label": "Original request", "kind": "select", "required": True, "choices": value["history"]}],
        blocked="No original request is retained for the current account and workspace." if not value["history"] else "")


def original_prepare(request, _selection, arguments):
    row = native.call(lambda: native.original(request, arguments["request"]))
    return Preview(row["message"], native={"Complete original outcome": row["confirmed"], "Current source permission": row["current"],
        "open": {"label": "Read complete protected original answer", "href": native.PAGE + "?original=" + row["id"]}})


def entries():
    common = {"family": "learning", "pages": (native.PAGE, "/learning", "/research", "/learning/recheck-rules"), "direct_ui": native.PAGE}
    return (Adapter("learning.request_program", "Prepare an answer for this request", input_model=EmptyIn, snapshot=snapshot, prepare=prepare, **common),
            Adapter("learning.request_program_original", "Read an original request-specific answer", input_model=OriginalIn, snapshot=original_snapshot, prepare=original_prepare, **common))
