"""Authorized complete native-form handoff and original visibility result."""
from __future__ import annotations

from maverick.governed_operations import digest
from pydantic import Field

from . import recovery_visibility as native
from .product_operations import Adapter, Preview, Snapshot, StrictInput


class EmptyIn(StrictInput):
    pass


class OriginalIn(StrictInput):
    request: str = Field(pattern=r"^RVP-[a-f0-9]{32}$")


def snapshot(request, _selection):
    value = native.call(lambda: native.listing(request))
    return Snapshot(digest([value["context"], value["enabled"]]), "Current fictional local practice controls", native.NOTICE,
                    details={"context": value["context"]}, blocked="Recovery visibility practice is off. An administrator can enable it in Settings." if not value["enabled"] else "")


def prepare(request, _selection, _arguments):
    value = native.call(lambda: native.listing(request))
    if not value["enabled"]:
        from fastapi import HTTPException
        raise HTTPException(409, "Recovery visibility practice is off. Review current settings first.")
    return Preview("Choose named visible observations, review the complete fictional search and authorize it in the protected native form. This handoff performs no search.",
                   native={"recovery_visibility_form": {"context": value["context"]},
                           "open": {"label": "Review recovery visibility practice", "href": native.PAGE}})


def original_snapshot(request, _selection):
    value = native.call(lambda: native.listing(request))
    choices = [{"value": row["value"], "label": row["label"]} for row in value["history"]]
    return Snapshot(digest(value), "Your retained original local practices", "Read a retained original without rerunning its search or changing live requests.",
                    fields=[{"name": "request", "label": "Original practice", "kind": "select", "required": True, "choices": choices}],
                    blocked="No original local practice is retained for this account and workspace." if not choices else "")


def original_prepare(request, _selection, arguments):
    row = native.call(lambda: native.original(request, arguments["request"]))
    return Preview(row["message"], native={"Complete original result": row["confirmed"], "Current installed source": row["current"],
        "Scope": native.LIMITS, "open": {"label": "Read complete original result", "href": native.PAGE + "?original=" + row["id"]}})


def entries():
    common = {"family": "learning", "pages": (native.PAGE, "/learning", "/research", "/learning/approval-challenges"), "direct_ui": native.PAGE}
    return (Adapter("learning.recovery_visibility", "Review missing-reply visibility", input_model=EmptyIn,
                    snapshot=snapshot, prepare=prepare, aliases=("paired recovery histories", "what can an unknown reply tell us"), **common),
            Adapter("learning.recovery_visibility_original", "Read an original visibility practice", input_model=OriginalIn,
                    snapshot=original_snapshot, prepare=original_prepare, **common))
