"""Exact native assurance-record reviews and GRC original delivery receipts."""
from __future__ import annotations

from functools import partial
from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import model_risk_api as native
from .assurance_pickers_api import _grc_source_choices
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGE = "/security/assurance"
NOTICE = "Review the complete current record and exact destination. Sending can create or update the destination's record. Local delivery rows require an external receipt before they establish delivery."


class RecordIn(StrictInput):
    target: Literal["servicenow_irm", "archer"]
    record: str = Field(min_length=3, max_length=180)


def snapshot(request, selection, *, write=False):
    if selection:
        raise HTTPException(422, "Choose an actual assurance record in this review.")
    context = native._grc_context(request, write=write)
    officer = native._module("model_risk_assurance", "model_risk_assurance")
    grc = native._module("grc_outbound_sync", "grc_outbound_sync")
    rows = []
    for kind, label in (("finding", "Finding"), ("risk_acceptance", "Accepted risk"), ("ai_incident", "AI incident")):
        for row in _grc_source_choices(officer, kind):
            source, record = native._grc_source(grc, kind, row["source"]["source_id"])
            rows.append({"value": kind + "|" + source.source_id,
                "label": label + " · " + row["label"] + " · " + source.severity.title(),
                "binding": digest([record, source.source_revision, source.source_digest])})
    targets = sorted(target.value for target in grc.policy_from_config().allowed_targets)
    return Snapshot(digest([context, rows, targets]), "Current authorized Lightwork assurance records", NOTICE,
        fields=[{"name": "target", "label": "Destination", "kind": "select", "required": True,
                 "choices": [{"value": value, "label": "ServiceNow IRM" if value == "servicenow_irm" else "Archer"} for value in targets]},
                {"name": "record", "label": "Current record", "kind": "select", "required": True,
                 "choices": [{"value": row["value"], "label": row["label"]} for row in rows]}],
        blocked="No current assurance record or admitted destination is available. Finish setup in Settings or record the source evidence first." if not rows or not targets else "")


def prepare(request, selection, arguments, *, write=False):
    snapshot(request, selection, write=write)
    try:
        kind, source_id = arguments["record"].split("|", 1)
        selected = native.GRCOutboundSelectionIn(source_kind=kind, source_id=source_id)
    except ValueError as exc:
        raise HTTPException(422, "Choose a current assurance record from the available records.") from exc
    value = native.prepare_grc_record_review(request, arguments["target"], selected)
    protected = {"target": arguments["target"], "review_token": value["review_token"]} if write else {}
    return Preview(NOTICE if write else value["message"],
        changes=[{"label": row["label"], "after": row["value"]} for row in value["details"]],
        native={**protected,
            "Exact outbound record": value["technical"],
            "open": {"label": "Open the same protected GRC controls", "href": PAGE + "#grc-outbound-panel"}})


def _outcome(value, *, replay=False):
    delivered = value["status"] == "delivered"
    return Outcome("replayed" if delivered and replay else "confirmed" if delivered else "unconfirmed",
        value["message"], {"Delivery status": value["status"], "Original native result": value.get("state"),
                          "open": {"label": "Check original delivery in Assurance", "href": PAGE + "#grc-outbound-panel"}})


def execute(request, _selection, _arguments, prepared, _operation):
    return _outcome(native.execute_grc_record_review(request, prepared["target"], prepared["review_token"], confirmed=True))


def recover(request, _selection, _arguments, prepared, _operation):
    value = native.read_grc_record_review(request, prepared["target"], prepared["review_token"])
    return _outcome(value, replay=True) if value["original_found"] else None


def read_recovery(request, _selection, _arguments, prepared, _operation):
    return _outcome(native.read_grc_record_review(request, prepared["target"], prepared["review_token"]), replay=True)


def original_snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Read the saved original review from its protected controls.")
    context = native._grc_context(request)
    return Snapshot(context, "Your current Assurance workspace", "Open the protected original-result lookup. The retained review stays in this browser and cannot be authored in conversation.")


def original_prepare(request, selection, _arguments):
    original_snapshot(request, selection)
    return Preview("Open Check original delivery result for the saved review. Reading sends nothing and only an exact native receipt proves delivery.",
        native={"open": {"label": "Read the retained original delivery", "href": PAGE + "#grc-outbound-original"}})


def entries():
    common = {"family": "reviews", "pages": (PAGE,), "direct_ui": PAGE + "#grc-outbound-panel"}
    return (
        Adapter("grc.outbound.review", "Review a current record for ServiceNow or Archer", input_model=RecordIn,
            snapshot=snapshot, prepare=prepare, **common),
        Adapter("grc.outbound.send", "Send an exact reviewed assurance record", input_model=RecordIn,
            snapshot=partial(snapshot, write=True), prepare=partial(prepare, write=True), execute=execute,
            recover=recover, read_recovery=read_recovery, **common),
        Adapter("grc.outbound.original", "Read an original GRC delivery result", input_model=EmptyInput,
            snapshot=original_snapshot, prepare=original_prepare, **common),
    )
