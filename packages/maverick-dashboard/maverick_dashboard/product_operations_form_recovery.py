"""Copilot review of one signed, interrupted public-form decision."""
from __future__ import annotations

import re

from fastapi import HTTPException, Response
from maverick.governed_operations import digest

from . import api as native
from .api_schemas import FormDecisionRecoveryIn
from .draft_api import context_for
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot

_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")


def _selection(value):
    if (not isinstance(value, dict) or set(value) != {"kind", "name", "sequence"}
            or value["kind"] != "form_recovery"
            or not isinstance(value["name"], str)
            or _NAME.fullmatch(value["name"]) is None
            or type(value["sequence"]) is not int or value["sequence"] < 1):
        raise HTTPException(404, "Choose the held form decision in Automations first.")
    return value["name"], value["sequence"]


def _current(request, selection):
    name, sequence = _selection(selection)
    result = native.waiting_form_submissions(request, Response(), name)
    held = result.get("interrupted_decision")
    if isinstance(held, dict) and held.get("sequence") == sequence:
        return name, sequence, result, held, None
    receipt = native.form_submission_decision_receipt(request, Response(), name, sequence)
    return name, sequence, result, None, receipt


def snapshot(request, selection):
    name, sequence, result, held, receipt = _current(request, selection)
    if receipt is not None:
        revision = digest([context_for(request), name, sequence,
                           receipt["binding_revision"], receipt["fields_sha256"],
                           receipt["decision_sha256"], "complete"])
        return Snapshot(revision, "Signed form decision",
                        "The recorded Do not run decision is complete.",
                        {"form": name, "submission": sequence, "do_not_run": True},
                        blocked="This decision is already complete.")
    revision = digest([context_for(request), name, sequence, result["binding_revision"],
                       held["fields_sha256"], held["decision_sha256"]])
    return Snapshot(revision, "Signed form decision", "The saved decision is held until its record is completed.",
                    {"form": name, "submission": sequence,
                     "recorded_reason": held["reason"],
                     "recorded_by": held["decided_by"],
                     "received_at": held["received_at"]})


def prepare(request, selection, _arguments):
    name, sequence, result, held, _receipt = _current(request, selection)
    if held is None:
        raise HTTPException(409, "This decision is already complete. Refresh its status.")
    fields = held["fields"]
    if (not isinstance(fields, dict) or len(fields) > 50
            or len(str(fields)) > 12000):
        raise HTTPException(409, "This submission needs review on the Automations page.")
    return Preview(
        "Complete the recorded Do not run decision for this exact submission. This does not start work or remove the received answers.",
        changes=[{"label": "Received answers", "before": fields,
                  "after": "Kept with the form"},
                 {"label": "Recorded decision", "before": "Held after an interruption",
                  "after": "Do not run: " + held["reason"]}],
        native={"name": name, "sequence": sequence,
                "expected_generation": result["binding_revision"],
                "expected_fields_sha256": held["fields_sha256"],
                "expected_decision_sha256": held["decision_sha256"]},
    )


def execute(request, selection, _arguments, prepared, _operation_id):
    name, sequence = _selection(selection)
    if prepared.get("name") != name or prepared.get("sequence") != sequence:
        raise HTTPException(409, "The selected form decision changed. Review it again.")
    body = FormDecisionRecoveryIn(
        expected_generation=prepared["expected_generation"],
        expected_fields_sha256=prepared["expected_fields_sha256"],
        expected_decision_sha256=prepared["expected_decision_sha256"],
    )
    result = native.recover_form_submission_decision(request, Response(), name, sequence, body)
    if (result.get("do_not_run") is not True
            or result.get("decision_sha256") != prepared["expected_decision_sha256"]):
        return Outcome("unconfirmed", "The recovery result could not be confirmed. Open Automations to check the held submission.")
    return Outcome("confirmed", "The recorded decision is complete. The received answers remain saved; no work was started.",
                   {"form": name, "submission": sequence, "decision": "Do not run"})


def recover(request, selection, _arguments, prepared, _operation_id):
    """Resolve a lost response from the native, cursor-independent receipt."""
    name, sequence = _selection(selection)
    if prepared.get("name") != name or prepared.get("sequence") != sequence:
        raise HTTPException(409, "The selected form decision changed. Review it again.")
    try:
        receipt = native.form_submission_decision_receipt(request, Response(), name, sequence)
    except HTTPException as exc:
        if exc.status_code in {404, 503}:
            return None  # Still held, or no exact signed receipt can be proved.
        raise
    if (receipt.get("sequence") != sequence
            or receipt.get("binding_revision") != prepared.get("expected_generation")
            or receipt.get("fields_sha256") != prepared.get("expected_fields_sha256")
            or receipt.get("decision_sha256") != prepared.get("expected_decision_sha256")
            or receipt.get("do_not_run") is not True):
        raise HTTPException(409, "The form decision differs from the reviewed record. Open Automations.")
    return Outcome("replayed", "The signed Do not run decision is complete. The received answers remain saved.",
                   {"form": name, "submission": sequence, "decision": "Do not run"})


def entries():
    return (Adapter("learning.form_decision_recovery", "Complete this held form decision", "learning",
                    "/automations", ("/automations",), EmptyInput,
                    snapshot, prepare, execute, recover,
                    aliases=("complete held form decision", "recover form decision")),)
