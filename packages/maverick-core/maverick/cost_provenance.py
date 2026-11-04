"""Explicit provenance for runtime amounts and exact work-item provider receipts.

Episode dollars never become invoice verified because a current price setting or
another receipt happens to match. Provider evidence belongs to the whole work
item, not to an episode unless that association was recorded at admission.
"""
from __future__ import annotations

import hashlib
import json
import math

EXCLUDED = "Platform subscription, external-tool fees, taxes, credits and provider-invoice adjustments unless separately evidenced."


def amount(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        value = float(value)
        return value if math.isfinite(value) and value >= 0 else None
    except (TypeError, ValueError, OverflowError):
        return None


def runtime_basis(value):
    return ("Unknown runtime cost; not free" if amount(value) is None else
            "Recorded runtime amount; may include pricing estimates; not provider-invoice verified")


def receipt_row(receipt):
    evidence = receipt.pricing_evidence or {}
    reconciliation = getattr(receipt, "reconciliation", None)
    if receipt.state != "settled":
        basis = "unknown" if receipt.state == "unknown" else "ceiling"
    elif reconciliation:
        basis = "reconciled"
    elif receipt.cost_basis == "observed" and evidence.get("verified") is True:
        basis = "recorded"
    else:
        basis = "estimated"
    return {"reference": receipt.reference, "provider": receipt.provider, "period": receipt.period,
            "state": receipt.state, "projected": amount(receipt.projected), "actual": amount(receipt.actual),
            "currency": receipt.currency, "basis": basis, "pricing_basis": evidence.get("pricing_basis"),
            "rate_card_version": evidence.get("rate_card_version"), "pricing_evidence_id": evidence.get("evidence_id"),
            "rate_verified": evidence.get("verified") is True, "reconciliation_review": reconciliation,
            "invoice_verified": False}


def for_goal(goal_id):
    """Caller authorizes this exact goal before passing its ID."""
    from .provider_cost_cap import reservation_catalogue_for_work_item
    result = {"scope": "Whole task across attempts and provider periods; do not add to episode totals",
              "excluded": EXCLUDED, "invoice_verified": False}
    if goal_id is None:
        return {**result, "state": "unlinked", "receipts": [], "basis": "unavailable", "sha256": None}
    try:
        catalogue = reservation_catalogue_for_work_item(f"goal:{goal_id}")
        rows = [receipt_row(row) for row in catalogue.receipts]
        state = "available" if rows else "no_linked_receipts"
        return {**result, "state": state, "receipts": rows,
                "basis": ", ".join(sorted({row["basis"] for row in rows})) or "unavailable",
                "sha256": hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    except (ValueError, OSError, RuntimeError):
        return {**result, "state": "unavailable", "receipts": [], "basis": "unavailable", "sha256": None}


def export_fields(episode):
    source = for_goal(episode.goal_id)
    return [runtime_basis(episode.cost_dollars), "USD", source["state"], source["basis"],
            source["sha256"] or "", json.dumps(source["receipts"], sort_keys=True, separators=(",", ":")),
            source["scope"], EXCLUDED]


EXPORT_HEADERS = ["runtime_cost_basis", "currency", "provider_evidence_state", "provider_cost_bases",
                  "provider_evidence_sha256", "provider_receipts_json", "provider_receipt_scope", "excluded_cost_categories"]
