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
        return _from_catalogue(result, reservation_catalogue_for_work_item(f"goal:{goal_id}"))
    except (ValueError, OSError, RuntimeError):
        return {**result, "state": "unavailable", "receipts": [], "basis": "unavailable", "sha256": None}


def _from_catalogue(result, catalogue):
    rows = [receipt_row(row) for row in catalogue.receipts]
    state = "available" if rows else "no_linked_receipts"
    return {**result, "state": state, "receipts": rows,
            "basis": ", ".join(sorted({row["basis"] for row in rows})) or "unavailable",
            "sha256": hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def for_goals(goal_ids):
    """:func:`for_goal` for each id, reading the spend ledger once where it can.

    Lists of tasks (Spend, the cost export) would otherwise verify the sealed
    ledger once per row. Each value equals what :func:`for_goal` returns for
    that id; the caller authorizes every id first.
    """
    from .provider_cost_cap import reservation_catalogues_for_work_items
    base = {"scope": "Whole task across attempts and provider periods; do not add to episode totals",
            "excluded": EXCLUDED, "invoice_verified": False}
    unavailable = {**base, "state": "unavailable", "receipts": [], "basis": "unavailable", "sha256": None}
    ids = list(dict.fromkeys(goal_ids))
    linked = [goal_id for goal_id in ids if goal_id is not None]
    try:
        catalogues = reservation_catalogues_for_work_items([f"goal:{goal_id}" for goal_id in linked])
    except (ValueError, OSError, RuntimeError):
        catalogues = {}
    out = {}
    for goal_id in ids:
        if goal_id is None:
            out[goal_id] = {**base, "state": "unlinked", "receipts": [], "basis": "unavailable", "sha256": None}
            continue
        catalogue = catalogues.get(f"goal:{goal_id}")
        try:
            if catalogue is None or isinstance(catalogue, Exception):
                raise RuntimeError("provider accounting unavailable")
            out[goal_id] = _from_catalogue(base, catalogue)
        except (ValueError, OSError, RuntimeError):
            out[goal_id] = dict(unavailable)
    return out


def with_sources(episodes, *, chunk: int = 100):
    """Yield ``(episode, for_goal value)``, reading the ledger once per chunk so
    a streamed export stays streamed (bounded memory) without a read per row."""
    batch = []
    for episode in episodes:
        batch.append(episode)
        if len(batch) >= chunk:
            sources = for_goals([row.goal_id for row in batch])
            yield from ((row, sources[row.goal_id]) for row in batch)
            batch = []
    if batch:
        sources = for_goals([row.goal_id for row in batch])
        yield from ((row, sources[row.goal_id]) for row in batch)


def export_fields(episode, source=None):
    """``source`` is this episode's :func:`for_goals` value when the caller read a batch."""
    source = for_goal(episode.goal_id) if source is None else source
    return [runtime_basis(episode.cost_dollars), "USD", source["state"], source["basis"],
            source["sha256"] or "", json.dumps(source["receipts"], sort_keys=True, separators=(",", ":")),
            source["scope"], EXCLUDED]


EXPORT_HEADERS = ["runtime_cost_basis", "currency", "provider_evidence_state", "provider_cost_bases",
                  "provider_evidence_sha256", "provider_receipts_json", "provider_receipt_scope", "excluded_cost_categories"]
