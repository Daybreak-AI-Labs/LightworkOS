"""One bounded needs-attention digest across the governance registers.

Aggregates the deadline- and staleness-bearing state the compliance team
must act on: Art. 73 serious-incident clocks (overdue and due soon), Art. 4
literacy gaps (missing, expired, expiring soon), Art. 27(2) outdated FRIAs,
and Art. 43(4) routes flagged for reassessment. Pure read-side aggregation:
it carries no configuration knob of its own — each section rides its source
module's opt-in knob and reports ``enabled: false`` when that module is off
or unavailable. Nothing here transmits anything anywhere; delivery to chat
or e-mail stays with the operator's own scheduler around the CLI.
"""
from __future__ import annotations

import time
from typing import Any

_DAY = 86_400.0
_MAX_IDS = 50


def _declaration_inventory(now: float) -> dict[str, Any]:
    try:
        from . import ai_incident_reporting as air
        if not air.enabled():
            return {"enabled": False, "rows": []}
        rows = air.list_declarations(now=now, limit=5_000)
        return {"enabled": True, "rows": [{
            "id": str(row["id"]), "due_at": float(row["report_due_at"]),
            "running": row["status"] == "declared",
            "reported": row["status"] in {"initial_reported", "complete_reported"},
            "withdrawn": row["status"] == "withdrawn",
        } for row in rows]}
    except Exception:
        return {"enabled": True, "error": "unavailable", "rows": []}


def _article_inventory(now: float) -> dict[str, Any]:
    try:
        from . import eu_ai_incidents as article
        if not article.enabled():
            return {"enabled": False, "rows": []}
        rows = article.reporting_inventory(now=now)
        return {"enabled": True, "rows": [{
            "id": str(row["incident_id"]),
            "due_at": float(row["clock"]["outer_limit_at"]),
            "running": row["status"] != "not_reportable"
            and row["clock"]["first_submission_at"] is None,
            "reported": row["clock"]["first_submission_at"] is not None,
            "withdrawn": False,
        } for row in rows]}
    except Exception:
        return {"enabled": True, "error": "unavailable", "rows": []}


def incident_reporting_posture(now: float, due_soon_seconds: float = 2 * _DAY) -> dict[str, Any]:
    """Current complete reporting clocks from both native registers; no filing claim."""
    registers = {"declarations": _declaration_inventory(now),
                 "article_73": _article_inventory(now)}
    unavailable = [name for name, value in registers.items() if value.get("error")]
    rows = sorted((row for value in registers.values() for row in value["rows"]),
                  key=lambda row: (row["due_at"], row["id"]))
    overdue = [row["id"] for row in rows if row["running"] and row["due_at"] < now]
    due_soon = [row["id"] for row in rows
                if row["running"] and 0 <= row["due_at"] - now <= due_soon_seconds]
    return {
        "enabled": any(value["enabled"] for value in registers.values()),
        "complete": not unavailable,
        "overdue": overdue[:_MAX_IDS],
        "due_soon": due_soon[:_MAX_IDS],
        "overdue_count": len(overdue), "due_soon_count": len(due_soon),
        "listed_ids_truncated": len(overdue) > _MAX_IDS or len(due_soon) > _MAX_IDS,
        "record_count": len(rows),
        "reported": sum(row["reported"] for row in rows),
        "withdrawn": sum(row["withdrawn"] for row in rows),
        "unavailable_registers": unavailable,
        "registers": {name: {"enabled": value["enabled"],
                              "available": not bool(value.get("error")),
                              "record_count": len(value["rows"])}
                      for name, value in registers.items()},
        "notice": "Counts cover records in two reporting registers; the same incident may appear in both. Recorded filings are human assertions, not proof of authority receipt.",
        "citation": "Art. 73",
    }


def _incident_section(now: float, due_soon_seconds: float) -> tuple[dict[str, Any], int]:
    section = incident_reporting_posture(now, due_soon_seconds)
    return section, section["overdue_count"] + section["due_soon_count"]


def _literacy_section(now: float, expiring_days: int) -> tuple[dict[str, Any], int]:
    try:
        from . import ai_literacy

        if not ai_literacy.enabled():
            return {"enabled": False}, 0
        gaps = ai_literacy.literacy_gaps(now=now)
        plane_status = ai_literacy.literacy_plane_status(now=now)
    except Exception:
        return {"enabled": False, "error": "unavailable"}, 0
    horizon = now + expiring_days * _DAY
    expiring = 0
    for person in gaps.get("persons") or []:
        for state in person.get("trainings") or []:
            valid_until = state.get("valid_until")
            if (
                state.get("status") == "current"
                and valid_until is not None
                and float(valid_until) <= horizon
            ):
                expiring += 1
    counts = gaps.get("counts") or {}
    missing = int(counts.get("missing") or 0)
    expired = int(counts.get("expired") or 0)
    canonical = plane_status.get("canonical") or {}
    canonical_summary = canonical.get("summary") or {}
    canonical_gaps = int(canonical_summary.get("coverage_gaps") or 0)
    reconciliation_required = bool(plane_status.get("reconciliation_required"))
    section = {
        "enabled": True,
        "missing": missing,
        "expired": expired,
        "expiring_soon": expiring,
        "canonical_coverage_gaps": canonical_gaps,
        "canonical_available": canonical.get("available") is True,
        "data_plane": "role_compatibility",
        "authoritative_for_compliance": False,
        "unreconciled_ai_literacy_data": reconciliation_required,
        "reconciliation_notice": plane_status.get("notice"),
        "citation": "Art. 4",
    }
    return (
        section,
        missing + expired + expiring + canonical_gaps
        + (1 if reconciliation_required else 0),
    )


def _conformity_section(now: float) -> tuple[dict[str, Any], int]:
    del now
    try:
        from . import eu_conformity as euc

        if not euc.enabled():
            return {"enabled": False}, 0
        outdated = [
            str(row.get("id")) for row in euc.list_frias(status="outdated")
        ]
        reassess = [
            str(row.get("asset_id"))
            for row in euc.list_assessment_routes(status="reassessment_required")
        ]
    except Exception:
        return {"enabled": False, "error": "unavailable"}, 0
    section = {
        "enabled": True,
        "outdated_frias": outdated[:_MAX_IDS],
        "reassessment_required": reassess[:_MAX_IDS],
        "citations": ["Art. 27(2)", "Art. 43(4)"],
    }
    return section, len(outdated) + len(reassess)


def _vendor_section(now: float, renewal_days: int) -> tuple[dict[str, Any], int]:
    try:
        from . import vendor_management as vm

        if not vm.enabled():
            return {"enabled": False}, 0
        renewals = vm.contract_renewals(now=now, due_soon_days=renewal_days)
    except Exception:
        return {"enabled": False, "error": "unavailable"}, 0
    overdue = [
        f"{entry['vendor_id']}:{entry['kind']}"
        for entry in renewals["overdue"]
    ]
    due_soon = [
        f"{entry['vendor_id']}:{entry['kind']}"
        for entry in renewals["due_soon"]
    ]
    section = {
        "enabled": True,
        "contracts_overdue": overdue[:_MAX_IDS],
        "contracts_due_soon": due_soon[:_MAX_IDS],
    }
    return section, len(overdue) + len(due_soon)


def _data_map_section(now: float) -> tuple[dict[str, Any], int]:
    del now
    try:
        from . import data_map as dm

        if not dm.enabled():
            return {"enabled": False}, 0
        posture = dm.data_map_posture()
    except Exception:
        return {"enabled": False, "error": "unavailable"}, 0
    unlinked = int(posture.get("unlinked_flagged_assets") or 0)
    section = {
        "enabled": True,
        "unlinked_flagged_assets": unlinked,
        "special_category_assets": int(
            posture.get("special_category_assets") or 0
        ),
    }
    return section, unlinked


def digest(
    *,
    now: float | None = None,
    due_soon_seconds: float = 2 * _DAY,
    expiring_days: int = 30,
) -> dict[str, Any]:
    """The needs-attention digest; ``attention_count`` totals every item."""

    if now is not None and (isinstance(now, bool) or not isinstance(now, (int, float))):
        raise ValueError("now must be a numeric timestamp")
    if (
        isinstance(due_soon_seconds, bool)
        or not isinstance(due_soon_seconds, (int, float))
        or not 0 < float(due_soon_seconds) <= 30 * _DAY
    ):
        raise ValueError("due_soon_seconds must be between 1 second and 30 days")
    if (
        isinstance(expiring_days, bool)
        or not isinstance(expiring_days, int)
        or not 1 <= expiring_days <= 365
    ):
        raise ValueError("expiring_days must be between 1 and 365")
    current = time.time() if now is None else float(now)
    incidents, incident_count = _incident_section(current, float(due_soon_seconds))
    literacy, literacy_count = _literacy_section(current, expiring_days)
    conformity, conformity_count = _conformity_section(current)
    vendors, vendor_count = _vendor_section(current, expiring_days)
    estate, estate_count = _data_map_section(current)
    return {
        "generated_at": current,
        "attention_count": (
            incident_count + literacy_count + conformity_count
            + vendor_count + estate_count
        ),
        "sections": {
            "serious_incidents": incidents,
            "ai_literacy": literacy,
            "eu_conformity": conformity,
            "vendors": vendors,
            "data_map": estate,
        },
    }


__all__ = ["digest", "incident_reporting_posture"]
