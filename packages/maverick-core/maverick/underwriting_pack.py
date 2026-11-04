"""The AI-insurance underwriting evidence pack: governance as premium input.

Underwriters of AI performance and liability cover state that ISO 42001 /
NIST AI RMF governance evidence plus third-party validation shortens
underwriting and affects premium. This module packages what the platform
already proves into the shape an underwriter reads: a bounded summary of
governance posture — evidence coverage by kind and freshness, incident and
Art. 73 reporting discipline, drift and red-team and explainability
coverage, EU AI Act register completeness, literacy posture — wrapped
AROUND the signed, externally verifiable assurance pack whose Ed25519
attestation carries the tamper evidence. The summary is derived data bound
to the inner pack by digest; the inner pack is the record of proof.

Read-side composition with no knob of its own: it rides the enabled source
modules and reports a section absent when its module is off. Decision
support for the operator's own submission — never an insurance application,
a risk rating, or a representation to any insurer.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from . import model_risk_assurance as mra

PACK_SCHEMA = "lightwork.underwriting-pack.v1"
NON_CERTIFICATION_NOTICE = (
    "A governed evidence summary for the operator's own insurance "
    "submission; not an insurance application, a risk rating, or a "
    "representation made to any insurer."
)


class UnderwritingPackError(RuntimeError):
    """Base failure for the underwriting evidence pack."""


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _evidence_posture(evidence: list[dict[str, Any]], now: float) -> dict[str, Any]:
    by_kind: dict[str, dict[str, int]] = {}
    for row in evidence:
        kind = str(row.get("evidence_kind") or "unknown")
        bucket = by_kind.setdefault(
            kind, {"total": 0, "passed": 0, "valid_now": 0},
        )
        bucket["total"] += 1
        if row.get("result") == "passed":
            bucket["passed"] += 1
        valid_until = row.get("valid_until")
        try:
            if valid_until is not None and float(valid_until) > now:
                bucket["valid_now"] += 1
        except (TypeError, ValueError):
            pass
    return dict(sorted(by_kind.items()))


def _conformity_posture() -> dict[str, Any]:
    try:
        from . import eu_conformity as euc

        if not euc.enabled():
            return {"enabled": False}
        frias = euc.list_frias()
        routes = euc.list_assessment_routes()
        return {
            "enabled": True,
            "fria": {
                "total": len(frias),
                "completed": sum(
                    1 for row in frias if row.get("status") == "completed"
                ),
                "outdated": sum(
                    1 for row in frias if row.get("status") == "outdated"
                ),
            },
            "assessment_routes": {
                "total": len(routes),
                "reassessment_required": sum(
                    1
                    for row in routes
                    if row.get("status") == "reassessment_required"
                ),
            },
            "registrations": len(euc.list_registrations()),
            "monitoring_plans": len(euc.list_pmm_plans()),
            "gpai_registers": len(euc.list_gpai_registers()),
        }
    except Exception:
        return {"enabled": False, "error": "unavailable"}


def _incident_posture(now: float) -> dict[str, Any]:
    from .governance_alerts import incident_reporting_posture

    section = incident_reporting_posture(now)
    return {
        "enabled": section["enabled"], "complete": section["complete"],
        "declarations": section["record_count"], "overdue": section["overdue_count"],
        "withdrawn": section["withdrawn"], "reported": section["reported"],
        "unavailable_registers": section["unavailable_registers"],
        "registers": section["registers"], "notice": section["notice"],
    }


def _literacy_posture(now: float) -> dict[str, Any]:
    try:
        from . import ai_literacy

        if not ai_literacy.enabled():
            return {"enabled": False}
        gaps = ai_literacy.literacy_gaps(now=now)
        plane_status = ai_literacy.literacy_plane_status(now=now)
        counts = gaps.get("counts") or {}
        return {
            "enabled": True,
            "people_tracked": gaps.get("person_count"),
            "current": counts.get("current"),
            "expired": counts.get("expired"),
            "missing": counts.get("missing"),
            "data_plane": "role_compatibility",
            "authoritative_for_compliance": False,
            "authoritative_plane": plane_status.get("authoritative_plane"),
            "canonical": plane_status.get("canonical"),
            "reconciliation_required": plane_status.get(
                "reconciliation_required"
            ),
            "reconciliation_notice": plane_status.get("notice"),
        }
    except Exception:
        return {"enabled": False, "error": "unavailable"}


def export_underwriting_pack(
    *,
    actor: str,
    asset_id: str | None = None,
) -> dict[str, Any]:
    """One underwriter-oriented pack around the signed assurance pack.

    Requires model-risk assurance (the record of proof); every other section
    degrades to ``enabled: false`` when its module is off.
    """

    operator = str(actor or "").strip()
    if not operator or len(operator) > 256:
        raise ValueError("actor must be a short identity")
    if not mra.enabled():
        raise UnderwritingPackError(
            "the underwriting pack requires enabled model-risk assurance"
        )
    inner = mra.render_assurance_pack(actor=operator, asset_id=asset_id)
    now = time.time()
    summary = {
        "generated_at": now,
        "generated_by": operator,
        "asset_filter": asset_id or "",
        "inventory_count": len(inner.get("inventory") or []),
        "evidence_by_kind": _evidence_posture(
            list(inner.get("evidence") or []), now,
        ),
        "open_findings": len(inner.get("findings") or []),
        "human_decisions": len(inner.get("human_decisions") or []),
        "eu_conformity": _conformity_posture(),
        "serious_incidents": _incident_posture(now),
        "ai_literacy": _literacy_posture(now),
        "framework_metadata": inner.get("framework_metadata"),
        "assurance_pack_sha256": inner.get("pack_sha256"),
        "verification_note": (
            "Integrity rests on the embedded assurance pack (rendered by "
            "model_risk_assurance.render_assurance_pack): verify it with "
            "model_risk_assurance.verify_assurance_pack against your own key "
            "registry. This summary is derived data bound to that pack by "
            "digest."
        ),
        "notice": NON_CERTIFICATION_NOTICE,
    }
    return {
        "schema": PACK_SCHEMA,
        "summary": summary,
        "summary_sha256": _sha256(summary),
        "assurance_pack": inner,
        "legal_certification": False,
    }


__all__ = [
    "NON_CERTIFICATION_NOTICE",
    "PACK_SCHEMA",
    "UnderwritingPackError",
    "export_underwriting_pack",
]
