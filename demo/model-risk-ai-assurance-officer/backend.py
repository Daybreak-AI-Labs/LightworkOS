"""Authority-preserving backend seam for the Model Risk Officer standalone."""

from __future__ import annotations

import assurance_engine as local
from capabilities import CAPABILITY_LABELS, CAPS, FORCED_STANDALONE, STANDALONE
from capabilities import caps_summary as _caps_summary

STORE = local.LocalStore()


def _binding(implementation: str, authority: str, active: bool = True) -> dict:
    return {"implementation": implementation, "authority": authority, "active": active}


def _integrated_only(path: str) -> dict:
    return _binding(
        f"Not available in this standalone app; use integrated Lightwork {path}",
        "integrated-lightwork-only",
        False,
    )


CAPABILITY_BINDINGS = {
    "local_ai_inventory": _binding(
        "assurance_engine.analyze_snapshot normalized inventory", "unsigned-local"
    ),
    "deterministic_operational_risk": _binding(
        "assurance_engine deterministic triage rules", "advisory-analysis-only"
    ),
    "advisory_framework_mapping": _binding(
        "assurance_engine.FRAMEWORK_CATALOG and finding references",
        "versioned-advisory-metadata",
    ),
    "evaluation_freshness": _binding(
        "assurance_engine freshness and post-change invalidation rules",
        "advisory-analysis-only",
    ),
    "red_team_evidence": _binding(
        "assurance_engine red-team coverage rule", "advisory-analysis-only"
    ),
    "change_lineage": _binding(
        "assurance_engine declared lineage and approved-change rules",
        "unsigned-local",
    ),
    "drift_incident_risk": _binding(
        "assurance_engine drift and incident rules", "advisory-analysis-only"
    ),
    "third_party_risk": _binding(
        "assurance_engine provider assurance and exit-readiness rules",
        "advisory-analysis-only",
    ),
    "human_assurance_review": _binding(
        "assurance_engine.review_assessment", "unsigned-local-human-attestation"
    ),
    "human_risk_acceptance": _binding(
        "assurance_engine.create_risk_acceptance",
        "unsigned-time-bounded-local-human-attestation",
    ),
    "dgm_readiness_report": _binding(
        "assurance_engine.build_dgm_readiness_report",
        "report-only-no-promotion-authority",
    ),
    "local_cas_store": _binding("assurance_engine.LocalStore", "unsigned-local-revision-cas"),
    "automatic_legal_classification": _binding(
        "Deliberately unsupported; legal applicability defaults to undetermined",
        "prohibited",
        False,
    ),
    "compliance_certification": _binding(
        "Deliberately unsupported; framework mappings are advisory",
        "prohibited",
        False,
    ),
    "dgm_promotion_execution": _binding(
        "Deliberately unsupported; readiness reports never execute",
        "prohibited",
        False,
    ),
    "autonomous_external_effects": _binding(
        "No network or provider effect implementation is present", "prohibited", False
    ),
    "live_discovery": _integrated_only("AI inventory and connector discovery"),
    "signed_audit": _integrated_only("signed audit authority"),
    "continuous_evidence_graph": _integrated_only("evidence graph"),
    "governed_platform_authority": _integrated_only("model-risk governance"),
}


def _validate_bindings() -> None:
    if set(CAPABILITY_BINDINGS) != set(CAPS):
        raise RuntimeError("Model Risk Officer capability binding drift")
    for capability, enabled in CAPS.items():
        binding = CAPABILITY_BINDINGS[capability]
        if binding.get("active") is not enabled:
            raise RuntimeError(f"Model Risk Officer capability state drift: {capability}")
        if not binding.get("implementation") or not binding.get("authority"):
            raise RuntimeError(f"Model Risk Officer capability binding is incomplete: {capability}")


_validate_bindings()


def caps_summary() -> dict:
    summary = _caps_summary()
    summary["capabilities"] = [
        {
            "id": capability,
            "label": CAPABILITY_LABELS[capability],
            **CAPABILITY_BINDINGS[capability],
        }
        for capability in CAPS
    ]
    summary["platform_authority_used"] = False
    summary["framework_catalog"] = [dict(row) for row in local.FRAMEWORK_CATALOG]
    return summary


def current_revision() -> int:
    return STORE.current_revision()


def list_records(kind: str | None = None) -> list[dict]:
    return STORE.list_records(kind)


def _record(record_id: str, kind: str, label: str) -> dict:
    if not isinstance(record_id, str) or not record_id or len(record_id) > 160:
        raise ValueError(f"{label} id must contain 1 to 160 characters")
    value = STORE.get_record(record_id)
    if value is None:
        raise LookupError(f"stored {label} not found")
    if value.get("type") != kind:
        raise ValueError(f"record is not a {label}")
    return value


def create_assessment(
    snapshot: dict,
    expected_revision: int,
    *,
    now: str | None = None,
    freshness_days: int = local.DEFAULT_FRESHNESS_DAYS,
) -> dict:
    report = local.analyze_snapshot(snapshot, now=now, freshness_days=freshness_days)
    return STORE.save(report, expected_revision)


def review_assessment(
    assessment_id,
    decision,
    reviewer,
    rationale,
    decided_at,
    expected_revision: int,
) -> dict:
    assessment = _record(assessment_id, "assurance_assessment", "assurance assessment")
    reviewed = local.review_assessment(assessment, decision, reviewer, rationale, decided_at)
    return STORE.replace(assessment_id, reviewed, expected_revision)


def create_risk_acceptance(
    assessment_id,
    finding_id,
    decision,
    reviewer,
    rationale,
    expires_at,
    decided_at,
    expected_revision: int,
) -> dict:
    assessment = _record(assessment_id, "assurance_assessment", "assurance assessment")
    record = local.create_risk_acceptance(
        assessment,
        finding_id,
        decision,
        reviewer,
        rationale,
        expires_at,
        decided_at,
    )
    return STORE.save(record, expected_revision)


def create_dgm_readiness_report(
    assessment_id,
    target_asset_ref,
    candidate_id,
    candidate_version,
    requested_by,
    now,
    expected_revision: int,
) -> dict:
    assessment = _record(assessment_id, "assurance_assessment", "assurance assessment")
    acceptances = [
        row
        for row in STORE.list_records("risk_acceptance")
        if row.get("assessment_id") == assessment_id
    ]
    report = local.build_dgm_readiness_report(
        assessment,
        acceptances,
        target_asset_ref,
        candidate_id,
        candidate_version,
        requested_by,
        now,
    )
    return STORE.save(report, expected_revision)


__all__ = [
    "CAPABILITY_BINDINGS",
    "CAPS",
    "FORCED_STANDALONE",
    "STANDALONE",
    "caps_summary",
    "create_assessment",
    "create_dgm_readiness_report",
    "create_risk_acceptance",
    "current_revision",
    "list_records",
    "review_assessment",
]
