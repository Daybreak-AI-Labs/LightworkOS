"""Capability and authority matrix for the Model Risk Officer standalone."""

from __future__ import annotations

import os

FORCED_STANDALONE = os.environ.get("MODEL_RISK_OFFICER_STANDALONE") == "1"
STANDALONE = True
VENDORED_ANALYSIS = True

CAPS = {
    "local_ai_inventory": True,
    "deterministic_operational_risk": True,
    "advisory_framework_mapping": True,
    "evaluation_freshness": True,
    "red_team_evidence": True,
    "change_lineage": True,
    "drift_incident_risk": True,
    "third_party_risk": True,
    "human_assurance_review": True,
    "human_risk_acceptance": True,
    "dgm_readiness_report": True,
    "local_cas_store": True,
    "automatic_legal_classification": False,
    "compliance_certification": False,
    "dgm_promotion_execution": False,
    "autonomous_external_effects": False,
    "live_discovery": False,
    "signed_audit": False,
    "continuous_evidence_graph": False,
    "governed_platform_authority": False,
}

CAPABILITY_LABELS = {
    "local_ai_inventory": "Local model, agent, tool, dataset, and provider inventory",
    "deterministic_operational_risk": "Deterministic operational risk classification and gap findings",
    "advisory_framework_mapping": "Versioned advisory NIST AI RMF, ISO/IEC 42001, and EU AI Act metadata",
    "evaluation_freshness": "Evaluation evidence freshness and change invalidation",
    "red_team_evidence": "Red-team evidence coverage",
    "change_lineage": "Model, agent, tool, dataset, and provider change lineage",
    "drift_incident_risk": "Drift and incident posture analysis",
    "third_party_risk": "Third-party assurance and exit-readiness analysis",
    "human_assurance_review": "Local human assurance review decisions",
    "human_risk_acceptance": "Time-bounded local human risk acceptances",
    "dgm_readiness_report": "Local DGM promotion-readiness report (report only)",
    "local_cas_store": "Private unsigned local JSON store with revision CAS",
    "automatic_legal_classification": "Automatic legal role, scope, or risk classification",
    "compliance_certification": "NIST, ISO, EU AI Act, or other compliance certification",
    "dgm_promotion_execution": "DGM candidate promotion, deployment, or rollback execution",
    "autonomous_external_effects": "Autonomous network, provider, ticketing, or control-plane effects",
    "live_discovery": "Configured live estate and evidence discovery",
    "signed_audit": "Signed tamper-evident audit",
    "continuous_evidence_graph": "Continuous governed evidence graph",
    "governed_platform_authority": "Tenant-scoped governed Lightwork authority",
}


def caps_summary() -> dict:
    """Return the executable capability and platform boundary."""
    return {
        "standalone": True,
        "forced_standalone": FORCED_STANDALONE,
        "vendored_analysis": VENDORED_ANALYSIS,
        "analysis_backend": "vendored-deterministic-rules",
        "integrated_governance": False,
        "authority": "unsigned-local-advisory-only",
        "legal_applicability_default": "undetermined",
        "certification": False,
        "external_effects": False,
        "dgm_execution": False,
        "mode": "Model Risk & AI Assurance Officer (standalone vendored analysis)",
        "active": [CAPABILITY_LABELS[key] for key, enabled in CAPS.items() if enabled],
        "gated": [CAPABILITY_LABELS[key] for key, enabled in CAPS.items() if not enabled],
    }


__all__ = [
    "CAPABILITY_LABELS",
    "CAPS",
    "FORCED_STANDALONE",
    "STANDALONE",
    "VENDORED_ANALYSIS",
    "caps_summary",
]
