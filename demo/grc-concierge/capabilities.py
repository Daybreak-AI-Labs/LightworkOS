"""Runtime capability matrix for the standalone GRC Concierge build."""
from __future__ import annotations

import importlib.util
import os


def _can_import(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


# ``GRC_STANDALONE=1`` must be a hard isolation switch.  In particular, do not
# even probe a nested ``maverick`` module in that mode: ``find_spec`` is allowed
# to import a parent package while resolving it.
FORCED_STANDALONE = os.environ.get("GRC_STANDALONE") == "1"
CORE_ANALYSIS = False if FORCED_STANDALONE else _can_import("maverick.assessment")

# Compatibility names used by the backend.  They select the analysis engine,
# not the authority boundary: this reduced web SKU always has unsigned local
# persistence and never becomes the integrated governed Lightwork product.
STANDALONE = not CORE_ANALYSIS
PLATFORM_ENGINE = CORE_ANALYSIS

CAPS = {
    "starter_catalog": True,
    "questionnaire_scoring": True,
    "evidence_quotes": True,
    "guided_browser_intake": True,
    "local_risk_register": True,
    "local_poam": True,
    "mock_grc_handoff": True,
    "mock_tenant_review": True,
    "vendor_carry_forward": True,
    "workflow_speed_metrics": True,
    "platform_assessment_adapter": PLATFORM_ENGINE,
    "expanded_security_catalog": PLATFORM_ENGINE,
    "full_framework_catalog": False,
    "cross_framework_crosswalk": False,
    "connected_evidence_sources": False,
    "signed_audit": False,
    "governed_approval": False,
    "program_workspace": False,
    "cross_run_learning": False,
}

CAPABILITY_LABELS = {
    "starter_catalog": "SOC 2, ISO 27001, and NIST CSF starter catalog",
    "questionnaire_scoring": "Deterministic control questionnaire scoring",
    "evidence_quotes": "Evidence verdicts with matched quotes",
    "guided_browser_intake": "Accessible guided questionnaire and filing forms",
    "local_risk_register": "Local risk register",
    "local_poam": "Local plan of action and milestones",
    "mock_grc_handoff": "Local-only mock GRC review handoff receipts",
    "mock_tenant_review": "Local mock tenant queue with human approve or reject decisions",
    "vendor_carry_forward": "Local vendor posture carry-forward with field provenance",
    "workflow_speed_metrics": "Measured local handoff and review elapsed time",
    "platform_assessment_adapter": "Lightwork questionnaire and scoring engine adapter",
    "expanded_security_catalog": "Expanded Lightwork security questionnaire catalog",
    "full_framework_catalog": "Full global framework catalog",
    "cross_framework_crosswalk": "Governed cross-framework crosswalk",
    "connected_evidence_sources": "Enterprise evidence connectors",
    "signed_audit": "Ed25519 tamper-evident audit chain",
    "governed_approval": "Governed human approval queue",
    "program_workspace": "Security and GRC program workspace",
    "cross_run_learning": "Cross-run learning and memory",
}


def caps_summary() -> dict:
    """Describe engine selection separately from the product trust boundary."""
    mode = (
        "Standalone GRC Concierge (vendored analysis)"
        if STANDALONE
        else "Standalone GRC Concierge (Lightwork core analysis)"
    )
    return {
        "standalone": True,
        "forced_standalone": FORCED_STANDALONE,
        "vendored_analysis": STANDALONE,
        "core_analysis": CORE_ANALYSIS,
        "analysis_backend": "vendored" if STANDALONE else "lightwork-core",
        "integrated_governance": False,
        "authority": "unsigned-local",
        "mode": mode,
        "local_authority": True,
        "active": [
            CAPABILITY_LABELS[key] for key, enabled in CAPS.items() if enabled
        ],
        "gated": [
            CAPABILITY_LABELS[key] for key, enabled in CAPS.items() if not enabled
        ],
    }
