"""Capability matrix for the environment threat-hunter SKU."""
from __future__ import annotations

import importlib.util
import os


def _can_import(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


FORCED_STANDALONE = os.environ.get("ENV_HUNTER_STANDALONE") == "1"
CORE_ANALYSIS = False if FORCED_STANDALONE else _can_import("maverick.env_hunt")
STANDALONE = not CORE_ANALYSIS
PLATFORM_ENGINE = CORE_ANALYSIS
CAPS = {
    "generic_ingestion": True,
    "sigma_import": True,
    "deterministic_detection": True,
    "derived_findings_only": True,
    "response_proposals": True,
    "proposal_only": True,
    "platform_detector_adapter": PLATFORM_ENGINE,
    "managed_connectors": False,
    "governed_approval": False,
    "response_execution": False,
    "signed_audit": False,
    "cross_run_learning": False,
    "soc_workspace": False,
}
CAPABILITY_LABELS = {
    "generic_ingestion": "JSON, syslog, CloudTrail, and Kubernetes ingestion",
    "sigma_import": "Customer Sigma rule import (safe match subset)",
    "deterministic_detection": "Deterministic detection and correlation",
    "derived_findings_only": "Derived records only; raw telemetry stays ephemeral",
    "response_proposals": "Human-readable response proposals",
    "proposal_only": "Proposal-only response boundary; no standalone execution endpoint",
    "platform_detector_adapter": "Lightwork core detector library adapter",
    "managed_connectors": "Managed SIEM, EDR, cloud, identity, and Kubernetes connectors",
    "governed_approval": "Governed human approval and response receipts",
    "response_execution": "Proposal-bound governed response execution",
    "signed_audit": "Ed25519 tamper-evident audit chain",
    "cross_run_learning": "Cross-run environment learning",
    "soc_workspace": "Governed SOC workspace",
}


def caps_summary() -> dict:
    mode = (
        "Standalone Environment Hunter (vendored analysis)"
        if STANDALONE
        else "Standalone Environment Hunter (Lightwork core analysis)"
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
        "active": [
            CAPABILITY_LABELS[key] for key, enabled in CAPS.items() if enabled
        ],
        "gated": [
            CAPABILITY_LABELS[key] for key, enabled in CAPS.items() if not enabled
        ],
        "response_mode": "proposal-only",
    }
