"""Capability matrix for the platform threat-hunter SKU."""
from __future__ import annotations

import importlib.util
import os


def _can_import(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


FORCED_STANDALONE = os.environ.get("PLATFORM_HUNTER_STANDALONE") == "1"
CORE_ANALYSIS = (
    False if FORCED_STANDALONE else _can_import("maverick.platform_hunt")
)
STANDALONE = not CORE_ANALYSIS
PLATFORM_ENGINE = CORE_ANALYSIS
CAPS = {
    "deterministic_detection": True,
    "local_investigations": True,
    "derived_findings_only": True,
    "platform_detector_adapter": PLATFORM_ENGINE,
    "signed_chain_input": False,
    "continuous_monitor": False,
    "governed_response": False,
    "fleet_baselines": False,
    "signed_audit": False,
    "program_workspace": False,
}
CAPABILITY_LABELS = {
    "deterministic_detection": "Deterministic platform-event detections",
    "local_investigations": "Local finding and investigation records",
    "derived_findings_only": "Derived records only; raw events not retained",
    "platform_detector_adapter": "Lightwork core detector library adapter",
    "signed_chain_input": "Verified signed audit chain as source of truth",
    "continuous_monitor": "Continuous platform telemetry monitor",
    "governed_response": "Human-gated governed containment",
    "fleet_baselines": "Cross-agent and operator baselines",
    "signed_audit": "Ed25519 tamper-evident audit trail",
    "program_workspace": "Security threat workspace",
}


def caps_summary() -> dict:
    mode = (
        "Standalone Platform Hunter (vendored analysis)"
        if STANDALONE
        else "Standalone Platform Hunter (Lightwork core analysis)"
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
    }
