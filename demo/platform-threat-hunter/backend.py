"""Backend seam for the platform threat-hunter demo."""
from __future__ import annotations

from dataclasses import asdict

import hunter_engine as local
from capabilities import (
    CAPABILITY_LABELS,
    CAPS,
    FORCED_STANDALONE,
    PLATFORM_ENGINE,
    STANDALONE,
)
from capabilities import (
    caps_summary as _caps_summary,
)

if not STANDALONE:
    from maverick import platform_hunt as _platform
else:
    _platform = None

STORE = local.LocalFindingStore()


def _binding(implementation: str, authority: str, active: bool = True) -> dict:
    return {
        "implementation": implementation,
        "authority": authority,
        "active": active,
    }


def _integrated_only() -> dict:
    return _binding(
        "Not available in this standalone app; use integrated Lightwork /security/threats",
        "integrated-lightwork-only",
        False,
    )


_DETECTION_ENGINE = (
    "maverick.platform_hunt scan adapter (analysis only)"
    if PLATFORM_ENGINE
    else "hunter_engine.detect vendored detector"
)

CAPABILITY_BINDINGS = {
    "deterministic_detection": _binding(
        _DETECTION_ENGINE, "unsigned-local-input"
    ),
    "local_investigations": _binding(
        "hunter_engine.open_investigation and LocalFindingStore",
        "unsigned-local",
    ),
    "derived_findings_only": _binding(
        "hunter_engine.LocalFindingStore", "unsigned-local-derived-records"
    ),
    "platform_detector_adapter": _binding(
        (
            "maverick.platform_hunt scan adapter (analysis only)"
            if PLATFORM_ENGINE
            else "Not bound: Lightwork core analysis is unavailable or forced off"
        ),
        "analysis-only-no-platform-authority",
        PLATFORM_ENGINE,
    ),
    "signed_chain_input": _integrated_only(),
    "continuous_monitor": _integrated_only(),
    "governed_response": _integrated_only(),
    "fleet_baselines": _integrated_only(),
    "signed_audit": _integrated_only(),
    "program_workspace": _integrated_only(),
}


def _validate_capability_bindings() -> None:
    if set(CAPABILITY_BINDINGS) != set(CAPS):
        raise RuntimeError("platform hunter capability bindings do not match CAPS")
    for capability, enabled in CAPS.items():
        binding = CAPABILITY_BINDINGS[capability]
        if binding.get("active") is not enabled:
            raise RuntimeError(f"platform hunter capability binding drift: {capability}")
        if not binding.get("implementation") or not binding.get("authority"):
            raise RuntimeError(
                f"platform hunter capability binding is incomplete: {capability}"
            )


_validate_capability_bindings()


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
    return summary


def _standalone_audit_boundary(_kind: str, _payload: dict) -> bool:
    """Keep unsigned demo input out of Lightwork's authoritative audit chain."""
    return False


def detect(events: list[dict]):
    implementation = getattr(_platform, "detect", None) if _platform else None
    if callable(implementation):
        return implementation(events)
    scan = getattr(_platform, "scan", None) if _platform else None
    event_type = getattr(_platform, "HuntEvent", None) if _platform else None
    if callable(scan) and event_type is not None:
        normalized = []
        for index, event in enumerate(events):
            row = dict(event)
            row.setdefault("event_id", str(row.get("id") or f"demo-{index}"))
            row.setdefault("observed_at", float(row.get("timestamp", index)))
            row.setdefault("kind", "event")
            normalized.append(event_type.from_mapping("standalone.demo", row))
        return [
            _finding_shape(item)
            for item in scan(
                normalized,
                audit_recorder=_standalone_audit_boundary,
            ).findings
        ]
    return local.detect(events)


def _finding_shape(finding) -> dict:
    """Adapt the Lightwork detector contract to the demo's stable record shape."""
    row = asdict(finding)
    evidence = row.get("evidence") or []
    first = evidence[0] if evidence else {}
    techniques = row.get("mitre_techniques") or []
    return {
        "id": row["finding_id"],
        "type": "finding",
        "rule_id": row["rule_id"],
        "title": row["title"],
        "severity": row["severity"],
        "technique": techniques[0] if techniques else "unmapped",
        "mitre_techniques": list(techniques),
        "status": row.get("status", "open"),
        "score": row.get("score", 0),
        "evidence": {
            "source_event_id": first.get("event_id", "unknown"),
            "kind": first.get("source", "event"),
            "excerpt": first.get("quote", ""),
            "sha256": first.get("sha256", ""),
            "reason": row.get("verdict", "deterministic rule match"),
        },
        "suggested_containment": row.get("suggested_containment", ""),
    }


def open_investigation(finding: dict, analyst: str = "unassigned"):
    return local.open_investigation(finding, analyst)


def get_finding(finding_id: str):
    return STORE.get_finding(finding_id)


def save_derived(records: list[dict], expected_revision: int):
    return STORE.save_derived(records, expected_revision)


def list_records():
    return STORE.list_records()


__all__ = [
    "CAPS",
    "CAPABILITY_BINDINGS",
    "FORCED_STANDALONE",
    "PLATFORM_ENGINE",
    "STANDALONE",
    "caps_summary",
    "detect",
    "get_finding",
    "open_investigation",
    "save_derived",
    "list_records",
]
