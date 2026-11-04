"""Backend seam for standalone or Lightwork environment hunting."""
from __future__ import annotations

from dataclasses import asdict

import env_engine as local
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
    from maverick import env_hunt as _platform
    from maverick.platform_hunt import EvidenceRef as _EvidenceRef
else:
    _platform = None
    _EvidenceRef = None

STORE = local.DerivedStore()


def _binding(implementation: str, authority: str, active: bool = True) -> dict:
    return {
        "implementation": implementation,
        "authority": authority,
        "active": active,
    }


def _integrated_only() -> dict:
    return _binding(
        "Not available in this standalone app; use integrated Lightwork /security/soc",
        "integrated-lightwork-only",
        False,
    )


_DETECTION_ENGINE = (
    "maverick.env_hunt scan adapter plus vendored rules (analysis only)"
    if PLATFORM_ENGINE
    else "env_engine.detect vendored detector"
)
_INGEST_ENGINE = (
    "maverick.env_hunt ingest adapter with env_engine fallback"
    if PLATFORM_ENGINE
    else "env_engine.ingest vendored normalizer"
)
_PROPOSAL_ENGINE = (
    "maverick.env_hunt proposal adapter (proposal only)"
    if PLATFORM_ENGINE
    else "env_engine.propose_response vendored proposal builder"
)

CAPABILITY_BINDINGS = {
    "generic_ingestion": _binding(_INGEST_ENGINE, "ephemeral-unsigned-input"),
    "sigma_import": _binding(_DETECTION_ENGINE, "unsigned-local-analysis"),
    "deterministic_detection": _binding(
        _DETECTION_ENGINE, "unsigned-local-analysis"
    ),
    "derived_findings_only": _binding(
        "env_engine.DerivedStore", "unsigned-local-derived-records"
    ),
    "response_proposals": _binding(_PROPOSAL_ENGINE, "unsigned-local-proposal"),
    "proposal_only": _binding(
        "app.py proposal route; no delivery or execution binding",
        "non-executing-local-proposal",
    ),
    "platform_detector_adapter": _binding(
        (
            "maverick.env_hunt adapters (analysis only)"
            if PLATFORM_ENGINE
            else "Not bound: Lightwork core analysis is unavailable or forced off"
        ),
        "analysis-only-no-platform-authority",
        PLATFORM_ENGINE,
    ),
    "managed_connectors": _integrated_only(),
    "governed_approval": _integrated_only(),
    "response_execution": _integrated_only(),
    "signed_audit": _integrated_only(),
    "cross_run_learning": _integrated_only(),
    "soc_workspace": _integrated_only(),
}


def _validate_capability_bindings() -> None:
    if set(CAPABILITY_BINDINGS) != set(CAPS):
        raise RuntimeError("environment hunter capability bindings do not match CAPS")
    for capability, enabled in CAPS.items():
        binding = CAPABILITY_BINDINGS[capability]
        if binding.get("active") is not enabled:
            raise RuntimeError(
                f"environment hunter capability binding drift: {capability}"
            )
        if not binding.get("implementation") or not binding.get("authority"):
            raise RuntimeError(
                f"environment hunter capability binding is incomplete: {capability}"
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


def _call(name, fallback, *args, **kwargs):
    implementation = getattr(_platform, name, None) if _platform else None
    return implementation(*args, **kwargs) if callable(implementation) else fallback(*args, **kwargs)


def ingest(source_type: str, payload):
    return _call("ingest", local.ingest, source_type, payload)


def detect(events: list[dict], sigma_rules: list[dict] | None = None):
    scan = getattr(_platform, "scan", None) if _platform else None
    if callable(scan):
        platform_events = [_platform_event(item) for item in events]
        rules = list(_platform.curated_rules())
        rules.extend(_platform_rule(item) for item in sigma_rules or [])
        platform_findings = [
            _finding_shape(item)
            for item in scan(
                platform_events,
                rules=rules,
                audit_recorder=_standalone_audit_boundary,
            ).findings
        ]
        local_findings = local.detect(events, sigma_rules)
        return list({item["id"]: item for item in (*platform_findings, *local_findings)}.values())
    return local.detect(events, sigma_rules)


def _platform_rule(rule: dict) -> dict:
    row = dict(rule)
    detection = dict(row.get("detection") or {})
    detection.setdefault("condition", "selection")
    row["detection"] = detection
    return row


def _platform_event(event: dict):
    """Normalize native standalone inputs before calling the core detector."""
    row = dict(event)
    if "eventName" in row:
        row.setdefault("eventTime", row.get("timestamp", 0))
        return _platform.parse_cloudtrail(row)
    if "auditID" in row or "objectRef" in row:
        row.setdefault("requestReceivedTimestamp", row.get("timestamp", 0))
        return _platform.parse_kubernetes_audit(row)
    if row.get("kind") == "syslog":
        return _platform.TelemetryEvent.from_mapping(
            {
                "event_id": row.get("id", ""),
                "source": "host.syslog",
                "observed_at": row.get("timestamp", 0),
                "category": "host",
                "action": "syslog",
                "principal": row.get("actor", ""),
                "target": row.get("host", ""),
                "attributes": {"message": row.get("message", "")},
            }
        )
    return _platform.TelemetryEvent.from_mapping(row)


def _finding_shape(finding) -> dict:
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
        "actor": str(row.get("metadata", {}).get("principal", "unknown")),
        "status": row.get("status", "open"),
        "confidence": min(0.99, float(row.get("score", 0)) / 100),
        "evidence": {
            "source_event_id": first.get("event_id", "unknown"),
            "source_kind": first.get("source", "event"),
            "excerpt": first.get("quote", ""),
            "sha256": first.get("sha256", ""),
            "observed_at": first.get("observed_at", 0),
            "reason": row.get("verdict", "deterministic rule match"),
        },
    }


def investigate(finding: dict, related_findings: list[dict] | None = None):
    return local.investigate(finding, related_findings)


def get_finding(finding_id: str):
    return STORE.get_record(finding_id, "finding")


def get_investigation(investigation_id: str):
    return STORE.get_record(investigation_id, "investigation")


def propose_response(investigation: dict, action: str, target: str):
    implementation = getattr(_platform, "propose_response", None) if _platform else None
    if not callable(implementation):
        return local.propose_response(investigation, action, target)
    evidence = tuple(_evidence_ref(item) for item in investigation.get("timeline", []))
    evidence = tuple(item for item in evidence if item is not None)
    if not evidence:
        return local.propose_response(investigation, action, target)
    proposal = implementation(
        action,
        target,
        f"Investigation {investigation.get('id', 'unknown')}: {investigation.get('title', 'SOC finding')}",
        evidence,
        audit_recorder=_standalone_audit_boundary,
    )
    row = asdict(proposal)
    proposal_id = row.pop("proposal_id")
    return {
        **row,
        "id": proposal_id,
        "type": "response_proposal",
        "status": "proposed",
        "digest": proposal.digest,
        "warning": (
            "Proposal only in this standalone app. Use its exact digest in Lightwork "
            "/security/soc for governed approval and execution."
        ),
    }


def _evidence_ref(item: dict):
    if _EvidenceRef is None:
        return None
    digest = str(item.get("sha256", ""))
    if len(digest) != 64:
        return None
    return _EvidenceRef(
        event_id=str(item.get("source_event_id", "unknown")),
        source=str(item.get("source_kind", "event")),
        observed_at=float(item.get("observed_at", 0)),
        sha256=digest,
        quote=str(item.get("excerpt", ""))[:320],
    )


def save_derived(records: list[dict], expected_revision: int):
    return STORE.save(records, expected_revision)


def list_records():
    return STORE.list_records()


__all__ = [
    "CAPS",
    "CAPABILITY_BINDINGS",
    "FORCED_STANDALONE",
    "PLATFORM_ENGINE",
    "STANDALONE",
    "caps_summary",
    "ingest",
    "detect",
    "get_finding",
    "get_investigation",
    "investigate",
    "propose_response",
    "save_derived",
    "list_records",
]
