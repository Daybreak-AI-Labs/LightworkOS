"""Environment-hunt orchestration over deterministic Sigma and correlation."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ..audit.errors import AuditRefused
from ..platform_hunt.models import Finding, canonical_digest
from .correlation import correlate
from .models import TelemetryEvent
from .sigma import SigmaRule
from .sigma import detect as _sigma_detect

AuditRecorder = Callable[[str, dict[str, Any]], bool]


@dataclass(frozen=True)
class EnvironmentHuntReport:
    findings: tuple[Finding, ...]
    events_scanned: int
    sigma_findings: int
    correlation_findings: int
    audited_findings: int


def enabled(config: dict[str, Any] | None = None) -> bool:
    """Environment hunting requires explicit opt-in and defaults off."""
    if config is None:
        try:
            from ..config import config_source_errors, load_global_config

            config = load_global_config()
            if config_source_errors(include_tenant=False):
                return False
        except Exception:  # failure-policy: fail_closed
            return False
    section = config.get("env_hunt") if isinstance(config, dict) else None
    return section.get("enable", False) is True if isinstance(section, dict) else False


def _record(recorder: AuditRecorder | None, finding: Finding) -> bool:
    payload = {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "score": finding.score,
        "mitre_techniques": list(finding.mitre_techniques),
        "evidence_ids": [item.event_id for item in finding.evidence],
        "finding_sha256": canonical_digest(finding),
    }
    if recorder is not None:
        try:
            return bool(recorder("env_hunt_detection", payload))
        except AuditRefused:
            raise
        except Exception:  # failure-policy: visible_degradation
            return False
    try:
        from ..audit import record

        return bool(record("env_hunt_detection", **payload))
    except AuditRefused:
        raise
    except Exception:  # failure-policy: visible_degradation
        return False


def detect(
    events: Iterable[TelemetryEvent | dict[str, Any]],
    rules: Iterable[SigmaRule | dict[str, Any]] | None = None,
) -> tuple[Finding, ...]:
    """Convenience boundary accepting normalized mappings or typed contracts."""
    normalized = tuple(
        event if isinstance(event, TelemetryEvent) else TelemetryEvent.from_mapping(event)
        for event in events
    )
    active = None if rules is None else tuple(
        rule if isinstance(rule, SigmaRule) else SigmaRule(rule) for rule in rules
    )
    return _sigma_detect(normalized, active)


def scan(
    events: Iterable[TelemetryEvent | dict[str, Any]],
    *,
    rules: Iterable[SigmaRule | dict[str, Any]] | None = None,
    include_correlations: bool = True,
    audit_recorder: AuditRecorder | None = None,
) -> EnvironmentHuntReport:
    ordered = tuple(sorted(
        (
            event if isinstance(event, TelemetryEvent) else TelemetryEvent.from_mapping(event)
            for event in events
        ),
        key=lambda item: (item.observed_at, item.event_id),
    ))
    sigma_findings = detect(ordered, rules)
    correlations = correlate(ordered, sigma_findings) if include_correlations else ()
    unique = {finding.finding_id: finding for finding in (*sigma_findings, *correlations)}
    findings = tuple(sorted(
        unique.values(), key=lambda item: (-item.score, item.rule_id, item.finding_id),
    ))
    audited = sum(_record(audit_recorder, finding) for finding in findings)
    return EnvironmentHuntReport(
        findings=findings,
        events_scanned=len(ordered),
        sigma_findings=len(sigma_findings),
        correlation_findings=len(correlations),
        audited_findings=audited,
    )


__all__ = ["EnvironmentHuntReport", "detect", "enabled", "scan"]
