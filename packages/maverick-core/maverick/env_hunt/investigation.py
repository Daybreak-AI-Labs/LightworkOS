"""Deterministic investigation timelines and allowlisted enrichment."""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Any, Protocol, runtime_checkable

from ..audit.errors import AuditRefused
from ..platform_hunt.models import EvidenceRef, Finding, canonical_digest, deterministic_id
from .models import TelemetryEvent


@dataclass(frozen=True)
class TimelineEntry:
    observed_at: float
    event_id: str
    source: str
    category: str
    action: str
    principal: str
    target: str
    outcome: str


@dataclass(frozen=True)
class Enrichment:
    source: str
    indicator: str
    fields: dict[str, Any]


@dataclass(frozen=True)
class EnvironmentInvestigation:
    investigation_id: str
    title: str
    finding_ids: tuple[str, ...]
    evidence: tuple[EvidenceRef, ...]
    timeline: tuple[TimelineEntry, ...]
    mitre_techniques: tuple[str, ...]
    confidence: int
    summary: str
    status: str = "open"
    assignee: str = ""
    enrichments: tuple[Enrichment, ...] = ()
    response_proposal_ids: tuple[str, ...] = ()
    created_at: float = 0.0


@runtime_checkable
class EnrichmentProvider(Protocol):
    name: str

    def lookup(self, indicator: str) -> dict[str, Any]: ...


def build_investigation(
    findings: Iterable[Finding], events: Iterable[TelemetryEvent], *, title: str = "SOC investigation",
) -> EnvironmentInvestigation:
    selected = tuple(sorted(findings, key=lambda item: item.finding_id))
    if not selected:
        raise ValueError("an investigation requires at least one finding")
    cited_ids = {item.event_id for finding in selected for item in finding.evidence}
    supplied = tuple(events)
    cited_events = tuple(event for event in supplied if event.event_id in cited_ids)
    if cited_ids.difference(event.event_id for event in cited_events):
        raise ValueError("all cited finding events must be supplied to the investigation")
    principals = {event.principal for event in cited_events if event.principal}
    targets = {event.target for event in cited_events if event.target}
    related = sorted(
        (
            event for event in supplied
            if event.event_id not in cited_ids
            and (
                (event.principal and event.principal in principals)
                or (event.target and event.target in targets)
            )
        ),
        key=lambda item: (item.observed_at, item.event_id),
    )
    timeline_by_id = {event.event_id: event for event in cited_events}
    for event in related:
        if len(timeline_by_id) >= 2000:
            break
        timeline_by_id.setdefault(event.event_id, event)
    relevant = tuple(sorted(
        timeline_by_id.values(), key=lambda item: (item.observed_at, item.event_id),
    ))
    evidence_by_id = {
        evidence.event_id: evidence for finding in selected for evidence in finding.evidence
    }
    evidence = tuple(evidence_by_id[key] for key in sorted(evidence_by_id))
    techniques = tuple(sorted({
        technique for finding in selected for technique in finding.mitre_techniques
    }))
    confidence = min(100, 35 + 10 * len(selected) + 5 * len(evidence) + 3 * len(techniques))
    timeline = tuple(TimelineEntry(
        observed_at=event.observed_at,
        event_id=event.event_id,
        source=event.source,
        category=event.category,
        action=event.action,
        principal=event.principal,
        target=event.target,
        outcome=event.outcome,
    ) for event in relevant)
    finding_ids = tuple(finding.finding_id for finding in selected)
    created_at = max(event.observed_at for event in relevant)
    return EnvironmentInvestigation(
        investigation_id=deterministic_id("inv", finding_ids, tuple(cited_ids)),
        title=title,
        finding_ids=finding_ids,
        evidence=evidence,
        timeline=timeline,
        mitre_techniques=techniques,
        confidence=confidence,
        summary=(
            f"{len(selected)} deterministic finding(s), {len(evidence)} cited event(s), "
            f"and {len(techniques)} ATT&CK technique(s). Human validation is required."
        ),
        created_at=created_at,
    )


_INDICATOR_RE = re.compile(
    r"^(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$|^(?:\d{1,3}\.){3}\d{1,3}$"
)
_ENRICHMENT_FIELDS = {
    "classification", "confidence", "first_seen", "last_seen", "reference", "reputation",
}


def enrich(
    investigation: EnvironmentInvestigation,
    providers: Iterable[EnrichmentProvider],
    *,
    allowed_sources: Iterable[str],
    audit_recorder: Callable[[str, dict[str, Any]], bool] | None = None,
) -> EnvironmentInvestigation:
    allowed = {name.strip().lower() for name in allowed_sources}
    indicators = sorted({
        value
        for entry in investigation.timeline
        for value in (entry.target, entry.principal)
        if _INDICATOR_RE.fullmatch(value)
    })[:64]
    results = list(investigation.enrichments)
    for provider in sorted(providers, key=lambda item: item.name):
        if provider.name.strip().lower() not in allowed:
            continue
        for indicator in indicators:
            raw = provider.lookup(indicator)
            if not isinstance(raw, dict):
                raise ValueError("enrichment providers must return a mapping")
            fields = {
                str(key): value for key, value in raw.items()
                if key in _ENRICHMENT_FIELDS and isinstance(value, (str, int, float, bool))
            }
            payload = {
                "investigation_id": investigation.investigation_id,
                "source": provider.name,
                "indicator_sha256": canonical_digest(indicator),
                "fields_sha256": canonical_digest(fields),
            }
            try:
                if audit_recorder is not None:
                    audited = bool(audit_recorder("env_hunt_enrichment", payload))
                else:
                    from ..audit import record

                    audited = bool(record("env_hunt_enrichment", **payload))
            except AuditRefused:
                raise
            except Exception:  # failure-policy: fail_closed
                audited = False
            if not audited:
                raise RuntimeError("enrichment audit record was not accepted")
            results.append(Enrichment(provider.name, indicator, fields))
    return replace(
        investigation,
        enrichments=tuple(sorted(results, key=lambda item: (item.source, item.indicator))),
    )


__all__ = [
    "Enrichment",
    "EnrichmentProvider",
    "EnvironmentInvestigation",
    "TimelineEntry",
    "build_investigation",
    "enrich",
]
