"""Stable data contracts for Lightwork's deterministic platform hunter."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from typing import Any


def canonical_digest(value: object) -> str:
    """Return a stable content commitment for evidence and records."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def deterministic_id(prefix: str, *parts: object) -> str:
    digest = canonical_digest(list(parts))[:24]
    return f"{prefix}_{digest}"


@dataclass(frozen=True)
class HuntEvent:
    """Normalized platform telemetry; callers retain custody of original rows."""

    event_id: str
    source: str
    observed_at: float
    kind: str
    actor: str = "system"
    action: str = ""
    target: str = ""
    outcome: str = ""
    tenant: str = ""
    goal_id: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id or not self.source or not self.kind:
            raise ValueError("hunt events require event_id, source, and kind")
        if not math.isfinite(float(self.observed_at)):
            raise ValueError("hunt event timestamp must be finite")

    @classmethod
    def from_mapping(cls, source: str, row: dict[str, Any]) -> HuntEvent:
        """Normalize a mapping without trusting a producer-supplied event id."""
        timestamp = row.get("observed_at", row.get("ts", row.get("timestamp", 0.0)))
        try:
            observed_at = float(timestamp)
        except (TypeError, ValueError) as exc:
            raise ValueError("hunt event has an invalid timestamp") from exc
        if not math.isfinite(observed_at):
            raise ValueError("hunt event timestamp must be finite")
        supplied = row.get("event_id", row.get("id"))
        event_id = str(supplied or deterministic_id("evt", source, row))
        structural = {
            "event_id", "id", "source", "observed_at", "ts", "timestamp",
            "kind", "category", "actor", "agent", "principal", "action",
            "name", "tool", "target", "resource", "outcome", "status",
            "tenant", "goal_id",
        }
        attributes = {str(k): v for k, v in row.items() if k not in structural}
        return cls(
            event_id=event_id,
            source=source,
            observed_at=observed_at,
            kind=str(row.get("kind", row.get("category", "event"))),
            actor=str(row.get("actor", row.get("agent", row.get("principal", "system")))),
            action=str(row.get("action", row.get("name", row.get("tool", "")))),
            target=str(row.get("target", row.get("resource", ""))),
            outcome=str(row.get("outcome", row.get("status", ""))),
            tenant=str(row.get("tenant", "")),
            goal_id=str(row.get("goal_id", "") or ""),
            attributes=attributes,
        )

    def evidence(self, quote: str = "") -> EvidenceRef:
        row = asdict(self)
        return EvidenceRef(
            event_id=self.event_id,
            source=self.source,
            observed_at=self.observed_at,
            sha256=canonical_digest(row),
            quote=quote[:320],
        )


@dataclass(frozen=True)
class EvidenceRef:
    """An exact event citation plus a commitment to the normalized event."""

    event_id: str
    source: str
    observed_at: float
    sha256: str
    quote: str = ""

    def __post_init__(self) -> None:
        if not self.event_id or not self.source:
            raise ValueError("evidence requires an event id and source")
        if len(self.sha256) != 64:
            raise ValueError("evidence sha256 must be a hexadecimal digest")
        try:
            int(self.sha256, 16)
        except ValueError as exc:
            raise ValueError("evidence sha256 must be a hexadecimal digest") from exc


@dataclass(frozen=True)
class Finding:
    """A deterministic verdict whose evidence is mandatory."""

    finding_id: str
    rule_id: str
    title: str
    severity: str
    verdict: str
    mitre_techniques: tuple[str, ...]
    evidence: tuple[EvidenceRef, ...]
    score: int
    suggested_containment: str = ""
    status: str = "open"
    created_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("every finding verdict must cite at least one event")
        if self.severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("invalid finding severity")
        if not 0 <= self.score <= 100:
            raise ValueError("finding score must be between 0 and 100")


@dataclass(frozen=True)
class ContainmentProposal:
    """A suggestion only; this package deliberately has no execution method."""

    proposal_id: str
    action: str
    scope: str
    reason: str
    evidence: tuple[EvidenceRef, ...]

    @classmethod
    def build(
        cls, action: str, scope: str, reason: str, evidence: tuple[EvidenceRef, ...],
    ) -> ContainmentProposal:
        if not evidence:
            raise ValueError("containment proposals require cited evidence")
        return cls(
            proposal_id=deterministic_id("contain", action, scope, evidence),
            action=action,
            scope=scope,
            reason=reason,
            evidence=evidence,
        )


@dataclass(frozen=True)
class Investigation:
    investigation_id: str
    title: str
    finding_ids: tuple[str, ...]
    evidence: tuple[EvidenceRef, ...]
    summary: str
    status: str = "open"
    assignee: str = ""
    containment: ContainmentProposal | None = None
    created_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.finding_ids or not self.evidence:
            raise ValueError("investigations require findings and cited evidence")


@dataclass(frozen=True)
class ChainIntegrityStatus:
    intact: bool
    paths_checked: tuple[str, ...]
    breaks: tuple[dict[str, Any], ...] = ()
    checked_at: float = 0.0


@dataclass(frozen=True)
class BaselineProfile:
    tools_by_actor: dict[str, tuple[str, ...]]
    countries_by_actor: dict[str, tuple[str, ...]]
    hourly_counts: dict[str, tuple[int, ...]]
    operator_hour_counts: dict[str, tuple[int, ...]]


@dataclass(frozen=True)
class HuntReport:
    findings: tuple[Finding, ...]
    events_scanned: int
    baseline: BaselineProfile
    chain_status: ChainIntegrityStatus | None = None
    audited_findings: int = 0


__all__ = [
    "BaselineProfile",
    "ChainIntegrityStatus",
    "ContainmentProposal",
    "EvidenceRef",
    "Finding",
    "HuntEvent",
    "HuntReport",
    "Investigation",
    "canonical_digest",
    "deterministic_id",
]
