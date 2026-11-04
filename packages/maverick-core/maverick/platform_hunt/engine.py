"""Deterministic, evidence-citing detections for Lightwork itself.

The engine contains no model calls. An LLM may narrate its findings later, but
cannot create, suppress, or relabel the rule verdicts produced here.
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import asdict
from typing import Any

from ..audit.errors import AuditRefused
from .models import (
    BaselineProfile,
    ChainIntegrityStatus,
    Finding,
    HuntEvent,
    HuntReport,
    canonical_digest,
    deterministic_id,
)

AuditRecorder = Callable[[str, dict[str, Any]], bool]

_PROMPT_MARKERS = (
    "ignore previous instructions",
    "ignore all previous",
    "reveal the system prompt",
    "developer message",
    "bypass the policy",
    "disable the shield",
)
_READ_ACTIONS = {
    "read", "read_file", "get_object", "query", "search", "export", "download",
}
_EGRESS_ACTIONS = {
    "email", "http_post", "post", "send", "upload", "webhook", "curl", "publish",
}
_SELF_MODIFY_ACTIONS = {
    "apply_patch", "write", "write_file", "shell", "exec", "update_code",
}
_PRIVILEGED_ACTIONS = {
    "approve", "grant", "change_role", "configure", "disable_control",
    "rotate_key", "delete", "deploy",
}
_SEVERITY_SCORE = {"low": 30, "medium": 50, "high": 75, "critical": 95}


def enabled(config: dict[str, Any] | None = None) -> bool:
    """Return the explicit opt-in state; platform hunting is disabled by default."""
    if config is None:
        try:
            from ..config import config_source_errors, load_global_config

            config = load_global_config()
            if config_source_errors(include_tenant=False):
                return False
        except Exception:  # failure-policy: fail_closed
            return False
    section = config.get("threat_hunt") if isinstance(config, dict) else None
    return section.get("enable", False) is True if isinstance(section, dict) else False


def _text(event: HuntEvent) -> str:
    values = [event.kind, event.actor, event.action, event.target, event.outcome]
    for key, value in sorted(event.attributes.items()):
        if isinstance(value, (str, int, float, bool)):
            values.extend((key, str(value)))
    return " ".join(values).lower()


def _quote(event: HuntEvent, reason: str) -> str:
    return (
        f"{reason}; kind={event.kind}; actor={event.actor}; "
        f"action={event.action or '-'}; outcome={event.outcome or '-'}"
    )[:320]


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    verdict: str,
    techniques: tuple[str, ...],
    events: Iterable[HuntEvent],
    *,
    containment: str,
    score: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    unique = {event.event_id: event for event in events}
    ordered = tuple(sorted(unique.values(), key=lambda item: (item.observed_at, item.event_id)))
    evidence = tuple(event.evidence(_quote(event, verdict)) for event in ordered)
    return Finding(
        finding_id=deterministic_id("pf", rule_id, tuple(item.event_id for item in ordered)),
        rule_id=rule_id,
        title=title,
        severity=severity,
        verdict=verdict,
        mitre_techniques=techniques,
        evidence=evidence,
        score=score if score is not None else _SEVERITY_SCORE[severity],
        suggested_containment=containment,
        created_at=max(item.observed_at for item in ordered),
        metadata=metadata or {},
    )


def build_baseline(events: Iterable[HuntEvent]) -> BaselineProfile:
    tools: dict[str, set[str]] = defaultdict(set)
    countries: dict[str, set[str]] = defaultdict(set)
    hourly: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    operator_hours: dict[str, list[int]] = defaultdict(lambda: [0] * 24)
    for event in sorted(events, key=lambda item: (item.observed_at, item.event_id)):
        if event.kind in {"tool_call", "tool_result"} and event.action:
            tools[event.actor].add(event.action.lower())
        country = event.attributes.get("country")
        if isinstance(country, str) and country:
            countries[event.actor].add(country.upper())
        hour = int(event.observed_at // 3600)
        hourly[f"{event.actor}|{event.kind}"][hour] += 1
        if event.action.lower() in _PRIVILEGED_ACTIONS:
            operator_hours[event.actor][int(event.observed_at % 86400 // 3600)] += 1
    return BaselineProfile(
        tools_by_actor={key: tuple(sorted(value)) for key, value in sorted(tools.items())},
        countries_by_actor={
            key: tuple(sorted(value)) for key, value in sorted(countries.items())
        },
        hourly_counts={
            key: tuple(value[hour] for hour in sorted(value))
            for key, value in sorted(hourly.items())
        },
        operator_hour_counts={
            key: tuple(value) for key, value in sorted(operator_hours.items())
        },
    )


def _shield_bypass(events: tuple[HuntEvent, ...], _baseline: BaselineProfile) -> list[Finding]:
    grouped: dict[str, list[HuntEvent]] = defaultdict(list)
    for event in events:
        if event.kind == "shield_block" or "shield" in event.source.lower():
            grouped[event.actor].append(event)
    findings = []
    for actor, matches in sorted(grouped.items()):
        marker_hits = [event for event in matches if any(marker in _text(event) for marker in _PROMPT_MARKERS)]
        if len(matches) < 3 and not marker_hits:
            continue
        cited = marker_hits or matches
        findings.append(_finding(
            "LW-PLAT-001", "Repeated shield-bypass attempts", "high",
            f"{actor} triggered {len(matches)} shield blocks; deterministic threshold is 3",
            ("T1059", "T1204"), cited,
            containment="Pause the affected goal and require an operator to review its inputs.",
            score=min(95, 65 + 5 * len(matches)),
        ))
    return findings


def _novel_tools(events: tuple[HuntEvent, ...], baseline: BaselineProfile) -> list[Finding]:
    grouped: dict[tuple[str, str], list[HuntEvent]] = defaultdict(list)
    for event in events:
        if event.kind != "tool_call" or not event.action:
            continue
        known = set(baseline.tools_by_actor.get(event.actor, ()))
        if known and event.action.lower() not in known:
            grouped[(event.actor, event.action.lower())].append(event)
    return [
        _finding(
            "LW-PLAT-002", "Novel tool use for agent", "medium",
            f"{actor} used {tool}, which is absent from its deterministic baseline",
            ("T1059",), matches,
            containment="Review the capability grant and the goal that introduced the tool.",
            metadata={"baseline_tools": list(baseline.tools_by_actor.get(actor, ()))},
        )
        for (actor, tool), matches in sorted(grouped.items())
    ]


def _approval_escalation(
    events: tuple[HuntEvent, ...], _baseline: BaselineProfile,
) -> list[Finding]:
    denials: dict[tuple[str, str], list[HuntEvent]] = defaultdict(list)
    findings: list[Finding] = []
    for event in events:
        if event.kind in {"capability_denied", "governance_denied"}:
            denials[(event.actor, event.action or event.target)].append(event)
        if event.kind == "approval" and event.outcome.lower() in {"denied", "deny"}:
            denials[(event.actor, event.action)].append(event)
    for event in events:
        if event.kind not in {"tool_call", "tool_result"}:
            continue
        prior = [
            denial for denial in denials.get((event.actor, event.action), ())
            if 0 <= event.observed_at - denial.observed_at <= 3600
        ]
        if prior and event.outcome.lower() not in {"denied", "blocked", "failed", "error"}:
            findings.append(_finding(
                "LW-PLAT-003", "Action followed an approval or capability denial", "critical",
                "A previously denied action appears to have executed within one hour",
                ("T1548",), [*prior, event],
                containment="Suspend the principal's capability grant pending approval-path review.",
            ))
    for (actor, action), matches in sorted(denials.items()):
        if len(matches) >= 3:
            findings.append(_finding(
                "LW-PLAT-003", "Repeated privilege-escalation pattern", "high",
                f"{actor} accumulated {len(matches)} denials for {action or 'an action'}",
                ("T1548",), matches,
                containment="Review and narrow the principal's delegated capability envelope.",
            ))
    return findings


def _prompt_injection(events: tuple[HuntEvent, ...], _baseline: BaselineProfile) -> list[Finding]:
    matches = []
    for event in events:
        if event.kind in {"tool_result", "memory_write", "ingested_content", "document_ingested"}:
            markers = [marker for marker in _PROMPT_MARKERS if marker in _text(event)]
            if markers:
                matches.append((event, markers))
    return [
        _finding(
            "LW-PLAT-004", "Prompt-injection marker in ingested content", "high",
            f"Ingested content matched marker(s): {', '.join(markers)}",
            ("T1059", "T1204"), [event],
            containment="Quarantine the cited content and re-run ingestion through the shield.",
            metadata={"markers": markers},
        )
        for event, markers in matches
    ]


def _exfiltration_sequence(
    events: tuple[HuntEvent, ...], _baseline: BaselineProfile,
) -> list[Finding]:
    by_actor: dict[str, list[HuntEvent]] = defaultdict(list)
    for event in events:
        by_actor[event.actor].append(event)
    findings = []
    for _actor, actor_events in sorted(by_actor.items()):
        reads = [event for event in actor_events if event.action.lower() in _READ_ACTIONS]
        for outbound in actor_events:
            is_egress = outbound.action.lower() in _EGRESS_ACTIONS or outbound.kind == "egress_blocked"
            if not is_egress:
                continue
            related = [
                event for event in reads
                if 0 <= outbound.observed_at - event.observed_at <= 600
                and (not outbound.goal_id or not event.goal_id or outbound.goal_id == event.goal_id)
            ]
            if related:
                findings.append(_finding(
                    "LW-PLAT-005", "Data-access followed by outbound transfer", "critical",
                    "A read/export event was followed by an egress-shaped action within 10 minutes",
                    ("T1041", "T1567"), [related[-1], outbound],
                    containment="Block the destination and pause the affected goal for human review.",
                ))
    return findings


def _self_modification(events: tuple[HuntEvent, ...], _baseline: BaselineProfile) -> list[Finding]:
    findings = []
    for event in events:
        text = _text(event)
        action_match = event.action.lower() in _SELF_MODIFY_ACTIONS
        code_target = any(token in text for token in ("maverick/", ".py", "pyproject.toml"))
        sanctioned = bool(event.attributes.get("sanctioned_learning")) or event.kind in {
            "learning_update", "promotion_commit",
        }
        if (event.kind == "self_modification" or (action_match and code_target)) and not sanctioned:
            findings.append(_finding(
                "LW-PLAT-006", "Self-modification outside sanctioned learning", "critical",
                "A code-changing action lacks a sanctioned-learning or promotion receipt",
                ("T1505", "T1565.001"), [event],
                containment="Freeze the workspace and compare it with the last governed promotion.",
            ))
    return findings


def _rate_threshold(counts: tuple[int, ...]) -> float:
    if not counts:
        return 10.0
    median = statistics.median(counts)
    deviations = [abs(value - median) for value in counts]
    mad = statistics.median(deviations)
    return float(max(10, median + max(3, 6 * mad)))


def _budget_and_rate(events: tuple[HuntEvent, ...], baseline: BaselineProfile) -> list[Finding]:
    findings = []
    current_counts: dict[tuple[str, str, int], list[HuntEvent]] = defaultdict(list)
    for event in events:
        if event.kind == "budget":
            used = event.attributes.get("used", event.attributes.get("spent"))
            limit = event.attributes.get("limit", event.attributes.get("max"))
            try:
                exceeded = float(used) > float(limit)
            except (TypeError, ValueError):
                exceeded = event.outcome.lower() in {"exceeded", "blocked"}
            if exceeded:
                findings.append(_finding(
                    "LW-PLAT-007", "Budget ceiling exceeded", "high",
                    "Recorded usage exceeded its configured deterministic ceiling",
                    ("T1496",), [event],
                    containment="Pause the goal and review its budget and tool-call trajectory.",
                ))
        current_counts[(event.actor, event.kind, int(event.observed_at // 3600))].append(event)
    for (actor, kind, _hour), matches in sorted(current_counts.items()):
        history = baseline.hourly_counts.get(f"{actor}|{kind}", ())
        threshold = _rate_threshold(history)
        if history and len(matches) > threshold:
            findings.append(_finding(
                "LW-PLAT-007", "Behavioral rate anomaly", "high",
                f"Observed {len(matches)} {kind} events in an hour; baseline threshold is {threshold:g}",
                ("T1496", "T1499"), matches,
                containment="Rate-limit the principal and review the cited burst.",
                score=min(95, 70 + int(25 * len(matches) / max(threshold, 1))),
            ))
    return findings


def _operator_anomaly(events: tuple[HuntEvent, ...], baseline: BaselineProfile) -> list[Finding]:
    findings = []
    for event in events:
        if event.action.lower() not in _PRIVILEGED_ACTIONS:
            continue
        hour = int(event.observed_at % 86400 // 3600)
        country = str(event.attributes.get("country", "")).upper()
        countries = baseline.countries_by_actor.get(event.actor, ())
        hour_counts = baseline.operator_hour_counts.get(event.actor, ())
        reasons = []
        if len(hour_counts) == 24 and sum(hour_counts) >= 4:
            nearby = sum(hour_counts[(hour + offset) % 24] for offset in range(-2, 3))
            if nearby == 0:
                active_hours = [
                    index for index, count in enumerate(hour_counts) if count
                ]
                reasons.append(
                    f"UTC hour {hour} is outside this operator's learned active hours "
                    f"{active_hours}"
                )
        if country and countries and country not in countries:
            reasons.append(f"novel country {country}")
        if reasons:
            findings.append(_finding(
                "LW-PLAT-008", "Anomalous privileged operator action", "high",
                "; ".join(reasons), ("T1078",), [event],
                containment="Require fresh step-up authentication and independent review.",
                metadata={
                    "baseline_countries": list(countries),
                    "baseline_active_hours": [
                        index for index, count in enumerate(hour_counts) if count
                    ],
                },
            ))
    return findings


def _quorum_abuse(events: tuple[HuntEvent, ...], _baseline: BaselineProfile) -> list[Finding]:
    findings = []
    for event in events:
        if event.kind not in {"approval", "approval_decision"}:
            continue
        requester = str(event.attributes.get("requested_by", event.attributes.get("requester", "")))
        approvers = event.attributes.get("approvers")
        if isinstance(approvers, str):
            approver_set = {approvers}
        elif isinstance(approvers, (list, tuple, set)):
            approver_set = {str(value) for value in approvers}
        else:
            approver = event.attributes.get("decided_by", event.actor)
            approver_set = {str(approver)} if approver else set()
        required = event.attributes.get("approvals_required", 1)
        try:
            required_count = int(required)
        except (TypeError, ValueError):
            required_count = 1
        reasons = []
        if requester and requester in approver_set:
            reasons.append("requester self-approved")
        if event.outcome.lower() in {"approved", "approve"} and len(approver_set) < required_count:
            reasons.append(
                f"approval has {len(approver_set)} distinct approver(s), requires {required_count}"
            )
        requester_role = event.attributes.get("requester_role")
        approver_roles = event.attributes.get("approver_roles", ())
        if requester_role and requester_role in approver_roles:
            reasons.append("requester and approver roles violate segregation of duties")
        if reasons:
            findings.append(_finding(
                "LW-PLAT-009", "Approval quorum or segregation-of-duties abuse", "critical",
                "; ".join(reasons), ("T1078", "T1548"), [event],
                containment="Invalidate the approval and require an independent quorum.",
            ))
    return findings


def _goal_anomaly(events: tuple[HuntEvent, ...], baseline: BaselineProfile) -> list[Finding]:
    starts: dict[tuple[str, int], list[HuntEvent]] = defaultdict(list)
    for event in events:
        if event.kind in {"goal_start", "goal"} and event.outcome.lower() not in {
            "succeeded", "completed",
        }:
            starts[(event.actor, int(event.observed_at // 3600))].append(event)
    findings = []
    for (actor, _hour), matches in sorted(starts.items()):
        history = baseline.hourly_counts.get(f"{actor}|goal_start", ())
        threshold = _rate_threshold(history)
        if len(matches) > threshold:
            findings.append(_finding(
                "LW-PLAT-010", "Goal-creation burst", "medium",
                f"{len(matches)} goals started in one hour; deterministic threshold is {threshold:g}",
                ("T1499",), matches,
                containment="Throttle goal creation and inspect the initiating principal.",
            ))
    return findings


_RULES: tuple[Callable[[tuple[HuntEvent, ...], BaselineProfile], list[Finding]], ...] = (
    _shield_bypass,
    _novel_tools,
    _approval_escalation,
    _prompt_injection,
    _exfiltration_sequence,
    _self_modification,
    _budget_and_rate,
    _operator_anomaly,
    _quorum_abuse,
    _goal_anomaly,
)


def _chain_finding(status: ChainIntegrityStatus) -> Finding | None:
    if status.intact:
        return None
    row = {
        "event_id": deterministic_id("chain", status.paths_checked, status.breaks),
        "ts": status.checked_at,
        "kind": "audit_chain_break",
        "actor": "system",
        "action": "verify",
        "outcome": "failed",
        "paths": status.paths_checked,
        "breaks": status.breaks,
    }
    event = HuntEvent.from_mapping("audit.integrity", row)
    return _finding(
        "LW-PLAT-000", "Signed audit chain integrity failure", "critical",
        f"Audit verification reported {len(status.breaks)} break(s)",
        ("T1565.001",), [event],
        containment="Stop promotion and response workflows; preserve and inspect the audit media.",
        metadata={"chain_status": asdict(status)},
    )


def _audit_finding(recorder: AuditRecorder | None, finding: Finding) -> bool:
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
            return bool(recorder("platform_hunt_detection", payload))
        except AuditRefused:
            raise
        except Exception:  # failure-policy: visible_degradation
            return False
    try:
        from ..audit import record

        return bool(record("platform_hunt_detection", **payload))
    except AuditRefused:
        raise
    except Exception:  # failure-policy: visible_degradation
        return False


def scan(
    events: Iterable[HuntEvent],
    *,
    baseline_events: Iterable[HuntEvent] = (),
    chain_status: ChainIntegrityStatus | None = None,
    now: float | None = None,
    audit_recorder: AuditRecorder | None = None,
) -> HuntReport:
    """Run all rules in a stable order and return de-duplicated findings.

    ``now`` is accepted for scheduler/API symmetry but does not influence rule
    verdicts; replaying the same event sets always produces the same findings.
    A supplied ``chain_status`` selects production trust semantics: only events
    normalized from the verified audit chain or verified budget-receipt ledger
    may drive a verdict. Mutable world-model snapshots cannot become evidence by
    merely being passed beside an intact chain result.
    """
    del now
    ordered = tuple(sorted(events, key=lambda item: (item.observed_at, item.event_id)))
    telemetry_trusted = chain_status is None or chain_status.intact
    verdict_events = ordered
    trusted_baseline = tuple(baseline_events)
    if chain_status is not None:
        authoritative_sources = {"audit", "budget.receipts"}
        verdict_events = tuple(
            event for event in ordered if event.source in authoritative_sources
        )
        trusted_baseline = tuple(
            event for event in trusted_baseline
            if event.source in authoritative_sources
        )
    baseline = build_baseline(trusted_baseline if telemetry_trusted else ())
    findings: dict[str, Finding] = {}
    if chain_status is not None:
        chain_finding = _chain_finding(chain_status)
        if chain_finding is not None:
            findings[chain_finding.finding_id] = chain_finding
    if telemetry_trusted:
        for rule in _RULES:
            for finding in rule(verdict_events, baseline):
                findings[finding.finding_id] = finding
    ranked = tuple(sorted(
        findings.values(),
        key=lambda item: (-item.score, item.rule_id, item.finding_id),
    ))
    audited = sum(_audit_finding(audit_recorder, finding) for finding in ranked)
    return HuntReport(ranked, len(ordered), baseline, chain_status, audited)


__all__ = ["build_baseline", "enabled", "scan"]
