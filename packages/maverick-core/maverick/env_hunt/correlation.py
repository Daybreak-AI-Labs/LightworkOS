"""Deterministic multi-source correlations and ATT&CK attack-chain assembly."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from ..platform_hunt.models import Finding, deterministic_id
from .models import TelemetryEvent

_INITIAL = (
    "consolelogin", "user.session.start", "signin", "login", "authentication",
)
_PERSISTENCE = (
    "createaccesskey", "clusterrolebinding", "application.lifecycle.create",
    "add service principal", "create service account", "scheduledtask",
)
_EXFIL = ("upload", "putobject", "data transfer", "archive", "exfil")


def _stage(event: TelemetryEvent) -> str | None:
    action = f"{event.action} {event.target}".lower()
    if any(marker in action for marker in _INITIAL) and event.outcome not in {
        "failure", "failed", "denied",
    }:
        return "initial_access"
    if any(marker in action for marker in _PERSISTENCE):
        return "persistence"
    try:
        large_outbound = float(event.attributes.get("bytes_out", 0)) >= 10 * 1024 * 1024
    except (TypeError, ValueError):
        large_outbound = False
    if large_outbound or any(marker in action for marker in _EXFIL):
        return "exfiltration"
    return None


def _scope(event: TelemetryEvent) -> str:
    return event.principal or event.target or "unknown"


def correlate(
    events: Iterable[TelemetryEvent], findings: Iterable[Finding] = (),
    *, window_seconds: float = 24 * 3600,
) -> tuple[Finding, ...]:
    """Correlate initial access -> persistence -> exfiltration by principal.

    Existing findings are accepted to keep the public seam stable; correlation
    is deliberately event-grounded and never treats an LLM or prior severity as
    evidence for a new verdict.
    """
    del findings
    grouped: dict[str, list[tuple[TelemetryEvent, str]]] = defaultdict(list)
    for event in sorted(events, key=lambda item: (item.observed_at, item.event_id)):
        stage = _stage(event)
        if stage:
            grouped[_scope(event)].append((event, stage))
    out = []
    for scope, staged in sorted(grouped.items()):
        for index, (initial, initial_stage) in enumerate(staged):
            if initial_stage != "initial_access":
                continue
            persistence = next((
                event for event, stage in staged[index + 1:]
                if stage == "persistence"
                and 0 <= event.observed_at - initial.observed_at <= window_seconds
            ), None)
            if persistence is None:
                continue
            exfiltration = next((
                event for event, stage in staged[index + 1:]
                if stage == "exfiltration"
                and 0 <= event.observed_at - persistence.observed_at <= window_seconds
            ), None)
            if exfiltration is None:
                continue
            chain = (initial, persistence, exfiltration)
            evidence = tuple(event.evidence(
                f"attack-chain stage={stage}; event={event.event_id}; action={event.action}"
            ) for event, stage in zip(chain, ("initial_access", "persistence", "exfiltration"), strict=True))
            out.append(Finding(
                finding_id=deterministic_id(
                    "ef", "LW-CORR-001", tuple(event.event_id for event in chain),
                ),
                rule_id="LW-CORR-001",
                title="Correlated initial-access to exfiltration chain",
                severity="critical",
                verdict=(
                    f"{scope} produced ordered initial-access, persistence, and "
                    f"exfiltration evidence within {window_seconds:g} seconds"
                ),
                mitre_techniques=("T1078", "T1098", "T1041"),
                evidence=evidence,
                score=98,
                suggested_containment=(
                    "Propose isolation of the affected host and revocation of the cited identity."
                ),
                created_at=exfiltration.observed_at,
                metadata={
                    "scope": scope,
                    "stages": ["initial_access", "persistence", "exfiltration"],
                },
            ))
            break
    return tuple(out)


__all__ = ["correlate"]
