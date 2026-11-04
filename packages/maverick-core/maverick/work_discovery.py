"""Ekko work discovery primitives.

Ekko learns *the shape of work*, not the contents of a person's screen.  This
module deliberately accepts only a small semantic event vocabulary.  There is
no field for a window title, URL, file name, keystroke, clipboard value, prompt,
or document body, so those values cannot accidentally cross the core capture
boundary.

Discovery and drafting are deterministic and provider-free.  A draft returned
by :func:`draft_bundle` is an in-memory proposal only: this module never saves a
flow, provisions an agent, calls a provider, or executes a tool.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from itertools import islice
from typing import Any

DEFAULT_RETENTION_DAYS = 14
MAX_RETENTION_DAYS = 30
DEFAULT_MIN_OCCURRENCES = 3
DEFAULT_MIN_DISTINCT_DAYS = 2
MAX_PATTERN_LENGTH = 6
MAX_DISCOVERY_EVENTS = 50_000
MAX_CANDIDATES = 20
MAX_SEQUENCE_GAP_SECONDS = 30 * 60

# Canonical application identifiers.  Platform adapters may map a process name
# to one of these values, but an unknown process is never persisted as-is.
KNOWN_APPS = frozenset({
    "browser", "chrome", "edge", "firefox", "safari",
    "spreadsheet", "excel", "google_sheets",
    "presentation", "powerpoint", "google_slides",
    "document", "word", "google_docs",
    "file_manager", "file_explorer", "finder",
    "analytics", "power_bi", "tableau",
    "database", "crm", "salesforce", "erp", "sap",
    "email", "outlook", "gmail", "chat", "teams", "slack",
    "lightwork",
})

ACTION_KINDS = frozenset({
    "activate", "open", "view", "download", "upload", "create", "edit",
    "save", "export", "refresh", "query", "send", "close", "switch",
})

OBJECT_KINDS = frozenset({
    "none", "report", "dashboard", "spreadsheet", "presentation",
    "document", "pdf", "email", "message", "record", "folder", "file",
    "archive",
})
SENSITIVE_OBJECT_KINDS = frozenset({"email", "message", "record"})
GUIDED_OBJECT_KINDS = OBJECT_KINDS - SENSITIVE_OBJECT_KINDS
APPLICATION_METADATA_ACTIONS = frozenset({"switch"})
APPLICATION_METADATA_OBJECT_TYPES = frozenset({"none"})

# Communication and record systems can expose special-category or personal data
# even through coarse metadata. Their app IDs and guided email/message/record
# object labels remain an immutable block floor in this collector release; a
# future exception needs a separately reviewed consent and classification path.
DEFAULT_BLOCKED_APPS = frozenset({
    "email", "outlook", "gmail", "chat", "teams", "slack", "crm",
    "salesforce", "erp", "sap", "database",
})
DEFAULT_ALLOWED_APPS = frozenset({
    "browser", "chrome", "edge", "firefox", "safari",
    "spreadsheet", "excel", "google_sheets",
    "presentation", "powerpoint", "google_slides",
    "document", "word", "google_docs",
    "file_manager", "file_explorer", "finder",
    "analytics", "power_bi", "tableau", "lightwork",
})

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_MIN_TIMESTAMP = 946_684_800.0   # 2000-01-01
_MAX_TIMESTAMP = 4_102_444_800.0  # 2100-01-01
_MAX_DURATION_SECONDS = 86_400.0


class SessionState(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    HALTED = "halted"


@dataclass(frozen=True)
class CapturePolicy:
    """Client-selected boundary for an Ekko capture session.

    ``allowed_apps`` is a positive allowlist and ``blocked_apps`` always wins.
    Unknown identifiers are policy errors.  Provider egress is intentionally
    unsupported in this local-first capture core.
    """

    enabled: bool = False
    capture_level: str = "application_metadata"
    allowed_apps: frozenset[str] = field(default_factory=lambda: DEFAULT_ALLOWED_APPS)
    blocked_apps: frozenset[str] = field(default_factory=lambda: DEFAULT_BLOCKED_APPS)
    allowed_actions: frozenset[str] = field(
        default_factory=lambda: APPLICATION_METADATA_ACTIONS
    )
    allowed_object_types: frozenset[str] = field(
        default_factory=lambda: APPLICATION_METADATA_OBJECT_TYPES
    )
    retention_days: int = DEFAULT_RETENTION_DAYS
    min_occurrences: int = DEFAULT_MIN_OCCURRENCES
    min_distinct_days: int = DEFAULT_MIN_DISTINCT_DAYS
    poll_interval_seconds: float = 5.0
    provider_egress: bool = False

    def __post_init__(self) -> None:
        for name in ("allowed_apps", "blocked_apps", "allowed_actions", "allowed_object_types"):
            raw = getattr(self, name)
            object.__setattr__(self, name, frozenset(str(v).strip().lower() for v in raw))
        # Sensitive communication and system-of-record apps are an immutable
        # floor in this collector release. A future exception needs its own
        # reviewed data-classification and consent path, not an empty list.
        object.__setattr__(
            self,
            "blocked_apps",
            self.blocked_apps | DEFAULT_BLOCKED_APPS,
        )

    @classmethod
    def from_config(cls, config: Mapping[str, Any] | None) -> CapturePolicy:
        """Normalize ``get_ekko()`` output into the canonical capture boundary.

        An empty configured application list means deny-all (and therefore an
        invalid enrollment), not the dataclass's convenient disabled default.
        Built-in sensitive blocks are a floor; configuration may only add to it.
        """
        cfg = dict(config or {})
        allowed = cfg.get("allowed_apps") or []
        blocked = DEFAULT_BLOCKED_APPS | frozenset(cfg.get("blocked_apps") or [])
        capture_level = str(cfg.get("capture_level", "application_metadata"))
        default_actions = (
            ACTION_KINDS if capture_level == "guided"
            else APPLICATION_METADATA_ACTIONS
        )
        default_objects = (
            GUIDED_OBJECT_KINDS if capture_level == "guided"
            else APPLICATION_METADATA_OBJECT_TYPES
        )
        return cls(
            enabled=cfg.get("enable", cfg.get("enabled", False)),
            capture_level=capture_level,
            allowed_apps=frozenset(allowed),
            blocked_apps=frozenset(blocked),
            allowed_actions=frozenset(cfg.get("allowed_actions") or default_actions),
            allowed_object_types=frozenset(
                cfg.get("allowed_object_types") or default_objects
            ),
            retention_days=cfg.get("retention_days", DEFAULT_RETENTION_DAYS),
            min_occurrences=cfg.get("min_occurrences", DEFAULT_MIN_OCCURRENCES),
            min_distinct_days=cfg.get(
                "min_distinct_days", DEFAULT_MIN_DISTINCT_DAYS,
            ),
            poll_interval_seconds=cfg.get("poll_interval_seconds", 5.0),
            provider_egress=cfg.get("provider_egress", False),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CapturePolicy:
        expected = {
            "enabled", "capture_level", "allowed_apps", "blocked_apps",
            "allowed_actions", "allowed_object_types", "retention_days",
            "min_occurrences", "min_distinct_days", "poll_interval_seconds",
            "provider_egress",
        }
        if set(value) - expected:
            raise ValueError("capture policy contains unknown fields")
        return cls(
            enabled=value.get("enabled", False),
            capture_level=str(value.get("capture_level", "application_metadata")),
            allowed_apps=frozenset(value.get("allowed_apps") or []),
            blocked_apps=frozenset(value.get("blocked_apps") or DEFAULT_BLOCKED_APPS),
            allowed_actions=frozenset(value.get("allowed_actions") or []),
            allowed_object_types=frozenset(value.get("allowed_object_types") or []),
            retention_days=value.get("retention_days", DEFAULT_RETENTION_DAYS),
            min_occurrences=value.get("min_occurrences", DEFAULT_MIN_OCCURRENCES),
            min_distinct_days=value.get(
                "min_distinct_days", DEFAULT_MIN_DISTINCT_DAYS,
            ),
            poll_interval_seconds=value.get("poll_interval_seconds", 5.0),
            provider_egress=value.get("provider_egress", False),
        )

    def validation_errors(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.enabled, bool):
            errors.append("enabled must be a boolean")
        if self.capture_level not in {"application_metadata", "guided"}:
            errors.append("capture_level must be application_metadata or guided")
        unknown_apps = (self.allowed_apps | self.blocked_apps) - KNOWN_APPS
        if unknown_apps:
            errors.append("unknown application identifiers: " + ", ".join(sorted(unknown_apps)))
        unknown_actions = self.allowed_actions - ACTION_KINDS
        if unknown_actions:
            errors.append("unknown action kinds: " + ", ".join(sorted(unknown_actions)))
        unknown_objects = self.allowed_object_types - OBJECT_KINDS
        if unknown_objects:
            errors.append("unknown object kinds: " + ", ".join(sorted(unknown_objects)))
        sensitive_objects = self.allowed_object_types & SENSITIVE_OBJECT_KINDS
        if sensitive_objects:
            errors.append(
                "sensitive object kinds are not supported: "
                + ", ".join(sorted(sensitive_objects))
            )
        if not self.allowed_apps:
            errors.append("allowed_apps must not be empty")
        if not self.allowed_actions:
            errors.append("allowed_actions must not be empty")
        if not self.allowed_object_types:
            errors.append("allowed_object_types must not be empty")
        if self.capture_level == "application_metadata":
            if self.allowed_actions != APPLICATION_METADATA_ACTIONS:
                errors.append(
                    "application_metadata permits only the switch action"
                )
            if self.allowed_object_types != APPLICATION_METADATA_OBJECT_TYPES:
                errors.append(
                    "application_metadata permits only object_type none"
                )
        if not isinstance(self.retention_days, int) or not 1 <= self.retention_days <= MAX_RETENTION_DAYS:
            errors.append(f"retention_days must be between 1 and {MAX_RETENTION_DAYS}")
        if not isinstance(self.min_occurrences, int) or not 2 <= self.min_occurrences <= 100:
            errors.append("min_occurrences must be between 2 and 100")
        if not isinstance(self.min_distinct_days, int) or not 2 <= self.min_distinct_days <= 30:
            errors.append("min_distinct_days must be between 2 and 30")
        elif isinstance(self.retention_days, int) and self.min_distinct_days > self.retention_days:
            errors.append("min_distinct_days cannot exceed retention_days")
        try:
            poll = float(self.poll_interval_seconds)
        except (TypeError, ValueError):
            poll = 0.0
        if not 0.25 <= poll <= 3600.0:
            errors.append("poll_interval_seconds must be between 0.25 and 3600")
        if self.provider_egress is not False:
            errors.append("provider_egress is not supported for work discovery")
        return errors

    def require_valid(self, *, require_enabled: bool = False) -> None:
        errors = self.validation_errors()
        if require_enabled and not self.enabled:
            errors.append("work discovery is not enabled")
        if errors:
            raise ValueError("invalid capture policy: " + "; ".join(errors))

    def allows(self, activity: ObservedActivity | WorkEvent) -> bool:
        return bool(
            self.enabled
            and activity.app in self.allowed_apps
            and activity.app not in self.blocked_apps
            and activity.action in self.allowed_actions
            and activity.object_type in self.allowed_object_types
            and activity.object_type not in SENSITIVE_OBJECT_KINDS
        )

    def fingerprint(self) -> str:
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "capture_level": self.capture_level,
            "allowed_apps": sorted(self.allowed_apps),
            "blocked_apps": sorted(self.blocked_apps),
            "allowed_actions": sorted(self.allowed_actions),
            "allowed_object_types": sorted(self.allowed_object_types),
            "retention_days": self.retention_days,
            "min_occurrences": self.min_occurrences,
            "min_distinct_days": self.min_distinct_days,
            "poll_interval_seconds": float(self.poll_interval_seconds),
            "provider_egress": self.provider_egress,
        }


def _validate_semantic(app: str, action: str, object_type: str, duration: float) -> None:
    if app not in KNOWN_APPS:
        raise ValueError("unknown application identifier")
    if action not in ACTION_KINDS:
        raise ValueError("unknown action kind")
    if object_type not in OBJECT_KINDS:
        raise ValueError("unknown object kind")
    if not math.isfinite(duration) or not 0.0 <= duration <= _MAX_DURATION_SECONDS:
        raise ValueError("duration_seconds is outside the allowed range")


@dataclass(frozen=True)
class ObservedActivity:
    """One content-free observation emitted by an explicitly supplied adapter."""

    app: str
    action: str
    object_type: str = "none"
    duration_seconds: float = 0.0

    def __post_init__(self) -> None:
        app = str(self.app).strip().lower()
        action = str(self.action).strip().lower()
        object_type = str(self.object_type).strip().lower()
        duration = float(self.duration_seconds)
        _validate_semantic(app, action, object_type, duration)
        object.__setattr__(self, "app", app)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "object_type", object_type)
        object.__setattr__(self, "duration_seconds", duration)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_mapping(value: Mapping[str, Any]) -> ObservedActivity:
        # Enumerating accepted keys prevents an adapter from smuggling raw text
        # (window_title/url/path/etc.) through an ignored extension field.
        expected = {"app", "action", "object_type", "duration_seconds"}
        extras = set(value) - expected
        if extras:
            raise ValueError("observation contains forbidden fields")
        return ObservedActivity(
            app=str(value.get("app", "")),
            action=str(value.get("action", "")),
            object_type=str(value.get("object_type", "none")),
            duration_seconds=float(value.get("duration_seconds", 0.0)),
        )


@dataclass(frozen=True)
class WorkEvent:
    """A sequenced, content-free event inside one explicit capture session."""

    event_id: str
    session_id: str
    sequence: int
    occurred_at: float
    app: str
    action: str
    object_type: str = "none"
    duration_seconds: float = 0.0

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(str(self.event_id)):
            raise ValueError("invalid event_id")
        if not _ID_RE.fullmatch(str(self.session_id)):
            raise ValueError("invalid session_id")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 1:
            raise ValueError("sequence must be a positive integer")
        occurred = float(self.occurred_at)
        if not math.isfinite(occurred) or not _MIN_TIMESTAMP <= occurred <= _MAX_TIMESTAMP:
            raise ValueError("occurred_at is outside the allowed range")
        app = str(self.app).strip().lower()
        action = str(self.action).strip().lower()
        object_type = str(self.object_type).strip().lower()
        duration = float(self.duration_seconds)
        _validate_semantic(app, action, object_type, duration)
        object.__setattr__(self, "occurred_at", occurred)
        object.__setattr__(self, "app", app)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "object_type", object_type)
        object.__setattr__(self, "duration_seconds", duration)

    @property
    def day(self) -> str:
        return datetime.fromtimestamp(self.occurred_at, tz=timezone.utc).date().isoformat()

    def semantic_key(self) -> tuple[str, str, str]:
        return self.app, self.action, self.object_type

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(value: Mapping[str, Any]) -> WorkEvent:
        expected = {
            "event_id", "session_id", "sequence", "occurred_at", "app", "action",
            "object_type", "duration_seconds",
        }
        if set(value) - expected:
            raise ValueError("event contains forbidden fields")
        return WorkEvent(
            event_id=str(value.get("event_id", "")),
            session_id=str(value.get("session_id", "")),
            sequence=int(value.get("sequence", 0)),
            occurred_at=float(value.get("occurred_at", 0.0)),
            app=str(value.get("app", "")),
            action=str(value.get("action", "")),
            object_type=str(value.get("object_type", "none")),
            duration_seconds=float(value.get("duration_seconds", 0.0)),
        )


@dataclass(frozen=True)
class WorkSession:
    session_id: str
    state: SessionState
    policy_digest: str
    started_at: float
    updated_at: float
    ended_at: float | None = None
    last_sequence: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        return d


@dataclass(frozen=True)
class Enrollment:
    active: bool
    policy_digest: str
    enrolled_at: float
    updated_at: float
    expires_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StepSignature:
    app: str
    action: str
    object_type: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class OpportunityEvidence:
    session_id: str
    day: str
    start_sequence: int
    end_sequence: int
    event_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["event_ids"] = list(self.event_ids)
        return d


@dataclass(frozen=True)
class WorkOpportunity:
    opportunity_id: str
    title: str
    pattern: tuple[StepSignature, ...]
    occurrences: int
    distinct_days: int
    confidence: float
    opportunity_score: float
    estimated_minutes_per_run: float | None
    risk: str
    evidence: tuple[OpportunityEvidence, ...]

    @property
    def observation_basis(self) -> str:
        return (
            "application_metadata"
            if all(step.action == "switch" and step.object_type == "none" for step in self.pattern)
            else "guided"
        )

    def to_dict(self) -> dict[str, Any]:
        result = {
            "opportunity_id": self.opportunity_id,
            "title": self.title,
            "pattern": [step.to_dict() for step in self.pattern],
            "occurrences": self.occurrences,
            "distinct_days": self.distinct_days,
            "confidence": self.confidence,
            "opportunity_score": self.opportunity_score,
            "estimated_minutes_per_run": self.estimated_minutes_per_run,
            "risk": self.risk,
            "evidence": [item.to_dict() for item in self.evidence],
            "observation_basis": self.observation_basis,
            "confidence_kind": "recurrence_heuristic",
            "review_required": True,
            "timing_basis": "recorded_step_durations" if self.estimated_minutes_per_run is not None else "unknown",
        }
        result["evidence_revision"] = hashlib.sha256(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return result


@dataclass
class DraftBundle:
    """Reviewable in-memory artifacts; persistence and execution are separate."""

    opportunity: WorkOpportunity
    demonstration: Any
    profile: Any
    flow: Any
    unsaved: bool = True
    requires_human_approval: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "opportunity": self.opportunity.to_dict(),
            "demonstration": asdict(self.demonstration),
            "profile": asdict(self.profile),
            "flow": self.flow.to_dict(),
            "unsaved": self.unsaved,
            "requires_human_approval": self.requires_human_approval,
        }


@dataclass
class _Candidate:
    pattern: tuple[tuple[str, str, str], ...]
    evidence: list[OpportunityEvidence] = field(default_factory=list)
    durations: list[float] = field(default_factory=list)


def _candidate_windows(by_session, max_pattern_length):
    candidates: dict[tuple[tuple[str, str, str], ...], _Candidate] = {}
    for session_id in sorted(by_session):
        ordered = sorted(by_session[session_id], key=lambda e: (e.sequence, e.event_id))
        last_end: dict[tuple, int] = {}
        for length in range(2, min(max_pattern_length, len(ordered)) + 1):
            for start in range(len(ordered) - length + 1):
                window = ordered[start:start + length]
                if any(
                    b.sequence != a.sequence + 1
                    or not 0 <= b.occurred_at - a.occurred_at <= MAX_SEQUENCE_GAP_SECONDS
                    for a, b in zip(window, window[1:], strict=False)
                ):
                    continue
                pattern = tuple(event.semantic_key() for event in window)
                # One repeated action and periodic loops are not new tasks.
                if any(all(step == pattern[index % size] for index, step in enumerate(pattern))
                       for size in range(1, length // 2 + 1)):
                    continue
                # A recorded event may support only one occurrence of this pattern.
                if window[0].sequence <= last_end.get(pattern, -1):
                    continue
                last_end[pattern] = window[-1].sequence
                candidate = candidates.setdefault(pattern, _Candidate(pattern))
                candidate.evidence.append(OpportunityEvidence(
                    session_id=session_id, day=window[0].day,
                    start_sequence=window[0].sequence, end_sequence=window[-1].sequence,
                    event_ids=tuple(event.event_id for event in window),
                ))
                # Foreground intervals precede app switches; they are not task effort.
                candidate.durations.append(
                    sum(event.duration_seconds for event in window)
                    if all(event.duration_seconds > 0 and event.action != "switch" for event in window)
                    else 0.0
                )
    return candidates.values()


def _evidence_sample(evidence):
    """Represent distinct days before filling the bounded evidence preview."""
    ordered = sorted(evidence, key=lambda e: (e.day, e.session_id, e.start_sequence))
    first_by_day = {item.day: item for item in reversed(ordered)}
    first = sorted(first_by_day.values(), key=lambda e: e.day, reverse=True)[:20]
    sampled = set(first)
    return tuple(sorted((first + [e for e in ordered if e not in sampled])[:20],
                        key=lambda e: (e.day, e.session_id, e.start_sequence)))


def discover_candidates(
    events: Iterable[WorkEvent], *, min_occurrences: int = DEFAULT_MIN_OCCURRENCES,
    min_distinct_days: int = DEFAULT_MIN_DISTINCT_DAYS,
    max_pattern_length: int = MAX_PATTERN_LENGTH,
    max_candidates: int = MAX_CANDIDATES,
) -> list[WorkOpportunity]:
    """Mine recurring contiguous work patterns across distinct UTC days.

    A same-day loop is never enough evidence.  Every returned candidate meets
    both the occurrence threshold and the distinct-day threshold.
    """
    if not 2 <= int(min_occurrences) <= 100:
        raise ValueError("min_occurrences must be between 2 and 100")
    if not 2 <= int(min_distinct_days) <= 30:
        raise ValueError("min_distinct_days must be between 2 and 30")
    if not 2 <= int(max_pattern_length) <= MAX_PATTERN_LENGTH:
        raise ValueError(f"max_pattern_length must be between 2 and {MAX_PATTERN_LENGTH}")
    if not 1 <= int(max_candidates) <= MAX_CANDIDATES:
        raise ValueError(f"max_candidates must be between 1 and {MAX_CANDIDATES}")

    materialized = list(islice(events, MAX_DISCOVERY_EVENTS + 1))
    if len(materialized) > MAX_DISCOVERY_EVENTS:
        raise ValueError(f"discovery accepts at most {MAX_DISCOVERY_EVENTS} events")
    by_session: dict[str, list[WorkEvent]] = defaultdict(list)
    seen_ids: set[str] = set()
    for event in materialized:
        if not isinstance(event, WorkEvent):
            raise TypeError("events must contain WorkEvent values")
        if event.event_id in seen_ids:
            continue
        seen_ids.add(event.event_id)
        by_session[event.session_id].append(event)

    opportunities: list[WorkOpportunity] = []
    for candidate in _candidate_windows(by_session, max_pattern_length):
        days = {item.day for item in candidate.evidence}
        occurrences = len(candidate.evidence)
        if occurrences < min_occurrences or len(days) < min_distinct_days:
            continue
        confidence = min(
            0.97,
            0.45
            + 0.12 * min(len(days) - 1, 3)
            + 0.04 * min(occurrences - len(days), 4)
            + 0.03 * min(len(candidate.pattern) - 2, 3),
        )
        minutes = statistics.median(candidate.durations) / 60.0 if all(candidate.durations) else None
        risk = _pattern_risk(candidate.pattern)
        recurrence = min(1.0, len(days) / 5.0)
        time_value = min(1.0, math.log1p(minutes or 0) / math.log(31.0))
        risk_penalty = {"low": 0.0, "medium": 8.0, "high": 20.0}[risk]
        score = max(0.0, min(100.0, confidence * 70.0 + recurrence * 15.0 + time_value * 15.0 - risk_penalty))
        canonical = json.dumps(candidate.pattern, separators=(",", ":"))
        opportunity_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
        pattern = tuple(StepSignature(*values) for values in candidate.pattern)
        opportunities.append(WorkOpportunity(
            opportunity_id=opportunity_id,
            title=_opportunity_title(pattern),
            pattern=pattern,
            occurrences=occurrences,
            distinct_days=len(days),
            confidence=round(confidence, 3),
            opportunity_score=round(score, 1),
            estimated_minutes_per_run=round(minutes, 1) if minutes is not None else None,
            risk=risk,
            evidence=_evidence_sample(candidate.evidence),
        ))

    # Prefer the most useful maximal explanation and suppress a shorter slice of
    # a pattern already selected.  This avoids three cards for A->B, B->C, A->B->C.
    opportunities.sort(
        key=lambda item: (item.opportunity_score, len(item.pattern), item.distinct_days, item.opportunity_id),
        reverse=True,
    )
    selected: list[WorkOpportunity] = []
    for item in opportunities:
        signature = tuple((s.app, s.action, s.object_type) for s in item.pattern)
        if any(_is_contiguous_subsequence(
            signature,
            tuple((s.app, s.action, s.object_type) for s in chosen.pattern),
        ) and chosen.occurrences >= item.occurrences
          and chosen.distinct_days >= item.distinct_days for chosen in selected):
            continue
        selected.append(item)
        if len(selected) >= max_candidates:
            break
    return selected


def _is_contiguous_subsequence(needle: Sequence[Any], haystack: Sequence[Any]) -> bool:
    if len(needle) >= len(haystack):
        return False
    return any(tuple(haystack[i:i + len(needle)]) == tuple(needle)
               for i in range(len(haystack) - len(needle) + 1))


def _pattern_risk(pattern: Sequence[tuple[str, str, str]]) -> str:
    sensitive_apps = DEFAULT_BLOCKED_APPS
    sensitive_objects = {"email", "message", "record"}
    outbound_actions = {"upload", "send"}
    if any(app in sensitive_apps or obj in sensitive_objects for app, _, obj in pattern):
        return "high"
    if any(action in outbound_actions for _, action, _ in pattern):
        return "medium"
    return "low"


_APP_LABELS = {
    "excel": "Microsoft Excel", "powerpoint": "Microsoft PowerPoint",
    "chrome": "Google Chrome", "edge": "Microsoft Edge",
    "google_sheets": "Google Sheets", "google_slides": "Google Slides",
    "google_docs": "Google Docs", "file_manager": "file manager",
    "file_explorer": "File Explorer", "power_bi": "Power BI",
}


def _step_label(step: StepSignature) -> str:
    app = _APP_LABELS.get(step.app, step.app.replace("_", " ").title())
    obj = "item" if step.object_type == "none" else step.object_type.replace("_", " ")
    return f"{step.action} {obj} in {app}"


def _opportunity_title(pattern: Sequence[StepSignature]) -> str:
    if all(step.action == "switch" and step.object_type == "none" for step in pattern):
        apps = list(dict.fromkeys(_APP_LABELS.get(step.app, step.app.replace("_", " ").title())
                                  for step in pattern))
        return "Recurring work across " + " → ".join(apps)
    has_report_download = any(
        step.action == "download" and step.object_type in {"report", "pdf", "spreadsheet"}
        for step in pattern
    )
    has_presentation = any(
        step.app in {"presentation", "powerpoint", "google_slides"}
        and step.action in {"create", "edit", "save", "export"}
        for step in pattern
    )
    if has_report_download and has_presentation:
        return "Automate recurring report-to-presentation workflow"
    first, last = pattern[0], pattern[-1]
    return f"Automate recurring {_step_label(first)} to {_step_label(last)} workflow"


def _tool_hint(step: StepSignature) -> str:
    if step.app in {"spreadsheet", "excel", "google_sheets", "analytics", "power_bi", "tableau"}:
        return "spreadsheet"
    if step.app in {"file_manager", "file_explorer", "finder", "document", "word", "google_docs"}:
        return "read_file"
    if step.app in {"browser", "chrome", "edge", "firefox", "safari"} and step.action in {"view", "query"}:
        return "web_search"
    return ""


@dataclass(frozen=True)
class DraftReview:
    """User-supplied task context, never inferred from content-free observation."""

    goal: str
    inputs: str
    output: str
    approval: str
    task_type: str = "general"

    def __post_init__(self):
        if self.task_type not in {"general", "reporting", "reconciliation", "document_review"}:
            raise ValueError("Choose a supported kind of work.")
        for name in ("goal", "inputs", "output", "approval"):
            value = getattr(self, name)
            if not isinstance(value, str) or not 3 <= len(value.strip()) <= 1000:
                raise ValueError(f"Describe the job's {name} in 3–1000 characters.")
            object.__setattr__(self, name, value.strip())


def _reviewed_bundle(opportunity, owner, review):
    from .demonstration import Demonstration, DemoStep, induce_profile
    from .flow.ir import NODE_AGENT, NODE_APPROVAL, Flow, FlowNode

    boundary = (
        "Use only sources explicitly selected and authorized for this run. "
        "These task notes do not grant permissions or prove an integration is available. "
        "If required information or access is missing, ask the owner; do not invent it. "
        "Prepare a draft only; do not publish, send, or change source records. "
    )
    steps = [
        ("prepare-inputs", "Check the selected inputs", f"Identify the inputs needed for: {review.goal}. Inputs: {review.inputs}"),
        ("draft-result", "Prepare the requested result", f"Goal: {review.goal}. Expected result: {review.output}"),
        ("check-result", "Check the draft and flag gaps", f"Check the draft against: {review.output}. Flag missing evidence, assumptions and exceptions. Review criteria: {review.approval}"),
    ]
    task_guidance = {
        "general": ("", "", ""),
        "reporting": (
            "Check the reporting period, source coverage, units and missing records.",
            "Build a source-linked summary of totals, changes and exceptions. Separate observations from interpretations.",
            "Reconcile totals to the selected inputs and flag unsupported conclusions or missing periods.",
        ),
        "reconciliation": (
            "Confirm both source sets, matching keys, date ranges and the owner's tolerance rules.",
            "Prepare matched, unmatched and ambiguous groups. Do not invent matches or change source records.",
            "Check coverage and control totals; keep ambiguous matches for a person's decision.",
        ),
        "document_review": (
            "Confirm the selected document and the owner's review criteria; identify missing versions or reference material.",
            "Prepare a findings table with supporting passages, the applicable criterion and a proposed follow-up.",
            "Check each finding against its source and flag uncertainty. Do not present the review as legal or regulatory approval.",
        ),
    }[review.task_type]
    steps = [(node_id, label, brief + " " + guidance)
             for (node_id, label, brief), guidance in zip(steps, task_guidance, strict=True)]
    demonstration = Demonstration(
        title=review.goal, source="ekko-owner-reviewed-task",
        steps=[DemoStep(kind="action", summary=brief, tool="", target="").normalized()
               for _, _, brief in steps],
    )
    nodes = {
        node_id: FlowNode(id=node_id, kind=NODE_AGENT, label=label,
                          brief=boundary + brief,
                          next=steps[index + 1][0] if index + 1 < len(steps) else "review-result",
                          x=380.0 + index * 260, y=140.0)
        for index, (node_id, label, brief) in enumerate(steps)
    }
    nodes["human-review"] = FlowNode(
        id="human-review", kind=NODE_APPROVAL, next="prepare-inputs", label="Approve inputs and plan",
        prompt=f"Review the selected sources, permissions and plan before starting. Goal: {review.goal}. Inputs: {review.inputs}",
        x=120.0, y=140.0,
    )
    nodes["review-result"] = FlowNode(
        id="review-result", kind=NODE_APPROVAL, label="Review the finished draft",
        prompt=f"Check the output before using or sharing it. {review.approval}", x=1160.0, y=140.0,
    )
    flow = Flow(id=f"ekko-draft-{opportunity.opportunity_id}", name=review.goal,
                start="human-review", nodes=nodes, owner=owner, schedule="", notify=True)
    errors = flow.validate()
    if errors:
        raise ValueError("generated draft flow is invalid: " + "; ".join(map(str, errors)))
    return DraftBundle(opportunity, demonstration, induce_profile(demonstration), flow)


def draft_bundle(opportunity: WorkOpportunity, *, owner: str = "", review: DraftReview | None = None) -> DraftBundle:
    """Build deterministic, UNSAVED flow and agent-factory proposals."""
    if not isinstance(opportunity, WorkOpportunity) or len(opportunity.pattern) < 2:
        raise ValueError("a recurring work opportunity is required")
    if review is not None:
        if not isinstance(review, DraftReview):
            raise ValueError("a validated task review is required")
        return _reviewed_bundle(opportunity, owner, review)
    if opportunity.observation_basis == "application_metadata":
        raise ValueError("Describe the job, inputs, expected output and review before drafting from app activity.")
    from .demonstration import Demonstration, DemoStep, induce_profile
    from .flow.ir import NODE_AGENT, NODE_APPROVAL, Flow, FlowNode

    demo_steps = [
        DemoStep(
            kind="action",
            summary=_step_label(step),
            tool=_tool_hint(step),
            target=step.object_type if step.object_type != "none" else "",
        ).normalized()
        for step in opportunity.pattern
    ]
    demonstration = Demonstration(
        title=opportunity.title,
        steps=demo_steps,
        source="ekko-semantic-observation",
    )
    # No llm argument: this is deliberately the deterministic, provider-free path.
    profile = induce_profile(demonstration)

    nodes: dict[str, FlowNode] = {}
    for index, step in enumerate(opportunity.pattern, 1):
        node_id = f"observed-{index}"
        next_id = f"observed-{index + 1}" if index < len(opportunity.pattern) else None
        nodes[node_id] = FlowNode(
            id=node_id,
            kind=NODE_AGENT,
            next=next_id,
            brief=(
                f"Draft this observed work step: {_step_label(step)}. "
                "Use only approved sources and tools; do not perform irreversible actions."
            ),
            label=_step_label(step),
            x=120.0 + index * 260.0,
            y=140.0,
        )
    nodes["human-review"] = FlowNode(
        id="human-review",
        kind=NODE_APPROVAL,
        next="observed-1",
        prompt=(
            "Review this run's inputs, planned steps, and intended outputs. "
            "Approve before the workflow does any work."
        ),
        label="Human review",
        x=120.0,
        y=140.0,
    )
    flow = Flow(
        id=f"ekko-draft-{opportunity.opportunity_id}",
        name=opportunity.title,
        start="human-review",
        nodes=nodes,
        owner=owner,
        schedule="",
        notify=True,
    )
    errors = flow.validate()
    if errors:
        raise ValueError("generated draft flow is invalid: " + "; ".join(map(str, errors)))
    return DraftBundle(
        opportunity=opportunity,
        demonstration=demonstration,
        profile=profile,
        flow=flow,
    )


# Descriptive alias used by API surfaces.
build_draft_bundle = draft_bundle


__all__ = [
    "ACTION_KINDS", "APPLICATION_METADATA_ACTIONS",
    "APPLICATION_METADATA_OBJECT_TYPES", "CapturePolicy", "DEFAULT_ALLOWED_APPS",
    "DEFAULT_BLOCKED_APPS", "DEFAULT_MIN_DISTINCT_DAYS",
    "DEFAULT_MIN_OCCURRENCES", "DEFAULT_RETENTION_DAYS", "DraftBundle", "DraftReview",
    "Enrollment", "GUIDED_OBJECT_KINDS", "KNOWN_APPS", "MAX_RETENTION_DAYS",
    "OBJECT_KINDS", "ObservedActivity", "OpportunityEvidence",
    "SENSITIVE_OBJECT_KINDS", "SessionState", "StepSignature",
    "WorkEvent", "WorkOpportunity", "WorkSession", "build_draft_bundle",
    "discover_candidates", "draft_bundle",
]
