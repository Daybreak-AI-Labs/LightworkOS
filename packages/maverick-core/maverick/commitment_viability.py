"""Bounded, source-aware feasibility for already accepted business commitments.

This is a decision model, not an inventory or reservation connector. Lots are
fungible within their named resource and become usable at ``ready_at``; the
model does not infer production precedence, quality, or external guarantees.
An option is *only* a conditional path until an independently observed effect
enters as a current lot. Callers must authenticate owners, fetch current source
revisions, persist snapshots/receipts, and execute approved effects separately.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import math
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from typing import Literal

Kind = Literal["capacity", "material"]
Certainty = Literal["confirmed", "unknown", "unavailable"]
Status = Literal["feasible", "unknown", "infeasible"]

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z")
_MAX_COMMITMENTS = 32
_MAX_LOTS = 128
_MAX_OPTIONS = 8
_MAX_TRACES = 128
_MAX_UNITS = 1_000_000


def _name(value: str, label: str) -> None:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a bounded portable identifier")


def _time(value: float, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{label} must be a positive finite timestamp")


def _units(value: int) -> None:
    if type(value) is not int or not 1 <= value <= _MAX_UNITS:
        raise ValueError("units must be a positive bounded integer")


def _kind(value: str) -> None:
    if value not in ("capacity", "material"):
        raise ValueError("resource kind must be capacity or material")


def _unique(values: tuple[object, ...], label: str) -> None:
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")


@dataclass(frozen=True)
class Evidence:
    source_id: str
    revision: str
    observed_at: float
    expires_at: float

    def __post_init__(self) -> None:
        _name(self.source_id, "source_id")
        _name(self.revision, "source revision")
        _time(self.observed_at, "observed_at")
        _time(self.expires_at, "expires_at")
        if self.expires_at <= self.observed_at:
            raise ValueError("evidence must expire after observation")

    def current(self, now: float, revisions: Mapping[str, str]) -> bool:
        return self.observed_at <= now < self.expires_at and revisions.get(self.source_id) == self.revision


@dataclass(frozen=True)
class Demand:
    kind: Kind
    key: str
    units: int

    def __post_init__(self) -> None:
        _kind(self.kind)
        _name(self.key, "resource key")
        _units(self.units)


@dataclass(frozen=True)
class Commitment:
    id: str
    due_at: float
    demands: tuple[Demand, ...]
    acceptance: Evidence

    def __post_init__(self) -> None:
        _name(self.id, "commitment id")
        _time(self.due_at, "due_at")
        if (not isinstance(self.demands, tuple) or not 1 <= len(self.demands) <= 16
                or any(type(item) is not Demand for item in self.demands)):
            raise ValueError("commitment requires one to sixteen demands")
        _unique(tuple((item.kind, item.key) for item in self.demands), "commitment demand keys")
        if type(self.acceptance) is not Evidence:
            raise ValueError("commitment requires source-backed acceptance evidence")


@dataclass(frozen=True)
class Lot:
    id: str
    kind: Kind
    key: str
    units: int
    ready_at: float
    certainty: Certainty
    evidence: Evidence

    def __post_init__(self) -> None:
        _name(self.id, "lot id")
        _kind(self.kind)
        _name(self.key, "lot key")
        _units(self.units)
        _time(self.ready_at, "ready_at")
        if self.certainty not in ("confirmed", "unknown", "unavailable"):
            raise ValueError("lot certainty is unsupported")
        if type(self.evidence) is not Evidence:
            raise ValueError("lot requires source evidence")


@dataclass(frozen=True)
class OwnerConfirmation:
    option_id: str
    option_digest: str
    actor: str
    confirmed_at: float
    source_revision: str

    def __post_init__(self) -> None:
        _name(self.option_id, "confirmed option")
        if not isinstance(self.option_digest, str) or re.fullmatch(r"[0-9a-f]{64}", self.option_digest) is None:
            raise ValueError("confirmed option digest is invalid")
        _name(self.actor, "confirming actor")
        _time(self.confirmed_at, "confirmed_at")
        _name(self.source_revision, "confirmed source revision")


@dataclass(frozen=True)
class ReversibleOption:
    id: str
    kind: Kind
    key: str
    units: int
    ready_at: float
    expires_at: float
    evidence: Evidence
    cost_note: str = ""
    owner_confirmation: OwnerConfirmation | None = None
    lead_seconds: float = 0.0

    def __post_init__(self) -> None:
        _name(self.id, "option id")
        _kind(self.kind)
        _name(self.key, "option key")
        _units(self.units)
        _time(self.ready_at, "option ready_at")
        _time(self.expires_at, "option expires_at")
        if type(self.evidence) is not Evidence:
            raise ValueError("option requires source evidence")
        if not isinstance(self.cost_note, str) or len(self.cost_note) > 240:
            raise ValueError("option cost note is too long")
        if self.owner_confirmation is not None and type(self.owner_confirmation) is not OwnerConfirmation:
            raise ValueError("option owner confirmation is malformed")
        if (isinstance(self.lead_seconds, bool) or not isinstance(self.lead_seconds, (int, float))
                or not math.isfinite(self.lead_seconds) or not 0 <= self.lead_seconds <= 1_000_000_000):
            raise ValueError("option lead time must be finite and nonnegative")
        if self.owner_confirmation is not None and (
            self.owner_confirmation.option_id != self.id
            or self.owner_confirmation.option_digest != _option_digest(self)
            or self.owner_confirmation.source_revision != self.evidence.revision
            or self.owner_confirmation.confirmed_at < self.evidence.observed_at
            or self.owner_confirmation.confirmed_at >= self.expires_at
        ):
            raise ValueError("option confirmation does not match the exact available option")


def _option_digest(option: ReversibleOption) -> str:
    payload = [option.id, option.kind, option.key, option.units,
               option.ready_at, option.expires_at, asdict(option.evidence),
               option.cost_note, option.lead_seconds]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TraceObservation:
    id: str
    commitment_id: str
    resource_key: str
    units: int
    start_at: float
    end_at: float
    blocked: bool
    evidence: Evidence

    def __post_init__(self) -> None:
        _name(self.id, "trace id")
        _name(self.commitment_id, "trace commitment id")
        _name(self.resource_key, "trace resource key")
        _units(self.units)
        _time(self.start_at, "trace start_at")
        _time(self.end_at, "trace end_at")
        if self.end_at <= self.start_at or type(self.blocked) is not bool:
            raise ValueError("trace interval or blocked state is invalid")
        if type(self.evidence) is not Evidence:
            raise ValueError("trace requires source evidence")


@dataclass(frozen=True)
class DependencyProposal:
    id: str
    snapshot_digest: str
    left_id: str
    right_id: str
    resource_key: str
    left_units: int
    right_units: int
    trace_ids: tuple[str, str]
    trace_digest: str
    evidence: tuple[Evidence, Evidence]


@dataclass(frozen=True)
class SharedDependency:
    left_id: str
    right_id: str
    resource_key: str
    left_units: int
    right_units: int
    proposal_id: str
    confirmed_by: str
    confirmed_at: float

    def __post_init__(self) -> None:
        for label, value in (("left commitment", self.left_id), ("right commitment", self.right_id),
                             ("resource key", self.resource_key), ("proposal id", self.proposal_id),
                             ("confirming actor", self.confirmed_by)):
            _name(value, label)
        _units(self.left_units)
        _units(self.right_units)
        _time(self.confirmed_at, "confirmed_at")


@dataclass(frozen=True)
class Snapshot:
    revision: int
    commitments: tuple[Commitment, ...]
    lots: tuple[Lot, ...]
    options: tuple[ReversibleOption, ...] = ()
    dependencies: tuple[SharedDependency, ...] = ()

    def __post_init__(self) -> None:
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("snapshot revision must be nonnegative")
        for label, values, limit, item_type in (
            ("commitments", self.commitments, _MAX_COMMITMENTS, Commitment),
            ("lots", self.lots, _MAX_LOTS, Lot),
            ("options", self.options, _MAX_OPTIONS, ReversibleOption),
            ("dependencies", self.dependencies, _MAX_TRACES, SharedDependency),
        ):
            if not isinstance(values, tuple) or len(values) > limit or any(type(item) is not item_type for item in values):
                raise ValueError(f"{label} must be a bounded tuple")
        if not self.commitments:
            raise ValueError("snapshot requires accepted commitments")
        _unique(tuple(item.id for item in self.commitments), "commitment ids")
        _unique(tuple(item.id for item in self.lots), "lot ids")
        _unique(tuple(item.id for item in self.options), "option ids")
        ids = {item.id for item in self.commitments}
        for item in self.dependencies:
            if item.left_id not in ids or item.right_id not in ids or item.left_id == item.right_id:
                raise ValueError("dependency must join distinct accepted commitments")
        _unique(tuple((min(item.left_id, item.right_id), max(item.left_id, item.right_id),
                       item.resource_key) for item in self.dependencies), "shared dependencies")


@dataclass(frozen=True)
class ActionPlan:
    """Conditional bundle path; act *before* the reported deadline and recheck.

    ``conditional_status`` assumes the option effects will be observed. Owner
    confirmation records intent only. No plan is proof of an external hold.
    """

    option_ids: tuple[str, ...]
    conditional_status: Status
    latest_safe_bundle_decision_at: float
    requires_owner_confirmation: bool
    external_effect_verified: bool = False


@dataclass(frozen=True)
class ComponentResult:
    commitment_ids: tuple[str, ...]
    status: Status
    plans: tuple[ActionPlan, ...]


@dataclass(frozen=True)
class Assessment:
    """Feasibility inside the declared model, not a guarantee about the world.

    ``latest_safe_bundle_decision_at`` is an exclusive upper bound for taking
    all listed option actions together under currently observed source versions.
    New external changes can invalidate it earlier.
    """

    snapshot_revision: int
    snapshot_digest: str
    evaluated_at: float
    source_revisions_digest: str
    status: Status
    components: tuple[ComponentResult, ...]
    stale_source_ids: tuple[str, ...]
    latest_safe_bundle_decision_at: float | None
    recomputed_commitment_ids: tuple[str, ...]


@dataclass(frozen=True)
class ResourceGap:
    """Reported resource shortfall, not a discovered supplier or deliverable promise.

    ``confirmed_shortfall_units`` excludes uncertain stock and unexercised
    choices. ``remaining_shortfall_units`` is the shortfall even if all usable
    uncertain stock and recorded choices arrive on time. A zero remaining
    shortfall is conditional, never proof that those effects will occur.
    """

    commitment_ids: tuple[str, ...]
    kind: Kind
    key: str
    first_shortfall_at: float
    confirmed_shortfall_units: int
    remaining_shortfall_units: int
    remaining_first_shortfall_at: float | None
    conditional_source_ids: tuple[str, ...]
    option_ids: tuple[str, ...]


def _revision_digest(revisions: Mapping[str, str]) -> str:
    if not isinstance(revisions, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in revisions.items()
    ):
        raise ValueError("current source revisions must be a string mapping")
    if len(revisions) > _MAX_COMMITMENTS + _MAX_LOTS + _MAX_OPTIONS + _MAX_TRACES:
        raise ValueError("current source revision map is too large")
    for key, value in revisions.items():
        _name(key, "current source")
        _name(value, "current source revision")
    raw = json.dumps(sorted(revisions.items()), separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _snapshot_digest(snapshot: Snapshot) -> str:
    raw = json.dumps(asdict(snapshot), sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _effective_demands(snapshot: Snapshot) -> dict[str, tuple[Demand, ...]]:
    demands = {item.id: {(part.kind, part.key): part for part in item.demands} for item in snapshot.commitments}
    for edge in snapshot.dependencies:
        for commitment_id, units in ((edge.left_id, edge.left_units), (edge.right_id, edge.right_units)):
            key = ("capacity", edge.resource_key)
            existing = demands[commitment_id].get(key)
            if existing is None:
                demands[commitment_id][key] = Demand("capacity", edge.resource_key, units)
            elif existing.units != units:
                raise ValueError("confirmed dependency conflicts with a declared demand")
    return {key: tuple(parts.values()) for key, parts in demands.items()}


def _component_ids(snapshot: Snapshot, demands: Mapping[str, tuple[Demand, ...]]) -> tuple[tuple[str, ...], ...]:
    remaining = {item.id for item in snapshot.commitments}
    by_key: dict[tuple[str, str], set[str]] = {}
    for commitment_id, parts in demands.items():
        for part in parts:
            by_key.setdefault((part.kind, part.key), set()).add(commitment_id)
    groups: list[tuple[str, ...]] = []
    while remaining:
        component = {min(remaining)}
        while True:
            expanded = component | set().union(*(
                by_key[(part.kind, part.key)]
                for commitment_id in component for part in demands[commitment_id]
            ))
            if expanded == component:
                break
            component = expanded
        groups.append(tuple(sorted(component)))
        remaining -= component
    return tuple(sorted(groups))


def _covered(
    commitments: tuple[Commitment, ...], demands: Mapping[str, tuple[Demand, ...]],
    lots: tuple[Lot, ...], *, now: float,
) -> bool:
    if any(item.due_at <= now for item in commitments):
        return False
    keys = {(part.kind, part.key) for item in commitments for part in demands[item.id]}
    for key in keys:
        required = sorted((item.due_at, part.units) for item in commitments
                          for part in demands[item.id] if (part.kind, part.key) == key)
        available = sorted((lot.ready_at, lot.units) for lot in lots if (lot.kind, lot.key) == key)
        count = 0
        units = 0
        for due, needed in required:
            while count < len(available) and available[count][0] <= due:
                units += available[count][1]
                count += 1
            if units < needed:
                return False
            units -= needed
    return True


def _resource_shortfall(
    commitments: tuple[Commitment, ...], demands: Mapping[str, tuple[Demand, ...]],
    supply: tuple[tuple[float, int], ...], key: tuple[Kind, str],
) -> tuple[float | None, int]:
    """Maximum cumulative deficit at each due date in the fixed resource model."""
    due_dates = sorted({item.due_at for item in commitments
                        if any((part.kind, part.key) == key for part in demands[item.id])})
    first = None
    maximum = 0
    for due in due_dates:
        needed = sum(part.units for item in commitments if item.due_at <= due
                     for part in demands[item.id] if (part.kind, part.key) == key)
        ready = sum(units for ready_at, units in supply if ready_at <= due)
        deficit = max(0, needed - ready)
        if deficit and first is None:
            first = due
        maximum = max(maximum, deficit)
    return first, maximum


def explain_resource_gaps(
    snapshot: Snapshot, *, now: float, current_source_revisions: Mapping[str, str],
) -> tuple[ResourceGap, ...]:
    """Show bounded, source-aware resource boundaries for the declared model.

    No new external capability is inferred or executed. Expired choices do not
    count; overdue work needs a new review rather than hypothetical rescue.
    """
    _time(now, "now")
    _revision_digest(current_source_revisions)
    demands = _effective_demands(snapshot)
    gaps = []
    for ids in _component_ids(snapshot, demands):
        commitments = tuple(item for item in snapshot.commitments if item.id in ids)
        if any(item.due_at <= now or not item.acceptance.current(now, current_source_revisions)
               for item in commitments):
            continue
        keys = sorted({(part.kind, part.key) for item in commitments
                       for part in demands[item.id]})
        for kind, key in keys:
            lots = tuple(item for item in snapshot.lots if (item.kind, item.key) == (kind, key))
            confirmed = tuple((item.ready_at, item.units) for item in lots
                              if item.certainty == "confirmed"
                              and item.evidence.current(now, current_source_revisions))
            possible_lots = tuple(item for item in lots if item.certainty != "unavailable"
                                  or not item.evidence.current(now, current_source_revisions))
            options = tuple(item for item in snapshot.options
                            if (item.kind, item.key) == (kind, key) and now < item.expires_at)
            possible = tuple((item.ready_at, item.units) for item in possible_lots) + tuple(
                (max(item.ready_at, now + item.lead_seconds), item.units) for item in options
            )
            first, confirmed_units = _resource_shortfall(commitments, demands, confirmed, (kind, key))
            if not confirmed_units or first is None:
                continue
            remaining_first, remaining_units = _resource_shortfall(
                commitments, demands, possible, (kind, key)
            )
            conditional_sources = tuple(sorted(
                {item.evidence.source_id for item in possible_lots
                 if item.certainty != "confirmed" or not item.evidence.current(now, current_source_revisions)}
                | {item.evidence.source_id for item in options
                   if not item.evidence.current(now, current_source_revisions)}
            ))
            gaps.append(ResourceGap(ids, kind, key, first, confirmed_units,
                                    remaining_units, remaining_first, conditional_sources,
                                    tuple(item.id for item in options)))
    return tuple(gaps)


def _state(
    commitments: tuple[Commitment, ...], demands: Mapping[str, tuple[Demand, ...]],
    lots: tuple[Lot, ...], options: tuple[ReversibleOption, ...],
    *, now: float, revisions: Mapping[str, str],
) -> Status:
    if any(not item.acceptance.current(now, revisions) for item in commitments):
        return "unknown"
    if any(item.due_at <= now for item in commitments):
        return "infeasible"
    confirmed = tuple(lot for lot in lots if lot.certainty == "confirmed" and lot.evidence.current(now, revisions))
    possible = tuple(lot for lot in lots if lot.certainty != "unavailable" or not lot.evidence.current(now, revisions))
    for option in options:
        if now >= option.expires_at:
            return "infeasible"
        synthetic = Lot(option.id, option.kind, option.key, option.units,
                        max(option.ready_at, now + option.lead_seconds),
                        "confirmed", option.evidence)
        possible += (synthetic,)
        if option.evidence.current(now, revisions):
            confirmed += (synthetic,)
    if _covered(commitments, demands, confirmed, now=now):
        return "feasible"
    if _covered(commitments, demands, possible, now=now):
        return "unknown"
    return "infeasible"


def _latest_bundle_decision(
    commitments: tuple[Commitment, ...], demands: Mapping[str, tuple[Demand, ...]],
    lots: tuple[Lot, ...], options: tuple[ReversibleOption, ...],
    *, now: float, revisions: Mapping[str, str], desired: Status,
) -> float | None:
    """Latest time to decide on the *whole bundle* under the frozen model.

    Source revision can change at any time; this is a conditional deadline,
    not a promise of future stock. Expiry/due bounds are exclusive when the
    status only holds at their immediately preceding representable timestamp.
    """
    evidence = [*(item.acceptance for item in commitments),
                *(item.evidence for item in lots), *(item.evidence for item in options)]
    strict_bounds = {*(item.due_at for item in commitments),
                     *(item.expires_at for item in options),
                     *(item.expires_at for item in evidence)}
    candidate_times = {(now, now)}
    candidate_times.update((bound, math.nextafter(bound, -math.inf)) for bound in strict_bounds)
    candidate_times.update((item.due_at - option.lead_seconds,
                            item.due_at - option.lead_seconds)
                           for item in commitments for option in options)
    for reported, probe in sorted(candidate_times, reverse=True):
        if probe < now or probe <= 0:
            continue
        state = _state(commitments, demands, lots, options, now=probe, revisions=revisions)
        if state == desired:
            return reported
    return None


def _component(
    ids: tuple[str, ...], snapshot: Snapshot, demands: Mapping[str, tuple[Demand, ...]],
    *, now: float, revisions: Mapping[str, str],
) -> ComponentResult:
    commitments = tuple(item for item in snapshot.commitments if item.id in ids)
    keys = {(part.kind, part.key) for item in commitments for part in demands[item.id]}
    lots = tuple(item for item in snapshot.lots if (item.kind, item.key) in keys)
    state = _state(commitments, demands, lots, (), now=now, revisions=revisions)
    if state == "feasible":
        return ComponentResult(ids, state, ())
    options = tuple(item for item in snapshot.options if (item.kind, item.key) in keys
                    and now < item.expires_at and item.ready_at <= max(c.due_at for c in commitments))
    plans: list[ActionPlan] = []
    for size in range(1, len(options) + 1):
        for subset in itertools.combinations(options, size):
            conditional = _state(commitments, demands, lots, subset, now=now, revisions=revisions)
            if conditional == "infeasible" or (state == "unknown" and conditional != "feasible"):
                continue
            deadline = _latest_bundle_decision(commitments, demands, lots, subset,
                                               now=now, revisions=revisions,
                                               desired=conditional)
            if deadline is None:
                continue
            plans.append(ActionPlan(
                tuple(item.id for item in subset), conditional, deadline,
                any(item.owner_confirmation is None
                    or item.owner_confirmation.confirmed_at > now
                    for item in subset),
            ))
    plans.sort(key=lambda item: (item.conditional_status != "feasible",
                                 -item.latest_safe_bundle_decision_at, len(item.option_ids), item.option_ids))
    return ComponentResult(ids, state, tuple(plans[:_MAX_OPTIONS]))


def _summary(
    snapshot: Snapshot, now: float, revisions: Mapping[str, str],
    components: tuple[ComponentResult, ...], recomputed: tuple[str, ...],
) -> Assessment:
    status: Status = ("infeasible" if any(item.status == "infeasible" for item in components)
                      else "unknown" if any(item.status == "unknown" for item in components)
                      else "feasible")
    stale = sorted({evidence.source_id for evidence in (
        *(item.acceptance for item in snapshot.commitments),
        *(item.evidence for item in snapshot.lots),
        *(item.evidence for item in snapshot.options),
    ) if not evidence.current(now, revisions)})
    next_times: list[float] = []
    for component in components:
        if component.status == "feasible":
            continue
        robust_plans = [item.latest_safe_bundle_decision_at for item in component.plans
                        if item.conditional_status == "feasible"]
        if not robust_plans:
            next_times = []
            break
        next_times.append(max(robust_plans))
    latest = min(next_times) if next_times else None
    return Assessment(snapshot.revision, _snapshot_digest(snapshot), now,
                      _revision_digest(revisions), status, components,
                      tuple(stale), latest, recomputed)


def assess(snapshot: Snapshot, *, now: float, current_source_revisions: Mapping[str, str]) -> Assessment:
    """Evaluate all accepted commitments under current evidence and optional paths."""
    _time(now, "now")
    _revision_digest(current_source_revisions)
    demands = _effective_demands(snapshot)
    groups = _component_ids(snapshot, demands)
    components = tuple(_component(group, snapshot, demands, now=now,
                                  revisions=current_source_revisions) for group in groups)
    return _summary(snapshot, now, current_source_revisions, components,
                    tuple(sorted(item.id for item in snapshot.commitments)))


def propose_shared_dependencies(
    snapshot: Snapshot, traces: tuple[TraceObservation, ...], *, now: float,
    current_source_revisions: Mapping[str, str],
) -> tuple[DependencyProposal, ...]:
    """Propose an observed contention edge; observation alone never activates it."""
    _time(now, "now")
    _revision_digest(current_source_revisions)
    if not isinstance(traces, tuple) or len(traces) > _MAX_TRACES or any(type(item) is not TraceObservation for item in traces):
        raise ValueError("traces must be a bounded tuple")
    _unique(tuple(item.id for item in traces), "trace ids")
    commitments = {item.id: item for item in snapshot.commitments}
    snapshot_digest = _snapshot_digest(snapshot)
    demands = _effective_demands(snapshot)
    finite_resources = {item.key for item in snapshot.lots if item.kind == "capacity"
                        and item.certainty != "unavailable"
                        and item.evidence.current(now, current_source_revisions)}
    valid = tuple(item for item in traces if item.commitment_id in commitments
                  and item.resource_key in finite_resources
                  and item.evidence.current(now, current_source_revisions)
                  and item.end_at <= item.evidence.observed_at <= now
                  and commitments[item.commitment_id].acceptance.current(now, current_source_revisions))
    proposals = {}
    for first, second in itertools.combinations(valid, 2):
        if (first.commitment_id == second.commitment_id
                or first.resource_key != second.resource_key
                or first.blocked == second.blocked
                or max(first.start_at, second.start_at) >= min(first.end_at, second.end_at)):
            continue
        left, right = sorted((first, second), key=lambda item: item.commitment_id)
        key = (left.commitment_id, right.commitment_id, left.resource_key)
        if any((min(edge.left_id, edge.right_id), max(edge.left_id, edge.right_id),
                edge.resource_key) == key for edge in snapshot.dependencies):
            continue
        existing = tuple(next((part.units for part in demands[item.commitment_id]
                               if (part.kind, part.key) == ("capacity", item.resource_key)), None)
                         for item in (left, right))
        if (existing[0] is not None and existing[1] is not None) or any(
            prior is not None and prior != item.units for prior, item in zip(existing, (left, right), strict=True)
        ):
            continue
        trace_ids = (left.id, right.id)
        trace_payload = [asdict(left), asdict(right)]
        trace_digest = hashlib.sha256(json.dumps(trace_payload, sort_keys=True,
                                                 separators=(",", ":")).encode("utf-8")).hexdigest()
        payload = [snapshot_digest, *key, left.units, right.units, *trace_ids,
                   trace_digest]
        identifier = "DPR-" + hashlib.sha256(json.dumps(payload).encode("utf-8")).hexdigest()[:32]
        candidate = DependencyProposal(identifier, snapshot_digest, *key,
                                       left.units, right.units, trace_ids, trace_digest,
                                       (left.evidence, right.evidence))
        if key not in proposals or candidate.id < proposals[key].id:
            proposals[key] = candidate
    return tuple(proposals[key] for key in sorted(proposals))


def confirm_dependency(
    snapshot: Snapshot, proposal: DependencyProposal, traces: tuple[TraceObservation, ...],
    *, actor: str, expected_revision: int, now: float,
    current_source_revisions: Mapping[str, str],
) -> Snapshot:
    """Bind an owner-reviewed proposal to the exact still-current observation."""
    _name(actor, "confirming actor")
    if expected_revision != snapshot.revision:
        raise ValueError("commitment snapshot changed; refresh the dependency review")
    current = propose_shared_dependencies(snapshot, traces, now=now,
                                          current_source_revisions=current_source_revisions)
    if proposal not in current:
        raise ValueError("dependency evidence changed; review the current proposal")
    edge = SharedDependency(proposal.left_id, proposal.right_id, proposal.resource_key,
                            proposal.left_units, proposal.right_units, proposal.id, actor, now)
    updated = replace(snapshot, revision=snapshot.revision + 1,
                      dependencies=(*snapshot.dependencies, edge))
    _effective_demands(updated)
    return updated


def confirm_option(
    snapshot: Snapshot, option_id: str, *, actor: str, expected_revision: int,
    now: float, current_source_revisions: Mapping[str, str],
) -> Snapshot:
    """Record owner intent only; this never asserts an external hold occurred."""
    _name(actor, "confirming actor")
    _time(now, "now")
    _revision_digest(current_source_revisions)
    if expected_revision != snapshot.revision:
        raise ValueError("commitment snapshot changed; refresh the option review")
    selected = next((item for item in snapshot.options if item.id == option_id), None)
    if selected is None or now >= selected.expires_at or not selected.evidence.current(now, current_source_revisions):
        raise ValueError("option is unavailable or its source changed")
    if selected.owner_confirmation is not None:
        raise ValueError("option was already confirmed; refresh its current outcome")
    current = assess(snapshot, now=now, current_source_revisions=current_source_revisions)
    if not any(
        option_id in plan.option_ids and plan.conditional_status == "feasible"
        and now < plan.latest_safe_bundle_decision_at
        for component in current.components for plan in component.plans
    ):
        raise ValueError("option has no current feasible path; review its changed effect")
    confirmation = OwnerConfirmation(selected.id, _option_digest(selected),
                                     actor, now, selected.evidence.revision)
    options = tuple(replace(item, owner_confirmation=confirmation) if item.id == option_id else item
                    for item in snapshot.options)
    return replace(snapshot, revision=snapshot.revision + 1, options=options)


def recompute_after_dependency(
    previous: Assessment, before: Snapshot, after: Snapshot, *, now: float,
    current_source_revisions: Mapping[str, str],
) -> Assessment:
    """Recompute the newly linked component and reuse unchanged components."""
    _time(now, "now")
    digest = _revision_digest(current_source_revisions)
    if (previous.snapshot_revision != before.revision
            or previous.snapshot_digest != _snapshot_digest(before)
            or previous.evaluated_at != now
            or previous.source_revisions_digest != digest or after.revision != before.revision + 1
            or before.commitments != after.commitments or before.lots != after.lots
            or before.options != after.options or after.dependencies[:-1] != before.dependencies):
        raise ValueError("incremental assessment needs an exact unchanged source snapshot")
    edge = after.dependencies[-1]
    demands = _effective_demands(after)
    groups = _component_ids(after, demands)
    prior = {item.commitment_ids: item for item in previous.components}
    components = tuple(
        prior[group] if group in prior and edge.left_id not in group and edge.right_id not in group
        else _component(group, after, demands, now=now, revisions=current_source_revisions)
        for group in groups
    )
    recomputed = tuple(sorted({item for group in groups
                               if edge.left_id in group or edge.right_id in group for item in group}))
    return _summary(after, now, current_source_revisions, components, recomputed)


__all__ = [
    "ActionPlan", "Assessment", "Commitment", "ComponentResult", "Demand", "ResourceGap",
    "DependencyProposal", "Evidence", "Lot", "OwnerConfirmation", "ReversibleOption",
    "SharedDependency", "Snapshot", "TraceObservation", "assess", "confirm_dependency",
    "confirm_option", "explain_resource_gaps", "propose_shared_dependencies", "recompute_after_dependency",
]
