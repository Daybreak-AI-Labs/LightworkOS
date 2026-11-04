"""Cross-run anomaly detection.

A single run's spend outlier is caught by the cost-anomaly endpoint; this
watches *behavior* across runs: a goal that suddenly exercises tools its
history never touched, an error-rate spike, or an event volume far outside
the deployment's baseline — the signals of compromise, runaway loops, or a
silently-degraded model that per-run checks miss.

Deterministic statistics over the event log (no model): build a baseline
profile from recent terminal runs, then score a run against it. Findings are
*signals for a human*, not verdicts — the report says what deviated and by
how much.

  baseline(runs)              -> BaselineProfile (kind/agent distributions,
                                  volume + error-rate bands)
  score_run(run, profile)     -> [Anomaly] (kind, detail, severity)
  gather_runs(world, limit)   -> the duck-typed adapter over goal_events
"""
from __future__ import annotations

import hashlib
import json
import statistics
from dataclasses import dataclass, field
from typing import Any

# A run must deviate by at least this many baseline stdevs to flag volume /
# error-rate anomalies (conservative: cross-run variance is naturally high).
SIGMA = 3.0
# An event kind is "novel" only when the baseline saw >= this many runs and
# none of them produced it.
MIN_BASELINE_RUNS = 5
DETECTOR_VERSION = "cross-run-anomaly-v1"


@dataclass
class RunProfile:
    goal_id: int
    events: int
    errors: int
    kinds: dict[str, int] = field(default_factory=dict)

    @property
    def error_rate(self) -> float:
        return self.errors / self.events if self.events else 0.0


@dataclass
class BaselineProfile:
    runs: int
    mean_events: float
    stdev_events: float
    mean_error_rate: float
    stdev_error_rate: float
    kinds_seen: frozenset[str]


@dataclass(frozen=True)
class Anomaly:
    kind: str          # "novel_event_kind" | "event_volume" | "error_rate"
    severity: str      # "medium" | "high"
    detail: str


def profile_run(goal_id: int, events: list[Any]) -> RunProfile:
    kinds: dict[str, int] = {}
    errors = 0
    for e in events or []:
        k = str(getattr(e, "kind", e.get("kind") if isinstance(e, dict) else "") or "")
        if not k:
            continue
        kinds[k] = kinds.get(k, 0) + 1
        if k == "error":
            errors += 1
    return RunProfile(goal_id=goal_id, events=sum(kinds.values()),
                      errors=errors, kinds=kinds)


def baseline(runs: list[RunProfile]) -> BaselineProfile:
    counts = [r.events for r in runs] or [0]
    rates = [r.error_rate for r in runs] or [0.0]
    seen: set[str] = set()
    for r in runs:
        seen |= set(r.kinds)
    return BaselineProfile(
        runs=len(runs),
        mean_events=statistics.fmean(counts),
        stdev_events=statistics.pstdev(counts),
        mean_error_rate=statistics.fmean(rates),
        stdev_error_rate=statistics.pstdev(rates),
        kinds_seen=frozenset(seen),
    )


def score_run(run: RunProfile, base: BaselineProfile) -> list[Anomaly]:
    """Anomalies for one run against the deployment baseline.

    Empty when the baseline is too thin (< :data:`MIN_BASELINE_RUNS`) — a
    cold deployment must not page anyone.
    """
    if base.runs < MIN_BASELINE_RUNS:
        return []
    out: list[Anomaly] = []

    novel = sorted(set(run.kinds) - set(base.kinds_seen))
    if novel:
        out.append(Anomaly(
            "novel_event_kind", "high",
            f"run #{run.goal_id} produced event kind(s) never seen in the "
            f"baseline ({base.runs} runs): {', '.join(novel)}",
        ))

    if base.stdev_events > 0:
        z = (run.events - base.mean_events) / base.stdev_events
        if z >= SIGMA:
            out.append(Anomaly(
                "event_volume", "medium",
                f"run #{run.goal_id} produced {run.events} events — "
                f"{z:.1f}σ above the baseline mean of {base.mean_events:.0f} "
                "(runaway-loop signal)",
            ))

    if base.stdev_error_rate > 0 and run.events >= 5:
        z = (run.error_rate - base.mean_error_rate) / base.stdev_error_rate
        if z >= SIGMA:
            out.append(Anomaly(
                "error_rate", "high",
                f"run #{run.goal_id} error rate {run.error_rate:.0%} is "
                f"{z:.1f}σ above the baseline {base.mean_error_rate:.0%}",
            ))
    return out


def gather_runs(
    world, *, limit: int = 50, owner: str | None = None
) -> list[RunProfile]:
    """Profiles for the most recent terminal goals (duck-typed world).

    ``owner`` scopes the baseline for authenticated non-admin dashboard callers
    so anomaly details are derived only from goals the caller is allowed to see.
    """
    terminal = {"done", "completed", "failed", "error", "cancelled"}
    profiles: list[RunProfile] = []
    try:
        goals = world.list_goals(limit=limit, order="desc", owner=owner)
    except TypeError:
        if owner is not None:
            try:
                goals = world.list_goals(limit=limit, owner=owner)
            except TypeError:
                goals = [
                    g for g in (world.list_goals(limit=limit) or [])
                    if getattr(g, "owner", None) == owner
                ]
        else:
            goals = world.list_goals(limit=limit)
    for g in goals or []:
        if str(getattr(g, "status", "")) not in terminal:
            continue
        gid = int(getattr(g, "id", 0) or 0)
        events = world.goal_events(gid, limit=10_000)
        profiles.append(profile_run(gid, events))
    return profiles


def detect(
    world, goal_id: int, *, history: int = 50, owner: str | None = None
) -> list[Anomaly]:
    """Score ``goal_id`` against a baseline of its recent siblings."""
    runs = [
        r for r in gather_runs(world, limit=history, owner=owner)
        if r.goal_id != goal_id
    ]
    target = profile_run(goal_id, world.goal_events(goal_id, limit=10_000))
    return score_run(target, baseline(runs))


def to_signal(goal_id: int, anomaly: Anomaly):
    """Project a native run anomaly into the platform-neutral signal envelope."""
    from .anomaly_signal import AnomalySignal

    if isinstance(goal_id, bool) or not isinstance(goal_id, int) or goal_id <= 0:
        raise ValueError("goal_id must be a positive integer")
    if not isinstance(anomaly, Anomaly):
        raise TypeError("anomaly must be an Anomaly")
    material = json.dumps(
        {
            "goal_id": goal_id,
            "kind": anomaly.kind,
            "severity": anomaly.severity,
            "detail": anomaly.detail,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return AnomalySignal(
        detector_id="cross_run_anomaly",
        detector_version=DETECTOR_VERSION,
        kind=anomaly.kind,
        severity=anomaly.severity,
        subject_ref=f"goal:{goal_id}",
        detail=anomaly.detail,
        evidence_sha256s=(hashlib.sha256(material).hexdigest(),),
    )


__all__ = ["RunProfile", "BaselineProfile", "Anomaly", "profile_run",
           "baseline", "score_run", "gather_runs", "detect",
           "to_signal", "DETECTOR_VERSION", "SIGMA", "MIN_BASELINE_RUNS"]
