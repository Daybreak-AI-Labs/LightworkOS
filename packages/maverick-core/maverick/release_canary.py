"""Cost/perf canary per release.

A release can pass every test and still quietly get **slower or pricier**.
This is the guard: snapshot a release's cost/perf metrics, and before shipping
the next one, compare it against the recorded baseline and fail on a
regression beyond tolerance. It's the perf analogue of a test gate.

The comparison is **direction-aware** — for cost / latency / error-rate lower
is better, for success-rate / throughput higher is better — and relative, so a
metric is flagged only when it moves the wrong way by more than ``tolerance``.
Pure and deterministic (plain metric dicts in, verdicts out); the snapshot
store is an atomic JSON file keyed by release tag. ``maverick canary
record/compare`` drives it; a non-zero exit on regression gates a release.
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass

log = logging.getLogger(__name__)

# Metrics where a HIGHER value is better; everything else is lower-is-better
# (cost, latency, error rate, tokens, ...).
HIGHER_IS_BETTER = frozenset({
    "success_rate", "pass_rate", "accuracy", "throughput", "cache_hit_rate",
})
DEFAULT_TOLERANCE = 0.10   # 10% worse = regression


@dataclass(frozen=True)
class MetricVerdict:
    metric: str
    baseline: float
    candidate: float
    rel_change: float       # (candidate - baseline) / |baseline|
    verdict: str            # "regressed" | "improved" | "ok" | "new" | "missing" | "invalid"


# Verdicts that fail the gate: a worse move, a baseline metric the candidate did
# not record, or a value that is not a finite number (NaN compares as "ok").
_FAILING = frozenset({"regressed", "missing", "invalid"})


@dataclass(frozen=True)
class CanaryResult:
    verdicts: list[MetricVerdict]

    @property
    def regressions(self) -> list[MetricVerdict]:
        return [v for v in self.verdicts if v.verdict in _FAILING]

    @property
    def passed(self) -> bool:
        return not self.regressions


def _classify(metric: str, base: float, cand: float, tol: float) -> MetricVerdict:
    higher_better = metric in HIGHER_IS_BETTER
    denom = abs(base) if base else 0.0
    # Zero baseline: sign the infinite sentinel by the direction of the move so
    # a negative candidate isn't judged as a large positive move (and vice versa).
    rel = ((cand - base) / denom if denom
           else (0.0 if cand == base else math.copysign(float("inf"), cand - base)))
    # Worse-direction movement beyond tolerance is a regression.
    if higher_better:
        verdict = "regressed" if rel < -tol else ("improved" if rel > tol else "ok")
    else:
        verdict = "regressed" if rel > tol else ("improved" if rel < -tol else "ok")
    return MetricVerdict(metric, float(base), float(cand), round(rel, 4), verdict)


def compare(baseline: dict, candidate: dict, *,
            tolerance: float = DEFAULT_TOLERANCE) -> CanaryResult:
    """Compare two metric snapshots into per-metric verdicts.

    A candidate-only metric is marked ``new`` (informational, never a
    regression). A numeric baseline metric the candidate does not record is
    ``missing``, and a non-finite value on either side is ``invalid``; both
    fail the gate. ``tolerance`` is the relative move (e.g. 0.10) allowed
    before flagging.
    """
    verdicts: list[MetricVerdict] = []
    for metric, cand in candidate.items():
        if not isinstance(cand, (int, float)):
            continue
        if metric not in baseline or not isinstance(baseline[metric], (int, float)):
            verdict = "new" if math.isfinite(cand) else "invalid"
            verdicts.append(MetricVerdict(metric, 0.0, float(cand), 0.0, verdict))
            continue
        base = float(baseline[metric])
        if not (math.isfinite(base) and math.isfinite(cand)):
            verdicts.append(MetricVerdict(metric, base, float(cand), 0.0, "invalid"))
            continue
        verdicts.append(_classify(metric, base, float(cand), tolerance))
    for metric, base in baseline.items():
        if isinstance(base, (int, float)) and not isinstance(candidate.get(metric), (int, float)):
            verdicts.append(MetricVerdict(metric, float(base), math.nan, 0.0, "missing"))
    verdicts.sort(key=lambda v: v.metric)
    return CanaryResult(verdicts)


class CanaryStore:
    """Atomic JSON store of ``release -> metrics``."""

    def __init__(self, path=None):
        self._explicit = path

    @property
    def path(self):
        from pathlib import Path
        if self._explicit is not None:
            return Path(self._explicit)
        from .paths import data_dir
        return data_dir("release_canary.json")

    def _load(self) -> dict:
        try:
            from .file_lock import ensure_private_file

            ensure_private_file(self.path)
            return json.loads(self.path.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        from .file_lock import atomic_write_text, ensure_private_directory

        p = self.path
        ensure_private_directory(p.parent)
        atomic_write_text(p, json.dumps(data, sort_keys=True, indent=2), mode=0o600)

    def record(self, release: str, metrics: dict) -> None:
        bad = sorted(k for k, v in metrics.items()
                     if isinstance(v, (int, float)) and not math.isfinite(v))
        if bad:
            raise ValueError(f"metric values must be finite numbers: {bad}")
        data = self._load()
        data[release] = {k: float(v) for k, v in metrics.items()
                         if isinstance(v, (int, float))}
        self._save(data)

    def get(self, release: str) -> dict | None:
        return self._load().get(release)

    def releases(self) -> list[str]:
        return sorted(self._load())


def measure(world, *, window_days: int = 30, now: float | None = None,
            episode_limit: int = 5000) -> dict[str, float]:
    """This installation's current cost/perf snapshot from finished runs.

    ``cost_per_task`` and ``tokens_per_task`` (averages), ``p95_latency_s``
    (95th-percentile run time) and ``success_rate`` over runs that finished in
    the last ``window_days``. Empty when nothing finished in the window, so a
    snapshot is never invented. Read-only.
    """
    import time as _time

    from .workforce_value import _is_done

    cutoff = (now if now is not None else _time.time()) - window_days * 86400.0
    costs: list[float] = []
    tokens: list[int] = []
    durations: list[float] = []
    done = 0
    for ep in world.list_episodes(limit=episode_limit):
        ended = float(getattr(ep, "ended_at", 0) or 0)
        started = float(getattr(ep, "started_at", 0) or 0)
        if not ended or ended < cutoff:
            continue
        costs.append(float(getattr(ep, "cost_dollars", 0) or 0))
        tokens.append(int(getattr(ep, "input_tokens", 0) or 0) + int(getattr(ep, "output_tokens", 0) or 0))
        durations.append(max(0.0, ended - started))
        done += 1 if _is_done(getattr(ep, "outcome", None)) else 0
    if not costs:
        return {}
    ordered = sorted(durations)
    p95 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.95 * len(ordered)) - 1))]
    return {
        "cost_per_task": round(sum(costs) / len(costs), 6),
        "tokens_per_task": round(sum(tokens) / len(tokens), 2),
        "p95_latency_s": round(p95, 3),
        "success_rate": round(done / len(costs), 4),
    }


def render(result: CanaryResult) -> str:
    lines = ["CANARY: " + ("PASS" if result.passed else "FAIL")]
    for v in result.verdicts:
        mark = {"regressed": "✗", "improved": "↑", "ok": "·", "new": "+",
                "missing": "✗", "invalid": "✗"}.get(v.verdict, "?")
        lines.append(f"  {mark} {v.metric}: {v.baseline:g} -> {v.candidate:g} "
                     f"({v.rel_change:+.1%}) [{v.verdict}]")
    return "\n".join(lines)


__all__ = ["MetricVerdict", "CanaryResult", "compare", "CanaryStore", "render", "measure",
           "HIGHER_IS_BETTER", "DEFAULT_TOLERANCE"]
