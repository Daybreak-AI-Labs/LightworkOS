"""Continuous group-fairness monitoring -- the streaming form of ``bias_eval``.

``tools/bias_eval`` answers "is this *batch* of outcomes fair?" on demand. ISO/IEC
42001 A.6.2.6 (operation & monitoring) wants the *continuous* form: watch decision
outcomes as they stream, recompute group-fairness metrics over a rolling window,
and raise an alert the moment the four-fifths rule is breached OR fairness drifts
below an established baseline. This module is that monitor.

It reuses the same disparate-impact math as ``bias_eval`` (four-fifths impact
ratios, demographic-parity difference, equal-opportunity difference) but exposes
it as *structured* metrics over an accumulating window, with a signed
``FAIRNESS_ALERT`` audit row when an alert fires -- so a fairness regression lands
in the Operating Record the same way a shield block or a learning promotion does.

The core (:func:`compute_metrics`, :class:`FairnessMonitor`) is pure and
deterministic with an injected audit sink + clock; :func:`live_monitor` wires the
real signed-audit sink and reads tuning from ``[fairness_monitor]`` config.
Nothing is auto-wired into a decision path -- a deployment opts in by feeding the
monitor its outcomes -- so the kernel is unchanged out of the box. A screening
aid, not a legal determination.
"""
from __future__ import annotations

import logging
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass

log = logging.getLogger(__name__)

DEFAULT_THRESHOLD = 0.8        # four-fifths rule
DEFAULT_WINDOW = 1000          # max outcomes retained (rolling)
DEFAULT_MIN_SAMPLES = 30       # don't evaluate below this (noise floor)
DEFAULT_DRIFT_TOLERANCE = 0.1  # alert if min impact ratio falls this far below baseline

FAIRNESS_REPORT_SCHEMA = "lightwork.fairness-report.v1"


@dataclass(frozen=True)
class Observation:
    """One decision outcome: which group, selected or not, and (optionally) the
    ground-truth positive label used for the equal-opportunity metric."""

    group: str
    selected: bool
    positive: bool | None = None


@dataclass
class FairnessMetrics:
    """Structured group-fairness metrics over a set of per-group counts."""

    rates: dict[str, float]
    impact_ratios: dict[str, float]
    min_impact_ratio: float
    demographic_parity_diff: float
    equal_opportunity_diff: float | None
    failing_groups: list[str]
    passed: bool
    samples: int
    threshold: float


@dataclass
class FairnessAlert:
    """A raised fairness alert: why it fired and the metrics that triggered it."""

    reason: str  # "adverse_impact", "drift", or "adverse_impact+drift"
    metrics: FairnessMetrics
    baseline_min_ratio: float | None = None
    recorded: bool = False


def compute_metrics(counts: dict, *, threshold: float = DEFAULT_THRESHOLD
                    ) -> FairnessMetrics | None:
    """Four-fifths / demographic-parity / equal-opportunity metrics, structured.

    ``counts`` maps ``group -> {"selected": int, "total": int, "positives"?: int,
    "tp"?: int}``. ``positives`` is the group's ground-truth positive count and
    ``tp`` the selected-among-positives count (for equal opportunity). Returns
    ``None`` when fewer than two groups have ``total > 0`` (a single group has no
    disparity to measure). Pure and deterministic; tolerant of out-of-range
    counts (clamped) so a noisy feed never raises.
    """
    rates: dict[str, float] = {}
    tprs: dict[str, float] = {}
    for name, g in counts.items():
        if not isinstance(g, dict):
            continue
        total = int(g.get("total", 0) or 0)
        if total <= 0:
            continue
        selected = max(0, min(int(g.get("selected", 0) or 0), total))
        rates[str(name)] = selected / total
        positives = int(g.get("positives", 0) or 0)
        if positives > 0:
            tp = max(0, min(int(g.get("tp", 0) or 0), positives))
            tprs[str(name)] = tp / positives

    if len(rates) < 2:
        return None

    best = max(rates.values())
    impact = {n: (r / best if best > 0 else 1.0) for n, r in rates.items()}
    failing = sorted(n for n, ratio in impact.items() if ratio < threshold)
    eo = (max(tprs.values()) - min(tprs.values())) if len(tprs) >= 2 else None
    return FairnessMetrics(
        rates=rates,
        impact_ratios=impact,
        min_impact_ratio=min(impact.values()),
        demographic_parity_diff=best - min(rates.values()),
        equal_opportunity_diff=eo,
        failing_groups=failing,
        passed=not failing,
        samples=sum(int(g.get("total", 0) or 0) for g in counts.values() if isinstance(g, dict)),
        threshold=threshold,
    )


def metrics_report(counts: dict, *, threshold: float = DEFAULT_THRESHOLD
                   ) -> dict | None:
    """:func:`compute_metrics` as a schema'd, evidence-recordable dict.

    ``None`` when the counts cannot support a disparity measure (fewer
    than two populated groups) — record no evidence rather than empty
    evidence.
    """

    metrics = compute_metrics(counts, threshold=threshold)
    if metrics is None:
        return None
    return {
        "schema": FAIRNESS_REPORT_SCHEMA,
        "rates": dict(metrics.rates),
        "impact_ratios": dict(metrics.impact_ratios),
        "min_impact_ratio": metrics.min_impact_ratio,
        "demographic_parity_diff": metrics.demographic_parity_diff,
        "equal_opportunity_diff": metrics.equal_opportunity_diff,
        "failing_groups": list(metrics.failing_groups),
        "passed": metrics.passed,
        "samples": metrics.samples,
        "threshold": metrics.threshold,
    }


class FairnessMonitor:
    """Rolling-window continuous fairness monitor.

    Feed it outcomes with :meth:`record` / :meth:`record_batch`; it keeps the
    most recent ``window`` of them. :meth:`evaluate` recomputes structured
    metrics (``None`` until ``min_samples`` are seen). :meth:`check` evaluates and
    raises a :class:`FairnessAlert` -- emitting a signed ``FAIRNESS_ALERT`` audit
    row via the injected ``audit_sink`` -- when the four-fifths rule is breached
    OR the minimum impact ratio drifts more than ``drift_tolerance`` below the
    baseline. The baseline is established automatically on the first healthy
    evaluation (or pinned via :meth:`set_baseline`). Deterministic; the audit sink
    and clock are injected so it is fully offline-testable.
    """

    def __init__(self, *, threshold: float = DEFAULT_THRESHOLD,
                 window: int = DEFAULT_WINDOW, min_samples: int = DEFAULT_MIN_SAMPLES,
                 drift_tolerance: float = DEFAULT_DRIFT_TOLERANCE,
                 audit_sink: Callable[[FairnessAlert], bool] | None = None,
                 clock: Callable[[], float] | None = None) -> None:
        self.threshold = float(threshold)
        self.min_samples = max(1, int(min_samples))
        self.drift_tolerance = float(drift_tolerance)
        self.audit_sink = audit_sink
        self.clock = clock
        self.baseline_min_ratio: float | None = None
        self._obs: deque[Observation] = deque(maxlen=max(1, int(window)))

    def record(self, group, selected, positive=None) -> None:
        """Record one outcome into the rolling window."""
        self._obs.append(Observation(
            str(group), bool(selected),
            None if positive is None else bool(positive)))

    def record_batch(self, observations: Iterable) -> None:
        """Record many outcomes. Items are ``Observation`` or
        ``(group, selected[, positive])`` tuples/lists."""
        for o in observations:
            if isinstance(o, Observation):
                self._obs.append(o)
            else:
                seq = list(o)
                self.record(seq[0], seq[1], seq[2] if len(seq) > 2 else None)

    def _counts(self) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        for o in self._obs:
            c = counts.setdefault(o.group, {"selected": 0, "total": 0, "tp": 0, "positives": 0})
            c["total"] += 1
            if o.selected:
                c["selected"] += 1
            if o.positive:  # ground-truth positive
                c["positives"] += 1
                if o.selected:
                    c["tp"] += 1
        return counts

    def evaluate(self) -> FairnessMetrics | None:
        """Current metrics over the window, or ``None`` below ``min_samples``."""
        if len(self._obs) < self.min_samples:
            return None
        return compute_metrics(self._counts(), threshold=self.threshold)

    def set_baseline(self, value: float | None = None) -> float | None:
        """Pin the drift baseline to ``value`` (or the current min impact ratio)."""
        if value is None:
            metrics = self.evaluate()
            value = metrics.min_impact_ratio if metrics else None
        if value is not None:
            self.baseline_min_ratio = float(value)
        return self.baseline_min_ratio

    def check(self) -> FairnessAlert | None:
        """Evaluate and raise an alert on breach/drift; ``None`` when healthy.

        On the first healthy evaluation the drift baseline is set automatically.
        When an alert fires and an ``audit_sink`` is configured, a signed
        ``FAIRNESS_ALERT`` row is emitted (the sink's truthiness sets
        ``alert.recorded``); a sink that raises is swallowed -- monitoring must
        never crash the path it watches.
        """
        metrics = self.evaluate()
        if metrics is None:
            return None

        reasons = []
        if not metrics.passed:
            reasons.append("adverse_impact")
        if (self.baseline_min_ratio is not None
                and (self.baseline_min_ratio - metrics.min_impact_ratio) > self.drift_tolerance):
            reasons.append("drift")

        if not reasons:
            if self.baseline_min_ratio is None:
                self.baseline_min_ratio = metrics.min_impact_ratio
            return None

        alert = FairnessAlert(reason="+".join(reasons), metrics=metrics,
                              baseline_min_ratio=self.baseline_min_ratio)
        if self.audit_sink is not None:
            try:
                alert.recorded = bool(self.audit_sink(alert))
            except Exception as e:  # monitoring must not crash the watched path
                log.warning("fairness_monitor: audit sink failed (%s)", e)
        return alert


def _live_audit_sink(alert: FairnessAlert) -> bool:  # pragma: no cover -- audit sink
    """Emit a signed ``FAIRNESS_ALERT`` audit row for a raised alert."""
    from .audit import EventKind, record
    m = alert.metrics
    return record(
        EventKind.FAIRNESS_ALERT, agent="fairness_monitor",
        reason=alert.reason,
        min_impact_ratio=round(m.min_impact_ratio, 4),
        demographic_parity_diff=round(m.demographic_parity_diff, 4),
        equal_opportunity_diff=(None if m.equal_opportunity_diff is None
                                else round(m.equal_opportunity_diff, 4)),
        failing_groups=m.failing_groups, samples=m.samples, threshold=m.threshold,
    )


def live_monitor(**overrides) -> FairnessMonitor:  # pragma: no cover -- reads config / wires audit
    """Build a :class:`FairnessMonitor` wired to the signed-audit sink, with tuning
    from ``[fairness_monitor]`` config (overridable via kwargs). Fail-soft: a
    missing/!broken config degrades to module defaults."""
    cfg = {}
    try:
        from . import config
        cfg = config.get_fairness_monitor()
    except Exception as e:
        log.debug("fairness_monitor: config read failed (%s); using defaults", e)
    params = {
        "threshold": cfg.get("threshold", DEFAULT_THRESHOLD),
        "window": cfg.get("window", DEFAULT_WINDOW),
        "min_samples": cfg.get("min_samples", DEFAULT_MIN_SAMPLES),
        "drift_tolerance": cfg.get("drift_tolerance", DEFAULT_DRIFT_TOLERANCE),
        "audit_sink": _live_audit_sink,
    }
    params.update(overrides)
    return FairnessMonitor(**params)


__all__ = [
    "Observation", "FairnessMetrics", "FairnessAlert", "FairnessMonitor",
    "compute_metrics", "live_monitor",
    "DEFAULT_THRESHOLD", "DEFAULT_WINDOW", "DEFAULT_MIN_SAMPLES", "DEFAULT_DRIFT_TOLERANCE",
]
