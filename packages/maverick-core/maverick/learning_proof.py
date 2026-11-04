"""Learning-proof harness: measure whether self-learning actually improves the
workforce, with a reproducible A/B and honest statistics.

Provability needs two things the learning loop doesn't give on its own:

  1. a FIXED held-out task suite scored for SUCCESS (not lexical coverage), and
  2. a clean A/B -- the same tasks run with learning LIVE vs forced-FROZEN
     (``calibration.learning_frozen`` via ``MAVERICK_LEARNING_FROZEN``), scored
     the same way, with the paired difference reported as an effect size + CI.

This module owns the statistics and the (dependency-injected) A/B runner so it
is testable without a live LLM or GPU: the CLI wires the real agent runner +
verifier into ``run``/``score``; tests inject deterministic callables. The
bootstrap CI is seeded, so a reported lift is reproducible for a given seed.
"""
from __future__ import annotations

import os
import random
from contextlib import contextmanager
from dataclasses import dataclass

FROZEN_ENV = "MAVERICK_LEARNING_FROZEN"


@contextmanager
def forced_freeze(frozen: bool):
    """Temporarily force ``calibration.learning_frozen()`` via the env override,
    restoring the prior value on exit. Used to build the control (frozen) and
    treatment (live) arms around an agent run."""
    prev = os.environ.get(FROZEN_ENV)
    os.environ[FROZEN_ENV] = "1" if frozen else "0"
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(FROZEN_ENV, None)
        else:
            os.environ[FROZEN_ENV] = prev


@dataclass
class LiftResult:
    n: int
    baseline_mean: float       # learning FROZEN (control)
    treatment_mean: float      # learning LIVE (treatment)
    delta: float               # treatment - baseline (mean paired difference)
    ci_low: float
    ci_high: float
    wins: int
    losses: int
    ties: int
    significant: bool          # 95% CI for the paired delta excludes 0
    improved: bool             # significant AND delta > 0

    def summary(self) -> str:
        verdict = (
            "IMPROVED" if self.improved else
            "REGRESSED" if (self.significant and self.delta < 0) else
            "no significant change"
        )
        return (
            f"Learning lift: {verdict}. n={self.n}, "
            f"frozen={self.baseline_mean:.3f} -> live={self.treatment_mean:.3f} "
            f"(delta {self.delta:+.3f}, 95% CI [{self.ci_low:+.3f}, "
            f"{self.ci_high:+.3f}]); {self.wins} win / {self.losses} loss / "
            f"{self.ties} tie."
        )


def paired_lift(
    baseline: list[float], treatment: list[float], *,
    confidence: float = 0.95, bootstrap: int = 2000, seed: int = 1234,
) -> LiftResult:
    """Paired comparison of treatment (learning live) vs baseline (frozen).

    Reports the mean paired delta with a seeded bootstrap percentile CI --
    deterministic for a given seed (so a result is reproducible) and
    distribution-free, which matters at the small n a held-out suite has.
    ``significant`` means the CI excludes 0; a single observation never counts
    as significant.
    """
    if len(baseline) != len(treatment):
        raise ValueError("baseline and treatment must be paired (equal length)")
    n = len(baseline)
    if n == 0:
        raise ValueError("need at least one paired observation")
    deltas = [t - b for b, t in zip(baseline, treatment, strict=True)]
    mean_delta = sum(deltas) / n
    wins = sum(1 for d in deltas if d > 0)
    losses = sum(1 for d in deltas if d < 0)
    ties = n - wins - losses
    # Seeded bootstrap percentile CI on the mean paired delta.
    rng = random.Random(seed)
    reps = max(1, bootstrap)
    means: list[float] = []
    for _ in range(reps):
        sample_sum = sum(deltas[rng.randrange(n)] for _ in range(n))
        means.append(sample_sum / n)
    means.sort()
    tail = (1.0 - confidence) / 2.0
    lo_i = max(0, int(tail * reps))
    hi_i = min(reps - 1, int((1.0 - tail) * reps))
    ci_low, ci_high = means[lo_i], means[hi_i]
    significant = n >= 2 and (ci_low > 0 or ci_high < 0)
    return LiftResult(
        n=n,
        baseline_mean=sum(baseline) / n,
        treatment_mean=sum(treatment) / n,
        delta=mean_delta,
        ci_low=ci_low, ci_high=ci_high,
        wins=wins, losses=losses, ties=ties,
        significant=significant,
        improved=significant and mean_delta > 0,
    )


def measure_lift(
    tasks: list, *, run, score, confidence: float = 0.95,
    bootstrap: int = 2000, seed: int = 1234,
) -> LiftResult:
    """Run each task under learning FROZEN (control) then LIVE (treatment),
    score both, and return the paired lift.

    ``run(task, frozen: bool) -> output`` performs one attempt with learning
    forced off/on (this fn sets ``MAVERICK_LEARNING_FROZEN`` around the call via
    :func:`forced_freeze`); ``score(task, output) -> float`` is the
    verifier-backed success score in ``[0, 1]``. Both are injected so this is
    testable without a live agent. Each task is run once per arm, in order, so a
    deterministic ``run``/``score`` yields a deterministic result.
    """
    baseline: list[float] = []
    treatment: list[float] = []
    for task in tasks:
        with forced_freeze(True):
            b_out = run(task, True)
        baseline.append(float(score(task, b_out)))
        with forced_freeze(False):
            t_out = run(task, False)
        treatment.append(float(score(task, t_out)))
    return paired_lift(
        baseline, treatment, confidence=confidence,
        bootstrap=bootstrap, seed=seed,
    )


__all__ = [
    "LiftResult", "paired_lift", "measure_lift", "forced_freeze", "FROZEN_ENV",
]
