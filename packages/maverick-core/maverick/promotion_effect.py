"""Stratified outcome comparison for governed improvement decisions.

Logged tool use is observational. Matching episodes by recorded context can
remove measured differences, but cannot rule out easier tasks, operator choices,
or other unrecorded causes. Such comparisons are useful for *finding candidates*
and are never promotion-grade causal evidence on their own.

The estimator reports overlap, uncertainty, and a permutation test of the
observed association. Promotion-grade ``trustworthy`` requires prospectively
randomized assignment supplied by a controlled experiment; callers deriving
units from ordinary trajectories cannot claim that design. A permutation test
cannot validate randomization or detect an unmeasured common cause.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

from .config import governed_learning_env_flag

# Two-sided 95% normal quantile.
_Z95 = 1.959963984540054
_PLACEBO_PERMUTATIONS = 999


@dataclass(frozen=True)
class Unit:
    """One episode reduced to an outcome-comparison record.

    ``treatment`` is 1 when the candidate change was present, 0 when absent;
    ``outcome`` is the episode's task outcome in [0, 1] (e.g. the terminal
    verifier confidence / success label); ``stratum`` is the confounder cell --
    a hashable key of the comparable-context features (domain, depth bucket,
    ...). Episodes only compare *within* a stratum. ``randomized`` must only be
    set for an arm assigned prospectively by a controlled experiment; ordinary
    trajectory capture leaves it False.
    """

    treatment: int
    outcome: float
    stratum: tuple
    randomized: bool = False


@dataclass(frozen=True)
class EffectEstimate:
    """A stratified comparison with its evidence limits exposed."""

    effect: float
    ci_low: float
    ci_high: float
    n_used: int
    n_total: int
    strata_used: int
    overlap: float
    naive_effect: float
    placebo_effect: float
    trustworthy: bool
    adjusted_for: tuple[str, ...] = field(default_factory=tuple)
    permutation_p_value: float = 1.0
    randomized: bool = False


def enabled() -> bool:
    """Whether the controller should consult controlled-effect evidence."""
    _v = governed_learning_env_flag("MAVERICK_CAUSAL_PROMOTION")
    if _v is not None:
        return _v
    try:
        from .config import get_self_improvement

        return bool(get_self_improvement().get("causal_promotion", False))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def _mean_var(xs: list[float]) -> tuple[float, float, int]:
    n = len(xs)
    if n == 0:
        return 0.0, 0.0, 0
    m = sum(xs) / n
    # The sampling variance of an arm mean needs n-1; one observation cannot
    # establish within-arm uncertainty and is excluded from the calibrated ATE.
    v = sum((x - m) ** 2 for x in xs) / (n - 1) if n > 1 else 0.0
    return m, v, n


def _strata(units: list[Unit]) -> dict:
    """Group outcomes by stratum and treatment arm."""
    out: dict = {}
    for u in units:
        arms = out.setdefault(u.stratum, ([], []))  # (control, treated)
        arms[1 if u.treatment else 0].append(float(u.outcome))
    return out


def _stratified_ate(strata: dict) -> tuple[float, float, int, int]:
    """Subclassification ATE + its variance over overlapping strata.

    Returns ``(ate, variance, n_used, strata_used)``. Only strata with both a
    treated and a control observation contribute (positivity / overlap).
    """
    weighted_effect = 0.0
    weighted_var = 0.0
    total_w = 0
    strata_used = 0
    for control, treated in strata.values():
        if len(control) < 2 or len(treated) < 2:
            continue  # no support for both arm variances in this cell
        m1, v1, n1 = _mean_var(treated)
        m0, v0, n0 = _mean_var(control)
        w = n1 + n0
        tau = m1 - m0
        # Variance of the difference of means within the stratum.
        var_s = (v1 / n1 if n1 else 0.0) + (v0 / n0 if n0 else 0.0)
        weighted_effect += w * tau
        weighted_var += (w ** 2) * var_s
        total_w += w
        strata_used += 1
    if total_w == 0:
        return 0.0, 0.0, 0, 0
    ate = weighted_effect / total_w
    var = weighted_var / (total_w ** 2)
    return ate, var, total_w, strata_used


def _naive_difference(units: list[Unit]) -> float:
    treated = [u.outcome for u in units if u.treatment]
    control = [u.outcome for u in units if not u.treatment]
    m1, _, n1 = _mean_var(treated)
    m0, _, n0 = _mean_var(control)
    if n1 == 0 or n0 == 0:
        return 0.0
    return m1 - m0


def _permutation_diagnostics(
    strata: dict, observed: float, *, seed: int,
    permutations: int = _PLACEBO_PERMUTATIONS,
) -> tuple[float, float]:
    """Return the null mean and two-sided randomization p-value.

    The null mean is retained as a diagnostic, never a trust gate: it tends to
    zero even for a badly confounded observed association. The p-value instead
    compares the observed statistic with the full shuffled distribution. This
    test only has a causal interpretation for prospectively randomized units.
    """
    rng = random.Random(seed)
    # Only overlapping strata matter (they're the ones that carry the estimate).
    pools = [
        (control + treated, len(treated))
        for control, treated in strata.values()
        if len(control) >= 2 and len(treated) >= 2
    ]
    if not pools:
        return 0.0, 1.0
    acc = 0.0
    as_extreme = 0
    for _ in range(permutations):
        weighted_effect = 0.0
        total_w = 0
        for pool, n1 in pools:
            shuffled = pool[:]
            rng.shuffle(shuffled)
            fake_treated = shuffled[:n1]
            fake_control = shuffled[n1:]
            m1, _, _ = _mean_var(fake_treated)
            m0, _, _ = _mean_var(fake_control)
            w = len(pool)
            weighted_effect += w * (m1 - m0)
            total_w += w
        null_effect = weighted_effect / total_w if total_w else 0.0
        acc += null_effect
        if abs(null_effect) >= abs(observed) - 1e-12:
            as_extreme += 1
    return acc / permutations, (as_extreme + 1) / (permutations + 1)


def estimate_effect(
    units: list[Unit],
    *,
    adjusted_for: tuple[str, ...] = (),
    min_overlap: float = 0.5,
    min_used: int = 8,
    placebo_tol: float = 0.05,
    placebo_seed: int = 0,
) -> EffectEstimate:
    """Compare outcomes within measured strata, with a conservative trust gate.

    ``placebo_tol`` is retained for existing callers and now sets the two-sided
    permutation significance threshold. The gate also requires enough supported
    randomized units; ordinary observed trajectories are diagnostic only.
    """
    n_total = len(units)
    if n_total == 0:
        return EffectEstimate(0.0, 0.0, 0.0, 0, 0, 0, 0.0, 0.0, 0.0, False, adjusted_for)
    if not all(u.treatment in (0, 1) and math.isfinite(u.outcome)
               and 0.0 <= u.outcome <= 1.0 for u in units):
        return EffectEstimate(0.0, 0.0, 0.0, 0, n_total, 0, 0.0, 0.0, 0.0,
                              False, adjusted_for)
    strata = _strata(units)
    ate, var, n_used, strata_used = _stratified_ate(strata)
    half = _Z95 * math.sqrt(var) if var > 0 else 0.0
    overlap = n_used / n_total if n_total else 0.0
    randomized = all(u.randomized for u in units)
    placebo, p_value = (
        _permutation_diagnostics(strata, ate, seed=placebo_seed)
        if randomized and n_used >= min_used and overlap >= min_overlap
        else (0.0, 1.0)
    )
    trustworthy = (
        randomized
        and n_used >= min_used
        and overlap >= min_overlap
        and strata_used >= 1
        and p_value <= placebo_tol
    )
    return EffectEstimate(
        effect=ate,
        ci_low=ate - half,
        ci_high=ate + half,
        n_used=n_used,
        n_total=n_total,
        strata_used=strata_used,
        overlap=overlap,
        naive_effect=_naive_difference(units),
        placebo_effect=placebo,
        trustworthy=trustworthy,
        adjusted_for=tuple(adjusted_for),
        permutation_p_value=p_value,
        randomized=randomized,
    )


def units_from_trajectories(
    steps,
    *,
    treatment_fn,
    outcome_fn,
    stratum_fn,
) -> list[Unit]:
    """Build observational units from a flat trajectory step stream.

    ``steps`` is any iterable of :class:`maverick.trajectory_store.TrajectoryStep`
    (e.g. ``store.iter_steps()``). Steps are grouped by ``(goal_id, episode_id)``;
    each callback receives that episode's ordered steps and returns the
    treatment (0/1 or None to skip), the outcome (float or None to skip), and the
    stratum key. Episodes where any callback returns None are dropped.
    """
    episodes: dict = {}
    for s in steps:
        episodes.setdefault((s.goal_id, s.episode_id), []).append(s)
    units: list[Unit] = []
    for key in episodes:
        ep = sorted(episodes[key], key=lambda s: s.step)
        t = treatment_fn(ep)
        y = outcome_fn(ep)
        stratum = stratum_fn(ep)
        if t is None or y is None or stratum is None:
            continue
        units.append(Unit(treatment=1 if t else 0, outcome=float(y), stratum=tuple(stratum)))
    return units


__all__ = [
    "Unit",
    "EffectEstimate",
    "enabled",
    "estimate_effect",
    "units_from_trajectories",
]
