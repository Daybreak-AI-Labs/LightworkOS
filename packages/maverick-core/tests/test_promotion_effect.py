"""Observed comparisons inform hypotheses; controlled evidence gates adoption."""
from __future__ import annotations

from maverick import promotion_effect as pe
from maverick.self_improvement import Candidate, SelfImprovementController
from maverick.si_producers import propose_with_effect
from maverick.trajectory_store import TrajectoryStep


def _units(spec):
    """spec: list of (stratum, treatment, outcome, count)."""
    out = []
    for stratum, t, y, n in spec:
        out.extend(pe.Unit(treatment=t, outcome=y, stratum=(stratum,)) for _ in range(n))
    return out


def test_recovers_effect_under_confounding():
    # True effect is +0.10 in both strata. Treatment is confounded with the
    # stratum (A has a high base outcome AND mostly treated; B the reverse), so
    # the naive treated-minus-control comparison is badly biased upward.
    units = _units([
        ("A", 1, 0.9, 10), ("A", 0, 0.8, 2),
        ("B", 1, 0.3, 2),  ("B", 0, 0.2, 10),
    ])
    est = pe.estimate_effect(units, adjusted_for=("stratum",))
    assert abs(est.effect - 0.10) < 1e-9          # stratification recovers the truth
    assert est.naive_effect > 0.45                # ... while the naive number lies
    assert not est.trustworthy                  # logged use was not randomized
    assert est.permutation_p_value == 1.0
    assert abs(est.ci_low - 0.10) < 1e-9


def test_mean_permutation_is_not_used_as_a_refutation():
    units = _units([
        ("A", 1, 0.9, 10), ("A", 0, 0.8, 4),
        ("B", 1, 0.3, 4),  ("B", 0, 0.2, 10),
    ])
    est = pe.estimate_effect(units)
    # The old zero-mean check always passed. Observational evidence is never
    # promoted even with strong overlap and a clean-looking comparison.
    assert not est.trustworthy
    assert est.permutation_p_value == 1.0


def test_ci_contains_true_effect_with_variance():
    units = [
        pe.Unit(1, y, ("s",)) for y in (0.7, 0.8, 0.9, 1.0)
    ] + [
        pe.Unit(0, y, ("s",)) for y in (0.6, 0.7, 0.8, 0.9)
    ]
    est = pe.estimate_effect(units)
    assert abs(est.effect - 0.10) < 1e-9
    assert est.ci_low < 0.10 < est.ci_high        # non-degenerate interval covers truth
    assert not est.trustworthy


def test_prospective_randomization_can_clear_the_gate():
    units = [pe.Unit(1, 0.8, ("s",), randomized=True) for _ in range(12)]
    units += [pe.Unit(0, 0.4, ("s",), randomized=True) for _ in range(12)]
    est = pe.estimate_effect(units)
    assert est.randomized and est.trustworthy
    assert est.permutation_p_value <= 0.05
    assert est.ci_low > 0.0
    verdict = propose_with_effect("prompt", "controlled improvement", est, rollback="snap")
    assert verdict.promote, verdict.blocking_reason


def test_hidden_workload_difference_cannot_promote_observed_tool_use():
    # The tool happens to be used on easy work within the same recorded domain.
    # The observed difference is large, but the unrecorded difficulty caused it.
    units = [pe.Unit(1, 0.95, ("same-domain",)) for _ in range(20)]
    units += [pe.Unit(0, 0.35, ("same-domain",)) for _ in range(20)]
    est = pe.estimate_effect(units)
    assert est.effect > 0.5 and not est.trustworthy
    verdict = propose_with_effect("prompt", "easy-work mirage", est, rollback="snap")
    assert not verdict.promote


def test_singleton_arm_does_not_create_zero_width_confidence():
    units = [pe.Unit(1, 0.9, ("single",)), pe.Unit(0, 0.2, ("single",))]
    est = pe.estimate_effect(units)
    assert est.n_used == 0 and not est.trustworthy


def test_low_overlap_is_untrustworthy():
    # One overlapping stratum (4 units) plus a treated-only stratum (no control,
    # excluded): the comparable fraction is tiny -> not trustworthy, fail-closed.
    units = _units([
        ("A", 1, 0.9, 2), ("A", 0, 0.8, 2),
        ("C", 1, 0.5, 20),
    ])
    est = pe.estimate_effect(units, min_overlap=0.5, min_used=8)
    assert est.overlap < 0.5
    assert not est.trustworthy


def test_empty_units():
    est = pe.estimate_effect([])
    assert est.effect == 0.0 and est.n_total == 0 and not est.trustworthy


def test_units_from_trajectories():
    steps = [
        TrajectoryStep(ts=0, goal_id=1, episode_id=1, step=0, role="r", tool="X", domain="fin"),
        TrajectoryStep(ts=0, goal_id=1, episode_id=1, step=1, role="r", tool="",
                       is_final=True, outcome=0.9, domain="fin"),
        TrajectoryStep(ts=0, goal_id=1, episode_id=2, step=0, role="r", tool="Y", domain="fin"),
        TrajectoryStep(ts=0, goal_id=1, episode_id=2, step=1, role="r", tool="",
                       is_final=True, outcome=0.2, domain="fin"),
    ]

    def treatment(ep):
        return 1 if any(s.tool == "X" for s in ep) else 0

    def outcome(ep):
        finals = [s for s in ep if s.is_final and s.outcome is not None]
        return finals[-1].outcome if finals else None

    def stratum(ep):
        return (ep[0].domain,)

    units = pe.units_from_trajectories(
        steps, treatment_fn=treatment, outcome_fn=outcome, stratum_fn=stratum)
    assert len(units) == 2
    treated = {u.treatment: u.outcome for u in units}
    assert treated[1] == 0.9 and treated[0] == 0.2


def _controller():
    # evaluate() is pure and doesn't require the engine to be enabled; force the
    # calibration interlock open so we exercise the evidence gate itself.
    return SelfImprovementController(frozen_fn=lambda: False)


def test_gate_promotes_on_positive_causal_lower_bound():
    ctrl = _controller()
    cand = Candidate(
        rung="prompt", summary="causal win", baseline_score=0.0, candidate_score=0.2,
        samples=12, effect_ci_low=0.05, capability_widens=False, rollback="snap-1",
    )
    verdict = ctrl.evaluate(cand)
    assert verdict.promote, verdict.blocking_reason


def test_gate_rejects_high_mean_but_unconfident_effect():
    # candidate_score (the naive mean) looks great, but the causal lower bound is
    # below the margin -> the evidence gate refuses. This is the whole point.
    ctrl = _controller()
    cand = Candidate(
        rung="prompt", summary="confounded", baseline_score=0.0, candidate_score=0.5,
        samples=12, effect_ci_low=-0.01, capability_widens=False, rollback="snap-1",
    )
    verdict = ctrl.evaluate(cand)
    assert not verdict.promote
    assert "causal effect" in verdict.blocking_reason


def test_propose_with_effect_fail_closed_on_untrustworthy():
    bad = pe.EffectEstimate(
        effect=0.3, ci_low=0.2, ci_high=0.4, n_used=3, n_total=50, strata_used=1,
        overlap=0.06, naive_effect=0.5, placebo_effect=0.0, trustworthy=False,
    )
    verdict = propose_with_effect("prompt", "should not promote", bad, rollback="snap")
    assert not verdict.promote
    assert verdict.gates[0].gate == "effect_calibration"


def test_enabled_respects_explicit_opt_out_and_opt_in(monkeypatch):
    monkeypatch.setenv("MAVERICK_CAUSAL_PROMOTION", "0")
    monkeypatch.setattr("maverick.config.get_self_improvement", lambda: {"causal_promotion": False})
    assert pe.enabled() is False
    monkeypatch.setenv("MAVERICK_CAUSAL_PROMOTION", "1")
    assert pe.enabled() is True
