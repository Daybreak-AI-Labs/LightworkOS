"""Model-based counterfactual rollouts (Phase B): g-computation must recover an
effect that stratification (Phase A) structurally cannot, and must fail closed
when the simulator hasn't earned trust.
"""
from __future__ import annotations

from maverick import promotion_effect as pe
from maverick.counterfactual_rollout import (
    Transition,
    TransitionModel,
    estimate_effect_via_rollout,
    transitions_from_trajectories,
)
from maverick.si_producers import propose_with_effect
from maverick.trajectory_store import TrajectoryStep

START = ("start",)
GOOD = ("good",)
BAD = ("bad",)


def _confounded_corpus(n=20):
    """A 2-step world where action A->good->1.0 and B->bad->0.0 (true effect 1.0).

    The behaviour policy is DETERMINISTICALLY confounded: a hidden context c picks
    the action (c0 always A, c1 always B). So within either c-stratum there is no
    overlap -- Phase A can estimate nothing -- yet the action still varies across
    the corpus and the transition state ("start") is sufficient, so Phase B can.
    """
    transitions = []
    for _ in range(n):  # c0 episodes: start --A--> good --go--> 1.0
        transitions += [
            Transition(START, "A", GOOD),
            Transition(GOOD, "go", None, 1.0),
        ]
    for _ in range(n):  # c1 episodes: start --B--> bad --go--> 0.0
        transitions += [
            Transition(START, "B", BAD),
            Transition(BAD, "go", None, 0.0),
        ]
    return transitions


def test_rollout_recovers_effect_where_stratification_fails():
    # Phase A on the same episodes: deterministic confounding => zero overlap.
    units = (
        [pe.Unit(1, 1.0, ("c0",)) for _ in range(20)]
        + [pe.Unit(0, 0.0, ("c1",)) for _ in range(20)]
    )
    phase_a = pe.estimate_effect(units)
    assert phase_a.overlap == 0.0
    assert not phase_a.trustworthy            # honest: cannot estimate

    # Phase B: g-computation over the learned dynamics recovers it.
    model = TransitionModel(alpha=0.5).fit(_confounded_corpus())
    est = estimate_effect_via_rollout(
        model, [START], treated_action="A", control_action="B",
        horizon=4, rollouts=50, adjusted_for=("state",),
    )
    # Deterministic dynamics + 0.5-smoothed terminals: (20.5-0.5)/21 = 20/21.
    assert abs(est.effect - 20 / 21) < 1e-9
    assert est.trustworthy
    assert est.ci_low > 0.9
    assert abs(est.placebo_effect) < 1e-9     # null action: treated vs treated == 0


def test_untrustworthy_without_action_support():
    # Model only ever saw action A at start; B has no support -> can't compare.
    model = TransitionModel().fit([
        Transition(START, "A", GOOD), Transition(GOOD, "go", None, 1.0),
    ] * 10)
    est = estimate_effect_via_rollout(
        model, [START], treated_action="A", control_action="B", rollouts=20)
    assert est.overlap == 0.0
    assert not est.trustworthy


def test_calibration_gate_with_holdout():
    model = TransitionModel().fit(_confounded_corpus())
    # Holdout that contradicts the learned dynamics (A is "supposed" to go good):
    bad_holdout = [Transition(START, "A", BAD)] * 10
    est = estimate_effect_via_rollout(
        model, [START], treated_action="A", control_action="B",
        rollouts=20, holdout=bad_holdout, min_accuracy=0.7,
    )
    assert not est.trustworthy                # simulator failed held-out prediction

    good_holdout = [Transition(START, "A", GOOD)] * 10
    est2 = estimate_effect_via_rollout(
        model, [START], treated_action="A", control_action="B",
        rollouts=20, holdout=good_holdout, min_accuracy=0.7,
    )
    assert est2.trustworthy


def test_naive_contrast_is_recorded():
    model = TransitionModel().fit(_confounded_corpus())
    # The caller supplies the unadjusted episode-level contrast for the audit
    # record; here episodes that took A ended at 1.0 and B at 0.0 -> 1.0.
    est = estimate_effect_via_rollout(
        model, [START], treated_action="A", control_action="B", rollouts=10,
        naive_effect=1.0)
    assert est.naive_effect == 1.0          # recorded for contrast, never gates
    assert abs(est.effect - 20 / 21) < 1e-9  # the adjusted estimate is what counts


def test_feeds_propose_with_effect():
    model = TransitionModel().fit(_confounded_corpus())
    est = estimate_effect_via_rollout(
        model, [START], treated_action="A", control_action="B", rollouts=20)
    # A predictive model trained on observed trajectories can motivate a trial,
    # but its simulation cannot clear the controlled-evidence promotion gate.
    verdict = propose_with_effect("prompt", "rollout win", est, rollback="snap")
    assert not verdict.promote
    assert "effect estimate not trustworthy" in verdict.blocking_reason


def test_transitions_from_trajectories():
    steps = [
        TrajectoryStep(ts=0, goal_id=1, episode_id=1, step=0, role="r", tool="A"),
        TrajectoryStep(ts=0, goal_id=1, episode_id=1, step=1, role="r", tool="go",
                       is_final=True, outcome=1.0),
    ]

    def state_fn(ep, i):
        return ("good",) if ep[i].tool == "go" else ("start",)

    def action_fn(ep, i):
        return ep[i].tool

    def outcome_fn(ep):
        return ep[-1].outcome

    trans = transitions_from_trajectories(
        steps, state_fn=state_fn, action_fn=action_fn, outcome_fn=outcome_fn)
    assert len(trans) == 2
    assert trans[0].next_state == ("good",) and trans[0].next_state is not None
    assert trans[1].next_state is None and trans[1].outcome == 1.0
