"""End-to-end: one trajectory corpus must flow through every Operating Twin
seam -- learning (stratified + rollout) and governance (rehearsal) -- and
produce sane, composed results. The unit tests cover each estimator; this proves
the adapters and interfaces actually fit together.
"""
from __future__ import annotations

from maverick import promotion_effect as pe
from maverick import rehearsal as rh
from maverick.counterfactual_rollout import (
    TransitionModel,
    estimate_effect_via_rollout,
    transitions_from_trajectories,
)
from maverick.si_producers import propose_with_effect
from maverick.trajectory_store import TrajectoryStep


def _corpus():
    """Episodes where tool 'X' causes +0.3 over 'Y' within domain, but is
    confounded with a high-base domain. Both arms appear in both domains
    (overlap), and every episode carries a terminal outcome."""
    rows = []
    eid = 0

    def episode(domain, tool, outcome):
        nonlocal eid
        eid += 1
        return [
            TrajectoryStep(ts=0, goal_id=1, episode_id=eid, step=0, role="orch",
                           tool=tool, domain=domain),
            TrajectoryStep(ts=0, goal_id=1, episode_id=eid, step=1, role="orch",
                           tool="", is_final=True, outcome=outcome, domain=domain),
        ]

    for _ in range(20):
        rows += episode("fin", "X", 0.9)
    for _ in range(8):
        rows += episode("fin", "Y", 0.6)
    for _ in range(8):
        rows += episode("legal", "X", 0.6)
    for _ in range(20):
        rows += episode("legal", "Y", 0.3)
    return rows


def test_learning_path_stratified_to_gate():
    steps = _corpus()

    units = pe.units_from_trajectories(
        steps,
        treatment_fn=lambda ep: 1 if any(s.tool == "X" for s in ep) else 0,
        outcome_fn=lambda ep: next((s.outcome for s in ep if s.is_final), None),
        stratum_fn=lambda ep: (ep[0].domain,),
    )
    assert len(units) == 56

    est = pe.estimate_effect(units, adjusted_for=("domain",))
    # True within-domain effect is +0.3; the naive (confounded) number is larger.
    assert abs(est.effect - 0.3) < 1e-9
    assert est.naive_effect > 0.4
    assert not est.trustworthy and est.ci_low > 0.0

    # The logged trajectory comparison may motivate an experiment, but the
    # promotion adapter must reject it before it reaches the controller.
    verdict = propose_with_effect("prompt", "adopt tool X", est, rollback="snap")
    assert not verdict.promote


def test_rollout_and_rehearsal_share_one_world_model():
    steps = _corpus()

    transitions = transitions_from_trajectories(
        steps,
        # The post-decision state must carry the decision's consequence, or the
        # model can't attribute outcome to action.
        state_fn=lambda ep, i: ("start",) if i == 0 else ("after", ep[i - 1].tool),
        action_fn=lambda ep, i: ep[i].tool or "finish",
        outcome_fn=lambda ep: next((s.outcome for s in ep if s.is_final), None),
    )
    model = TransitionModel().fit(transitions)

    # Learning via g-computation off the same model.
    est = estimate_effect_via_rollout(
        model, [("start",)], treated_action="X", control_action="Y", rollouts=50)
    assert est.effect > 0.0 and est.trustworthy

    # Governance: rehearse the better plan against that same model.
    good = rh.rehearse(model, ("start",), ["X"])
    bad = rh.rehearse(model, ("start",), ["Y"])
    assert good.predicted_outcome > bad.predicted_outcome
    assert good.known and bad.known

    # And the twin refuses to vouch for a move it has never seen here.
    unknown = rh.rehearse(model, ("start",), ["nonexistent_tool"])
    assert unknown.decision == rh.ESCALATE and not unknown.known
