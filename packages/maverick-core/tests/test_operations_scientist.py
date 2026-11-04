"""The Operations Scientist: hypothesize a swap from causal structure, then prove
the lift in the world-model before any real experiment.
"""
from __future__ import annotations

from dataclasses import dataclass

from maverick import operations_scientist as ops
from maverick.counterfactual_rollout import Transition, TransitionModel
from maverick.data_engine import FailureClass

START, GOOD, BAD = ("start",), ("good",), ("bad",)


@dataclass(frozen=True)
class _Mem:  # duck-typed procedural memory
    action: str
    benefit: float


def _fc(action, effect, ci_high):
    return FailureClass(action=action, count=5, mean_outcome=0.3, causal_effect=effect,
                        ci_low=effect - 0.1, ci_high=ci_high, trustworthy=True,
                        exemplars=((1, 1),))


def test_propose_swaps_harmful_for_best_beneficial():
    hyps = ops.propose(
        [_fc("A", -0.5, -0.2), _fc("C", -0.3, -0.1)],
        [_Mem("B", 0.4), _Mem("weak", 0.1)],
    )
    # A is the more harmful -> ranked first; both swap to the BEST habit (B).
    assert hyps[0].baseline_action == "A" and hyps[0].candidate_action == "B"
    assert abs(hyps[0].predicted_lift - (0.5 + 0.4)) < 1e-9
    assert {h.candidate_action for h in hyps} == {"B"}


def test_propose_skips_non_harmful_and_self_swaps():
    hyps = ops.propose(
        [_fc("B", -0.5, -0.2),          # harmful action IS the best habit -> skip self-swap
         _fc("D", -0.2, 0.05)],          # CI crosses zero -> not confidently harmful
        [_Mem("B", 0.4)],
    )
    assert hyps == []


def test_propose_no_beneficial_habits():
    assert ops.propose([_fc("A", -0.5, -0.2)], []) == []


def _world():
    return TransitionModel().fit(
        [Transition(START, "B", GOOD)] * 12 + [Transition(GOOD, "go", None, 1.0)] * 12
        + [Transition(START, "A", BAD)] * 12 + [Transition(BAD, "go", None, 0.0)] * 12
    )


def test_simulate_validates_a_good_swap():
    h = ops.Hypothesis(baseline_action="A", candidate_action="B",
                       predicted_lift=0.9, rationale="")
    res = ops.simulate(h, _world(), [START], rollouts=50)
    assert res.sim_lift > 0.5 and res.trustworthy
    assert res.worth_experimenting


def test_simulate_untrustworthy_model_is_not_worth_experimenting():
    # A model that has never seen the candidate action can't vouch for the swap.
    thin = TransitionModel().fit([Transition(START, "A", BAD)] * 3)
    h = ops.Hypothesis(baseline_action="A", candidate_action="B",
                       predicted_lift=0.9, rationale="")
    res = ops.simulate(h, thin, [START], rollouts=20)
    assert not res.worth_experimenting


def test_enabled_off_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_OPERATIONS_SCIENTIST", raising=False)
    monkeypatch.setattr("maverick.config.get_operations_scientist", lambda: {"enable": False})
    assert ops.enabled() is False
    monkeypatch.setenv("MAVERICK_OPERATIONS_SCIENTIST", "1")
    assert ops.enabled() is True


def test_propose_creative_generates_new_interventions():
    # an injected LLM generator proposes actions the data hasn't tried
    def generate(fc):
        return {"A": ["new_tool_1", "new_tool_2"], "C": ["batch_first"]}.get(fc.action, [])

    hyps = ops.propose_creative([_fc("A", -0.5, -0.2), _fc("C", -0.3, -0.1)],
                                generate=generate)
    swaps = {(h.baseline_action, h.candidate_action) for h in hyps}
    assert ("A", "new_tool_1") in swaps and ("C", "batch_first") in swaps
    assert hyps[0].baseline_action == "A"          # most harmful first
    assert hyps[0].predicted_lift == 0.5


def test_propose_creative_skips_self_dupes_and_non_harmful():
    def generate(fc):
        return ["A", "A", "good_one"]              # self + duplicate + one real

    hyps = ops.propose_creative(
        [_fc("A", -0.5, -0.2), _fc("D", -0.2, 0.05)],  # D's CI crosses 0 -> skipped
        generate=generate)
    assert [(h.baseline_action, h.candidate_action) for h in hyps] == [("A", "good_one")]


def test_propose_creative_survives_a_flaky_generator():
    def generate(fc):
        raise RuntimeError("LLM hiccup")
    assert ops.propose_creative([_fc("A", -0.5, -0.2)], generate=generate) == []


def test_creative_hypotheses_are_sim_validated():
    # the LLM proposes B; the world-model proves it actually helps (or wouldn't)
    wm = TransitionModel().fit(
        [Transition(START, "B", GOOD)] * 12 + [Transition(GOOD, "go", None, 1.0)] * 12
        + [Transition(START, "A", BAD)] * 12 + [Transition(BAD, "go", None, 0.0)] * 12)
    [hyp] = ops.propose_creative([_fc("A", -0.5, -0.2)], generate=lambda fc: ["B"])
    res = ops.simulate(hyp, wm, [START], rollouts=50)
    assert res.worth_experimenting and res.sim_lift > 0
