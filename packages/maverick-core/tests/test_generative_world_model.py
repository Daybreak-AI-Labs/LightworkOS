"""The generative (backoff) world-model must generalise to novel-but-similar
states where the tabular model is blind -- without erasing "escalate the
unknown" for a wholly novel context.
"""
from __future__ import annotations

from maverick import rehearsal as rh
from maverick.counterfactual_rollout import Transition, TransitionModel
from maverick.generative_world_model import BackoffTransitionModel

# state = (domain, sub_context); backoff drops the trailing (specific) feature.
FIN_A = ("fin", "ctxA")
FIN_B = ("fin", "ctxB")
FIN_NEW = ("fin", "ctxNEVER_SEEN")
LEGAL = ("legal", "ctxA")


def _corpus():
    return (
        [Transition(FIN_A, "X", None, 1.0)] * 10
        + [Transition(FIN_B, "X", None, 0.0)] * 10
    )


def test_generalises_where_tabular_is_blind():
    transitions = _corpus()
    tab = TransitionModel().fit(transitions)
    gen = BackoffTransitionModel(min_support=3, min_specificity=1).fit(transitions)

    # A state never seen in full: the tabular model has zero support; the backoff
    # model recognises the domain prefix and vouches.
    assert tab.support(FIN_NEW, "X") == 0
    assert gen.support(FIN_NEW, "X") >= 3


def test_specific_context_wins_when_it_has_data():
    gen = BackoffTransitionModel(min_support=3).fit(_corpus())
    # The full context distinguishes the two outcomes...
    assert gen._terminal_outcome((FIN_A, "X")) > 0.8
    assert gen._terminal_outcome((FIN_B, "X")) < 0.2
    # ...while a novel sub-context backs off to the domain average (~0.5).
    assert 0.3 < gen._terminal_outcome((FIN_NEW, "X")) < 0.7


def test_wholly_novel_domain_still_escalates():
    # min_specificity=1: a novel sub-context within a known domain generalises,
    # but a never-seen DOMAIN backs off past the floor -> unknown -> escalate.
    gen = BackoffTransitionModel(min_support=3, min_specificity=1).fit(_corpus())
    assert gen.support(LEGAL, "X") == 0


def test_drop_in_rehearsal_contrast():
    transitions = _corpus()
    tab = TransitionModel().fit(transitions)
    gen = BackoffTransitionModel().fit(transitions)

    # Same plan, same novel-but-similar state: the tabular twin escalates (it has
    # never seen this exact state); the generative twin can vouch and decide.
    assert rh.rehearse(tab, FIN_NEW, ["X"]).decision == rh.ESCALATE
    gen_verdict = rh.rehearse(gen, FIN_NEW, ["X"])
    assert gen_verdict.known
    assert gen_verdict.decision in (rh.PROCEED, rh.BLOCK, rh.ESCALATE)

    # But a wholly novel domain still escalates even on the generative model.
    assert rh.rehearse(gen, LEGAL, ["X"]).decision == rh.ESCALATE


def test_one_step_accuracy_inherited():
    gen = BackoffTransitionModel().fit([Transition(("a",), "go", ("b",))] * 10)
    acc, n = gen.one_step_accuracy([Transition(("a",), "go", ("b",))] * 5)
    assert acc == 1.0 and n == 5
