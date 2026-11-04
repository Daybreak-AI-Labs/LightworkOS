"""The Operations Scientist -- an agent that discovers a better way to work and
proves it.

Every agent today *executes* work a human already knows how to do. The unlock is
an agent that **discovers a better process than the incumbent and proves it
causally.** This is the discovery loop, built on the Operating Twin:

    HYPOTHESIZE  -- from the causal structure of production: pair a *harmful*
                    action (a data_engine failure class, ci_high < 0) with the
                    *beneficial* habit that should replace it (a consolidated
                    procedural memory, ci_low > 0). "Stop doing A; do B."
    SIMULATE     -- test the swap in the learned world-model (g-computation
                    rollout, candidate B vs baseline A). A predicted lift, with
                    the model calibration-bounded, promotes the hypothesis from a
                    hunch to a candidate worth a real experiment.
    EXPERIMENT   -- (downstream) run the swap on a fraction, measure the REAL
                    outcome (Consequence Engine), attribute the lift causally
                    (promotion_effect), and ship through the safety ladder.

This module is the discovery + simulation core (hypothesis from causal structure,
validated in the world-model). The LLM-creative hypothesis generation and the
live A/B harness are seams; the rigorous core -- propose a swap the data says
should help, prove it in simulation before spending a real experiment -- is here.

Pure + ON by default. ``propose`` on no failures / no memories returns ``[]``;
``simulate`` on an untrustworthy model returns a non-promoting result.
"""
from __future__ import annotations

from dataclasses import dataclass

from .config import governed_learning_env_flag
from .counterfactual_rollout import estimate_effect_via_rollout


@dataclass(frozen=True)
class Hypothesis:
    """A discoverable, testable improvement: stop ``baseline_action``, do
    ``candidate_action`` -- the data says it should lift outcomes by ``predicted_lift``."""

    baseline_action: str    # the harmful action to retire
    candidate_action: str   # the beneficial habit to adopt
    predicted_lift: float   # |harm avoided| + benefit gained (from causal structure)
    rationale: str


@dataclass(frozen=True)
class SimResult:
    """A hypothesis tested in the world-model before any real experiment."""

    hypothesis: Hypothesis
    sim_lift: float         # predicted outcome(candidate) - outcome(baseline)
    trustworthy: bool       # the world-model was calibrated enough to believe it

    @property
    def worth_experimenting(self) -> bool:
        """Promote from hunch to real experiment only on a trustworthy positive lift."""
        return self.trustworthy and self.sim_lift > 0.0


def enabled() -> bool:
    """Whether the default-on Operations Scientist may run."""
    _v = governed_learning_env_flag("MAVERICK_OPERATIONS_SCIENTIST")
    if _v is not None:
        return _v
    try:
        from .config import get_operations_scientist

        return bool(get_operations_scientist().get("enable", False))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def propose(failure_classes, memories, *, top_k: int = 10) -> list[Hypothesis]:
    """Pair each harmful action with the best beneficial habit -> swap hypotheses.

    ``failure_classes`` are ``data_engine.FailureClass`` (causally harmful);
    ``memories`` are procedural memories (duck-typed: ``.action``, ``.benefit``).
    Each hypothesis swaps a harmful action for the single best beneficial one;
    ranked by predicted lift (the harm we'd avoid plus the benefit we'd gain).
    """
    benefits = [(m.action, float(m.benefit)) for m in memories
                if float(getattr(m, "benefit", 0.0)) > 0.0]
    if not benefits:
        return []
    best_action, best_benefit = max(benefits, key=lambda kv: kv[1])

    out: list[Hypothesis] = []
    for fc in failure_classes:
        if getattr(fc, "ci_high", 0.0) >= 0.0 or fc.action == best_action:
            continue  # only confidently-harmful actions, and don't swap A for A
        harm = abs(fc.causal_effect)
        out.append(Hypothesis(
            baseline_action=fc.action, candidate_action=best_action,
            predicted_lift=harm + best_benefit,
            rationale=(f"'{fc.action}' lowers outcome ~{harm:.2f}; '{best_action}' raises "
                       f"it ~{best_benefit:.2f} -- swap to recover ~{harm + best_benefit:.2f}"),
        ))
    out.sort(key=lambda h: h.predicted_lift, reverse=True)
    return out[:top_k]


def propose_creative(failure_classes, *, generate, candidates_per: int = 3,
                     top_k: int = 10) -> list[Hypothesis]:
    """Propose genuinely NEW interventions, not just swaps from known habits.

    For each causally-harmful failure class, ``generate(failure_class) -> list[str]``
    (an injected LLM seam) suggests candidate replacement actions the data hasn't
    tried -- the *creative* half of discovery. Each becomes a hypothesis whose
    predicted lift is the harm avoided; the benefit is unknown until ``simulate``
    validates it in the world-model, so a wild idea can't reach a real experiment
    on confidence alone. ``generate`` is injected so this module stays
    LLM-agnostic and trivially testable; the caller wires it to a provider.
    """
    out: list[Hypothesis] = []
    for fc in failure_classes:
        if getattr(fc, "ci_high", 0.0) >= 0.0:
            continue  # only confidently-harmful classes
        try:
            candidates = generate(fc) or []
        except Exception:  # pragma: no cover -- a flaky generator yields nothing
            candidates = []
        seen: set = set()
        for cand in candidates[:candidates_per]:
            cand = str(cand).strip()
            if not cand or cand == fc.action or cand in seen:
                continue
            seen.add(cand)
            out.append(Hypothesis(
                baseline_action=fc.action, candidate_action=cand,
                predicted_lift=abs(fc.causal_effect),   # benefit proven later, in sim
                rationale=(f"proposed '{cand}' to replace harmful '{fc.action}' "
                           f"(lowers outcome ~{abs(fc.causal_effect):.2f}); "
                           "validate in simulation before experimenting"),
            ))
    out.sort(key=lambda h: h.predicted_lift, reverse=True)
    return out[:top_k]


def simulate(hypothesis: Hypothesis, model, start_states, *, rollouts: int = 100,
             min_support: int = 5) -> SimResult:
    """Test the swap in the world-model: g-computation lift of candidate vs baseline.

    Reuses the Operating Twin's rollout estimator, so the result inherits its
    calibration gate -- an untrustworthy model yields ``worth_experimenting ==
    False`` and the hypothesis never reaches a real experiment on a guess.
    """
    est = estimate_effect_via_rollout(
        model, list(start_states),
        treated_action=hypothesis.candidate_action,
        control_action=hypothesis.baseline_action,
        rollouts=rollouts, min_support=min_support,
    )
    return SimResult(hypothesis=hypothesis, sim_lift=est.effect, trustworthy=est.trustworthy)


__all__ = ["Hypothesis", "SimResult", "enabled", "propose", "propose_creative", "simulate"]
