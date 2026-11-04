"""Model-based counterfactual rollouts -- Phase B of counterfactual promotion.

Stratified effect estimation (:mod:`maverick.promotion_effect`) compares
treated vs untreated episodes *within* a cell of comparable context. When the
behaviour policy confounds the decision so hard that no cell has both arms --
zero overlap -- stratification is honest but blind: it can estimate nothing.

This module estimates the effect anyway, when a weaker condition holds: the
decision's action varies *somewhere* in the corpus and the **state representation
is sufficient** (the transition dynamics don't depend on the unobserved
confounder). It fits a tabular transition model over the logged
``(state, action) -> next_state`` records -- a discrete world-model of the
agent's own environment -- and runs **g-computation**: re-simulate each starting
context with the decision's action forced to ``treated`` vs ``control``, roll
forward under the learned dynamics + observed behaviour policy to a terminal
outcome, and difference the two. This is the tabular first version of the
Operating Twin's learning half; a generative transition model is the same
interface (it returns an :class:`~maverick.promotion_effect.EffectEstimate`), so
the promotion ladder never changes when the model gets stronger.

Honest about its one assumption: g-computation identifies the effect only if the
state captures everything that confounds action with outcome (no unobserved
confounding *given the model's state*). So it is **fail-closed by calibration** --
the estimate is ``trustworthy`` only when the model predicts held-out one-step
transitions well AND both actions have real support; a null-action placebo
(treated vs treated, which must be ~0) is the built-in refutation. Promote on a
simulated counterfactual only when the simulator has earned it.

Posture (kernel rule 1): OFF by default, behind the same
``[self_improvement] causal_promotion`` knob as Phase A -- it is a stronger
estimator for the same governed capability, not a new one. Pure, dependency-free,
deterministic given a seed.
"""
from __future__ import annotations

import math
import random
from collections import defaultdict
from collections.abc import Hashable
from dataclasses import dataclass

from .promotion_effect import EffectEstimate

# Sentinel for "this (state, action) led to a terminal step".
_TERMINAL = None

_Z95 = 1.959963984540054


@dataclass(frozen=True)
class Transition:
    """One logged step: ``(state, action) -> next_state``.

    ``next_state`` is ``None`` for a terminal step, in which case ``outcome`` (in
    [0, 1]) is the episode's task result observed at that leaf.
    """

    state: tuple
    action: Hashable
    next_state: tuple | None = None
    outcome: float | None = None


class TransitionModel:
    """Smoothed tabular dynamics + behaviour policy + terminal outcomes."""

    def __init__(self, alpha: float = 0.5) -> None:
        self.alpha = alpha
        # (state, action) -> {next_state_or_None: count}
        self._next: dict[tuple, dict] = defaultdict(lambda: defaultdict(int))
        # state -> {action: count}  (the observed behaviour policy)
        self._policy: dict[tuple, dict] = defaultdict(lambda: defaultdict(int))
        # (state, action) -> [sum_outcome, n]  for terminal transitions
        self._term: dict[tuple, list] = defaultdict(lambda: [0.0, 0])

    def fit(self, transitions) -> TransitionModel:
        for t in transitions:
            sa = (t.state, t.action)
            self._next[sa][t.next_state] += 1
            self._policy[t.state][t.action] += 1
            if t.next_state is _TERMINAL:
                y = 0.0 if t.outcome is None else float(t.outcome)
                self._term[sa][0] += y
                self._term[sa][1] += 1
        return self

    def support(self, state: tuple, action: Hashable) -> int:
        return sum((self._next_counts(state, action) or {}).values())

    def actions(self, state: tuple) -> list:
        return list(self._policy.get(state, {}))

    def policy(self, state: tuple) -> dict:
        """Behaviour-policy action counts for ``state`` ({} if unseen). Public
        accessor used by speculative execution; subclasses generalise via
        ``_policy_counts``."""
        return dict(self._policy_counts(state) or {})

    def _next_counts(self, state: tuple, action: Hashable):
        """Next-state counts for ``(state, action)`` (None if unseen). Subclasses
        override to generalise (e.g. feature backoff) rather than return None."""
        return self._next.get((state, action))

    def _policy_counts(self, state: tuple):
        """Behaviour-policy action counts for ``state`` (None if unseen)."""
        return self._policy.get(state)

    @staticmethod
    def _weighted_choice(counts, rng: random.Random):
        items = list(counts.items())
        total = sum(c for _, c in items)
        r = rng.random() * total
        upto = 0.0
        for key, c in items:
            upto += c
            if r <= upto:
                return key
        return items[-1][0]

    def _sample_next(self, sa: tuple, rng: random.Random):
        counts = self._next_counts(sa[0], sa[1])
        if not counts:
            return _TERMINAL  # unseen (s,a): treat as absorbing, scored by prior
        return self._weighted_choice(counts, rng)

    def _sample_action(self, state: tuple, rng: random.Random):
        pol = self._policy_counts(state)
        if not pol:
            return None
        return self._weighted_choice(pol, rng)

    def _terminal_outcome(self, sa: tuple) -> float:
        s, n = self._term.get(sa, (0.0, 0))
        # Laplace-smoothed toward 0.5 so an unseen leaf is maximally uncertain,
        # never a confident 0 or 1.
        return (s + self.alpha) / (n + 2 * self.alpha)

    def rollout(self, start: tuple, first_action: Hashable, *, horizon: int,
                rng: random.Random) -> float:
        """One Monte-Carlo g-computation rollout: outcome under do(a0=first_action)."""
        return self.rollout_plan(start, [first_action], horizon=horizon, rng=rng)

    def rollout_plan(self, start: tuple, forced_actions, *, horizon: int,
                     rng: random.Random) -> float:
        """Roll out forcing ``forced_actions`` for the first steps, then following
        the observed behaviour policy -- the outcome under ``do(plan)``."""
        forced = list(forced_actions)
        state = start
        for step in range(horizon):
            action = forced[step] if step < len(forced) else self._sample_action(state, rng)
            if action is None:
                return self._terminal_outcome((state, None))
            sa = (state, action)
            nxt = self._sample_next(sa, rng)
            if nxt is _TERMINAL:
                return self._terminal_outcome(sa)
            state = nxt
        return self._terminal_outcome((state, self._sample_action(state, rng)))

    def one_step_accuracy(self, holdout) -> tuple[float, int]:
        """Fraction of held-out transitions whose next_state is the model's mode.

        The calibration signal: can the fitted dynamics predict transitions it
        didn't train on? Returns ``(accuracy, n_scored)``; unseen (s,a) score 0.
        """
        correct = 0
        n = 0
        for t in holdout:
            counts = self._next_counts(t.state, t.action)
            n += 1
            if not counts:
                continue
            mode = max(counts.items(), key=lambda kv: kv[1])[0]
            if mode == t.next_state:
                correct += 1
        return (correct / n if n else 0.0), n


def estimate_effect_via_rollout(
    model: TransitionModel,
    start_states,
    *,
    treated_action: Hashable,
    control_action: Hashable,
    horizon: int = 8,
    rollouts: int = 200,
    seed: int = 0,
    holdout=None,
    min_accuracy: float = 0.7,
    min_support: int = 5,
    naive_effect: float = 0.0,
    adjusted_for: tuple[str, ...] = (),
) -> EffectEstimate:
    """G-computation effect of ``treated_action`` vs ``control_action``.

    Averages, over the supplied ``start_states`` (the contexts where the decision
    is made), the rollout outcome under each forced first action; the difference
    is the causal effect. ``trustworthy`` requires both actions to have real
    support in the start states, a near-zero null-action placebo, and -- when a
    ``holdout`` set is given -- one-step predictive accuracy >= ``min_accuracy``.

    ``naive_effect`` is the unadjusted episode-level contrast (mean outcome where
    the first action was treated vs control), recorded purely for audit contrast;
    the model can't compute it (it carries no episode identity), so the caller --
    which has the grouped episodes -- supplies it. It never affects the gate.
    """
    starts = list(start_states)
    if not starts:
        return EffectEstimate(0.0, 0.0, 0.0, 0, 0, 0, 0.0, 0.0, 0.0, False, adjusted_for)

    rng = random.Random(seed)

    def mean_rollout(s0, action) -> float:
        return sum(model.rollout(s0, action, horizon=horizon, rng=rng)
                   for _ in range(rollouts)) / rollouts

    per_state_effects: list[float] = []
    placebo_effects: list[float] = []
    supported = 0
    for s0 in starts:
        if model.support(s0, treated_action) >= min_support and \
                model.support(s0, control_action) >= min_support:
            supported += 1
        y_t = mean_rollout(s0, treated_action)
        y_c = mean_rollout(s0, control_action)
        per_state_effects.append(y_t - y_c)
        # Null-action placebo: treated vs treated must read ~0 (pure MC noise).
        placebo_effects.append(mean_rollout(s0, treated_action) - y_t)

    n = len(per_state_effects)
    effect = sum(per_state_effects) / n
    var = (sum((e - effect) ** 2 for e in per_state_effects) / n / n) if n > 1 else 0.0
    half = _Z95 * math.sqrt(var) if var > 0 else 0.0
    placebo = sum(placebo_effects) / n
    overlap = supported / n

    accuracy, n_scored = (1.0, 0)
    if holdout is not None:
        accuracy, n_scored = model.one_step_accuracy(holdout)

    trustworthy = (
        overlap >= 0.5
        and abs(placebo) <= 0.05
        and (holdout is None or (n_scored > 0 and accuracy >= min_accuracy))
    )

    return EffectEstimate(
        effect=effect,
        ci_low=effect - half,
        ci_high=effect + half,
        n_used=supported,
        n_total=n,
        strata_used=n,
        overlap=overlap,
        naive_effect=naive_effect,
        placebo_effect=placebo,
        trustworthy=trustworthy,
        adjusted_for=tuple(adjusted_for),
    )


def transitions_from_trajectories(steps, *, state_fn, action_fn, outcome_fn) -> list[Transition]:
    """Build ``Transition`` records from a flat trajectory step stream.

    Steps are grouped by ``(goal_id, episode_id)`` and ordered by ``step``; each
    consecutive pair becomes a transition, and the final step becomes a terminal
    transition carrying ``outcome_fn(episode)``.
    """
    episodes: dict = {}
    for s in steps:
        episodes.setdefault((s.goal_id, s.episode_id), []).append(s)
    out: list[Transition] = []
    for ep in episodes.values():
        ep = sorted(ep, key=lambda s: s.step)
        y = outcome_fn(ep)
        for i in range(len(ep)):
            state = state_fn(ep, i)
            action = action_fn(ep, i)
            if state is None or action is None:
                continue
            if i + 1 < len(ep):
                nxt = state_fn(ep, i + 1)
                out.append(Transition(state=state, action=action, next_state=nxt))
            else:
                out.append(Transition(state=state, action=action,
                                      next_state=_TERMINAL, outcome=y))
    return out


__all__ = [
    "Transition",
    "TransitionModel",
    "estimate_effect_via_rollout",
    "transitions_from_trajectories",
]
