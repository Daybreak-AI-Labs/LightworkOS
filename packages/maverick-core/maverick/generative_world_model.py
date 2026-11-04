"""A generative (feature-backoff) world-model -- generalising beyond what was seen.

The tabular :class:`~maverick.counterfactual_rollout.TransitionModel` only knows
``(state, action)`` pairs it has observed; in a state it has never seen it
returns no support, so rehearsal escalates and g-computation can't roll forward.
That's honest but it never *generalises*; accumulated learning needs a model that
gets more useful as the Operating Record grows, including for novel-but-similar
contexts.

``BackoffTransitionModel`` is that generative step, kept dependency-free (no
torch): it represents a state as an ordered tuple of features from **general to
specific** (e.g. ``(domain, role, depth_bucket, last_tool)``) and learns the
dynamics at *every* prefix granularity at once. To predict in a state it hasn't
seen in full, it **backs off** to the longest prefix it has enough support for --
generalising across the specific features it lacks data on. A generative neural
model is a future drop-in behind the same interface; this is the n-gram-style
first version, mirroring "stratified before neural" for Phase A.

The crucial governance subtlety: generalisation must not erase the
"escalate the unknown" property. So support (what rehearsal gates on) only counts
prefixes at or above ``min_specificity`` -- the model will generalise *within* a
domain but a wholly novel domain still backs off past the floor and is escalated,
never waved through on the fully-marginal prior. Sampling during a rollout may
back off further (to keep the simulation moving); only the *vouching* is floored.
"""
from __future__ import annotations

from collections.abc import Hashable

from .counterfactual_rollout import _TERMINAL, TransitionModel


class BackoffTransitionModel(TransitionModel):
    """Dynamics learned at every state-feature prefix; predicts by backing off.

    ``min_support`` is the count a prefix needs before it's preferred (more
    specific contexts win when they have the data). ``min_specificity`` is the
    shortest prefix length that still counts as "known" for support/vouching --
    below it, the context is treated as unseen and rehearsal escalates.
    """

    def __init__(self, *, min_support: int = 3, min_specificity: int = 1, alpha: float = 0.5):
        super().__init__(alpha=alpha)
        self.min_support = min_support
        self.min_specificity = min_specificity

    def fit(self, transitions) -> BackoffTransitionModel:
        for t in transitions:
            for length in range(len(t.state) + 1):
                pre = t.state[:length]
                self._next[(pre, t.action)][t.next_state] += 1
                self._policy[pre][t.action] += 1
                if t.next_state is _TERMINAL:
                    y = 0.0 if t.outcome is None else float(t.outcome)
                    self._term[(pre, t.action)][0] += y
                    self._term[(pre, t.action)][1] += 1
        return self

    def _prefixes(self, state: tuple, *, floor: int = 0):
        """Yield ``state``'s prefixes longest-first, down to length ``floor``."""
        for length in range(len(state), floor - 1, -1):
            yield state[:length]

    # --- vouching (floored at min_specificity) -----------------------------

    def support(self, state: tuple, action: Hashable) -> int:
        """Effective support: the most specific prefix (>= min_specificity) that
        has enough data. 0 when even the floor prefix is unseen -> escalate."""
        for pre in self._prefixes(state, floor=self.min_specificity):
            counts = self._next.get((pre, action))
            total = sum(counts.values()) if counts else 0
            if total >= self.min_support:
                return total
        return 0

    # --- prediction (may back off all the way, to keep rollouts moving) -----

    def _next_counts(self, state: tuple, action: Hashable):
        best = None
        for pre in self._prefixes(state):
            counts = self._next.get((pre, action))
            if counts:
                best = best or counts
                if sum(counts.values()) >= self.min_support:
                    return counts
        return best

    def _policy_counts(self, state: tuple):
        best = None
        for pre in self._prefixes(state):
            pol = self._policy.get(pre)
            if pol:
                best = best or pol
                if sum(pol.values()) >= self.min_support:
                    return pol
        return best

    def _terminal_outcome(self, sa: tuple) -> float:
        state, action = sa
        fallback = None
        for pre in self._prefixes(state):
            s, n = self._term.get((pre, action), (0.0, 0))
            if n > 0:
                if fallback is None:
                    fallback = (s, n)
                if n >= self.min_support:
                    return (s + self.alpha) / (n + 2 * self.alpha)
        if fallback is not None:
            s, n = fallback
            return (s + self.alpha) / (n + 2 * self.alpha)
        return 0.5


__all__ = ["BackoffTransitionModel"]
