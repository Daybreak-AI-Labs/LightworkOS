"""Proposer disagreement signal: normalized answer entropy.

``answer_entropy(answers)`` returns a normalized Shannon entropy in [0, 1]
over hash-clustered answers (0 = all identical, 1 = every answer unique).
The spawn machinery computes it after a parallel fan-out and posts it to the
blackboard, so the orchestrator's verify branch and the trajectory-donation
selector can read how much the proposers diverged.

Estimation is intentionally cheap: a normalized hash-cluster entropy over the
first ~256 chars of each answer, not an embedding model. The signal is
observability only: nothing re-fans-out adaptively on high disagreement.
"""
from __future__ import annotations

import math
import re
from collections import Counter

_NORM_RE = re.compile(r"\s+")


def _normalize(text: str, prefix_len: int = 256) -> str:
    """Strip whitespace + truncate so trivial formatting differences
    don't read as 'disagreement'."""
    return _NORM_RE.sub(" ", text.strip())[:prefix_len].lower()


def answer_entropy(answers: list[str]) -> float:
    """Normalized Shannon entropy across answer clusters in [0, 1].

    0 = all answers identical; 1 = every answer unique.
    """
    if len(answers) <= 1:
        return 0.0
    buckets = Counter(_normalize(a) for a in answers)
    n = sum(buckets.values())
    if n == 0:
        return 0.0
    # H = -sum(p log p)
    h = -sum((c / n) * math.log(c / n) for c in buckets.values())
    # Normalize by max entropy log(n) (when all unique).
    h_max = math.log(n)
    return h / h_max if h_max > 0 else 0.0
