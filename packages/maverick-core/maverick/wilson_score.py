"""Wilson score confidence interval for a binomial proportion.

The statistically-honest "how good is this, conservatively?" given ``n``
observations: a 1-of-1 win has a wide, low-confidence interval; a 50-of-50
win has a narrow one near 1.0. At small ``n`` the raw point estimate
(``successes / n``) is close to meaningless -- 1 win in 5 uses (0.2) and 0
wins in 5 uses (0.0) both have a 95% upper bound well above 0.2 -- so a
decision gated on "the win rate is at or below X" should compare against a
bound, not the point estimate.

Pulled out as its own leaf module (``math`` only, no other imports) because
three callers need the exact same formula: ``self_harness``'s promotion/
retirement math, ``skill.stats.evictable``'s eviction gate and
``immune.oversight``'s conservative catch rate. A prior version duplicated
this formula in the first two modules on the theory that importing across
them would create a layering cycle; that theory doesn't hold (neither module
imports the other, in either direction), and the duplication meant a future
numerical fix (a different ``z``, an edge-case correction) would have to be
found and applied by hand in two places.
"""
from __future__ import annotations

import math


def wilson_lower_bound(successes: float, n: int, z: float = 1.96) -> float:
    """Lower bound of the Wilson score interval for a binomial proportion."""
    if n <= 0:
        return 0.0
    phat = max(0.0, min(1.0, successes / n))
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = phat + z2 / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat) + z2 / (4 * n)) / n)
    return max(0.0, (centre - margin) / denom)


def wilson_upper_bound(successes: float, n: int, z: float = 1.96) -> float:
    """Upper endpoint paired with :func:`wilson_lower_bound`."""
    if n <= 0:
        return 1.0
    phat = max(0.0, min(1.0, successes / n))
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = phat + z2 / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat) + z2 / (4 * n)) / n)
    return min(1.0, (centre + margin) / denom)


__all__ = ["wilson_lower_bound", "wilson_upper_bound"]
