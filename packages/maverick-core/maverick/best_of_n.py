"""Verifier-guided best-of-N: generate several candidates, keep the best.

SOTA test-time scaling: scaling the *generator* axis (sample N candidate
answers) and selecting with a verifier as the value function beats a single
greedy pass on hard tasks. Lightwork already scales the *verifier* axis (MAV
ensemble in ``verifier.py``); this adds the orthogonal generator axis.

This is the tractable core of verifier-guided search. It is dependency-injected
(caller supplies an async ``generate`` and an async ``verify``) so it composes
with the existing agent loop and the cross-family verifier without this module
importing them, and stays trivially testable. Full tree search / MCTS over
actions is a documented extension on top of this selection primitive.

Off by default + fail-open at the call site; this module is a pure primitive.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .config import env_flag

log = logging.getLogger(__name__)


class AllAttemptsFailed(Exception):
    """Every candidate/attempt in a best-of-N / racing primitive failed.

    Defined here once and re-exported by latency_best_of_n, so a caller
    catching it from one module also catches it from the other."""


def enabled() -> bool:
    _v = env_flag("MAVERICK_BEST_OF_N")
    if _v is not None:
        return _v
    try:
        from .config import get_search
        return bool(get_search()["enable"])
    except Exception:  # pragma: no cover
        return False


def n_candidates(default: int = 3) -> int:
    try:
        from .config import get_search
        return max(1, int(get_search()["n"]))
    except Exception:  # pragma: no cover
        return default


@dataclass
class Candidate:
    text: str
    confidence: float
    accepts: bool = False


@dataclass
class BestOfNResult:
    best: str
    best_confidence: float
    candidates: list[Candidate] = field(default_factory=list)


async def best_of_n(
    generate: Callable[[], Awaitable[str]],
    verify: Callable[[str], Awaitable[object]],
    *,
    n: int = 3,
    accept_early: bool = True,
    select: Callable[[list[Candidate]], Candidate] | None = None,
) -> BestOfNResult:
    """Sample ``n`` candidates, score each with ``verify``, return the best.

    ``generate()`` yields one candidate answer; ``verify(candidate)`` returns a
    verdict with ``.confidence`` (float) and ``.accepts`` (bool) -- the shape of
    ``verifier.VerifierVerdict``. Candidates are generated sequentially (so an
    early accept can short-circuit) and the highest-confidence one wins.

    ``accept_early``: stop as soon as a candidate is accepted with confidence
    >= any already seen (saves compute on easy tasks). Empty/failed generations
    are skipped; if all fail, raises ValueError (the caller falls back to its
    normal single-pass path).

    ``select``: an optional hook that chooses the winner from the scored
    candidates, overriding the default ``max(accepts, confidence)``. This is the
    seam where learned test-time adaptation plugs in --
    :func:`maverick.jit_rl.make_best_of_n_selector` factors a candidate's
    learned advantage into the choice (and reduces to the default with a cold
    store). ``None`` keeps the pure verifier-guided selection.
    """
    n = max(1, int(n))
    scored: list[Candidate] = []
    for _ in range(n):
        try:
            text = await generate()
        except Exception as e:  # pragma: no cover -- caller's generator failed
            log.debug("best_of_n: generate failed: %s", e)
            continue
        if not text or not text.strip():
            continue
        try:
            verdict = await verify(text)
        except Exception as e:  # pragma: no cover
            log.debug("best_of_n: verify failed: %s", e)
            continue
        conf = float(getattr(verdict, "confidence", 0.0) or 0.0)
        acc = bool(getattr(verdict, "accepts", False))
        scored.append(Candidate(text=text, confidence=conf, accepts=acc))
        if accept_early and acc and conf >= max(c.confidence for c in scored):
            break

    if not scored:
        raise ValueError("best_of_n: no usable candidates generated")
    if select is not None:
        try:
            best = select(scored)
        except Exception as e:  # pragma: no cover -- a bad hook must not lose the answer
            log.debug("best_of_n: select hook failed: %s; using default", e)
            best = max(scored, key=lambda c: (c.accepts, c.confidence))
    else:
        best = max(scored, key=lambda c: (c.accepts, c.confidence))
    return BestOfNResult(
        best=best.text, best_confidence=best.confidence, candidates=scored,
    )


__all__ = ["enabled", "n_candidates", "Candidate", "BestOfNResult", "best_of_n"]
