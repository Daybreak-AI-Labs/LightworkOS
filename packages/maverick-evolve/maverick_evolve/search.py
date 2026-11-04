"""Config-only evolutionary search.

Propose a mutated config, score it on a development split, keep it only if it
genuinely beats the incumbent. Mutations are bounded to **configuration**
(prompts, role roster, workflow knobs) -- never code -- so a candidate can't
escape the sandbox and this rung is safe to actually run.

Dependency-injected: the caller supplies ``mutate(config) -> config`` and an
async ``score(config) -> float`` (typically wrapping ``eval_harness.evaluate``
on a development set, gated by ``maverick.calibration``). Pure control flow, so
it tests without a model. Code self-modification is a later, separate rung.
"""
from __future__ import annotations

import copy
import random
from collections.abc import Awaitable, Callable

from .archive import Archive, Candidate, _config_id


async def evolve(
    seed_config: dict,
    mutate: Callable[[dict], dict],
    score: Callable[[dict], Awaitable[float]],
    *,
    generations: int = 10,
    archive: Archive | None = None,
    rng: random.Random | None = None,
    min_improvement: float = 0.0,
    seed_score: float | None = None,
) -> Candidate:
    """Evolve ``seed_config`` for ``generations`` rounds; return the best found.

    Each round: sample a parent from the archive (weighted by score), mutate it,
    score the child, and admit it to the archive. The returned best is the
    archive's top scorer -- and because admission only *keeps* what scores well
    and branching pulls from a *diverse* archive, this resists the plateau trap.
    ``min_improvement`` lets the caller require a child to beat its parent by a
    margin before it's treated as progress (guards against eval noise).

    Scores are memoized by config identity WITHIN this run: the mutation space
    is a small discrete lattice and the ±1 random walk revisits configs
    constantly, while one ``score()`` is a full |cases| evaluation — each case
    an entire swarm run. A revisit reuses the first sample (noise re-sampling
    is not worth the eval cost). ``seed_score`` lets a caller that already
    evaluated the seed (the continuous loop re-seeds each round from the prior
    round's scored best) skip re-paying that evaluation.
    """
    rng = rng or random.Random()
    archive = archive or Archive()

    memo: dict[str, float] = {}

    async def _score_memo(config: dict) -> float:
        cid = _config_id(config)
        if cid in memo:
            return memo[cid]
        s = await score(config)
        memo[cid] = s
        return s

    if seed_score is None:
        seed_score = await _score_memo(seed_config)
    else:
        memo[_config_id(seed_config)] = seed_score
    seed = Candidate(config=seed_config, score=seed_score)
    archive.add(seed)
    # Track the incumbent best explicitly: admission to the archive stays
    # unconditional (diversity/plateau traversal depends on keeping equal- and
    # near-scoring configs to branch from), but a child only *displaces* the
    # returned best when it clears the noise margin. At min_improvement=0.0 that
    # is "strictly better", so eval jitter can't ratchet a tie into a new best.
    best = seed

    for _ in range(max(0, generations)):
        parent = archive.sample(rng) or archive.best()
        child_config = mutate(copy.deepcopy(parent.config))
        child_score = await _score_memo(child_config)
        child = archive.add(Candidate(config=child_config, score=child_score))
        if child.score > best.score + min_improvement:
            best = child

    assert best is not None  # archive always holds at least the seed
    return best


__all__ = ["evolve"]
