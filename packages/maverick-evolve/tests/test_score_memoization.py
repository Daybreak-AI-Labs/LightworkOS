"""Score memoization in the config-evolution search.

Regression target: ``search.evolve`` called ``score()`` unconditionally for
the seed and every child. The mutation space is a small discrete lattice and
``mutate`` is a ±1 random walk, so configs are revisited constantly — and one
``score()`` is a full |cases| evaluation, each case a complete swarm run.
The continuous loop also re-scored each round's seed (the prior round's best,
already evaluated).
"""
from __future__ import annotations

import asyncio
import random

from maverick_evolve.search import evolve


def test_revisited_config_scored_once():
    calls: list[dict] = []

    async def score(config):
        calls.append(dict(config))
        return float(config["knob"])

    # mutate flips between exactly two configs -> heavy revisiting
    def mutate(config):
        return {"knob": 1 if config["knob"] == 2 else 2}

    best = asyncio.run(evolve(
        {"knob": 1}, mutate, score,
        generations=10, rng=random.Random(7),
    ))
    # 3 distinct configs max ({1},{2}) — the seed and its flip — so at most
    # 2 evaluations regardless of 10 generations.
    assert len(calls) <= 2
    assert best.score == 2.0


def test_seed_score_skips_seed_evaluation():
    calls: list[dict] = []

    async def score(config):
        calls.append(dict(config))
        return 0.5

    def mutate(config):
        return {"knob": config["knob"] + 1}

    asyncio.run(evolve(
        {"knob": 0}, mutate, score,
        generations=2, rng=random.Random(1), seed_score=0.9,
    ))
    assert {"knob": 0} not in calls  # seed never re-evaluated


def test_continuous_loop_threads_prior_best_score(monkeypatch):
    import maverick_evolve.loop as loop_mod

    seen_seed_scores: list[float | None] = []

    async def fake_ewe(seed_config, cases, agent_factory, *, seed_score=None, **kw):
        seen_seed_scores.append(seed_score)
        from maverick_evolve.archive import Candidate
        return Candidate(config=dict(seed_config), score=0.7)

    monkeypatch.setattr(loop_mod, "evolve_with_eval", fake_ewe)
    monkeypatch.setattr(loop_mod, "calibration_frozen", lambda: False)
    asyncio.run(loop_mod.evolve_continuous(
        {"knob": 1}, [], lambda cfg: None, rounds=3, generations_per_round=1,
    ))
    # round 0: unscored seed; rounds 1-2: prior best's score passed down
    assert seen_seed_scores == [None, 0.7, 0.7]
