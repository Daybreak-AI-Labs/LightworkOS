from __future__ import annotations

import random

import pytest
from maverick_evolve.archive import Archive
from maverick_evolve.search import evolve


@pytest.mark.asyncio
async def test_evolve_finds_better_config():
    # Fitness = the value of config["n"]; mutate nudges it up or down.
    async def score(cfg: dict) -> float:
        return float(cfg["n"])

    def mutate(cfg: dict) -> dict:
        cfg["n"] = cfg["n"] + rng.choice([-1, 1, 1, 2])  # biased upward
        return cfg

    rng = random.Random(0)
    best = await evolve({"n": 0}, mutate, score, generations=40, rng=rng)
    assert best.config["n"] > 0  # search climbed above the seed


@pytest.mark.asyncio
async def test_evolve_returns_seed_when_no_improvement():
    async def score(cfg: dict) -> float:
        return 1.0  # flat landscape

    def mutate(cfg: dict) -> dict:
        cfg["v"] = cfg.get("v", 0) + 1
        return cfg

    best = await evolve({"v": 0}, mutate, score, generations=5,
                        rng=random.Random(1))
    assert best.score == 1.0  # everything ties; a valid best is still returned


@pytest.mark.asyncio
async def test_evolve_populates_archive():
    arch = Archive()

    async def score(cfg: dict) -> float:
        return float(cfg.get("n", 0))

    def mutate(cfg: dict) -> dict:
        cfg["n"] = cfg.get("n", 0) + 1
        return cfg

    await evolve({"n": 0}, mutate, score, generations=5, archive=arch,
                 rng=random.Random(2))
    assert len(arch.candidates) >= 2  # seed + at least one child retained
