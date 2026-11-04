from __future__ import annotations

import random

from maverick_evolve import config_space


def test_default_config_in_bounds():
    cfg = config_space.default_config()
    assert config_space.in_bounds(cfg)
    assert set(cfg) == set(config_space.SPACE)


def test_mutate_stays_in_bounds():
    rng = random.Random(0)
    cfg = config_space.default_config()
    for _ in range(200):
        cfg = config_space.mutate(cfg, rng)
        assert config_space.in_bounds(cfg), cfg


def test_mutate_changes_one_knob():
    rng = random.Random(1)
    cfg = config_space.default_config()
    out = config_space.mutate(cfg, rng)
    diffs = [k for k in cfg if cfg[k] != out.get(k)]
    assert len(diffs) <= 1  # at most one knob moves per mutation


def test_mutate_preserves_unknown_keys():
    rng = random.Random(2)
    cfg = {**config_space.default_config(), "custom_unmanaged": "keep-me"}
    out = config_space.mutate(cfg, rng)
    assert out["custom_unmanaged"] == "keep-me"


def test_int_knob_respects_floor():
    rng = random.Random(3)
    space = {"k": ("int", 1, 3)}
    cfg = {"k": 1}
    for _ in range(50):
        cfg = config_space.mutate(cfg, rng, space=space)
        assert 1 <= cfg["k"] <= 3
