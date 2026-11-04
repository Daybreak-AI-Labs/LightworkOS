"""Decay actually changes recall ranking (skills._relevant_skills_lexical).

The point of the track record is that it influences which skills surface, not
just that it's stored. These tests use the lexical scorer directly (fastembed
isn't installed in CI, so it's the live path) and pin that a decayed skill
yields rank to an equally-relevant healthy one -- and that with MAVERICK_SKILL_DECAY=0
ranking is untouched.
"""
from __future__ import annotations

import pytest
from maverick.skill import stats as skill_stats
from maverick.skills import Skill, _relevant_skills_lexical


def _skill(name: str) -> Skill:
    # Identical triggers -> identical raw lexical score, so any reordering is
    # purely the decay multiplier.
    return Skill(
        name=name,
        triggers=["deploy the service"],
        tools_needed=[],
        body="body",
        path=None,  # not loaded from disk in this test
    )


@pytest.fixture
def _point_stats_at_tmp(tmp_path, monkeypatch):
    # skills._decay_weights calls skill_stats with no explicit path, so it uses
    # the module DEFAULT_PATH; _resolve reads it at call time, so monkeypatching
    # it here takes effect.
    monkeypatch.setattr(skill_stats, "DEFAULT_PATH", tmp_path / "stats.json")
    return tmp_path / "stats.json"


def test_decayed_skill_loses_rank(_point_stats_at_tmp):
    good, bad = _skill("good"), _skill("bad")
    # Give 'bad' a fair-trial losing record; 'good' an equal winning record.
    for _ in range(4):
        skill_stats.record_use(["good", "bad"])
        skill_stats.record_outcome(["good"], success=True)
        skill_stats.record_outcome(["bad"], success=False)

    # Pass bad first so default (stable) ordering would keep it first absent decay.
    ranked = _relevant_skills_lexical("deploy the service", [bad, good], max_n=2)
    assert [s.name for s in ranked] == ["good", "bad"]


def test_decay_disabled_preserves_input_order(_point_stats_at_tmp, monkeypatch):
    good, bad = _skill("good"), _skill("bad")
    for _ in range(4):
        skill_stats.record_use(["good", "bad"])
        skill_stats.record_outcome(["good"], success=True)
        skill_stats.record_outcome(["bad"], success=False)

    monkeypatch.setenv("MAVERICK_SKILL_DECAY", "0")
    ranked = _relevant_skills_lexical("deploy the service", [bad, good], max_n=2)
    # Equal raw scores + neutral weights -> stable sort keeps the input order.
    assert [s.name for s in ranked] == ["bad", "good"]


def test_no_stats_is_neutral(_point_stats_at_tmp):
    good, bad = _skill("good"), _skill("bad")
    ranked = _relevant_skills_lexical("deploy the service", [bad, good], max_n=2)
    assert [s.name for s in ranked] == ["bad", "good"]
