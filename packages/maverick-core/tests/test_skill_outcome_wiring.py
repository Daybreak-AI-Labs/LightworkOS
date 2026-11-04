"""The run-finalize loop closes: recalled skills get their outcome attributed.

Exercises the orchestrator helper (_record_skill_outcome) against the same
ctx.skills_used set the agent populates at recall time, and the SwarmContext
field that carries it. Full run_goal is covered elsewhere; this pins the
attribution unit + its fail-safe contract.
"""
from __future__ import annotations

from types import SimpleNamespace

from maverick.orchestrator import _record_skill_outcome
from maverick.skill import stats as skill_stats


def test_swarmcontext_has_skills_used_set():
    from maverick.swarm import SwarmContext
    f = {f.name: f for f in SwarmContext.__dataclass_fields__.values()}
    assert "skills_used" in f
    # default_factory=set -> each ctx gets its own, not a shared mutable.
    assert f["skills_used"].default_factory is set


def test_record_outcome_attributes_to_used_skills(tmp_path, monkeypatch):
    monkeypatch.setattr(skill_stats, "DEFAULT_PATH", tmp_path / "stats.json")
    ctx = SimpleNamespace(skills_used={"alpha", "beta"})
    _record_skill_outcome(ctx, success=True)
    assert skill_stats.get("alpha").wins == 1
    assert skill_stats.get("beta").wins == 1

    _record_skill_outcome(ctx, success=False)
    assert skill_stats.get("alpha").losses == 1


def test_record_outcome_empty_is_noop(tmp_path, monkeypatch):
    path = tmp_path / "stats.json"
    monkeypatch.setattr(skill_stats, "DEFAULT_PATH", path)
    _record_skill_outcome(SimpleNamespace(skills_used=set()), success=True)
    assert not path.exists()


def test_record_outcome_missing_attr_is_safe(tmp_path, monkeypatch):
    path = tmp_path / "stats.json"
    monkeypatch.setattr(skill_stats, "DEFAULT_PATH", path)
    # A ctx without skills_used (e.g. an old/foreign object) must not raise.
    _record_skill_outcome(SimpleNamespace(), success=True)
    assert not path.exists()
