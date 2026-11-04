"""Content authority before retrieval/ranking; local execution is coordinated separately."""
from types import SimpleNamespace

from maverick import dreaming, reflexion
from maverick.tools import recall as recall_module


def test_candidate_owner_is_applied_before_embedding(monkeypatch):
    from maverick import memory_ownership
    own = SimpleNamespace(id=1, owner="user:a", title="own", description="", status="done")
    other = SimpleNamespace(id=2, owner="user:b", title="secret", description="", status="done")
    class World:
        def candidate_goals(self, running, *, limit, owner):
            assert owner == "user:a"
            return [own, other]  # defensive adapter check still precedes embeddings
    monkeypatch.setattr(memory_ownership, "source_allowed", lambda *a, **kw: True)
    seen = []
    monkeypatch.setattr(recall_module, "_rank_with_embeddings", lambda query, goals: seen.extend(goals) or [(1, goals[0])])
    result = recall_module.recall_past_goals("own", world=World(), owner="user:a")
    assert [goal.id for goal in seen] == [1]
    assert result == [(1, own)]


def test_private_reflection_never_becomes_shared_insight():
    failures = [{"goal_text": "private payroll", "failure_class": "timeout", "reflection": "private detail",
                 "owner": "user:a", "channel": None, "user_id": None, "goal_id": 2} for _ in range(2)]
    assert dreaming.promote_shared_insights(failures) == []
    assert dreaming.build_rehearsal_cases(failures) == []


def test_dream_recall_rechecks_owner_and_source_exclusion(monkeypatch):
    from maverick import memory_ownership
    entries = [dreaming.DreamInsight(ts=1, kind="failure_pattern", domain=None, text="same problem",
                                    owner=owner, source_goal_ids=[gid])
               for owner, gid in [("user:a", 1), ("user:b", 2), (None, 3)]]
    monkeypatch.setattr(dreaming, "load_insights", lambda path: entries)
    monkeypatch.setattr(memory_ownership, "source_allowed", lambda gid, owner: gid == 1)
    result = dreaming.recall_insights("same problem", owner="user:a")
    assert len(result) == 1 and result[0][1].owner == "user:a"
    monkeypatch.setattr(memory_ownership, "source_allowed", lambda *a: False)
    assert dreaming.recall_insights("same problem", owner="user:a") == []


def test_legacy_reflection_owner_is_unknown():
    record = reflexion.Reflexion(ts=1, goal_text="legacy", failure_class="failure", failure_msg="", reflection="")
    assert record.owner is None


def test_distilled_skill_owner_and_exclusion_precede_render(monkeypatch, tmp_path):
    from maverick import memory_ownership, skills
    skill = skills.Skill.parse("---\nname: learned\nsource: auto-distilled-local-v2\nsource_goal_ids: 7\n---\nprivate instruction", tmp_path / "learned.md")
    monkeypatch.setattr(memory_ownership, "current_owner", lambda: "user:a")
    monkeypatch.setattr(memory_ownership, "source_allowed", lambda gid, owner: gid == 7 and owner == "user:b")
    assert skills.render_for_prompt([skill]) == ""
    monkeypatch.setattr(memory_ownership, "source_allowed", lambda gid, owner: gid == 7 and owner == "user:a")
    assert "private instruction" in skills.render_for_prompt([skill])
    monkeypatch.setattr(memory_ownership, "source_allowed", lambda *args: False)
    assert skills.render_for_prompt([skill]) == ""


def test_distilled_skill_missing_lineage_is_not_recalled(tmp_path):
    from maverick import skills
    skill = skills.Skill.parse("---\nname: learned\nsource: auto-distilled-local-v2\n---\nlegacy instruction", tmp_path / "learned.md")
    assert skills.render_for_prompt([skill]) == ""


def test_model_managed_memory_separates_tenant_owner_and_legacy(tmp_path, monkeypatch):
    from maverick import paths
    from maverick.tools.memory import memory_root_for
    monkeypatch.setenv("MAVERICK_MEMORY_DIR", str(tmp_path))
    monkeypatch.setattr(paths, "current_tenant_id_strict", lambda: "tenant-a")
    alice = memory_root_for("user:alice")
    assert alice != memory_root_for("user:bob")
    assert alice != memory_root_for("")
    assert alice != tmp_path.resolve()
    monkeypatch.setattr(paths, "current_tenant_id_strict", lambda: "tenant-b")
    assert alice != memory_root_for("user:alice")
