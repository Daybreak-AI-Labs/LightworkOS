"""Learning rollback must be a FULL revert.

A store that did not exist at snapshot time but was created during the cycle
(e.g. the first-ever insights file / learned-skills dir on a fresh tenant) must
be deleted on rollback -- otherwise newly-created (possibly poisoned) learning
survives a rollback that is supposed to leave state "fully restored or unchanged".
"""
from __future__ import annotations

import json

import pytest
from maverick import dreaming


def _stores(tmp):
    return {
        "pre_existing.ndjson": tmp / "pre_existing.ndjson",   # exists at snapshot
        "created_after.ndjson": tmp / "created_after.ndjson",  # created post-snapshot
        "learned-skills": tmp / "learned-skills",              # dir, created after
    }


def test_rollback_deletes_stores_created_after_snapshot(tmp_path):
    live = tmp_path / "live"
    live.mkdir()
    snaps = tmp_path / "snaps"
    stores = _stores(live)

    # Snapshot time: only the pre-existing store exists.
    stores["pre_existing.ndjson"].write_text("v1\n", encoding="utf-8")
    snap = dreaming.snapshot_learning_state(directory=snaps, stores=stores)
    assert snap is not None

    # During the "cycle": mutate the existing store AND create new ones.
    stores["pre_existing.ndjson"].write_text("v1\nMUTATED\n", encoding="utf-8")
    stores["created_after.ndjson"].write_text("poisoned insight\n", encoding="utf-8")
    skills = stores["learned-skills"]
    skills.mkdir()
    (skills / "bad-skill.md").write_text("learned during cycle\n", encoding="utf-8")

    restored = dreaming.rollback_learning_state(
        "latest", directory=snaps, stores=stores)

    # Pre-existing store reverted to snapshot content.
    assert stores["pre_existing.ndjson"].read_text(encoding="utf-8") == "v1\n"
    # Post-snapshot creations are GONE (the bug: they survived).
    assert not stores["created_after.ndjson"].exists()
    assert not skills.exists()
    assert "created_after.ndjson" in restored and "learned-skills" in restored


def test_rollback_noop_when_nothing_created_after(tmp_path):
    live = tmp_path / "live"
    live.mkdir()
    snaps = tmp_path / "snaps"
    stores = {"a.ndjson": live / "a.ndjson"}
    stores["a.ndjson"].write_text("orig\n", encoding="utf-8")
    dreaming.snapshot_learning_state(directory=snaps, stores=stores)
    stores["a.ndjson"].write_text("changed\n", encoding="utf-8")
    dreaming.rollback_learning_state("latest", directory=snaps, stores=stores)
    assert stores["a.ndjson"].read_text(encoding="utf-8") == "orig\n"


@pytest.fixture
def native_learning(monkeypatch):
    from maverick import config, negative_knowledge, procedural_memory
    from maverick.paths import reset_tenant, set_tenant

    cfg = {"self_harness": {"enable": True, "store": "files"},
           "dreaming": {"enable": True, "snapshots": True}}
    monkeypatch.setattr(config, "load_config", lambda *a, **kw: cfg)
    token = set_tenant("snapshot-owned-a")
    try:
        yield cfg
    finally:
        negative_knowledge.reset_shared()
        procedural_memory.reset_shared()
        reset_tenant(token)


@pytest.mark.parametrize("mode", ["files", "world"])
def test_native_restoration_reaches_next_recall_and_preserves_history(native_learning, mode):
    from maverick import learning_store as ls
    from maverick import negative_knowledge as nk
    from maverick import procedural_memory as pm
    from maverick import self_harness as sh
    from maverick.file_lock import atomic_write_text
    from maverick.paths import data_dir, reset_tenant, set_tenant
    from maverick.world_model import close_world_if_owned, open_world

    native_learning["self_harness"]["store"] = mode
    world = open_world()
    try:
        source = world.create_goal("Unowned learning source")

        def guidance(line):
            with ls.guidance_fence():
                sh._write_addenda({"M": sh._ADDENDUM_HEADER + "\n- " + line})
                sh._write_line_meta({sh._line_id("M", line): {
                    "model_id": "M", "text": line, "source_goal_ids": [source],
                    "privacy_schema": "shared-unowned-sources-v1",
                }})

        rails, habits = nk.shared(), pm.shared()
        rails.update([nk.Guardrail("old-action", 0.9, -0.1, "Review first")])
        habits.update([pm.Memory("old-action", 0.2, 0.8)])
        guidance("Verify the saved result first")
        assert "Verify the saved result first" in sh.recall_addendum("M")
        with dreaming.learning_mutation_scope() as snap:
            with dreaming.learning_mutation_scope() as nested:
                assert nested == snap
        reviewed = dreaming.snapshot_coverage(snap.name)
        assert reviewed["integrity_verified"]
        assert {"Learned safeguards", "Learned habits"} <= set(reviewed["labels"])

        rails.update([nk.Guardrail("new-action", 0.8, -0.2, "Later rule")])
        habits.update([pm.Memory("new-action", 0.3, 0.9)])
        peer = nk.GuardrailRegistry(path=rails.path)
        guidance("Review the changed instructions")
        customer_work = world.create_goal("Later customer work", owner="employee")
        observed = data_dir("consequences.ndjson")
        atomic_write_text(observed, '{"customer_event":"keep"}\n')
        if mode == "world":
            ls.write_transfer_tried_db({"new-attempt": 12.0})
            ls.write_corpus_db("live", {"M": [{"goal": "Keep this evaluation example"}]})
        else:
            atomic_write_text(sh._transfer_tried_path(), '{"new-attempt":12.0}')

        other = set_tenant("snapshot-owned-b")
        try:
            nk.shared().update([nk.Guardrail("other-tenant", 0.8, -0.2, "Keep")])
            with pytest.raises(RuntimeError, match="different learning storage"):
                dreaming.rollback_learning_state(snap.name, directory=snap.parent,
                                                 expected_revision=reviewed["revision"])
            assert nk.shared().consult("other-tenant") is not None
        finally:
            reset_tenant(other)

        restored = dreaming.rollback_learning_state(snap.name, expected_revision=reviewed["revision"])
        assert "guardrails.json" in restored and "procedural_memory.json" in restored
        assert rails.consult("old-action") is not None and rails.consult("new-action") is None
        assert peer.consult("old-action") is not None and peer.consult("new-action") is None
        assert habits.strength_of("old-action") == 0.8 and habits.strength_of("new-action") == 0
        assert "Verify the saved result first" in sh.recall_addendum("M")
        assert "Review the changed instructions" not in sh.recall_addendum("M")
        assert world.get_goal(customer_work).owner == "employee"
        assert observed.read_text() == '{"customer_event":"keep"}\n'
        if mode == "world":
            assert ls.load_transfer_tried_db() == {"new-attempt": 12.0}
            assert ls.load_corpus_db("live") == {"M": [{"goal": "Keep this evaluation example"}]}
        else:
            assert json.loads(sh._transfer_tried_path().read_text()) == {"new-attempt": 12.0}
    finally:
        close_world_if_owned(world)


def test_saved_byte_corruption_refuses_before_any_native_effect(native_learning):
    from maverick import negative_knowledge as nk
    from maverick.file_lock import atomic_write_text

    rails = nk.shared()
    rails.update([nk.Guardrail("old", 0.9, -0.1, "Old")])
    snap = dreaming.prepare_learning_snapshot()
    reviewed = dreaming.snapshot_coverage(snap.name)
    rails.update([nk.Guardrail("current", 0.8, -0.2, "Current")])
    atomic_write_text(snap / "guardrails.json", '[]')
    with pytest.raises(RuntimeError, match="saved safety copy has changed"):
        dreaming.rollback_learning_state(snap.name, expected_revision=reviewed["revision"])
    assert rails.consult("current") is not None


def test_legacy_point_cannot_erase_new_families_and_is_bound_to_review(native_learning):
    from maverick import negative_knowledge as nk
    from maverick.file_lock import atomic_write_text, ensure_private_directory

    base = ensure_private_directory(dreaming.snapshots_dir())
    old = ensure_private_directory(base / "legacy-point")
    atomic_write_text(old / "insights.ndjson", "old insight\n")
    rails = nk.shared()
    rails.update([nk.Guardrail("current", 0.8, -0.2, "Keep")])
    reviewed = dreaming.snapshot_coverage(old.name)
    assert not reviewed["integrity_verified"] and len(reviewed["labels"]) == 6
    atomic_write_text(old / "insights.ndjson", "changed saved insight\n")
    with pytest.raises(RuntimeError, match="changed after review"):
        dreaming.rollback_learning_state(old.name, expected_revision=reviewed["revision"])
    reviewed = dreaming.snapshot_coverage(old.name)
    dreaming.rollback_learning_state(old.name, expected_revision=reviewed["revision"])
    assert rails.consult("current") is not None


def test_nightly_mutation_requires_a_published_boundary(native_learning, monkeypatch):
    from maverick import self_improvement_runner as runner

    calls = []
    monkeypatch.setattr(runner, "nightly_self_harness_enabled", lambda: True)
    monkeypatch.setattr(runner, "_run_nightly_self_harness", lambda world: calls.append(world))
    native_learning["dreaming"]["snapshots"] = False
    with pytest.raises(RuntimeError, match="safety copies"):
        runner.run_nightly_self_harness(None)
    native_learning["dreaming"]["snapshots"] = True
    monkeypatch.setattr(dreaming, "snapshot_learning_state", lambda **kw: None)
    with pytest.raises(RuntimeError, match="could not be prepared"):
        runner.run_nightly_self_harness(None)
    assert not calls
