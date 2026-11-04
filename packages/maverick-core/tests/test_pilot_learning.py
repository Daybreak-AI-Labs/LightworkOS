"""Real learning sinks cannot ingest the selected frozen holdout goal."""
import json
import os
import subprocess
import sys
from dataclasses import asdict

import pytest
from maverick import audit, config
from maverick import pilot_learning as policy
from maverick.logging_config import reset_goal_context, set_goal_context
from maverick.paths import tenant_scope
from maverick.trajectory_store import TrajectoryStep, TrajectoryStore


@pytest.fixture
def protected(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *a, **k: True)
    monkeypatch.setattr("maverick.killswitch.check", lambda **k: None)
    with tenant_scope(tenant="pilot-test"):
        policy.protect(11, pilot_id="OPL-pilot", plan_version="a" * 64, input_version="b" * 64, actor="user:owner")
        yield tmp_path
    config.reset_config_cache()


def test_current_goal_learning_sinks_refuse_holdout_but_other_goals_remain_eligible(protected):
    from maverick.learning_guard import Halted, check_learning_halt, learning_write_allowed
    tokens = set_goal_context(goal_id=11)
    try:
        assert learning_write_allowed("reflexion") is False
        with pytest.raises(Halted, match="pilot"):
            check_learning_halt("skill_distillation", "save")
    finally:
        reset_goal_context(tokens)
    tokens = set_goal_context(goal_id=12)
    try:
        assert learning_write_allowed("reflexion") is True
    finally:
        reset_goal_context(tokens)


def test_capture_and_later_corpus_read_exclude_holdout_without_erasing_business_history(protected, monkeypatch):
    monkeypatch.setattr("maverick.trajectory_store.enabled", lambda: True)
    store = TrajectoryStore(path=protected / "trajectories.ndjson")
    step = TrajectoryStep(ts=1, goal_id=11, episode_id=1, step=1, role="worker")
    assert store.record(step) is False
    assert not store.path.exists()
    permitted = TrajectoryStep(ts=1, goal_id=12, episode_id=2, step=1, role="worker")
    assert store.record(permitted) is True
    # Legacy rows are not silently erased; they are excluded on learning read.
    with store.path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(asdict(step)) + "\n")
    assert [row.goal_id for row in store.iter_steps()] == [12]
    assert "\"goal_id\": 11" in store.path.read_text(encoding="utf-8")


def test_local_distillation_excludes_protected_goal_even_outside_running_context(protected):
    from maverick.skill.distillation_local import distill
    rows = [{"goal_id": 11, "goal": "Secret pilot signal", "success": True, "t": 2},
            {"goal_id": 12, "goal": "Allowed control testing workflow", "success": True, "t": 1}]
    result = distill(rows)
    assert result["source_goal_ids"] == [12]
    assert "Secret" not in str(result)


def test_training_ingest_does_not_rehydrate_holdout_events_or_donated_text(protected):
    from maverick.training.ingest import fetch_steps_for_goal, load_donations
    class World:
        def get_goal(self, goal_id):
            from types import SimpleNamespace
            return SimpleNamespace(owner="")

        def goal_events(self, *args, **kwargs):
            pytest.fail("holdout business history must not be fetched for training")
    assert fetch_steps_for_goal(World(), 11) == []
    outbox = protected / "outbox"
    outbox.mkdir()
    (outbox / "held.json").write_text(json.dumps({"goal_id": 11, "source_ownership": "unowned", "task_brief_text": "private held-out case"}), encoding="utf-8")
    (outbox / "dev.json").write_text(json.dumps({"goal_id": 12, "source_ownership": "unowned", "task_brief_text": "permitted development case"}), encoding="utf-8")
    assert [row["goal_id"] for row in load_donations(outbox, world=World())] == [12]


def test_donation_and_semantic_index_refuse_before_payload_or_provider_work(protected, monkeypatch):
    from types import SimpleNamespace

    from maverick import donation, semantic_recall, skills
    monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
    record = donation.TrajectoryRecord(goal_id=11, task_brief_text="Private held-out input", outcome="success", verifier_confidence=1, disagreement_entropy=1)
    assert donation.write_record(record, outbox=protected / "outbox") is None
    assert not (protected / "outbox").exists()
    def forbidden_store():
        pytest.fail("protected text must not reach the embedding backend")
    monkeypatch.setattr(semantic_recall, "build_store", forbidden_store)
    assert semantic_recall.index_goal(SimpleNamespace(id=11, title="Private held-out input")) is False
    tokens = set_goal_context(goal_id=11)
    try:
        assert skills.distill("private goal", "private result", None, None, skills_dir=protected / "skills") is None
        assert not (protected / "skills").exists()
    finally:
        reset_goal_context(tokens)


def test_missing_or_unreadable_retained_policy_refuses_capture_and_tenant_ids_do_not_collide(protected, monkeypatch):
    with tenant_scope(tenant="other-pilot"):
        assert not policy.excluded(11)
    monkeypatch.setattr(policy.STORE, "get", lambda _identity: None)
    assert policy.excluded(11) is True
    def unreadable(_identity):
        raise OSError("synthetic policy failure")
    monkeypatch.setattr(policy.STORE, "get", unreadable)
    assert policy.excluded(12) is True
    assert not policy.evidence(11, pilot_id="OPL-pilot", plan_version="a" * 64, input_version="b" * 64)["enforced"]


def test_protected_parent_task_excludes_descendant_work_and_only_its_goal_bound_user_notes(protected):
    from maverick import user_notes
    from maverick.paths import data_dir
    from maverick.world_model import WorldModel
    world = WorldModel(data_dir("world.db"))
    try:
        for index in range(11):
            world.create_goal("Synthetic goal " + str(index), "")
        child = world.create_goal("Child of protected task", "", parent_id=11)
        assert policy.excluded(child) is True
        ordinary = world.create_goal("Ordinary task", "")
        assert policy.excluded(ordinary) is False
        conversation = world.get_or_create_conversation("api", "synthetic-owner")
        world.append_turn(conversation.id, "user", "I prefer secret pilot instructions.", goal_id=child)
        world.append_turn(conversation.id, "user", "I prefer concise answers.", goal_id=ordinary)
        notes = protected / "notes.ndjson"
        assert user_notes.consolidate(world, path=notes) == 1
        assert "secret pilot" not in notes.read_text(encoding="utf-8")
        assert len(world.recent_turns(conversation.id)) == 2
    finally:
        world.close()


def test_exclusion_survives_fresh_process_and_does_not_disable_development_capture(protected):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("MAVERICK_", "LIGHTWORK_"))}
    environment.update({"MAVERICK_HOME": str(protected),
                        "MAVERICK_CONFIG": str(protected / "config.toml"),
                        "MAVERICK_TENANT": "pilot-test", "MAVERICK_SECURE_DEFAULT": "0",
                        "MAVERICK_TRAJECTORY_CAPTURE": "1"})
    child = subprocess.run([sys.executable, "-c", """
import json
from maverick.pilot_learning import excluded
from maverick.paths import data_dir
from maverick.trajectory_store import TrajectoryStep, TrajectoryStore
store = TrajectoryStore(path=data_dir('process-trajectories.ndjson'))
held = store.record(TrajectoryStep(ts=1, goal_id=11, episode_id=1, step=1, role='worker'))
development = store.record(TrajectoryStep(ts=1, goal_id=12, episode_id=2, step=1, role='worker'))
print(json.dumps({'excluded': excluded(11), 'held': held, 'development': development,
                  'rows': [row.goal_id for row in store.iter_steps()]}))
"""], env=environment, capture_output=True, text=True, timeout=30, check=False)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == {"excluded": True, "held": False,
                                       "development": True, "rows": [12]}
