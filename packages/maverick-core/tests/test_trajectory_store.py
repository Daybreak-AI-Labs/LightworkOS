"""Tests for governed trajectory capture."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from maverick.trajectory_store import (
    TrajectoryStep,
    TrajectoryStore,
    capture_step,
    episode_dag_fields,
    reset_shared,
)


def _step(**kw):
    base = dict(ts=1.0, goal_id=7, episode_id=1, step=0, role="coder")
    base.update(kw)
    return TrajectoryStep(**base)


def test_episode_dag_fields():
    # Root step: no parent, no terminal outcome yet.
    root = episode_dag_fields(0, is_final=False, verifier_confidence=None)
    assert root == {"parent_step": None, "verifier_confidence": None, "outcome": None}
    # Mid step: links to its predecessor; still no outcome.
    mid = episode_dag_fields(3, is_final=False, verifier_confidence=0.9)
    assert mid["parent_step"] == 2 and mid["outcome"] is None
    # Final step: carries the terminal outcome (the verifier's confidence).
    fin = episode_dag_fields(5, is_final=True, verifier_confidence=0.8)
    assert fin == {"parent_step": 4, "verifier_confidence": 0.8, "outcome": 0.8}


def test_dag_fields_flow_to_estimator_outcome(tmp_path):
    # A captured episode with the DAG fields is readable by the promotion_effect
    # adapter without a custom outcome_fn beyond reading `.outcome`.
    store = TrajectoryStore(path=tmp_path / "dag.ndjson")
    for i, (final, conf) in enumerate([(False, None), (True, 0.75)]):
        store.record(TrajectoryStep(
            ts=1.0, goal_id=1, episode_id=1, step=i, role="orch", tool="X" if i == 0 else "",
            is_final=final, **episode_dag_fields(i, final, conf)))
    steps = list(store.iter_steps())
    assert steps[0].parent_step is None and steps[1].parent_step == 0
    assert steps[1].outcome == 0.75


def test_capture_explicit_opt_out_is_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TRAJECTORY_CAPTURE", "0")
    reset_shared()
    assert capture_step(_step()) is False


def test_record_and_iter_roundtrip(tmp_path):
    path = tmp_path / "t.ndjson"
    store = TrajectoryStore(path=path)
    assert store.record(_step(step=0, tool="read_file", tool_succeeded=True))
    assert store.record(_step(
        step=1, tool="shell", tool_succeeded=False, error="boom",
        task_id="stable-task", outcome=0.0, outcome_source="tests",
        outcome_verified_at=3.0,
    ))
    steps = list(store.iter_steps(goal_id=7))
    assert len(steps) == 2
    assert steps[0].tool == "read_file"
    assert steps[1].tool_succeeded is False
    assert steps[1].task_id == "stable-task"
    assert steps[1].outcome_source == "tests"
    assert steps[1].outcome_verified_at == 3.0
    from maverick.file_lock import private_path_is_restricted
    assert private_path_is_restricted(path)


def test_independent_stores_serialize_appends(tmp_path):
    path = tmp_path / "t.ndjson"
    stores = [TrajectoryStore(path=path, max_rows=1_000) for _ in range(20)]
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(
            lambda pair: pair[1].record(_step(step=pair[0])),
            enumerate(stores),
        ))
    assert all(results)
    assert TrajectoryStore(path=path).count() == len(stores)
    assert len(list(TrajectoryStore(path=path).iter_steps())) == len(stores)


def test_reader_skips_non_object_json_rows(tmp_path):
    path = tmp_path / "t.ndjson"
    path.write_text('[]\n{"goal_id": 7}\n', encoding="utf-8")
    assert len(list(TrajectoryStore(path=path).iter_steps())) == 1


def test_secrets_are_redacted_before_disk(tmp_path):
    secret = "sk-ant-" + "a" * 30  # pragma: allowlist secret  (fabricated test fixture)
    store = TrajectoryStore(path=tmp_path / "t.ndjson")
    store.record(_step(error=f"failed with key {secret}"))
    raw = (tmp_path / "t.ndjson").read_text(encoding="utf-8")
    assert secret not in raw  # scrubbed
    assert "goal_id" in raw   # but the row is still there


def test_goal_filter_and_count(tmp_path):
    store = TrajectoryStore(path=tmp_path / "t.ndjson")
    store.record(_step(goal_id=7))
    store.record(_step(goal_id=8))
    assert store.count() == 2
    assert len(list(store.iter_steps(goal_id=7))) == 1


def test_rotation_bounds_the_file(tmp_path):
    store = TrajectoryStore(path=tmp_path / "t.ndjson", max_rows=10)
    for i in range(25):
        store.record(_step(step=i))
    assert store.count() <= 10


def test_capture_step_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TRAJECTORY_CAPTURE", "1")
    store = TrajectoryStore(path=tmp_path / "t.ndjson")
    assert capture_step(_step(), store=store) is True
    assert store.count() == 1


def test_tools_by_goal_groups_distinct_tools(tmp_path):
    store = TrajectoryStore(path=tmp_path / "t.ndjson")
    store.record(_step(goal_id=7, step=0, tool="web_search"))
    store.record(_step(goal_id=7, step=1, tool="send_email"))
    store.record(_step(goal_id=7, step=2, tool="web_search"))   # duplicate
    store.record(_step(goal_id=7, step=3, tool=""))             # no tool -> ignored
    store.record(_step(goal_id=8, step=0, tool="ocr_read"))
    by_goal = store.tools_by_goal()
    assert by_goal[7] == ["web_search", "send_email"]           # de-duped, in order
    assert by_goal[8] == ["ocr_read"]
