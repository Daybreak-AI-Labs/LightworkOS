import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import donation
from maverick.training import export_texts, ingest, rlaif
from maverick.training.identity import record_trajectory_id
from maverick.training.schema import to_klear_jsonl


def test_same_second_family_keeps_every_run_and_candidate(monkeypatch, tmp_path):
    monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
    monkeypatch.setattr(donation, "_text_donations_enabled", lambda: True)
    from maverick import world_model
    db = tmp_path / "source-world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    world = world_model.WorldModel(db)
    try:
        goal_ids = [world.create_goal("synthetic shared training", owner="") for _ in range(4)]
    finally:
        world.close()
    records = [donation.TrajectoryRecord(
        ts=1700000000.0, task_brief_hash="same-family", goal_id=i,
        outcome="success", verifier_confidence=0.9, disagreement_entropy=0.9,
        rejected_attempts=[{"text": f"draft-{i}", "confidence": 0.1}],
        scored_candidates=[{"text": f"candidate-{i}", "score": 0.4}],
    ) for i in goal_ids]
    with ThreadPoolExecutor(max_workers=4) as pool:
        paths = list(pool.map(lambda record: donation.write_record(record, outbox=tmp_path), records))
    assert None not in paths and len(set(paths)) == 4
    payloads = [json.loads(path.read_text()) for path in paths]
    rows = []
    for payload in payloads:
        rows.extend([ingest.build_trajectory(payload, []), *ingest.build_rejected_trajectories(payload), *ingest.build_candidate_trajectories(payload)])
    assert len({row.trajectory_id for row in rows}) == 12
    assert {row.task_family for row in rows} == {"same-family"}
    texts = export_texts.export_texts(payloads, lambda record: [{"kind": "finding", "content": f"result-{record['goal_id']}"}])
    assert len(texts) == 12
    for payload in payloads:
        assert f"result-{payload['goal_id']}" in texts[record_trajectory_id(payload)]
        assert texts[ingest.rejected_trajectory_id(payload, 0)] == f"draft-{payload['goal_id']}"
        assert texts[ingest.candidate_trajectory_id(payload, 0)] == f"candidate-{payload['goal_id']}"
    mapped = rlaif.index_trajectories([to_klear_jsonl(row) for row in rows])
    assert set(mapped) == set(texts)


def test_record_replay_is_immutable(monkeypatch, tmp_path):
    monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
    monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
    record = donation.TrajectoryRecord(outcome="success", verifier_confidence=0.9, disagreement_entropy=0.9)
    path = donation.write_record(record, outbox=tmp_path)
    original = path.read_bytes()
    assert donation.write_record(record, outbox=tmp_path) == path
    record.reward = 0.5
    assert donation.write_record(record, outbox=tmp_path) is None
    assert path.read_bytes() == original


def test_legacy_migration_is_deterministic_and_rejects_old_colliding_corpus():
    a = {"task_brief_hash": "family", "ts": 1000.1, "goal_id": 1}
    b = {**a, "ts": 1000.2, "goal_id": 2}
    assert record_trajectory_id(a) != record_trajectory_id(b)
    assert record_trajectory_id(a) == record_trajectory_id(json.loads(json.dumps(a)))
    with pytest.raises(ValueError, match="Duplicate training"):
        rlaif.index_trajectories([{"id": "family-1000"}, {"id": "family-1000"}])
