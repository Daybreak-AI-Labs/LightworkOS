"""Shared training and signed exchange cannot inherit employee-private sources."""
import json
from types import SimpleNamespace

import pytest
from maverick import donation, dreaming, insight_exchange
from maverick.training.ingest import fetch_steps_for_goal, load_donations


def test_training_filters_capture_and_current_source_ownership(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.pilot_learning.excluded", lambda goal_id: goal_id == 4)
    owners = {1: "", 2: "user:employee", 3: "", 4: ""}
    world = SimpleNamespace(get_goal=lambda goal_id: SimpleNamespace(owner=owners[goal_id]) if goal_id in owners else None)
    rows = [
        {"goal_id": 1, "source_ownership": "unowned"},
        {"goal_id": 2, "source_ownership": "unowned"},  # ownership changed since capture
        {"goal_id": 3, "source_ownership": "private"},
        {"goal_id": 4, "source_ownership": "unowned"},
        {"goal_id": 5, "source_ownership": "unowned"},  # source removed
        {"goal_id": 1},  # legacy capture has no provenance
    ]
    for index, row in enumerate(rows):
        (tmp_path / f"{index}.json").write_text(json.dumps(row), encoding="utf-8")
    assert list(load_donations(tmp_path, world=world)) == [rows[0]]
    world.goal_events = lambda *a, **k: pytest.fail("private source events must not be read")
    assert fetch_steps_for_goal(world, 2) == []


def test_installation_donation_opt_in_does_not_grant_employee_content(tmp_path, monkeypatch):
    monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
    monkeypatch.setattr("maverick.memory_ownership.current_owner", lambda **kwargs: "user:employee")
    monkeypatch.setattr("maverick.pilot_learning.excluded", lambda goal_id: False)
    row = donation.TrajectoryRecord(goal_id=1, outcome="success", verifier_confidence=1, disagreement_entropy=1)
    assert donation.write_record(row, outbox=tmp_path) is None
    assert list(tmp_path.glob("*.json")) == []


def test_exchange_exports_only_known_shared_current_sources(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    import maverick.audit.signing as signing
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    monkeypatch.setattr("maverick.memory_ownership.source_allowed", lambda goal_id, owner: goal_id == 1 and owner == "")
    path = tmp_path / "insights.ndjson"
    rows = [
        dreaming.DreamInsight(ts=1, kind="failure_pattern", domain=None, text="shared", owner="", source_goal_ids=[1]),
        dreaming.DreamInsight(ts=1, kind="failure_pattern", domain=None, text="private", owner="user:a", source_goal_ids=[1]),
        dreaming.DreamInsight(ts=1, kind="failure_pattern", domain=None, text="unknown"),
        dreaming.DreamInsight(ts=1, kind="failure_pattern", domain=None, text="revoked", owner="", source_goal_ids=[2]),
        dreaming.DreamInsight(ts=1, kind="failure_pattern", domain=None, text="channel", owner="", channel="slack", user_id="a"),
    ]
    dreaming.append_insights(rows, path=path)
    result = insight_exchange.export_insights(tmp_path / "export.json", path=path)
    assert [row["text"] for row in json.loads(result.read_text(encoding="utf-8"))["insights"]] == ["shared"]
