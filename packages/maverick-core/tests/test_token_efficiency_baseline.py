"""Per-goal token-efficiency baseline: cache buckets persisted end to end.

Regression target: Budget breaks out cache_read/cache_write tokens (priced at
0.1x / 1.25-2x) but the episodes table stored only cost/input/output/tools —
the breakdown was computed every run and discarded at the DB boundary, so
nothing persisted could answer "how much of this goal's input was cache vs
fresh". The cost-router curve fitter also read ep.in_tokens/out_tokens
(fields that don't exist), fitting on all-zero rows.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from maverick.world_model import WorldModel


def _world() -> WorldModel:
    return WorldModel(Path(tempfile.mkdtemp()) / "w.db")


def test_end_episode_persists_cache_buckets():
    w = _world()
    gid = w.create_goal("g", "d")
    eid = w.start_episode(gid)
    w.end_episode(eid, "done", "success", cost_dollars=1.5,
                  input_tokens=1000, output_tokens=200, tool_calls=3,
                  cache_read_tokens=9000, cache_write_tokens=1200)
    ep = w.list_episodes(goal_id=gid)[0]
    assert ep.cache_read_tokens == 9000
    assert ep.cache_write_tokens == 1200
    assert ep.input_tokens == 1000


def test_live_mirror_persists_cache_buckets():
    w = _world()
    gid = w.create_goal("g", "d")
    eid = w.start_episode(gid)
    w.update_episode_spend(eid, cost_dollars=0.5, input_tokens=100,
                           output_tokens=10, tool_calls=1,
                           cache_read_tokens=400, cache_write_tokens=50)
    ep = w.list_episodes(goal_id=gid)[0]
    assert ep.cache_read_tokens == 400 and ep.cache_write_tokens == 50


def test_pre_migration_db_upgrades_in_place(tmp_path):
    # A v26-era row (no cache columns) must read back as zeros, not crash.
    import sqlite3
    db = tmp_path / "w.db"
    w = WorldModel(db)
    gid = w.create_goal("g", "d")
    eid = w.start_episode(gid)
    # simulate a legacy row by nulling the new columns directly
    with sqlite3.connect(w.path) as conn:
        conn.execute("UPDATE episodes SET cache_read_tokens = NULL, "
                     "cache_write_tokens = NULL WHERE id = ?", (eid,))
    ep = w.list_episodes(goal_id=gid)[0]
    assert ep.cache_read_tokens == 0 and ep.cache_write_tokens == 0


def test_curve_fitter_reads_real_token_fields():
    from maverick.cost.curve_fitter import gather
    w = _world()
    gid = w.create_goal("g", "d")
    eid = w.start_episode(gid)
    w.end_episode(eid, "done", "success", cost_dollars=2.0,
                  input_tokens=100_000, output_tokens=20_000, tool_calls=1)
    rows = gather(w)
    assert rows, "episode with cost must be gathered"
    (in_tok, out_tok, cost) = next(iter(rows.values()))[0]
    assert in_tok == 100_000.0 and out_tok == 20_000.0 and cost == 2.0


def test_receipt_payload_carries_cache_buckets(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import budget_receipts
    w = _world()
    gid = w.create_goal("g", "d")
    eid = w.start_episode(gid)
    w.end_episode(eid, "done", "success", cost_dollars=1.0,
                  input_tokens=500, output_tokens=100, tool_calls=2,
                  cache_read_tokens=4000, cache_write_tokens=600)
    import json
    line = budget_receipts.mint(w, gid, "test-receipt-key",
                                path=tmp_path / "receipts.jsonl")
    payload = json.loads(line)["payload"]
    assert payload["cache_read_tokens"] == 4000
    assert payload["cache_write_tokens"] == 600
