"""Durable cumulative usage survives lost acknowledgements and stale replay."""
from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from maverick.checkpoint import Checkpointer
from maverick.quotas import UsageLedger, UsageLedgerError
from maverick.world_model import WorldModel

SCOPE = "ab" * 16


def test_duplicate_and_older_totals_are_not_charged_again(tmp_path):
    ledger = UsageLedger(tmp_path / "ledger.json")
    ledger.record_cumulative("alice", SCOPE, 2.0, 100, 20)
    ledger.record_cumulative("alice", SCOPE, 2.0, 100, 20)
    ledger.record_cumulative("alice", SCOPE, 1.0, 50, 10)
    assert ledger.usage("alice") == {"dollars": 2.0, "in_tokens": 100, "out_tokens": 20}
    ledger.record_cumulative("alice", SCOPE, 3.0, 130, 30)
    assert ledger.usage("alice") == {"dollars": 3.0, "in_tokens": 130, "out_tokens": 30}
    assert ledger.settlement(SCOPE, "alice")["revision"] == 2


def test_receipt_survives_an_actual_process_exit_after_atomic_commit(tmp_path):
    path = tmp_path / "ledger.json"
    source = """
import os, sys
from pathlib import Path
from maverick.quotas import UsageLedger
UsageLedger(Path(sys.argv[1])).record_cumulative('alice', 'ab' * 16, 2.0, 100, 20)
os._exit(23)
"""
    process = subprocess.run([sys.executable, "-c", source, str(path)], check=False)
    assert process.returncode == 23
    ledger = UsageLedger(path)
    ledger.record_cumulative("alice", SCOPE, 2.0, 100, 20)
    assert ledger.usage("alice")["in_tokens"] == 100


def test_only_new_usage_is_charged_across_midnight_and_retention(tmp_path):
    ledger = UsageLedger(tmp_path / "ledger.json")
    ledger.record_cumulative("alice", SCOPE, 2.0, 100, 20, day="2026-01-01")
    ledger.record_cumulative("alice", SCOPE, 3.0, 140, 30, day="2026-01-02")
    assert ledger.usage("alice", day="2026-01-02")["in_tokens"] == 40
    ledger.prune(keep_days=1, now=datetime(2026, 2, 1, tzinfo=timezone.utc).timestamp())
    assert ledger._load() == {}
    ledger.record_cumulative("alice", SCOPE, 4.0, 160, 40, day="2026-02-02")
    assert ledger.usage("alice", day="2026-02-02")["in_tokens"] == 20
    receipt = ledger.settlement(SCOPE, "alice")
    assert "2026-01-01" not in receipt["charges"]
    assert receipt["total"]["in_tokens"] == 160


def test_legacy_credit_is_imported_once_and_additive_writers_preserve_receipts(tmp_path):
    ledger = UsageLedger(tmp_path / "ledger.json")
    ledger.record("alice", 2.0, 100, 20)
    credited = {"dollars": 2.0, "in_tokens": 100, "out_tokens": 20}
    ledger.record_cumulative("alice", SCOPE, 3.0, 140, 30, already_settled=credited)
    ledger.record("bob", 1.0, 10, 2)
    ledger.record_cumulative("alice", SCOPE, 3.0, 140, 30, already_settled=credited)
    assert ledger.usage("alice")["in_tokens"] == 140
    assert ledger.usage("bob")["in_tokens"] == 10
    assert ledger.settlement(SCOPE, "alice")["credited"] == credited


def test_concurrent_duplicates_commit_one_increase(tmp_path):
    ledger = UsageLedger(tmp_path / "ledger.json")
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: ledger.record_cumulative("alice", SCOPE, 2.0, 100, 20), range(24)))
    assert ledger.usage("alice")["in_tokens"] == 100


def test_scope_reuse_by_another_principal_and_incomparable_totals_are_rejected(tmp_path):
    ledger = UsageLedger(tmp_path / "ledger.json")
    ledger.record_cumulative("alice", SCOPE, 2.0, 100, 20)
    before = ledger.path.read_bytes()
    with pytest.raises(UsageLedgerError, match="another principal"):
        ledger.record_cumulative("bob", SCOPE, 3.0, 120, 30)
    with pytest.raises(UsageLedgerError, match="conflict"):
        ledger.record_cumulative("alice", SCOPE, 3.0, 80, 30)
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize("field,value", [("in_tokens", -1), ("out_tokens", 0.5), ("dollars", True)])
def test_corrupt_receipt_blocks_reads_and_new_writes(tmp_path, field, value):
    ledger = UsageLedger(tmp_path / "ledger.json")
    ledger.record_cumulative("alice", SCOPE, 2.0, 100, 20)
    raw = json.loads(ledger.path.read_text(encoding="utf-8"))
    raw["settlements"][SCOPE]["total"][field] = value
    ledger.path.write_text(json.dumps(raw), encoding="utf-8")
    before = ledger.path.read_bytes()
    with pytest.raises(UsageLedgerError):
        ledger.usage("alice")
    with pytest.raises(UsageLedgerError):
        ledger.record("alice", 1.0, 10, 2)
    assert ledger.path.read_bytes() == before


def test_scope_is_persisted_in_world_and_numeric_ids_do_not_collide(tmp_path):
    scopes = []
    for filename in ("first.db", "second.db"):
        with WorldModel(tmp_path / filename) as world:
            goal = world.create_goal("request", "")
            episode = world.start_episode(goal)
            scope = Checkpointer(world).settlement_scope(goal, episode, "alice")
            assert Checkpointer(world).settlement_scope(goal, episode, "alice") == scope
            with pytest.raises(ValueError, match="principal"):
                Checkpointer(world).settlement_scope(goal, episode, "bob")
            scopes.append(scope)
    assert scopes[0] != scopes[1]


def test_receipts_are_tenant_scoped(monkeypatch):
    from maverick.paths import reset_tenant, set_tenant

    for tenant, amount in (("first", 100), ("second", 200)):
        token = set_tenant(tenant)
        try:
            ledger = UsageLedger()
            assert ledger.settlement(SCOPE, "alice") is None
            ledger.record_cumulative("alice", SCOPE, 1.0, amount, 10)
            assert ledger.usage("alice")["in_tokens"] == amount
        finally:
            reset_tenant(token)
