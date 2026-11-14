"""Regression contracts for learning publication and evidence boundaries."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from maverick import (
    dreaming,
    earned_autonomy,
    harness_refine,
    insight_exchange,
    jit_rl,
    learning_store,
)


def test_pg_schema_initialized_once_after_successful_commit(monkeypatch):
    calls = []
    monkeypatch.setattr(learning_store, "_pg_schema_ready", set())
    connection = SimpleNamespace(
        cursor=lambda: nullcontext(object()), commit=lambda: calls.append("commit"),
        rollback=lambda: calls.append("rollback"), close=lambda: None,
    )
    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=lambda *a, **k: connection))
    monkeypatch.setattr(learning_store, "_pg_dsn", lambda: "round5-schema-contract")
    monkeypatch.setattr("maverick.learning_store_pg_schema.ensure_schema", lambda cur: calls.append("schema"))
    for _ in range(2):
        with learning_store._pg_conn():
            pass
    assert calls.count("schema") == 1
    monkeypatch.setattr(learning_store, "_pg_dsn", lambda: "round5-failed-schema-contract")

    def fail_commit():
        raise OSError("schema commit failed")

    connection.commit = fail_commit
    with pytest.raises(OSError, match="schema commit failed"):
        with learning_store._pg_conn():
            pass
    connection.commit = lambda: calls.append("commit")
    with learning_store._pg_conn():
        pass
    assert calls.count("schema") == 3
    assert calls.count("rollback") == 1


@pytest.mark.asyncio
async def test_evolve_rehearsal_checks_halt_before_each_prompt(monkeypatch):
    from maverick.killswitch import Halted
    calls = []
    monkeypatch.setattr(dreaming, "load_rehearsals", lambda path: [{"prompt": "one"}, {"prompt": "two"}])
    monkeypatch.setattr("maverick.calibration.learning_frozen_safe", lambda: False)

    def check(*args):
        if calls:
            raise Halted("operator stopped rehearsal", "operator")

    monkeypatch.setattr(dreaming, "check_learning_halt", check)

    async def agent(prompt):
        calls.append(prompt)
        return "completed"

    with pytest.raises(Halted):
        await dreaming.rehearse(agent)
    assert calls == ["one"]


def test_foreign_donations_require_unowned_without_local_goal_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.memory_ownership.source_allowed", lambda *args: False)
    for index, ownership in enumerate(("unowned", "owned", None)):
        (tmp_path / f"{index}.json").write_text(json.dumps({
            "source_ownership": ownership, "goal_id": 999,
            "task_brief_text": "Reconcile totals", "outcome": "success",
        }))
    successes, failures = dreaming._replay_donations(tmp_path)
    assert len(successes) == 1 and not failures
    assert not successes[0].get("goal_id")


def test_peer_insights_are_not_resigned_for_another_peer(tmp_path, monkeypatch):
    from maverick.audit import signing
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    path = tmp_path / "insights.ndjson"
    dreaming.append_insights([
        dreaming.DreamInsight(ts=1.0, kind="failure_pattern", domain=None, text=text, evidence=1, owner="")
        for text in ("(peer abc) Peer lesson", "Local lesson")
    ], path=path)
    bundle = insight_exchange.export_insights(tmp_path / "bundle.json", path=path, now=2.0)
    assert [row["text"] for row in json.loads(bundle.read_text())["insights"]] == ["Local lesson"]


def test_scoring_group_is_atomic_when_superseded_write_fails(monkeypatch):
    monkeypatch.setenv("MAVERICK_EARNED_AUTONOMY", "1")
    engine = earned_autonomy.EarnedAutonomyEngine(
        cards=earned_autonomy.CardStore(), ledger=earned_autonomy.TrustLedger(),
        frozen_fn=lambda: False, audit_fn=lambda *a, **k: None,
    )
    for index in range(2):
        engine.record_card(principal="p", action="deploy", risk="high", predicted_outcome=1,
                           goal_id=1, episode_id=7, ts=float(index))
    original = engine.ledger.record_event
    monkeypatch.setattr(engine.ledger, "record_event", lambda kind, *a, **k: False if kind == "superseded" else original(kind, *a, **k))
    assert engine.reconcile(resolve=lambda *args: 1.0).scored == 1
    assert engine.reconcile(resolve=lambda *args: 1.0).scored == 0
    assert engine.ledger.state("deploy").hits == 1


def test_persistent_chain_rejects_truncated_or_rebuilt_history(tmp_path, monkeypatch):
    path = tmp_path / "trust.ndjson"
    ledger = earned_autonomy.TrustLedger(path=path)
    assert ledger.record_event("hit", "deploy", card_id="one")
    assert ledger.record_event("miss", "deploy", card_id="two")
    lines = path.read_text().splitlines()
    path.write_text(lines[0] + "\n")
    assert ledger.verify().startswith("BROKEN")
    row = json.loads(lines[0])
    row["action"] = "tamper"
    row["hash"] = earned_autonomy._ChainedLog._row_hash(
        {k: v for k, v in row.items() if k not in {"prev", "hash"}}, row["prev"],
    )
    path.write_text(json.dumps(row) + "\n")
    assert ledger.verify().startswith("BROKEN")
    assert not ledger.record_event("hit", "deploy", card_id="three")
    path.write_text("\n".join(lines) + "\n")
    assert ledger.verify().startswith("VALID")
    # An attacker can rebuild both unkeyed hashes; a self-selected signing key
    # must still not establish audit authority for a forged head.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from maverick.audit.signing import day_files
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    anchor = day_files(ledger._log._anchor_location()[1])[-1]
    saved = anchor.read_bytes()
    forged = json.loads(anchor.read_text().splitlines()[-1])
    forged["key_id"] = hashlib.sha256(public).hexdigest()[:16]
    forged["prev_hash"] = ""
    material = {k: v for k, v in forged.items() if k not in {"hash", "sig"}}
    forged["hash"] = hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
    forged["sig"] = private.sign(bytes.fromhex(forged["hash"])).hex()
    anchor.write_text(json.dumps(forged) + "\n")
    assert ledger.verify().startswith("BROKEN")
    anchor.write_bytes(saved)
    from maverick.audit import AuditRefused

    def refuse(*args):
        raise AuditRefused("signing custody unavailable")

    monkeypatch.setattr(ledger._log, "_record_anchor", refuse)
    with pytest.raises(AuditRefused, match="custody"):
        ledger.record_event("hit", "deploy", card_id="refused")
    assert ledger.verify().startswith("BROKEN")


def test_nonfinite_returns_are_not_recorded():
    store = jit_rl.JitStore()
    for value in (float("nan"), float("inf"), float("-inf")):
        store.record([1.0], "deploy", value)
    store.record([1.0], "deploy", 0.5)
    assert len(store) == 1
    assert store.value([1.0]) == 0.5


def test_pending_approval_below_evicted_ids_remains_usable(tmp_path, monkeypatch):
    from maverick.world_model import open_world
    monkeypatch.setenv("MAVERICK_HARNESS_REFINE", "1")
    monkeypatch.setattr(harness_refine, "_MAX_CONSUMED_APPROVALS", 1)
    observations = {
        "target": "prompt", "name": "approval", "failure": "Approval was missing.",
        "change": "Check approval before writing.", "rationale": "Require confirmation.",
    }
    records = [harness_refine.propose({**observations, "name": f"approval-{i}"}) for i in range(3)]
    for record in records:
        open_world().decide_approval(record["approval_id"], "approved", decided_by="operator")
    store = harness_refine._load_store()
    for record in records[1:]:
        harness_refine._consume_approval(store, record, record["approval_id"], applied_by="local:operator")
        store["proposals"][record["id"]]["status"] = "applied"
    assert harness_refine._consume_approval(store, records[0], records[0]["approval_id"], applied_by="local:operator") == records[0]["approval_id"]
    with pytest.raises(harness_refine.RefineError, match="already applied"):
        harness_refine._consume_approval(store, records[1], records[1]["approval_id"], applied_by="local:operator")


def test_snapshot_pin_survives_other_process_and_releases_after_crash(tmp_path):
    base = tmp_path / "snapshots"
    script = """
import sys
from pathlib import Path
from maverick import dreaming
dreaming.snapshots_dir = lambda: Path(sys.argv[1])
dreaming._live_stores = lambda: {}
dreaming.settings = lambda: {"snapshots": True}
with dreaming.learning_mutation_scope(keep_last=1) as snap:
    print(snap.name, flush=True)
    sys.stdin.read()
"""
    process = subprocess.Popen([sys.executable, "-c", script, str(base)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        name = process.stdout.readline().strip()
        assert name, process.stderr.read()
        snap = base / name
        for _ in range(3):
            dreaming.snapshot_learning_state(directory=base, stores={}, keep_last=1,
                                             publish_empty=True, raise_on_error=True)
        assert snap.is_dir()
        process.kill()
        process.wait(timeout=5)
        dreaming.snapshot_learning_state(directory=base, stores={}, keep_last=1,
                                         publish_empty=True, raise_on_error=True)
        assert not snap.exists()
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
