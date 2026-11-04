"""Tests for the governed self-improvement controller.

Deterministic and offline: no LLM, no torch, no training. We exercise the
governance spine -- the gate pipeline, the capability-non-escalation proof, the
calibration freeze, human approval, reversibility, audit, and the ledger.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from maverick.self_improvement import (
    ArtifactRevision,
    Candidate,
    PromotionLedger,
    PromotionLedgerError,
    PromotionRecord,
    SelfImprovementController,
    consider,
    reset_shared,
)


class _Grant:
    """Minimal capability stand-in: permits a fixed set of tools."""

    def __init__(self, tools):
        self._tools = set(tools)

    def permits(self, tool, *, now=None):
        return tool in self._tools


def _ctrl(audit=None, frozen=False, **kw):
    return SelfImprovementController(
        frozen_fn=lambda: frozen,
        audit_fn=(audit if audit is not None else (lambda **k: None)),
        **kw,
    )


def _cand(**kw):
    base = dict(
        rung="config", summary="tweak", baseline_score=0.5, candidate_score=0.7,
        samples=5, rollback="snap-1",
    )
    base.update(kw)
    return Candidate(**base)


def _artifact(content: str, *, identity: str = "prompt-addenda:model-a",
              version: str | None = None) -> ArtifactRevision:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return ArtifactRevision(identity, digest, version or digest[:16])


# -- evaluate(): gate logic (pure, no env / no enable needed) --------------

def test_promotes_config_rung_when_it_beats_baseline():
    v = _ctrl().evaluate(_cand(rung="config", baseline_score=0.5, candidate_score=0.7))
    assert v.ok
    assert all(g.ok for g in v.gates)


def test_no_improvement_is_rejected():
    v = _ctrl().evaluate(_cand(candidate_score=0.5))  # == baseline
    assert not v.ok
    assert any(g.gate == "evidence" and not g.ok for g in v.gates)


def test_insufficient_samples_is_rejected():
    v = _ctrl().evaluate(_cand(rung="config", samples=1))
    assert not v.ok
    assert "evidence" in v.blocking_reason or "sample" in v.blocking_reason.lower()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("baseline_score", float("nan")),
        ("candidate_score", float("inf")),
        ("candidate_score", True),
        ("candidate_score", 1.01),
        ("samples", True),
        ("samples", 5.0),
        ("effect_ci_low", float("nan")),
        ("effect_ci_low", 1.01),
    ],
)
def test_invalid_promotion_evidence_fails_closed(field, value):
    verdict = _ctrl().evaluate(_cand(**{field: value}))

    assert not verdict.ok
    assert any(g.gate == "evidence" and not g.ok for g in verdict.gates)


def test_invalid_controller_margin_fails_closed():
    assert not _ctrl(min_improvement=float("nan")).evaluate(_cand()).ok
    assert not _ctrl(min_improvement=-0.1).evaluate(_cand()).ok


def test_calibration_freeze_blocks_all_promotion():
    v = _ctrl(frozen=True).evaluate(_cand())
    assert not v.ok
    assert any(g.gate == "calibration" and not g.ok for g in v.gates)


def test_frozen_fn_error_fails_closed():
    def boom():
        raise RuntimeError("cannot reach calibration verdict")

    ctrl = SelfImprovementController(frozen_fn=boom, audit_fn=lambda **k: None)
    v = ctrl.evaluate(_cand())
    assert not v.ok  # can't confirm the judge is honest -> refuse


# -- capability non-escalation (the core safety property) ------------------

def test_tool_rung_without_capability_proof_is_rejected():
    v = _ctrl().evaluate(_cand(rung="tool", samples=5))
    assert not v.ok
    assert any(g.gate == "capability" and not g.ok for g in v.gates)


def test_tool_rung_with_non_escalation_proof_promotes():
    v = _ctrl().evaluate(_cand(rung="tool", samples=5, capability_widens=False))
    assert v.ok


def test_declared_widening_is_rejected():
    v = _ctrl().evaluate(_cand(rung="tool", samples=5, capability_widens=True))
    assert not v.ok
    assert any(g.gate == "capability" and not g.ok for g in v.gates)


def test_capability_probe_detects_widening_from_grants():
    before, after = _Grant({"read_file"}), _Grant({"read_file", "shell"})
    v = _ctrl().evaluate(_cand(
        rung="tool", samples=5,
        capability_before=before, capability_after=after,
        probe_tools=("read_file", "shell"),
    ))
    assert not v.ok  # 'shell' is newly permitted -> escalation


def test_capability_probe_passes_when_bounded():
    before, after = _Grant({"read_file", "shell"}), _Grant({"read_file"})
    v = _ctrl().evaluate(_cand(
        rung="tool", samples=5,
        capability_before=before, capability_after=after,
        probe_tools=("read_file", "shell"),
    ))
    assert v.ok  # strictly narrower -> bounded


# -- human approval & the auto-promotion ceiling ---------------------------

def test_code_rung_requires_human_approval():
    v = _ctrl().evaluate(_cand(rung="code", samples=10, capability_widens=False, approved=False))
    assert not v.ok
    assert any(g.gate == "human_approval" and not g.ok for g in v.gates)
    v2 = _ctrl().evaluate(_cand(rung="code", samples=10, capability_widens=False, approved=True))
    assert not v2.ok  # a self-settable boolean is not a cryptographic approval


def test_max_auto_rung_ceiling_forces_human_above_it():
    # Ceiling at 'config' means even a 'policy' change needs a human.
    ctrl = _ctrl(max_auto_rung="config")
    v = ctrl.evaluate(_cand(rung="policy", samples=8, capability_widens=False, approved=False))
    assert not v.ok
    assert any(g.gate == "human_approval" and not g.ok for g in v.gates)


def test_unknown_max_auto_rung_fails_closed_not_open():
    # Regression: a typo'd/unknown ceiling must behave as the MOST restrictive
    # ceiling (require human for everything above the lowest rung), never as an
    # unbounded ceiling that silently disables the autonomous-promotion gate.
    ctrl = _ctrl(max_auto_rung="polciy")   # deliberate typo of "policy"
    v = ctrl.evaluate(_cand(rung="policy", samples=8, capability_widens=False, approved=False))
    assert not v.ok
    assert any(g.gate == "human_approval" and not g.ok for g in v.gates)


# -- reversibility ---------------------------------------------------------

def test_non_reversible_change_is_rejected():
    v = _ctrl().evaluate(_cand(rollback=None))
    assert not v.ok
    assert any(g.gate == "rollback" and not g.ok for g in v.gates)


def test_truthy_rollback_placeholder_is_not_a_recovery_handle():
    verdict = _ctrl().evaluate(_cand(rollback=True))
    assert not verdict.ok
    assert any(g.gate == "rollback" and not g.ok for g in verdict.gates)


def test_truthy_non_boolean_approval_cannot_cross_human_gate():
    verdict = _ctrl().evaluate(_cand(
        rung="code", samples=10, capability_widens=False,
        approved="false",
    ))
    assert not verdict.ok
    assert any(g.gate == "human_approval" and not g.ok for g in verdict.gates)


def test_unknown_rung_is_rejected():
    v = _ctrl().evaluate(_cand(rung="weights_and_biases"))
    assert not v.ok


# -- promote()/rollback() with a ledger + audit ----------------------------

def test_promote_records_and_audits(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    audited = []
    ledger = PromotionLedger(path=tmp_path / "si.json")
    ctrl = _ctrl(audit=lambda **k: audited.append(k), ledger=ledger)
    cand = _cand(rung="config")
    v = ctrl.promote(cand)
    assert v.ok
    assert ledger.get(cand.id) is not None
    assert any(a.get("decision") == "promote" for a in audited)


def test_rejected_promotion_is_audited_but_not_recorded(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    audited = []
    ledger = PromotionLedger(path=tmp_path / "si.json")
    ctrl = _ctrl(audit=lambda **k: audited.append(k), ledger=ledger)
    cand = _cand(candidate_score=0.4)  # below baseline
    v = ctrl.promote(cand)
    assert not v.ok
    assert ledger.get(cand.id) is None
    assert any(a.get("decision") == "reject" for a in audited)


def test_rollback_reverses_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    audited = []
    ledger = PromotionLedger(path=tmp_path / "si.json")
    ctrl = _ctrl(audit=lambda **k: audited.append(k), ledger=ledger)
    cand = _cand(rung="config")
    ctrl.promote(cand)
    undone = []
    assert ctrl.rollback(cand.id, undo=lambda: undone.append(True)) is True
    assert undone == [True]
    assert ledger.get(cand.id).rolled_back is True
    assert any(a.get("decision") == "rollback" for a in audited)
    # Second rollback is a no-op.
    assert ctrl.rollback(cand.id, undo=lambda: undone.append(True)) is False


def test_ledger_persists_across_instances(tmp_path):
    p = tmp_path / "si.json"
    led = PromotionLedger(path=p)
    led.add(PromotionRecord(id="abc", rung="config", summary="x",
                            baseline_score=0.1, candidate_score=0.9, promoted_at=1.0))
    reloaded = PromotionLedger(path=p)
    assert reloaded.get("abc") is not None
    assert reloaded.get("abc").candidate_score == 0.9


def test_prepare_is_invisible_until_exact_artifact_commit(tmp_path):
    p = tmp_path / "si.json"
    ledger = PromotionLedger(path=p)
    before, after = _artifact("before"), _artifact("after")
    rec = PromotionRecord(
        id="tx-record", rung="prompt", summary="x",
        baseline_score=0.1, candidate_score=0.9, promoted_at=1.0)

    tx = ledger.prepare(
        rec, before=before, after=after, prepared_at=1.0,
        transaction_id="tx-1")
    assert tx.state == "prepared"
    assert ledger.get(rec.id) is None
    assert json.loads(p.read_text(encoding="utf-8")) == []
    with pytest.raises(PromotionLedgerError, match="does not match"):
        ledger.commit("tx-1", artifact=before, at=2.0)
    assert ledger.transaction("tx-1").state == "prepared"

    committed = ledger.commit("tx-1", artifact=after, at=3.0)
    assert committed.promoted_at == 3.0
    assert ledger.get(rec.id) == committed
    # Repeating the exact operation is idempotent and appends no second COMMIT.
    assert ledger.commit("tx-1", artifact=after, at=4.0) == committed
    events = [json.loads(line) for line in Path(
        f"{p}.journal").read_text(encoding="utf-8").splitlines()]
    assert [event["event"] for event in events] == ["prepare", "commit"]
    assert events[0]["transaction"]["before"] == before.to_dict()
    assert events[0]["transaction"]["after"] == after.to_dict()
    assert PromotionLedger(path=p).transaction("tx-1").state == "committed"


def test_transactions_filters_durable_authority_and_refreshes_rollback(tmp_path):
    p = tmp_path / "si.json"
    writer = PromotionLedger(path=p)
    a_before = _artifact("a-before", identity="artifact:a")
    a_after = _artifact("a-after", identity="artifact:a")
    a_next = _artifact("a-next", identity="artifact:a")
    b_before = _artifact("b-before", identity="artifact:b")
    b_after = _artifact("b-after", identity="artifact:b")

    writer.prepare(PromotionRecord(
        id="rec-z", rung="evaluator", summary="committed",
        baseline_score=0.1, candidate_score=0.9, promoted_at=2.0,
    ), before=a_before, after=a_after, prepared_at=2.0, transaction_id="tx-z")
    writer.commit("tx-z", artifact=a_after, at=3.0)
    # Construct the reader before later events to prove the query re-reads the
    # durable journal instead of serving its initialization-time cache.
    reader = PromotionLedger(path=p)

    assert writer.mark_rolled_back("rec-z", at=4.0)
    writer.prepare(PromotionRecord(
        id="rec-b", rung="evaluator", summary="aborted",
        baseline_score=0.1, candidate_score=0.8, promoted_at=1.0,
    ), before=b_before, after=b_after, prepared_at=1.0, transaction_id="tx-b")
    writer.abort("tx-b", artifact=b_before, at=5.0, reason="not activated")
    writer.prepare(PromotionRecord(
        id="rec-a", rung="evaluator", summary="prepared",
        baseline_score=0.1, candidate_score=0.7, promoted_at=1.0,
    ), before=a_after, after=a_next, prepared_at=1.0, transaction_id="tx-a")

    assert [tx.id for tx in reader.transactions()] == ["tx-a", "tx-b", "tx-z"]
    assert [tx.id for tx in reader.transactions(
        artifact_identity="artifact:a",
    )] == ["tx-a", "tx-z"]
    assert [tx.id for tx in reader.transactions(
        artifact_identity="artifact:a", state="prepared",
    )] == ["tx-a"]
    assert [tx.id for tx in reader.transactions(state="aborted")] == ["tx-b"]

    committed = reader.transactions(
        artifact_identity="artifact:a", state="committed",
    )
    assert [tx.id for tx in committed] == ["tx-z"]
    assert committed[0].record.promoted_at == 3.0
    assert committed[0].record.rolled_back is True
    assert committed[0].record.rolled_back_at == 4.0


@pytest.mark.parametrize("query", [
    {"artifact_identity": 1},
    {"artifact_identity": ""},
    {"artifact_identity": " artifact:a"},
    {"artifact_identity": "artifact:a\n"},
    {"artifact_identity": "x" * 2049},
    {"state": True},
    {"state": ""},
    {"state": "COMMITTED"},
    {"state": {"committed"}},
])
def test_transactions_rejects_invalid_filters_before_authority_read(monkeypatch, query):
    ledger = PromotionLedger()

    def should_not_read():
        raise AssertionError("invalid filters must be rejected before authority I/O")

    monkeypatch.setattr(ledger, "_full_state_locked", should_not_read)
    with pytest.raises(ValueError):
        ledger.transactions(**query)


def test_abort_requires_proof_original_artifact_is_live(tmp_path):
    ledger = PromotionLedger(path=tmp_path / "si.json")
    before, after = _artifact("before"), _artifact("after")
    unknown = _artifact("unknown")
    rec = PromotionRecord(
        id="abort-record", rung="prompt", summary="x",
        baseline_score=0.1, candidate_score=0.9, promoted_at=1.0)
    ledger.prepare(rec, before=before, after=after, prepared_at=1.0,
                   transaction_id="abort-tx")

    with pytest.raises(PromotionLedgerError, match="differs from prepared before"):
        ledger.abort("abort-tx", artifact=unknown, at=2.0, reason="write failed")
    assert ledger.transaction("abort-tx").in_doubt
    aborted = ledger.abort(
        "abort-tx", artifact=before, at=3.0, reason="write failed")
    assert aborted.state == "aborted"
    assert ledger.get(rec.id) is None
    assert ledger.abort(
        "abort-tx", artifact=before, at=4.0, reason="retry") == aborted
    with pytest.raises(PromotionLedgerError, match="aborted"):
        ledger.commit("abort-tx", artifact=after, at=5.0)


def test_recovery_commits_after_aborts_before_and_blocks_unknown_state(tmp_path):
    p = tmp_path / "si.json"
    ledger = PromotionLedger(path=p)
    before_a, after_a = _artifact("a-before", identity="artifact:a"), _artifact(
        "a-after", identity="artifact:a")
    before_b, after_b = _artifact("b-before", identity="artifact:b"), _artifact(
        "b-after", identity="artifact:b")
    before_c, after_c = _artifact("c-before", identity="artifact:c"), _artifact(
        "c-after", identity="artifact:c")
    unknown_c = _artifact("c-partial", identity="artifact:c")
    for tx_id, rec_id, before, after in (
        ("tx-a", "rec-a", before_a, after_a),
        ("tx-b", "rec-b", before_b, after_b),
        ("tx-c", "rec-c", before_c, after_c),
    ):
        ledger.prepare(PromotionRecord(
            id=rec_id, rung="prompt", summary="x", baseline_score=0.1,
            candidate_score=0.9, promoted_at=1.0), before=before, after=after,
            prepared_at=1.0, transaction_id=tx_id)

    current = {
        "artifact:a": after_a,
        "artifact:b": before_b,
        "artifact:c": unknown_c,
    }
    recovered = ledger.recover_in_doubt(current.__getitem__, at=10.0)
    states = {tx.id: tx.state for tx in recovered}
    assert states == {"tx-a": "committed", "tx-b": "aborted", "tx-c": "prepared"}
    assert ledger.get("rec-a") is not None
    assert ledger.get("rec-b") is None
    conflicted = ledger.transaction("tx-c")
    assert conflicted.in_doubt
    assert conflicted.last_observed == unknown_c
    assert conflicted.recovery_attempts == 1

    with pytest.raises(PromotionLedgerError, match="unresolved"):
        ledger.prepare(PromotionRecord(
            id="rec-c2", rung="prompt", summary="x", baseline_score=0.1,
            candidate_score=0.9, promoted_at=2.0), before=unknown_c,
            after=_artifact("c-next", identity="artifact:c"), prepared_at=2.0)

    # A later trustworthy observation resolves the crash window without a
    # whole-store snapshot restore or operator guessing which side won.
    current["artifact:c"] = after_c
    resolved = PromotionLedger(path=p).recover_in_doubt(
        current.__getitem__, artifact_identity="artifact:c", at=11.0)
    assert [tx.state for tx in resolved] == ["committed"]
    assert PromotionLedger(path=p).get("rec-c") is not None


def test_controller_prepare_and_commit_never_claims_promotion_early(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    audited = []
    ledger = PromotionLedger(path=tmp_path / "si.json")
    ctrl = _ctrl(audit=lambda **event: audited.append(event), ledger=ledger)
    before, after = _artifact("before"), _artifact("after")
    candidate = _cand(rung="config")

    preparation = ctrl.prepare_promotion(candidate, before=before, after=after)
    assert preparation.ok
    assert preparation.needs_apply
    assert not preparation.committed
    assert ledger.get(candidate.id) is None
    assert not any(event.get("decision") == "promote" for event in audited)
    verdict = ctrl.commit_prepared(preparation, artifact=after)
    assert verdict.ok
    assert ledger.get(candidate.id) is not None
    assert any(event.get("decision") == "prepare" for event in audited)
    assert any(event.get("decision") == "promote" for event in audited)
    retry = ctrl.prepare_promotion(candidate, before=before, after=after)
    assert retry.ok and retry.committed and not retry.needs_apply


def test_controller_abort_mismatch_remains_in_doubt_for_recovery(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    ledger = PromotionLedger(path=tmp_path / "si.json")
    ctrl = _ctrl(ledger=ledger)
    before, after = _artifact("before"), _artifact("after")
    preparation = ctrl.prepare_promotion(_cand(), before=before, after=after)

    verdict = ctrl.abort_prepared(
        preparation, artifact=_artifact("partial"), reason="apply failed")
    assert not verdict.ok
    assert "recovery required" in verdict.blocking_reason
    assert ledger.transaction(preparation.transaction_id).in_doubt
    recovered = ctrl.recover_promotions(
        lambda _identity: after, artifact_identity=before.identity)
    assert [tx.state for tx in recovered] == ["committed"]
    assert ledger.get(preparation.verdict.candidate_id) is not None


def test_commit_journal_failure_keeps_prepare_recoverable(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    p = tmp_path / "si.json"
    ledger = PromotionLedger(path=p)
    ctrl = _ctrl(ledger=ledger)
    before, after = _artifact("before"), _artifact("after")
    preparation = ctrl.prepare_promotion(_cand(), before=before, after=after)
    real_append = ledger._append_events_locked

    def fail_append(_events):
        raise PromotionLedgerError("simulated COMMIT fsync failure")

    monkeypatch.setattr(ledger, "_append_events_locked", fail_append)
    verdict = ctrl.commit_prepared(preparation, artifact=after)
    assert not verdict.ok
    assert "recovery required" in verdict.blocking_reason
    assert PromotionLedger(path=p).transaction(preparation.transaction_id).in_doubt

    monkeypatch.setattr(ledger, "_append_events_locked", real_append)
    recovered = PromotionLedger(path=p).recover_in_doubt(
        lambda _identity: after, at=20.0)
    assert [tx.state for tx in recovered] == ["committed"]
    assert PromotionLedger(path=p).get(preparation.verdict.candidate_id) is not None


def test_ledger_journal_is_append_only_hash_chained_and_auditor_compatible(tmp_path):
    """Rollback appends authority while retaining the JSON audit projection."""
    p = tmp_path / "si.json"
    ledger = PromotionLedger(path=p)
    ledger.add(PromotionRecord(id="receipt", rung="config", summary="x",
                               baseline_score=0.1, candidate_score=0.9, promoted_at=1.0))
    journal = Path(f"{p}.journal")
    first_bytes = journal.read_bytes()
    assert isinstance(json.loads(p.read_text(encoding="utf-8")), list)

    assert ledger.mark_rolled_back("receipt", at=2.0) is True
    assert journal.read_bytes().startswith(first_bytes)
    events = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]
    assert [event["event"] for event in events] == ["promote", "rollback"]
    assert events[1]["prev_sha256"] == events[0]["sha256"]


def test_ledger_retention_limit_refuses_without_erasing_history(tmp_path):
    ledger = PromotionLedger(path=tmp_path / "si.json", max_records=1)
    ledger.add(PromotionRecord(id="first", rung="config", summary="x",
                               baseline_score=0.1, candidate_score=0.9, promoted_at=1.0))

    with pytest.raises(PromotionLedgerError, match="retention limit"):
        ledger.add(PromotionRecord(id="second", rung="config", summary="x",
                                   baseline_score=0.1, candidate_score=0.9, promoted_at=2.0))

    assert [record.id for record in ledger.all()] == ["first"]


def test_ledger_rejects_journal_tampering_and_repairs_projection(tmp_path):
    p = tmp_path / "si.json"
    ledger = PromotionLedger(path=p)
    ledger.add(PromotionRecord(id="receipt", rung="config", summary="x",
                               baseline_score=0.1, candidate_score=0.9, promoted_at=1.0))
    journal = Path(f"{p}.journal")
    event = json.loads(journal.read_text(encoding="utf-8"))
    event["record"]["summary"] = "forged"
    journal.write_text(json.dumps(event) + "\n", encoding="utf-8")
    with pytest.raises(PromotionLedgerError, match="hash check"):
        PromotionLedger(path=p)

    projection_path = tmp_path / "projection.json"
    projection_ledger = PromotionLedger(path=projection_path)
    projection_ledger.add(PromotionRecord(
        id="receipt", rung="config", summary="x",
        baseline_score=0.1, candidate_score=0.9, promoted_at=1.0,
    ))
    projection = json.loads(projection_path.read_text(encoding="utf-8"))
    projection[0]["candidate_score"] = 999.0
    projection_path.write_text(json.dumps(projection), encoding="utf-8")

    repaired = PromotionLedger(path=projection_path)
    assert repaired.get("receipt").candidate_score == 0.9
    assert json.loads(projection_path.read_text(encoding="utf-8"))[0][
        "candidate_score"
    ] == 0.9


def test_persist_failure_rejects_promotion_and_surfaces_from_add(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    ledger = PromotionLedger(path=tmp_path / "si.json")

    def fail_append(_events):
        raise PromotionLedgerError("simulated durable write failure")

    monkeypatch.setattr(ledger, "_append_events_locked", fail_append)
    audited = []
    verdict = _ctrl(audit=lambda **event: audited.append(event), ledger=ledger).promote(_cand())
    assert not verdict.ok
    assert any(gate.gate == "ledger" and not gate.ok for gate in verdict.gates)
    assert not any(event.get("decision") == "promote" for event in audited)
    assert any(event.get("decision") == "reject" for event in audited)
    assert not (tmp_path / "si.json").exists()

    with pytest.raises(PromotionLedgerError, match="simulated"):
        ledger.add(PromotionRecord(id="direct", rung="config", summary="x",
                                   baseline_score=0.1, candidate_score=0.9, promoted_at=1.0))


def test_missing_ledger_is_a_failed_promotion_gate(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    audited = []
    verdict = _ctrl(audit=lambda **event: audited.append(event)).promote(_cand())
    assert not verdict.ok
    assert any(gate.gate == "ledger" and not gate.ok for gate in verdict.gates)
    assert not any(event.get("decision") == "promote" for event in audited)


def test_projection_failure_after_journal_commit_repairs_from_authority(tmp_path, monkeypatch):
    """A committed receipt remains true even if its rebuildable cache fails."""
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    p = tmp_path / "si.json"
    ledger = PromotionLedger(path=p)
    original_write = ledger._write_projection_locked

    def fail_projection(_records):
        raise PromotionLedgerError("simulated projection failure")

    monkeypatch.setattr(ledger, "_write_projection_locked", fail_projection)
    candidate = _cand()
    assert _ctrl(ledger=ledger).promote(candidate).ok
    assert Path(f"{p}.journal").exists()
    assert not p.exists()
    # Persistent cache failure cannot block authority reads or a later commit.
    assert ledger.get(candidate.id) is not None
    ledger.add(PromotionRecord(id="second", rung="config", summary="x",
                               baseline_score=0.2, candidate_score=0.8, promoted_at=2.0))

    monkeypatch.setattr(ledger, "_write_projection_locked", original_write)
    repaired = PromotionLedger(path=p)
    assert repaired.get(candidate.id) is not None
    assert repaired.get("second") is not None
    assert p.exists()


def test_audit_sink_failure_cannot_invert_a_committed_transition(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    ledger = PromotionLedger(path=tmp_path / "si.json")

    def fail_audit(**_payload):
        raise RuntimeError("audit sink unavailable")

    ctrl = _ctrl(audit=fail_audit, ledger=ledger)
    candidate = _cand()
    assert ctrl.promote(candidate).ok
    assert ledger.get(candidate.id) is not None
    assert ctrl.rollback(candidate.id, undo=lambda: None) is True
    assert ledger.get(candidate.id).rolled_back is True


def test_rollback_persist_failure_is_not_reported_as_complete(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    ledger = PromotionLedger(path=tmp_path / "si.json")
    ctrl = _ctrl(ledger=ledger)
    candidate = _cand()
    assert ctrl.promote(candidate).ok

    def fail_append(_events):
        raise PromotionLedgerError("simulated durable write failure")

    monkeypatch.setattr(ledger, "_append_events_locked", fail_append)
    undone = []
    assert ctrl.rollback(candidate.id, undo=lambda: undone.append(True)) is False
    assert undone == [True]
    assert ledger.get(candidate.id).rolled_back is False
    with pytest.raises(PromotionLedgerError, match="simulated"):
        ledger.mark_rolled_back(candidate.id, at=3.0)


def test_concurrent_processes_do_not_lose_promotion_receipts(tmp_path):
    p = tmp_path / "si.json"
    source_root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        filter(None, (str(source_root), env.get("PYTHONPATH", ""))))
    children = []
    for index in range(6):
        code = (
            "from pathlib import Path\n"
            "from maverick.self_improvement import PromotionLedger, PromotionRecord\n"
            f"ledger = PromotionLedger(path=Path({str(p)!r}))\n"
            f"ledger.add(PromotionRecord(id='p{index}', rung='config', summary='x', "
            f"baseline_score=0.1, candidate_score=0.9, promoted_at={float(index)!r}))\n"
        )
        children.append(subprocess.Popen(
            [sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env,
        ))
    for child in children:
        _, stderr = child.communicate(timeout=45)
        assert child.returncode == 0, stderr

    reloaded = PromotionLedger(path=p)
    assert {record.id for record in reloaded.all()} == {f"p{index}" for index in range(6)}


def test_concurrent_prepare_retry_is_one_idempotent_journal_event(tmp_path):
    p = tmp_path / "si.json"
    source_root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        filter(None, (str(source_root), env.get("PYTHONPATH", ""))))
    before, after = _artifact("before"), _artifact("after")
    code = (
        "from pathlib import Path\n"
        "from maverick.self_improvement import (ArtifactRevision, PromotionLedger, "
        "PromotionRecord)\n"
        f"ledger = PromotionLedger(path=Path({str(p)!r}))\n"
        "record = PromotionRecord(id='same-record', rung='prompt', summary='x', "
        "baseline_score=0.1, candidate_score=0.9, promoted_at=1.0)\n"
        f"before = ArtifactRevision(**{before.to_dict()!r})\n"
        f"after = ArtifactRevision(**{after.to_dict()!r})\n"
        "ledger.prepare(record, before=before, after=after, prepared_at=1.0, "
        "transaction_id='same-tx')\n"
    )
    children = [subprocess.Popen(
        [sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    ) for _ in range(4)]
    for child in children:
        _, stderr = child.communicate(timeout=45)
        assert child.returncode == 0, stderr

    events = [json.loads(line) for line in Path(
        f"{p}.journal").read_text(encoding="utf-8").splitlines()]
    assert [event["event"] for event in events] == ["prepare"]
    assert PromotionLedger(path=p).in_doubt()[0].id == "same-tx"


# -- signature material persisted in the ledger (independent verifiability) --

def test_promotion_record_signature_fields_round_trip(tmp_path):
    """approver_id/payload_sha256/approval_signature survive save -> load so a
    third party can re-verify the Ed25519 signature from the ledger file alone."""
    p = tmp_path / "si.json"
    led = PromotionLedger(path=p)
    led.add(PromotionRecord(
        id="sig-1", rung="code", summary="signed change",
        baseline_score=0.2, candidate_score=0.9, promoted_at=2.0,
        approver_id="abc123deadbeef00", payload_sha256="deadbeef" * 8,
        approval_signature="ff" * 64))
    rec = PromotionLedger(path=p).get("sig-1")
    assert rec is not None
    assert rec.approver_id == "abc123deadbeef00"
    assert rec.payload_sha256 == "deadbeef" * 8
    assert rec.approval_signature == "ff" * 64
    assert rec.to_dict()["approval_signature"] == "ff" * 64


def test_old_ledger_without_signature_fields_still_loads(tmp_path):
    """A ledger written BEFORE the signature fields existed loads exactly as
    before; the new fields default None (backward compatibility)."""
    p = tmp_path / "si.json"
    p.write_text(json.dumps([{
        "id": "old-1", "rung": "config", "summary": "legacy",
        "baseline_score": 0.1, "candidate_score": 0.5, "promoted_at": 1.0,
        "rolled_back": False, "rolled_back_at": None,
    }]), encoding="utf-8")
    rec = PromotionLedger(path=p).get("old-1")
    assert rec is not None
    assert Path(f"{p}.journal").exists()
    assert rec.candidate_score == 0.5
    assert rec.approver_id is None
    assert rec.payload_sha256 is None
    assert rec.approval_signature is None


def test_promote_persists_candidate_signature_material(tmp_path, monkeypatch):
    """promote() copies a candidate's signature material into the ledger record,
    and mark_rolled_back preserves it through the to_dict -> constructor round-trip."""
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    ledger = PromotionLedger(path=tmp_path / "si.json")
    ctrl = _ctrl(ledger=ledger)
    cand = _cand(rung="config", payload_sha256="ab" * 32, approval_signature="cd" * 64)
    assert ctrl.promote(cand).ok
    rec = ledger.get(cand.id)
    assert rec.payload_sha256 == "ab" * 32
    assert rec.approval_signature == "cd" * 64
    ctrl.rollback(cand.id, undo=lambda: None)
    rec2 = ledger.get(cand.id)
    assert rec2.rolled_back is True
    assert rec2.approval_signature == "cd" * 64  # survived the rolled-back rewrite


def test_promote_without_signature_leaves_fields_none(tmp_path, monkeypatch):
    """A promotion with no cryptographic approval records None -- unchanged
    behaviour from before the fields existed."""
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    ledger = PromotionLedger(path=tmp_path / "si.json")
    ctrl = _ctrl(ledger=ledger)
    rec = None
    assert ctrl.promote(_cand(rung="config")).ok
    rec = ledger.get(next(iter(r.id for r in ledger.all())))
    assert rec.approver_id is None
    assert rec.payload_sha256 is None
    assert rec.approval_signature is None


# -- governed default-on posture ------------------------------------------

def test_enabled_by_default_can_consider_safe_rung(monkeypatch):
    monkeypatch.delenv("MAVERICK_SELF_IMPROVEMENT", raising=False)
    reset_shared()
    v = consider(_cand(rung="config"))
    assert v.ok


def test_explicit_opt_out_is_a_noop(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "0")
    reset_shared()
    v = consider(_cand(rung="config"))
    assert not v.ok and "disabled" in v.blocking_reason


def test_consider_promotes_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    ledger = PromotionLedger(path=tmp_path / "si.json")
    ctrl = _ctrl(ledger=ledger)
    v = consider(_cand(rung="config"), controller=ctrl)
    assert v.ok


# -- capability evidence on the receipt (bounded self-improvement, checkable) --
#
# The capability gate always refused a widening change, but the durable receipt
# did not record WHAT the gate concluded -- so a third party reading the ledger
# afterwards could not tell "proven bounded" from "never checked". These tests
# pin the grading and, just as importantly, pin that a missing grading stays
# missing rather than being read as bounded.

def test_a_walked_probe_is_recorded_as_probed_bounded():
    v = _ctrl().evaluate(_cand(
        rung="tool", capability_before=_Grant({"a"}), capability_after=_Grant({"a"}),
        probe_tools=("a", "b", "c")))
    assert v.ok
    assert v.capability_evidence == "probed_bounded"
    assert v.capability_probe_tools == 3


def test_a_declared_verdict_is_recorded_as_weaker_than_a_probe():
    """'The caller asserted it' and 'the algebra was walked over 3 tools' are
    different grades of proof; the receipt has to keep them apart."""
    v = _ctrl().evaluate(_cand(rung="tool", capability_widens=False))
    assert v.ok
    assert v.capability_evidence == "declared_bounded"
    assert v.capability_probe_tools is None


def test_a_rung_needing_no_capability_proof_records_unproven():
    v = _ctrl().evaluate(_cand(rung="config"))
    assert v.ok
    assert v.capability_evidence == "unproven"


def test_a_widening_change_is_still_refused_and_says_so():
    v = _ctrl().evaluate(_cand(
        rung="tool", capability_before=_Grant({"a"}),
        capability_after=_Grant({"a", "danger"}), probe_tools=("a", "danger")))
    assert not v.ok
    assert any(g.gate == "capability" and not g.ok for g in v.gates)


def test_an_ill_typed_widening_claim_does_not_masquerade_as_proof():
    """A truthy string is not a proof about authority."""
    v = _ctrl().evaluate(_cand(rung="config", capability_widens="false"))
    assert v.capability_evidence == "unproven"


def test_the_grading_survives_a_later_gate_failure():
    ctrl = _ctrl()
    v = ctrl.evaluate(_cand(rung="tool", capability_widens=False))
    failed = ctrl._fail_verdict(v, gate="ledger", reason="boom")
    assert failed.capability_evidence == "declared_bounded"


def test_the_grading_reaches_the_persisted_receipt(tmp_path):
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    ctrl = _ctrl(ledger=ledger)
    cand = _cand(rung="tool", capability_before=_Grant({"a"}),
                 capability_after=_Grant({"a"}), probe_tools=("a", "b"))
    v = ctrl._promotion_record(cand, ctrl.evaluate(cand), at=1.0)
    assert v.capability_evidence == "probed_bounded"
    assert v.capability_probe_tools == 2
    assert v.to_dict()["capability_evidence"] == "probed_bounded"


def test_a_receipt_without_a_grading_omits_the_field_entirely():
    """Backward compatibility is load-bearing here: the journal is hash-chained
    over ``to_dict()``, so a receipt written before this field existed must
    re-serialize byte-identically or its recorded hash stops verifying."""
    rec = PromotionRecord(id="a", rung="config", summary="s", baseline_score=0.1,
                          candidate_score=0.2, promoted_at=1.0)
    data = rec.to_dict()
    assert "capability_evidence" not in data
    assert "capability_probe_tools" not in data
    # And the round trip a projection rebuild performs must be lossless.
    assert PromotionRecord(**data).to_dict() == data


def test_a_legacy_journal_hash_still_verifies_after_the_field_was_added(tmp_path):
    """The concrete regression the omission guards: an existing ledger must
    still load and verify, not fail closed because the schema grew."""
    path = tmp_path / "ledger.json"
    ledger = PromotionLedger(path=path)
    ledger.add(PromotionRecord(id="legacy", rung="config", summary="s",
                               baseline_score=0.1, candidate_score=0.2,
                               promoted_at=1.0))
    journal = Path(f"{path}.journal")
    before = journal.read_bytes()
    reopened = PromotionLedger(path=path)
    assert [r.id for r in reopened.all()] == ["legacy"]
    assert reopened.get("legacy").capability_evidence is None
    assert journal.read_bytes() == before  # loading rewrote nothing


def test_an_unrecognised_grading_is_rejected_not_downgraded(tmp_path):
    """A stronger-sounding invented label must not be quietly accepted as a
    weaker one -- that is how a future writer or an editor launders a claim."""
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps([{
        "id": "a", "rung": "config", "summary": "s", "baseline_score": 0.1,
        "candidate_score": 0.2, "promoted_at": 1.0,
        "capability_evidence": "cryptographically_bounded",
    }]), encoding="utf-8")
    with pytest.raises(PromotionLedgerError):
        PromotionLedger(path=path)


def test_a_probe_count_without_a_probed_grading_is_rejected(tmp_path):
    """A probe count alongside a declared verdict would imply a probe that
    never ran."""
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps([{
        "id": "a", "rung": "config", "summary": "s", "baseline_score": 0.1,
        "candidate_score": 0.2, "promoted_at": 1.0,
        "capability_evidence": "declared_bounded", "capability_probe_tools": 40,
    }]), encoding="utf-8")
    with pytest.raises(PromotionLedgerError):
        PromotionLedger(path=path)


def test_a_negative_probe_count_is_rejected(tmp_path):
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps([{
        "id": "a", "rung": "config", "summary": "s", "baseline_score": 0.1,
        "candidate_score": 0.2, "promoted_at": 1.0,
        "capability_evidence": "probed_bounded", "capability_probe_tools": -1,
    }]), encoding="utf-8")
    with pytest.raises(PromotionLedgerError):
        PromotionLedger(path=path)


def test_a_graded_receipt_round_trips_through_the_ledger(tmp_path):
    path = tmp_path / "ledger.json"
    ledger = PromotionLedger(path=path)
    ledger.add(PromotionRecord(
        id="a", rung="tool", summary="s", baseline_score=0.1,
        candidate_score=0.2, promoted_at=1.0,
        capability_evidence="probed_bounded", capability_probe_tools=40))
    loaded = PromotionLedger(path=path).get("a")
    assert loaded.capability_evidence == "probed_bounded"
    assert loaded.capability_probe_tools == 40


def test_marking_a_graded_receipt_rolled_back_preserves_its_grading(tmp_path):
    path = tmp_path / "ledger.json"
    ledger = PromotionLedger(path=path)
    ledger.add(PromotionRecord(
        id="a", rung="tool", summary="s", baseline_score=0.1,
        candidate_score=0.2, promoted_at=1.0,
        capability_evidence="probed_bounded", capability_probe_tools=7))
    assert ledger.mark_rolled_back("a", at=2.0)
    rec = PromotionLedger(path=path).get("a")
    assert rec.rolled_back is True
    assert rec.capability_evidence == "probed_bounded"
    assert rec.capability_probe_tools == 7
