"""Regression coverage for bounded learning history and crash recovery."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from maverick import self_improvement as si
from maverick import self_learning, self_modify_archive, verifier_head


def test_diverse_preserves_greedy_order_without_retokenizing(monkeypatch):
    candidates = [
        self_modify_archive.CodeCandidate(
            summary=f"candidate {i}", patch=patch, score=float(i % 3),
        )
        for i, patch in enumerate(
            ["+same tokens", "+same tokens", "", "+unrelated"]
            + [f"+group_{i % 4} value_{i}" for i in range(20)]
        )
    ]
    archive = self_modify_archive.CodeArchive(candidates=candidates)
    expected = [max(candidates, key=lambda c: c.score)]
    pool = [c for c in candidates if c.id != expected[0].id]
    while pool:
        nxt = max(pool, key=lambda c: (
            min(archive.patch_distance(c, other) for other in expected), c.score,
        ))
        expected.append(nxt)
        pool.remove(nxt)
    tokenize = self_modify_archive._added_line_tokens
    calls = []

    def counted(patch):
        calls.append(patch)
        return tokenize(patch)

    monkeypatch.setattr(self_modify_archive, "_added_line_tokens", counted)
    actual = archive.diverse(len(candidates))
    assert all(a is b for a, b in zip(actual, expected, strict=True))
    assert len(calls) <= len(candidates)


@pytest.mark.parametrize("damage", [
    "partial", "partial_utf8", "missing_newline", "corrupt_prefix",
    "corrupt_complete_tail", "audit_failure", "only_partial",
])
def test_promotion_tail_recovery_preserves_verified_history(tmp_path, monkeypatch, damage):
    path = tmp_path / "promotions.json"
    ledger = si.PromotionLedger(path=path)
    ledger.add(si.PromotionRecord(
        id="retained", rung="config", summary="first", baseline_score=0.1,
        candidate_score=0.5, promoted_at=1.0,
    ))
    journal = Path(f"{path}.journal")
    prefix = journal.read_bytes()
    damaged = prefix + b'{"event":"promote"'
    if damage == "partial_utf8":
        damaged += b',"summary":"\xe2\x82'
    elif damage == "missing_newline":
        damaged = prefix[:-1]
    elif damage == "corrupt_prefix":
        damaged = damaged.replace(b'"first"', b'"forged"')
    elif damage == "corrupt_complete_tail":
        damaged = prefix + b'{"event":"promote"}'
    elif damage == "only_partial":
        damaged = b'{"event":"promote"'
    journal.write_bytes(damaged)
    audited = []

    def audit(**payload):
        assert journal.read_bytes() == damaged
        audited.append(payload)
        return damage != "audit_failure"

    monkeypatch.setattr(si, "_default_audit_fn", audit)
    # The evolution auditor also calls this parser without a lock; its default
    # read must fail closed rather than repairing evidence as a side effect.
    with pytest.raises(si.PromotionLedgerError):
        ledger._read_journal_state_locked()
    assert journal.read_bytes() == damaged
    assert not audited
    if damage in {"corrupt_prefix", "corrupt_complete_tail", "audit_failure", "only_partial"}:
        with pytest.raises(si.PromotionLedgerError):
            si.PromotionLedger(path=path)
        assert journal.read_bytes() == damaged
        assert bool(audited) == (damage == "audit_failure")
    else:
        recovered = si.PromotionLedger(path=path)
        assert recovered.get("retained").summary == "first"
        assert journal.read_bytes() == prefix
        assert len(audited) == 1
        recovered.mark_rolled_back("retained", at=2.0)
        assert si.PromotionLedger(path=path).get("retained").rolled_back


def test_learned_ledger_keeps_newest_rows_and_accepts_new_records(tmp_path, monkeypatch):
    path = tmp_path / "learned.ndjson"
    monkeypatch.setattr(self_learning.time, "time", lambda: 1_700_000_000.0)
    for i in range(5):
        assert self_learning.record("need", "tool", f"tool-{i}", path=path)
    original = path.read_bytes()
    row_size = len(original.splitlines(keepends=True)[0])
    monkeypatch.setattr(self_learning, "_MAX_LEARNED_LEDGER_BYTES", row_size * 2 + 10)
    assert [row.name for row in self_learning.history(path=path)] == ["tool-4", "tool-3"]
    assert path.read_bytes() == original  # reads do not rewrite history
    from maverick.killswitch import Halted

    def halt(_job, phase):
        if phase == "record_persistence":
            raise Halted("stop", "test")

    monkeypatch.setattr(self_learning, "check_learning_halt", halt)
    with pytest.raises(Halted):
        self_learning.record("need", "tool", "tool-5", path=path)
    assert path.read_bytes() == original
    monkeypatch.setattr(self_learning, "check_learning_halt", lambda *args: None)
    assert self_learning.record("need", "tool", "tool-5", path=path)
    assert path.stat().st_size <= self_learning._MAX_LEARNED_LEDGER_BYTES
    assert [row.name for row in self_learning.history(path=path)] == ["tool-5", "tool-4"]
    assert all(json.loads(row)["content_version"] == 1 for row in path.read_text().splitlines())


@pytest.mark.parametrize("count", [0, 1])
def test_verifier_refuses_training_without_a_held_out_example(count):
    example = {"features": [0.0] * 12, "promise": 1.0, "progress": 0.0}
    with pytest.raises(ValueError):
        verifier_head.train_and_evaluate([example] * count)
