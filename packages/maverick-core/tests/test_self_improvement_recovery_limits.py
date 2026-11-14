"""Regression coverage for bounded learning history and crash recovery."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from maverick import file_lock, self_learning, self_modify_archive, verifier_head
from maverick import self_improvement as si


@pytest.fixture
def windows_default_newlines(monkeypatch):
    """Exercise real text translation without changing the host OS or locks."""
    write = file_lock.atomic_write_text

    def windows_write(path, text, **kwargs):
        kwargs.setdefault("newline", "\r\n")
        return write(path, text, **kwargs)

    monkeypatch.setattr(file_lock, "atomic_write_text", windows_write)
    monkeypatch.setattr(self_learning, "atomic_write_text", windows_write)


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
@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"])
def test_promotion_tail_recovery_preserves_verified_history(
    tmp_path, monkeypatch, damage, line_ending, windows_default_newlines,
):
    path = tmp_path / "promotions.json"
    ledger = si.PromotionLedger(path=path)
    ledger.add(si.PromotionRecord(
        id="retained", rung="config", summary="first", baseline_score=0.1,
        candidate_score=0.5, promoted_at=1.0,
    ))
    journal = Path(f"{path}.journal")
    prefix = journal.read_bytes().replace(b"\n", line_ending)
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
        assert audited[-1]["after_sha256"] == hashlib.sha256(prefix).hexdigest()
        damaged = journal.read_bytes() + b'{"event":"promote"'
        journal.write_bytes(damaged)
        recovered = si.PromotionLedger(path=path)
        assert recovered.get("retained").summary == "first"
        assert journal.read_bytes() == prefix
        assert len(audited) == 2
        assert audited[-1]["after_sha256"] == hashlib.sha256(prefix).hexdigest()
        recovered.mark_rolled_back("retained", at=2.0)
        assert si.PromotionLedger(path=path).get("retained").rolled_back


@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"])
def test_learned_ledger_keeps_newest_rows_and_accepts_new_records(
    tmp_path, monkeypatch, line_ending, windows_default_newlines,
):
    path = tmp_path / "learned.ndjson"
    monkeypatch.setattr(self_learning.time, "time", lambda: 1_700_000_000.0)
    for i in range(5):
        assert self_learning.record("need", "tool", f"tool-{i}", path=path)
        assert b"\r\r\n" not in path.read_bytes()
    original = line_ending.join(path.read_bytes().splitlines()) + line_ending
    path.write_bytes(original)
    row_size = len(original.splitlines()[0]) + 1
    monkeypatch.setattr(self_learning, "_MAX_LEARNED_LEDGER_BYTES",
                        row_size * 2 + 2 * (len(line_ending) - 1))
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
    # One retained CRLF row plus a new LF row fits this exact physical budget.
    monkeypatch.setattr(self_learning, "_MAX_LEARNED_LEDGER_BYTES", row_size * 2 + 1)
    assert self_learning.record("need", "tool", "tool-5", path=path)
    assert path.stat().st_size <= self_learning._MAX_LEARNED_LEDGER_BYTES
    assert [row.name for row in self_learning.history(path=path)] == ["tool-5", "tool-4"]
    assert path.read_bytes().startswith(original.splitlines(keepends=True)[-1])
    assert all(json.loads(row)["content_version"] == 1 for row in path.read_text().splitlines())
    assert self_learning.record("need", "tool", "tool-6", path=path)
    assert path.stat().st_size <= self_learning._MAX_LEARNED_LEDGER_BYTES
    assert b"\r\r\n" not in path.read_bytes()
    assert [row.name for row in self_learning.history(path=path)] == ["tool-6", "tool-5"]


@pytest.mark.parametrize("count", [0, 1])
def test_verifier_refuses_training_without_a_held_out_example(count):
    example = {"features": [0.0] * 12, "promise": 1.0, "progress": 0.0}
    with pytest.raises(ValueError):
        verifier_head.train_and_evaluate([example] * count)
