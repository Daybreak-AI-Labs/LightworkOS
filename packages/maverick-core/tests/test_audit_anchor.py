"""Cross-file tip-ledger: deleting/truncating a WHOLE day-file is detectable.

Each YYYY-MM-DD.ndjson is an independent Ed25519 hash-chain,
so per-file ``verify_chain`` can't notice that a whole day-file is *missing*.
``ensure_anchors`` records a signed, chained tip (hash + row count) per completed
day in ``anchors.ndjson``; ``verify_anchors`` confirms every anchored day still
matches. A GDPR erase appends a superseding anchor (no re-sign cascade).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from maverick.audit import signing  # noqa: E402
from maverick.audit.signing import (  # noqa: E402
    AuditSigner,
    ensure_anchors,
    reanchor_day_after_erase,
    verify_anchors,
)


def _isolate_keys(monkeypatch, tmp_path):
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")


def _past_day(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d")


def _write_signed_day(audit_dir, day, n=3):
    signer = AuditSigner(audit_dir / f"{day}.ndjson")
    for i in range(n):
        signer.write({"kind": "tool_call", "i": i})


def test_ensure_anchors_then_verify_clean(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path)
    _write_signed_day(tmp_path, _past_day(2), 3)
    _write_signed_day(tmp_path, _past_day(1), 2)
    assert ensure_anchors(tmp_path) == 2   # both completed days anchored
    assert ensure_anchors(tmp_path) == 0   # idempotent (doesn't re-anchor)
    assert verify_anchors(tmp_path) == []  # intact


def test_whole_file_deletion_is_detected(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path)
    d1 = _past_day(2)
    _write_signed_day(tmp_path, d1, 3)
    _write_signed_day(tmp_path, _past_day(1), 2)
    ensure_anchors(tmp_path)
    (tmp_path / f"{d1}.ndjson").unlink()   # attacker drops a whole day-file
    breaks = verify_anchors(tmp_path)
    assert any(b.reason == "anchored_file_deleted" for b in breaks)


def test_truncation_is_detected(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path)
    d = _past_day(1)
    _write_signed_day(tmp_path, d, 3)
    ensure_anchors(tmp_path)
    # Drop the last row -- a per-file-self-consistent truncation.
    p = tmp_path / f"{d}.ndjson"
    p.write_text("\n".join(p.read_text().splitlines()[:-1]) + "\n")
    reasons = {b.reason for b in verify_anchors(tmp_path)}
    assert "anchor_count_mismatch" in reasons or "anchor_tip_mismatch" in reasons


def test_todays_in_progress_file_is_not_anchored(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _write_signed_day(tmp_path, today, 2)
    assert ensure_anchors(tmp_path) == 0   # today is still growing -> not anchored
    assert verify_anchors(tmp_path) == []


def test_erase_appends_superseding_anchor(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path)
    d = _past_day(1)
    _write_signed_day(tmp_path, d, 3)
    ensure_anchors(tmp_path)

    # Simulate a GDPR erase: rewrite the day-file (fewer rows, new tip), re-sign
    # it, then run the hook erase.py now calls.
    p = tmp_path / f"{d}.ndjson"
    p.write_text("\n".join(p.read_text().splitlines()[:-1]) + "\n")
    signing.reanchor_file(p, force=True, preverified=True)

    # The stale anchor flags the change...
    assert verify_anchors(tmp_path)
    # ...and the superseding anchor restores a clean verify (the prior anchor
    # stays in the append-only ledger as an auditable record of the change).
    reanchor_day_after_erase(tmp_path, p)
    assert verify_anchors(tmp_path) == []


def test_missing_anchor_ledger_is_detected(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path)
    _write_signed_day(tmp_path, _past_day(1), 2)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _write_signed_day(tmp_path, today, 1)
    ensure_anchors(tmp_path)

    (tmp_path / signing.ANCHOR_FILENAME).unlink()

    breaks = verify_anchors(tmp_path)
    assert any(b.reason == "anchor_ledger_missing" for b in breaks)


def test_ensure_anchors_does_not_rebuild_deleted_anchor_ledger(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path)
    survivor = _past_day(1)
    _write_signed_day(tmp_path, _past_day(2), 2)
    _write_signed_day(tmp_path, survivor, 2)
    ensure_anchors(tmp_path)

    (tmp_path / f"{_past_day(2)}.ndjson").unlink()
    (tmp_path / signing.ANCHOR_FILENAME).unlink()

    assert ensure_anchors(tmp_path) == 0
    assert not (tmp_path / signing.ANCHOR_FILENAME).exists()
    breaks = verify_anchors(tmp_path)
    assert any(b.reason == "anchor_ledger_missing" for b in breaks)


def test_ledger_truncated_with_day_files_is_detected(tmp_path, monkeypatch):
    # Cutting anchors.ndjson back together with the newest day-file leaves a
    # self-consistent shorter ledger; the signed high-water record shows it.
    _isolate_keys(monkeypatch, tmp_path)
    older, newer = _past_day(2), _past_day(1)
    _write_signed_day(tmp_path, older, 2)
    ensure_anchors(tmp_path)
    ledger = tmp_path / signing.ANCHOR_FILENAME
    ledger_after_older = ledger.read_bytes()
    _write_signed_day(tmp_path, newer, 2)
    assert ensure_anchors(tmp_path) == 1
    assert verify_anchors(tmp_path) == []

    (tmp_path / f"{newer}.ndjson").unlink()
    ledger.write_bytes(ledger_after_older)
    assert {b.reason for b in verify_anchors(tmp_path)} == {"anchor_ledger_truncated"}
    ledger.write_bytes(b"")
    assert {b.reason for b in verify_anchors(tmp_path)} == {"anchor_ledger_truncated"}

    # A later honest anchor does not launder the cut, and removing the record
    # is itself reported.
    _write_signed_day(tmp_path, newer, 1)
    ensure_anchors(tmp_path)
    assert "anchor_ledger_truncated" in {b.reason for b in verify_anchors(tmp_path)}
    (tmp_path / signing.ANCHOR_HIGHWATER_FILENAME).unlink()
    assert "anchor_highwater_missing" in {b.reason for b in verify_anchors(tmp_path)}

    # An installation that predates the record still verifies until it is written.
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    _write_signed_day(legacy, older, 2)
    ensure_anchors(legacy)
    (legacy / signing.ANCHOR_HIGHWATER_FILENAME).unlink()
    (legacy / signing.ANCHOR_MARKER_FILENAME).write_text("anchors.ndjson is required\n")
    assert verify_anchors(legacy) == []


def test_unreadable_day_does_not_stop_later_days_being_anchored(tmp_path, monkeypatch):
    _isolate_keys(monkeypatch, tmp_path)
    bad, good = _past_day(2), _past_day(1)
    _write_signed_day(tmp_path, bad, 1)
    _write_signed_day(tmp_path, good, 1)
    real = signing._file_tip_and_count

    def _flaky(path):
        from maverick.audit.segments import SegmentReadError

        if path.stem == bad:
            raise SegmentReadError("cannot decrypt")
        return real(path)

    monkeypatch.setattr(signing, "_file_tip_and_count", _flaky)
    assert ensure_anchors(tmp_path) == 1
    assert signing._anchored_days(tmp_path) == {good}
