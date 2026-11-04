"""Audit-log erase and append lifecycle.

Covers four properties of the audit erase/write path:

  1. GDPR erase matches on STRUCTURED channel+user_id fields only -- it must
     match ``slack``+``42`` but never over-match ``slack:4200`` via a substring
     of a serialized value (and never under-match a ``slack/42`` encoding).
  2. A same-process erase-then-record verifies clean: erase resets the live
     signer's stale in-memory chain head so the next record() chains onto the
     re-anchored tail, not a hash no longer in the file.
  3. The unsigned write path fsyncs (durability parity with the signed path).
  4. Concurrent appends serialize under an advisory flock.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


def _have_crypto() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Task 1: structured erase match (no signing required)
# ---------------------------------------------------------------------------


def _write_plain(path, events):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def test_erase_matches_structured_user_not_substring(tmp_path):
    from maverick.audit.erase import delete_user

    ad = tmp_path / "audit"
    path = ad / "2026-01-01.ndjson"
    _write_plain(
        path,
        [
            {"v": 1, "ts": 1.0, "kind": "goal_start", "channel": "slack", "user_id": "42"},
            {"v": 1, "ts": 2.0, "kind": "goal_start", "channel": "slack", "user_id": "4200"},
        ],
    )

    deleted, _ = delete_user("slack", "42", audit_dir=ad)
    assert deleted == 1, "exact structured match only -- slack:4200 must survive"

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    assert rows[0]["user_id"] == "4200"


def test_erase_matches_structured_even_with_slashed_serialization(tmp_path):
    """A row whose serialized form would read ``slack/42`` (never ``slack:42``)
    must STILL match, because matching is on the structured fields."""
    from maverick.audit.erase import delete_user

    ad = tmp_path / "audit"
    path = ad / "2026-01-02.ndjson"
    _write_plain(
        path,
        [
            {"v": 1, "ts": 1.0, "kind": "tool_call", "channel": "slack", "user_id": "42",
             "input_summary": "posted to slack/42"},
        ],
    )

    deleted, _ = delete_user("slack", "42", audit_dir=ad)
    assert deleted == 1
    assert path.read_text(encoding="utf-8").strip() == ""


def test_erase_does_not_match_substring_only_rows(tmp_path):
    """A row that merely *mentions* ``slack:42`` in a free-text field but has no
    structured channel/user_id must NOT be erased (no substring fallback)."""
    from maverick.audit.erase import delete_user

    ad = tmp_path / "audit"
    path = ad / "2026-01-03.ndjson"
    _write_plain(
        path,
        [
            {"v": 1, "ts": 1.0, "kind": "tool_call", "input_summary": "ref slack:42 in a log line"},
        ],
    )

    deleted, _ = delete_user("slack", "42", audit_dir=ad)
    assert deleted == 0
    assert path.read_text(encoding="utf-8").strip() != ""


def test_erase_scrubs_capability_denial_with_structured_subject(tmp_path):
    """Capability-denial audit events may carry an identifying principal.

    They must also carry structured channel/user_id fields so user erasure can
    tombstone the row and remove that principal instead of leaving it in audit
    tail/search output.
    """
    from maverick.audit.erase import scrub_user

    ad = tmp_path / "audit"
    path = ad / "2026-01-04.ndjson"
    _write_plain(
        path,
        [
            {
                "v": 1,
                "ts": 1.0,
                "kind": "capability_denied",
                "tool": "shell",
                "principal": "user:sms:+15551234567",
                "channel": "sms",
                "user_id": "sms:+15551234567",
            },
        ],
    )

    matched, scanned = scrub_user("sms", "sms:+15551234567", audit_dir=ad)
    assert matched == 1
    assert scanned == 1
    row = json.loads(path.read_text(encoding="utf-8"))
    assert row["kind"] == "capability_denied"
    assert row["user_id"] == "[REDACTED]"
    assert "principal" not in row
    assert "+15551234567" not in json.dumps(row)


# ---------------------------------------------------------------------------
# Task 3: unsigned write path fsync
# ---------------------------------------------------------------------------


def test_unsigned_record_fsyncs(tmp_path, monkeypatch):
    from maverick.audit import writer as W
    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    monkeypatch.delenv("MAVERICK_AUDIT_SIGN", raising=False)
    fsynced: list[int] = []
    monkeypatch.setattr(W.os, "fsync", lambda fd: fsynced.append(fd))

    log = AuditLog(audit_dir=tmp_path, sign=False)
    assert log.record(AuditEvent(ts=1.0, kind="tool_call", agent="a", payload={}))
    assert fsynced, "unsigned audit write must fsync the row"


# ---------------------------------------------------------------------------
# Task 4: concurrent appends serialize under flock (POSIX)
# ---------------------------------------------------------------------------


def test_unsigned_record_acquires_flock(tmp_path, monkeypatch):
    """The unsigned append takes an exclusive advisory flock and releases it."""
    fcntl = pytest.importorskip("fcntl")
    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    calls: list[int] = []
    real_flock = fcntl.flock
    monkeypatch.setattr(
        fcntl, "flock", lambda fd, op: (calls.append(op), real_flock(fd, op))[1]
    )

    log = AuditLog(audit_dir=tmp_path, sign=False)
    assert log.record(AuditEvent(ts=1.0, kind="tool_call", agent="a", payload={}))
    assert fcntl.LOCK_EX in calls, "append must acquire an exclusive flock"
    assert fcntl.LOCK_UN in calls, "the flock must be released after the append"


def test_concurrent_unsigned_appends_do_not_interleave(tmp_path):
    """Two processes appending big rows to the same day-file must not interleave
    torn records: every line stays valid JSON and the count is exact."""
    ad = tmp_path / "audit"
    code = r"""
import sys
from pathlib import Path
from maverick.audit.events import AuditEvent
from maverick.audit.writer import AuditLog

audit_dir, tag, count = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
log = AuditLog(audit_dir=audit_dir, sign=False)
big = tag * 8000
for i in range(count):
    ok = log.record(AuditEvent(ts=float(i), kind="tool_call", agent=tag,
                               payload={"blob": big}))
    if not ok:
        raise SystemExit("audit append failed")
"""
    n = 30
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(ad), tag, str(n)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for tag in ("a", "b")
    ]
    for proc in procs:
        stdout, stderr = proc.communicate(timeout=60)
        assert proc.returncode == 0, (stdout, stderr)

    files = list(ad.glob("*.ndjson"))
    assert len(files) == 1
    lines = [ln for ln in files[0].read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 2 * n, f"expected {2 * n} rows, got {len(lines)}"
    for ln in lines:
        json.loads(ln)  # raises if any record was torn / interleaved


@pytest.mark.skipif(not _have_crypto(), reason="cryptography not installed")
def test_concurrent_signed_appends_keep_one_chain_on_windows_and_posix(
    tmp_path, monkeypatch,
):
    """Independent processes must serialize tail-read, sign, and append."""
    from maverick.audit import signing
    from maverick.audit.signing import verify_chain

    home = tmp_path / "home"
    audit_dir = home / "audit"
    key_dir = audit_dir / "keys"
    monkeypatch.setattr(signing, "KEY_DIR", key_dir)

    code = r"""
import sys
from pathlib import Path
from maverick.audit.events import AuditEvent
from maverick.audit.writer import AuditLog

audit_dir, tag, count = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
log = AuditLog(audit_dir=audit_dir, sign=True)
for i in range(count):
    ok = log.record(AuditEvent(ts=float(i), kind="tool_call", agent=tag,
                               payload={"sequence": i, "blob": tag * 2048}))
    if not ok:
        raise SystemExit("signed audit append failed")
"""
    env = os.environ.copy()
    env["MAVERICK_HOME"] = str(home)
    env.pop("MAVERICK_TENANT", None)
    env["MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY"] = "0"
    count = 20
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(audit_dir), tag, str(count)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for tag in ("a", "b", "c")
    ]
    for proc in procs:
        stdout, stderr = proc.communicate(timeout=90)
        assert proc.returncode == 0, (stdout, stderr)

    files = list(audit_dir.glob("20??-??-??.ndjson"))
    assert len(files) == 1
    rows = [json.loads(line) for line in files[0].read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 3 * count
    assert verify_chain(files[0]) == []


def test_append_lock_backend_failure_refuses_write_and_releases_stripe(
    tmp_path, monkeypatch,
):
    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    log = AuditLog(audit_dir=tmp_path / "audit", sign=False)
    event = AuditEvent(ts=1.0, kind="tool_call", agent="a", payload={})
    assert log.record(event)

    if os.name == "nt":
        import msvcrt

        real_lock = msvcrt.locking
        monkeypatch.setattr(
            msvcrt,
            "locking",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("lock denied")),
        )
    else:
        import fcntl

        real_lock = fcntl.flock
        monkeypatch.setattr(
            fcntl,
            "flock",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("lock denied")),
        )

    assert log.record(event) is False
    if os.name == "nt":
        monkeypatch.setattr(msvcrt, "locking", real_lock)
    else:
        monkeypatch.setattr(fcntl, "flock", real_lock)
    assert log.record(event), "failed __enter__ must not strand the local stripe"

    path = next((tmp_path / "audit").glob("*.ndjson"))
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


@pytest.mark.skipif(not _have_crypto(), reason="cryptography not installed")
def test_two_signed_writers_refresh_the_locked_chain_tail(_isolate_keys, tmp_path):
    """Two signer instances created at the same tip must not fork the chain.

    Construct both before either writes so both cache genesis. The second write
    must ignore that stale cache, read the first row while holding the append
    lock, and bind its ``prev_hash`` to the actual durable tip.
    """
    from maverick.audit.signing import AuditSigner, verify_chain

    path = tmp_path / "audit" / "2026-01-05.ndjson"
    path.parent.mkdir(parents=True)
    path.touch()
    first = AuditSigner(path)
    second = AuditSigner(path)

    # Make the first row larger than the signer's bounded reverse-read chunk so
    # the stale-tip regression also exercises a chain tip that spans chunks.
    assert first.write(
        {
            "v": 1,
            "kind": "goal_start",
            "agent": "first",
            "detail": "x" * (70 * 1024),
        }
    )
    assert second.write({"v": 1, "kind": "goal_end", "agent": "second"})

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert rows[1]["prev_hash"] == rows[0]["hash"]
    assert verify_chain(path) == []


# ---------------------------------------------------------------------------
# Task 2: same-process erase-then-record verifies clean
# ---------------------------------------------------------------------------


@pytest.fixture
def _isolate_keys(monkeypatch, tmp_path):
    from maverick.audit import signing

    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")


@pytest.mark.skipif(not _have_crypto(), reason="cryptography not installed")
def test_same_process_erase_then_record_verifies_clean(_isolate_keys, tmp_path):
    """erase resets the live signer so a later record() in the SAME process
    chains onto the re-anchored tail -- no explicit reanchor_after_erase()."""
    from maverick.audit.erase import scrub_user
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.signing import verify_chain
    from maverick.audit.writer import AuditLog

    ad = tmp_path / "audit"
    log = AuditLog(audit_dir=ad, sign=True)
    ts = 1000.0
    for ch, uid in [("slack", "alice"), ("slack", "bob"), ("slack", "alice")]:
        assert log.record(
            AuditEvent(ts=ts, kind=EventKind.GOAL_START,
                       payload={"channel": ch, "user_id": uid, "title": f"{uid} goal"})
        )
        ts += 1.0
    path = sorted(ad.glob("*.ndjson"))[0]
    assert verify_chain(path) == []

    matched, _ = scrub_user("slack", "alice", audit_dir=ad)
    assert matched == 2
    assert verify_chain(path) == []

    # No explicit reanchor_after_erase(): the erase already reset the live
    # signer, so this record() must extend the rewritten chain cleanly.
    assert log.record(
        AuditEvent(ts=2000.0, kind=EventKind.GOAL_END,
                   payload={"status": "succeeded", "result": None})
    )
    assert verify_chain(path) == [], "erase-then-record must not chain_mismatch"
