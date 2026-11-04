"""Crash-only log: fsync'd appends, torn-tail recovery, seq resume, gaps.

Deterministic and offline: the clock is injected, "crashes" are simulated by
writing partial lines straight to the file, and fsync behavior is observed by
counting (not skipping) real ``os.fsync`` calls.
"""
from __future__ import annotations

import json
import os
import subprocess

import pytest
from maverick import crash_only_log as col
from maverick.file_lock import private_path_is_restricted


def _make_shared_directory(path):
    path.mkdir(mode=0o777)
    if os.name == "nt":
        subprocess.run(
            ["icacls", str(path), "/grant", "*S-1-1-0:(OI)(CI)RX"],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        path.chmod(0o755)
    assert not private_path_is_restricted(path, 0o700)


def _security_snapshot(path):
    if os.name == "nt":
        import maverick.file_lock as file_lock

        return file_lock._windows_private_sddl(path)[0]
    return path.stat().st_mode & 0o777


def _log(tmp_path, **kw):
    return col.CrashOnlyLog(tmp_path / "events.jsonl", clock=lambda: 123.0, **kw)


def test_append_replay_roundtrip(tmp_path):
    log = _log(tmp_path)
    assert log.append("start", goal="g1") == 1
    assert log.append("tool", name="shell", ok=True) == 2
    assert log.append("end") == 3

    result = col.replay(log.path)
    assert len(result) == 3 and not result.torn_tail and result.corrupt == 0
    recs = list(result)
    assert [r["seq"] for r in recs] == [1, 2, 3]
    assert recs[0] == {"seq": 1, "ts": 123.0, "kind": "start", "goal": "g1"}
    assert recs[1]["name"] == "shell" and recs[1]["ok"] is True


def test_reserved_keys_win_over_fields(tmp_path):
    log = _log(tmp_path)
    log.append("k", seq=999, ts=999, extra="kept")
    rec = col.replay(log.path).records[0]
    assert rec["seq"] == 1 and rec["ts"] == 123.0 and rec["extra"] == "kept"


def test_torn_tail_is_skipped_and_flagged(tmp_path):
    log = _log(tmp_path)
    log.append("a")
    log.append("b")
    with open(log.path, "ab") as fh:  # kill -9 mid-append: half a line, no newline
        fh.write(b'{"seq": 3, "ts": 1, "kind": "tor')

    result = col.replay(log.path)
    assert [r["kind"] for r in result] == ["a", "b"]
    assert result.torn_tail is True
    assert result.corrupt == 0  # a torn tail is the legal crash artifact


def test_complete_record_missing_only_newline_is_kept(tmp_path):
    log = _log(tmp_path)
    log.append("a")
    with open(log.path, "ab") as fh:  # crash exactly between payload and "\n"
        fh.write(json.dumps({"seq": 2, "ts": 1.0, "kind": "b"}).encode())

    result = col.replay(log.path)
    assert [r["kind"] for r in result] == ["a", "b"]
    assert result.torn_tail is False  # nothing was discarded


def test_seq_resumes_after_clean_reopen(tmp_path):
    log = _log(tmp_path)
    log.append("a")
    log.append("b")
    log.close()

    log2 = _log(tmp_path)
    assert log2.append("c") == 3
    assert [r["seq"] for r in col.replay(log2.path)] == [1, 2, 3]


def test_reopen_seals_torn_tail_and_resumes_from_last_intact(tmp_path):
    log = _log(tmp_path)
    log.append("a")
    log.append("b")
    log.close()
    with open(tmp_path / "events.jsonl", "ab") as fh:
        fh.write(b'{"seq": 3, "kind": "garbage half li')

    log2 = _log(tmp_path)              # open seals the torn line with a newline
    assert log2.append("c") == 3       # resumes after the last INTACT record

    result = col.replay(log2.path)
    assert [(r["seq"], r["kind"]) for r in result] == [(1, "a"), (2, "b"), (3, "c")]
    assert result.torn_tail is False
    assert result.corrupt == 1         # the sealed fragment is now mid-file damage
    assert col.verify(log2.path)["gaps"] == []


def test_verify_reports_gaps_and_seq_range(tmp_path):
    path = tmp_path / "events.jsonl"
    lines = [
        {"seq": 1, "ts": 1.0, "kind": "a"},
        {"seq": 2, "ts": 2.0, "kind": "b"},
        {"seq": 5, "ts": 5.0, "kind": "e"},   # 3 and 4 lost
    ]
    path.write_text("".join(json.dumps(r) + "\n" for r in lines))

    v = col.verify(path)
    assert v["records"] == 3
    assert v["first_seq"] == 1 and v["last_seq"] == 5
    assert v["gaps"] == [(2, 5)]
    assert v["torn_tail"] is False and v["corrupt"] == 0


def test_replay_missing_file_is_empty(tmp_path):
    result = col.replay(tmp_path / "never-written.jsonl")
    assert len(result) == 0 and not result.torn_tail and result.corrupt == 0


def test_log_file_created_0600(tmp_path):
    log = _log(tmp_path)
    log.append("a")
    assert private_path_is_restricted(log.path)
    assert private_path_is_restricted(log.path.parent, 0o700)


def test_log_refuses_shared_parent_without_mutating_it(tmp_path):
    shared = tmp_path / "shared"
    _make_shared_directory(shared)
    unrelated = shared / "team-file.txt"
    unrelated.write_text("keep-access", encoding="utf-8")
    before = _security_snapshot(shared)

    with pytest.raises(PermissionError, match="must already be private"):
        col.CrashOnlyLog(shared / "events.jsonl")

    assert _security_snapshot(shared) == before
    assert not private_path_is_restricted(shared, 0o700)
    assert unrelated.read_text(encoding="utf-8") == "keep-access"
    assert not (shared / "events.jsonl").exists()


def test_constructor_closes_append_fd_when_recovery_raises(tmp_path, monkeypatch):
    import maverick.file_lock as file_lock

    raw_path = tmp_path / "opened.jsonl"
    fd = os.open(str(raw_path), os.O_WRONLY | os.O_CREAT, 0o600)
    monkeypatch.setattr(file_lock, "open_private_append", lambda *a, **kw: fd)

    def _fail_recovery(self):
        raise RuntimeError("simulated recovery failure")

    monkeypatch.setattr(col.CrashOnlyLog, "_recover", _fail_recovery)
    with pytest.raises(RuntimeError, match="recovery failure"):
        col.CrashOnlyLog(tmp_path / "events.jsonl")
    with pytest.raises(OSError):
        os.fstat(fd)


def test_fsync_always_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_CRASH_ONLY_FSYNC", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    real_fsync = os.fsync
    calls: list[int] = []

    def counting_fsync(fd):
        calls.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", counting_fsync)
    log = _log(tmp_path)
    before = len(calls)
    log.append("a")
    log.append("b")
    assert len(calls) - before == 2  # exactly one fsync per record


def test_fsync_never_via_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_CRASH_ONLY_FSYNC", "never")
    calls: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    log = _log(tmp_path)
    before = len(calls)  # private file publication may durably fsync once
    log.append("a")
    log.append("b")
    assert len(calls) == before
    # Format/recovery are unchanged in throughput mode.
    assert [r["kind"] for r in col.replay(log.path)] == ["a", "b"]


def test_fsync_constructor_override_beats_policy(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_CRASH_ONLY_FSYNC", raising=False)
    calls: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    log = _log(tmp_path, fsync=False)
    before = len(calls)  # private file publication may durably fsync once
    log.append("a")
    assert len(calls) == before


def test_fsync_policy_env_wins_over_config(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[logging]\ncrash_only_fsync = "never"\n')
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.delenv("MAVERICK_CRASH_ONLY_FSYNC", raising=False)
    assert col.fsync_policy() == "never"          # config honored
    monkeypatch.setenv("MAVERICK_CRASH_ONLY_FSYNC", "always")
    assert col.fsync_policy() == "always"         # env wins
    monkeypatch.setenv("MAVERICK_CRASH_ONLY_FSYNC", "bogus")
    assert col.fsync_policy() == "never"          # unrecognized env -> config


def test_last_seq_property(tmp_path):
    log = _log(tmp_path)
    assert log.last_seq == 0
    log.append("a")
    assert log.last_seq == 1
