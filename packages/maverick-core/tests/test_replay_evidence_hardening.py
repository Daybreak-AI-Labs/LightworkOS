"""Adversarial replay evidence, video, and trace regressions."""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick.file_lock import (
    atomic_write_text,
    ensure_private_directory,
    private_path_is_restricted,
)
from maverick.paths import data_dir, tenant_scope
from maverick.replay import export as replay_export
from maverick.replay import trace as replay_trace
from maverick.replay import video as replay_video


def _write_rows(root: Path, rows: list[dict], *, day: str = "2026-01-01") -> Path:
    ensure_private_directory(root)
    path = root / f"{day}.ndjson"
    atomic_write_text(
        path,
        "".join(json.dumps(row) + "\n" for row in rows),
        mode=0o600,
    )
    return path


def test_export_resolves_audit_root_for_each_tenant_call(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))

    with tenant_scope(tenant="tenant-a"):
        _write_rows(
            data_dir("audit"),
            [{"goal_id": 7, "kind": "note", "value": "tenant-a"}],
        )
    with tenant_scope(tenant="tenant-b"):
        _write_rows(
            data_dir("audit"),
            [{"goal_id": 7, "kind": "note", "value": "tenant-b"}],
        )

    with tenant_scope(tenant="tenant-a"):
        out_a = tmp_path / "out-a.json"
        assert replay_export.export_json(7, out_a) == 1
        payload_a = json.loads(out_a.read_text(encoding="utf-8"))
    with tenant_scope(tenant="tenant-b"):
        out_b = tmp_path / "out-b.json"
        assert replay_export.export_json(7, out_b) == 1
        payload_b = json.loads(out_b.read_text(encoding="utf-8"))

    assert payload_a["events"][0]["value"] == "tenant-a"
    assert payload_b["events"][0]["value"] == "tenant-b"
    assert payload_a["proof"]["status"] == "unsigned"
    assert private_path_is_restricted(out_a)
    assert private_path_is_restricted(out_b)


def test_export_rejects_malformed_middle_without_replacing_output(tmp_path, monkeypatch):
    audit = ensure_private_directory(tmp_path / "audit")
    path = audit / "2026-01-01.ndjson"
    atomic_write_text(
        path,
        '{"goal_id":7,"kind":"start"}\nnot-json\n'
        '{"goal_id":7,"kind":"end"}\n',
    )
    monkeypatch.setattr(replay_export, "_AUDIT_DIR", audit)
    out = tmp_path / "replay.json"
    atomic_write_text(out, "existing-private-output")

    with pytest.raises(replay_export.ReplayEvidenceError, match="malformed row"):
        replay_export.export_json(7, out)

    assert out.read_text(encoding="utf-8") == "existing-private-output"


def test_export_rejects_forged_proof_fields(tmp_path, monkeypatch):
    audit = tmp_path / "audit"
    _write_rows(
        audit,
        [{
            "goal_id": 7,
            "kind": "forged",
            "prev_hash": "",
            "hash": "0" * 64,
            "sig": "0" * 128,
            "key_id": "0" * 16,
        }],
    )
    monkeypatch.setattr(replay_export, "_AUDIT_DIR", audit)

    with pytest.raises(replay_export.ReplayEvidenceError, match="day-chain"):
        replay_export.export_json(7, tmp_path / "forged.json")


def test_export_verifies_signed_day_and_cross_day_anchor_then_detects_tamper(
    tmp_path, monkeypatch
):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    from maverick.audit.signing import AuditSigner, ensure_anchors

    with tenant_scope(tenant="signed-tenant"):
        audit = data_dir("audit")
        day_file = audit / "2026-07-16.ndjson"
        assert AuditSigner(day_file).write(
            {"goal_id": 9, "kind": "goal_end", "status": "succeeded"}
        )
        assert ensure_anchors(audit) == 1
        out = tmp_path / "verified.json"
        assert replay_export.export_json(9, out) == 1
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["proof"]["status"] == "verified"
        assert payload["proof"]["anchors"] == "verified"

        original_row = json.loads(day_file.read_text(encoding="utf-8"))
        stripped = {
            key: value
            for key, value in original_row.items()
            if key not in {"prev_hash", "hash", "sig", "key_id"}
        }
        atomic_write_text(day_file, json.dumps(stripped) + "\n")
        with pytest.raises(replay_export.ReplayEvidenceError, match="trust material"):
            replay_export.export_json(9, out)

        row = dict(original_row)
        row["status"] = "tampered"
        atomic_write_text(day_file, json.dumps(row) + "\n")
        atomic_write_text(out, "verified-output-must-survive")
        with pytest.raises(replay_export.ReplayEvidenceError, match="day-chain"):
            replay_export.export_json(9, out)
        assert out.read_text(encoding="utf-8") == "verified-output-must-survive"


def test_export_replaces_symlink_itself_never_referent(tmp_path, monkeypatch):
    audit = tmp_path / "audit"
    _write_rows(audit, [{"goal_id": 1, "kind": "note"}])
    monkeypatch.setattr(replay_export, "_AUDIT_DIR", audit)
    referent = tmp_path / "referent.txt"
    referent.write_text("do-not-touch", encoding="utf-8")
    out = tmp_path / "replay.json"
    try:
        out.symlink_to(referent)
    except OSError:
        pytest.skip("symlink creation is not available")

    replay_export.export_json(1, out)

    assert referent.read_text(encoding="utf-8") == "do-not-touch"
    assert not out.is_symlink()
    assert private_path_is_restricted(out)


@pytest.mark.parametrize("fps", [0, 121, True, 1.5])
def test_video_rejects_invalid_fps(tmp_path, fps):
    with pytest.raises(ValueError, match="fps"):
        replay_video.render(1, tmp_path / "r.mp4", events=[], fps=fps)


def test_video_manifest_uses_only_generated_relative_names(tmp_path):
    frames = replay_video.storyboard(
        1,
        events=[{"kind": "step", "content": "safe"}],
    )
    injected = tmp_path / "frames'\nfile C:/sensitive"
    manifest = replay_video._ffmpeg_concat(frames, injected)

    assert str(injected) not in manifest
    assert "file frame_00000.png" in manifest
    assert "-safe" in replay_video.ffmpeg_command(tmp_path / "x", tmp_path / "y")
    command = replay_video.ffmpeg_command(tmp_path / "x", tmp_path / "y")
    assert command[command.index("-safe") + 1] == "1"


def test_video_bounds_frames_and_event_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(replay_video, "MAX_VIDEO_FRAMES", 2)
    with pytest.raises(ValueError, match="frame limit"):
        replay_video.storyboard(
            1,
            events=[{"kind": "x"}, {"kind": "x"}, {"kind": "x"}],
        )
    monkeypatch.setattr(replay_video, "MAX_VIDEO_EVENT_BYTES", 32)
    with pytest.raises(ValueError, match="byte limit"):
        replay_video.render(
            1,
            tmp_path / "bounded.mp4",
            events=[{"kind": "x", "content": "z" * 100}],
        )


def test_video_scrubs_sandbox_exception_and_cleans_staging(tmp_path, monkeypatch):
    if __import__("importlib").util.find_spec("PIL") is None:
        pytest.skip("Pillow not installed")
    import maverick.tools as tools_mod

    def fail_sandbox(*_args, **_kwargs):
        raise RuntimeError("sensitive host detail")

    monkeypatch.setattr(tools_mod, "sandbox_run", fail_sandbox)
    result = replay_video.render(
        1,
        tmp_path / "failed.mp4",
        events=[{"kind": "step", "content": "safe"}],
    )

    assert not result.encoded
    assert "sensitive host detail" not in result.detail
    assert "cleaned" in result.detail
    assert not result.frame_dir.exists()
    assert not result.concat_path.exists()
    assert not list(tmp_path.glob(".replay-video-*"))


def test_video_can_explicitly_retain_private_failure_staging(tmp_path, monkeypatch):
    if __import__("importlib").util.find_spec("PIL") is None:
        pytest.skip("Pillow not installed")
    import maverick.tools as tools_mod

    monkeypatch.setattr(
        tools_mod,
        "sandbox_run",
        lambda *_args, **_kwargs: (1, "", "sensitive host detail"),
    )
    result = replay_video.render(
        1,
        tmp_path / "failed.mp4",
        events=[{"kind": "step", "content": "safe"}],
        retain_staging=True,
    )

    assert not result.encoded
    assert "retained by request" in result.detail
    assert "sensitive host detail" not in result.detail
    assert private_path_is_restricted(result.frame_dir, 0o700)
    assert private_path_is_restricted(result.concat_path)


def test_video_same_output_is_serialized_and_staging_is_cleaned(tmp_path, monkeypatch):
    if __import__("importlib").util.find_spec("PIL") is None:
        pytest.skip("Pillow not installed")
    import maverick.tools as tools_mod

    def fake_sandbox(_sandbox, argv, **_kwargs):
        time.sleep(0.03)
        Path(argv[-1]).write_bytes(b"fake-mp4")
        return 0, "", ""

    monkeypatch.setattr(tools_mod, "sandbox_run", fake_sandbox)
    output = tmp_path / "shared.mp4"
    events = [{"kind": "step", "content": "safe"}]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: replay_video.render(1, output, events=events), range(2)))

    assert all(result.encoded for result in results)
    assert output.read_bytes() == b"fake-mp4"
    assert private_path_is_restricted(output)
    assert not list(tmp_path.glob(".replay-video-*"))


def test_trace_reopen_continues_sequence_and_chain(tmp_path):
    path = tmp_path / "traces" / "run.jsonl"
    with replay_trace.TraceWriter(path, writer_id="writer-a", run_id="run-a") as first:
        assert first.record("one") == 1
    with replay_trace.TraceWriter(path, writer_id="writer-b") as second:
        assert second.run_id == "run-a"
        assert second.record("two") == 2

    events = replay_trace.read_trace(path)
    assert [event["seq"] for event in events] == [1, 2]
    assert [event["writer_id"] for event in events] == ["writer-a", "writer-b"]
    assert events[1]["prev_hash"] == events[0]["hash"]

    with pytest.raises(replay_trace.TraceCorruptionError, match="run_id"):
        replay_trace.TraceWriter(path, run_id="different-run")


def test_trace_concurrent_first_append_rejects_mismatched_run_ids(tmp_path):
    path = tmp_path / "traces" / "run.jsonl"
    first = replay_trace.TraceWriter(path, writer_id="writer-a", run_id="run-a")
    second = replay_trace.TraceWriter(path, writer_id="writer-b", run_id="run-b")

    def append(writer):
        try:
            return writer.record("first")
        except replay_trace.TraceCorruptionError as exc:
            return exc

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(append, (first, second)))
    finally:
        first.close()
        second.close()

    assert sum(isinstance(result, int) for result in results) == 1
    failures = [result for result in results if isinstance(result, Exception)]
    assert len(failures) == 1
    assert "run_id" in str(failures[0])
    events = replay_trace.read_trace(path)
    assert len(events) == 1
    assert events[0]["run_id"] in {"run-a", "run-b"}


def test_trace_validation_rejects_rehashed_mixed_run_ids(tmp_path):
    path = tmp_path / "traces" / "run.jsonl"
    with replay_trace.TraceWriter(path, run_id="run-a") as writer:
        writer.record("one")
        writer.record("two")
    records = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    records[1]["run_id"] = "run-b"
    records[1]["hash"] = replay_trace._record_hash(records[1])
    atomic_write_text(
        path,
        "".join(json.dumps(record) + "\n" for record in records),
    )

    with pytest.raises(replay_trace.TraceCorruptionError, match="run_id"):
        replay_trace.read_trace(path)


def test_trace_tamper_and_malformed_middle_fail_closed(tmp_path):
    path = tmp_path / "traces" / "run.jsonl"
    with replay_trace.TraceWriter(path) as writer:
        writer.record("one")
        writer.record("two")
    lines = path.read_text(encoding="utf-8").splitlines()

    forged = json.loads(lines[0])
    forged["kind"] = "forged"
    atomic_write_text(path, json.dumps(forged) + "\n" + lines[1] + "\n")
    with pytest.raises(replay_trace.TraceCorruptionError, match="hash"):
        replay_trace.read_trace(path)

    atomic_write_text(path, lines[0] + "\nnot-json\n" + lines[1] + "\n")
    with pytest.raises(replay_trace.TraceCorruptionError, match="malformed"):
        replay_trace.read_trace(path)


def test_trace_wholesale_integrity_field_stripping_is_not_a_legacy_downgrade(tmp_path):
    path = tmp_path / "traces" / "run.jsonl"
    with replay_trace.TraceWriter(path) as writer:
        writer.record("one", value="original")
    row = json.loads(path.read_text(encoding="utf-8"))
    legacy = {
        "seq": row["seq"],
        "t": row["t"],
        "kind": "forged",
        "value": "changed",
    }
    atomic_write_text(path, json.dumps(legacy) + "\n")

    with pytest.raises(replay_trace.TraceCorruptionError, match="no per-record"):
        replay_trace.read_trace(path)
    assert replay_trace.read_trace(path, allow_legacy=True)[0]["kind"] == "forged"


def test_trace_final_partial_is_ignored_then_recovered_on_append(tmp_path):
    path = tmp_path / "traces" / "run.jsonl"
    with replay_trace.TraceWriter(path) as writer:
        writer.record("one")
        writer.record("two")
    with path.open("ab") as stream:
        stream.write(b'{"seq":3,"kind":"partial"')

    assert [event["seq"] for event in replay_trace.read_trace(path)] == [1, 2]
    with replay_trace.TraceWriter(path) as writer:
        assert writer.record("three") == 3
    assert [event["kind"] for event in replay_trace.read_trace(path)] == [
        "one",
        "two",
        "three",
    ]


def test_trace_enforces_record_and_file_bounds(tmp_path, monkeypatch):
    path = tmp_path / "traces" / "run.jsonl"
    with replay_trace.TraceWriter(path) as writer:
        writer.record("small")
        monkeypatch.setattr(replay_trace, "MAX_TRACE_RECORD_BYTES", 128)
        with pytest.raises(replay_trace.TraceLimitError, match="record"):
            writer.record("large", content="x" * 1_000)

    monkeypatch.setattr(replay_trace, "MAX_TRACE_FILE_BYTES", 10)
    with pytest.raises(replay_trace.TraceLimitError, match="file"):
        replay_trace.read_trace(path)


def test_trace_concurrent_process_writers_have_one_monotonic_chain(tmp_path):
    trace_dir = ensure_private_directory(tmp_path / "traces")
    path = trace_dir / "run.jsonl"
    barrier = tmp_path / "start"
    script = textwrap.dedent(
        """
        import sys
        import time
        from pathlib import Path
        from maverick.replay.trace import TraceWriter

        path, barrier, worker = sys.argv[1:]
        deadline = time.monotonic() + 15
        while not Path(barrier).exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("barrier")
            time.sleep(0.01)
        with TraceWriter(path, writer_id=f"writer-{worker}", run_id="shared-run") as trace:
            for index in range(4):
                trace.record("step", worker=worker, index=index)
        """
    )
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(path), str(barrier), str(index)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(3)
    ]
    barrier.touch()
    for worker in workers:
        stdout, stderr = worker.communicate(timeout=45)
        assert worker.returncode == 0, (stdout, stderr)

    events = replay_trace.read_trace(path)
    assert len(events) == 12
    assert [event["seq"] for event in events] == list(range(1, 13))
    assert {event["writer_id"] for event in events} == {
        "writer-0",
        "writer-1",
        "writer-2",
    }


def test_trace_refuses_alias_without_touching_referent(tmp_path):
    trace_dir = ensure_private_directory(tmp_path / "traces")
    referent = tmp_path / "referent.jsonl"
    referent.write_text("unchanged", encoding="utf-8")
    alias = trace_dir / "run.jsonl"
    try:
        alias.symlink_to(referent)
    except OSError:
        pytest.skip("symlink creation is not available")

    with pytest.raises(PermissionError, match="not a regular file"):
        replay_trace.TraceWriter(alias)
    assert referent.read_text(encoding="utf-8") == "unchanged"
