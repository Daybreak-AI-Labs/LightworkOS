"""Portable acceptance exercises real source/target processes and app readers."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "acceptance" / "workspace_application_recovery.py"


def test_fresh_application_recovery_and_known_later_write_loss_in_real_processes(tmp_path):
    output = tmp_path / "application-recovery.json"
    completed = subprocess.run([sys.executable, str(SCRIPT), "--output", str(output)],
                               capture_output=True, timeout=90)
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert completed.stderr == b""
    evidence = json.loads(completed.stdout)
    assert evidence == json.loads(output.read_text())
    assert evidence["temporary_state_cleaned_before_publication"] is True
    assert evidence["signed_snapshot_application_binding_verified"] is True
    assert evidence["source_and_retained_custody_unchanged_during_targets"] is True
    source = evidence["source"]
    assert source["original_synthetic_primary_absent"] is True
    assert source["pre_snapshot_acknowledged_writes"] == source["post_snapshot_acknowledged_writes"] == 3
    assert evidence["observed_post_snapshot_acknowledgement_window_seconds"] >= 0
    reports = {row["variant"]: row for row in evidence["reports"]}
    assert set(reports) == {"complete", "missing-custody", "wrong-primary"}
    processes = {source["source_pid"], *(row["signed_report"]["target_pid"] for row in reports.values())}
    assert len(processes) == 4 and os.getpid() not in processes
    complete = reports["complete"]["signed_report"]
    assert complete["outcome"] == "verified_fixture_application_reads"
    assert complete["application_identity"] == source["application_identity"]
    assert complete["archive_sha256"] == source["archive_sha256"]
    assert complete["custody_sha256"] == source["custody_sha256"]
    assert complete["known_pre_snapshot_writes_restored"] == complete["known_post_snapshot_writes_not_restored"] == 3
    assert len(complete["application_checks"]) == 7 and all(complete["application_checks"].values())
    assert 0 < complete["first_successful_application_reads_seconds"] < 90
    for variant, report in reports.items():
        assert report["signature_verified"] is True
        result = report["signed_report"]
        assert result["coverage_complete"] is False and result["external_stores_tested"] is False
        assert result["live_workspace_changed"] is False
        assert result["application_reads_started"] == (variant == "complete")
        if variant != "complete":
            assert result["outcome"] == "failed"
    rendered = completed.stdout.decode()
    assert "Synthetic accepted-before-snapshot" not in rendered
    assert "Synthetic accepted-after-snapshot" not in rendered
    assert "BEGIN PRIVATE KEY" not in rendered  # pragma: allowlist secret


def test_cleanup_refusal_preserves_previous_output_and_emits_no_success(tmp_path, monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location("workspace_application_acceptance", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "previous.json"
    previous = '{"prior":"evidence"}\n'
    output.write_text(previous)
    @contextmanager
    def cleanup_refusal():
        yield tmp_path
        raise PermissionError("synthetic private cleanup refusal")
    monkeypatch.setattr(module, "_temporary_workspace", cleanup_refusal)
    monkeypatch.setattr(module, "_run_fixture", lambda _: {"outcome": "verified"})
    previous_logging_level = module.logging.root.manager.disable
    try:
        assert module.main(["--output", str(output)]) == 1
    finally:
        module.logging.disable(previous_logging_level)
    captured = capsys.readouterr()
    assert captured.out == "" and "could not complete safely" in captured.err
    assert "synthetic private" not in captured.err and str(tmp_path) not in captured.err
    assert output.read_text() == previous
