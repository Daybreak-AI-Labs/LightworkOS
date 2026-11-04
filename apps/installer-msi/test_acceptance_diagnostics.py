"""Failure uploads retain useful fixture evidence without collecting private state."""
from __future__ import annotations

import importlib.util
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE = Path(__file__).with_name("collect_acceptance_diagnostics.py")
spec = importlib.util.spec_from_file_location("acceptance_diagnostics", MODULE)
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


def test_collect_keeps_failed_msi_and_recovery_evidence_but_excludes_keys_and_state(tmp_path):
    runner = tmp_path / "runner"
    artifacts = tmp_path / "artifacts"
    output = tmp_path / "output"
    recovery = runner / "lw-rollback-fixture"
    recovery.mkdir(parents=True)
    artifacts.mkdir()
    (runner / "lightwork-msi-fixture.log").write_text("Error 1324: invalid folder\nAction ended: InstallFiles. Return value 3.\n", encoding="utf-16")
    (recovery / "recovery-error.log").write_text("RuntimeError: fixture startup failed\nAuthorization: Bearer confidential fixture\ntoken=secret fixture value\n" + "a" * 64)
    (recovery / "state.json").write_text("PRIVATE WORKSPACE CONTENT")
    (runner / "acceptance-updater.key").write_text("PRIVATE SIGNING KEY")
    (artifacts / "acceptance.json").write_text('{"install":"passed","repair":"failed"}')
    (artifacts / "Lightwork.msi").write_bytes(b"PRIVATE BINARY")
    publisher = runner / "rollback-signed-fixture"
    publisher.mkdir()
    (publisher / "trust.log").write_text("Trust operation started but did not complete")
    (publisher / "stages.json").write_text('{"phase":"trust","acceptance_passed":false}')
    (publisher / "fixture.cer").write_bytes(b"PRIVATE CERTIFICATE")
    (publisher / "publisher-thumbprint.txt").write_text("PRIVATE IDENTITY")
    report = diagnostics.collect(runner, artifacts, output)
    assert len(report["files"]) == 5
    combined = "\n".join(path.read_text() for path in output.iterdir())
    assert "Error 1324" in combined and "fixture startup failed" in combined
    assert '"repair":"failed"' in combined
    assert "Trust operation started but did not complete" in combined and '"phase":"trust"' in combined
    for excluded in ("PRIVATE", "confidential fixture", "secret fixture value", "a" * 64):
        assert excluded not in combined


def test_collect_bounds_log_tails_and_scrubs_embedded_credentials(tmp_path, monkeypatch):
    runner = tmp_path / "runner"
    runner.mkdir()
    (runner / "lightwork-msi-long.log").write_text("old output\n" * 100 + "recent failure")
    monkeypatch.setattr(diagnostics, "MAX_BYTES", 64)
    output = tmp_path / "output"
    report = diagnostics.collect(runner, tmp_path / "missing", output)
    assert report["files"][0]["truncated"] is True
    assert (output / report["files"][0]["file"]).read_text().endswith("recent failure")
    assert diagnostics.scrub("https://example.test/file?signature=private&key=private") == "https://example.test/file?[REDACTED]"
    assert "private" not in diagnostics.scrub("-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----")  # pragma: allowlist secret - synthetic redaction fixture


def test_native_captures_are_exact_allowlisted_and_bounded(tmp_path, monkeypatch):
    runner = tmp_path / "runner"
    native = runner / "native-webview-fixture"
    native.mkdir(parents=True)
    header = b"\x89PNG\r\n\x1a\n"
    (native / "first-owner.png").write_bytes(header + b"fixture capture")
    (native / "normal-support.png").write_bytes(header + b"reviewed bundle")
    (native / "signed-native-upgrade.png").write_bytes(header + b"x" * 100)
    (native / "signed-native-rollback.png").write_bytes(b"not a PNG")
    (native / "private-grant.png").write_bytes(header + b"PRIVATE")
    (native / "tls.key").write_bytes(b"PRIVATE")
    monkeypatch.setattr(diagnostics, "MAX_IMAGE_BYTES", 32)
    output = tmp_path / "output"
    report = diagnostics.collect(runner, tmp_path / "missing", output)
    assert len(report["images"]) == 2
    assert report["images"][0]["source"] == "native-webview-fixture/first-owner.png"
    assert (output / report["images"][0]["file"]).read_bytes() == header + b"fixture capture"
    assert report["images"][1]["source"] == "native-webview-fixture/normal-support.png"
    assert report["maximum_images"] == 5
    assert sorted(path.suffix for path in output.iterdir()) == [".json", ".png", ".png"]


def test_transition_reports_survive_log_volume_without_collecting_signing_inputs(tmp_path, monkeypatch):
    runner = tmp_path / "runner"
    transition = runner / "identity-transition-fixture"
    transition.mkdir(parents=True)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "publisher-transition-acceptance.json").write_text('{"phase":"complete"}')
    (transition / "stages.json").write_text('{"phase":"transition-rollback"}')
    (transition / "transition-rollback.log").write_text("Retained real transition failure")
    (transition / "bridge.json").write_text("PRIVATE POLICY")
    (transition / "bridge-policy.json.sig").write_text("PRIVATE SIGNATURE")
    (transition / "fixture.key").write_text("PRIVATE KEY")
    for index in range(10):
        (runner / f"lightwork-msi-{index:02d}.log").write_text("old MSI output")
    monkeypatch.setattr(diagnostics, "MAX_FILES", 3)
    output = tmp_path / "output"
    report = diagnostics.collect(runner, artifacts, output)
    assert len(report["files"]) == 3
    assert [row["source"] for row in report["files"]] == [
        "publisher-transition-acceptance.json", "identity-transition-fixture/stages.json",
        "identity-transition-fixture/transition-rollback.log",
    ]
    combined = "\n".join(path.read_text() for path in output.iterdir())
    assert "Retained real transition failure" in combined
    assert "PRIVATE" not in combined


def test_native_maintenance_logs_survive_file_cap_after_reports(tmp_path):
    runner = tmp_path / "runner"
    native = runner / "native-webview-fixture"
    point = native / "state/backups/installation-recovery/fixture-point"
    point.mkdir(parents=True)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "acceptance.json").write_text('{"phase":"complete"}')
    (native / "acceptance.json").write_text('{"failed_phase":"signed-native-rollback"}')
    expected = []
    for name in ("i-new.log", "x-new.log", "i-old.log"):
        log = point / name
        log.write_text("Native maintenance MSI failure: " + name)
        expected.append(log.relative_to(runner).as_posix())
    for name in ("record.json", "before.tgz", "old.msi", "operator.key"):
        (point / name).write_text("PRIVATE RETAINED INPUT")
    for index in range(40):
        (runner / f"lightwork-msi-{index:02d}.log").write_text("Earlier installer output")
    output = tmp_path / "output"
    report = diagnostics.collect(runner, artifacts, output)
    sources = [row["source"] for row in report["files"]]
    assert len(sources) == report["maximum_files"] == 32
    assert report["maximum_bytes_per_file"] == 1024 * 1024
    assert report["maximum_images"] == 5
    assert report["maximum_image_bytes"] == 4 * 1024 * 1024
    assert sources[:2] == ["acceptance.json", "native-webview-fixture/acceptance.json"]
    assert set(sources[2:5]) == set(expected)
    combined = "\n".join(path.read_text() for path in output.iterdir())
    assert "Native maintenance MSI failure" in combined
    assert "PRIVATE" not in combined


def test_native_maintenance_log_retains_only_bounded_scrubbed_tail(tmp_path, monkeypatch):
    runner = tmp_path / "runner"
    point = runner / "native-webview-fixture/state/backups/installation-recovery/fixture-point"
    point.mkdir(parents=True)
    (point / "i-new.log").write_text("old output\n" * 100 + "authorization: private fixture\nrecent failure")
    monkeypatch.setattr(diagnostics, "MAX_BYTES", 64)
    monkeypatch.setattr(diagnostics, "MAX_FILES", 1)
    output = tmp_path / "output"
    report = diagnostics.collect(runner, tmp_path / "missing", output)
    assert len(report["files"]) == 1
    assert report["files"][0]["truncated"] is True
    retained = (output / report["files"][0]["file"]).read_text()
    assert retained.endswith("recent failure")
    assert "private fixture" not in retained
    assert "[REDACTED]" in retained


@pytest.mark.parametrize("linked", ["file", "directory"])
def test_native_maintenance_symlink_targets_are_not_collected(tmp_path, linked):
    runner = tmp_path / "runner"
    parent = runner / "native-webview-fixture/state/backups/installation-recovery"
    parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "i-new.log").write_text("PRIVATE OUTSIDE CONTENT")
    try:
        if linked == "directory":
            (parent / "fixture-point").symlink_to(outside, target_is_directory=True)
        else:
            point = parent / "fixture-point"
            point.mkdir()
            (point / "i-new.log").symlink_to(outside / "i-new.log")
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("This Windows account cannot create symlinks.")
        raise
    output = tmp_path / "output"
    report = diagnostics.collect(runner, tmp_path / "missing", output)
    assert report["files"] == []
    assert list(output.iterdir()) == [output / "manifest.json"]


@pytest.mark.parametrize("marked", ["file", "directory"])
def test_native_maintenance_reparse_files_and_ancestors_are_refused(tmp_path, monkeypatch, marked):
    runner = tmp_path / "runner"
    point = runner / "native-webview-fixture/state/backups/installation-recovery/fixture-point"
    point.mkdir(parents=True)
    log = point / "i-new.log"
    log.write_text("PRIVATE REPARSE CONTENT")
    flagged = log if marked == "file" else point
    original = Path.lstat

    def lstat(path, *args, **kwargs):
        details = original(path, *args, **kwargs)
        if path == flagged:
            return SimpleNamespace(st_mode=stat.S_IFREG if marked == "file" else stat.S_IFDIR,
                                   st_file_attributes=0x400)
        return details

    monkeypatch.setattr(Path, "lstat", lstat)
    output = tmp_path / "output"
    report = diagnostics.collect(runner, tmp_path / "missing", output)
    assert report["files"] == []
    assert list(output.iterdir()) == [output / "manifest.json"]


def test_native_dashboard_stacks_survive_file_cap_after_reports(tmp_path):
    runner = tmp_path / "runner"
    native = runner / "native-webview-fixture"
    native.mkdir(parents=True)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (native / "acceptance.json").write_text('{"failed_phase":"first-launch-and-named-owner"}')
    (native / "dashboard-stacks.txt").write_text("process 0\nthread MainThread (idle)\n  app.py:1350:_lifespan\n")
    (native / "state").mkdir()
    (native / "state/private.txt").write_text("PRIVATE STATE")
    for index in range(40):
        (runner / f"lightwork-msi-{index:02d}.log").write_text("Earlier installer output")
    report = diagnostics.collect(runner, tmp_path / "artifacts", tmp_path / "output")
    sources = [row["source"] for row in report["files"]]
    assert len(sources) == 32
    assert sources[:2] == ["native-webview-fixture/acceptance.json", "native-webview-fixture/dashboard-stacks.txt"]
    combined = "\n".join(path.read_text() for path in (tmp_path / "output").iterdir())
    assert "app.py:1350:_lifespan" in combined and "PRIVATE" not in combined
