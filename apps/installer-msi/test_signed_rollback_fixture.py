from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

DIRECTORY = Path(__file__).parent
sys.path.insert(0, str(DIRECTORY))
spec = importlib.util.spec_from_file_location("rollback_fixture_test_target", DIRECTORY / "accept_signed_rollback_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def test_real_child_timeout_is_bounded_and_preserves_its_last_stage(tmp_path):
    with pytest.raises(RuntimeError, match="exceeded"):
        fixture.run_stage([sys.executable, "-u", "-c", "import time; print('before synthetic stall'); time.sleep(30)"],
                          "synthetic-stall", tmp_path, timeout=1, cwd=tmp_path)
    assert "before synthetic stall" in (tmp_path / "synthetic-stall.log").read_text()


def test_failed_native_exit_cannot_be_reported_as_acceptance(tmp_path, capsys):
    with pytest.raises(RuntimeError, match="exit code 17"):
        fixture.run_stage([sys.executable, "-c", "print('token=synthetic-private-value'); raise SystemExit(17)"],
                          "synthetic-failure", tmp_path, timeout=10, cwd=tmp_path)
    assert "synthetic-private-value" not in capsys.readouterr().out


@pytest.mark.skipif(os.name != "nt", reason="Hosted Windows fixture orchestration")
@pytest.mark.parametrize("failure", ["create", "trust", "sign-base", "sign-next", "native-webview", "completed-rollback", "cleanup", None])
def test_each_stage_failure_keeps_original_error_and_attempts_exact_cleanup(tmp_path, monkeypatch, failure):
    workspace = tmp_path / "workspace"
    runner = tmp_path / "runner"
    (workspace / "customer-artifacts").mkdir(parents=True)
    runner.mkdir()
    (workspace / "customer-artifacts/Lightwork.msi").write_bytes(b"synthetic base")
    (runner / "upgrade-fixture.msi").write_bytes(b"synthetic candidate")
    for key, value in {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows",
                       "GITHUB_JOB": "build-and-accept", "RUNNER_TEMP": str(runner),
                       "ACCEPTANCE_PRIVATE_KEY": str(runner / "synthetic.key")}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(fixture.shutil, "which", lambda _: "never-executed-pwsh")
    stages = []

    def run(command, name, directory, **kwargs):
        stages.append(name)
        assert kwargs["timeout"] <= 2400
        if name == "create":
            (directory / "publisher-thumbprint.txt").write_text("synthetic identity only")
        if name == failure or (name == "cleanup" and failure not in (None, "cleanup")):
            raise RuntimeError("synthetic " + name + " failure")

    monkeypatch.setattr(fixture, "run_stage", run)
    if failure:
        with pytest.raises(RuntimeError, match="synthetic " + failure + " failure"):
            fixture.accept(workspace, runner)
    else:
        fixture.accept(workspace, runner)
    assert stages[-1] == "cleanup"
    record = json.loads(next(runner.glob("rollback-signed-*/stages.json")).read_text())
    assert record["acceptance_passed"] == (failure in (None, "cleanup"))
    assert record["cleanup_passed"] == (failure is None)
    if failure not in (None, "cleanup"):
        assert record["failed_phase"] == failure
    assert (workspace / "customer-artifacts/Lightwork.msi").read_bytes() == b"synthetic base"


def test_workstation_never_reaches_a_trust_or_installer_operation(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(RuntimeError, match="disposable GitHub-hosted"):
        fixture.accept(tmp_path, tmp_path)
    assert list(tmp_path.iterdir()) == []
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if powershell:
        forbidden = tmp_path / "forbidden-fixture"
        completed = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-File",
            str(DIRECTORY / "fixture-publisher.ps1"), "-Phase", "create", "-FixtureDirectory", str(forbidden)],
            capture_output=True, text=True, timeout=15, check=False)
        assert completed.returncode != 0
        assert "disposable GitHub-hosted acceptance job" in completed.stderr
        # PowerShell may create its own AppData cache under the isolated HOME.
        assert not forbidden.exists()
