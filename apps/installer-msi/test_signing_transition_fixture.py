"""Acceptance-driver contracts; never execute MSI or change host trust here."""
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
spec = importlib.util.spec_from_file_location("signing_transition_fixture", DIRECTORY / "accept_signing_transition_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def policy():
    return fixture.make_policy(version="1.0.0", runtime_hash="a" * 64, old_native="b" * 64,
        new_native="c" * 64, old_publisher="A" * 40, new_publisher="B" * 40,
        public_key="synthetic public key only", installer_hash="d" * 64)


def report(value, envelope_hash="e" * 64, old_hash="f" * 64):
    return {"schema": "lightwork.publisher-transition-acceptance.v1", "phase": "complete",
        "reviewed_transition_sha256": envelope_hash, "old_publisher_thumbprint": value["from"]["publisher_thumbprint"],
        "new_publisher_thumbprint": value["to"]["publisher_thumbprint"], "base_installer_sha256": old_hash,
        "candidate_installer_sha256": value["new_installer_sha256"], "old_native_sha256": value["from"]["native_sha256"],
        "new_native_sha256": value["to"]["native_sha256"], "initial_native_version": value["from"]["version"],
        "upgraded_native_version": value["to"]["version"], "rolled_back_native_version": value["from"]["version"],
        "same_updater_key": True, "same_frozen_runtime_fixture": True, "synthetic_fixture_versions": True,
        "mid_msi_crash_tested": False, "publicly_recognized_publisher": False, "clean_virtual_machine": False,
        "cleanup_failures": 0, **dict.fromkeys((
            "actual_distinct_publisher_trust", "authenticated_administrator_api", "default_off_refusal",
            "tampered_policy_refused", "expired_admission_refused", "unrelated_publisher_rejected_before_execution",
            "pre_execution_process_resume", "protected_upgrade", "completed_upgrade_rollback",
            "exact_native_transition_and_return", "all_local_workspaces_restored", "runtime_bytes_unchanged"), "passed")}


@pytest.mark.parametrize("field", ["native_sha256", "publisher_thumbprint"])
def test_fixture_requires_actual_distinct_inputs(field):
    args = dict(version="1.0.0", runtime_hash="a" * 64, old_native="b" * 64, new_native="c" * 64,
                old_publisher="A" * 40, new_publisher="B" * 40, public_key="synthetic", installer_hash="d" * 64)
    args["new_native" if field == "native_sha256" else "new_publisher"] = args["old_native" if field == "native_sha256" else "old_publisher"]
    with pytest.raises(ValueError, match="distinct"):
        fixture.make_policy(**args)


def test_fixture_labels_publisher_only_rotation_and_unchanged_runtime_honestly():
    value = policy()
    assert value["from"]["version"] == "1.0.0" and value["to"]["version"] == "1.0.1"
    assert value["from"]["public_key"] == value["to"]["public_key"]
    assert value["from"]["runtime_sha256"] == value["to"]["runtime_sha256"]
    fixture.validate_report(report(value), value, "e" * 64, "f" * 64)


@pytest.mark.parametrize("damage", [
    {"new_publisher_thumbprint": "A" * 40}, {"old_native_sha256": "c" * 64},
    {"reviewed_transition_sha256": "0" * 64}, {"candidate_installer_sha256": "0" * 64},
    {"base_installer_sha256": "0" * 64}, {"upgraded_native_version": "1.0.0"},
    {"default_off_refusal": "not-run"}, {"unrelated_publisher_rejected_before_execution": "not-run"},
    {"pre_execution_process_resume": "not-run"}, {"completed_upgrade_rollback": "not-run"},
    {"actual_distinct_publisher_trust": "not-run"}, {"publicly_recognized_publisher": True},
    {"same_updater_key": "true"}, {"mid_msi_crash_tested": True}, {"acceptance_failed": True},
    {"cleanup_failures": 1}, {"cleanup_failures": False}, {"phase": "base-install"},
])
def test_zero_exit_alone_cannot_satisfy_native_transition_acceptance(damage):
    value = policy()
    with pytest.raises(RuntimeError, match="incomplete or bound"):
        fixture.validate_report({**report(value), **damage}, value, "e" * 64, "f" * 64)


def test_workstation_refused_before_input_reads_trust_or_install(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(RuntimeError, match="disposable GitHub-hosted"):
        fixture.accept(tmp_path, tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows hosted orchestration contract; no native execution")
@pytest.mark.parametrize("failure", ["base-payload", "next-payload", "payload-binding", "old-create", "new-trust", "bridge-to-signature", "transition-rollback", "new-cleanup", "deadline", None])
def test_failed_stages_preserve_error_and_try_both_exact_certificate_cleanups(tmp_path, monkeypatch, failure):
    from maverick import release_identity_transition as bridge
    workspace, runner = tmp_path / "workspace", tmp_path / "runner"
    (workspace / "customer-artifacts").mkdir(parents=True)
    runner.mkdir()
    originals = {workspace / "customer-artifacts/Lightwork.msi": b"original base",
                 runner / "upgrade-fixture.msi": b"original next",
                 runner / "transition-base-native.exe": b"native base",
                 runner / "transition-next-native.exe": b"native next"}
    for path, raw in originals.items():
        path.write_bytes(raw)
    (workspace / "customer-artifacts/runtime-inventory.json").write_text(json.dumps({"version": "1.0.0", "runtime": {"sha256": "a" * 64}}))
    key = runner / "synthetic.key"
    key.with_suffix(".key.pub").write_text("synthetic public key only")
    for name, value in {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows",
                       "GITHUB_JOB": "build-and-accept", "RUNNER_TEMP": str(runner), "GITHUB_WORKSPACE": str(workspace),
                       "ACCEPTANCE_PRIVATE_KEY": str(key)}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(fixture.shutil, "which", lambda _: "never-executed")
    clock = [1000.0]
    monkeypatch.setattr(fixture.time, "monotonic", lambda: clock[0])
    # This test verifies orchestration/cleanup; real cryptography has its own
    # actual-signer and fixture regressions, and the hosted driver does not mock it.
    monkeypatch.setattr(bridge, "verify", lambda envelope, **kwargs: envelope)
    stages, identities = [], {}

    def stage(command, name, directory, **kwargs):
        assert kwargs["timeout"] <= 2400
        stages.append(name)
        if name.endswith("-payload"):
            source = Path(command[command.index("--msi") + 1])
            payload = {"schema": "lightwork.msi-native-payload.v1", "msi_sha256": fixture.file_hash(source),
                       "native_sha256": ("b" if name == "base-payload" else "c") * 64}
            if failure == "payload-binding":
                payload["msi_sha256"] = "0" * 64
            Path(command[command.index("--report") + 1]).write_text(json.dumps(payload))
        if failure == "deadline" and name == "old-trust":
            clock[0] += 2300
        if name.endswith("-create"):
            publisher = Path(command[command.index("-FixtureDirectory") + 1])
            identities[name.split("-")[0]] = publisher
            (publisher / "publisher-thumbprint.txt").write_text(("A" if name.startswith("old") else "B") * 40)
        if name.endswith("-signature"):
            Path(command[-1] + ".sig").write_text("synthetic signature only")
        if name == "transition-rollback":
            envelope = json.loads((directory / "bridge.json").read_text())
            # The restored build-output decoys above must never enter policy.
            assert envelope["policy"]["from"]["native_sha256"] == "b" * 64
            assert envelope["policy"]["to"]["native_sha256"] == "c" * 64
            final = report(envelope["policy"], bridge.digest(envelope), fixture.file_hash(identities["old"] / "base.msi"))
            (workspace / "customer-artifacts/publisher-transition-acceptance.json").write_text(json.dumps(final))
        if name == failure or name == "new-cleanup" and failure not in (None, "new-cleanup", "old-create"):
            raise RuntimeError("synthetic " + name + " failure")

    monkeypatch.setattr(fixture, "run_stage", stage)
    if failure:
        expected = "work deadline" if failure == "deadline" else "bound to the exact input MSI" if failure == "payload-binding" else "synthetic " + failure + " failure"
        with pytest.raises(RuntimeError, match=expected):
            fixture.accept(workspace, runner)
    else:
        fixture.accept(workspace, runner)
    if "old" in identities:
        assert stages[-1] == "old-cleanup"
    else:
        assert not any(name.endswith(("-create", "-trust", "-cleanup")) for name in stages)
    if "new" in identities:
        assert stages[-2] == "new-cleanup"
    saved = json.loads(next(runner.glob("identity-transition-*/stages.json")).read_text())
    assert saved["acceptance_passed"] == (failure in (None, "new-cleanup"))
    assert saved["cleanup_passed"] == (failure in (None, "base-payload", "next-payload", "payload-binding", "old-create", "deadline"))
    for path, raw in originals.items():
        assert path.read_bytes() == raw


def powershell(tmp_path, source, **environment):
    executable = shutil.which("pwsh")
    if not executable:
        pytest.skip("PowerShell 7 is required for acceptance-driver contract execution")
    probe = tmp_path / "probe.ps1"
    probe.write_text("$ErrorActionPreference='Stop'\n" + source, encoding="utf-8")
    return subprocess.run([executable, "-NoProfile", "-NonInteractive", "-File", str(probe)],
        env={**os.environ, "TRANSITION_DRIVER": str(DIRECTORY / "test-completed-rollback.ps1"),
             "PROBE_ROOT": str(tmp_path), **environment}, capture_output=True, text=True, timeout=30, check=False)


@pytest.mark.parametrize("error_view", ["ConciseView", "NormalView"])
@pytest.mark.parametrize("rendering", ["PlainText", "Ansi"])
def test_transition_driver_parse_and_exact_host_guard_do_not_execute_native_work(tmp_path, error_view, rendering):
    result = powershell(tmp_path, """
    $ErrorView=$env:TEST_ERROR_VIEW
    $PSStyle.OutputRendering=$env:TEST_RENDERING
    $errors=$null
    [Management.Automation.Language.Parser]::ParseFile($env:TRANSITION_DRIVER,[ref]$null,[ref]$errors)|Out-Null
    if($errors.Count){throw ($errors|Out-String)}
    function Get-Item {throw 'UNEXPECTED FILE OR TRUST READ'}
    function Start-Process {throw 'UNEXPECTED NATIVE EXECUTION'}
    try {
        & $env:TRANSITION_DRIVER -BaseMsi unused -CandidateMsi unused -PublicKeyFile unused -Inventory unused -Report unused -TransitionDirectory $env:PROBE_ROOT
    } catch {
        # Compare the real exception, not host-width/ANSI-dependent ErrorView.
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
    """, CI="true", RUNNER_TEMP=str(tmp_path), GITHUB_ACTIONS="false", TEST_ERROR_VIEW=error_view, TEST_RENDERING=rendering)
    assert result.returncode == 1
    assert result.stderr.strip() == "Publisher transition acceptance requires the disposable GitHub-hosted acceptance job."
    assert "UNEXPECTED" not in result.stderr


@pytest.mark.parametrize("http_status,reason,accepted", [(409, "signatures did not verify", True),
    (401, "signatures did not verify", False), (500, "signatures did not verify", False), (409, "unrelated storage error", False)])
def test_negative_driver_checks_specific_real_http_reason_not_any_error(tmp_path, http_status, reason, accepted):
    (tmp_path / "bridge.json").write_text("{}")
    result = powershell(tmp_path, """
    $ast=[Management.Automation.Language.Parser]::ParseFile($env:TRANSITION_DRIVER,[ref]$null,[ref]$null)
    $method=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-TransitionReviewRefused'},$true)
    . ([scriptblock]::Create($method.Extent.Text))
    function Invoke-RestMethod($Uri,$Headers,$TimeoutSec,$Method,$ContentType,$Body,[switch]$SkipHttpErrorCheck,$StatusCodeVariable) {
        if($Uri.EndsWith('/status')) {return @{context='review-context';expected_tenant='fixture'}}
        if($Headers['X-Lightwork-Recovery-Context'] -ne 'review-context' -or $Headers['X-Lightwork-Expected-Tenant'] -ne 'fixture') {throw 'Unbound negative request'}
        Set-Variable -Name $StatusCodeVariable -Value ([int]$env:TEST_HTTP_STATUS) -Scope 1
        return @{detail=$env:TEST_REASON}
    }
    Assert-TransitionReviewRefused (Join-Path $env:PROBE_ROOT 'bridge.json') 'signatures did not verify'
    """, TEST_HTTP_STATUS=str(http_status), TEST_REASON=reason)
    assert (result.returncode == 0) is accepted, result.stderr


def test_staging_binds_helper_request_and_preserves_exact_reviewed_envelope(tmp_path):
    for name in ("base", "next"):
        (tmp_path / (name + ".msi")).write_bytes(("nonexecutable " + name).encode())
        (tmp_path / (name + ".msi.sig")).write_text(name + "-signature")
    envelope = {"policy": {"id": "fixture exact policy"}, "from_signature": "old", "to_signature": "same updater key"}
    (tmp_path / "bridge.json").write_text(json.dumps(envelope))
    result = powershell(tmp_path, """
    $ast=[Management.Automation.Language.Parser]::ParseFile($env:TRANSITION_DRIVER,[ref]$null,[ref]$null)
    $method=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Stage-Installers'},$true)
    . ([scriptblock]::Create($method.Extent.Text))
    $runtime='NEVER EXECUTE'; $expectedPublicKey='fixed key'; $metadata=@{version='1.0.0';runtime=@{sha256=('a'*64)}}; $newVersion='1.0.1'
    $BaseMsi=Join-Path $env:PROBE_ROOT 'base.msi';$CandidateMsi=Join-Path $env:PROBE_ROOT 'next.msi'
    function Protocol($binary,$step,$payload) {if($step -ne 'inspect' -or $payload.authorization -ne 'fixed grant'){throw 'Unexpected native operation'};return @{directory=$env:PROBE_ROOT}}
    function Start-Process {throw 'NO MSI OR NATIVE EXECUTION'}
    Stage-Installers @{authorization='fixed grant'} (Join-Path $env:PROBE_ROOT 'bridge.json')
    """)
    assert result.returncode == 0, result.stderr
    saved = json.loads((tmp_path / "downloads.json").read_text(encoding="utf-8-sig"))
    assert saved["identity_transition"] == envelope
    assert saved["old"]["signature"] == "base-signature" and saved["new"]["signature"] == "next-signature"
    assert (tmp_path / "old.msi").read_bytes() == (tmp_path / "base.msi").read_bytes()


@pytest.mark.parametrize("damage", ["none", "native", "key", "version"])
def test_installed_transition_identity_check_reads_actual_file_hash(tmp_path, damage):
    native = tmp_path / "maverick-desktop.exe"
    native.write_bytes(b"nonexecutable exact native fixture")
    expected_hash = fixture.file_hash(native)
    if damage == "native":
        native.write_bytes(b"changed native bytes")
    result = powershell(tmp_path, """
    $ast=[Management.Automation.Language.Parser]::ParseFile($env:TRANSITION_DRIVER,[ref]$null,[ref]$null)
    $method=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-InstalledChannel'},$true)
    . ([scriptblock]::Create($method.Extent.Text))
    $installPath=$env:PROBE_ROOT; $expectedPublicKey='fixture key'
    $transition=@{policy=@{from=@{version='1.0.0';native_sha256=('0'*64)};to=@{version='1.0.1';native_sha256=$env:EXPECTED_HASH}}}
    function Read-InstalledChannel {return @{version=$(if($env:DAMAGE -eq 'version'){'1.0.0'}else{'1.0.1'});public_key=$(if($env:DAMAGE -eq 'key'){'wrong key'}else{'fixture key'});packaged_runtime=$true}}
    function Start-Process {throw 'NO NATIVE EXECUTION'}
    Assert-InstalledChannel '1.0.1'
    """, DAMAGE=damage, EXPECTED_HASH=expected_hash)
    assert (result.returncode == 0) is (damage == "none"), result.stderr
