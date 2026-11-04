"""Execute bounded PowerShell contracts with no installer or native process."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

DRIVER = Path(__file__).with_name("test-release-pair.ps1")
PWSH = shutil.which("pwsh")


def powershell(tmp_path, source, **environment):
    if not PWSH:
        pytest.skip("PowerShell 7 is required for the Windows acceptance driver contract")
    probe = tmp_path / "probe.ps1"
    probe.write_text("$ErrorActionPreference='Stop'\n" + source, encoding="utf-8")
    return subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(probe)],
        env={
            **os.environ,
            "RELEASE_DRIVER": str(DRIVER),
            "PROBE_ROOT": str(tmp_path),
            **environment,
        },
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )


def test_release_driver_parses_without_executing_any_statement(tmp_path):
    result = powershell(
        tmp_path,
        """
    $parseErrors=$null
    [Management.Automation.Language.Parser]::ParseFile($env:RELEASE_DRIVER,[ref]$null,[ref]$parseErrors)|Out-Null
    if ($parseErrors.Count) {throw ($parseErrors|Out-String)}
    Write-Output 'parsed'
    """,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "parsed"


def test_driver_refuses_non_ci_host_before_machine_reads_or_any_install(tmp_path):
    result = powershell(
        tmp_path,
        """
    function Get-CimInstance { throw 'UNEXPECTED HOST READ' }
    function Start-Process { throw 'UNEXPECTED PROCESS START' }
    & $env:RELEASE_DRIVER -InputsDirectory $env:PROBE_ROOT -Report (Join-Path $env:PROBE_ROOT 'report.json')
    """,
        CI="false",
        LIGHTWORK_RELEASE_VM_CONFIRM="",
    )
    assert result.returncode != 0
    assert "Explicit disposable release-VM authorization is required" in result.stderr
    assert "UNEXPECTED" not in result.stderr
    assert not (tmp_path / "report.json").exists()


@pytest.mark.parametrize("damage", ["string_confirmation", "wrong_instance", "old_vm"])
def test_attestation_must_bind_fresh_exact_vm_with_real_boolean_consent(tmp_path, damage):
    result = powershell(
        tmp_path,
        """
        function Start-Process {throw 'UNEXPECTED INSTALL OR PROCESS'}
        function Get-CimInstance($ClassName) {
            if ($ClassName -eq 'Win32_ComputerSystem') {return @{Model='Virtual Machine'}}
            if ($ClassName -eq 'Win32_ComputerSystemProduct') {return @{UUID='SYNTHETIC-VM-UUID'}}
            return @{ProductType=1;BuildNumber=26100;OSArchitecture='64-bit';LastBootUpTime=[datetime]::Now}
        }
        $attestation=@{schema='lightwork.clean-windows-acceptance-host.v1';disposable=$true;clean_supported_windows=$true;image_name='Synthetic test image';image_sha256=('a'*64);instance_id='SYNTHETIC-VM-UUID';created_at=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')}
        if ($env:PROBE_DAMAGE -eq 'string_confirmation') {$attestation.disposable='true'}
        if ($env:PROBE_DAMAGE -eq 'wrong_instance') {$attestation.instance_id='ANOTHER-VM'}
        if ($env:PROBE_DAMAGE -eq 'old_vm') {$attestation.created_at=[datetime]::UtcNow.AddDays(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')}
        $env:LIGHTWORK_CLEAN_VM_ATTESTATION=$attestation|ConvertTo-Json -Compress
        & $env:RELEASE_DRIVER -InputsDirectory $env:PROBE_ROOT -Report (Join-Path $env:PROBE_ROOT 'report.json')
        """,
        CI="true",
        RUNNER_TEMP=str(tmp_path),
        PROBE_DAMAGE=damage,
        LIGHTWORK_RELEASE_VM_CONFIRM="DISPOSABLE_VM_INSTALL_REPAIR_UPGRADE_ROLLBACK",
    )
    assert result.returncode != 0
    assert "fresh disposable VM and exact owner-attested image/instance provenance" in result.stderr
    assert "UNEXPECTED" not in result.stderr
    assert not (tmp_path / "report.json").exists()


def test_upgrade_passes_distinct_original_versions_hashes_and_signatures(tmp_path):
    """Exercise the actual Upgrade function; process and HTTP boundaries are fakes."""
    for name in ("previous", "candidate"):
        (tmp_path / (name + ".msi")).write_bytes(b"NONEXECUTABLE ORIGINAL " + name.encode())
        (tmp_path / (name + ".msi.sig")).write_text(name + "-signature")
    result = powershell(
        tmp_path,
        """
    function Start-Process {throw 'NO PROCESS ALLOWED'}
    $ast=[Management.Automation.Language.Parser]::ParseFile($env:RELEASE_DRIVER,[ref]$null,[ref]$null)
    $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Upgrade'},$true)
    . ([scriptblock]::Create($function.Extent.Text))
    $pair=[pscustomobject]@{previous=@{version='0.1.7';runtime_sha256=('a'*64)};candidate=@{version='0.2.0';runtime_sha256=('b'*64)}}
    $packages=@{previous=(Join-Path $env:PROBE_ROOT 'previous.msi');candidate=(Join-Path $env:PROBE_ROOT 'candidate.msi')}
    $expectedPublicKey='synthetic-public-key'; $runtime='NONEXECUTABLE'
    $script:stopped=$false; $script:checked=$false
    function Start-App([bool]$recovery) {if (-not $recovery) {throw 'Upgrade must authorize in isolated recovery'}}
    function Authorization {return @{id='reviewed-id';authorization='reviewed-grant'}}
    function Stop-App {$script:stopped=$true}
    function Protocol($binary,$step,$payload) {
        if (-not $script:stopped -or $payload.authorization -ne 'reviewed-grant') {throw 'Unstopped or unbound transition'}
        if ($step -eq 'inspect') {return @{directory=$env:PROBE_ROOT}}
        if ($step -eq 'prepare') {return @{helper='RETAINED-HELPER'}}
        throw 'Unexpected protocol call'
    }
    function Execute-Retained($prepared,$grant) {if ($prepared.helper -ne 'RETAINED-HELPER' -or $grant.id -ne 'reviewed-id') {throw 'Wrong helper/grant'}; return @{status='upgraded'}}
    function Assert-Installed($identity) {if ($identity.version -ne '0.2.0' -or $identity.runtime_sha256 -ne ('b'*64)) {throw 'Wrong installed identity'}; $script:checked=$true}
    $grant=Upgrade
    if (-not $script:checked) {throw 'Installed identity never checked'}
    Get-Content -Raw -LiteralPath (Join-Path $env:PROBE_ROOT 'downloads.json')
    """,
    )
    assert result.returncode == 0, result.stderr
    downloads = json.loads(result.stdout)
    assert downloads["old"] == {
        "version": "0.1.7",
        "runtime_sha256": "a" * 64,
        "signature": "previous-signature",
    }
    assert downloads["new"] == {
        "version": "0.2.0",
        "runtime_sha256": "b" * 64,
        "signature": "candidate-signature",
    }
    assert (tmp_path / "old.msi").read_bytes() == (tmp_path / "previous.msi").read_bytes()
    assert (tmp_path / "new.msi").read_bytes() == (tmp_path / "candidate.msi").read_bytes()


@pytest.mark.parametrize("damage", ["none", "fact", "draft", "revision"])
def test_application_reader_state_check_refuses_missing_or_changed_data(tmp_path, damage):
    result = powershell(
        tmp_path,
        """
    $ast=[Management.Automation.Language.Parser]::ParseFile($env:RELEASE_DRIVER,[ref]$null,[ref]$null)
    $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-State'},$true)
    . ([scriptblock]::Create($function.Extent.Text))
    $script:origin='http://synthetic.invalid'; $script:slot='a'*64
    function Headers {return @{}}
    function Draft-Headers {return @{}}
    function Invoke-RestMethod($Uri,$Headers,$TimeoutSec) {
        if ($Uri.EndsWith('/facts')) {return @{'release-acceptance'=$(if ($env:PROBE_DAMAGE -eq 'fact') {'missing'} else {'original'})}}
        return @{payload=@{title=$(if ($env:PROBE_DAMAGE -eq 'draft') {'missing'} else {'Synthetic retained customer draft'})};revision=$(if ($env:PROBE_DAMAGE -eq 'revision') {2} else {1})}
    }
    Assert-State
    Write-Output 'preserved'
    """,
        PROBE_DAMAGE=damage,
    )
    if damage == "none":
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "preserved"
    else:
        assert result.returncode != 0
        assert "Actual application readers did not preserve" in result.stderr


def test_workflow_requires_manual_main_protected_vm_and_keeps_originals():
    import yaml

    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load(
        (root / ".github/workflows/windows-release-acceptance.yml").read_text()
    )
    jobs = workflow["jobs"]
    assert workflow["permissions"] == {"contents": "read", "actions": "read"}
    assert set(workflow.get("on", workflow.get(True))) == {"workflow_dispatch"}
    vm = jobs["install-repair-upgrade-rollback"]
    assert vm["environment"] == "windows-release-acceptance"
    assert vm["runs-on"] == ["self-hosted", "Windows", "X64", "lightwork-clean-release-acceptance"]
    assert "refs/heads/main" in vm["if"] and "inputs.confirm_disposable_vm" in vm["if"]
    assert not any("checkout@" in step.get("uses", "") for step in vm["steps"])
    upload = jobs["pin-original-inputs"]["steps"][-1]
    assert (
        upload["with"]["path"] == "release-pair-inputs/" and upload["with"]["retention-days"] == 90
    )
    input_step = next(
        step
        for step in jobs["pin-original-inputs"]["steps"]
        if "LIGHTWORK_RELEASE_ACCEPTANCE_PLAN" in step.get("env", {})
    )
    assert "${{ inputs.plan }}" not in input_step["run"]


@pytest.mark.parametrize("exit_code", [0, 7])
def test_binary_query_drains_both_real_pipes_and_checks_exit(tmp_path, exit_code):
    child = tmp_path / "child.py"
    child.write_text(
        "import json, sys\n"
        "sys.stderr.write('synthetic diagnostic ' * 16000)\n"
        "print(json.dumps({'version': '0.2.0', 'packaged_runtime': True}))\n"
        f"sys.exit({exit_code})\n"
    )
    result = powershell(
        tmp_path,
        """
        $ast=[Management.Automation.Language.Parser]::ParseFile($env:RELEASE_DRIVER,[ref]$null,[ref]$null)
        $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-Binary'},$true)
        . ([scriptblock]::Create($function.Extent.Text))
        Read-Binary $env:PROBE_PYTHON @((Join-Path $env:PROBE_ROOT 'child.py'))
        """,
        PROBE_PYTHON=sys.executable,
    )
    if exit_code:
        assert result.returncode != 0
        assert "Installed binary query failed" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"version": "0.2.0", "packaged_runtime": True}


def test_cleanup_report_failure_does_not_replace_primary_acceptance_failure(tmp_path):
    result = powershell(
        tmp_path,
        """
        $ast=[Management.Automation.Language.Parser]::ParseFile($env:RELEASE_DRIVER,[ref]$null,[ref]$null)
        $outer=$ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]}|Select-Object -Last 1
        $cleanup=[scriptblock]::Create(($outer.Finally.Statements|ForEach-Object {$_.Extent.Text}) -join "`n")
        function Start-Process {throw 'UNEXPECTED PROCESS START'}
        function Stop-App {}
        $observed=[ordered]@{release_pair_accepted=$false}
        $Report=$env:PROBE_ROOT # existing directory: both report writes really fail
        $originalPath=$env:PATH; $originalEnvironment=@{}
        try {throw 'PRIMARY_ACCEPTANCE_FAILURE'} catch {$acceptanceError=$_; throw} finally {. $cleanup}
        """,
    )
    assert result.returncode != 0
    assert "PRIMARY_ACCEPTANCE_FAILURE" in result.stderr
    assert "original acceptance error is retained" in result.stdout
    assert "UNEXPECTED PROCESS" not in result.stderr
