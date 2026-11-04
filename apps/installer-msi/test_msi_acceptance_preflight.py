"""Read-only MSI preflight; native installer process launch is always replaced."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent
PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(os.name != "nt" or not PWSH, reason="Windows PowerShell MSI metadata probe")


@pytest.fixture
def package(tmp_path):
    # Inert MSI Property table only: this tests real COM inspection, not a
    # runnable installer, native app, publisher signature or installation.
    import msilib
    from msilib import schema

    path = tmp_path / "Lightwork metadata fixture.msi"
    database = msilib.OpenDatabase(str(path), msilib.MSIDBOPEN_CREATE)
    schema.Property.create(database)
    msilib.add_data(database, "Property", [
        ("ProductName", "Lightwork Desktop"),
        ("ProductVersion", "0.1.7"),
        ("UpgradeCode", "{AB5BC260-7EC9-4B70-AF78-28F4067BC530}"),
    ])
    database.Commit()
    del database
    return path


@pytest.fixture
def inventory(tmp_path):
    value = {
        "schema": "lightwork.windows-customer-build.v1", "version": "0.1.7", "cohort_version": "0.1.7",
        "complete_release_cohort": True, "acceptance_fixture": False, "publisher_signature_verified": False,
        "requires_customer_python": False, "requires_customer_git": False,
        "packages": [{"distribution": name} for name in ("maverick-agent", "maverick-shield", "maverick-channels",
            "maverick-evolve", "maverick-dashboard", "maverick-mcp-server", "maverick-knowledge", "maverick-installer")],
        "runtime": {"sha256": "a" * 64, "bytes": 1234},
        "installed_recovery": {
            "runtime": "maverick-recovery.exe",
            "native_shell": "maverick-recovery-desktop.exe",
            "signed_installer": "Lightwork-recovery.msi",
            "start_menu": "Repair Lightwork",
        },
    }
    path = tmp_path / "runtime-inventory.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def probe(tmp_path, source):
    path = tmp_path / "probe.ps1"
    path.write_text("$ErrorActionPreference='Stop'\n" + source, encoding="utf-8")
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(path)],
        env=dict(os.environ, PREFLIGHT_SOURCE=str(ROOT), PREFLIGHT_ROOT=str(tmp_path), POWERSHELL_TELEMETRY_OPTOUT="1"),
        cwd=tmp_path, capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)


IMPORT = r"""
$helper=Join-Path $env:PREFLIGHT_SOURCE 'msi-acceptance-preflight.ps1'
if (Test-Path -LiteralPath $helper) {. $helper}
$tree=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:PREFLIGHT_SOURCE 'SCRIPT'),[ref]$null,[ref]$null)
$function=$tree.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Msi'},$true)
. ([scriptblock]::Create($function.Extent.Text))
$script:called=0
function Start-Process {
    param($FilePath,$ArgumentList,[switch]$PassThru,$WindowStyle)
    $script:called++
    $process=[pscustomobject]@{ExitCode=0}
    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {param($timeout) return $true}
    return $process
}
$env:RUNNER_TEMP=$env:PREFLIGHT_ROOT
$installPath=Join-Path $env:PREFLIGHT_ROOT 'never-installed'
$package=Join-Path $env:PREFLIGHT_ROOT 'Lightwork metadata fixture.msi'
$packageExpectations=@{}
$packageExpectations[$package]=@{version='0.1.7';sha256='HASH'}
"""


@pytest.mark.parametrize("script", ["test-customer.ps1", "test-completed-rollback.ps1"])
@pytest.mark.parametrize("damage", ["empty", "invalid", "unreadable", "changed_bytes", "wrong_version"])
def test_actual_invocation_refuses_unusable_or_changed_package_before_process(tmp_path, package, script, damage):
    expected = hashlib.sha256(package.read_bytes()).hexdigest()
    if damage == "empty":
        package.write_bytes(b"")
    elif damage == "invalid":
        package.write_bytes(b"Not an MSI")
        expected = hashlib.sha256(package.read_bytes()).hexdigest()
    elif damage == "changed_bytes":
        package.write_bytes(package.read_bytes() + b"changed after admission")
    lock = "$held=[IO.File]::Open($package,'Open','ReadWrite','None')" if damage == "unreadable" else "$held=$null"
    version = "$packageExpectations[$package].version='0.1.8'" if damage == "wrong_version" else ""
    result = probe(tmp_path, IMPORT.replace("SCRIPT", script).replace("HASH", expected) + lock + "\n" + version + r"""
$message=''
try {Invoke-Msi $package '/i' | Out-Null} catch {$message=$_.Exception.Message} finally {if ($held) {$held.Dispose()}}
if ($script:called -ne 0) {throw 'Unusable package reached Windows Installer process launch'}
if (-not $message.Contains($package)) {throw ('Missing resolved diagnostic path: '+$message)}
Write-Output 'rejected before installer'
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "rejected before installer" in result.stdout


def test_real_readonly_metadata_and_bytes_bind_every_maintenance_action(tmp_path, package):
    expected = hashlib.sha256(package.read_bytes()).hexdigest()
    result = probe(tmp_path, IMPORT.replace("SCRIPT", "test-customer.ps1").replace("HASH", expected) + r"""
$input=Resolve-AcceptanceMsi './Lightwork metadata fixture.msi' '0.1.7'
foreach ($action in @('/i','/fa','/x')) {Invoke-Msi './Lightwork metadata fixture.msi' $action | Out-Null}
if ($script:called -ne 3) {throw 'Expected exactly the three mocked maintenance launches'}
$input | ConvertTo-Json -Compress
""")
    assert result.returncode == 0, result.stdout + result.stderr
    inspected = json.loads(result.stdout)
    assert inspected["sha256"] == expected
    assert inspected["bytes"] == package.stat().st_size
    assert inspected["path"] == str(package)
    assert inspected["version"] == "0.1.7"
    assert hashlib.sha256(package.read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("property_name,value", [
    ("ProductName", "Other Product"), ("UpgradeCode", "{00000000-0000-0000-0000-000000000000}"),
    ("ProductVersion", "0.1.8"),
])
def test_real_metadata_rejects_other_product_or_version(tmp_path, package, property_name, value):
    import msilib

    database = msilib.OpenDatabase(str(package), msilib.MSIDBOPEN_TRANSACT)
    view = database.OpenView(f"UPDATE `Property` SET `Value` = '{value}' WHERE `Property` = '{property_name}'")
    view.Execute(None)
    view.Close()
    database.Commit()
    del view, database
    result = probe(tmp_path, r"""
. (Join-Path $env:PREFLIGHT_SOURCE 'msi-acceptance-preflight.ps1')
$package=Join-Path $env:PREFLIGHT_ROOT 'Lightwork metadata fixture.msi'
$message=''
try {Resolve-AcceptanceMsi $package '0.1.7' | Out-Null} catch {$message=$_.Exception.Message}
if (-not $message.Contains($package) -or -not $message.Contains('PROPERTY')) {throw ('Missing property/path diagnostic: '+$message)}
""".replace("PROPERTY", property_name))
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("script", ["test-customer.ps1", "test-completed-rollback.ps1"])
@pytest.mark.parametrize("damage", ["missing", "empty", "invalid", "directory", "unreadable", "candidate"])
def test_full_entrypoint_preflight_retains_diagnostic_without_fixture_or_process(tmp_path, package, inventory, script, damage):
    if damage == "missing":
        package.unlink()
    elif damage == "empty":
        package.write_bytes(b"")
    elif damage == "invalid":
        package.write_bytes(b"Not an MSI")
    elif damage == "directory":
        package.unlink()
        package.mkdir()
    lock = "$held=[IO.File]::Open($package,'Open','ReadWrite','None')" if damage == "unreadable" else "$held=$null"
    source = r"""
$env:CI='true';$env:RUNNER_TEMP=$env:PREFLIGHT_ROOT
function Start-Process {throw 'UNEXPECTED PROCESS START'}
$package=Join-Path $env:PREFLIGHT_ROOT 'Lightwork metadata fixture.msi'
$report=Join-Path $env:PREFLIGHT_ROOT 'failure.json'
LOCK
$arguments=@{BaseMsi=$package;CandidateMsi=(Join-Path $env:PREFLIGHT_ROOT 'missing-candidate.msi');Inventory=(Join-Path $env:PREFLIGHT_ROOT 'runtime-inventory.json');Report=$report}
if ('SCRIPT' -eq 'test-customer.ps1') {$arguments.InstallDirectory=Join-Path $env:PREFLIGHT_ROOT 'never-installed'} else {$arguments.PublicKeyFile=Join-Path $env:PREFLIGHT_ROOT 'never-read.pub'}
# Snapshot after PowerShell itself initializes its startup cache.
$before=@(Get-ChildItem -LiteralPath $env:PREFLIGHT_ROOT -Recurse | ForEach-Object {$_.FullName})
$message=''
try {& (Join-Path $env:PREFLIGHT_SOURCE 'SCRIPT') @arguments} catch {$message=$_.Exception.Message} finally {if ($held) {$held.Dispose()}}
if ($message.Contains('UNEXPECTED PROCESS')) {throw $message}
if (-not $message.Contains('EXPECTED_PATH')) {throw ('No resolved input diagnostic: '+$message)}
@{report=(Get-Content -Raw -LiteralPath $report | ConvertFrom-Json);created=@(Get-ChildItem -LiteralPath $env:PREFLIGHT_ROOT -Recurse | Where-Object {$_.FullName -notin $before} | ForEach-Object {$_.FullName})} | ConvertTo-Json -Depth 8 -Compress
""".replace("SCRIPT", script).replace("LOCK", lock).replace("EXPECTED_PATH", str(tmp_path / "missing-candidate.msi") if damage == "candidate" else str(package))
    result = probe(tmp_path, source)
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    report = observed["report"]
    assert report["preflight"] == "failed" and report["acceptance_failed"] is True
    assert report["production_publisher_acceptance"] is False
    assert observed["created"] == [str(tmp_path / "failure.json")]


@pytest.mark.parametrize("damage", ["bad_json", "missing_package", "duplicate_package", "runtime_hash", "runtime_size_bool", "publisher_claim", "fixture_string", "cohort_relabel", "recovery_set"])
def test_inventory_contract_is_checked_before_any_package_or_process(tmp_path, inventory, damage):
    value = json.loads(inventory.read_text())
    if damage == "missing_package":
        value["packages"].pop()
    elif damage == "duplicate_package":
        value["packages"][-1] = value["packages"][0]
    elif damage == "runtime_hash":
        value["runtime"]["sha256"] = "unbound"
    elif damage == "runtime_size_bool":
        value["runtime"]["bytes"] = True
    elif damage == "publisher_claim":
        value["publisher_signature_verified"] = True
    elif damage == "fixture_string":
        value["acceptance_fixture"] = "false"
    elif damage == "cohort_relabel":
        value["version"] = "0.1.8"
    elif damage == "recovery_set":
        value["installed_recovery"]["runtime"] = "developer-python.exe"
    inventory.write_text("{invalid" if damage == "bad_json" else json.dumps(value))
    result = probe(tmp_path, r"""
. (Join-Path $env:PREFLIGHT_SOURCE 'msi-acceptance-preflight.ps1')
function Resolve-AcceptanceMsi {throw 'UNEXPECTED PACKAGE READ'}
$message=''
try {Initialize-AcceptancePreflight 'unused-base' 'unused-candidate' (Join-Path $env:PREFLIGHT_ROOT 'runtime-inventory.json') (Join-Path $env:PREFLIGHT_ROOT 'failure.json') 'synthetic-preflight-test' | Out-Null} catch {$message=$_.Exception.Message}
if ($message.Contains('UNEXPECTED') -or -not $message.Contains('runtime-inventory.json')) {throw $message}
Get-Content -Raw -LiteralPath (Join-Path $env:PREFLIGHT_ROOT 'failure.json')
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["preflight"] == "failed"


def test_success_report_binds_actual_metadata_files_without_claiming_publisher_or_installation(tmp_path, package, inventory):
    import msilib

    candidate = tmp_path / "candidate.msi"
    candidate.write_bytes(package.read_bytes())
    database = msilib.OpenDatabase(str(candidate), msilib.MSIDBOPEN_TRANSACT)
    view = database.OpenView("UPDATE `Property` SET `Value` = '0.1.8' WHERE `Property` = 'ProductVersion'")
    view.Execute(None)
    view.Close()
    database.Commit()
    del view, database
    result = probe(tmp_path, r"""
. (Join-Path $env:PREFLIGHT_SOURCE 'msi-acceptance-preflight.ps1')
$result=Initialize-AcceptancePreflight (Join-Path $env:PREFLIGHT_ROOT 'Lightwork metadata fixture.msi') (Join-Path $env:PREFLIGHT_ROOT 'candidate.msi') (Join-Path $env:PREFLIGHT_ROOT 'runtime-inventory.json') (Join-Path $env:PREFLIGHT_ROOT 'unused-report.json') 'synthetic-preflight-test'
$result.report | ConvertTo-Json -Depth 8 -Compress
""")
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["preflight"] == "passed"
    for field in ("publicly_recognized_publisher", "publisher_signature_verified", "production_publisher_acceptance", "clean_virtual_machine", "native_webview_automated"):
        assert report[field] is False
    assert report["synthetic_fixture_versions"] is True
    assert report["same_frozen_runtime_fixture"] is True
    assert report["inputs"]["inventory_sha256"] == hashlib.sha256(inventory.read_bytes()).hexdigest()
    for label, path in (("base", package), ("candidate", candidate)):
        assert report["inputs"][label]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert not (tmp_path / "unused-report.json").exists()


def test_windows_customer_workflow_executes_preflight_regressions():
    import yaml

    workflow = yaml.safe_load((ROOT.parents[1] / ".github/workflows/windows-customer.yml").read_text(encoding="utf-8"))
    commands = [step.get("run", "") for step in workflow["jobs"]["build-and-accept"]["steps"]]
    assert any("-m pytest" in command and "apps/installer-msi/test_msi_acceptance_preflight.py" in command for command in commands)
