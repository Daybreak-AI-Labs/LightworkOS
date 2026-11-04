"""The acceptance drivers must authorize an upgrade the way the product does.

The dashboard refuses to authorize an upgrade unless the request names the
release the native application reviewed (``review_id``) or the completed upgrade
it rolls back (``rollback_id``). These tests run each driver's real
``Authorization`` function with only its process and HTTP boundaries replaced, so
a driver that skips the native review again fails here instead of on a hosted
Windows runner.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

DIRECTORY = Path(__file__).parent
ROLLBACK_DRIVER = DIRECTORY / "test-completed-rollback.ps1"
PAIR_DRIVER = DIRECTORY / "test-release-pair.ps1"
PWSH = shutil.which("pwsh")

# Replaces Invoke-RestMethod and the frozen maintenance helper. Every call is
# recorded so a test can assert the order and the exact request bodies.
BOUNDARIES = r"""
$script:calls = New-Object System.Collections.ArrayList
$script:shown = $env:PROBE_SHOWN
function Invoke-RestMethod {
    param([Parameter(Position=0)]$Uri, $TimeoutSec, $Method='Get', $Headers, $ContentType, $Body)
    $path = ([Uri]$Uri).AbsolutePath
    [void]$script:calls.Add(@{kind='http'; method=$Method; path=$path; body=$Body})
    if ($path -eq '/api/v1/recovery/status') { return [pscustomobject]@{context='ctx'; expected_tenant='tenant'} }
    if ($path -eq '/api/v1/recovery/installation' -and $Method -eq 'Get') {
        switch ($script:shown) {
            'match'  { return [pscustomobject]@{native_review=[pscustomobject]@{id=('a'*32); release_sha256=('b'*64)}} }
            'other'  { return [pscustomobject]@{native_review=[pscustomobject]@{id=('c'*32); release_sha256=('b'*64)}} }
            'empty'  { return [pscustomobject]@{native_review=$null} }
            'legacy' { return [pscustomobject]@{version='1.0.0'} }
        }
    }
    if ($path -eq '/api/v1/recovery/installation/authorize') { return [pscustomobject]@{id=('d'*32); authorization='grant'} }
    throw "unexpected request $Method $path"
}
function Protocol([string]$binary, [string]$step, [hashtable]$payload) {
    [void]$script:calls.Add(@{kind='protocol'; step=$step; payload=($payload | ConvertTo-Json -Compress -Depth 8)})
    return [pscustomobject]@{id=('a'*32); release_sha256=('b'*64)}
}
function Get-DriverFunction([string]$driver, [string]$name) {
    $ast = [Management.Automation.Language.Parser]::ParseFile($driver, [ref]$null, [ref]$null)
    $found = $ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}, $true)
    if (-not $found) { throw "driver has no function $name" }
    return $found.Extent.Text
}
"""


def run(tmp_path, source, **environment):
    if not PWSH:
        pytest.skip("PowerShell 7 is required for the Windows acceptance driver contract")
    probe = tmp_path / "probe.ps1"
    probe.write_text("$ErrorActionPreference='Stop'\n" + BOUNDARIES + source, encoding="utf-8")
    return subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(probe)],
        env={**os.environ, **environment}, capture_output=True, text=True, encoding="utf-8",
        timeout=60, check=False,
    )


def calls_of(result):
    assert result.returncode == 0, result.stderr + result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])


ROLLBACK_SETUP = r"""
$candidate = Join-Path $env:PROBE_ROOT 'candidate.msi'
[IO.File]::WriteAllText($candidate, 'synthetic installer bytes')
[IO.File]::WriteAllText($candidate + '.sig', "synthetic-signature`n")
$CandidateMsi = $candidate
$newVersion = '1.2.4'
$runtime = 'synthetic-runtime'
$metadata = [pscustomobject]@{runtime=[pscustomobject]@{sha256=('e'*64)}}
$env:MAVERICK_DASHBOARD_TOKEN = 'synthetic-token'
$null = . ([scriptblock]::Create((Get-DriverFunction $env:DRIVER 'Save-NativeReview')))
$null = . ([scriptblock]::Create((Get-DriverFunction $env:DRIVER 'Authorization')))
"""

PAIR_SETUP = r"""
$candidate = Join-Path $env:PROBE_ROOT 'candidate.msi'
[IO.File]::WriteAllText($candidate, 'synthetic installer bytes')
[IO.File]::WriteAllText($candidate + '.sig', "synthetic-signature`n")
$packages = @{candidate=$candidate}
$pair = [pscustomobject]@{candidate=[pscustomobject]@{version='1.2.4'; runtime_sha256=('e'*64)}}
$runtime = 'synthetic-runtime'
$script:origin = 'http://127.0.0.1:8765'
$env:MAVERICK_DASHBOARD_TOKEN = 'synthetic-token'
function Headers { return @{Origin=$script:origin} }
$null = . ([scriptblock]::Create((Get-DriverFunction $env:DRIVER 'Authorization')))
"""

EMIT = "\n$script:calls | ConvertTo-Json -Compress -Depth 8 -AsArray\n"


def posted(calls):
    return [json.loads(c["body"]) for c in calls if c["kind"] == "http" and c["path"].endswith("/authorize")]


@pytest.mark.parametrize("setup, driver", [(ROLLBACK_SETUP, ROLLBACK_DRIVER), (PAIR_SETUP, PAIR_DRIVER)], ids=["completed-rollback", "release-pair"])
def test_upgrade_authorization_names_the_release_the_native_app_reviewed(tmp_path, setup, driver):
    result = run(tmp_path, setup + "Authorization '' | Out-Null" + EMIT,
                 DRIVER=str(driver), PROBE_ROOT=str(tmp_path), PROBE_SHOWN="match")
    calls = calls_of(result)
    saves = [c for c in calls if c["kind"] == "protocol"]
    assert [c["step"] for c in saves] == ["save-native-review"]
    release = json.loads(saves[0]["payload"])["release"]
    assert release["version"] == "1.2.4"
    assert release["runtime_sha256"] == "e" * 64
    assert release["signature"] == "synthetic-signature"
    assert release["installer_sha256"] == hashlib.sha256(b"synthetic installer bytes").hexdigest()
    body = posted(calls)[0]
    assert body["review_id"] == "a" * 32
    assert "rollback_id" not in body
    # The review exists before the browser asks to authorize against it.
    order = [c["step"] if c["kind"] == "protocol" else c["path"] for c in calls]
    assert order.index("save-native-review") < order.index("/api/v1/recovery/installation/authorize")


@pytest.mark.parametrize("setup, driver", [(ROLLBACK_SETUP, ROLLBACK_DRIVER), (PAIR_SETUP, PAIR_DRIVER)], ids=["completed-rollback", "release-pair"])
def test_rollback_authorization_uses_the_admitted_upgrade_and_no_review(tmp_path, setup, driver):
    result = run(tmp_path, setup + "Authorization ('f'*32) | Out-Null" + EMIT,
                 DRIVER=str(driver), PROBE_ROOT=str(tmp_path), PROBE_SHOWN="match")
    calls = calls_of(result)
    assert not [c for c in calls if c["kind"] == "protocol"]
    body = posted(calls)[0]
    assert body["rollback_id"] == "f" * 32
    assert "review_id" not in body


@pytest.mark.parametrize("shown", ["other", "empty"])
def test_driver_refuses_when_workspace_recovery_shows_a_different_review(tmp_path, shown):
    result = run(tmp_path, ROLLBACK_SETUP + "Authorization '' | Out-Null" + EMIT,
                 DRIVER=str(ROLLBACK_DRIVER), PROBE_ROOT=str(tmp_path), PROBE_SHOWN=shown)
    assert result.returncode != 0
    assert "did not show the exact release" in result.stderr + result.stdout


def test_release_pair_still_authorizes_a_release_that_predates_native_reviews(tmp_path):
    result = run(tmp_path, PAIR_SETUP + "Authorization '' | Out-Null" + EMIT,
                 DRIVER=str(PAIR_DRIVER), PROBE_ROOT=str(tmp_path), PROBE_SHOWN="legacy")
    calls = calls_of(result)
    assert not [c for c in calls if c["kind"] == "protocol"]
    assert "review_id" not in posted(calls)[0]


def test_every_authorize_call_in_the_drivers_goes_through_the_checked_function():
    """A new direct POST would bypass the review step these tests exercise."""
    for driver in (ROLLBACK_DRIVER, PAIR_DRIVER):
        text = driver.read_text(encoding="utf-8")
        assert text.count("/api/v1/recovery/installation/authorize") == 1, driver.name
        assert "save-native-review" in text, driver.name
