"""Real listener closure around the acceptance driver's owned-process boundary."""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

DRIVER = Path(__file__).with_name("test-completed-rollback.ps1")


@pytest.mark.skipif(os.name != "nt", reason="Windows recovery driver lifecycle")
@pytest.mark.parametrize("scenario", ["delayed-close", "still-listening", "not-owned"])
def test_stop_recovery_waits_for_owned_listener_and_refuses_an_unclosed_port(tmp_path, scenario):
    powershell = shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell 7 is required for the Windows packaging driver")
    with socket.socket() as available:
        try:
            available.bind(("127.0.0.1", 8765))
        except OSError:
            pytest.skip("Canonical recovery port is already owned by another process")
    probe = tmp_path / "probe.ps1"
    probe.write_text(r'''
$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile($env:RECOVERY_DRIVER,[ref]$null,[ref]$null)
$method=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Stop-Recovery'},$true)
. ([scriptblock]::Create($method.Extent.Text))
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
public sealed class DelayedListener : IDisposable {
    private readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 8765);
    public DelayedListener(int delay) {
        listener.Start();
        if (delay > 0) {
            var closer = new Thread(() => { Thread.Sleep(delay); listener.Stop(); });
            closer.IsBackground = true;
            closer.Start();
        }
    }
    public void Dispose() { listener.Stop(); }
}
'@
function Listening {
    $client=[Net.Sockets.TcpClient]::new()
    try { return ($client.ConnectAsync('127.0.0.1',8765).Wait(200) -and $client.Connected) }
    catch { return $false }
    finally { $client.Dispose() }
}
$scenario=$env:RECOVERY_SCENARIO
$delay=if($scenario -eq 'delayed-close'){750}else{0}
$listener=[DelayedListener]::new($delay)
# The owned bootloader has exited, while the real TCP endpoint is still
# closing. No test kills a process or runs any installer/trust command.
$script:server=if($scenario -eq 'not-owned'){$null}else{[pscustomobject]@{HasExited=$true}}
try {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $refusal=$null
    try {
        if($scenario -eq 'still-listening'){Stop-Recovery -TimeoutMilliseconds 300}
        else {Stop-Recovery}
    } catch {$refusal=$_.Exception.Message}
    if($scenario -eq 'delayed-close') {
        if($refusal -or (Listening) -or $clock.Elapsed.TotalMilliseconds -lt 500) {
            throw 'Stop returned before the owned listener closed.'
        }
        if($script:server){throw 'Closed owned process was not released.'}
    } elseif($scenario -eq 'still-listening') {
        if($refusal -notmatch 'still responding' -or -not (Listening) -or
           $clock.Elapsed.TotalMilliseconds -gt 3000 -or -not $script:server) {
            throw 'The unclosed listener was not refused within the bound and preserved.'
        }
    } elseif($refusal -or -not (Listening) -or $clock.Elapsed.TotalMilliseconds -gt 500) {
        throw 'An unowned listener was changed or waited on.'
    }
} finally { $listener.Dispose() }
''', encoding="utf-8")
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(probe)],
        env={**os.environ, "RECOVERY_DRIVER": str(DRIVER), "RECOVERY_SCENARIO": scenario},
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == 0, result.stderr[-4000:]
