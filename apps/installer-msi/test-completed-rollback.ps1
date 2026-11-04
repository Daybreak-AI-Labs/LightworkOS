# Disposable Windows CI acceptance of the actual frozen maintenance protocol.
# Synthetic trusted publisher identity; no claim of public certificate or clean VM acceptance.
param(
    [Parameter(Mandatory=$true)][string]$BaseMsi,
    [Parameter(Mandatory=$true)][string]$CandidateMsi,
    [Parameter(Mandatory=$true)][string]$PublicKeyFile,
    [Parameter(Mandatory=$true)][string]$Inventory,
    [Parameter(Mandatory=$true)][string]$Report,
    [string]$TransitionDirectory = ''
)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or -not $env:RUNNER_TEMP) { throw 'Completed rollback acceptance requires a disposable CI runner.' }
if ($TransitionDirectory -and ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_JOB -ne 'build-and-accept')) {
    throw 'Publisher transition acceptance requires the disposable GitHub-hosted acceptance job.'
}
$runnerRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
$transition = $null
if ($TransitionDirectory) {
    $transitionRoot = Get-Item -LiteralPath $TransitionDirectory
    if (-not $transitionRoot.PSIsContainer -or $transitionRoot.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
        -not $transitionRoot.FullName.StartsWith($runnerRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $transitionRoot.Name -notmatch '^identity-transition-[a-f0-9]{32}$') { throw 'Invalid disposable transition directory.' }
    $TransitionDirectory = $transitionRoot.FullName
    $transition = Get-Content -Raw -LiteralPath (Join-Path $TransitionDirectory 'bridge.json') | ConvertFrom-Json
}
. (Join-Path $PSScriptRoot 'msi-acceptance-preflight.ps1')
$preflight=Initialize-AcceptancePreflight $BaseMsi $CandidateMsi $Inventory $Report 'lightwork.completed-upgrade-rollback-acceptance.v1'
$packageExpectations=$preflight.expectations
$metadata=$preflight.metadata
$fixtureRoot = Join-Path $env:RUNNER_TEMP ('lw-rollback-' + [guid]::NewGuid().ToString('N'))
$fixtureRoot = [IO.Path]::GetFullPath($fixtureRoot)
if (-not $fixtureRoot.StartsWith($runnerRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Acceptance fixture escaped RUNNER_TEMP.' }
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
$installPath = Join-Path $fixtureRoot 'app'
$statePath = Join-Path $fixtureRoot 'state'
New-Item -ItemType Directory -Path $statePath | Out-Null
$expectedPublicKey = (Get-Content -Raw -LiteralPath $PublicKeyFile).Trim()
$baseVersion = [version]$metadata.version
$newVersion = '{0}.{1}.{2}' -f $baseVersion.Major,$baseVersion.Minor,($baseVersion.Build + 1)
$originalEnvironment = @{}
Get-ChildItem Env: | Where-Object { $_.Name -match '^(MAVERICK_|LIGHTWORK_)' } | ForEach-Object {
    $originalEnvironment[$_.Name] = $_.Value
    Remove-Item -LiteralPath ('Env:' + $_.Name)
}
$originalPath = $env:PATH
$observed=$preflight.report
if ($transition) {
    $observed.schema = 'lightwork.publisher-transition-acceptance.v1'
    $observed.same_updater_key = $true
    $observed.mid_msi_crash_tested = $false
}
$server = $null

function Invoke-Msi([string]$package,[string]$action) {
    $package = (Confirm-AcceptanceMsi $package $packageExpectations).path
    $log = Join-Path $env:RUNNER_TEMP ('lightwork-msi-' + [guid]::NewGuid().ToString('N') + '.log')
    $arguments = @($action,('"' + $package + '"'),'/qn','/norestart','/L*v',('"' + $log + '"'),('INSTALLDIR="' + $installPath + '"'))
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32/msiexec.exe') -ArgumentList $arguments -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(240000)) { throw "Fixture Windows Installer timed out; log: $log" }
    if ($process.ExitCode -notin @(0,3010) -and -not ($action -eq '/x' -and $process.ExitCode -in @(1605,1614))) { throw "Fixture Windows Installer failed: $($process.ExitCode); log: $log" }
}

function Read-InstalledChannel {
    param([ValidateRange(100,30000)][int]$TimeoutMilliseconds=30000)
    # This fixed native query exits before WebView or dashboard initialization.
    # PowerShell does not reliably wait for a GUI-subsystem executable invoked
    # with &, so it can close the output pipe while the application is writing.
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $installPath 'maverick-desktop.exe'
    $info.ArgumentList.Add('--maintenance-channel')
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'The installed native channel query did not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            $process.WaitForExit(5000) | Out-Null
            throw 'The installed native channel query timed out; its owned process tree was stopped.'
        }
        $output = $stdout.GetAwaiter().GetResult()
        $errorOutput = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "The installed native channel query failed ($($process.ExitCode)): $($errorOutput.Substring(0,[Math]::Min(1000,$errorOutput.Length)))"
        }
        return ($output | ConvertFrom-Json)
    } finally { $process.Dispose() }
}

function Assert-InstalledChannel([string]$ExpectedVersion) {
    $channel = Read-InstalledChannel
    if ($channel.version -cne $ExpectedVersion -or $channel.packaged_runtime -ne $true -or $channel.public_key -cne $expectedPublicKey) {
        throw "Installed native application does not match the expected customer version/channel: $ExpectedVersion"
    }
    if ($transition) {
        $side = if ($ExpectedVersion -eq $transition.policy.from.version) { $transition.policy.from } else { $transition.policy.to }
        if ($side.version -cne $ExpectedVersion -or
            (Get-FileHash -LiteralPath (Join-Path $installPath 'maverick-desktop.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $side.native_sha256) {
            throw 'Installed native bytes do not match the exact signed transition policy.'
        }
    }
    return $channel.version
}

function Protocol([string]$binary,[string]$step,[hashtable]$payload) {
    Write-Host "Completed rollback acceptance: maintenance $step started."
    $observed.phase = 'maintenance-' + $step
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $binary
    $info.ArgumentList.Add('installation-maintenance')
    $info.ArgumentList.Add($step)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Frozen maintenance helper did not start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write(($payload | ConvertTo-Json -Compress -Depth 8))
    $process.StandardInput.Close()
    # Execution includes bounded Windows Installer work; preparation/status
    # must fail promptly instead of inheriting the installer's long deadline.
    $timeout = if ($step -eq 'execute') { 1900000 } else { 180000 }
    if (-not $process.WaitForExit($timeout)) {
        & (Join-Path $env:SystemRoot 'System32/taskkill.exe') /PID $process.Id /T /F | Out-Null
        throw 'Frozen maintenance protocol timed out; only its owned CI process tree was stopped.'
    }
    $output = $stdout.GetAwaiter().GetResult()
    $errorOutput = $stderr.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw "Frozen maintenance $step failed: $errorOutput" }
    Write-Host "Completed rollback acceptance: maintenance $step finished."
    return ($output | ConvertFrom-Json)
}

function Start-Recovery {
    $observed.phase = 'start-recovery'
    Write-Host 'Completed rollback acceptance: starting isolated recovery.'
    $script:server = Start-Process -FilePath (Join-Path $installPath 'maverick.exe') -ArgumentList @('dashboard','--host','127.0.0.1','--port','8765','--recovery-mode') -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $fixtureRoot 'recovery-out.log') -RedirectStandardError (Join-Path $fixtureRoot 'recovery-error.log')
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($deadline.Elapsed.TotalSeconds -lt 90) {
        if ($script:server.HasExited) { throw 'Fixture recovery server exited before becoming live.' }
        try { if ((Invoke-WebRequest 'http://127.0.0.1:8765/livez' -TimeoutSec 3).StatusCode -eq 200) { return } } catch { }
        Start-Sleep -Milliseconds 500
    }
    throw 'Fixture recovery server never became live.'
}

function Stop-Recovery {
    param([ValidateRange(100,15000)][int]$TimeoutMilliseconds=10000)
    if (-not $script:server) { return }
    if ($script:server -and -not $script:server.HasExited) {
        & (Join-Path $env:SystemRoot 'System32/taskkill.exe') /PID $script:server.Id /T /F | Out-Null
        if (-not $script:server.WaitForExit(15000)) { throw 'The owned recovery process did not stop.' }
    }
    # The frozen bootloader can exit before its worker's listener closes.
    # Do not start another server or acquire a maintenance lease in that gap.
    # A different listener is never killed: uncertainty ends in a refusal.
    $closure = [Diagnostics.Stopwatch]::StartNew()
    while ($closure.Elapsed.TotalMilliseconds -lt $TimeoutMilliseconds) {
        $client = [Net.Sockets.TcpClient]::new()
        $closed = $false
        # Windows can take about two seconds to report a refused loopback
        # connection. A short timeout alone is not proof that the port closed.
        $remaining = [Math]::Max(1, [Math]::Min(3000, [int]($TimeoutMilliseconds - $closure.Elapsed.TotalMilliseconds)))
        try { $null = $client.ConnectAsync('127.0.0.1',8765).Wait($remaining) }
        catch {
            $failure = $_.Exception.GetBaseException()
            $closed = $failure -is [Net.Sockets.SocketException] -and
                $failure.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionRefused
        } finally { $client.Dispose() }
        if ($closed) { $script:server = $null; return }
        Start-Sleep -Milliseconds 50
    }
    throw 'The owned recovery workspace is still responding. A new recovery process was not started.'
}

function Save-NativeReview {
    # The native application records the exact release it reviewed before the
    # browser may authorize an upgrade. This is that native step, run through
    # the same frozen helper; it authorizes nothing by itself.
    return Protocol $runtime 'save-native-review' @{release=[ordered]@{
        version=$newVersion
        runtime_sha256=$metadata.runtime.sha256
        installer_sha256=(Get-FileHash -LiteralPath $CandidateMsi -Algorithm SHA256).Hash.ToLowerInvariant()
        signature=(Get-Content -Raw -LiteralPath ($CandidateMsi+'.sig')).Trim()}}
}

function Authorization([string]$rollbackId='', [string]$BridgeFile='') {
    $origin = 'http://127.0.0.1:8765'
    $bearer = 'Bearer ' + $env:MAVERICK_DASHBOARD_TOKEN
    $status = Invoke-RestMethod ($origin + '/api/v1/recovery/status') -TimeoutSec 15 -Headers @{Origin=$origin; Authorization=$bearer}
    $headers = @{Origin=$origin; Authorization=$bearer; 'X-Lightwork-Recovery-Context'=$status.context; 'X-Lightwork-Expected-Tenant'=$status.expected_tenant}
    $body = @{confirm=$true; confirm_all_workspaces=$true}
    if ($rollbackId) { $body.rollback_id=$rollbackId }
    else {
        # An upgrade is authorized only against the release the native
        # application reviewed; the dashboard must show that exact review.
        $saved = Save-NativeReview
        $shown = (Invoke-RestMethod ($origin + '/api/v1/recovery/installation') -TimeoutSec 15 -Headers $headers).native_review
        if (-not $shown -or $shown.id -cne $saved.id -or $shown.release_sha256 -cne $saved.release_sha256) {
            throw 'Workspace recovery did not show the exact release the native application reviewed.'
        }
        $body.review_id = $saved.id
    }
    if ($BridgeFile) {
        if ($rollbackId) { throw 'A rollback must use the originally admitted transition.' }
        $envelope = Get-Content -Raw -LiteralPath $BridgeFile
        $review = Invoke-RestMethod ($origin + '/api/v1/recovery/installation/identity-transition') -TimeoutSec 30 -Method Post -Headers $headers -ContentType 'application/json' -Body (@{envelope=$envelope}|ConvertTo-Json -Compress)
        if ($review.sha256 -notmatch '^[a-f0-9]{64}$' -or $review.publisher_os_trust_checked -ne $false) { throw 'The transition API returned invalid review evidence.' }
        $body.identity_transition=$envelope
        $body.transition_sha256=$review.sha256
        $body.confirm_identity_transition=$true
        $observed.reviewed_transition_sha256=$review.sha256
    }
    return Invoke-RestMethod ($origin + '/api/v1/recovery/installation/authorize') -TimeoutSec 30 -Method Post -Headers $headers -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 12)
}

function Assert-TransitionReviewRefused([string]$BridgeFile, [string]$ExpectedReason) {
    $origin = 'http://127.0.0.1:8765'
    $headers = @{Origin=$origin; Authorization=('Bearer ' + $env:MAVERICK_DASHBOARD_TOKEN)}
    $status = Invoke-RestMethod ($origin + '/api/v1/recovery/status') -TimeoutSec 15 -Headers $headers
    $headers['X-Lightwork-Recovery-Context']=$status.context
    $headers['X-Lightwork-Expected-Tenant']=$status.expected_tenant
    $body = @{envelope=(Get-Content -Raw -LiteralPath $BridgeFile)} | ConvertTo-Json -Compress
    $response = Invoke-RestMethod ($origin + '/api/v1/recovery/installation/identity-transition') -TimeoutSec 30 -Method Post -Headers $headers -ContentType 'application/json' -Body $body -SkipHttpErrorCheck -StatusCodeVariable httpStatus
    if ($httpStatus -ne 409 -or $response.detail -notmatch $ExpectedReason) { throw 'A negative signing-transition case did not fail for the expected policy reason.' }
}

function Stage-Installers($grant, [string]$BridgeFile='') {
    $details = Protocol $runtime 'inspect' @{authorization=$grant.authorization}
    Copy-Item -LiteralPath $BaseMsi -Destination (Join-Path $details.directory 'old.msi')
    Copy-Item -LiteralPath $CandidateMsi -Destination (Join-Path $details.directory 'new.msi')
    $downloads = @{public_key=$expectedPublicKey;old=@{version=$metadata.version;runtime_sha256=$metadata.runtime.sha256;signature=(Get-Content -Raw -LiteralPath ($BaseMsi+'.sig')).Trim()};new=@{version=$newVersion;runtime_sha256=$metadata.runtime.sha256;signature=(Get-Content -Raw -LiteralPath ($CandidateMsi+'.sig')).Trim()}}
    if ($BridgeFile) { $downloads.identity_transition=Get-Content -Raw -LiteralPath $BridgeFile | ConvertFrom-Json }
    [IO.File]::WriteAllText((Join-Path $details.directory 'downloads.json'),($downloads | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
}

function Execute-Retained([string]$helper,[string]$authorization) {
    # A real finished sentinel process stands in for the native shell's exited
    # parent. Suppressing result UI changes no grant/signature/restore checks.
    $sentinel = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32/ping.exe') -ArgumentList @('127.0.0.1','-n','1') -PassThru -WindowStyle Hidden
    if (-not $sentinel.WaitForExit(10000)) { throw 'The owned maintenance parent fixture did not exit.' }
    return Protocol $helper 'execute' @{authorization=$authorization;parent_pid=$sentinel.Id;open_result=$false}
}

$acceptanceError = $null
try {
    foreach ($package in @($BaseMsi,$CandidateMsi)) {
        if ((Get-AuthenticodeSignature -LiteralPath $package).Status -ne 'Valid') { throw 'Synthetic fixture publisher is not trusted on this disposable runner.' }
        if (-not (Test-Path -LiteralPath ($package + '.sig'))) { throw 'Fixture lacks its real updater signature.' }
    }
    if ($transition) {
        $oldPublisher=(Get-AuthenticodeSignature -LiteralPath $BaseMsi).SignerCertificate.Thumbprint
        $newPublisher=(Get-AuthenticodeSignature -LiteralPath $CandidateMsi).SignerCertificate.Thumbprint
        if ($oldPublisher -eq $newPublisher -or $oldPublisher -cne $transition.policy.from.publisher_thumbprint -or
            $newPublisher -cne $transition.policy.to.publisher_thumbprint -or
            $transition.policy.from.public_key -cne $expectedPublicKey -or $transition.policy.to.public_key -cne $expectedPublicKey) {
            throw 'The actual trusted MSI publishers and compiled updater key do not match the distinct-publisher fixture.'
        }
        $observed.old_publisher_thumbprint=$oldPublisher
        $observed.new_publisher_thumbprint=$newPublisher
        $observed.actual_distinct_publisher_trust='passed'
        $observed.base_installer_sha256=(Get-FileHash -LiteralPath $BaseMsi -Algorithm SHA256).Hash.ToLowerInvariant()
        $observed.candidate_installer_sha256=(Get-FileHash -LiteralPath $CandidateMsi -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $observed.phase = 'base-install'
    Write-Host 'Completed rollback acceptance: installing trusted base fixture.'
    Invoke-Msi $BaseMsi '/i'
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\Wbem"
    $env:MAVERICK_HOME = $statePath
    $env:MAVERICK_CLIENT_ID = 'acceptance'
    $env:MAVERICK_TENANT = 'acceptance'
    $env:MAVERICK_DASHBOARD_TOKEN = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText((Join-Path $statePath 'config.toml'), "[client]`nid = 'acceptance'`n[features]`nworkspace_recovery = true`n")
    foreach ($tenant in @('acceptance','second')) {
        $directory = Join-Path $statePath ('tenants/' + $tenant)
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $directory 'fixture-state.txt'),'before-upgrade')
    }
    $runtime = Join-Path $installPath 'maverick.exe'
    $observed.initial_native_version = Assert-InstalledChannel $metadata.version
    if ((Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.runtime.sha256) { throw 'Installed base runtime differs from the fixture inventory.' }
    Start-Recovery
    $unauthenticated = $false
    try { Invoke-RestMethod 'http://127.0.0.1:8765/api/v1/recovery/installation' -TimeoutSec 15 -Headers @{Origin='http://127.0.0.1:8765'} | Out-Null } catch {
        $unauthenticated = $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401
    }
    if (-not $unauthenticated) { throw 'Installation recovery did not require its synthetic administrator bearer.' }
    $observed.authenticated_administrator_api='passed'
    $bridgeFile = ''
    if ($transition) {
        $bridgeFile = Join-Path $TransitionDirectory 'bridge.json'
        Assert-TransitionReviewRefused $bridgeFile 'disabled'
        $observed.default_off_refusal='passed'
        Stop-Recovery
        [IO.File]::WriteAllText((Join-Path $statePath 'config.toml'), "[client]`nid = 'acceptance'`n[features]`nworkspace_recovery = true`nsigning_identity_transition = true`n")
        Start-Recovery
        Assert-TransitionReviewRefused (Join-Path $TransitionDirectory 'tampered.json') 'signatures did not verify'
        Assert-TransitionReviewRefused (Join-Path $TransitionDirectory 'expired.json') 'not currently open'
        $observed.tampered_policy_refused='passed'
        $observed.expired_admission_refused='passed'
        $unrelated = Join-Path $TransitionDirectory 'unrelated.json'
        $unrelatedGrant = Authorization '' $unrelated
        Stop-Recovery
        Stage-Installers $unrelatedGrant $unrelated
        $unrelatedRejected = $false
        try { Protocol $runtime 'prepare' @{authorization=$unrelatedGrant.authorization} | Out-Null } catch {
            if ($_.Exception.Message -notmatch 'verified installer does not match the reviewed identity transition') { throw }
            $unrelatedRejected = $true
        }
        if (-not $unrelatedRejected -or (Protocol $runtime 'status' @{}).incomplete) { throw 'Unrelated publisher admission was accepted or left a startup block.' }
        Assert-InstalledChannel $metadata.version | Out-Null
        $observed.unrelated_publisher_rejected_before_execution='passed'
        Start-Recovery
    }
    $grant = Authorization '' $bridgeFile
    Stop-Recovery
    Stage-Installers $grant $bridgeFile
    $prepared = Protocol $runtime 'prepare' @{authorization=$grant.authorization}
    if ($transition) {
        # The prepare process has exited. Resume from a separately launched
        # retained helper before executing; this does not simulate a mid-MSI crash.
        if (-not (Protocol $runtime 'status' @{}).incomplete) { throw 'Prepared transition did not hold the normal-start block.' }
        $resumed = Protocol $prepared.helper 'resume' @{id=$grant.id}
        if ($resumed.id -cne $grant.id -or $resumed.authorization -eq $grant.authorization) { throw 'Resume did not renew the exact admitted operation.' }
        $grant.authorization=$resumed.authorization
        $observed.pre_execution_process_resume='passed'
    }
    $result = Execute-Retained $prepared.helper $grant.authorization
    if ($result.status -ne 'upgraded') { throw 'No completed upgrade receipt.' }
    $observed.upgraded_native_version = Assert-InstalledChannel $newVersion
    if ((Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.runtime.sha256) { throw 'Upgraded fixture runtime differs from its declared shared bytes.' }
    $observed.protected_upgrade='passed'
    [IO.File]::WriteAllText((Join-Path $statePath 'tenants/acceptance/fixture-state.txt'),'newer-state')
    [IO.File]::WriteAllText((Join-Path $statePath 'tenants/second/newer.txt'),'created after upgrade')
    Start-Recovery
    $rollback = Authorization $grant.id
    Stop-Recovery
    $prepared = Protocol $runtime 'prepare' @{authorization=$rollback.authorization}
    $result = Execute-Retained $prepared.helper $rollback.authorization
    if ($result.status -ne 'rolled_back') { throw 'No completed rollback receipt.' }
    $observed.rolled_back_native_version = Assert-InstalledChannel $metadata.version
    if ($transition) {
        $observed.old_native_sha256=$transition.policy.from.native_sha256
        $observed.new_native_sha256=$transition.policy.to.native_sha256
        $observed.exact_native_transition_and_return='passed'
    }
    foreach ($tenant in @('acceptance','second')) {
        if ([IO.File]::ReadAllText((Join-Path $statePath ('tenants/'+$tenant+'/fixture-state.txt'))) -ne 'before-upgrade') { throw 'The complete local workspace snapshot was not restored.' }
    }
    if (Test-Path -LiteralPath (Join-Path $statePath 'tenants/second/newer.txt')) { throw 'Newer file survived exact rollback.' }
    if ((Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.runtime.sha256) { throw 'Rollback runtime differs from the verified original.' }
    $status = Protocol $runtime 'status' @{}
    if ($status.incomplete) { throw 'Rollback left an unresolved startup block.' }
    $observed.completed_upgrade_rollback='passed'
    $observed.all_local_workspaces_restored='passed'
    $observed.developer_tools_absent_from_runtime_path='passed'
    $observed.runtime_bytes_unchanged='passed'
    $observed.phase='complete'
} catch {
    $acceptanceError = $_
    $observed.acceptance_failed = $true
    throw
} finally {
    $cleanupErrors = @()
    # Preserve the acceptance phase before cleanup can time out or be cancelled.
    try { $observed | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Report -Encoding utf8 } catch { $cleanupErrors += $_; Write-Warning 'Interim acceptance report could not be saved.' }
    try { Stop-Recovery } catch { $cleanupErrors += $_; Write-Warning 'Owned recovery process cleanup failed.' }
    $env:PATH = $originalPath
    foreach ($package in @($CandidateMsi, $BaseMsi)) {
        try { Invoke-Msi $package '/x' } catch { $cleanupErrors += $_; Write-Warning 'Fixture uninstall cleanup failed; installer log retained.' }
    }
    Get-ChildItem Env: | Where-Object { $_.Name -match '^(MAVERICK_|LIGHTWORK_)' } | ForEach-Object { Remove-Item -LiteralPath ('Env:' + $_.Name) }
    foreach ($name in $originalEnvironment.Keys) { Set-Item -LiteralPath ('Env:' + $name) -Value $originalEnvironment[$name] }
    $observed.cleanup_failures = $cleanupErrors.Count
    try { $observed | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Report -Encoding utf8 } catch { $cleanupErrors += $_; Write-Warning 'Acceptance report could not be saved.' }
    if (-not $acceptanceError -and $cleanupErrors.Count) { throw $cleanupErrors[0] }
}
