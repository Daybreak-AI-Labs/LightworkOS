# Runs only on an owner-provisioned disposable Windows VM, never a developer host.
# Inputs are the original pinned release bundles, not rebuilt/relabelled fixtures.
param(
    [Parameter(Mandatory=$true)][string]$InputsDirectory,
    [Parameter(Mandatory=$true)][string]$Report
)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or -not $env:RUNNER_TEMP -or $env:LIGHTWORK_RELEASE_VM_CONFIRM -cne 'DISPOSABLE_VM_INSTALL_REPAIR_UPGRADE_ROLLBACK') { throw 'Explicit disposable release-VM authorization is required.' }
if (-not $env:LIGHTWORK_CLEAN_VM_ATTESTATION -or $env:LIGHTWORK_CLEAN_VM_ATTESTATION.Length -gt 4096) {throw 'Bounded provisioner VM attestation is required.'}
$attestation = $env:LIGHTWORK_CLEAN_VM_ATTESTATION | ConvertFrom-Json
$machine = Get-CimInstance Win32_ComputerSystem
$product = Get-CimInstance Win32_ComputerSystemProduct
$system = Get-CimInstance Win32_OperatingSystem
if ($system.ProductType -ne 1 -or [int]$system.BuildNumber -lt 22000 -or $system.OSArchitecture -notmatch '64' -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne 'X64') { throw 'This acceptance profile requires a supported Windows 11 x64 customer image.' }
if ($attestation.schema -cne 'lightwork.clean-windows-acceptance-host.v1' -or $attestation.disposable -isnot [bool] -or $attestation.disposable -ne $true -or $attestation.clean_supported_windows -isnot [bool] -or $attestation.clean_supported_windows -ne $true -or $attestation.image_sha256 -notmatch '^[a-f0-9]{64}$' -or $attestation.instance_id -cne $product.UUID -or [string]::IsNullOrWhiteSpace($attestation.image_name) -or $attestation.image_name.Length -gt 128 -or $machine.Model -notmatch 'Virtual|VMware|KVM|HVM' -or $attestation.created_at -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' -or [datetimeoffset]$attestation.created_at -lt [datetimeoffset]::UtcNow.AddHours(-6) -or [datetimeoffset]$attestation.created_at -gt [datetimeoffset]::UtcNow.AddMinutes(5) -or $system.LastBootUpTime -lt [datetime]::Now.AddHours(-6)) { throw 'A fresh disposable VM and exact owner-attested image/instance provenance are required.' }
foreach ($tool in @('python','python3','git','cargo','rustc','cl','candle','light')) {
    if (Get-Command $tool -ErrorAction SilentlyContinue) { throw "The customer acceptance VM contains a development tool on PATH: $tool" }
}
# Do not use Win32_Product: enumerating it can initiate unrelated MSI repairs.
foreach ($registry in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    if (Get-ItemProperty $registry -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '^Lightwork|^Maverick Desktop' }) { throw 'The VM already has a Lightwork installation.' }
}
$inputs = (Get-Item -LiteralPath $InputsDirectory).FullName
$pair = Get-Content -Raw -LiteralPath (Join-Path $inputs 'release-pair.json') | ConvertFrom-Json
$expectedPublicKey = $env:LIGHTWORK_APPROVED_UPDATE_PUBLIC_KEY.Trim()
$keyHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($expectedPublicKey))).ToLowerInvariant()
if ($pair.schema -cne 'lightwork.release-pair-inputs.v1' -or $pair.updater_public_key_sha256 -cne $keyHash -or $pair.publisher_thumbprint -ine $env:LIGHTWORK_APPROVED_PUBLISHER_THUMBPRINT -or $pair.previous.runtime_sha256 -ceq $pair.candidate.runtime_sha256 -or [version]$pair.previous.version -ge [version]$pair.candidate.version -or $pair.state_profile -cne 'facts-and-encrypted-draft-v1') { throw 'The pair does not match the protected production public identities and distinct actual release versions.' }
$verifier = Join-Path $inputs 'lightwork-verify-update.exe'
$verifierHash = (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash.ToLowerInvariant()
if ($verifierHash -cne $env:LIGHTWORK_VERIFIER_SHA256) { throw 'The reviewed native signature verifier changed in transit.' }
$packages = @{}
$installer = New-Object -ComObject WindowsInstaller.Installer
foreach ($label in @('previous','candidate')) {
    $identity = $pair.$label
    $directory = Join-Path $inputs $label
    $package = Join-Path $directory 'Lightwork.msi'
    $packages[$label] = $package
    if ((Get-FileHash -LiteralPath (Join-Path $inputs ($label+'-original.zip'))).Hash.ToLowerInvariant() -cne $identity.archive_sha256 -or (Get-FileHash -LiteralPath $package).Hash.ToLowerInvariant() -cne $identity.installer_sha256 -or (Get-FileHash -LiteralPath (Join-Path $directory ('versions/'+$identity.version+'.json'))).Hash.ToLowerInvariant() -cne $identity.manifest_sha256 -or (Get-FileHash -LiteralPath (Join-Path $directory 'runtime-inventory.json')).Hash.ToLowerInvariant() -cne $identity.inventory_sha256) { throw 'An original pinned release input changed in transit.' }
    $publicKeyFile = Join-Path $directory 'updater.pub'
    if ((Get-Content -Raw -LiteralPath $publicKeyFile).Trim() -cne $expectedPublicKey) { throw 'Original release updater identity differs from the protected identity.' }
    $manifest=Get-Content -Raw -LiteralPath (Join-Path $directory ('versions/'+$identity.version+'.json'))|ConvertFrom-Json
    if ($manifest.platforms.'windows-x86_64'.signature -cne (Get-Content -Raw -LiteralPath ($package+'.sig')).Trim()) {throw 'Original detached signature differs from the pinned immutable manifest.'}
    $signature = Get-AuthenticodeSignature -LiteralPath $package
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ine $pair.publisher_thumbprint -or $signature.SignerCertificate.Subject -eq $signature.SignerCertificate.Issuer) { throw 'An original MSI lacks the approved, chain-valid, non-self-signed publisher identity.' }
    & $verifier $publicKeyFile ($package+'.sig') $package
    if ($LASTEXITCODE -ne 0) { throw 'An original MSI updater signature failed verification.' }
    $database = $installer.OpenDatabase($package,0)
    $view = $database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = ''ProductVersion''')
    $view.Execute(); $row = $view.Fetch()
    if (-not $row -or $row.StringData(1) -cne $identity.version) { throw 'Actual MSI ProductVersion differs from the original runtime inventory.' }
    $view.Close()
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
}
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
$runnerRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP ('lw-release-pair-'+[guid]::NewGuid().ToString('N'))))
if (-not $fixtureRoot.StartsWith($runnerRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Release fixture escaped RUNNER_TEMP.' }
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
$installPath = Join-Path $fixtureRoot 'app'
$statePath = Join-Path $fixtureRoot 'state'
New-Item -ItemType Directory -Path $statePath | Out-Null
$runtime = Join-Path $installPath 'maverick.exe'
$server = $null
$originalEnvironment = @{}
Get-ChildItem Env: | Where-Object { $_.Name -match '^(MAVERICK_|LIGHTWORK_)' } | ForEach-Object { $originalEnvironment[$_.Name]=$_.Value; Remove-Item -LiteralPath ('Env:'+$_.Name) }
$originalPath = $env:PATH
$observed = [ordered]@{schema='lightwork.real-release-pair-acceptance.v1'; previous=$pair.previous; candidate=$pair.candidate; candidate_head_sha=$pair.candidate_head_sha; previous_release_id=$pair.previous_release_id; previous_asset_id=$pair.previous_asset_id; candidate_run_id=$pair.candidate_run_id; candidate_artifact_id=$pair.candidate_artifact_id; state_profile=$pair.state_profile; compatibility_review=$pair.compatibility_review; owner_attested_clean_vm=$attestation; observed_os=$system.Caption; observed_os_version=$system.Version; signatures_reverified=$true; approved_publisher_thumbprint=$pair.publisher_thumbprint; updater_public_key_sha256=$keyHash; synthetic_fixture_versions=$false; same_frozen_runtime_fixture=$false; synthetic_state=$true; provider_calls=$false; native_webview_automated=$false; network_isolated_install_verified=$false; release_pair_accepted=$false; installer_executed=$false}

function Invoke-Msi([string]$package,[string]$action) {
    $observed.installer_executed=$true
    $log = Join-Path $env:RUNNER_TEMP ('lightwork-release-msi-'+[guid]::NewGuid().ToString('N')+'.log')
    $arguments=@($action,('"'+$package+'"'),'/qn','/norestart','/L*v',('"'+$log+'"'),('INSTALLDIR="'+$installPath+'"'))
    $process=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32/msiexec.exe') -ArgumentList $arguments -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(240000)) { throw "Windows Installer timed out; retain disposable VM and log: $log" }
    if ($process.ExitCode -notin @(0,3010) -and -not ($action -eq '/x' -and $process.ExitCode -in @(1605,1614))) { throw "Windows Installer failed: $($process.ExitCode); log: $log" }
}
function Read-Binary([string]$binary,[string[]]$arguments) {
    # GUI-subsystem binaries require explicit redirected process handles; direct
    # PowerShell capture can close the native stdout pipe before its JSON write.
    $info=[Diagnostics.ProcessStartInfo]::new(); $info.FileName=$binary
    foreach ($argument in $arguments) {$info.ArgumentList.Add($argument)}
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new(); $process.StartInfo=$info
    try {
        if (-not $process.Start()) {throw 'Installed binary did not start.'}
        $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) {& (Join-Path $env:SystemRoot 'System32/taskkill.exe') /PID $process.Id /T /F | Out-Null; throw 'Owned installed-binary query timed out.'}
        $output=$stdout.GetAwaiter().GetResult(); $errorOutput=$stderr.GetAwaiter().GetResult()
        $errorSummary=if ($errorOutput.Length -gt 4096) {$errorOutput.Substring(0,4096)+' [truncated]'} else {$errorOutput}
        if ($process.ExitCode -ne 0 -or $output.Length -gt 1048576) {throw "Installed binary query failed: $errorSummary"}
        return $output
    } finally {$process.Dispose()}
}
function Assert-Installed($identity) {
    $channel = (Read-Binary (Join-Path $installPath 'maverick-desktop.exe') @('--maintenance-channel')) | ConvertFrom-Json
    if ($channel.version -cne $identity.version -or $channel.packaged_runtime -ne $true -or $channel.public_key -cne $expectedPublicKey) { throw 'The installed native channel is not the exact reviewed release.' }
    if ((Get-FileHash -LiteralPath $runtime).Hash.ToLowerInvariant() -cne $identity.runtime_sha256 -or (Get-Item -LiteralPath $runtime).Length -ne $identity.runtime_bytes) { throw 'Installed frozen runtime bytes differ from the original inventory.' }
    $versions = Read-Binary $runtime @('version')
    foreach ($package in $identity.packages) {
        if ($versions -notmatch ('(?m)^\s*'+[regex]::Escape($package)+'\s+'+[regex]::Escape($identity.version)+'\s*$')) { throw 'Actual frozen cohort metadata differs from the release version.' }
    }
    Read-Binary $runtime @('release-runtime-check') | Out-Null
}
function Protocol([string]$binary,[string]$step,[hashtable]$payload) {
    $info=[Diagnostics.ProcessStartInfo]::new(); $info.FileName=$binary
    $info.ArgumentList.Add('installation-maintenance'); $info.ArgumentList.Add($step)
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.RedirectStandardInput=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new(); $process.StartInfo=$info
    if (-not $process.Start()) { throw 'Frozen maintenance helper did not start.' }
    $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write(($payload|ConvertTo-Json -Compress -Depth 8)); $process.StandardInput.Close()
    $timeout=if ($step -eq 'execute') {1900000} else {180000}
    if (-not $process.WaitForExit($timeout)) { & (Join-Path $env:SystemRoot 'System32/taskkill.exe') /PID $process.Id /T /F | Out-Null; throw 'Owned frozen maintenance helper timed out.' }
    $output=$stdout.GetAwaiter().GetResult(); $errorOutput=$stderr.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw "Frozen maintenance $step failed: $errorOutput" }
    return ($output|ConvertFrom-Json)
}
function Start-App([bool]$recovery=$false) {
    $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0); $listener.Start()
    $port=$listener.LocalEndpoint.Port; $listener.Stop(); $script:origin='http://127.0.0.1:'+$port
    $arguments=@('dashboard','--host','127.0.0.1','--port',[string]$port)
    if ($recovery) { $arguments+='--recovery-mode' }
    $log=Join-Path $fixtureRoot ('server-'+[guid]::NewGuid().ToString('N'))
    $script:server=Start-Process -FilePath $runtime -ArgumentList $arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput ($log+'.out') -RedirectStandardError ($log+'.err')
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt 90) {
        if ($script:server.HasExited) { throw 'Owned isolated server exited before startup.' }
        try { if ((Invoke-WebRequest ($script:origin+'/livez') -TimeoutSec 3).StatusCode -eq 200) { return } } catch { }
        Start-Sleep -Milliseconds 300
    }
    throw 'Owned isolated server did not start.'
}
function Stop-App {
    if ($script:server -and -not $script:server.HasExited) { & (Join-Path $env:SystemRoot 'System32/taskkill.exe') /PID $script:server.Id /T /F | Out-Null; if (-not $script:server.WaitForExit(15000)) { throw 'Owned server did not stop.' } }
    $script:server=$null
}
function Headers { return @{Origin=$script:origin;Authorization=('Bearer '+$env:MAVERICK_DASHBOARD_TOKEN)} }
function Draft-Headers {
    $headers=Headers
    $page=Invoke-WebRequest ($script:origin+'/settings') -Headers $headers -TimeoutSec 30
    $match=[regex]::Match($page.Content,'name="lightwork-draft-context"\s+content="([a-f0-9]{64})"')
    if (-not $match.Success) { throw 'The prior release does not expose the supported draft context contract.' }
    $headers['X-Lightwork-Draft-Context']=$match.Groups[1].Value; return $headers
}
function Write-Fact([string]$value) { Invoke-RestMethod ($script:origin+'/api/v1/facts') -Headers (Headers) -Method Post -ContentType 'application/json' -Body (@{key='release-acceptance';value=$value}|ConvertTo-Json) -TimeoutSec 30 | Out-Null }
function Assert-State([string]$fact='original') {
    $facts=Invoke-RestMethod ($script:origin+'/api/v1/facts') -Headers (Headers) -TimeoutSec 30
    $draft=Invoke-RestMethod ($script:origin+'/api/v1/drafts/'+$script:slot) -Headers (Draft-Headers) -TimeoutSec 30
    if ($facts.'release-acceptance' -cne $fact -or $draft.payload.title -cne 'Synthetic retained customer draft' -or $draft.revision -ne 1) { throw 'Actual application readers did not preserve the representative database and encrypted draft.' }
}
function Authorization([string]$rollbackId='') {
    $headers=Headers; $status=Invoke-RestMethod ($script:origin+'/api/v1/recovery/status') -Headers $headers -TimeoutSec 30
    $headers['X-Lightwork-Recovery-Context']=$status.context; $headers['X-Lightwork-Expected-Tenant']=$status.expected_tenant
    $body=@{confirm=$true;confirm_all_workspaces=$true}
    if ($rollbackId) {$body.rollback_id=$rollbackId}
    else {
        # The installed (previous) release decides the contract. One that records
        # the native application's release review requires an upgrade to name it;
        # an earlier release has neither the review nor the field.
        $installation=Invoke-RestMethod ($script:origin+'/api/v1/recovery/installation') -Headers $headers -TimeoutSec 30
        if ($installation.PSObject.Properties.Name -contains 'native_review') {
            $candidate=$pair.candidate
            $saved=Protocol $runtime 'save-native-review' @{release=[ordered]@{
                version=$candidate.version; runtime_sha256=$candidate.runtime_sha256
                installer_sha256=(Get-FileHash -LiteralPath $packages.candidate -Algorithm SHA256).Hash.ToLowerInvariant()
                signature=(Get-Content -Raw -LiteralPath ($packages.candidate+'.sig')).Trim()}}
            $shown=(Invoke-RestMethod ($script:origin+'/api/v1/recovery/installation') -Headers $headers -TimeoutSec 30).native_review
            if (-not $shown -or $shown.id -cne $saved.id -or $shown.release_sha256 -cne $saved.release_sha256) { throw 'Workspace recovery did not show the exact release the native application reviewed.' }
            $body.review_id=$saved.id
        }
    }
    return Invoke-RestMethod ($script:origin+'/api/v1/recovery/installation/authorize') -Headers $headers -Method Post -ContentType 'application/json' -Body ($body|ConvertTo-Json) -TimeoutSec 30
}
function Execute-Retained($prepared,$grant) {
    $sentinel=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32/ping.exe') -ArgumentList @('127.0.0.1','-n','1') -PassThru -WindowStyle Hidden
    if (-not $sentinel.WaitForExit(10000)) { throw 'Owned exited-parent sentinel timed out.' }
    return Protocol $prepared.helper 'execute' @{authorization=$grant.authorization;parent_pid=$sentinel.Id;open_result=$false}
}
function Upgrade {
    Start-App $true; $grant=Authorization; Stop-App
    $details=Protocol $runtime 'inspect' @{authorization=$grant.authorization}
    Copy-Item -LiteralPath $packages.previous -Destination (Join-Path $details.directory 'old.msi')
    Copy-Item -LiteralPath $packages.candidate -Destination (Join-Path $details.directory 'new.msi')
    $downloads=@{public_key=$expectedPublicKey}
    foreach ($mapping in @(@('old','previous'),@('new','candidate'))) {
        $identity=$pair.($mapping[1]); $downloads[$mapping[0]]=@{version=$identity.version;runtime_sha256=$identity.runtime_sha256;signature=(Get-Content -Raw -LiteralPath ($packages[$mapping[1]]+'.sig')).Trim()}
    }
    [IO.File]::WriteAllText((Join-Path $details.directory 'downloads.json'),($downloads|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
    $prepared=Protocol $runtime 'prepare' @{authorization=$grant.authorization}
    $result=Execute-Retained $prepared $grant
    if ($result.status -ne 'upgraded') { throw 'No exact completed-upgrade receipt.' }
    Assert-Installed $pair.candidate; return $grant
}
$acceptanceError=$null
try {
    $env:PATH="$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\Wbem"
    $env:MAVERICK_HOME=$statePath; $env:MAVERICK_CLIENT_ID='release-acceptance'; $env:MAVERICK_TENANT='release-acceptance'
    $env:MAVERICK_DASHBOARD_TOKEN=[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N')
    $env:MAVERICK_ENCRYPT_AT_REST='1'; $env:MAVERICK_ENCRYPT_PER_TENANT='0'
    [IO.File]::WriteAllText((Join-Path $statePath 'config.toml'),"[client]`nid = 'release-acceptance'`n[features]`nworkspace_recovery = true`ndraft_recovery = true`n[voice]`nauto_fetch_model = false`n[encryption]`nat_rest = true`nper_tenant = false`n[kms]`nprovider = 'local'`n")
    $observed.phase='install-previous'; Invoke-Msi $packages.previous '/i'; Assert-Installed $pair.previous
    $observed.install_previous='passed'
    Start-App; Write-Fact 'original'
    $script:slot='a'*64
    $body=@{expected_revision=0;operation_id=[guid]::NewGuid().ToString('N');payload=@{title='Synthetic retained customer draft';rows=@('one','two')}}
    Invoke-RestMethod ($script:origin+'/api/v1/drafts/'+$script:slot) -Headers (Draft-Headers) -Method Put -ContentType 'application/json' -Body ($body|ConvertTo-Json -Depth 5) -TimeoutSec 30 | Out-Null
    Assert-State; Stop-App
    $draftFiles=@(Get-ChildItem -LiteralPath $statePath -Recurse -File | Where-Object { $_.FullName -match 'draft-recovery' -and $_.Extension -eq '.draft' })
    if (-not $draftFiles.Count) { throw 'No actual encrypted application draft was persisted.' }
    foreach ($file in $draftFiles) {
        $bytes=[IO.File]::ReadAllBytes($file.FullName)
        if ([Text.Encoding]::ASCII.GetString($bytes,0,[Math]::Min(7,$bytes.Length)) -notmatch '^MVKAR[12]\n' -or [Text.Encoding]::UTF8.GetString($bytes).Contains('Synthetic retained customer draft')) { throw 'The representative draft lacks its actual sealed format.' }
    }
    $second=Join-Path $statePath 'tenants/second'; New-Item -ItemType Directory -Path $second -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $second 'retained.txt'),'original-second-workspace')
    $observed.phase='repair-previous'; Invoke-Msi $packages.previous '/fa'; Assert-Installed $pair.previous
    Start-App; Assert-State; Stop-App; $observed.repair_previous='passed'
    $observed.phase='upgrade-real-candidate'; $grant=Upgrade
    Start-App; Assert-State; Stop-App; $observed.upgrade_candidate_readers='passed'
    [IO.File]::WriteAllText((Join-Path $second 'retained.txt'),'newer-unprotected-content')
    $observed.phase='rollback-real-candidate'; Start-App $true; $rollback=Authorization $grant.id; Stop-App
    $prepared=Protocol $runtime 'prepare' @{authorization=$rollback.authorization}
    $result=Execute-Retained $prepared $rollback
    if ($result.status -ne 'rolled_back') { throw 'No exact completed rollback receipt.' }
    Assert-Installed $pair.previous; Start-App; Assert-State; Stop-App
    if ([IO.File]::ReadAllText((Join-Path $second 'retained.txt')) -cne 'original-second-workspace' -or (Protocol $runtime 'status' @{}).incomplete) { throw 'Rollback did not restore the complete local scope or clear its startup block.' }
    $observed.rollback_previous_readers='passed'; $observed.second_workspace_restored='passed'
    $observed.phase='protect-newer-database'; $grant=Upgrade
    Start-App; Write-Fact 'newer-must-survive'; Assert-State 'newer-must-survive'; Stop-App
    Start-App $true; $rollback=Authorization $grant.id; Stop-App
    $refused=$false
    try { Protocol $runtime 'prepare' @{authorization=$rollback.authorization} | Out-Null } catch { $refused=$_.Exception.Message.Contains('Automatic restore is unavailable because spending, reservations, budget controls, database state or external-action history differs') }
    if (-not $refused -or (Protocol $runtime 'status' @{}).incomplete) { throw 'Changed protected database did not refuse rollback before installing or blocking startup.' }
    Assert-Installed $pair.candidate; Start-App; Assert-State 'newer-must-survive'; Stop-App
    $observed.protected_database_refusal='passed'; $observed.actual_versions_and_distinct_runtime='passed'
    $observed.phase='complete'; $observed.release_pair_accepted=$true
} catch { $acceptanceError=$_; $observed.acceptance_failed=$true; throw } finally {
    # Never upload the synthetic home: it contains encryption keys and bearer-bound drafts.
    # Keep the VM for investigation after an installer timeout; disposal belongs to its owner.
    $cleanupErrors=@()
    try { $observed|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $Report -Encoding utf8 } catch { $cleanupErrors+=$_ }
    try { Stop-App } catch { $cleanupErrors+=$_ }
    if (-not $acceptanceError) { foreach ($package in @($packages.candidate,$packages.previous)) { try { Invoke-Msi $package '/x' } catch { $cleanupErrors+=$_ } } }
    $env:PATH=$originalPath
    Get-ChildItem Env:|Where-Object { $_.Name -match '^(MAVERICK_|LIGHTWORK_)' }|ForEach-Object { Remove-Item -LiteralPath ('Env:'+$_.Name) }
    foreach ($name in $originalEnvironment.Keys) { Set-Item -LiteralPath ('Env:'+$name) -Value $originalEnvironment[$name] }
    $observed.cleanup_failures=$cleanupErrors.Count
    if ($cleanupErrors.Count) {$observed.release_pair_accepted=$false}
    try { $observed|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $Report -Encoding utf8 } catch { $cleanupErrors+=$_; Write-Warning 'Final acceptance report could not be saved; the original acceptance error is retained.' }
    if (-not $acceptanceError -and $cleanupErrors.Count) { throw $cleanupErrors[0] }
}
