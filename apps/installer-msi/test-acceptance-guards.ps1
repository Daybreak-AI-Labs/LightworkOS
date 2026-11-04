# Runs only the acceptance functions with synthetic processes/channel responses.
# Never invokes Windows Installer, a native executable, or the acceptance body.
param([Parameter(Mandatory=$true)][string]$ScriptDirectory)
$ErrorActionPreference = 'Stop'
. (Join-Path $ScriptDirectory 'msi-acceptance-preflight.ps1')
# These old process/quoting cases deliberately double metadata. Real read-only
# Windows Installer COM inspection has separate inert-database tests.
function Read-AcceptanceMsiProperties([string]$Package) {
    return @{ProductName='Lightwork Desktop';ProductVersion='0.1.7';UpgradeCode='{AB5BC260-7EC9-4B70-AF78-28F4067BC530}'}
}

function Import-Function([string]$File,[string]$Name) {
    $tokens=$null; $errors=$null
    $tree=[Management.Automation.Language.Parser]::ParseFile($File,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw "Acceptance script syntax errors: $errors" }
    $found=@($tree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name},$true))
    if ($found.Count -ne 1) { throw "Expected one acceptance function: $Name" }
    # Dot sourcing into the caller scope is unnecessary: export only the reviewed
    # function's body, never the script's installation entry point.
    Invoke-Expression ($found[0].Extent.Text -replace '^function\s+', 'function script:')
}

Import-Function (Join-Path $ScriptDirectory 'test-customer.ps1') 'Invoke-Msi'
$script:fixtureExit=1603
$script:fixtureLog=''
$script:called=0
function Start-Process {
    param($FilePath,$ArgumentList,[switch]$PassThru,$WindowStyle)
    $script:called++
    $script:lastArguments=@($ArgumentList)
    if ($FilePath -notlike '*msiexec.exe') { throw 'Unexpected mocked executable.' }
    $index=[Array]::IndexOf($ArgumentList,'/L*v')
    if ($index -ge 0) { [IO.File]::WriteAllText($ArgumentList[$index+1].Trim('"'),$script:fixtureLog) }
    $process=[pscustomobject]@{ExitCode=$script:fixtureExit}
    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {param($timeout) return $true}
    return $process
}
$originalTemp=$env:RUNNER_TEMP
$originalSystemRoot=$env:SystemRoot
if (-not $env:SystemRoot) { $env:SystemRoot=[IO.Path]::GetTempPath() }
$env:RUNNER_TEMP=Join-Path ([IO.Path]::GetTempPath()) ('lw-acceptance-guards-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $env:RUNNER_TEMP | Out-Null
try {
    $fixturePackage=Join-Path $env:RUNNER_TEMP 'Lightwork fixture.msi'
    [IO.File]::WriteAllText($fixturePackage,'Not an MSI: process calls are mocked.')
    $packageExpectations=@{}
    $packageExpectations[$fixturePackage]=Resolve-AcceptanceMsi $fixturePackage '0.1.7'
    [xml]$fragment=Get-Content -Raw -LiteralPath (Join-Path $ScriptDirectory 'acceptance-failure.wxs')
    $fault=$fragment.SelectSingleNode('//*[local-name()="CustomAction"]')
    $errorMessage=$fault.GetAttribute('Error')
    $action=$fault.GetAttribute('Id')
    $completed="Action ended 12:34:56: $action. Return value 3."
    $valid="MSI (s) (00:00) [12:34:56:000]: Product: Lightwork -- $errorMessage`r`n$completed`r`n"
    foreach ($case in @(
        @{code=1618;log=$valid},
        @{code=0;log=$valid},
        @{code=3010;log=$valid},
        @{code=1603;log='Windows Installer failed before InstallFiles.'},
        @{code=1603;log=$errorMessage},
        @{code=1603;log=$completed},
        @{code=1603;log="$errorMessage`nAction ended 12:34:56: UnrelatedAction. Return value 3."}
    )) {
        $script:fixtureExit=$case.code; $script:fixtureLog=$case.log
        $rejected=$false
        try { Invoke-Msi $fixturePackage '/i' -ExpectFailure | Out-Null } catch { $rejected=$true }
        if (-not $rejected) { throw "Accepted an unproven injected failure: $($case.code), $($case.log)" }
    }
    $script:fixtureExit=1603; $script:fixtureLog=$valid
    Invoke-Msi $fixturePackage '/i' -ExpectFailure | Out-Null
    if ($script:called -ne 8) { throw 'MSI guard checks did not exercise the real acceptance function.' }

    # GitHub supplies GITHUB_WORKSPACE with backslashes, while workflow paths
    # append /customer-artifacts/Lightwork.msi. MSI rejects that mixed path
    # with error 1324/1619 even though PowerShell can access the same file.
    $mixedPackage=$env:RUNNER_TEMP + '/Lightwork fixture.msi'
    $script:fixtureExit=0
    $pathCases=0
    foreach ($source in @('test-customer.ps1','test-completed-rollback.ps1')) {
        Import-Function (Join-Path $ScriptDirectory $source) 'Invoke-Msi'
        Push-Location $env:RUNNER_TEMP
        try {
            foreach ($packageArgument in @($mixedPackage,'./Lightwork fixture.msi')) {
                foreach ($msiAction in @('/i','/fa','/x')) {
                    Invoke-Msi $packageArgument $msiAction | Out-Null
                    if ($script:lastArguments[1] -cne ('"'+$fixturePackage+'"')) { throw "MSI package path was not normalized and quoted: $($script:lastArguments[1])" }
                    if ($script:lastArguments[0] -ne $msiAction -or $script:lastArguments[2] -ne '/qn' -or $script:lastArguments[3] -ne '/norestart') { throw 'MSI path normalization changed maintenance arguments.' }
                    if ($source -eq 'test-customer.ps1' -and ($script:lastArguments.Count -ne 6 -or $script:lastArguments[4] -ne '/L*v')) { throw 'Customer MSI logging arguments changed.' }
                    $pathCases++
                }
            }
            foreach ($invalidPackage in @('./missing.msi',$env:RUNNER_TEMP)) {
                $before=$script:called;$rejected=$false
                try { Invoke-Msi $invalidPackage '/i' | Out-Null } catch { $rejected=$true }
                if (-not $rejected -or $script:called -ne $before) { throw 'Missing or directory package reached Windows Installer.' }
                $pathCases++
            }
        } finally { Pop-Location }
    }

    # Execute the real outer catch/finally, replacing only its installer call.
    # A cleanup failure must not replace the original acceptance error.
    $tokens=$null;$errors=$null
    $tree=[Management.Automation.Language.Parser]::ParseFile((Join-Path $ScriptDirectory 'test-customer.ps1'),[ref]$tokens,[ref]$errors)
    $outer=@($tree.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
    if ($outer.Count -ne 1 -or $outer[0].CatchClauses.Count -ne 1) { throw 'Expected one acceptance error-preservation boundary.' }
    function Invoke-Msi { param($Package,$Action,[switch]$ExpectFailure) throw 'Synthetic cleanup failure' }
    $Report=Join-Path $env:RUNNER_TEMP 'cleanup-report.json';$observed=@{synthetic=$true};$acceptanceError=$null
    $originalPath=$env:PATH;$originalHome=$env:MAVERICK_HOME;$originalNoIndex=$env:PIP_NO_INDEX
    $caught=$null
    try { Invoke-Expression ("try { throw 'Synthetic original installation failure' } " + $outer[0].CatchClauses[0].Extent.Text + ' finally ' + $outer[0].Finally.Extent.Text) } catch { $caught=$_.Exception.Message }
    if ($caught -ne 'Synthetic original installation failure') { throw "Cleanup hid the original acceptance error: $caught" }
    if (-not (Test-Path -LiteralPath $Report)) { throw 'Failed acceptance did not retain its report.' }

    # Every completed-rollback phase shares this boundary. Even simultaneous
    # stop/uninstall failures must retain the original error, both uninstall
    # attempts, environment restoration and the partial phase report.
    $tree=[Management.Automation.Language.Parser]::ParseFile((Join-Path $ScriptDirectory 'test-completed-rollback.ps1'),[ref]$tokens,[ref]$errors)
    $outer=@($tree.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
    if ($outer.Count -ne 1 -or $outer[0].CatchClauses.Count -ne 1) { throw 'Expected completed rollback error-preservation boundary.' }
    function Stop-Recovery { throw 'Synthetic owned-process cleanup failure' }
    function Invoke-Msi { param($Package,$Action) $script:cleanupAttempts++; throw 'Synthetic uninstall failure' }
    $originalEnvironment=@{}
    Get-ChildItem Env: | Where-Object { $_.Name -match '^(MAVERICK_|LIGHTWORK_)' } | ForEach-Object { $originalEnvironment[$_.Name]=$_.Value }
    foreach ($phase in @('base-install','start-recovery','maintenance-prepare','maintenance-execute','complete')) {
        $script:cleanupAttempts=0;$acceptanceError=$null;$observed=@{phase=$phase};$caught=$null
        $env:LIGHTWORK_ACCEPTANCE_GUARD_ONLY='temporary fixture value'
        try { Invoke-Expression ("try { throw 'Synthetic original acceptance failure' } " + $outer[0].CatchClauses[0].Extent.Text + ' finally ' + $outer[0].Finally.Extent.Text) } catch { $caught=$_.Exception.Message }
        if ($caught -ne 'Synthetic original acceptance failure' -or $script:cleanupAttempts -ne 2) { throw 'Completed rollback cleanup hid the original error or skipped a resource.' }
        $retained=Get-Content -Raw -LiteralPath $Report | ConvertFrom-Json
        if ($retained.phase -ne $phase -or $retained.cleanup_failures -ne 3 -or -not $retained.acceptance_failed) { throw 'Completed rollback partial evidence was not retained.' }
        if (Test-Path Env:LIGHTWORK_ACCEPTANCE_GUARD_ONLY) { throw 'Acceptance fixture environment was not restored.' }
    }
    $script:cleanupAttempts=0;$acceptanceError=$null;$observed=@{phase='complete'};$caught=$null
    try { Invoke-Expression ('try { } ' + $outer[0].CatchClauses[0].Extent.Text + ' finally ' + $outer[0].Finally.Extent.Text) } catch { $caught=$_.Exception.Message }
    if ($caught -ne 'Synthetic owned-process cleanup failure' -or $script:cleanupAttempts -ne 2) { throw 'Failed cleanup was reported as successful acceptance.' }

    Import-Function (Join-Path $ScriptDirectory 'test-completed-rollback.ps1') 'Assert-InstalledChannel'
    function Read-InstalledChannel { return $script:fixtureChannel }
    $expectedPublicKey='fixture-public-key'
    $script:fixtureChannel=@{version='1.2.3';public_key=$expectedPublicKey;packaged_runtime=$true}
    if ((Assert-InstalledChannel '1.2.3') -ne '1.2.3') { throw 'Exact installed version was not returned.' }
    foreach ($channel in @(
        @{version='1.2.3';public_key=$expectedPublicKey;packaged_runtime=$true},
        @{version='1.2.4';public_key='different-key';packaged_runtime=$true},
        @{version='1.2.4';public_key=$expectedPublicKey;packaged_runtime=$false},
        @{public_key=$expectedPublicKey;packaged_runtime=$true}
    )) {
        $script:fixtureChannel=$channel; $rejected=$false
        try { Assert-InstalledChannel '1.2.4' | Out-Null } catch { $rejected=$true }
        if (-not $rejected) { throw 'Accepted an incorrect installed native version/channel.' }
    }
    Write-Output "Acceptance guards: 8 MSI failure cases, $pathCases native package-path cases, original-error preservation and 5 native channel cases passed."
} finally {
    # Only flat log files written by the mocked process above.
    Get-ChildItem -LiteralPath $env:RUNNER_TEMP -File | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
    Remove-Item -LiteralPath $env:RUNNER_TEMP
    $env:RUNNER_TEMP=$originalTemp
    $env:SystemRoot=$originalSystemRoot
}
