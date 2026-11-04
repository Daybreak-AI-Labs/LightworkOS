# Full Windows desktop package. Run on a Windows build host, never on the
# user's computer. The engineering build.ps1 remains a separate artifact.
param(
    [Parameter(Mandatory = $true)][string]$Runtime,
    [Parameter(Mandatory = $true)][string]$PublicKeyFile,
    [Parameter(Mandatory = $true)][string]$UpdateEndpoint,
    [Parameter(Mandatory = $true)][string]$StageDirectory,
    [string]$Python = 'python',
    [string]$AcceptanceFixtureVersion = '',
    [switch]$InjectAcceptanceFailure
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$stageArgs = @((Join-Path $PSScriptRoot 'stage_customer.py'), '--runtime', $Runtime,
    '--output', $StageDirectory, '--endpoint', $UpdateEndpoint, '--public-key-file', $PublicKeyFile)
if ($AcceptanceFixtureVersion) {
    $stageArgs += @('--acceptance-fixture-version', $AcceptanceFixtureVersion)
}
if ($InjectAcceptanceFailure) {
    if (-not $AcceptanceFixtureVersion) { throw 'Fault injection requires an acceptance fixture version.' }
    $stageArgs += @('--acceptance-fault-fragment', (Join-Path $PSScriptRoot 'acceptance-failure.wxs'))
}
& $Python @stageArgs
if ($LASTEXITCODE -ne 0) { throw 'Customer runtime staging failed.' }
$config = (Resolve-Path -LiteralPath (Join-Path $StageDirectory 'tauri.customer.json')).Path
$cli = Join-Path $repoRoot 'apps/installer-desktop/node_modules/@tauri-apps/cli/tauri.js'
if (-not (Test-Path -LiteralPath $cli)) { throw 'Install the locked installer-desktop build dependencies before building.' }
Push-Location (Join-Path $repoRoot 'apps/desktop')
try {
    # --verbose surfaces the WiX candle/light output; without it a linker or
    # ICE validation failure only reports "failed to run light.exe".
    & node $cli build --verbose --target x86_64-pc-windows-msvc --config $config --bundles msi --features customer-runtime -- --locked
    if ($LASTEXITCODE -ne 0) { throw 'Customer desktop packaging failed.' }
} finally { Pop-Location }
Write-Host 'Built the complete release candidate. Publisher signing and Windows acceptance must pass before distribution.'
