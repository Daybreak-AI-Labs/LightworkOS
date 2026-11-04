# Build the Lightwork CLI MSI with WiX Toolset v4.
#
# Requires (Windows host):
#   * .NET SDK + WiX v4 CLI:  dotnet tool install --global wix
#   * a built maverick-agent wheel:
#       python -m pip install build
#       python -m build --wheel packages/maverick-core   # writes packages/maverick-core/dist/
#
# Usage (from this directory):
#   .\build.ps1 -Wheel ..\..\packages\maverick-core\dist\maverick_agent-<version>-py3-none-any.whl
#
# The output MSI is UNSIGNED (same posture as apps/installer-desktop).
param(
    [Parameter(Mandatory = $true)][string]$Wheel,
    [string]$Version = "",
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $cohortPath = Join-Path $PSScriptRoot "..\..\release-cohort.toml"
    $versionLine = Select-String `
        -Path $cohortPath `
        -Pattern '^version\s*=\s*"([^"]+)"\s*$' |
        Select-Object -First 1
    if ($null -eq $versionLine) {
        throw "release-cohort.toml does not declare a version"
    }
    $Version = $versionLine.Matches[0].Groups[1].Value
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "MSI version must be a three-part numeric release version, got: $Version"
}

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw "WiX v4 CLI not found. Install it with: dotnet tool install --global wix"
}
if (-not (Test-Path $Wheel)) {
    throw "wheel not found: $Wheel (build it with `python -m build --wheel packages/maverick-core`)"
}

$wheelPath = (Resolve-Path $Wheel).Path
$wheelName = [System.IO.Path]::GetFileName($wheelPath)
$wheelPattern = '^maverick_agent-(?<version>[^-]+)(?:-(?<build>\d[^-]*))?-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl$'
if ($wheelName -notmatch $wheelPattern) {
    throw "wheel filename is not a valid maverick-agent PEP 427 name: $wheelName"
}
if ($Matches["version"] -ne $Version) {
    throw "wheel version $($Matches["version"]) does not match MSI version $Version"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$msi = Join-Path $OutDir "maverick-cli-$Version.msi"

wix build "$PSScriptRoot\Package.wxs" `
    -d ProductVersion=$Version `
    -d WheelPath=$wheelPath `
    -d WheelName=$wheelName `
    -arch x64 `
    -o $msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }

Write-Host "Wrote $msi"
Write-Host "NOTE: this MSI is UNSIGNED. SmartScreen will warn until a code-signing cert exists."
