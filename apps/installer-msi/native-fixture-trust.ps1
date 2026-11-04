param(
    [Parameter(Mandatory=$true)][ValidateSet('trust','cleanup','verify-driver')][string]$Phase,
    [Parameter(Mandatory=$true)][string]$FixtureDirectory,
    [string]$Thumbprint
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_JOB -ne 'build-and-accept') {
    throw 'Native fixture trust requires the disposable GitHub-hosted acceptance job.'
}
$fixture = Get-Item -LiteralPath $FixtureDirectory
$runner = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
if (-not $fixture.PSIsContainer -or $fixture.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    -not $fixture.FullName.StartsWith($runner, [StringComparison]::OrdinalIgnoreCase) -or
    $fixture.Name -notmatch '^native-webview-[a-f0-9]{32}$') { throw 'Invalid native acceptance fixture directory.' }
if ($Phase -eq 'verify-driver') {
    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $fixture.FullName 'msedgedriver.exe')
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|, )O=Microsoft Corporation(,|$)') {
        throw 'The exact-version WebView driver is not signed by Microsoft.'
    }
} else {
    if ($Thumbprint -notmatch '^[a-fA-F0-9]{40}$') { throw 'Invalid fixture TLS identity.' }
    $publicFile = Join-Path $fixture.FullName 'tls.cer'
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($publicFile)
    if ($certificate.Thumbprint -ne $Thumbprint -or $certificate.Subject -ne ('CN=' + $fixture.Name)) { throw 'Fixture TLS identity changed.' }
    if ($Phase -eq 'trust') {
        Import-Certificate -FilePath $publicFile -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    } else {
        $path = 'Cert:\LocalMachine\Root\' + $Thumbprint
        $stored = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($stored) {
            if ($stored.Subject -ne $certificate.Subject) { throw 'Refusing unrelated TLS trust cleanup.' }
            Remove-Item -LiteralPath $path
        }
    }
}
Write-Host "Native fixture: $Phase completed."
