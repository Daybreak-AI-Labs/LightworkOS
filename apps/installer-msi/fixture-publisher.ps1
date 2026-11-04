param(
    [Parameter(Mandatory=$true)][ValidateSet('create','trust','sign-base','sign-next','cleanup')][string]$Phase,
    [Parameter(Mandatory=$true)][string]$FixtureDirectory
)
$ErrorActionPreference = 'Stop'
# This helper is exclusively for the disposable GitHub-hosted acceptance VM.
# It must never change certificate trust on a workstation or release signer.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_JOB -ne 'build-and-accept') {
    throw 'Fixture publisher requires the disposable GitHub-hosted acceptance job.'
}
$fixture = Get-Item -LiteralPath $FixtureDirectory
$runner = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
if (-not $fixture.PSIsContainer -or $fixture.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    -not $fixture.FullName.StartsWith($runner, [StringComparison]::OrdinalIgnoreCase) -or
    $fixture.Name -notmatch '^rollback-signed-[a-f0-9]{32}$') {
    throw 'Invalid disposable fixture directory.'
}
$subject = 'CN=Lightwork disposable CI fixture ' + $fixture.Name.Substring(16)
$identity = Join-Path $fixture.FullName 'publisher-thumbprint.txt'
Write-Host "Fixture publisher: $Phase started."
if ($Phase -eq 'create') {
    if (Test-Path -LiteralPath $identity) { throw 'Fixture publisher already exists.' }
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
        -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddDays(2) `
        -KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider' `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256
    [IO.File]::WriteAllText($identity, $certificate.Thumbprint)
    Export-Certificate -Cert $certificate -FilePath (Join-Path $fixture.FullName 'fixture.cer') | Out-Null
} else {
    $thumbprint = [IO.File]::ReadAllText($identity).Trim()
    if ($thumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Invalid fixture publisher identity.' }
    $certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $thumbprint) -ErrorAction SilentlyContinue
    if ($certificate -and $certificate.Subject -ne $subject) { throw 'Fixture publisher identity changed.' }
    if ($Phase -eq 'cleanup') {
        # Attempt every exact fixture identity even if one store removal fails.
        $cleanupErrors = @()
        foreach ($store in @('LocalMachine\Root','LocalMachine\TrustedPublisher','CurrentUser\My')) {
            $path = 'Cert:\' + $store + '\' + $thumbprint
            try {
                $stored = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
                if ($stored) {
                    if ($stored.Subject -ne $subject) { throw 'Refusing to remove an unrelated certificate.' }
                    if ($store -eq 'CurrentUser\My') { Remove-Item -LiteralPath $path -DeleteKey }
                    else { Remove-Item -LiteralPath $path }
                }
            } catch { $cleanupErrors += $_ }
        }
        if ($cleanupErrors.Count) { throw $cleanupErrors[0] }
    } elseif ($Phase -eq 'trust') {
        if (-not $certificate) { throw 'Fixture publisher was not created.' }
        # The hosted VM is elevated and discarded after this job. Machine stores
        # avoid the interactive per-user root-trust UI in unattended acceptance.
        foreach ($store in @('Root','TrustedPublisher')) {
            Write-Host "Fixture publisher: importing into disposable machine $store store."
            Import-Certificate -FilePath (Join-Path $fixture.FullName 'fixture.cer') -CertStoreLocation ('Cert:\LocalMachine\' + $store) | Out-Null
        }
    } else {
        if (-not $certificate) { throw 'Fixture publisher was not created.' }
        $package = Join-Path $fixture.FullName ($(if ($Phase -eq 'sign-base') { 'base.msi' } else { 'next.msi' }))
        $signTool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' | Sort-Object FullName -Descending | Select-Object -First 1
        if (-not $signTool) { throw 'Windows SDK signing tool unavailable for fixture acceptance.' }
        & $signTool.FullName sign /fd SHA256 /sha1 $thumbprint $package
        if ($LASTEXITCODE -ne 0) { throw 'Disposable publisher signing failed.' }
        $signature = Get-AuthenticodeSignature -LiteralPath $package
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $thumbprint) {
            throw 'Disposable publisher signature did not verify.'
        }
        Set-Item -LiteralPath Env:TAURI_SIGNING_PRIVATE_KEY -Value (Get-Content -Raw -LiteralPath $env:ACCEPTANCE_PRIVATE_KEY)
        try {
            node apps/installer-desktop/node_modules/@tauri-apps/cli/tauri.js signer sign --password "" $package
            if ($LASTEXITCODE -ne 0) { throw 'Disposable updater signing failed.' }
        } finally { Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY -ErrorAction SilentlyContinue }
    }
}
Write-Host "Fixture publisher: $Phase completed."
