# Run only in the protected customer signing job, after all build commands.
# No key generation or unsigned fallback exists on this path.
param(
    [Parameter(Mandatory = $true)][string]$Msi,
    [Parameter(Mandatory = $true)][string]$CertificateThumbprint,
    [Parameter(Mandatory = $true)][string]$TimestampServer,
    [Parameter(Mandatory = $true)][string]$TauriCli
)
$ErrorActionPreference = 'Stop'
if ($CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw 'A reviewed Authenticode certificate thumbprint is required.' }
$timestamp = [uri]$TimestampServer
if ($timestamp.Scheme -ne 'https' -or $timestamp.UserInfo -or $timestamp.Fragment) { throw 'Timestamp service must use HTTPS without credentials.' }
$certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $CertificateThumbprint)
if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le (Get-Date) -or
    $certificate.EnhancedKeyUsageList.ObjectId -notcontains '1.3.6.1.5.5.7.3.3') { throw 'A current code-signing certificate with its private key is required.' }
if ([IO.Path]::GetExtension($Msi) -ne '.msi' -or -not (Test-Path -LiteralPath $Msi -PathType Leaf)) { throw 'Expected a customer MSI.' }
if (-not $env:TAURI_SIGNING_PRIVATE_KEY) { throw 'The dedicated updater signing key is unavailable.' }
$signature = Set-AuthenticodeSignature -LiteralPath $Msi -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint) { throw 'The Windows publisher signature did not validate.' }
& node $TauriCli signer sign $Msi
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath ($Msi + '.sig'))) { throw 'Updater artifact signing failed.' }
$verified = Get-AuthenticodeSignature -LiteralPath $Msi
if ($verified.Status -ne 'Valid' -or $verified.SignerCertificate.Thumbprint -ne $CertificateThumbprint) { throw 'Signed installer bytes changed during updater signing.' }
Write-Host 'Windows publisher signature verified; separate updater signature written.'
