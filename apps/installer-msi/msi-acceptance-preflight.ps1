# Read-only package admission for disposable acceptance. This is not publisher
# verification: signed customer maintenance retains its independent trust gate.
function Read-AcceptanceMsiProperties([string]$Package) {
    $engine=$null; $database=$null
    try {
        # Match the existing windows_installer_verification read-only COM query.
        $engine=New-Object -ComObject WindowsInstaller.Installer
        $database=$engine.OpenDatabase($Package,0)
        $properties=@{}
        foreach ($name in @('ProductName','ProductVersion','UpgradeCode')) {
            $view=$null; $record=$null
            try {
                $view=$database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = '''+$name+'''')
                $view.Execute(); $record=$view.Fetch()
                if (-not $record) {throw "Required MSI property $name is missing."}
                $properties[$name]=$record.StringData(1)
            } finally {
                if ($record) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)}
                if ($view) {$view.Close(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}
            }
        }
        return $properties
    } finally {
        if ($database) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)}
        if ($engine) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine)}
    }
}

function Resolve-AcceptanceMsi([string]$Package,[string]$ExpectedVersion,[string]$ExpectedSha256='') {
    $resolved=$Package; $stream=$null; $hasher=$null
    try {
        $resolved=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Package)
        if ($resolved -match '["\r\n]') {throw 'The package path contains unsupported native argument characters.'}
        $file=Get-Item -LiteralPath $resolved -ErrorAction Stop
        if ($file.PSProvider.Name -ne 'FileSystem' -or $file.PSIsContainer -or $file.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {throw 'Expected a regular MSI file.'}
        $resolved=[IO.Path]::GetFullPath($file.FullName)
        # An exclusive writer, inaccessible file or empty input must fail here,
        # before COM inspection and before any native installer process exists.
        $stream=[IO.File]::Open($resolved,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        # Existing maintenance/release policy: windows_installer_verification.py
        # MAX_INSTALLER_BYTES and release_acceptance.py expanded MSI limit.
        if ($stream.Length -lt 1 -or $stream.Length -gt 1GB) {throw 'MSI size must be between 1 byte and 1 GiB.'}
        $hasher=[Security.Cryptography.SHA256]::Create()
        $hash=([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-','').ToLowerInvariant()
        if ($ExpectedSha256 -and $hash -cne $ExpectedSha256) {throw 'MSI SHA-256 differs from the admitted package bytes.'}
        $properties=Read-AcceptanceMsiProperties $resolved
        if ($properties.ProductName -cne 'Lightwork Desktop') {throw 'MSI ProductName must be Lightwork Desktop.'}
        if ([string]$properties.UpgradeCode -notmatch '^(AB5BC260-7EC9-4B70-AF78-28F4067BC530|\{AB5BC260-7EC9-4B70-AF78-28F4067BC530\})$') {throw 'MSI UpgradeCode differs from the supported customer product.'}
        if ($ExpectedVersion -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$' -or $properties.ProductVersion -cne $ExpectedVersion) {throw "MSI ProductVersion differs from expected version $ExpectedVersion."}
        return @{path=$resolved;sha256=$hash;bytes=$stream.Length;version=$properties.ProductVersion;product_name=$properties.ProductName;upgrade_code=$properties.UpgradeCode}
    } catch {
        throw "MSI preflight failed for '$resolved': $($_.Exception.Message) Windows Installer was not started for this attempt; no installer log was created for this attempt."
    } finally {
        if ($hasher) {$hasher.Dispose()}
        if ($stream) {$stream.Dispose()}
    }
}

function Confirm-AcceptanceMsi([string]$Package,$Expectations) {
    $resolved=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Package)
    if (-not $Expectations -or -not $Expectations.ContainsKey($resolved)) {throw "MSI preflight failed for '$resolved': package is not in the admitted inventory. Windows Installer was not started for this attempt; no installer log was created for this attempt."}
    $expected=$Expectations[$resolved]
    return Resolve-AcceptanceMsi $resolved $expected.version $expected.sha256
}

function Read-AcceptanceInventory([string]$Inventory) {
    $resolved=$Inventory
    try {
        $resolved=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Inventory)
        $file=Get-Item -LiteralPath $resolved -ErrorAction Stop
        if ($file.PSProvider.Name -ne 'FileSystem' -or $file.PSIsContainer -or $file.Length -lt 1 -or $file.Length -gt 1MB -or $file.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {throw 'Expected a nonempty bounded runtime inventory file.'}
        $bytes=[IO.File]::ReadAllBytes($resolved)
        $metadata=[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
        $expected=@('maverick-agent','maverick-shield','maverick-channels','maverick-evolve','maverick-dashboard','maverick-mcp-server','maverick-knowledge','maverick-installer')
        $packages=@($metadata.packages | ForEach-Object {$_.distribution})
        if ($metadata.schema -cne 'lightwork.windows-customer-build.v1' -or
            $metadata.complete_release_cohort -isnot [bool] -or -not $metadata.complete_release_cohort -or
            $metadata.acceptance_fixture -isnot [bool] -or
            $metadata.publisher_signature_verified -isnot [bool] -or $metadata.publisher_signature_verified -or
            $metadata.requires_customer_python -isnot [bool] -or $metadata.requires_customer_python -or
            $metadata.requires_customer_git -isnot [bool] -or $metadata.requires_customer_git -or
            $packages.Count -ne 8 -or @($packages | Select-Object -Unique).Count -ne 8 -or
            @(Compare-Object ($expected | Sort-Object) ($packages | Sort-Object) -CaseSensitive).Count) {throw 'The inventory is not the complete unsigned staging contract; publisher acceptance cannot be inferred.'}
        foreach ($version in @($metadata.version,$metadata.cohort_version)) {
            if ($version -isnot [string] -or $version -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {throw 'The inventory requires exact three-part versions.'}
            $parsed=[version]$version
            if ($parsed.Major -gt 255 -or $parsed.Minor -gt 255 -or $parsed.Build -ge 65535) {throw 'The inventory version cannot support its next-patch MSI fixture.'}
        }
        if (-not $metadata.acceptance_fixture -and $metadata.version -cne $metadata.cohort_version) {throw 'A customer inventory cannot relabel the release cohort.'}
        $recovery=@{
            runtime='maverick-recovery.exe'
            native_shell='maverick-recovery-desktop.exe'
            signed_installer='Lightwork-recovery.msi'
            start_menu='Repair Lightwork'
        }
        if (-not $metadata.installed_recovery -or @($metadata.installed_recovery.PSObject.Properties).Count -ne $recovery.Count) {
            throw 'The inventory must declare the complete installed recovery set.'
        }
        foreach ($name in $recovery.Keys) {
            if ($metadata.installed_recovery.$name -cne $recovery[$name]) {
                throw 'The inventory contains an unexpected installed recovery artifact.'
            }
        }
        # Same runtime/inventory bounds as release_acceptance.py validate_bundle.
        if ($metadata.runtime.sha256 -isnot [string] -or $metadata.runtime.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            ($metadata.runtime.bytes -isnot [int] -and $metadata.runtime.bytes -isnot [long]) -or $metadata.runtime.bytes -lt 1 -or $metadata.runtime.bytes -gt 1GB) {throw 'The runtime inventory requires its exact bounded executable size and SHA-256.'}
        $hasher=[Security.Cryptography.SHA256]::Create()
        try {$hash=([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()} finally {$hasher.Dispose()}
        return @{path=$resolved;sha256=$hash;metadata=$metadata}
    } catch {throw "Inventory preflight failed for '$resolved': $($_.Exception.Message) Windows Installer was not started for this attempt; no installer log was created for this attempt."}
}

function Initialize-AcceptancePreflight([string]$BaseMsi,[string]$CandidateMsi,[string]$Inventory,[string]$Report,[string]$Schema) {
    $observed=[ordered]@{schema=$Schema;clean_virtual_machine=$false;publicly_recognized_publisher=$false;publisher_signature_verified=$false;production_publisher_acceptance=$false;synthetic_fixture_versions=$true;same_frozen_runtime_fixture=$true;native_webview_automated=$false;preflight='pending'}
    try {
        $inputInventory=Read-AcceptanceInventory $Inventory
        $metadata=$inputInventory.metadata
        $version=[version]$metadata.version
        $next='{0}.{1}.{2}' -f $version.Major,$version.Minor,($version.Build+1)
        $base=Resolve-AcceptanceMsi $BaseMsi $metadata.version
        $candidate=Resolve-AcceptanceMsi $CandidateMsi $next
        $observed.preflight='passed'
        $observed.inputs=@{inventory_path=$inputInventory.path;inventory_sha256=$inputInventory.sha256;base=$base;candidate=$candidate;base_acceptance_fixture=$metadata.acceptance_fixture;runtime=$metadata.runtime}
        $expectations=@{}; $expectations[$base.path]=$base; $expectations[$candidate.path]=$candidate
        return @{metadata=$metadata;report=$observed;expectations=$expectations}
    } catch {
        $observed.preflight='failed'; $observed.acceptance_failed=$true; $observed.failure=$_.Exception.Message
        try {$observed | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Report -Encoding utf8} catch {Write-Warning 'Preflight report could not be saved; the original diagnostic is retained.'}
        throw
    }
}
