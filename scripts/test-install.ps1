$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("lens-installer-test-" + [Guid]::NewGuid().ToString("N"))
$originalPath = $env:Path
$originalTesting = $env:LENS_INSTALLER_TESTING

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $packageRoot = Join-Path $temporaryRoot "lens-0.1.0-x86_64-pc-windows-msvc"
    New-Item -ItemType Directory -Path $packageRoot | Out-Null
    Copy-Item -LiteralPath "$env:WINDIR\System32\where.exe" -Destination (Join-Path $packageRoot "lens.exe")

    $archive = Join-Path $temporaryRoot "lens-0.1.0-x86_64-pc-windows-msvc.zip"
    Compress-Archive -LiteralPath $packageRoot -DestinationPath $archive
    $checksum = Join-Path $temporaryRoot "SHA256SUMS"
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath $checksum -Value "$hash  $(Split-Path -Leaf $archive)" -Encoding ascii

    $metadata = @{
        tag_name = "v0.1.0"
        draft = $false
        prerelease = $false
        assets = @(
            @{ name = (Split-Path -Leaf $archive); browser_download_url = $archive },
            @{ name = "SHA256SUMS"; browser_download_url = $checksum }
        )
    }
    $metadataPath = Join-Path $temporaryRoot "release.json"
    $metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $metadataPath -Encoding utf8

    $installDirectory = Join-Path $temporaryRoot "installed"
    $env:LENS_INSTALLER_TESTING = "1"
    & (Join-Path $repositoryRoot "install.ps1") `
        -ReleaseMetadataPath $metadataPath `
        -InstallDirectory $installDirectory `
        -SkipCommandCheck `
        -NoPathUpdate

    $installed = Join-Path $installDirectory "lens.exe"
    if (-not (Test-Path -LiteralPath $installed)) {
        throw "installer did not create lens.exe"
    }
    if (($env:Path -split ";")[0] -ine $installDirectory) {
        throw "installer did not add Lens to the current process PATH"
    }

    $previewRejectedStable = $false
    try {
        & (Join-Path $repositoryRoot "install.ps1") `
            -ReleaseMetadataPath $metadataPath `
            -InstallDirectory $installDirectory `
            -Preview `
            -SkipCommandCheck `
            -NoPathUpdate
    } catch {
        $previewRejectedStable = $_.Exception.Message -match "Preview installation requires"
    }
    if (-not $previewRejectedStable) {
        throw "preview mode accepted a stable release"
    }

    $previewMetadata = @{
        tag_name = "preview-v0.1.0-preview.1"
        draft = $false
        prerelease = $true
        assets = $metadata.assets
    }
    $previewMetadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $metadataPath -Encoding utf8

    $stableRejectedPreview = $false
    try {
        & (Join-Path $repositoryRoot "install.ps1") `
            -ReleaseMetadataPath $metadataPath `
            -InstallDirectory $installDirectory `
            -SkipCommandCheck `
            -NoPathUpdate
    } catch {
        $stableRejectedPreview = $_.Exception.Message -match "Stable installation refuses prerelease"
    }
    if (-not $stableRejectedPreview) {
        throw "stable mode accepted an unsigned preview release"
    }

    & (Join-Path $repositoryRoot "install.ps1") `
        -ReleaseMetadataPath $metadataPath `
        -InstallDirectory $installDirectory `
        -Preview `
        -SkipCommandCheck `
        -NoPathUpdate

    $metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $metadataPath -Encoding utf8

    & (Join-Path $repositoryRoot "install.ps1") `
        -ReleaseMetadataPath $metadataPath `
        -InstallDirectory $installDirectory `
        -SkipCommandCheck `
        -NoPathUpdate

    if (Test-Path -LiteralPath (Join-Path $installDirectory "lens.exe.previous")) {
        throw "idempotent reinstall unexpectedly created a rollback binary"
    }

    $firstHash = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash
    Copy-Item -LiteralPath "$env:WINDIR\System32\find.exe" -Destination (Join-Path $packageRoot "lens.exe") -Force
    Compress-Archive -LiteralPath $packageRoot -DestinationPath $archive -Force
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath $checksum -Value "$hash  $(Split-Path -Leaf $archive)" -Encoding ascii

    & (Join-Path $repositoryRoot "install.ps1") `
        -ReleaseMetadataPath $metadataPath `
        -InstallDirectory $installDirectory `
        -SkipCommandCheck `
        -NoPathUpdate

    $previous = Join-Path $installDirectory "lens.exe.previous"
    if (-not (Test-Path -LiteralPath $previous)) {
        throw "upgrade did not retain the previous binary"
    }
    if ((Get-FileHash -LiteralPath $previous -Algorithm SHA256).Hash -ne $firstHash) {
        throw "rollback binary does not match the replaced installation"
    }
    $upgradedHash = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash
    if ($upgradedHash -eq $firstHash) {
        throw "upgrade did not replace lens.exe"
    }

    Set-Content -LiteralPath $checksum -Value "$('0' * 64)  $(Split-Path -Leaf $archive)" -Encoding ascii
    $checksumRejected = $false
    try {
        & (Join-Path $repositoryRoot "install.ps1") `
            -ReleaseMetadataPath $metadataPath `
            -InstallDirectory $installDirectory `
            -SkipCommandCheck `
            -NoPathUpdate
    } catch {
        $checksumRejected = $_.Exception.Message -match "Checksum verification failed"
    }
    if (-not $checksumRejected) {
        throw "installer accepted an invalid checksum"
    }
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $upgradedHash) {
        throw "failed verification changed the installed binary"
    }

    Write-Host "Windows installer smoke test passed"
} finally {
    $env:Path = $originalPath
    $env:LENS_INSTALLER_TESTING = $originalTesting
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
