[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallDirectory,
    [string]$Repository = "dpsyfk/lens",
    [string]$ReleaseMetadataPath,
    [switch]$Preview,
    [switch]$SkipSignatureCheck,
    [switch]$SkipCommandCheck,
    [switch]$NoPathUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "This installer supports Windows only. Use the release archive documented in docs/INSTALL.md on macOS or Linux."
}

$architecture = if ($env:PROCESSOR_ARCHITEW6432) {
    $env:PROCESSOR_ARCHITEW6432
} else {
    $env:PROCESSOR_ARCHITECTURE
}
if ($architecture -ne "AMD64") {
    throw "Lens currently publishes a Windows x64 binary; this machine reports '$architecture'."
}

$testing = $env:LENS_INSTALLER_TESTING -eq "1"
if (($SkipSignatureCheck -or $SkipCommandCheck -or $NoPathUpdate -or $ReleaseMetadataPath) -and -not $testing) {
    throw "Installer test options require LENS_INSTALLER_TESTING=1."
}

if ([string]::IsNullOrWhiteSpace($InstallDirectory)) {
    $localPrograms = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "Programs"
    $InstallDirectory = Join-Path $localPrograms "Lens\bin"
}
$InstallDirectory = [IO.Path]::GetFullPath($InstallDirectory)

function Save-LensAsset {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][hashtable]$Headers
    )

    if ($testing -and [IO.Path]::IsPathRooted($Source)) {
        Copy-Item -LiteralPath $Source -Destination $Destination
        return
    }

    $previousProgress = $ProgressPreference
    try {
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -UseBasicParsing -Headers $Headers -Uri $Source -OutFile $Destination
    } finally {
        $ProgressPreference = $previousProgress
    }
}

function Add-LensPathEntry {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $normalized = $Directory.TrimEnd("\")
    $currentEntries = @($env:Path -split ";" | ForEach-Object { $_.Trim().Trim('"').TrimEnd("\") })
    if (-not ($currentEntries | Where-Object { $_ -ieq $normalized })) {
        $env:Path = if ([string]::IsNullOrWhiteSpace($env:Path)) { $Directory } else { "$Directory;$env:Path" }
    }

    if ($NoPathUpdate) {
        return
    }

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $userEntries = @($userPath -split ";" | ForEach-Object { $_.Trim().Trim('"').TrimEnd("\") })
    if (-not ($userEntries | Where-Object { $_ -ieq $normalized })) {
        $updatedPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $Directory } else { "$Directory;$userPath" }
        [Environment]::SetEnvironmentVariable("Path", $updatedPath, "User")
    }
}

$headers = @{
    Accept = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent" = "lens-installer"
}

if ($ReleaseMetadataPath) {
    $release = Get-Content -LiteralPath $ReleaseMetadataPath -Raw | ConvertFrom-Json
} else {
    $apiRoot = "https://api.github.com/repos/$Repository/releases"
    if ($Preview -and [string]::IsNullOrWhiteSpace($Version)) {
        $releaseUri = "${apiRoot}?per_page=50"
    } elseif ([string]::IsNullOrWhiteSpace($Version)) {
        $releaseUri = "$apiRoot/latest"
    } else {
        $tag = if ($Preview) {
            if ($Version.StartsWith("preview-v")) { $Version } else { "preview-v$Version" }
        } else {
            if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
        }
        $releaseUri = "$apiRoot/tags/$([Uri]::EscapeDataString($tag))"
    }

    try {
        $response = Invoke-RestMethod -UseBasicParsing -Headers $headers -Uri $releaseUri
    } catch {
        $responseProperty = $_.Exception.PSObject.Properties["Response"]
        if ($responseProperty -and $responseProperty.Value -and [int]$responseProperty.Value.StatusCode -eq 404) {
            throw "No published Lens release was found. Check https://github.com/$Repository/releases and try again after a release is published."
        }
        throw
    }

    if ($Preview -and [string]::IsNullOrWhiteSpace($Version)) {
        $matchingReleases = @($response | Where-Object {
                -not $_.draft -and $_.prerelease -and $_.tag_name -match '^preview-v\d+\.\d+\.\d+-preview\.\d+$'
            } | Select-Object -First 1)
        if ($matchingReleases.Count -eq 0) {
            throw "No published Lens preview was found. Check https://github.com/$Repository/releases."
        }
        $release = $matchingReleases[0]
    } else {
        $release = $response
    }
}

if ($release.draft) {
    throw "Refusing to install from a draft release."
}
if ($Preview) {
    if (-not $release.prerelease -or $release.tag_name -notmatch '^preview-v\d+\.\d+\.\d+-preview\.\d+$') {
        throw "Preview installation requires a published preview-vVERSION-preview.NUMBER prerelease."
    }
} elseif ($release.prerelease) {
    throw "Stable installation refuses prerelease artifacts; use -Preview explicitly."
}

$archivePattern = '^lens-.+-x86_64-pc-windows-msvc\.zip$'
$archiveAssets = @($release.assets | Where-Object { $_.name -match $archivePattern })
$checksumAssets = @($release.assets | Where-Object { $_.name -eq "SHA256SUMS" })
if ($archiveAssets.Count -ne 1) {
    throw "Release '$($release.tag_name)' must contain exactly one Windows x64 Lens archive."
}
if ($checksumAssets.Count -ne 1) {
    throw "Release '$($release.tag_name)' must contain SHA256SUMS."
}
$archiveAsset = $archiveAssets[0]
$checksumAsset = $checksumAssets[0]

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("lens-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

try {
    $archivePath = Join-Path $temporaryDirectory $archiveAsset.name
    $checksumPath = Join-Path $temporaryDirectory "SHA256SUMS"
    Save-LensAsset -Source $archiveAsset.browser_download_url -Destination $archivePath -Headers $headers
    Save-LensAsset -Source $checksumAsset.browser_download_url -Destination $checksumPath -Headers $headers

    $checksumPattern = '^(?<hash>[a-fA-F0-9]{64})\s+\*?' + [Regex]::Escape($archiveAsset.name) + '$'
    $expectedHash = $null
    foreach ($line in Get-Content -LiteralPath $checksumPath) {
        $match = [Regex]::Match($line.Trim(), $checksumPattern)
        if ($match.Success) {
            if ($expectedHash) {
                throw "SHA256SUMS contains more than one entry for '$($archiveAsset.name)'."
            }
            $expectedHash = $match.Groups["hash"].Value.ToLowerInvariant()
        }
    }
    if (-not $expectedHash) {
        throw "SHA256SUMS does not contain '$($archiveAsset.name)'."
    }

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "Checksum verification failed for '$($archiveAsset.name)'."
    }

    $expandedDirectory = Join-Path $temporaryDirectory "expanded"
    Expand-Archive -LiteralPath $archivePath -DestinationPath $expandedDirectory
    $binaries = @(Get-ChildItem -LiteralPath $expandedDirectory -Recurse -File -Filter "lens.exe")
    if ($binaries.Count -ne 1) {
        throw "The release archive must contain exactly one lens.exe."
    }
    $sourceBinary = $binaries[0].FullName

    if ($Preview) {
        Write-Warning "Installing unsigned Lens development preview '$($release.tag_name)'. Use it only on a development machine."
    } elseif (-not $SkipSignatureCheck) {
        $signature = Get-AuthenticodeSignature -FilePath $sourceBinary
        if ($signature.Status -ne "Valid") {
            throw "Authenticode verification failed: $($signature.Status) - $($signature.StatusMessage)"
        }
    }

    if (-not $SkipCommandCheck) {
        $versionOutput = @(& $sourceBinary --version 2>&1)
        if ($LASTEXITCODE -ne 0 -or ($versionOutput -join "`n") -notmatch '^lens\s+\S+') {
            throw "The downloaded binary did not pass 'lens --version'."
        }
    }

    New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
    $destination = Join-Path $InstallDirectory "lens.exe"
    $replacement = Join-Path $InstallDirectory "lens.exe.new"
    $previous = Join-Path $InstallDirectory "lens.exe.previous"

    $alreadyInstalled = (Test-Path -LiteralPath $destination) -and
        ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -eq
            (Get-FileHash -LiteralPath $sourceBinary -Algorithm SHA256).Hash.ToLowerInvariant())

    if (-not $alreadyInstalled) {
        Copy-Item -LiteralPath $sourceBinary -Destination $replacement -Force
        try {
            if (Test-Path -LiteralPath $previous) {
                Remove-Item -LiteralPath $previous -Force
            }
            if (Test-Path -LiteralPath $destination) {
                Move-Item -LiteralPath $destination -Destination $previous
            }
            Move-Item -LiteralPath $replacement -Destination $destination
        } catch {
            if (Test-Path -LiteralPath $replacement) {
                Remove-Item -LiteralPath $replacement -Force
            }
            if ((Test-Path -LiteralPath $previous) -and -not (Test-Path -LiteralPath $destination)) {
                Move-Item -LiteralPath $previous -Destination $destination
            }
            throw
        }
    }

    Add-LensPathEntry -Directory $InstallDirectory

    $action = if ($alreadyInstalled) { "Lens is already up to date" } elseif (Test-Path -LiteralPath $previous) { "Updated Lens" } else { "Installed Lens" }
    Write-Host "$action ($($release.tag_name)) at $destination"
    Write-Host "Run 'lens doctor --check all', then 'lens run --listen 127.0.0.1:8888'."
} finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
