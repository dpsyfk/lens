# Installing Lens v0.1

Lens v0.1 will be distributed as signed release archives for Windows, macOS, and Linux after the release gate passes. No signed public v0.1 release exists yet; until then, build from source or install a generated CI artifact as a development preview. Package-manager manifests remain deferred until after v1, but Windows has a first-party user-scoped installer.

## Windows one-line install

After the first signed release is published, open PowerShell and run:

```powershell
irm https://raw.githubusercontent.com/dpsyfk/lens/main/install.ps1 | iex
```

The script selects the latest published Windows x64 release, verifies the archive against `SHA256SUMS`, requires a valid Authenticode signature on `lens.exe`, installs to `%LOCALAPPDATA%\Programs\Lens\bin`, and adds that directory to the current process and user `PATH`. No administrator access or manual directory creation is required. Rerun the same command to update; the replaced executable is retained as `lens.exe.previous` for rollback.

To inspect the installer before running it:

```powershell
irm https://raw.githubusercontent.com/dpsyfk/lens/main/install.ps1 -OutFile install.ps1
Get-Content .\install.ps1
.\install.ps1
```

The installer stops without changing the existing installation if the release is missing, draft, malformed, unsigned, or fails checksum or command validation.

If the installer reports that no published Lens release was found, the repository has not published the first signed release yet. Use the development preview path below until that release exists.

## Windows development preview install

Use this path only before the first signed release exists, or when testing an unreleased build. Release workflow artifacts are unsigned previews unless they came from a tagged signed release, require GitHub access, and can expire.

Prerequisites:

- GitHub CLI authenticated with access to this repository: `gh auth status`
- PowerShell

From any PowerShell window:

```powershell
$InstallRoot = "$env:LOCALAPPDATA\Programs\Lens"
$Bin = Join-Path $InstallRoot "bin"
$ArtifactDir = Join-Path $InstallRoot "_artifact"
New-Item -ItemType Directory -Force -Path $Bin, $ArtifactDir | Out-Null

$RunId = gh run list `
  --repo dpsyfk/lens `
  --workflow release.yml `
  --status success `
  --limit 1 `
  --json databaseId `
  --jq '.[0].databaseId'

gh run download $RunId `
  --repo dpsyfk/lens `
  --name lens-x86_64-pc-windows-msvc `
  --dir $ArtifactDir

$LensExe = Get-ChildItem $ArtifactDir -Recurse -Filter lens.exe | Select-Object -First 1
Copy-Item $LensExe.FullName (Join-Path $Bin "lens.exe") -Force

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($UserPath -split ";") -notcontains $Bin) {
  [Environment]::SetEnvironmentVariable("Path", "$UserPath;$Bin", "User")
}
$env:Path = "$env:Path;$Bin"

lens --version
lens doctor --check all
```

Then start Lens:

```powershell
lens quickstart
lens run --listen 127.0.0.1:8888
```

In another PowerShell window:

```powershell
$env:HTTP_PROXY = "http://127.0.0.1:8888"
curl http://example.com/
```

After the signed release is published, switch to the one-line installer. It replaces the preview binary only after checksum, signature, and command validation pass.

## Manual installation

### 1. Choose an artifact

Download the archive for your platform from the matching GitHub release:

| Platform | Artifact |
| --- | --- |
| Windows x64 | `lens-VERSION-x86_64-pc-windows-msvc.zip` |
| macOS Apple silicon | `lens-VERSION-aarch64-apple-darwin.zip` |
| macOS Intel | `lens-VERSION-x86_64-apple-darwin.zip` |
| Linux x64 | `lens-VERSION-x86_64-unknown-linux-gnu.tar.gz` |

Every release also contains `SHA256SUMS` and one `.sigstore.json` bundle for each archive and for the checksum file.

Verify GitHub build provenance for the selected archive as an independent origin check:

```sh
gh attestation verify lens-0.1.0-TARGET.ARCHIVE -R dpsyfk/lens
```

The Linux release binary includes the optional eBPF discovery backend and embedded metadata-only probe. It remains inactive unless `--ebpf-cgroup` is supplied and still requires kernel support plus permission to attach cgroup BPF programs. Other platforms retain the portable process resolver.

### 2. Verify before extracting

Install [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) and verify the checksum manifest:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/dpsyfk/lens/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
```

On macOS or Linux, verify the downloaded archive with `sha256sum -c SHA256SUMS`. On Windows, compare `certutil -hashfile ARCHIVE SHA256` with the matching manifest entry. You can also verify the archive's own Sigstore bundle with the same `cosign verify-blob` command.

Tagged Windows binaries are Authenticode-signed. Tagged macOS binaries are Developer ID-signed and their ZIP archives are submitted to Apple's notarization service. The release workflow refuses to create a tagged release when either native signing credential set is absent.

### 3. Install the binary

Extract the archive and move `lens` or `lens.exe` into a user-owned directory on `PATH`. Lens does not require administrator or root access for its default proxy path.

Confirm the binary and configuration:

```sh
lens --version
lens doctor --check all
lens quickstart
```

## Enable HTTPS inspection explicitly

Lens never changes trust without an explicit command:

```sh
lens cert install
lens doctor --check trust
```

Remove that trust at any time with `lens cert uninstall`. Applications using certificate pinning may reject interception; use passthrough mode for those flows.

## Start a daily session

```sh
lens run --listen 127.0.0.1:8888
```

Point the application at `HTTP_PROXY=http://127.0.0.1:8888` and `HTTPS_PROXY=http://127.0.0.1:8888`. The release archive includes `QUICKSTART.md`, `REPLAY.md`, `PLUGINS.md`, `LINUX_DISCOVERY.md`, `TROUBLESHOOTING.md`, `DOGFOODING.md`, and the machine-readable dogfood report template; the same material is available in the online [quickstart](src/quickstart.md), [safe replay guide](src/export-replay.md), [plugin guide](src/plugins.md), [Linux discovery guide](src/linux-discovery.md), and [troubleshooting guide](src/troubleshooting.md).

Release candidates are verified with the maintainer [dogfood protocol](DOGFOODING.md) before publication.
