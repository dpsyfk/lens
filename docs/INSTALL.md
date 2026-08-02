# Install Lens

Lens is currently a development preview. Cross-platform release automation produces installable archives, but no signed public release exists because Windows Authenticode and Apple Developer ID/notarization credentials are external paid prerequisites.

For now, choose one of these paths:

1. Download the latest unsigned GitHub Actions artifact to evaluate Lens.
2. Build from source for development.
3. Wait for the first signed public release before wider distribution.

The public installer is intentionally not documented while there is no signed release for it to install.

## Development-preview artifacts

Preview artifacts are built from successful runs of `.github/workflows/release.yml`. They require a GitHub account, expire after 14 days, and have not received Windows Authenticode or Apple notarization approval.

| Platform | Actions artifact |
| --- | --- |
| Windows x64 | `lens-x86_64-pc-windows-msvc` |
| macOS Apple silicon | `lens-aarch64-apple-darwin` |
| macOS Intel | `lens-x86_64-apple-darwin` |
| Linux x64 | `lens-x86_64-unknown-linux-gnu` |

Prerequisites:

- [GitHub CLI](https://cli.github.com/)
- `gh auth status` reports an authenticated account
- Permission to read this repository's Actions runs

### Windows x64

Run the following block in PowerShell. It downloads the latest successful preview, copies `lens.exe` into `%LOCALAPPDATA%\Programs\Lens\bin`, and adds that directory to the user `PATH`.

```powershell
$InstallRoot = "$env:LOCALAPPDATA\Programs\Lens"
$Bin = Join-Path $InstallRoot "bin"

$RunId = gh run list `
  --repo dpsyfk/lens `
  --workflow release.yml `
  --status success `
  --limit 1 `
  --json databaseId `
  --jq '.[0].databaseId'

if (-not $RunId) { throw "No successful Lens release workflow was found." }

$ArtifactDir = Join-Path $InstallRoot "_artifact\$RunId-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $Bin, $ArtifactDir | Out-Null

gh run download $RunId `
  --repo dpsyfk/lens `
  --name lens-x86_64-pc-windows-msvc `
  --dir $ArtifactDir

if ($LASTEXITCODE -ne 0) { throw "Lens artifact download failed." }

$LensExe = Get-ChildItem $ArtifactDir -Recurse -Filter lens.exe | Select-Object -First 1
if (-not $LensExe) { throw "lens.exe was not found in the downloaded artifact." }

$Destination = Join-Path $Bin "lens.exe"
if (Test-Path -LiteralPath $Destination) {
  Copy-Item -LiteralPath $Destination -Destination "$Destination.previous" -Force
}
Copy-Item $LensExe.FullName $Destination -Force
Remove-Item -LiteralPath $ArtifactDir -Recurse -Force

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$PathEntries = @($UserPath -split ";" | Where-Object { $_ })
if ($PathEntries -notcontains $Bin) {
  $NewUserPath = (@($PathEntries) + $Bin) -join ";"
  [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
}
$env:Path = "$Bin;$env:Path"

lens --version
lens doctor --check all
```

The current terminal sees `lens` immediately. New terminals inherit the updated user `PATH` automatically.

### GitHub Codespaces and Linux x64

Run the following block in the Codespaces or Linux terminal. It downloads the latest successful Linux preview and installs `lens` into `$HOME/.local/bin`.

```sh
mkdir -p "$HOME/.local/bin"

RUN_ID="$(gh run list \
  --repo dpsyfk/lens \
  --workflow release.yml \
  --status success \
  --limit 1 \
  --json databaseId \
  --jq '.[0].databaseId')"

test -n "$RUN_ID" || { echo "No successful Lens release workflow was found." >&2; exit 1; }

ARTIFACT_DIR="${TMPDIR:-/tmp}/lens-$RUN_ID-linux-x64"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"

gh run download "$RUN_ID" \
  --repo dpsyfk/lens \
  --name lens-x86_64-unknown-linux-gnu \
  --dir "$ARTIFACT_DIR"

tar -xzf "$ARTIFACT_DIR"/*.tar.gz -C "$ARTIFACT_DIR"
LENS_BIN="$(find "$ARTIFACT_DIR" -type f -name lens | head -n 1)"
test -n "$LENS_BIN" || { echo "lens binary was not found in the downloaded artifact." >&2; exit 1; }

install -m 0755 "$LENS_BIN" "$HOME/.local/bin/lens"
export PATH="$HOME/.local/bin:$PATH"

lens --version
lens doctor --check all
```

Add `$HOME/.local/bin` to the shell profile if it is not already on `PATH`.

### macOS

Select the target matching the machine, download its latest artifact, extract the archive, and install the binary into a user-owned directory:

```sh
# macOS Apple silicon: aarch64-apple-darwin
# macOS Intel:         x86_64-apple-darwin
TARGET=aarch64-apple-darwin

RUN_ID="$(gh run list \
  --repo dpsyfk/lens \
  --workflow release.yml \
  --status success \
  --limit 1 \
  --json databaseId \
  --jq '.[0].databaseId')"

test -n "$RUN_ID" || { echo "No successful Lens release workflow was found." >&2; exit 1; }

ARTIFACT_DIR="${TMPDIR:-/tmp}/lens-$RUN_ID-$TARGET"
mkdir -p "$ARTIFACT_DIR"

gh run download "$RUN_ID" \
  --repo dpsyfk/lens \
  --name "lens-$TARGET" \
  --dir "$ARTIFACT_DIR"

unzip "$ARTIFACT_DIR"/*.zip -d "$ARTIFACT_DIR"
LENS_BIN="$(find "$ARTIFACT_DIR" -type f -name lens | head -n 1)"
test -n "$LENS_BIN" || { echo "lens binary was not found in the downloaded artifact." >&2; exit 1; }

mkdir -p "$HOME/.local/bin"
install -m 0755 "$LENS_BIN" "$HOME/.local/bin/lens"
export PATH="$HOME/.local/bin:$PATH"

lens --version
lens doctor --check all
```

Add `$HOME/.local/bin` to the shell profile if it is not already on `PATH`. macOS will identify the preview binary as unsigned; use it only if you intentionally downloaded it from the repository workflow.

## Build from source

Install the stable Rust toolchain and the native compiler/linker required by the platform:

```sh
git clone https://github.com/dpsyfk/lens.git
cd lens
cargo build --locked --release -p lens-cli
```

The binary is `target/release/lens` or `target\release\lens.exe` on Windows. Copy it to a user-owned directory on `PATH` and verify it:

```sh
lens --version
lens doctor --check all
lens quickstart
```

Windows source builds require Visual Studio Build Tools with the Desktop development with C++ workload so the MSVC linker `link.exe` is available. Linux source builds that enable optional eBPF discovery use `cargo build --locked --release -p lens-cli --features ebpf` and require Clang with the BPF target.

## Start the first capture

Terminal 1:

```sh
lens run --listen 127.0.0.1:8888
```

Terminal 2 on PowerShell:

```powershell
$env:HTTP_PROXY = "http://127.0.0.1:8888"
curl.exe http://example.com/
```

Terminal 2 on macOS or Linux:

```sh
HTTP_PROXY=http://127.0.0.1:8888 curl http://example.com/
```

For an application, set `HTTP_PROXY` and `HTTPS_PROXY` in the terminal that launches its development command. Applications that ignore those variables need their own proxy configuration.

## Enable HTTPS inspection explicitly

Lens never changes trust without an explicit command:

```sh
lens cert install
lens doctor --check trust
```

Remove that trust at any time with `lens cert uninstall`. Applications using certificate pinning or a private trust store may reject interception; use `lens run --https passthrough` for those flows.

## Update a preview installation

Stop Lens with `q` or Ctrl-C, then repeat the artifact download steps for the platform. The Windows block replaces only `%LOCALAPPDATA%\Programs\Lens\bin\lens.exe` and retains the prior binary as `lens.exe.previous` for rollback.

After replacing the binary:

```sh
lens --version
lens doctor --check all
```

The user CA and configuration are stored outside the executable. A normal binary update does not require reinstalling trust; check with `lens cert status`.

## Uninstall

Remove Lens trust first if it was installed:

```sh
lens cert uninstall
```

On Windows, close Lens and run:

```powershell
$InstallRoot = "$env:LOCALAPPDATA\Programs\Lens"
$Bin = Join-Path $InstallRoot "bin"
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$NewUserPath = @($UserPath -split ";" | Where-Object { $_ -and $_ -ne $Bin }) -join ";"
[Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
Remove-Item -LiteralPath $InstallRoot -Recurse -Force
```

On macOS or Linux, remove the installed binary from the user-owned directory, for example `rm "$HOME/.local/bin/lens"`. Remove any project proxy variables or application-specific proxy settings separately.

## Signed release installation (future)

When a signed release is published, the release page will contain these archives plus `SHA256SUMS`, Sigstore bundles, and GitHub build attestations:

| Platform | Release archive |
| --- | --- |
| Windows x64 | `lens-VERSION-x86_64-pc-windows-msvc.zip` |
| macOS Apple silicon | `lens-VERSION-aarch64-apple-darwin.zip` |
| macOS Intel | `lens-VERSION-x86_64-apple-darwin.zip` |
| Linux x64 | `lens-VERSION-x86_64-unknown-linux-gnu.tar.gz` |

Tagged Windows binaries must be Authenticode-signed. Tagged macOS binaries must be Developer ID-signed and notarized. The release workflow refuses to publish a tagged release when either native credential set is missing.

See [release safety](src/release.md) and the maintainer [dogfood protocol](DOGFOODING.md) for the publication gates.
