# Install Lens

Lens is a free development preview. Installing it does not require a paid code-signing certificate, Rust, Cargo, a GitHub account, or administrator access. Windows binaries are not Authenticode-signed and macOS binaries are not Developer ID-signed or notarized, so the operating system may show a warning. Install Lens only on a development machine you control.

The installer is downloaded as a file and does not use `iex`. It verifies the selected release archive against the release's SHA-256 manifest. Installation never changes HTTPS trust; `lens cert install` remains a separate, explicit action.

## Install the public preview

The preview installers:

- select only published prereleases tagged `preview-vVERSION-preview.NUMBER`;
- download the platform archive and `SHA256SUMS` from the same immutable release;
- reject missing, duplicate, or mismatched checksums;
- verify that the extracted binary runs before installing it;
- install into a user-owned directory without Rust, Cargo, GitHub CLI, or administrator access.

### Windows x64

Run this block in PowerShell. It downloads the installer as a file so you can inspect it before execution:

```powershell
$Installer = Join-Path $env:TEMP "lens-install.ps1"
Invoke-WebRequest https://raw.githubusercontent.com/dpsyfk/lens/main/install.ps1 -OutFile $Installer
try {
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer -Preview
  if ($LASTEXITCODE -ne 0) { throw "Lens preview installation failed." }
} finally {
  Remove-Item -LiteralPath $Installer -ErrorAction SilentlyContinue
}
```

The explicit `-Preview` flag is required. The installer downloads the newest Lens preview, verifies its SHA-256 checksum, copies `lens.exe` into `%LOCALAPPDATA%\Programs\Lens\bin`, and adds that directory to the user `PATH`.

Open a new PowerShell window and verify:

```powershell
lens --version
lens doctor --check all
```

Windows may display an unsigned-application warning. Do not bypass a warning if the reported file or publisher information differs from the Lens preview you intentionally downloaded.

### GitHub Codespaces and Linux x64

Run this block in the Codespaces or Linux shell:

```sh
installer="$(mktemp)"
curl -fsSL https://raw.githubusercontent.com/dpsyfk/lens/main/install-preview.sh -o "$installer"
sh "$installer"
rm -f "$installer"

export PATH="$HOME/.local/bin:$PATH"
lens --version
lens doctor --check all
```

Add `$HOME/.local/bin` to the shell profile if it is not already on `PATH`.

### macOS

The same installer detects Apple silicon and Intel machines:

```sh
installer="$(mktemp)"
curl -fsSL https://raw.githubusercontent.com/dpsyfk/lens/main/install-preview.sh -o "$installer"
sh "$installer"
rm -f "$installer"

export PATH="$HOME/.local/bin:$PATH"
lens --version
lens doctor --check all
```

macOS may block the unsigned preview. Use it only if you intentionally downloaded it from the Lens repository. A normal stable release will require Developer ID signing and notarization instead of asking users to normalize this warning.

## Pin a specific preview

Windows can request an exact immutable preview:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Preview -Version 0.1.0-preview.1
```

The Unix installer always selects the newest published `preview-v*` prerelease. Download a previous archive directly from the [Lens releases page](https://github.com/dpsyfk/lens/releases) when reproducibility requires an older build.

## Authenticated Actions-artifact fallback

Pull-request and scheduled builds remain available as 14-day GitHub Actions artifacts. This route is intended for maintainers testing an unpublished revision and still requires GitHub CLI authentication:

```sh
gh auth status
gh run list --repo dpsyfk/lens --workflow release.yml --status success --limit 1
```

Select the artifact matching the target platform, extract the packaged `.zip` or `.tar.gz`, and run the included binary. The public preview installers should be used for ordinary evaluation.

## Build from source

Install the stable Rust toolchain and platform build tools:

```sh
git clone https://github.com/dpsyfk/lens.git
cd lens
cargo build --locked --release -p lens-cli
```

The binary is `target/release/lens` or `target\release\lens.exe` on Windows. Copy it to a user-owned directory on `PATH`, then verify:

```sh
lens --version
lens doctor --check all
lens quickstart
```

Windows source builds require Visual Studio Build Tools with the Desktop development with C++ workload so the MSVC linker `link.exe` is available. Linux builds that enable optional eBPF discovery use `cargo build --locked --release -p lens-cli --features ebpf` and require Clang with the BPF target.

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

Lens never changes trust during installation. Enable HTTPS inspection separately:

```sh
lens cert install
lens doctor --check trust
```

Remove that trust with `lens cert uninstall`. Applications using certificate pinning or a private trust store may reject interception; use `lens run --https passthrough` for those flows.

## Update a preview installation

Stop Lens with `q` or Ctrl-C and rerun the platform installer. Windows keeps the replaced binary as `lens.exe.previous`; Unix replaces only `$HOME/.local/bin/lens`. Configuration and CA material remain outside the executable.

After updating:

```sh
lens --version
lens doctor --check all
lens cert status
```

## Uninstall

Stop Lens first. If you enabled HTTPS inspection, remove Lens trust while the command is still available:

```sh
lens cert uninstall
```

On Windows, close Lens and run:

```powershell
$InstallRoot = "$env:LOCALAPPDATA\Programs\Lens"
$Bin = Join-Path $InstallRoot "bin"
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$NewUserPath = @($UserPath -split ";" | Where-Object { $_ -and $_.TrimEnd("\") -ine $Bin.TrimEnd("\") }) -join ";"
[Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
$env:Path = @($env:Path -split ";" | Where-Object { $_ -and $_.TrimEnd("\") -ine $Bin.TrimEnd("\") }) -join ";"
if (Test-Path -LiteralPath $InstallRoot) {
  Remove-Item -LiteralPath $InstallRoot -Recurse -Force
}
```

On macOS or Linux:

```sh
lens cert uninstall
rm -f "$HOME/.local/bin/lens"
```

Remove project proxy variables or application-specific proxy settings separately. These commands preserve configuration, plugins, and generated CA files so a reinstall can reuse them. `lens cert uninstall` removes operating-system trust but intentionally retains the local CA key.

To remove all retained Lens data as well, first inspect and confirm the directory reported by `lens cert status`. Delete only that Lens-specific configuration directory. Plugins are stored in `%LOCALAPPDATA%\Lens\plugins` on Windows and `${XDG_DATA_HOME:-$HOME/.local/share}/lens/plugins` on macOS or Linux.

## Signed stable installation (future)

Signed `v*` releases will contain these archives plus `SHA256SUMS`, Sigstore bundles, and GitHub build attestations:

| Platform | Release archive |
| --- | --- |
| Windows x64 | `lens-VERSION-x86_64-pc-windows-msvc.zip` |
| macOS Apple silicon | `lens-VERSION-aarch64-apple-darwin.zip` |
| macOS Intel | `lens-VERSION-x86_64-apple-darwin.zip` |
| Linux x64 | `lens-VERSION-x86_64-unknown-linux-gnu.tar.gz` |

Tagged Windows binaries must be Authenticode-signed. Tagged macOS binaries must be Developer ID-signed and notarized. The stable release workflow refuses publication when either native credential set is missing.

See [release safety](src/release.md) and the maintainer [dogfood protocol](DOGFOODING.md) for the publication gates.
