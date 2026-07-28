# Installing Lens v0.1

Lens v0.1 is distributed as signed release archives for Windows, macOS, and Linux. Package-manager installation is intentionally deferred until after v1.

## 1. Choose an artifact

Download the archive for your platform from the matching GitHub release:

| Platform | Artifact |
| --- | --- |
| Windows x64 | `lens-VERSION-x86_64-pc-windows-msvc.zip` |
| macOS Apple silicon | `lens-VERSION-aarch64-apple-darwin.zip` |
| macOS Intel | `lens-VERSION-x86_64-apple-darwin.zip` |
| Linux x64 | `lens-VERSION-x86_64-unknown-linux-gnu.tar.gz` |

Every release also contains `SHA256SUMS` and one `.sigstore.json` bundle for each archive and for the checksum file.

## 2. Verify before extracting

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

## 3. Install the binary

Extract the archive and move `lens` or `lens.exe` into a user-owned directory on `PATH`. Lens does not require administrator or root access for its default proxy path.

Confirm the binary and configuration:

```sh
lens --version
lens doctor --check all
lens quickstart
```

## 4. Enable HTTPS inspection explicitly

Lens never changes trust without an explicit command:

```sh
lens cert install
lens doctor --check trust
```

Remove that trust at any time with `lens cert uninstall`. Applications using certificate pinning may reject interception; use passthrough mode for those flows.

## 5. Start a daily session

```sh
lens run --listen 127.0.0.1:8888
```

Point the application at `HTTP_PROXY=http://127.0.0.1:8888` and `HTTPS_PROXY=http://127.0.0.1:8888`. The release archive includes `QUICKSTART.md` and `TROUBLESHOOTING.md`; the same material is available in the online [quickstart](src/quickstart.md) and [troubleshooting guide](src/troubleshooting.md).

Release candidates are verified with the maintainer [dogfood protocol](DOGFOODING.md) before publication.
