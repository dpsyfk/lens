# Lens

**See what your application sends to APIs and databases without leaving the terminal.**

Lens is a local-first developer proxy with a live TUI. Point a development application at Lens and it forwards the traffic, decodes supported protocols, redacts common secrets, and shows each request, response, error, and latency in real time.

> **Development preview:** the proxy and cross-platform build pipeline work, but the preview binaries are not Windows Authenticode-signed or Apple Developer ID-signed/notarized. Install them only on a development machine. Stable public installation remains blocked on those signing credentials.

```text
your application  ──►  Lens  ──►  API / PostgreSQL / Redis / gRPC service
                         │
                         └────►  redacted live TUI or JSON/JSONL export
```

[Install](docs/INSTALL.md) · [Quickstart](docs/src/quickstart.md) · [Troubleshooting](docs/src/troubleshooting.md) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY_REVIEW.md)

## Install the development preview

| Platform | Available today | Public signed install |
| --- | --- | --- |
| Windows x64 | Public unsigned preview or source build | Not published yet |
| macOS Apple silicon / Intel | Public unsigned preview or source build | Not published yet |
| Linux x64 | Public unsigned preview or source build | Not published yet |

Preview installation does not require Rust, Cargo, the GitHub CLI, or a GitHub account. The installers select the newest published Lens prerelease and verify its archive against the published SHA-256 manifest. See the complete [cross-platform installation guide](docs/INSTALL.md) for source builds, updates, removal, and the authenticated Actions-artifact fallback.

### Windows x64

Download the installer before running it so it can be inspected. The explicit `-Preview` flag is required because the binary is unsigned:

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

Open a new PowerShell window, then verify:

```powershell
lens --version
lens doctor --check all
```

### GitHub Codespaces / Linux x64 / macOS

Download and run the portable preview installer:

```sh
installer="$(mktemp)"
curl -fsSL https://raw.githubusercontent.com/dpsyfk/lens/main/install-preview.sh -o "$installer"
sh "$installer"
rm -f "$installer"

export PATH="$HOME/.local/bin:$PATH"
lens --version
lens doctor --check all
```

The Unix installer supports Linux x64, macOS Apple silicon, and macOS Intel. Add `$HOME/.local/bin` to the shell profile to make `lens` available in future terminals. Windows or macOS may warn because the development preview is unsigned; do not redistribute it as a production release.

## See your first request

Open two terminals.

In terminal 1, start Lens:

```powershell
lens run --listen 127.0.0.1:8888
```

In terminal 2, send one HTTP request through it:

```powershell
$env:HTTP_PROXY = "http://127.0.0.1:8888"
curl.exe http://example.com/
```

On macOS or Linux, use:

```sh
HTTP_PROXY=http://127.0.0.1:8888 curl http://example.com/
```

The request appears in the TUI. Select it with `j`/`k` or the arrow keys, scroll with PageUp/PageDown, and press `q` to stop Lens cleanly.

## Use Lens with your own project

Lens works with projects whose HTTP client supports a standard proxy or an application-specific proxy option. Set the proxy variables in the same terminal that launches the development application so the child process inherits them.

PowerShell:

```powershell
$env:HTTP_PROXY = "http://127.0.0.1:8888"
$env:HTTPS_PROXY = "http://127.0.0.1:8888"
npm run dev                  # or: python app.py, cargo run, dotnet run, etc.
```

macOS or Linux:

```sh
HTTP_PROXY=http://127.0.0.1:8888 \
HTTPS_PROXY=http://127.0.0.1:8888 \
npm run dev
```

These settings affect only that terminal and its child processes. Some SDKs, browsers, and gRPC clients ignore proxy environment variables or use their own trust store; configure their documented proxy setting when needed. Lens does not silently capture every process in its normal cross-platform mode.

### Inspect HTTPS

HTTPS decryption is explicit. Install the user-scoped Lens development CA, confirm trust, then launch the application with `HTTPS_PROXY` set:

```powershell
lens cert install
lens doctor --check trust
$env:HTTPS_PROXY = "http://127.0.0.1:8888"
```

Remove trust with `lens cert uninstall`. Certificate-pinned clients will reject interception; run `lens run --https passthrough` for those clients and Lens will keep their encrypted payload opaque.

### Inspect a local database or direct service

Direct protocols use a dedicated Lens listening port and an explicit upstream. Point the development application's connection string at the Lens port.

```sh
# PostgreSQL: application uses 127.0.0.1:15432
lens run --protocol postgres --listen 127.0.0.1:15432 --upstream 127.0.0.1:5432

# Redis: application uses 127.0.0.1:16379
lens run --protocol redis --listen 127.0.0.1:16379 --upstream 127.0.0.1:6379

# Prior-knowledge HTTP/2 or gRPC over h2c
lens run --protocol http2 --listen 127.0.0.1:18080 --upstream 127.0.0.1:8080
lens run --protocol grpc --listen 127.0.0.1:15051 --upstream 127.0.0.1:50051
```

Lens never downgrades PostgreSQL or Redis TLS. Use a trusted cleartext local hop for inspectable database traffic, or retain TLS and accept an opaque flow.

## What you get

| Capability | Current support |
| --- | --- |
| HTTP | Explicit absolute-form HTTP/1.1 proxy with streaming request and response inspection |
| HTTPS | Explicit `CONNECT` interception after local CA trust; passthrough for pinned clients |
| HTTP/2 | HPACK-aware multiplexed stream inspection over intercepted TLS or a fixed h2c endpoint |
| gRPC | Service/method, message sizes, status, and per-stream latency; protobuf is redacted by default |
| PostgreSQL | Fixed-target proxy with redacted protocol metadata, query shape, errors, and timing |
| Redis | RESP2/RESP3 commands, replies, errors, pushes, timing, and structural credential redaction |
| TUI | Live flows, filters, message inspector, service map, latency, and drop/truncation indicators |
| Exports | Bounded JSON and JSONL snapshots; secret export requires a separate explicit opt-in |
| Replay | HTTP/1 request preview and guarded execution against an explicit target |
| Plugins | Explicitly installed ABI-v1 WASM annotations with no host capabilities |
| Linux discovery | Optional cgroup eBPF process identity metadata; no payload capture or routing |

### Daily commands

```sh
lens quickstart
lens doctor --check all
lens run --listen 127.0.0.1:8888
lens run --headless --export lens-flows.jsonl
lens cert status
lens --help
```

TUI controls:

- `j`/`k` or arrow keys select a flow.
- PageUp/PageDown scroll the inspector.
- `p`, `s`, and `l` cycle protocol, state, and latency filters.
- `/` searches; `x` clears filters.
- `q` or Ctrl-C stops Lens and restores the terminal.

## Safe by default

- Forwarding is independent from decoding, storage, export, and rendering; observation pressure must not block application traffic.
- Authorization headers, cookies, common secret fields, SQL literal values, credentials, and database result values are masked or omitted before storage.
- Bodies, retained flows, decoder buffers, plugin execution, and exports are bounded.
- `--reveal` is local and explicit. Exporting while reveal mode is active additionally requires `--allow-secret-export`.
- Export files use create-new behavior and never overwrite an existing file.

Use Lens only with systems and traffic you are authorized to inspect. Read the [security model](SECURITY_REVIEW.md) before handling sensitive development data.

## Build from source

Install the stable Rust toolchain and platform build tools, then run:

```sh
git clone https://github.com/dpsyfk/lens.git
cd lens
cargo build --locked --release -p lens-cli
cargo test --workspace --all-targets --all-features
```

The executable is `target/release/lens` (`target\release\lens.exe` on Windows). Windows source builds require the MSVC C++ build tools, including `link.exe`. Linux builds that enable optional eBPF discovery additionally require Clang with the BPF target.

## Current boundaries

- The normal portable path is an explicit proxy or fixed-target endpoint; it is not system-wide automatic capture.
- Windows transparent TCP mode requires the separate first-party WFP driver, elevation, and production driver signing before general distribution.
- Linux nftables and macOS PF transparent adapters are not delivered.
- Transparent HTTPS remains encrypted; use the explicit `HTTPS_PROXY` path for inspection.
- Publicly downloadable signed binaries, package-manager distribution, and the public installer are deferred until release signing is available.

## Documentation

- [Install, update, and uninstall](docs/INSTALL.md)
- [First capture and project setup](docs/src/quickstart.md)
- [Safe exports and HTTP replay](docs/src/export-replay.md)
- [WASM plugins](docs/src/plugins.md)
- [Linux eBPF discovery](docs/src/linux-discovery.md)
- [Troubleshooting](docs/src/troubleshooting.md)
- [Release and dogfood protocol](docs/RELEASING.md)
- [Future work](docs/src/future-work.md)

The historical [CLI design document](CLI.md) contains longer-term command ideas and is not a statement that every idea is implemented.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a large change. Lens is licensed under [Apache-2.0](LICENSE).
