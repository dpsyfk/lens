# Lens

**See what your application sends to APIs and databases without leaving the terminal.**

Lens is a local-first developer proxy with a live TUI. Point a development application at Lens and it forwards the traffic, decodes supported protocols, redacts common secrets, and shows each request, response, error, and latency in real time.

> **Free development preview:** no paid code-signing certificate, Rust toolchain, GitHub account, or administrator access is required. The binaries are unsigned, so Windows or macOS may show a warning. Install Lens only on a development machine you control.

```text
your application  ──►  Lens  ──►  API / PostgreSQL / Redis / gRPC service
                         │
                         └────►  redacted live TUI or JSON/JSONL export
```

[Install](docs/INSTALL.md) · [Quickstart](docs/src/quickstart.md) · [Troubleshooting](docs/src/troubleshooting.md) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY_REVIEW.md)

## Install Lens

| Platform | Free install available |
| --- | --- |
| Windows x64 | Unsigned development preview |
| macOS Apple silicon / Intel | Unsigned development preview |
| Linux x64 | Unsigned development preview |

The installer downloads the newest published Lens preview and verifies its archive against the published SHA-256 manifest. It does not use `iex` and does not install Lens's HTTPS certificate authority. HTTPS trust remains a separate, explicit `lens cert install` action. See the complete [cross-platform installation guide](docs/INSTALL.md) for source builds, updates, and removal.

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

The Unix installer supports Linux x64, macOS Apple silicon, and macOS Intel. Add `$HOME/.local/bin` to the shell profile to make `lens` available in future terminals. Windows or macOS may warn because the development preview is unsigned.

## Uninstall Lens

Stop Lens first. If you enabled HTTPS inspection, remove its user-scoped trust before deleting the executable:

```powershell
lens cert uninstall
```

On Windows, run this in PowerShell:

```powershell
$InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\Lens"
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

These commands remove the executable and Windows `PATH` entry but preserve Lens configuration, plugins, and local CA files for a later reinstall. See [complete removal options](docs/INSTALL.md#uninstall) if you also want to purge retained data.

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
- Signed stable binaries and package-manager distribution are deferred. The free unsigned preview installer remains available for development use.

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
