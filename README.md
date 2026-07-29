# Lens

Lens is a local-first developer proxy for inspecting HTTP/1.1, HTTPS, and PostgreSQL traffic in a terminal. Applications opt in through `HTTP_PROXY` / `HTTPS_PROXY` or an explicit PostgreSQL connection endpoint. Lens forwards traffic independently from its bounded observation pipeline, redacts common secrets by default, and can export safe diagnostic snapshots.

Lens is currently a development preview. Cross-platform release automation exists, but no signed public v0.1 release has been published yet.

## What works today

| Capability | Current support |
| --- | --- |
| HTTP | Explicit absolute-form HTTP/1.1 proxy with streaming request and response inspection |
| HTTPS | Explicit `CONNECT` interception after local CA trust; passthrough for pinned clients |
| PostgreSQL | Explicit fixed-target proxy with redacted protocol metadata and query timing |
| TUI | Live flow list, filtering, message inspection, latency, and drop/truncation indicators |
| Exports | Bounded JSON and JSONL snapshots; secret export requires a separate explicit opt-in |
| Replay | HTTP/1 request preview and guarded execution against an explicit target |
| Platforms | Windows, macOS Intel/Apple silicon, and Linux builds exercised in CI |

The process/service identity map is implemented. On Windows, Lens now has a first-party WFP driver plus crash-safe dynamic filter activation and original-destination TCP forwarding. Installing the signed driver still requires an explicit elevated step; Linux nftables and macOS PF adapters remain roadmap work. Redis, HTTP/2, gRPC, plugins, and eBPF discovery are also post-v1 work.

## Build and check

Install the stable Rust toolchain, clone the repository, then run:

```sh
cargo build --locked --release -p lens-cli
cargo test --workspace --all-targets --all-features
```

The executable is `target/release/lens` (`target\release\lens.exe` on Windows).

## First run

```sh
lens quickstart
lens doctor --check all
lens doctor --check transparent
lens run --mode transparent --protocol http --listen 127.0.0.1:8888
lens run --listen 127.0.0.1:8888
```

Point a development client at Lens:

```sh
HTTP_PROXY=http://127.0.0.1:8888 curl http://example.com/
```

For HTTPS inspection, explicitly install the user-scoped development CA:

```sh
lens cert install
lens doctor --check trust
HTTPS_PROXY=http://127.0.0.1:8888 curl https://example.com/
```

Remove trust with `lens cert uninstall`. Certificate-pinned clients must use `lens run --https passthrough`, which keeps their payload opaque.

## PostgreSQL

Run a dedicated Lens endpoint and point the application at it:

```sh
lens run --protocol postgres --listen 127.0.0.1:15432 \
  --upstream 127.0.0.1:5432
```

For inspectable traffic on a trusted local hop, use a connection such as `postgresql://app@127.0.0.1:15432/app?sslmode=disable`. Lens never downgrades PostgreSQL TLS. If the client negotiates TLS, Lens forwards the encrypted session unchanged and marks it opaque.

## Safe capture export

```sh
lens run --headless --listen 127.0.0.1:8888 \
  --export lens-flows.jsonl
```

Exports use create-new semantics and never overwrite an existing file. Authorization, cookies, common secret headers, sensitive query/form values, JSON secrets, SQL literal values, credentials, and database result values are masked or omitted by default.

The current export schema includes a binary-safe `wire_base64` representation of each already-redacted message. This permits exact replay of non-text request bodies without placing unredacted bytes into a normal capture.

## HTTP replay

Replay is preview-only by default and always requires an explicit target origin:

```sh
lens replay --input lens-flows.jsonl --flow 1 \
  --target http://127.0.0.1:8080
```

After reviewing the method, target, header names, body size, sensitivity, and warnings, add `--execute` to send it. Additional acknowledgements are deliberately independent:

- `--allow-unsafe` permits methods other than GET, HEAD, and OPTIONS.
- `--allow-redacted` permits sending literal `[REDACTED]` placeholders.
- `--allow-secrets` permits a reveal-mode capture.
- `--allow-remote` permits a non-loopback target.

Lens refuses to execute truncated requests and legacy text-only exports. It strips hop-by-hop headers, does not follow redirects, caps replay response bodies, and compares the replayed response status/body with the captured terminal response when a safe exact comparison is available.

## TUI controls

- `j`/`k` or arrow keys select a flow.
- `PageUp`/`PageDown` scroll the inspector.
- `p`, `s`, and `l` cycle protocol, state, and latency filters.
- `/` searches and `x` clears filters.
- `q` or Ctrl-C stops Lens and restores the terminal.

Non-interactive stdout automatically uses headless output.

## Architecture and safety

The data plane copies application bytes independently from decoding, storage, replay preparation, and rendering. Observation travels through bounded channels; diagnostic detail can be dropped under pressure, but inspection must not block application traffic.

Canonical records enter the store only after redaction. Bodies, retained flows, replay inputs, and replay responses are bounded. Malformed traffic and decoder failures are isolated to the affected flow.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for implemented boundaries and planned extension seams, [SECURITY.md](SECURITY.md) for reporting, and [SECURITY_REVIEW.md](SECURITY_REVIEW.md) for the threat model.

## Documentation

- [Quickstart](docs/src/quickstart.md)
- [Troubleshooting](docs/src/troubleshooting.md)
- [Installation and artifact verification](docs/INSTALL.md)
- [Release and dogfood protocol](docs/RELEASING.md)
- [Upgrade and rollback](docs/UPGRADING.md)
- [Future work](docs/src/future-work.md)

The historical [CLI design document](CLI.md) contains longer-term command ideas and is explicitly not a statement that every command is implemented.

## License

Apache-2.0. See [LICENSE](LICENSE).
