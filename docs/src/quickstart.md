# Quickstart

Lens is an explicit developer proxy. Your application opts in through HTTP proxy settings or a fixed PostgreSQL, Redis, HTTP/2, or gRPC endpoint. Normal operation is local-only, rootless, and limited to the application you configure.

## 1. Check the installation

```sh
lens --version
lens quickstart
lens doctor --check all
```

Resolve unexpected doctor failures before capturing traffic. A missing transparent driver or unavailable Linux discovery backend does not block the normal explicit proxy path.

## 2. Inspect one HTTP request

Start Lens in terminal 1:

```sh
lens run --listen 127.0.0.1:8888
```

In terminal 2 on PowerShell:

```powershell
$env:HTTP_PROXY = "http://127.0.0.1:8888"
curl.exe http://example.com/
```

In terminal 2 on macOS or Linux:

```sh
HTTP_PROXY=http://127.0.0.1:8888 curl http://example.com/
```

Select the new flow in the TUI to inspect its request, response, status, and latency.

## 3. Run a development project through Lens

Set the proxy variables in the same terminal that starts the application. The variables are inherited by that process and do not permanently change the whole machine.

PowerShell:

```powershell
$env:HTTP_PROXY = "http://127.0.0.1:8888"
$env:HTTPS_PROXY = "http://127.0.0.1:8888"
npm run dev                  # replace with the project's normal start command
```

macOS or Linux:

```sh
HTTP_PROXY=http://127.0.0.1:8888 \
HTTPS_PROXY=http://127.0.0.1:8888 \
npm run dev
```

Some HTTP libraries, browsers, and gRPC SDKs ignore proxy environment variables. Configure that client's documented proxy option and trust store when necessary. Lens can inspect only traffic the application actually sends through it.

## 4. Inspect HTTPS

Install the Lens development CA explicitly, confirm trust, and keep `HTTPS_PROXY` pointed at Lens:

```sh
lens cert install
lens doctor --check trust
```

Remove trust when it is no longer needed:

```sh
lens cert uninstall
```

Certificate-pinned applications must use `lens run --https passthrough`; their encrypted payload remains opaque. When client and server negotiate `h2`, Lens preserves the selected protocol and inspects multiplexed HTTP/2 streams.

## 5. Inspect PostgreSQL

Run a dedicated Lens endpoint and point the development application's connection string at it:

```sh
lens run --protocol postgres --listen 127.0.0.1:15432 \
  --upstream 127.0.0.1:5432
```

For an inspectable trusted local hop, use a connection such as `postgresql://app@127.0.0.1:15432/app?sslmode=disable`. Lens never downgrades PostgreSQL TLS. If the client negotiates TLS, Lens forwards it unchanged and marks the flow opaque.

## 6. Inspect Redis

```sh
lens run --protocol redis --listen 127.0.0.1:16379 \
  --upstream 127.0.0.1:6379
```

Point the development client at `redis://127.0.0.1:16379`. Authentication material, ACL passwords, scripts, write values, and response values are masked by default. Fixed-target Redis TLS remains opaque.

## 7. Inspect HTTP/2 or gRPC directly

For a prior-knowledge cleartext local endpoint:

```sh
lens run --protocol http2 --listen 127.0.0.1:18080 \
  --upstream 127.0.0.1:8080
lens run --protocol grpc --listen 127.0.0.1:15051 \
  --upstream 127.0.0.1:50051
```

Point the gRPC client at `127.0.0.1:15051` with transport security disabled only on that trusted local hop. Lens reports method paths, message sizes, compression flags, terminal status, and per-stream latency. Protobuf payloads are redacted by default and are not schema-decoded.

## 8. Use the TUI or a safe export

- `j`/`k` or arrow keys select a flow.
- PageUp/PageDown scroll the inspector.
- `p`, `s`, and `l` cycle protocol, state, and latency filters.
- `/` searches; `x` clears filters.
- `q` or Ctrl-C stops Lens and restores the terminal.

Use headless mode for automation and create a redacted diagnostic when Lens stops:

```sh
lens run --headless --export lens-flows.jsonl
```

Exports never overwrite an existing file. Do not use `--reveal` for a shareable diagnostic.

## Optional features

Install and explicitly enable a capability-limited WASM plugin:

```sh
lens plugin install --file ./plugin.wasm --name example --plugin-version 1.0.0
lens plugin list
lens run --enable-plugins
```

Add metadata-only process discovery to a supported Linux build:

```sh
lens doctor --check discovery
sudo lens run --ebpf-cgroup /sys/fs/cgroup
```

Preview one captured HTTP/1 request before any replay execution:

```sh
lens replay --input lens-flows.jsonl --flow 1 \
  --target http://127.0.0.1:8080
```

See [safe replay](export-replay.md), [WASM plugins](plugins.md), [Linux discovery](linux-discovery.md), and [troubleshooting](troubleshooting.md) for the complete safety and configuration details.
