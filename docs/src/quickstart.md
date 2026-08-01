# Quickstart

Lens is an explicit developer proxy. Your application opts in by using an HTTP proxy setting or a fixed PostgreSQL, Redis, HTTP/2, or gRPC endpoint; Lens does not silently redirect system traffic in its default mode.

## Check the installation

```sh
lens --version
lens quickstart
lens doctor --check all
```

Resolve unexplained doctor failures before capturing traffic. The default listener is local-only and does not require root or administrator access.

## Inspect HTTP

Start Lens in an interactive terminal:

```sh
lens run --listen 127.0.0.1:8888
```

In another shell, point a development application or command at it:

```sh
HTTP_PROXY=http://127.0.0.1:8888 curl http://example.com/
```

PowerShell can set the variable for the current process with `$env:HTTP_PROXY = "http://127.0.0.1:8888"`.

## Inspect HTTPS

Install the Lens development CA explicitly, then configure the HTTPS proxy:

```sh
lens cert install
lens doctor --check trust
HTTPS_PROXY=http://127.0.0.1:8888 curl https://example.com/
```

Remove trust when it is no longer needed:

```sh
lens cert uninstall
```

Certificate-pinned applications must use `lens run --https passthrough`; their encrypted payload remains opaque.

When client and server negotiate `h2`, Lens preserves that ALPN selection and inspects multiplexed HTTP/2 streams. Clients that select `http/1.1` continue through the HTTP/1 decoder.

## Inspect PostgreSQL

Run a dedicated Lens endpoint and point the application at it:

```sh
lens run --protocol postgres --listen 127.0.0.1:15432 \
  --upstream 127.0.0.1:5432
```

For an inspectable trusted local hop, use a connection such as `postgresql://app@127.0.0.1:15432/app?sslmode=disable`. Lens never downgrades PostgreSQL TLS. If the client negotiates TLS, Lens forwards it unchanged and marks the flow opaque.

## Inspect Redis

Run a dedicated RESP endpoint:

```sh
lens run --protocol redis --listen 127.0.0.1:16379 \
  --upstream 127.0.0.1:6379
```

Point the development client at `redis://127.0.0.1:16379`. Lens decodes RESP2 and RESP3, including pipelining and push messages. Authentication material, ACL passwords, scripts, write values, and response values are masked by default. Fixed-target Redis TLS remains opaque.

## Inspect HTTP/2 and gRPC

For a prior-knowledge cleartext endpoint:

```sh
lens run --protocol http2 --listen 127.0.0.1:18080 \
  --upstream 127.0.0.1:8080
lens run --protocol grpc --listen 127.0.0.1:15051 \
  --upstream 127.0.0.1:50051
```

The second command is an h2c endpoint; point the development gRPC client at `127.0.0.1:15051` with transport security disabled on that trusted local hop. For TLS gRPC clients that support `HTTPS_PROXY`, use the normal explicit proxy and install the Lens CA. Lens reports method paths, message sizes, compression flags, terminal status, and per-stream latency. Protobuf payloads are redacted by default and are not schema-decoded.

## Use the TUI

- `j`/`k` or arrow keys select a flow.
- `PageUp`/`PageDown` scroll the inspector.
- `p`, `s`, and `l` cycle protocol, state, and latency filters.
- `/` searches; `x` clears filters.
- `q` or Ctrl-C stops Lens and restores the terminal.

Use `--headless` for a non-interactive session and `--export PATH` for a redacted JSONL diagnostic. Exports never overwrite an existing file.

## Replay one HTTP request

Replay defaults to a preview and requires an explicit target:

```sh
lens replay --input lens-flows.jsonl --flow 1 \
  --target http://127.0.0.1:8080
```

Review the output before adding `--execute`. Redacted placeholders, reveal-mode secrets, state-changing methods, and remote targets each require their own acknowledgement. Truncated or legacy text-only requests cannot execute. See [safe replay](export-replay.md) for the complete guard model.
