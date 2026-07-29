# Quickstart

Lens is an explicit developer proxy. Your application opts in by using an HTTP proxy setting or a PostgreSQL connection string; Lens does not silently redirect system traffic.

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

## Inspect PostgreSQL

Run a dedicated Lens endpoint and point the application at it:

```sh
lens run --protocol postgres --listen 127.0.0.1:15432 \
  --upstream 127.0.0.1:5432
```

For an inspectable trusted local hop, use a connection such as `postgresql://app@127.0.0.1:15432/app?sslmode=disable`. Lens never downgrades PostgreSQL TLS. If the client negotiates TLS, Lens forwards it unchanged and marks the flow opaque.

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
