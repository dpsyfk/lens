# Safe exports and replay

Lens replay operates on JSON or JSONL snapshots created by `lens run --export`. It supports HTTP/1 requests only. PostgreSQL, opaque TCP, CONNECT tunnels, and incomplete decoder records are not replayed.

## Export contract

Exports are bounded diagnostic artifacts, not an unbounded traffic database. Each flow includes `schema_version`; current messages retain both a human-readable `body` and a binary-safe `wire_base64` value. The encoded value represents the already-redacted headers and body stored by Lens.

Normal captures redact before storage, so Base64 does not bypass redaction. Reveal-mode exports can contain plaintext secrets and require both `--reveal` and `--allow-secret-export` when captured.

Legacy exports without `wire_base64` can be previewed, but they cannot execute because the prior text representation could not guarantee exact binary preservation.

## Select and preview

```sh
lens replay \
  --input lens-flows.jsonl \
  --flow 12 \
  --request 1 \
  --target http://127.0.0.1:8080
```

`--request` is one-based and defaults to the first request in the flow. `--flow` may be omitted only when the capture contains exactly one HTTP/1 flow. The target must be an HTTP(S) origin without credentials, path, or query; Lens retains the captured path and query.

The preview prints method, final URL, header names, body size, sensitivity, captured response status, and warnings. It never prints header values or body content.

## Execute deliberately

Add `--execute` only after reviewing the preview. Lens applies independent guards:

| Condition | Required acknowledgement |
| --- | --- |
| Target is not loopback | `--allow-remote` |
| Method is not GET, HEAD, or OPTIONS | `--allow-unsafe` |
| Capture came from reveal mode | `--allow-secrets` |
| Request contains `[REDACTED]` placeholders | `--allow-redacted` |

These flags acknowledge different risks and do not imply one another. Truncated requests and legacy text-only requests are always blocked from execution.

Lens strips `Host`, `Content-Length`, `Connection`, proxy authentication, transfer framing, and other hop-by-hop headers before sending. It does not follow redirects. The default timeout is 10 seconds and can be changed with `--timeout-ms`.

## Response comparison

After execution, Lens reports the replay status, elapsed time, captured status comparison, and response-body comparison. Body comparison is unavailable when either body is truncated, the captured response is redacted, the capture uses the legacy text encoding, or no terminal captured response exists. Response bodies are capped at 1 MiB for comparison and are not printed.

Replay can change external state. Use development targets and accounts, prefer loopback fixtures, and never assume that a redacted request is harmless merely because credentials were removed.
