# Lens v1 dogfood protocol

Use this protocol on binaries downloaded from the draft GitHub release, not binaries built from a local checkout. A v1 release is ready to publish only after Windows x64, macOS Intel, macOS Apple silicon, and Linux x64 have passing reports from four independent testers.

## Safety

- Use a development account and development traffic only.
- Do not install the Lens CA on a shared or production machine.
- Confirm `lens cert uninstall` succeeds when the HTTPS checks are complete.
- Attach redacted diagnostics only. Never attach an export produced with `--reveal`.

## Tester checklist

Record the release tag, artifact name, operating-system version, terminal, shell, and application used. Then verify:

- [ ] The archive and `SHA256SUMS` pass the documented checksum, Sigstore, and GitHub provenance verification.
- [ ] Windows reports a valid Authenticode signature, or macOS reports a valid Developer ID signature and notarization. Linux has no native platform-signing requirement.
- [ ] `lens --version`, `lens quickstart`, and `lens doctor --check all` complete without an unexplained failure.
- [ ] `lens run --listen 127.0.0.1:8888` opens the TUI and restores the terminal after `q` and Ctrl-C.
- [ ] An application using `HTTP_PROXY` produces a flow with method, route, status, and latency.
- [ ] `lens cert install` enables an application using `HTTPS_PROXY` to produce an inspected HTTPS flow.
- [ ] Authorization, cookie, query-secret, and body-secret values are masked in the TUI and a JSONL export.
- [ ] A pinned-TLS client works with `--https passthrough` and is shown as opaque.
- [ ] A PostgreSQL client configured for the Lens endpoint produces redacted query metadata without behavior changes.
- [ ] A Redis client configured for the Lens endpoint preserves pipelining and masks authentication, write, and response values.
- [ ] An HTTP/2 client produces stream-correct request/response timing, including out-of-order responses.
- [ ] A gRPC client shows method, message size, terminal status, and latency without persisting protobuf payloads by default.
- [ ] An ABI-v1 plugin stays disabled by default, annotates only with `--enable-plugins`, and receives redacted input even during a local reveal-mode run.
- [ ] An importing, infinite-loop, oversized-output, or tampered plugin is rejected or contained without interrupting forwarding.
- [ ] On Linux, explicitly scoped eBPF discovery attributes a short-lived TCP client, excludes Lens itself, reads no payload, and detaches on exit.
- [ ] A run without plugins or `--ebpf-cgroup` behaves identically to the portable baseline.
- [ ] Saturating or malformed traffic does not terminate Lens or block application traffic.
- [ ] `lens cert uninstall` removes trust, and the operating system no longer trusts a Lens-issued leaf certificate.

## Report

Copy `DOGFOOD-REPORT.example.json` from the release archive, replace its placeholders, and set a check to `true` only after the corresponding test passes. Windows and macOS reports require `native_signature`; the Linux report requires `ebpf`. Keep `blocking_issues` empty only when every release-blocking finding is resolved. Attach the completed JSON to the matching GitHub dogfood issue; do not include secrets or reveal-mode output.

```text
Release/tag:
Artifact:
Artifact verification: pass/fail
OS and version:
CPU architecture:
Terminal and shell:
HTTP client/application:
PostgreSQL client/application:
Redis client/application:
HTTP/2 or gRPC client/application:

Install and first-run: pass/fail
TUI and terminal restoration: pass/fail
HTTP forwarding and inspection: pass/fail
HTTPS trust/interception/uninstall: pass/fail
PostgreSQL forwarding and inspection: pass/fail
Redis forwarding and inspection: pass/fail
HTTP/2 and gRPC inspection: pass/fail
WASM plugin sandbox and redaction: pass/fail
Linux eBPF discovery (Linux report): pass/fail/not-applicable
Default redaction and safe export: pass/fail
Fault/overload behavior: pass/fail

Blocking issue links:
Non-blocking observations:
Tester:
Date:
```

## Release gate

The maintainer downloads the four attached JSON reports and the draft release assets into separate directories, then runs:

```sh
python scripts/release_gate.py --reports ./dogfood-reports --artifacts ./release-assets
```

The command requires exactly one target per independent tester, the platform-specific native-signing/eBPF check, every common product check, no blocking issues, the exact archive set, exact SHA-256 matches, and a Sigstore bundle for every archive and checksum manifest. Cryptographic verification with Cosign and `gh attestation verify` remains mandatory; the script validates completeness and consistency of that evidence rather than replacing cryptography.

The maintainer links all four passing reports from the draft release checklist. Any failure involving traffic correctness, secret retention, certificate cleanup, terminal corruption, unbounded resource use, native signing, notarization, or artifact verification blocks publication. Other defects require an explicit documented disposition before publication.
