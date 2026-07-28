# Lens v1 dogfood protocol

Use this protocol on binaries downloaded from the draft GitHub release, not binaries built from a local checkout. A v1 release is ready to publish only after Windows x64, macOS Intel, macOS Apple silicon, and Linux x64 have passing reports.

## Safety

- Use a development account and development traffic only.
- Do not install the Lens CA on a shared or production machine.
- Confirm `lens cert uninstall` succeeds when the HTTPS checks are complete.
- Attach redacted diagnostics only. Never attach an export produced with `--reveal`.

## Tester checklist

Record the release tag, artifact name, operating-system version, terminal, shell, and application used. Then verify:

- [ ] The archive and `SHA256SUMS` pass the documented Sigstore and checksum verification.
- [ ] Windows reports a valid Authenticode signature, or macOS reports a valid Developer ID signature and notarization. Linux has no native platform-signing requirement.
- [ ] `lens --version`, `lens quickstart`, and `lens doctor --check all` complete without an unexplained failure.
- [ ] `lens run --listen 127.0.0.1:8888` opens the TUI and restores the terminal after `q` and Ctrl-C.
- [ ] An application using `HTTP_PROXY` produces a flow with method, route, status, and latency.
- [ ] `lens cert install` enables an application using `HTTPS_PROXY` to produce an inspected HTTPS flow.
- [ ] Authorization, cookie, query-secret, and body-secret values are masked in the TUI and a JSONL export.
- [ ] A pinned-TLS client works with `--https passthrough` and is shown as opaque.
- [ ] A PostgreSQL client configured for the Lens endpoint produces redacted query metadata without behavior changes.
- [ ] Saturating or malformed traffic does not terminate Lens or block application traffic.
- [ ] `lens cert uninstall` removes trust, and the operating system no longer trusts a Lens-issued leaf certificate.

## Report

```text
Release/tag:
Artifact:
Artifact verification: pass/fail
OS and version:
CPU architecture:
Terminal and shell:
HTTP client/application:
PostgreSQL client/application:

Install and first-run: pass/fail
TUI and terminal restoration: pass/fail
HTTP forwarding and inspection: pass/fail
HTTPS trust/interception/uninstall: pass/fail
PostgreSQL forwarding and inspection: pass/fail
Default redaction and safe export: pass/fail
Fault/overload behavior: pass/fail

Blocking issue links:
Non-blocking observations:
Tester:
Date:
```

## Release gate

The maintainer links all four passing reports from the draft release checklist. Any failure involving traffic correctness, secret retention, certificate cleanup, terminal corruption, unbounded resource use, native signing, notarization, or artifact verification blocks publication. Other defects require an explicit documented disposition before publication.
