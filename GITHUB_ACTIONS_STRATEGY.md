# GitHub Actions Strategy

## Goals
- Keep validation fast for pull requests.
- Separate unit, integration, fuzz, benchmark, and documentation jobs.
- Make release automation explicit and predictable.

## Workflow layout
- `ci.yml` validates every pull request with actionlint, deterministic package tests, formatting, warnings-as-errors clippy, and the three-OS workspace test matrix.
- `integration.yml` gates proxy load, observation saturation, flow fault isolation, retention limits, TLS failure, and bounded shutdown on relevant pull requests and on a weekly schedule.
- `fuzz.yml` compiles nightly libFuzzer targets and mutates seeded HTTP/1 and PostgreSQL state machines on relevant pull requests and weekly.
- `bench.yml` records maximum resident memory for the release-mode saturated-observation load test and enforces a 512 MiB CI safety ceiling on a weekly schedule.
- `docs.yml` checks local links, warnings-as-errors Rust documentation, and the mdBook user guide.
- `release.yml` builds and smoke-tests four target archives, checks repeat-build equality, gates native signing/notarization, emits checksums and Sigstore bundles, and creates a draft release.

## Principles
- Small workflows are easier to rerun and debug.
- Heavy jobs should be gated or scheduled so pull requests stay responsive.
- Secrets should be used sparingly and only where release or signing requires them.
- Tagged releases fail closed when Windows or Apple signing credentials are unavailable; ordinary pull requests never receive those secrets.
