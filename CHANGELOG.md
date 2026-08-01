# Changelog

All notable changes to this project will be documented in this file.

This project follows Keep a Changelog conventions.

## [Unreleased]

### Added

- Explicitly installed, import-free ABI-v1 WASM plugins with integrity verification, always-redacted inputs, bounded annotations, fresh instances, and fuel/memory/I/O limits.
- Optional Linux cgroup eBPF identity discovery for completed outbound TCP tuples without payload capture or traffic redirection.
- Plugin and discovery diagnostics, TUI annotations, safe export fields, Linux probe compilation checks, and release-feature coverage.
- Preview-first HTTP/1 replay with explicit target, side-effect, secret, redaction, and remote-target guards.
- Binary-safe replay fields in JSON/JSONL exports plus deterministic status and body comparison.
- Honest current-capability documentation that separates shipped source from future architecture.
- Cross-platform release smoke coverage for a real HTTP proxy flow, decoded redacted export, and bounded shutdown.
- A four-target v1 dogfood protocol and structured GitHub report for release-candidate evidence.
- Cross-platform deterministic release archives with native signing gates, checksums, Sigstore bundles, and binary smoke tests.
- Dedicated load, resource-bound, shutdown, flow-isolation, and decoder fuzz-smoke coverage.
- Versioned installation, verification, upgrade, rollback, and maintainer release documentation.

### Changed

- Transient listener accept failures now back off and retry instead of terminating the proxy session.
