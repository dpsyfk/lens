# Changelog

All notable changes to this project will be documented in this file.

This project follows Keep a Changelog conventions.

## [Unreleased]

### Added

- Cross-platform deterministic release archives with native signing gates, checksums, Sigstore bundles, and binary smoke tests.
- Dedicated load, resource-bound, shutdown, flow-isolation, and decoder fuzz-smoke coverage.
- Versioned installation, verification, upgrade, rollback, and maintainer release documentation.

### Changed

- Transient listener accept failures now back off and retry instead of terminating the proxy session.
