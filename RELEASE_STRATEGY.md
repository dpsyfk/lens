# Release Strategy

Lens releases are auditable, immutable, and fail closed when platform signing cannot be completed.

## Supported v0.1 artifacts

- Windows x64: Authenticode-signed `lens.exe` in ZIP
- macOS Intel and Apple silicon: Developer ID-signed binary in a notarized ZIP
- Linux x64: stripped binary in `tar.gz`
- Every archive: SHA-256 manifest entry and GitHub OIDC-backed Sigstore bundle

Package-manager publishing, HTTP/2, Redis, replay, plugins, and transparent interception remain post-v1 work.

## Gates

A tag is releasable only when cross-platform CI, hardening tests, decoder fuzz smoke, deterministic Linux rebuild comparison, platform binary smoke tests, native signing verification, notarization, checksums, and Sigstore verification pass. The workflow creates a draft release so a maintainer can independently verify the assets before publication.

See `docs/RELEASING.md` for credentials and procedure, `docs/INSTALL.md` for consumer verification, and `docs/UPGRADING.md` for upgrade and rollback policy.
