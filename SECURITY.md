# Security Policy

Report security issues privately to the maintainers. Do not open a public issue containing credentials, captured traffic, private certificates, or an unpatched vulnerability.

The project is designed around local-first observability and default redaction; secret handling should be treated carefully in all exports and screenshots.

Release archives must be verified against both `SHA256SUMS` and their Sigstore bundle before installation. Tagged Windows and macOS binaries also carry native platform signatures. Verification instructions are versioned in `docs/INSTALL.md`.

The Lens CA private key must never be exported to diagnostics, logs, release artifacts, or support bundles. Remove local trust with `lens cert uninstall` when Lens is no longer used. Revealed flow exports require a second explicit opt-in and should be handled as secrets.
