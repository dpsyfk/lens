# Lens release runbook

Only maintainers with access to the native signing identities may cut a public release.

## Required repository secrets

Windows Authenticode:

- `WINDOWS_CERTIFICATE_BASE64`: base64-encoded code-signing PFX
- `WINDOWS_CERTIFICATE_PASSWORD`: PFX password

Apple signing and notarization:

- `APPLE_CERTIFICATE_BASE64`: base64-encoded Developer ID Application PKCS#12
- `APPLE_CERTIFICATE_PASSWORD`: PKCS#12 password
- `APPLE_SIGNING_IDENTITY`: full Developer ID Application identity
- `APPLE_ID`, `APPLE_TEAM_ID`, and `APPLE_APP_PASSWORD`: notarization credentials

Linux and archive signatures use GitHub OIDC with Sigstore keyless signing, so no long-lived Cosign private key is stored.

## Preflight

1. Confirm main is green in CI, Hardening, Fuzz smoke, and Docs.
2. Update every workspace crate version, `Cargo.lock`, `CHANGELOG.md`, and release notes together.
3. Run `cargo fmt --all --check`, warnings-as-errors clippy, and all workspace tests.
4. Run the Release workflow manually once. Dispatch builds are intentionally unsigned and unpublished, but they validate compilation, deterministic packaging, smoke tests, and repeat-build equality.
5. Confirm both native certificates are valid beyond the planned release date and the timestamp/notarization services are reachable.
6. Open one dogfood report per release target from the repository issue template and assign independent testers. Follow [the dogfood protocol](DOGFOODING.md).

## Cut the release

Create a signed annotated tag whose version exactly matches `crates/lens-cli/Cargo.toml`, then push it:

```sh
git tag -s v0.1.0 -m "Lens v0.1.0"
git push origin v0.1.0
```

The tag workflow builds locked binaries for Windows x64, macOS Intel and Apple silicon, and Linux x64; verifies native signatures and notarization; smoke-tests and packages each binary; compares two Linux builds; emits checksums and Sigstore bundles; and creates a draft GitHub release.

Inspect the draft assets and complete the dogfood protocol using the downloaded artifacts. Link passing reports for Windows x64, macOS Intel, macOS Apple silicon, and Linux x64 from the draft release. Publish the draft only after every automated check and dogfood release gate passes. Release tags are immutable; correct a bad release with a new patch version rather than moving a published tag.

## Failure and credential response

The workflow fails closed when native credentials are missing. Rotate an expired or exposed signing credential before retrying. If an artifact was published with a compromised identity, unpublish the affected release, document the incident, revoke the certificate, and issue a new patch release with a new tag and signatures.
