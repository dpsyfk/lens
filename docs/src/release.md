# Release safety

Lens release archives are generated from locked dependencies, smoke-tested on their target OS, checksummed, signed with Sigstore, and registered with GitHub build-provenance attestations. Tagged Windows and macOS builds additionally require native platform signing; macOS archives are notarized.

Users should verify `SHA256SUMS.sigstore.json` before trusting a downloaded checksum manifest, then verify the selected archive and run `gh attestation verify <archive> -R dpsyfk/lens`. The standalone installation guide is included inside every release archive.

An upgrade should preserve the previous verified binary until the replacement passes `lens doctor --check all`. Certificate trust is user-scoped and does not normally need to be reinstalled during patch upgrades.
