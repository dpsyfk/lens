# Upgrading Lens v0.1

## Safe upgrade

1. Read the target release notes and `CHANGELOG.md`.
2. Download and verify the new artifact as described in `docs/INSTALL.md`.
3. Stop the active Lens session with `q` or Ctrl-C and wait for the shutdown summary.
4. Keep the previous binary until the new version passes `lens --version` and `lens doctor --check all`.
5. Replace the binary and start a short test session against a local HTTP request before resuming daily traffic.

The user CA and configuration live outside the binary. A normal patch or minor upgrade should not require reinstalling trust. Run `lens cert status` after an upgrade; only run `lens cert install` when diagnostics report that trust is missing.

## Rollback

Stop Lens, restore the previously verified binary, and run `lens doctor --check all`. Safe exports are versioned JSON/JSONL diagnostics, not an input database, so rollback does not require data migration.

If a release rotates or changes the local CA format, its release notes must call that out explicitly. Remove obsolete trust with the version that created it when possible, or use the documented platform trust-store procedure.

## Compatibility policy

- Patch releases preserve CLI and export compatibility except for security corrections.
- Minor releases may add fields and commands while preserving existing v0.1 behavior.
- Export schema 1.1 adds `wire_base64` for binary-safe replay. Older text-only exports remain readable for previews but are intentionally not executable.
- Export schema 1.3 adds `plugin_annotations` and `plugin_failures`; readers must ignore unknown additive fields.
- Plugin ABI compatibility is independent from the Lens package version. ABI-v1 modules declare no imports and may need reinstalling if a future release introduces a new ABI.
- Breaking changes require a major version change after v1; before v1 they require an explicit migration note.
- Downgrades never restore revealed secrets because revealed values are not persisted by default.
