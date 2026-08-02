# Upgrading Lens v0.1

No signed public release or public installer exists yet. For a development-preview installation, stop Lens and repeat the artifact download steps in the [installation guide](INSTALL.md); the Windows instructions replace the user-owned `lens.exe` and retain the prior binary as `lens.exe.previous`.

## Safe upgrade

1. Read the target release notes and `CHANGELOG.md`.
2. Download the new preview artifact or, after signed releases begin, verify the release artifact as described in `docs/INSTALL.md`.
3. Stop the active Lens session with `q` or Ctrl-C and wait for the shutdown summary.
4. Keep the previous binary until the new version passes `lens --version` and `lens doctor --check all`.
5. Replace the binary and start a short test session against a local HTTP request before resuming daily traffic.

The user CA and configuration live outside the binary. A normal patch or minor upgrade should not require reinstalling trust. Run `lens cert status` after an upgrade; only run `lens cert install` when diagnostics report that trust is missing.

## Rollback

Stop Lens, restore the previously verified binary, and run `lens doctor --check all`. A Windows preview installation can restore `%LOCALAPPDATA%\Programs\Lens\bin\lens.exe.previous`. Safe exports are versioned JSON/JSONL diagnostics, not an input database, so rollback does not require data migration.

If a release rotates or changes the local CA format, its release notes must call that out explicitly. Remove obsolete trust with the version that created it when possible, or use the documented platform trust-store procedure.

## Compatibility policy

- Patch releases preserve CLI and export compatibility except for security corrections.
- Minor releases may add fields and commands while preserving existing v0.1 behavior.
- Export schema 1.1 adds `wire_base64` for binary-safe replay. Older text-only exports remain readable for previews but are intentionally not executable.
- Export schema 1.3 adds `plugin_annotations` and `plugin_failures`; readers must ignore unknown additive fields.
- Plugin ABI compatibility is independent from the Lens package version. ABI-v1 modules declare no imports and may need reinstalling if a future release introduces a new ABI.

Release candidates must replay-preview the committed v0.1 JSONL fixture, complete `lens doctor --check all`, shut down gracefully, and write a final redacted export on every release operating system. The four-platform dogfood gate separately verifies that configuration and user-scoped CA trust survive an upgrade and that the previously verified binary remains usable for rollback.
- Breaking changes require a major version change after v1; before v1 they require an explicit migration note.
- Downgrades never restore revealed secrets because revealed values are not persisted by default.
