# Troubleshooting

Start with `lens doctor --check all`; it reports the effective configuration, platform support, and certificate trust state without exposing captured secrets.

`lens doctor --check transparent` is read-only. It reports the selected native backend and whether its platform facility or Windows driver is present; it does not install a driver, request elevation, or redirect traffic. On Windows, `lens run --mode transparent` opens a dynamic WFP session only after the signed Lens driver has been installed and started. Closing Lens removes the filters and disables the driver configuration.

## Lens does not start

- If the listener address is already in use, choose another local port and update the application proxy setting.
- Windows transparent mode requires an elevated, signed driver installation. Until signed driver artifacts are published, use the default explicit mode for normal development.
- Transparent HTTP inspection currently covers cleartext HTTP/1. HTTPS traffic is forwarded without a transparent MITM; use `HTTPS_PROXY` explicit mode for HTTPS inspection.
- If a configuration value is unexpected, `lens doctor --check config` shows the resolved value. CLI flags override environment, project configuration, user configuration, and defaults.

## HTTP traffic does not appear

- Confirm the application honors `HTTP_PROXY`; some clients require an application-specific proxy option.
- Use `127.0.0.1`, not a remote listener, for the normal local-first path.
- Check that `NO_PROXY` does not include the destination.
- Run once with `--headless` to separate application/proxy problems from terminal rendering problems.

## HTTPS fails

- Run `lens cert status` and `lens doctor --check trust`.
- Some OpenSSL clients on Linux require the `SSL_CERT_FILE` path reported by `lens cert status`.
- Node, Java, browsers, and other runtimes may use their own trust configuration.
- Certificate pinning intentionally rejects interception. Use `--https passthrough` for that client; Lens will not decode its encrypted payload.
- Remove local trust with `lens cert uninstall` after testing.

## PostgreSQL is opaque

Lens never weakens database TLS. For inspection on a trusted local hop, point the client at the Lens endpoint with `sslmode=disable`. Across an untrusted network, retain PostgreSQL TLS and accept that the payload is opaque, or connect through a trusted encrypted tunnel.

## The TUI is corrupted or input is not restored

Press Ctrl-C once and reset the terminal using the shell's normal reset command if necessary. Reproduce with the terminal name, shell, operating-system version, and whether stdout was redirected. Headless mode is the safe fallback for unsupported terminals.

## Flows or bodies are missing

Lens bounds retained flows, bodies, and observation queues. The TUI header and final counters report evictions, truncation, and dropped observations. Increase limits only for controlled development traffic; forwarding deliberately continues when observation is saturated.

## Preparing a safe report

Export without `--reveal`, include `lens doctor --check all`, and remove unrelated endpoints if necessary. Never publish CA private-key material, database credentials, authorization headers, cookies, or a reveal-mode export.
