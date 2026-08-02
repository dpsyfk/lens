# Troubleshooting

Start with `lens doctor --check all`; it reports the effective configuration, platform support, and certificate trust state without exposing captured secrets.

`lens doctor --check transparent` is read-only. It reports the selected native backend and whether its platform facility or Windows driver is present; it does not install a driver, request elevation, or redirect traffic. On Windows, `lens run --mode transparent` opens a dynamic WFP session only after the signed Lens driver has been installed and started. Closing Lens removes the filters and disables the driver configuration.

## Lens does not start

- If the listener address is already in use, choose another local port and update the application proxy setting.
- Windows transparent mode requires an elevated, signed driver installation. Until signed driver artifacts are published, use the default explicit mode for normal development.
- Transparent HTTP inspection currently covers cleartext HTTP/1. HTTPS traffic is forwarded without a transparent MITM; use `HTTPS_PROXY` explicit mode for HTTPS inspection.
- Driver installation and removal commands are documented in `drivers/windows/lens-wfp/README.md`. Never guess the Driver Store `oemNN.inf` name during removal.
- If a configuration value is unexpected, `lens doctor --check config` shows the resolved value. CLI flags override environment, project configuration, user configuration, and defaults.

## HTTP traffic does not appear

- Confirm the application honors `HTTP_PROXY`; some clients require an application-specific proxy option.
- Set `HTTP_PROXY` and `HTTPS_PROXY` in the same terminal that launches the development application so it inherits them.
- In Windows PowerShell, run `curl.exe`, not `curl`; older PowerShell versions alias `curl` to `Invoke-WebRequest` and may fail before a request reaches Lens.
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

## Redis traffic is missing or opaque

Use a fixed endpoint with `--protocol redis --upstream HOST:PORT` and point the client at the Lens listener. Redis TLS is forwarded but not terminated in fixed-target mode, so encrypted RESP cannot be decoded. RESP frames larger than the bounded observation buffer are skipped with a decoder warning while forwarding continues.

## HTTP/2 or gRPC is not decoded

- For TLS, confirm the client advertises `h2` through ALPN and honors `HTTPS_PROXY`; several gRPC libraries require their own proxy configuration.
- For a direct local endpoint, select `--protocol http2` or `--protocol grpc` and configure the client for prior-knowledge cleartext HTTP/2 (h2c).
- Lens does not translate between HTTP/1.1 and HTTP/2. The ALPN protocol selected by the client must also be supported by the upstream.
- Protobuf schemas are not loaded. Default captures intentionally replace protobuf bodies with `[REDACTED]`; `--reveal` exposes only bounded raw bytes.
- Oversized HTTP/2 frames or header blocks are skipped by the observation decoder and reported as a per-flow warning without stopping forwarding.

## The TUI is corrupted or input is not restored

Press Ctrl-C once and reset the terminal using the shell's normal reset command if necessary. Reproduce with the terminal name, shell, operating-system version, and whether stdout was redirected. Headless mode is the safe fallback for unsupported terminals.

## Flows or bodies are missing

Lens bounds retained flows, bodies, and observation queues. The TUI header and final counters report evictions, truncation, and dropped observations. Increase limits only for controlled development traffic; forwarding deliberately continues when observation is saturated.

## A plugin will not install or run

- `lens plugin install` rejects imports, missing/wrong ABI exports, modules larger than 4 MiB, invalid names, and an existing installation name.
- `lens doctor --check plugins` verifies installed manifests and SHA-256 values. Remove and reinstall a module whose bytes changed.
- Plugins stay disabled without `--enable-plugins`. Fuel/memory/output violations increment the flow's contained plugin failure count.
- ABI v1 has no WASI or other host calls. A module that expects filesystem, network, clocks, environment, or randomness is intentionally incompatible.

## Linux eBPF discovery is unavailable

- Run `lens doctor --check discovery`. The binary must be a Linux build with the `ebpf` feature.
- Confirm the selected cgroup v2 directory exists and is the intended observation scope.
- Loading and attaching normally requires root or appropriate BPF/network administration capabilities. Lens never elevates itself.
- Older kernels or locked-down BPF policy may reject the probe. Run without `--ebpf-cgroup` to use the portable process resolver.
- Discovery collects connection/process metadata only. It does not make HTTPS plaintext visible or enable transparent routing.

## Preparing a safe report

Export without `--reveal`, include `lens doctor --check all`, and remove unrelated endpoints if necessary. Never publish CA private-key material, database credentials, authorization headers, cookies, or a reveal-mode export.
