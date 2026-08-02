# Future work

This page records roadmap status. A milestone is complete only when its implementation and automated gates have landed; release publication and real-user validation are tracked separately.

1. **Signed v1 release and dogfooding - release operations pending.** Build, smoke, signing, packaging, provenance, and machine-readable dogfood quorum gates exist; native credentials, the release tag, and four independent human reports are still required.
2. **Replay and documentation cleanup - implemented in source.** HTTP replay is preview-first and guarded; public documentation distinguishes current behavior from later architecture.
3. **Transparent mode and service map - implemented for the supported Windows scope.** Process/service identity, the live map, a versioned native-control ABI, first-party Windows WFP driver, dynamic filter transactions, fail-open rollback, and original-destination TCP forwarding are implemented. Signed-driver publication and privileged clean-machine tests remain release gates. Linux nftables, macOS PF, and transparent HTTPS decryption are post-v1 platform work; the explicit proxy remains the cross-platform inspection path.
4. **Redis, HTTP/2, and gRPC - implemented in source.** RESP2/RESP3, HPACK-aware HTTP/2 streams, gRPC envelopes, ALPN preservation, structural redaction, integration tests, and fuzz smoke targets are present. Release publication and broad client-compatibility dogfooding remain separate validation work.
5. **Plugins and eBPF discovery - implemented in source.** ABI-v1 import-free WASM plugins are explicitly installed, integrity-checked, always fed redacted events, and bounded by fuel/memory/I/O limits. Optional Linux cgroup eBPF discovery correlates completed outbound TCP tuples with PID/process metadata without payload capture. Linux privilege/kernel compatibility and third-party plugin dogfooding remain release validation work.
6. **Full-platform stabilization - implemented in source.** Security, compatibility, resource, upgrade, packaged-binary, provenance, and four-target release gates are automated. Publication still fails closed until native signing credentials and four independent clean-machine dogfood reports exist.

Milestones are ordered by delivery dependency. Scope and timing may change, but the distinction between shipped and planned behavior must remain explicit.
