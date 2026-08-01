# Future work

This page records roadmap status. A milestone is complete only when its implementation and automated gates have landed; release publication and real-user validation are tracked separately.

1. **Signed v1 release and dogfooding - release operations pending.** Build, smoke, signing, packaging, and dogfood gates exist; native credentials, the release tag, and four human reports are still required.
2. **Replay and documentation cleanup - implemented in source.** HTTP replay is preview-first and guarded; public documentation distinguishes current behavior from later architecture.
3. **Transparent mode and service map - in progress.** Process/service identity, the live map, a versioned native-control ABI, first-party Windows WFP driver, dynamic filter transactions, fail-open rollback, and original-destination TCP forwarding are implemented. Signed-driver publication, privileged clean-machine tests, Linux nftables, macOS PF, and transparent HTTPS decryption remain required.
4. **Redis, HTTP/2, and gRPC - implemented in source.** RESP2/RESP3, HPACK-aware HTTP/2 streams, gRPC envelopes, ALPN preservation, structural redaction, integration tests, and fuzz smoke targets are present. Release publication and broad client-compatibility dogfooding remain separate validation work.
5. **Plugins and eBPF discovery** - add an explicitly installed, capability-limited WASM plugin system and optional Linux connection discovery.
6. **Full-platform stabilization** - complete security, compatibility, resource, upgrade, and cross-platform release validation.

Milestones are ordered by delivery dependency. Scope and timing may change, but the distinction between shipped and planned behavior must remain explicit.
