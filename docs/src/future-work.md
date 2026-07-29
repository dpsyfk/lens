# Future work

This page records roadmap status. A milestone is complete only when its implementation and automated gates have landed; release publication and real-user validation are tracked separately.

1. **Signed v1 release and dogfooding - release operations pending.** Build, smoke, signing, packaging, and dogfood gates exist; native credentials, the release tag, and four human reports are still required.
2. **Replay and documentation cleanup - implemented in source.** HTTP replay is preview-first and guarded; public documentation distinguishes current behavior from later architecture.
3. **Transparent mode and service map - in progress.** Process/service identity and the live map have landed. A versioned native-control ABI and first-party Windows WFP driver foundation are implemented; transactional WFP filters, original-destination forwarding, Linux nftables, macOS PF, rollback integration, signing, and privileged end-to-end tests remain required.
4. **Redis, HTTP/2, and gRPC** - add bounded streaming decoders, redaction, integration coverage, and fuzzing.
5. **Plugins and eBPF discovery** - add an explicitly installed, capability-limited WASM plugin system and optional Linux connection discovery.
6. **Full-platform stabilization** - complete security, compatibility, resource, upgrade, and cross-platform release validation.

Milestones are ordered by delivery dependency. Scope and timing may change, but the distinction between shipped and planned behavior must remain explicit.
