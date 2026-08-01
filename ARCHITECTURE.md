# Architecture

## Overview
Lens is a local-first, proxy-first observability tool. The default product observes traffic at the application boundary instead of the kernel, and it keeps Linux, macOS, and Windows as first-class targets. Optional Linux eBPF support is treated as a later discovery aid, not as the foundation.

The central design goal is simple: forwarding must stay fast and reliable even when inspection, storage, decoding, or the UI fall behind.

This document contains both implemented architecture and deliberately marked extension seams. The current implementation supports the explicit proxy path, HTTP/1, HTTP/2, gRPC, PostgreSQL, and Redis decoders, TLS interception, redaction, bounded storage, TUI, exports, guarded HTTP replay, and process/service identity. Windows transparent TCP mode uses a first-party WFP driver, a dynamic user-mode policy transaction, and original-destination socket context. Driver installation/signing and the Linux/macOS adapters remain separate platform work. Plugins and eBPF discovery remain planned.

## Internal Event Pipeline
### Decision
The hot path is a one-way pipeline:

- accept the connection
- classify it as explicit proxy traffic or Windows WFP-redirected TCP traffic
- resolve the upstream target
- establish or reuse TLS locally when required
- mirror bytes into an observation tap
- detect the protocol
- decode incrementally
- redact sensitive material
- normalize into canonical events
- publish into the store through a bounded channel
- expose read-only snapshots to the UI, exports, and replay

### Trade-offs
- Mirroring bytes adds some overhead, but it keeps forwarding independent from decoding.
- Bounded channels can drop observability detail under load, but they must never slow the application traffic.
- A strict pipeline is less flexible than ad hoc event handling, but it makes backpressure and failure modes visible.

## Data Flow
### Decision
The data plane and control plane are separated. The data plane only forwards bytes. The control plane consumes mirrored bytes and turns them into flow records, messages, indexes, and counters. The store is the single source of truth for everything the UI and exporters show.

### Trade-offs
- The UI is eventually consistent rather than perfectly synchronous with the live socket stream.
- Snapshot consumers are simpler and safer because they never mutate shared state.
- The data plane remains predictable at the cost of occasionally losing diagnostic detail when the control plane cannot keep up.

## Request Lifecycle
### Decision
A request is tracked as a flow with explicit lifecycle states: created, active, decoding, completed, closed, and evicted. The system records both wall-clock time and monotonic time so latency remains meaningful across clock shifts.

### Trade-offs
- An explicit lifecycle handles keep-alive, retries, and multiplexed protocols better than one-record-per-packet logging.
- State machines require more careful implementation and testing.
- The extra structure is worth it because the product is about understanding sessions, not just packets.

## Module Boundaries
### Decision
The codebase is split by responsibility:

- `lens-core` for domain types, IDs, and error models
- `lens-proxy` for connection management and traffic forwarding
- `lens-tls` for CA generation, signing, and trust-store integration
- `lens-protocol` for decoder contracts and registry logic
- `lens-proto-http1`, `lens-proto-http2`, `lens-proto-postgres`, and `lens-proto-redis` for bounded streaming decoders
- `lens-redact` for masking and reveal controls
- `lens-replay` for bounded capture loading, replay safety policy, execution, and comparison
- `lens-store` for bounded flow storage, indexing, and snapshots
- `lens-platform` for OS-specific trust, process identity, and versioned transparent-redirection seams
- `lens-tui` for rendering and input handling
- `lens-cli` for startup, config resolution, and composition
- `lens-plugin` as a placeholder for the planned sandboxed extension host
- `lens-ebpf` as a placeholder for planned optional Linux discovery
- `xtask`, `fuzz`, and benchmarks as tooling-only companions

### Trade-offs
- More crates increase build graph complexity and onboarding work.
- Strong boundaries reduce accidental coupling and make platform-specific code easier to isolate.
- Optional crates can be excluded from the default path, which keeps the MVP smaller and more portable.

## Protocol Decoder Architecture
### Decision
Decoders are streaming state machines. They detect protocols from early bytes and metadata, then decode incrementally from partial buffers. Each flow keeps independent per-direction decoder state. The public decoder contract must support partial reads, explicit "need more" states, and recoverable desync states.

HTTP/2 retains independent HPACK state per direction and associates request timing with stream identifiers rather than connection order. gRPC is recognized from HTTP/2 content type and framed incrementally across DATA boundaries; protobuf bodies are treated as opaque sensitive data. Redis uses bounded RESP2/RESP3 nesting and aggregate limits. Oversized observation frames degrade the affected flow and never participate in forwarding.

### Trade-offs
- Streaming decoders are harder to author than whole-message parsers.
- They are the only viable choice for fragmented packets, pipelined requests, and large bodies.
- A shared decoder contract creates a stable extension seam, but it must be versioned carefully.

## Plugin System (planned)
### Decision
The intended plugin system runs WASM components behind a versioned ABI. This host and ABI are not implemented yet. When implemented, plugins will be installed explicitly, sandboxed by resource limits, and denied ambient file or network access unless the host grants it. Plugin loading will remain opt-in only.

### Trade-offs
- WASM adds marshalling overhead and a larger runtime footprint.
- The isolation boundary is worth it because plugins may process sensitive payloads.
- Explicit installation is less convenient than auto-loading, but it is much safer.

## Memory Ownership
### Decision
Canonical flow and message records live in the store. Payload bodies use shared immutable byte storage so the same bytes can be inspected, redacted, and exported without repeated copying. Large bodies are capped and truncation is recorded explicitly. Secondary indexes hold lightweight metadata rather than duplicating payloads.

### Trade-offs
- Reference-counted bytes add some atomic overhead.
- Bounded bodies and capped history mean very long sessions lose older detail.
- The approach prevents runaway memory growth and keeps inspection cheap enough for interactive use.

## Concurrency Model
### Decision
Each accepted connection is handled by its own async task. Observation events travel through bounded channels to a single store actor that serializes state mutations. The UI and exporters only read snapshots. Long-running maintenance work, such as certificate installation or diagnostics, runs in separate background tasks.

### Trade-offs
- A single writer makes state easier to reason about and test.
- The store actor can become a bottleneck if messages are too large or too frequent.
- Bounded channels make overload visible instead of silently consuming memory.

## Async Runtime Decisions
### Decision
The process uses one runtime at the edge of the system for I/O, timers, and orchestration. Core domain code stays runtime-agnostic. Any blocking work is isolated into dedicated tasks or thread pools instead of being allowed onto the hot path. Nested runtimes are avoided.

### Trade-offs
- A runtime dependency adds binary size and operational complexity.
- Keeping runtime concerns at the boundary protects the core from framework churn.
- One runtime simplifies cancellation, backpressure, and task coordination.

## Error Handling Strategy
### Decision
Errors are typed by module and translated at boundaries into user-facing diagnostics. A malformed packet or decoder failure degrades the affected flow rather than crashing the whole process. The same containment rule will apply to the planned plugin host. Critical infrastructure failures stop the relevant session, not the entire tool.

### Trade-offs
- The error taxonomy is larger than a single generic error type.
- The richer model makes it easier to distinguish recoverable from fatal problems.
- The product should prefer partial visibility over total failure.

## Logging
### Decision
Logs are structured, correlated, and redacted by default. Every important event carries flow identifiers, protocol labels, and sensitivity markers. Human-facing diagnostics stay separate from machine-readable logs and counters.

### Trade-offs
- Structured logging requires more discipline than free-form text.
- Redaction can hide details that a debugger might wish to see, but the safety benefit is stronger.
- Correlation IDs make cross-module debugging much easier.

## Configuration System
### Decision
Configuration precedence is fixed: command-line flags, environment variables, project configuration, user configuration, then defaults. A validated configuration object is built once during startup. A diagnostic command should print the resolved effective configuration so users can see what won.

### Trade-offs
- Layered configuration is more complex than a single file or only flags.
- The hierarchy supports both quick local use and repeatable team workflows.
- Unsafe or privacy-sensitive settings must require explicit opt-in rather than hidden defaults.

## Dependency Injection Strategy
### Decision
Dependencies are passed in through constructors. The CLI is the composition root that wires concrete implementations together. Time, filesystem, trust-store, network, identity lookup, store, and decoder behavior are abstracted behind traits or interfaces where tests and platform adapters need them.

### Trade-offs
- Constructor wiring is more verbose than a global service locator.
- The resulting system is easier to test, mock, and reason about.
- Keeping the composition root in one place prevents scattered bootstrap logic.

## Extension Points
### Decision
The implemented system exposes seams for protocol decoders, redaction, exports, replay, platform trust, process identity, and native redirection control records. Windows WFP source is isolated under `drivers/windows`; its user-mode policy is dynamic, so filters disappear when the Lens session closes or crashes. Linux nftables and macOS PF adapters, discovery backends, and plugins remain extension work. The default explicit build works without privileged extensions.

### Trade-offs
- More seams mean more versioning and compatibility discipline.
- The extensibility is valuable because the product will evolve across protocols, platforms, and workflows.
- Explicit boundaries keep extensions from contaminating the core model.

## Summary
This architecture intentionally favors portable correctness, safe observability, and bounded resource usage over kernel-level magic. The cost is a bit more setup and a more explicit system shape. The benefit is a product that works across platforms, remains safe around secrets, and can evolve without rewriting the core.
