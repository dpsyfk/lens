# Security Review

## Scope
This review covers the Lens proxy-first architecture and its surrounding CLI, certificate management, decoder pipeline, plugin system, configuration system, export paths, and observability surfaces.

The review assumes the product intentionally handles decrypted traffic in a local trust boundary. That makes the biggest risks less about remote exploitation of a server and more about local abuse, sensitive-data handling, parser safety, and trust-store correctness.

## Threat Model
### Primary threats
- Man-in-the-middle abuse
- certificate misuse or trust-store compromise
- memory exhaustion
- denial of service
- malformed or hostile packets
- decoder implementation bugs
- plugin abuse
- configuration attacks

### Security goals
- Do not expose plaintext secrets unless the user explicitly opts in.
- Do not let malformed traffic crash the proxy or corrupt unrelated sessions.
- Do not let plugin failures or misbehavior compromise the host process.
- Do not let resource exhaustion turn into uncontrolled memory growth or deadlock.
- Do not let certificate or trust-store handling silently weaken the user’s machine trust boundary.
- Do not let configuration mistakes become hidden insecure defaults.

### Trade-offs
- The product is more useful when it can see decrypted traffic, but that means it must be much stricter about local trust and secret handling.
- A secure-by-default design creates some setup friction, but it is the only acceptable posture for a tool that handles secrets.

## Attack Surface Inventory

### 1. Network ingress and egress
#### Surface
- inbound client connections
- outbound upstream connections
- transparent interception redirection
- TLS handshake boundaries
- protocol detection on raw bytes

#### Risks
- malicious clients can send malformed traffic
- upstreams can misbehave or stall
- attacker-controlled payloads can attempt parser confusion
- interception logic can be abused to redirect traffic incorrectly

#### Mitigations
- strict session state machine
- bounded read and write buffers
- timeout per phase
- protocol detection confidence thresholds
- fail closed when trust state is invalid
- separate forwarding from observability so inspection failure does not block forwarding
- keep privileged redirectors payload-blind and version their pointer-free control records
- restrict the Windows control device to Local System and administrators
- exclude Lens upstream sockets and require a nonzero session generation to prevent redirect loops and stale activation
- permit the original connection if the redirector is unconfigured or encounters an internal failure

#### Residual risk
- any parser that reads arbitrary network bytes remains a target for denial of service and crash bugs.
- a kernel redirector defect can affect the entire host, so signed-driver review, Driver Verifier, and clean-machine rollback tests remain release gates.

### 2. MITM and certificate handling
#### Surface
- local CA generation
- leaf certificate issuance
- trust-store installation and removal
- hostname and SAN handling
- certificate cache
- certificate persistence on disk

#### Risks
- local CA private key theft
- certificate substitution or spoofing
- stale or overbroad trust-store installation
- hostname confusion or wildcard mistakes
- certificate cache poisoning
- user confusion around pinned or untrusted applications

#### Mitigations
- generate a unique user-scoped local CA
- protect CA private key with strict file permissions
- keep leaf certificates short-lived and per-host where possible
- cache leaves only for performance, not as a source of truth
- make trust-store install and uninstall explicit user actions
- verify hostname/SAN correctness before issuing a leaf cert
- surface certificate pinning failures clearly instead of silently bypassing them
- store fingerprints and audit metadata, not secrets, in diagnostics

#### Residual risk
- any local CA is a powerful trust anchor; if compromised, it can impersonate inspected hosts on the local machine.

### 3. Memory exhaustion
#### Surface
- body capture buffers
- reassembly buffers
- flow history ring
- plugin memory
- export buffering
- snapshot and UI copies

#### Risks
- large bodies consume too much RAM
- many concurrent flows cause unbounded growth
- protocol reassembly can accumulate partial state indefinitely
- plugin misuse can allocate excessively
- export of large captures can spike memory

#### Mitigations
- hard caps on per-body size
- hard caps on total resident flow history
- bounded MPSC queues
- bounded plugin memory and fuel limits
- eviction counters and visible truncation markers
- spill or truncate rather than expand indefinitely
- load-shedding on observability before forwarding is impacted

#### Residual risk
- finite limits mean some historical context is intentionally lost under sustained load.

### 4. Denial of service
#### Surface
- connection floods
- slowloris-style clients
- repeated handshake failures
- session churn
- oversized payloads
- heavy replay or export jobs
- expensive diagnostics

#### Risks
- connection slots become saturated
- handshake work consumes CPU and memory
- slow clients hold buffers open
- repeated retries create overload
- background jobs starve foreground capture

#### Mitigations
- per-listener and per-session concurrency limits
- idle, handshake, connect, and shutdown grace timeouts
- reject or drain behavior for over-capacity conditions
- rate-limit diagnostic-heavy background work
- keep the data plane independent from the inspection plane
- instrument queue depth and session count so overload is visible

#### Residual risk
- a local tool that accepts traffic can still be overloaded by a determined local user or malware on the same machine.

### 5. Malformed packets and hostile protocol inputs
#### Surface
- HTTP framing
- HTTP/2 framing and HPACK decompression
- gRPC message envelopes and opaque protobuf bodies
- PostgreSQL wire parsing
- Redis RESP2/RESP3 nesting and aggregate parsing
- partial reads and reassembly
- invalid UTF-8 or binary bodies
- mixed-direction state transitions
- truncated payloads

#### Risks
- crashes in parser edge cases
- desynchronization of stream state
- memory safety issues in low-level parsing code
- incorrect message boundaries leading to wrong inspection output
- infinite parse loops on malformed input

#### Mitigations
- streaming incremental parsers with explicit NeedMore and Desync states
- never assume a full message is available
- enforce parser progress invariants
- cap reassembly depth and body size
- cap HTTP/2 frame/header observation and Redis aggregate nesting/item counts
- fuzz parser boundaries heavily
- reject impossible state transitions
- treat parse failures as session degradation, not process failures

#### Residual risk
- any protocol parser can still hide an overlooked edge case, so fuzzing and golden fixtures are mandatory.

### 6. Decoder bugs
#### Surface
- protocol decoders
- redaction logic
- body normalization
- summary generation
- export transformations

#### Risks
- crash on unexpected protocol variants
- silent incorrect parsing
- leaked secrets due to a redaction bug
- event schema corruption
- memory aliasing or lifetime misuse in implementation

#### Mitigations
- strict decoder trait contract
- immutable event objects after emission
- decoder-specific corpus tests
- property tests for invariants
- golden tests for stable fixtures
- isolate decoder failures to the affected flow
- run decoders behind bounded queues and timeout guards

#### Residual risk
- decoders are the most likely place for subtle correctness issues because protocol variety is large and stateful.

### 7. Plugin abuse
#### Surface
- plugin installation
- plugin loading
- plugin execution
- plugin host calls
- plugin serialization boundaries

#### Risks
- malicious or buggy plugin reads sensitive data
- plugin consumes too much memory or CPU
- plugin tries to escape its sandbox
- plugin abuses host calls or claims unsupported protocols
- plugin supply-chain compromise

#### Mitigations
- use a sandboxed WASM host
- require explicit installation, never auto-load from CWD
- enforce fuel, memory, module, input, output, and retained-annotation limits
- reject every import, including WASI, so ABI v1 has no ambient capabilities
- version the plugin ABI
- validate ABI exports, metadata, and the installed SHA-256 before enabling it
- independently apply default redaction to plugin input even when the local UI uses reveal mode
- instantiate per call and contain traps or fuel exhaustion to the affected observation

#### Residual risk
- plugins are inherently untrusted code, so the sandbox is a containment layer, not a guarantee of zero risk. SHA-256 integrity does not authenticate a publisher.

### 7a. Linux eBPF discovery
#### Surface
- embedded cgroup connect and socket-operations programs
- privileged load and attach lifecycle
- fixed-width ring-buffer event ABI
- process and connection metadata

#### Risks
- excessive observation scope or unauthorized process monitoring
- verifier or kernel incompatibility
- stale or incorrect identity attribution
- persistent kernel programs after a crash

#### Mitigations
- explicit cgroup path and no automatic elevation, cgroup changes, or filesystem mounts
- metadata only: no payload, command-line, environment, or file access
- socket-cookie handoff followed by exact completed local tuple matching
- pointer-free fixed-size parser, bounded ring buffer/cache, and Lens PID exclusion
- process-owned unpinned links/maps detach on exit; failure to attach aborts only the requested discovery-enabled startup

#### Residual risk
- eBPF executes in a privileged kernel facility. Kernel version, policy, authorization, and narrow cgroup selection remain operator responsibilities.

### 8. Configuration attacks
#### Surface
- CLI flags
- environment variables
- project config files
- user config files
- config profiles
- export and replay inputs

#### Risks
- insecure defaults via hidden precedence
- malicious config overriding intended settings
- path traversal or unsafe file references
- wrong profile selected silently
- replay against the wrong target
- config-driven redaction disablement without obvious warning

#### Mitigations
- explicit precedence: flags, env, project, user, defaults
- show effective config in doctor output
- require confirmation for dangerous actions like replay or reveal
- validate file paths and writable targets
- print warnings when config disables privacy protections
- keep config parsing deterministic and strict

#### Residual risk
- any layered configuration system can be confusing, so the UX must surface the effective state clearly.

### 9. Export and replay surfaces
#### Surface
- capture export
- replay artifacts
- inspector output
- logs and diagnostics

#### Risks
- secrets leak into files or console output
- exports become a durable copy of sensitive traffic
- replay mutates remote systems unexpectedly
- path or file overwrites destroy user data

#### Mitigations
- redaction on by default in all exports
- explicit reveal mode with loud warnings
- require deliberate overwrite confirmation
- dry-run default for replay when ambiguity exists
- separate human-readable diagnostics from structured exports

#### Residual risk
- once a user explicitly exports or reveals data, the tool cannot control what they do with it afterward.

## Specific Review of Requested Threats

### MITM
#### Concern
The proxy is intentionally a MITM when TLS interception is enabled.

#### Mitigations
- make interception explicit and user-driven
- install and uninstall CA trust explicitly
- clearly label inspected versus tunneled traffic
- use a local-only CA and short-lived leaf certs
- warn about pinned applications and unsupported interception scenarios

### Certificate abuse
#### Concern
A compromised or misconfigured CA could impersonate trusted services.

#### Mitigations
- protect the CA private key with strict local permissions
- keep the CA scoped to the user profile and machine
- do not auto-export the CA unless requested
- log certificate installation and removal events
- make trust-store changes reversible and auditable

### Memory exhaustion
#### Concern
Large captures or many concurrent sessions can exhaust RAM.

#### Mitigations
- bounded buffers everywhere
- per-body caps
- flow history eviction
- bounded queues between stages
- plugin memory limits
- visible counters for truncation and eviction

### DoS
#### Concern
Attackers or accidental workloads can flood the proxy.

#### Mitigations
- concurrency limits
- timeouts per phase
- overload behavior that drops observability first
- graceful shutdown with bounded drain
- low-cost health and diagnostics paths

### Malformed packets
#### Concern
Bad traffic can crash parsers or desynchronize state.

#### Mitigations
- incremental parsers
- no unbounded recursion or buffering
- parser fuzzing and golden fixtures
- recoverable desync states
- per-flow error containment

### Decoder bugs
#### Concern
A decoder can misparse data or leak secrets.

#### Mitigations
- narrow decoder contract
- versioned event schema
- unit, property, golden, and fuzz coverage
- isolate failures to one flow
- never let decoder faults break forwarding

### Plugin abuse
#### Concern
A plugin can behave like a hostile extension.

#### Mitigations
- sandbox
- explicit install
- resource caps
- versioned ABI
- no ambient capabilities
- clear plugin claims and permissions

### Config attacks
#### Concern
A config file or environment variable can change behavior in unsafe ways.

#### Mitigations
- validated precedence
- effective config reporting
- explicit warnings for unsafe options
- path validation
- strict parsing

## Security Controls by Layer

### CLI layer
- require explicit confirmation for dangerous actions
- print loud warnings for reveal and replay
- keep help output clear about trust and privacy

### Proxy layer
- bound all queues and buffers
- time out all phases
- separate forwarding from observability
- prefer session-local failure over process-wide failure

### TLS layer
- explicit trust installation only
- short-lived leaf certs
- strict CA key permissions
- trustworthy certificate diagnostics

### Decoder layer
- streaming state machines
- no panics on malformed input
- tight parser invariants
- redaction before storage

### Plugin layer
- sandboxed execution
- explicit enablement
- memory and CPU quotas
- stable ABI and claims metadata

### Store and export layer
- bounded retention
- redacted exports by default
- visible eviction and truncation counters
- immutable snapshots for consumers

## Residual Risks
Even with these mitigations, some risks remain by design:
- the product intentionally handles sensitive plaintext
- any local CA introduces a trust anchor that must be managed carefully
- parsers will always carry some bug risk
- overload can still reduce observability quality
- plugins are only as safe as the sandbox and ABI discipline around them

## Final Position
Lens can be secure enough for its purpose if it treats trust, memory, parsing, and plugins as first-class security boundaries instead of incidental implementation details.

The core rule is simple: protect forwarding first, protect secrets by default, and make every dangerous capability explicit, bounded, and reversible.
