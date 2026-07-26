# Performance Budget

## Purpose
Lens is an always-on debugging proxy, so performance targets must be measurable and strict enough to preserve the user's interactive experience.

The right question is not whether the tool is fast in the abstract. The right question is whether it can stay near-pass-through while still capturing useful observability data.

## Performance Principles
- Forwarding latency matters more than perfect observability.
- The hot path must stay bounded under load.
- Allocation growth should be visible and controlled.
- Metrics should distinguish the data plane from the control plane.
- Benchmarks should be repeatable enough to compare across commits.

### Trade-offs
- A stricter budget may reduce feature richness in the hot path, but it keeps the tool usable while the user's own workload is running.
- Performance work is only meaningful when it is tied to specific benchmarks and measurable regressions.

## Measurable Targets

| Category | Target |
| --- | --- |
| Cold start | `lens run` should reach a usable ready state in under 2 seconds on a warm local build and under 5 seconds on a fresh binary on a typical developer laptop |
| Memory idle | Under 80 MiB resident memory while idle with the TUI open and no active traffic |
| Memory active | Under 256 MiB resident memory with a moderate active workload and bounded capture enabled |
| Added latency | Less than 1 ms p99 added latency for localhost HTTP forwarding in the steady state |
| CPU idle | Less than 5% of one core when idle with the session open |
| CPU active | Less than 25% of one core for a moderate single-flow workload, excluding intentionally heavy export or benchmark operations |
| Allocation count | No unbounded allocation growth in the steady state; allocations per request should remain low and predictable |
| Buffer size | Default per-body capture cap: 256 KiB; default flow ring: bounded and eviction-based rather than unbounded |
| Maximum throughput | Saturate a single core's loopback bandwidth before the data plane becomes the bottleneck; the exact number should be measured per platform rather than guessed |
| Event drop policy | Under overload, observability may degrade, but forwarded traffic must continue whenever possible |

### Trade-offs
- These targets are intentionally conservative enough to protect a real developer laptop, but aggressive enough to keep the tool feeling instant.
- Throughput is platform dependent, so the exact number should be measured and tracked per CI runner class instead of hard-coded as a universal claim.

## Cold Start Budget
### Targets
- Process startup and CLI parsing: under 200 ms on a warm build
- Config load and validation: under 100 ms
- Trust and certificate readiness checks: under 500 ms when already configured
- First interactive frame or ready prompt: under 2 seconds from process start in the common case

### Trade-offs
- Early validation makes startup more trustworthy, but it must not become a slow blocking ritual.
- If trust setup is required, it is acceptable for first-time startup to be slower than the steady state, but the user should see exactly why.

## Memory Budget
### Targets
- Idle baseline: under 80 MiB resident memory
- Active capture: under 256 MiB resident memory by default
- Per-message body cap: 256 KiB unless the user overrides it
- Flow history cap: bounded ring with visible eviction once full
- Queue depth: bounded and measurable at all stages

### Trade-offs
- Lower memory budgets force more truncation and eviction, but that is preferable to runaway growth.
- A ring-based store reduces memory risk, but it means long-running sessions must use export if they need full history.

## Latency Budget
### Targets
- Added p50 latency for localhost HTTP forwarding: effectively negligible in the common case, ideally below 0.5 ms
- Added p99 latency for localhost HTTP forwarding: under 1 ms
- TLS handshake overhead should be measurable but not dominant for short-lived connections
- UI refresh should not stall forwarding even when the user is navigating flows

### Trade-offs
- A proxy that adds too much latency is not acceptable, even if it captures more metadata.
- The budget favors the data plane over deep synchronous inspection.

## CPU Budget
### Targets
- Idle CPU usage: under 5% of one core
- Moderate workload CPU usage: under 25% of one core
- Heavy workloads should scale mostly with traffic volume, not with hidden background churn
- Background tasks such as export and benchmark should be explicit about their cost

### Trade-offs
- A few more CPU cycles in redaction or framing are acceptable if they buy strong safety and better diagnostics.
- CPU overhead should be paid in the control plane, not the forwarding path, whenever possible.

## Allocation Budget
### Targets
- Avoid per-byte allocations in the hot path
- Keep allocations per request low and predictable
- Reuse buffers where possible
- Prefer shared immutable payload storage over repeated cloning

### Trade-offs
- Some allocation overhead is acceptable for correctness and clarity.
- The important thing is that allocation patterns are stable and visible, not hidden and unbounded.

## Buffer Size Budget
### Targets
- Default request/response body capture cap: 256 KiB
- Default reassembly buffers: bounded and phase-specific
- Default queue sizes: bounded MPSC channels sized to absorb short bursts, not sustained overload
- Default flow history: fixed-size ring with eviction counters

### Trade-offs
- Smaller buffers reduce memory pressure but increase truncation risk.
- Larger buffers improve fidelity but can destabilize the tool under load.
- The default should favor safe interactive use rather than archival completeness.

## Maximum Throughput Budget
### Targets
- The proxy should be able to saturate loopback traffic on a single core before the inspection path becomes the bottleneck in the common case
- Throughput should be measured separately for:
  - plain HTTP forwarding
  - TLS termination and re-origination
  - decode plus redaction enabled
  - headless capture versus TUI capture

### Trade-offs
- There is no honest single throughput number without a workload definition.
- The goal is not to promise a specific magic number; the goal is to guarantee that throughput is tracked consistently across workloads and platforms.

## Benchmark Methodology
### Benchmark layers
1. microbenchmarks for decoders, redaction, and store insertion
2. integration benchmarks for proxy forwarding with a local echo or database service
3. end-to-end benchmarks for latency, throughput, and memory under real traffic shapes
4. regression benchmarks in CI against stored baselines

### Workloads to include
- short HTTP request/response bursts
- sustained local HTTP traffic
- TLS interception workloads
- PostgreSQL protocol traffic
- long-lived connections with periodic messages
- large bodies near the truncation limit
- shutdown during active traffic

### Measurement rules
- run each benchmark multiple times
- compare against a known baseline
- record platform and runner details
- separate warm-cache and cold-start numbers
- track both median behavior and tail latency
- report memory alongside latency and throughput

### Trade-offs
- Benchmarking in CI introduces noise, but it is the only way to spot regressions early.
- Real workloads are more valuable than synthetic ones alone, but synthetic microbenchmarks are easier to bisect when something slows down.

## CI Strategy

The weekly `Resource smoke` workflow now records maximum resident memory for the release-mode saturated-observation test and rejects runs above a 512 MiB runner-level safety ceiling. This ceiling includes the test harness and is a catastrophic-regression gate, not a replacement for the 256 MiB product target. The `Hardening` workflow separately proves bounded store retention, queue drops under overload, forwarding completion, and shutdown deadlines.

### Fast path
Every pull request should run:
- formatting checks
- lint checks
- unit tests
- a small integration smoke set
- a small golden/snapshot set where applicable

### Extended path
Nightly or gated jobs should run:
- full integration suites
- property tests
- fuzz smoke or corpus checks
- stress tests
- performance benchmarks against baselines
- docs and example validation where relevant

### Platform matrix
- Linux: primary full validation target
- macOS: cross-platform CLI and proxy behavior
- Windows: path handling, CLI behavior, and platform-specific edge cases

### Gating policy
- PRs should fail fast on functional regressions and major linting issues.
- Performance regressions should be compared against baselines and flagged when they exceed thresholds.
- Heavy stress and performance jobs can be scheduled or limited to specific branches to keep PR feedback fast.

### Trade-offs
- A broad CI matrix improves confidence, but it costs time and compute.
- The solution is tiered CI, not trying to run everything on every change.

## Suggested Regression Thresholds
- Added latency regression: fail if p99 regresses by more than 10% against baseline on the same runner class
- Memory regression: warn or fail if resident memory grows by more than 15% in steady-state benchmarks
- Allocation regression: flag if allocations per request materially increase without an intentional design change
- Throughput regression: fail if sustained throughput drops by more than 10% on representative workloads

### Trade-offs
- Thresholds need to be strict enough to matter, but not so strict that normal measurement noise becomes a constant source of false alarms.
- Nightly baselines and labeled runner classes can reduce false positives.

## Reporting Format
The benchmark output should always include:
- benchmark name
- runner/platform
- commit or revision identifier
- workload description
- latency summary
- throughput summary
- memory summary
- allocation summary when available
- pass/fail status against baseline

### Trade-offs
- More reporting fields make regressions easier to interpret.
- More fields also mean more maintenance, but the alternative is opaque benchmark numbers that no one can act on.

## Final Position
Lens should feel fast because it preserves the user's foreground workload.

The proxy can afford to be clever only if the cleverness stays within measurable budgets for startup time, memory, latency, CPU, allocations, buffers, and throughput. Anything that cannot be measured should not be treated as a performance claim.
