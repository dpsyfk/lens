# Testing Strategy

## Purpose
Lens is a systems-heavy developer tool, so the testing strategy must protect correctness, safety, and performance at the same time.

The goal is not just to prove that the code compiles. The goal is to prove that traffic still forwards, secrets stay redacted, protocols stay parseable, memory stays bounded, and regressions are visible before they ship.

## Testing Principles
- Test the smallest useful unit first.
- Test behavior, not implementation details.
- Keep the fast feedback loop fast.
- Use deterministic tests where possible.
- Use real-world fixtures and integration targets where correctness depends on protocol or OS behavior.
- Treat performance and memory regressions as bugs, not just observations.
- Make CI fast enough to trust and rich enough to catch the failure modes that matter.

### Trade-offs
- More test layers mean more maintenance, but they reduce the chance of shipping broken protocol, proxy, or redaction behavior.
- Real integration tests are slower than mocks, but they are much better at catching the problems that matter in a network tool.
- A balanced strategy is more work up front, but it is cheaper than chasing production bugs in a proxy that handles secrets.

## Unit Tests
### Scope
Unit tests should cover pure or mostly pure logic in:
- `lens-core`
- `lens-redact`
- `lens-plugin`
- portable `lens-ebpf` event parsing and cache correlation
- `lens-protocol`
- protocol decoders
- store indexing and flow aggregation logic
- configuration parsing and precedence resolution
- CLI argument interpretation
- error mapping and normalization

### What they should assert
- small deterministic transformations
- state machine transitions
- redaction rules and edge cases
- protocol framing decisions
- buffer accounting and truncation rules
- config merging order
- error classification and formatting
- WASM import rejection, ABI validation, fuel/memory/I/O limits, integrity checks, and trap containment
- eBPF fixed-width IPv4/IPv6 parsing, exact tuple consumption, retention, and self-exclusion

### Trade-offs
- Unit tests are fast and precise, but they cannot prove that the real network stack works.
- Good unit tests reduce the surface area needed for slower integration coverage.
- They are the cheapest place to enforce invariants like "never panic on malformed input."

## Integration Tests
### Scope
Integration tests should exercise real interactions between modules and real external systems where possible.

Examples:
- proxy to HTTP echo server
- proxy to PostgreSQL test instance
- TLS interception against a local test service
- config loading through actual files and environment variables
- CLI commands that interact with the filesystem and trust store abstractions
- store-to-UI snapshot pipeline
- redacted store-to-plugin annotations, including when the UI uses reveal mode
- Linux compilation of the embedded cgroup probe and its expected ELF sections

### What they should assert
- traffic forwards successfully
- TLS interception establishes the intended trust path
- captured flows contain the expected metadata
- errors are surfaced in the right subsystem
- shutdown drains in-flight work without truncating already-forwarded data
- the CLI behaves correctly in realistic environments

### Trade-offs
- Integration tests are slower and harder to debug than unit tests.
- They are essential because proxy behavior is mostly about subsystem interaction, not isolated functions.
- They can be fragile if they rely on too many external details, so the fixtures should stay intentionally small and controlled.

## Golden Tests
### Scope
Golden tests should cover textual and structured outputs that need stable formatting.

Examples:
- help output
- error message wording
- `doctor` diagnostics
- exported JSON or JSONL summaries
- CLI config summaries
- flow and message summaries

### What they should assert
- output structure stays stable
- important wording does not regress unexpectedly
- redaction still hides secrets in human-visible output
- structured export fields remain consistent

### Trade-offs
- Golden tests are excellent for user-facing contracts, but they can be noisy when formatting changes intentionally.
- They should be used for stable interfaces, not for every transient log line.
- Updating goldens should be a deliberate action so accidental churn is easy to spot.

## Snapshot Tests
### Scope
Snapshot tests should cover rendered UI states and structured summaries that are easier to compare visually than as individual assertions.

Examples:
- TUI flow map layouts
- inspector panes
- summary bars and counters
- diagnostics panels
- redacted versus revealed render states

### What they should assert
- layout remains legible
- labels and counts appear in the right places
- states do not collapse visually when data changes
- redaction state is obvious in the UI

### Trade-offs
- Snapshots are great at catching accidental UI regressions.
- They can be brittle when small layout tweaks are intentional.
- The best practice is to keep snapshots coarse enough to tolerate harmless text noise while still catching meaningful visual regressions.

## Property Testing
### Scope
Property testing should be used wherever the code is supposed to satisfy invariants over a large input space.

Examples:
- protocol parsers
- redaction rules
- flow aggregation invariants
- config precedence resolution
- ID generation and monotonicity
- truncation and buffer accounting

### Useful properties
- decoders never panic on arbitrary byte streams
- parsers either consume input or report that they need more data
- redaction never reveals a field it claims to mask
- flow counts remain internally consistent
- config merges are deterministic

### Trade-offs
- Property tests can find edge cases humans never think to write by hand.
- They require careful shrinking and seed management to stay debuggable.
- They are especially valuable for streaming parsers and state machines, where one bad edge case can corrupt an entire flow.

## Fuzzing
### Scope
Fuzzing should target the highest-risk parsing and boundary code.

Targets:
- HTTP parser inputs
- PostgreSQL wire parser inputs
- HTTP/2 frames, HPACK blocks, continuation sequences, and gRPC envelopes
- Redis RESP2/RESP3 frames, nesting, aggregates, pipelining, and pushes
- redaction parser inputs
- config file parser inputs
- export import readers
- event deserialization boundaries

### What fuzzing should catch
- panics
- hangs
- excessive memory growth
- malformed input handling bugs
- inconsistent parse states

### Trade-offs
- Fuzzing is slow to pay off but excellent at discovering deep parser bugs.
- It is most valuable when seeded with real protocol fixtures and then allowed to mutate from there.
- Fuzzing should protect the protocol edge, not replace normal tests.

## Stress Testing
### Scope
Stress tests should push throughput, concurrency, and memory pressure.

Examples:
- many concurrent local connections
- long-lived flows with many messages
- repeated session open/close cycles
- large bodies near the truncation limit
- high event rates with the store under pressure
- shutdown while traffic is still active

### What they should assert
- the proxy still forwards under load
- observability degrades before forwarding does
- queue depths remain bounded
- memory limits are enforced
- drop and eviction counters rise instead of the process crashing
- shutdown still completes within the configured grace period

### Trade-offs
- Stress tests are more realistic than small correctness tests, but they are also noisier and slower.
- They are essential for a proxy because overload behavior matters almost as much as happy-path behavior.
- Stress tests are best run as a scheduled or gated CI job rather than on every fast inner-loop edit.

## Performance Testing
### Scope
Performance tests should measure the cost of the proxy, decoder, redaction, storage, and UI pipeline.

Metrics:
- added latency per request
- throughput per core
- queue depth under load
- event drop rate
- memory growth over time
- certificate and handshake overhead
- snapshot rendering cost

### What they should assert
- regressions are visible and attributable
- the proxy stays within a defined latency budget
- memory use remains bounded under long runs
- optional features do not silently destroy the hot path

### Trade-offs
- Performance tests are harder to stabilize than functional tests.
- They should compare against baselines and trends, not just absolute numbers.
- They are a release-quality tool, not just a development curiosity.

## CI Strategy

The repository implements this hierarchy in `ci.yml`, `integration.yml`, `fuzz.yml`, `bench.yml`, and `docs.yml`. Parser corpus cases run in the stable workspace suite, while short libFuzzer mutation runs exercise the HTTP/1, HTTP/2/gRPC, PostgreSQL, and Redis state machines on relevant pull requests. Scheduled jobs extend load and resource reporting without slowing unrelated changes.

### Baseline pipeline
Every pull request should run a fast baseline that includes:
- formatting check
- clippy or equivalent linting
- unit tests
- a small set of integration tests
- golden and snapshot verification for stable interfaces

### Expanded pipeline
Additional jobs should cover:
- full integration tests
- property tests
- fuzz corpus checks or short fuzz smoke runs
- stress tests
- performance regressions
- docs or example validation where relevant

### Platform matrix
- Linux should be the primary CI target.
- macOS should validate cross-platform proxy and CLI behavior.
- Windows should validate path handling, config, and CLI behavior.
- Heavier jobs should be allowed to run on fewer platforms if the cost would otherwise make CI unusably slow.

### Trade-offs
- A wide CI matrix catches portability bugs, but it is expensive.
- The right answer is not to run everything everywhere; the right answer is to run the highest-value tests on each platform and reserve the heaviest work for dedicated jobs.
- CI should be fast enough that contributors do not avoid it, and strong enough that regressions are not waved through.

## Coverage Goals
### Goals by area
- Core logic libraries: target high coverage, ideally 90% or better where code is mostly pure and deterministic.
- Protocol parsers: prioritize branch and invariant coverage over raw line coverage.
- Proxy and I/O layers: rely more on integration, stress, and performance tests than on line-coverage vanity metrics.
- UI code: snapshot and state-transition coverage matter more than exhaustive line coverage.
- Fuzz targets: coverage is measured by corpus growth and bug discovery, not just percentage.

### Policy
- Coverage thresholds should be strict enough to matter, but not so strict that they force useless tests.
- The coverage gate should be applied primarily to deterministic libraries.
- Low-level socket and platform code should be judged by integration behavior and regression resistance rather than by raw coverage numbers alone.

### Trade-offs
- Coverage numbers are useful, but they can be misleading if used as the only quality signal.
- The best coverage strategy is layered: high unit coverage in pure code, strong integration coverage in system edges, and performance/stress coverage on the hot path.

## Suggested Test Hierarchy
1. Unit tests for pure logic.
2. Property tests for invariants and parser behavior.
3. Golden tests for textual contracts.
4. Snapshot tests for UI and structured view states.
5. Integration tests for module and system boundaries.
6. Fuzzing for parser and deserialization edges.
7. Stress tests for overload and shutdown behavior.
8. Performance tests for regression monitoring.

### Trade-offs
- A layered hierarchy makes it easier to pick the right tool for each failure mode.
- It also makes the test suite larger, so the CI plan must be selective and thoughtful.

## Final Position
Lens should be tested like a trust-sensitive network tool, not like a simple library.

That means the strategy must prove four things:
- traffic still moves
- secrets stay protected
- output stays stable
- performance stays bounded

If a test tier does not help prove one of those things, it should stay small, targeted, or optional.
