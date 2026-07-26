//! Lens core primitives.
//!
//! ## Sprint Plan
//! 1. Core identifiers and event envelope. Tests: constructor, default state, display, and builder coverage.
//! 2. Flow and message ID newtypes. Tests: equality, hashing, and monotonic formatting.
//! 3. Direction, severity, and sensitivity enums. Tests: display forms and round-trip matching.
//! 4. Session identity model. Tests: session creation and association with flows.
//! 5. Time abstraction. Tests: fixed clock behavior and timestamp formatting.
//! 6. Core error enum. Tests: display text and classification mapping.
//! 7. CLI skeleton. Tests: argument parsing and default subcommand behavior.
//! 8. Config precedence resolver. Tests: flags over env over file over defaults.
//! 9. Help output contract. Tests: stable help text and examples.
//! 10. Doctor diagnostics. Tests: platform and trust-state reporting.
//! 11. Explicit proxy bind path. Tests: bind address validation and listener setup.
//! 12. Connection accept loop. Tests: accept lifecycle and teardown.
//! 13. Upstream resolution. Tests: config, SNI, and transparent lookup fixtures.
//! 14. Timeout policy. Tests: per-phase expiration and grace period handling.
//! 15. TLS CA generation primitives. Tests: key/cert metadata and validity invariants.
//! 16. Leaf certificate cache. Tests: cache hit, miss, and eviction behavior.
//! 17. Trust-store adapter. Tests: install, uninstall, and error propagation.
//! 18. HTTP/1.1 request framing. Tests: fragmented request corpus.
//! 19. HTTP/1.1 response framing. Tests: pipelined response corpus.
//! 20. Body truncation and buffer reuse. Tests: caps and reuse accounting.
//! 21. Backpressure counters. Tests: queue saturation and drop visibility.
//! 22. Graceful shutdown. Tests: drain, cancel, and bounded exit timing.
//! 23. Store actor. Tests: single-writer ordering and bounded retention.
//! 24. Flow indexing. Tests: lookup consistency and eviction semantics.
//! 25. Snapshot export. Tests: stable structured output fixtures.
//! 26. TUI shell. Tests: render smoke and state transitions.
//! 27. Flow map view. Tests: layout snapshot and label stability.
//! 28. Inspector view. Tests: field ordering and redacted/reveal states.
//! 29. Redaction engine. Tests: secret masking fixtures and rule coverage.
//! 30. PostgreSQL decoder. Tests: golden wire-protocol corpus.
//! 31. Protocol registry. Tests: detector selection and fallback behavior.
//! 32. Replay reader. Tests: captured artifact round-trip.
//! 33. Export formats. Tests: JSONL, JSON, and HAR goldens.
//! 34. Plugin ABI metadata. Tests: compatibility and version checks.
//! 35. Plugin sandbox host. Tests: fuel, memory, and host-call limits.
//! 36. Optional Linux discovery hook. Tests: feature gating and Linux-only behavior.
//! 37. Fuzz targets. Tests: smoke corpus and panic-free mutation runs.
//! 38. Stress harness. Tests: many connections, long bodies, and shutdown under load.
//! 39. Performance harness. Tests: latency, throughput, memory, and allocation regressions.
//! 40. Release validation and docs sync. Tests: workspace, docs, and release checklist.
//!
//! Milestone 1 implements the shared event envelope and identifier primitives.
//! Milestone 2 adds the first concrete flow and message record primitives.
//! Milestone 3 adds the session identity model and lifecycle state primitives.
//! Milestone 4 (sprints 5–6) adds the time abstraction and core error enum.
//! Milestone 5 (sprints 7–10) lives in `lens-cli` (CLI skeleton, config, help, doctor).
//! Milestone 6 (sprint 11) lives in `lens-proxy` (explicit proxy bind path).

use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Session identifier within a run.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(u64);

impl SessionId {
    /// Creates a new session identifier.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Flow identifier within a run.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowId(u64);

impl FlowId {
    /// Creates a new flow identifier.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Message identifier within a flow.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(u64);

impl MessageId {
    /// Creates a new message identifier.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Run identifier for a capture session.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RunId(u64);

impl RunId {
    /// Creates a new run identifier.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Version of the core event schema.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaVersion {
    /// Major schema version.
    pub major: u16,
    /// Minor schema version.
    pub minor: u16,
}

impl SchemaVersion {
    /// Current schema version for milestone 1.
    pub const CURRENT: Self = Self { major: 0, minor: 1 };

    /// Creates a new schema version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Traffic direction relative to the client.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Direction {
    /// Client to server.
    ClientToServer,
    /// Server to client.
    ServerToClient,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ClientToServer => "client_to_server",
            Self::ServerToClient => "server_to_client",
        })
    }
}

/// Log or event severity.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// Informational.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        })
    }
}

/// Sensitivity classification for captured data.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Sensitivity {
    /// Public data.
    Public,
    /// Data has been redacted.
    Redacted,
    /// Data contains secrets or plaintext payloads.
    Secret,
}

impl fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Public => "public",
            Self::Redacted => "redacted",
            Self::Secret => "secret",
        })
    }
}

/// Origin of an event in the pipeline.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EventSource {
    /// Proxy accept/forwarding path.
    Proxy,
    /// TLS certificate and handshake path.
    Tls,
    /// Protocol detection or decoding path.
    Decoder,
    /// Store and aggregation path.
    Store,
    /// User interface path.
    Ui,
    /// CLI and command path.
    Cli,
    /// Plugin host path.
    Plugin,
    /// Benchmark or stress harness path.
    Benchmark,
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Proxy => "proxy",
            Self::Tls => "tls",
            Self::Decoder => "decoder",
            Self::Store => "store",
            Self::Ui => "ui",
            Self::Cli => "cli",
            Self::Plugin => "plugin",
            Self::Benchmark => "benchmark",
        })
    }
}

/// Shared immutable event envelope.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventEnvelope {
    /// Semantic event name.
    pub event_type: String,
    /// Schema version for the payload.
    pub schema_version: SchemaVersion,
    /// Run identifier.
    pub run_id: RunId,
    /// Session identifier, when relevant.
    pub session_id: Option<SessionId>,
    /// Flow identifier, when relevant.
    pub flow_id: Option<FlowId>,
    /// Message identifier, when relevant.
    pub message_id: Option<MessageId>,
    /// Traffic direction, when relevant.
    pub direction: Option<Direction>,
    /// Monotonic timestamp in nanoseconds.
    pub ts_mono_nanos: u64,
    /// Wall-clock timestamp in nanoseconds.
    pub ts_wall_nanos: u64,
    /// Originating subsystem.
    pub source: EventSource,
    /// Severity classification.
    pub severity: Severity,
    /// Sensitivity classification.
    pub sensitivity: Sensitivity,
}

impl EventEnvelope {
    /// Creates a new default-safe envelope for a given event type.
    #[must_use]
    pub fn new(event_type: impl Into<String>, run_id: RunId, source: EventSource) -> Self {
        Self {
            event_type: event_type.into(),
            schema_version: SchemaVersion::CURRENT,
            run_id,
            session_id: None,
            flow_id: None,
            message_id: None,
            direction: None,
            ts_mono_nanos: 0,
            ts_wall_nanos: 0,
            source,
            severity: Severity::Info,
            sensitivity: Sensitivity::Public,
        }
    }

    /// Attaches a session identifier.
    #[must_use]
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Attaches a flow identifier.
    #[must_use]
    pub fn with_flow_id(mut self, flow_id: FlowId) -> Self {
        self.flow_id = Some(flow_id);
        self
    }

    /// Attaches a message identifier.
    #[must_use]
    pub fn with_message_id(mut self, message_id: MessageId) -> Self {
        self.message_id = Some(message_id);
        self
    }

    /// Attaches a direction.
    #[must_use]
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = Some(direction);
        self
    }

    /// Attaches both monotonic and wall-clock timestamps.
    #[must_use]
    pub fn with_timestamps(mut self, ts_mono_nanos: u64, ts_wall_nanos: u64) -> Self {
        self.ts_mono_nanos = ts_mono_nanos;
        self.ts_wall_nanos = ts_wall_nanos;
        self
    }

    /// Updates severity.
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Updates sensitivity.
    #[must_use]
    pub fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }
}

impl Default for EventEnvelope {
    fn default() -> Self {
        Self::new("event.unknown", RunId::new(0), EventSource::Cli)
    }
}

/// Network endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    /// Hostname or IP address.
    pub host: String,
    /// Network port.
    pub port: u16,
}

impl Endpoint {
    /// Creates a new endpoint.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Non-blocking observation emitted by the proxy data plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationEvent {
    /// Flow this event belongs to.
    pub flow_id: FlowId,
    /// Timestamp captured at the proxy boundary.
    pub timestamp: TimestampPair,
    /// Lifecycle or transfer information.
    pub kind: ObservationKind,
}

impl ObservationEvent {
    /// Creates an observation for a flow.
    #[must_use]
    pub const fn new(flow_id: FlowId, timestamp: TimestampPair, kind: ObservationKind) -> Self {
        Self {
            flow_id,
            timestamp,
            kind,
        }
    }
}

/// Payload carried by a proxy observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationKind {
    /// A client flow has selected an upstream target.
    Opened {
        /// Client endpoint.
        client: Endpoint,
        /// Selected upstream endpoint.
        upstream: Endpoint,
        /// Protocol classification available at routing time.
        protocol: Option<String>,
    },
    /// Bytes were forwarded in one direction.
    Transferred {
        /// Direction relative to the client.
        direction: Direction,
        /// Number of bytes forwarded.
        bytes: u64,
    },
    /// Mirrored bytes for control-plane decoding. Delivery is best-effort.
    Data {
        /// Direction relative to the client.
        direction: Direction,
        /// One bounded forwarding fragment.
        bytes: Vec<u8>,
    },
    /// The flow completed normally.
    Closed,
    /// The flow failed without terminating the proxy session.
    Failed {
        /// Safe operational reason suitable for diagnostics.
        reason: String,
    },
}

/// Aggregate flow status.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FlowState {
    /// The flow is currently active.
    Open,
    /// The flow closed normally.
    Closed,
    /// The flow failed or was truncated.
    Failed,
}

impl fmt::Display for FlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Failed => "failed",
        })
    }
}

/// Aggregate flow record used by the store and UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRecord {
    /// Flow envelope.
    pub envelope: EventEnvelope,
    /// Client-side endpoint.
    pub client: Endpoint,
    /// Upstream endpoint.
    pub upstream: Endpoint,
    /// Protocol label, if known.
    pub protocol: Option<String>,
    /// Current flow state.
    pub state: FlowState,
    /// Messages observed in this flow.
    pub message_ids: Vec<MessageId>,
}

impl FlowRecord {
    /// Creates a new open flow record.
    #[must_use]
    pub fn new(envelope: EventEnvelope, client: Endpoint, upstream: Endpoint) -> Self {
        Self {
            envelope,
            client,
            upstream,
            protocol: None,
            state: FlowState::Open,
            message_ids: Vec::new(),
        }
    }

    /// Attaches a protocol label.
    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Updates the flow state.
    #[must_use]
    pub fn with_state(mut self, state: FlowState) -> Self {
        self.state = state;
        self
    }

    /// Records a message identifier.
    pub fn push_message_id(&mut self, message_id: MessageId) {
        self.message_ids.push(message_id);
    }
}

/// Normalized message record used by the store and export layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRecord {
    /// Message envelope.
    pub envelope: EventEnvelope,
    /// Human-readable summary.
    pub summary: String,
    /// Payload bytes.
    pub body: Vec<u8>,
    /// Whether the payload was truncated.
    pub truncated: bool,
    /// Request-to-terminal-response latency when the protocol exposes a boundary.
    pub latency_nanos: Option<u64>,
}

impl MessageRecord {
    /// Creates a new message record from an envelope and payload.
    #[must_use]
    pub fn new(
        envelope: EventEnvelope,
        summary: impl Into<String>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            envelope,
            summary: summary.into(),
            body: body.into(),
            truncated: false,
            latency_nanos: None,
        }
    }

    /// Marks the message payload as truncated.
    #[must_use]
    pub fn with_truncated(mut self, truncated: bool) -> Self {
        self.truncated = truncated;
        self
    }

    /// Attaches a protocol-level request/response latency.
    #[must_use]
    pub const fn with_latency_nanos(mut self, latency_nanos: Option<u64>) -> Self {
        self.latency_nanos = latency_nanos;
        self
    }
}

/// Session lifecycle state.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SessionState {
    /// The session is active.
    Open,
    /// The session closed normally.
    Closed,
    /// The session failed or was interrupted.
    Failed,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Failed => "failed",
        })
    }
}

/// Identity metadata associated with a capture session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SessionIdentity {
    /// Optional display label for the session owner.
    pub label: Option<String>,
    /// Optional user or account name.
    pub user: Option<String>,
    /// Optional container or service name.
    pub container: Option<String>,
    /// Optional executable path.
    pub binary_path: Option<String>,
}

impl SessionIdentity {
    /// Creates an empty session identity.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a display label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Sets the user or account name.
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Sets the container or service name.
    #[must_use]
    pub fn with_container(mut self, container: impl Into<String>) -> Self {
        self.container = Some(container.into());
        self
    }

    /// Sets the executable path.
    #[must_use]
    pub fn with_binary_path(mut self, binary_path: impl Into<String>) -> Self {
        self.binary_path = Some(binary_path.into());
        self
    }
}

/// Session-level aggregate record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    /// Session envelope.
    pub envelope: EventEnvelope,
    /// Identity information for the owner or workload.
    pub identity: SessionIdentity,
    /// Current session state.
    pub state: SessionState,
    /// Associated flow identifiers.
    pub flow_ids: Vec<FlowId>,
}

impl SessionRecord {
    /// Creates a new session record.
    #[must_use]
    pub fn new(envelope: EventEnvelope, identity: SessionIdentity) -> Self {
        Self {
            envelope,
            identity,
            state: SessionState::Open,
            flow_ids: Vec::new(),
        }
    }

    /// Updates the session state.
    #[must_use]
    pub fn with_state(mut self, state: SessionState) -> Self {
        self.state = state;
        self
    }

    /// Records a flow identifier for the session.
    pub fn push_flow_id(&mut self, flow_id: FlowId) {
        self.flow_ids.push(flow_id);
    }
}

/// Pair of monotonic and wall-clock timestamps in nanoseconds.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TimestampPair {
    /// Monotonic timestamp in nanoseconds.
    pub mono_nanos: u64,
    /// Wall-clock timestamp in nanoseconds since the Unix epoch.
    pub wall_nanos: u64,
}

impl TimestampPair {
    /// Creates a new timestamp pair.
    #[must_use]
    pub const fn new(mono_nanos: u64, wall_nanos: u64) -> Self {
        Self {
            mono_nanos,
            wall_nanos,
        }
    }
}

impl fmt::Display for TimestampPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mono={}ns wall={}ns", self.mono_nanos, self.wall_nanos)
    }
}

/// Clock abstraction used by capture pipelines and tests.
pub trait Clock: Send + Sync {
    /// Returns the current monotonic and wall-clock timestamps.
    fn now(&self) -> TimestampPair;

    /// Convenience accessor for the monotonic clock only.
    fn mono_nanos(&self) -> u64 {
        self.now().mono_nanos
    }

    /// Convenience accessor for the wall clock only.
    fn wall_nanos(&self) -> u64 {
        self.now().wall_nanos
    }
}

/// System clock backed by `Instant` and `SystemTime`.
#[derive(Clone, Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// Creates a system clock with a fresh monotonic origin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> TimestampPair {
        let mono_nanos = self.origin.elapsed().as_nanos() as u64;
        let wall_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64;
        TimestampPair::new(mono_nanos, wall_nanos)
    }
}

/// Fixed clock for deterministic tests and replay.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FixedClock {
    mono_nanos: u64,
    wall_nanos: u64,
}

impl FixedClock {
    /// Creates a fixed clock at the given timestamps.
    #[must_use]
    pub const fn new(mono_nanos: u64, wall_nanos: u64) -> Self {
        Self {
            mono_nanos,
            wall_nanos,
        }
    }

    /// Advances both clocks by the same duration.
    pub fn advance(&mut self, duration: Duration) {
        let delta = duration.as_nanos() as u64;
        self.mono_nanos = self.mono_nanos.saturating_add(delta);
        self.wall_nanos = self.wall_nanos.saturating_add(delta);
    }

    /// Sets absolute timestamps.
    pub fn set(&mut self, mono_nanos: u64, wall_nanos: u64) {
        self.mono_nanos = mono_nanos;
        self.wall_nanos = wall_nanos;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> TimestampPair {
        TimestampPair::new(self.mono_nanos, self.wall_nanos)
    }
}

/// High-level classification for core errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorClass {
    /// Invalid user input or configuration.
    User,
    /// Recoverable operational failure (I/O, bind, etc.).
    Operational,
    /// Internal invariant violation.
    Internal,
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "user",
            Self::Operational => "operational",
            Self::Internal => "internal",
        })
    }
}

/// Shared error type for pure domain and cross-crate boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreError {
    /// Invalid argument supplied by a caller or config surface.
    InvalidArgument {
        /// Argument name.
        name: String,
        /// Provided value.
        value: String,
        /// Expected form.
        expected: String,
    },
    /// A required resource was not found.
    NotFound {
        /// Resource kind.
        kind: String,
        /// Resource identifier.
        id: String,
    },
    /// An operation failed for operational reasons.
    OperationFailed {
        /// Short operation label.
        operation: String,
        /// Underlying cause text.
        cause: String,
    },
    /// An internal invariant was violated.
    Invariant {
        /// Description of the broken invariant.
        message: String,
    },
}

impl CoreError {
    /// Returns the error class for routing diagnostics.
    #[must_use]
    pub const fn class(&self) -> ErrorClass {
        match self {
            Self::InvalidArgument { .. } => ErrorClass::User,
            Self::NotFound { .. } | Self::OperationFailed { .. } => ErrorClass::Operational,
            Self::Invariant { .. } => ErrorClass::Internal,
        }
    }

    /// Creates an invalid-argument error.
    #[must_use]
    pub fn invalid_argument(
        name: impl Into<String>,
        value: impl Into<String>,
        expected: impl Into<String>,
    ) -> Self {
        Self::InvalidArgument {
            name: name.into(),
            value: value.into(),
            expected: expected.into(),
        }
    }

    /// Creates a not-found error.
    #[must_use]
    pub fn not_found(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            kind: kind.into(),
            id: id.into(),
        }
    }

    /// Creates an operation-failed error.
    #[must_use]
    pub fn operation_failed(operation: impl Into<String>, cause: impl Into<String>) -> Self {
        Self::OperationFailed {
            operation: operation.into(),
            cause: cause.into(),
        }
    }

    /// Creates an invariant error.
    #[must_use]
    pub fn invariant(message: impl Into<String>) -> Self {
        Self::Invariant {
            message: message.into(),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument {
                name,
                value,
                expected,
            } => write!(
                f,
                "invalid argument `{name}`: got `{value}`, expected {expected}"
            ),
            Self::NotFound { kind, id } => write!(f, "{kind} not found: {id}"),
            Self::OperationFailed { operation, cause } => {
                write!(f, "{operation} failed: {cause}")
            }
            Self::Invariant { message } => write!(f, "invariant violated: {message}"),
        }
    }
}

impl std::error::Error for CoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_defaults_are_safe_and_stable() {
        let envelope = EventEnvelope::new("flow.opened", RunId::new(7), EventSource::Proxy);

        assert_eq!(envelope.event_type, "flow.opened");
        assert_eq!(envelope.schema_version, SchemaVersion::CURRENT);
        assert_eq!(envelope.run_id, RunId::new(7));
        assert_eq!(envelope.session_id, None);
        assert_eq!(envelope.flow_id, None);
        assert_eq!(envelope.message_id, None);
        assert_eq!(envelope.direction, None);
        assert_eq!(envelope.ts_mono_nanos, 0);
        assert_eq!(envelope.ts_wall_nanos, 0);
        assert_eq!(envelope.source, EventSource::Proxy);
        assert_eq!(envelope.severity, Severity::Info);
        assert_eq!(envelope.sensitivity, Sensitivity::Public);
    }

    #[test]
    fn envelope_builder_attaches_context() {
        let envelope = EventEnvelope::new("message.emitted", RunId::new(9), EventSource::Decoder)
            .with_session_id(SessionId::new(11))
            .with_flow_id(FlowId::new(13))
            .with_message_id(MessageId::new(17))
            .with_direction(Direction::ClientToServer)
            .with_timestamps(19, 23)
            .with_severity(Severity::Warning)
            .with_sensitivity(Sensitivity::Redacted);

        assert_eq!(envelope.session_id, Some(SessionId::new(11)));
        assert_eq!(envelope.flow_id, Some(FlowId::new(13)));
        assert_eq!(envelope.message_id, Some(MessageId::new(17)));
        assert_eq!(envelope.direction, Some(Direction::ClientToServer));
        assert_eq!(envelope.ts_mono_nanos, 19);
        assert_eq!(envelope.ts_wall_nanos, 23);
        assert_eq!(envelope.severity, Severity::Warning);
        assert_eq!(envelope.sensitivity, Sensitivity::Redacted);
    }

    #[test]
    fn display_forms_are_stable() {
        assert_eq!(SessionId::new(5).to_string(), "5");
        assert_eq!(FlowId::new(6).to_string(), "6");
        assert_eq!(MessageId::new(7).to_string(), "7");
        assert_eq!(RunId::new(8).to_string(), "8");
        assert_eq!(SchemaVersion::new(2, 4).to_string(), "2.4");
        assert_eq!(Direction::ClientToServer.to_string(), "client_to_server");
        assert_eq!(Direction::ServerToClient.to_string(), "server_to_client");
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Error.to_string(), "error");
        assert_eq!(Sensitivity::Public.to_string(), "public");
        assert_eq!(Sensitivity::Redacted.to_string(), "redacted");
        assert_eq!(Sensitivity::Secret.to_string(), "secret");
        assert_eq!(EventSource::Proxy.to_string(), "proxy");
        assert_eq!(EventSource::Tls.to_string(), "tls");
        assert_eq!(EventSource::Decoder.to_string(), "decoder");
        assert_eq!(EventSource::Store.to_string(), "store");
        assert_eq!(EventSource::Ui.to_string(), "ui");
        assert_eq!(EventSource::Cli.to_string(), "cli");
        assert_eq!(EventSource::Plugin.to_string(), "plugin");
        assert_eq!(EventSource::Benchmark.to_string(), "benchmark");
    }

    #[test]
    fn endpoint_flow_and_message_records_are_constructible() {
        let flow_envelope = EventEnvelope::new("flow.opened", RunId::new(42), EventSource::Store)
            .with_session_id(SessionId::new(3))
            .with_flow_id(FlowId::new(5));
        let client = Endpoint::new("127.0.0.1", 51515);
        let upstream = Endpoint::new("example.com", 443);

        let mut flow = FlowRecord::new(flow_envelope.clone(), client.clone(), upstream.clone())
            .with_protocol("http1");
        flow.push_message_id(MessageId::new(99));

        assert_eq!(flow.envelope, flow_envelope);
        assert_eq!(flow.client, client);
        assert_eq!(flow.upstream, upstream);
        assert_eq!(flow.protocol.as_deref(), Some("http1"));
        assert_eq!(flow.state, FlowState::Open);
        assert_eq!(flow.message_ids, vec![MessageId::new(99)]);
        assert_eq!(flow.client.to_string(), "127.0.0.1:51515");
        assert_eq!(flow.upstream.to_string(), "example.com:443");
        assert_eq!(FlowState::Open.to_string(), "open");
        assert_eq!(FlowState::Closed.to_string(), "closed");
        assert_eq!(FlowState::Failed.to_string(), "failed");

        let message_envelope =
            EventEnvelope::new("message.emitted", RunId::new(42), EventSource::Decoder)
                .with_flow_id(FlowId::new(5))
                .with_message_id(MessageId::new(99))
                .with_direction(Direction::ClientToServer)
                .with_sensitivity(Sensitivity::Redacted);
        let message =
            MessageRecord::new(message_envelope.clone(), "GET /health", b"hello".to_vec())
                .with_truncated(true);

        assert_eq!(message.envelope, message_envelope);
        assert_eq!(message.summary, "GET /health");
        assert_eq!(message.body, b"hello");
        assert!(message.truncated);
        assert_eq!(message.latency_nanos, None);
    }

    #[test]
    fn session_identity_and_record_track_associated_flows() {
        let session_envelope =
            EventEnvelope::new("session.started", RunId::new(77), EventSource::Proxy)
                .with_session_id(SessionId::new(11));
        let identity = SessionIdentity::new()
            .with_label("api-service")
            .with_user("alice")
            .with_container("checkout")
            .with_binary_path("/usr/bin/app");

        let mut session = SessionRecord::new(session_envelope.clone(), identity.clone())
            .with_state(SessionState::Closed);
        session.push_flow_id(FlowId::new(101));
        session.push_flow_id(FlowId::new(202));

        assert_eq!(session.envelope, session_envelope);
        assert_eq!(session.identity, identity);
        assert_eq!(session.state, SessionState::Closed);
        assert_eq!(session.identity.label.as_deref(), Some("api-service"));
        assert_eq!(session.identity.user.as_deref(), Some("alice"));
        assert_eq!(session.identity.container.as_deref(), Some("checkout"));
        assert_eq!(
            session.identity.binary_path.as_deref(),
            Some("/usr/bin/app")
        );
        assert_eq!(SessionState::Open.to_string(), "open");
        assert_eq!(SessionState::Closed.to_string(), "closed");
        assert_eq!(SessionState::Failed.to_string(), "failed");
        assert_eq!(session.flow_ids, vec![FlowId::new(101), FlowId::new(202)]);
    }

    #[test]
    fn fixed_clock_is_deterministic_and_advances() {
        let mut clock = FixedClock::new(1_000, 2_000);
        assert_eq!(clock.now(), TimestampPair::new(1_000, 2_000));
        assert_eq!(clock.mono_nanos(), 1_000);
        assert_eq!(clock.wall_nanos(), 2_000);
        assert_eq!(clock.now().to_string(), "mono=1000ns wall=2000ns");

        clock.advance(Duration::from_nanos(50));
        assert_eq!(clock.now(), TimestampPair::new(1_050, 2_050));

        clock.set(9, 11);
        assert_eq!(clock.now(), TimestampPair::new(9, 11));
    }

    #[test]
    fn system_clock_reports_non_zero_wall_time() {
        let clock = SystemClock::new();
        let first = clock.now();
        let second = clock.now();

        assert!(first.wall_nanos > 0);
        assert!(second.mono_nanos >= first.mono_nanos);
        assert!(second.wall_nanos >= first.wall_nanos);
    }

    #[test]
    fn core_error_display_and_class_mapping() {
        let invalid = CoreError::invalid_argument("listen", "nope", "addr:port");
        assert_eq!(invalid.class(), ErrorClass::User);
        assert_eq!(
            invalid.to_string(),
            "invalid argument `listen`: got `nope`, expected addr:port"
        );

        let missing = CoreError::not_found("flow", "42");
        assert_eq!(missing.class(), ErrorClass::Operational);
        assert_eq!(missing.to_string(), "flow not found: 42");

        let failed = CoreError::operation_failed("bind", "address in use");
        assert_eq!(failed.class(), ErrorClass::Operational);
        assert_eq!(failed.to_string(), "bind failed: address in use");

        let invariant = CoreError::invariant("store closed");
        assert_eq!(invariant.class(), ErrorClass::Internal);
        assert_eq!(invariant.to_string(), "invariant violated: store closed");

        assert_eq!(ErrorClass::User.to_string(), "user");
        assert_eq!(ErrorClass::Operational.to_string(), "operational");
        assert_eq!(ErrorClass::Internal.to_string(), "internal");
    }
}
