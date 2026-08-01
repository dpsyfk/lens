//! Bounded, single-writer in-memory flow store.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use lens_core::{
    Direction, EventEnvelope, EventSource, FlowId, FlowRecord, FlowState, MessageId, MessageRecord,
    ObservationEvent, ObservationKind, RunId, Sensitivity, ServiceIdentity,
};
use lens_proto_http1::Http1Decoder;
use lens_proto_http2::Http2Decoder;
use lens_proto_postgres::PostgresDecoder;
use lens_proto_redis::RedisDecoder;
use lens_protocol::{DecodeBatch, StreamingDecoder};
use lens_redact::Redactor;
use tokio::sync::mpsc;

/// Flow record plus transfer counters maintained by the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredFlow {
    /// Canonical flow lifecycle record.
    pub record: FlowRecord,
    /// Bytes copied from client to upstream.
    pub client_to_upstream_bytes: u64,
    /// Bytes copied from upstream to client.
    pub upstream_to_client_bytes: u64,
    /// Safe operational failure reason, when present.
    pub failure: Option<String>,
    /// Recoverable decoder warning, when inspection lost framing.
    pub decoder_error: Option<String>,
    /// Redacted, body-capped messages decoded for this flow.
    pub messages: Vec<MessageRecord>,
}

impl StoredFlow {
    /// Renders a compact JSONL-compatible summary without payload data.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"schema_version\":\"1.2\",\"flow_id\":{},\"client\":\"{}\",\"upstream\":\"{}\",\"identity\":{},\"protocol\":{},\"state\":\"{}\",\"client_to_upstream_bytes\":{},\"upstream_to_client_bytes\":{},\"failure\":{},\"decoder_error\":{},\"messages\":{}}}",
            self.record
                .envelope
                .flow_id
                .unwrap_or_default()
                .get(),
            escape_json(&self.record.client.to_string()),
            escape_json(&self.record.upstream.to_string()),
            identity_json(self.record.identity.as_ref()),
            json_string(self.record.protocol.as_deref()),
            self.record.state,
            self.client_to_upstream_bytes,
            self.upstream_to_client_bytes,
            json_string(self.failure.as_deref()),
            json_string(self.decoder_error.as_deref()),
            messages_json(&self.messages)
        )
    }
}

/// Immutable copy of the current bounded store state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreSnapshot {
    /// Flows ordered from oldest retained to newest.
    pub flows: Vec<StoredFlow>,
    /// Number of old flows evicted by the retention cap.
    pub evicted: u64,
}

/// One deterministic service-to-upstream edge derived from retained flows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceEdge {
    /// Upstream endpoint reached by the service.
    pub upstream: String,
    /// Number of retained flows on this edge.
    pub flows: u64,
}

/// Aggregate node used by the terminal service map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceNode {
    /// Stable service or process label.
    pub service: String,
    /// Distinct process names observed for this service.
    pub processes: Vec<String>,
    /// Distinct process identifiers observed for this service.
    pub pids: Vec<u32>,
    /// Total retained flows owned by this service.
    pub flows: u64,
    /// Currently open flows.
    pub open: u64,
    /// Failed flows.
    pub failed: u64,
    /// Deterministically ordered upstream edges.
    pub upstreams: Vec<ServiceEdge>,
}

impl StoreSnapshot {
    /// Builds a deterministic service map from the current bounded flow snapshot.
    #[must_use]
    pub fn service_map(&self) -> Vec<ServiceNode> {
        #[derive(Default)]
        struct Aggregate {
            processes: BTreeSet<String>,
            pids: BTreeSet<u32>,
            flows: u64,
            open: u64,
            failed: u64,
            upstreams: BTreeMap<String, u64>,
        }

        let mut services = BTreeMap::<String, Aggregate>::new();
        for flow in &self.flows {
            let identity = flow.record.identity.as_ref();
            let service = identity.map_or("unknown", ServiceIdentity::display_name);
            let entry = services.entry(service.to_string()).or_default();
            if let Some(process) = identity.and_then(|value| value.process.as_ref()) {
                entry.processes.insert(process.clone());
            }
            if let Some(pid) = identity.and_then(|value| value.pid) {
                entry.pids.insert(pid);
            }
            entry.flows = entry.flows.saturating_add(1);
            entry.open = entry
                .open
                .saturating_add(u64::from(flow.record.state == FlowState::Open));
            entry.failed = entry
                .failed
                .saturating_add(u64::from(flow.record.state == FlowState::Failed));
            let upstream = flow.record.upstream.to_string();
            let count = entry.upstreams.entry(upstream).or_default();
            *count = count.saturating_add(1);
        }
        services
            .into_iter()
            .map(|(service, aggregate)| ServiceNode {
                service,
                processes: aggregate.processes.into_iter().collect(),
                pids: aggregate.pids.into_iter().collect(),
                flows: aggregate.flows,
                open: aggregate.open,
                failed: aggregate.failed,
                upstreams: aggregate
                    .upstreams
                    .into_iter()
                    .map(|(upstream, flows)| ServiceEdge { upstream, flows })
                    .collect(),
            })
            .collect()
    }

    /// Renders one safe flow object per line for streaming diagnostics.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        self.flows
            .iter()
            .map(StoredFlow::to_json_line)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Renders a deterministic JSON snapshot for file export.
    #[must_use]
    pub fn to_json(&self) -> String {
        let flows = self
            .flows
            .iter()
            .map(StoredFlow::to_json_line)
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"evicted\":{},\"flows\":[{flows}]}}", self.evicted)
    }
}

#[derive(Debug, Default)]
struct StoreState {
    flows: VecDeque<StoredFlow>,
    evicted: u64,
    next_message_id: u64,
}

#[derive(Debug)]
enum ProtocolDecoder {
    Http1(Box<Http1Decoder>),
    Http2(Box<Http2Decoder>),
    Postgres(Box<PostgresDecoder>),
    Redis(Box<RedisDecoder>),
}

impl ProtocolDecoder {
    fn push(&mut self, direction: Direction, bytes: &[u8]) -> DecodeBatch {
        match self {
            Self::Http1(decoder) => decoder.push(direction, bytes),
            Self::Http2(decoder) => decoder.push(direction, bytes),
            Self::Postgres(decoder) => decoder.push(direction, bytes),
            Self::Redis(decoder) => decoder.push(direction, bytes),
        }
    }

    fn finish(&mut self, direction: Direction) -> DecodeBatch {
        match self {
            Self::Http1(decoder) => decoder.finish(direction),
            Self::Http2(decoder) => decoder.finish(direction),
            Self::Postgres(decoder) => decoder.finish(direction),
            Self::Redis(decoder) => decoder.finish(direction),
        }
    }
}

/// Read-only handle used by UI and export consumers.
#[derive(Clone, Debug)]
pub struct StoreHandle {
    state: Arc<RwLock<StoreState>>,
}

impl StoreHandle {
    /// Returns an immutable point-in-time copy.
    #[must_use]
    pub fn snapshot(&self) -> StoreSnapshot {
        let state = self.state.read().unwrap_or_else(|error| error.into_inner());
        StoreSnapshot {
            flows: state.flows.iter().cloned().collect(),
            evicted: state.evicted,
        }
    }
}

/// Single consumer that serializes all store mutations.
#[derive(Debug)]
pub struct StoreActor {
    state: Arc<RwLock<StoreState>>,
    max_flows: usize,
    run_id: RunId,
    max_body: usize,
    reveal: bool,
    decoders: HashMap<FlowId, ProtocolDecoder>,
    pending_requests: HashMap<(FlowId, String), VecDeque<u64>>,
    redactor: Redactor,
}

impl StoreActor {
    /// Creates a bounded actor and its read-only handle.
    #[must_use]
    pub fn new(max_flows: usize, run_id: RunId) -> (Self, StoreHandle) {
        Self::with_inspection(max_flows, run_id, 262_144, false)
    }

    /// Creates an actor with explicit body and reveal settings.
    #[must_use]
    pub fn with_inspection(
        max_flows: usize,
        run_id: RunId,
        max_body: usize,
        reveal: bool,
    ) -> (Self, StoreHandle) {
        assert!(max_flows > 0, "max_flows must be positive");
        assert!(max_body > 0, "max_body must be positive");
        let state = Arc::new(RwLock::new(StoreState::default()));
        (
            Self {
                state: Arc::clone(&state),
                max_flows,
                run_id,
                max_body,
                reveal,
                decoders: HashMap::new(),
                pending_requests: HashMap::new(),
                redactor: Redactor::new(reveal),
            },
            StoreHandle { state },
        )
    }

    /// Consumes observations until every sender is dropped.
    pub async fn run(mut self, mut receiver: mpsc::Receiver<ObservationEvent>) {
        while let Some(event) = receiver.recv().await {
            self.apply(event);
        }
    }

    fn apply(&mut self, event: ObservationEvent) {
        if let ObservationKind::Data { direction, bytes } = &event.kind {
            let batch = self
                .decoders
                .get_mut(&event.flow_id)
                .map(|decoder| decoder.push(*direction, bytes));
            if let Some(batch) = batch {
                self.store_batch(event.flow_id, event.timestamp, batch);
            }
            return;
        }

        if matches!(
            &event.kind,
            ObservationKind::Closed | ObservationKind::Failed { .. }
        ) {
            if let Some(mut decoder) = self.decoders.remove(&event.flow_id) {
                let client = decoder.finish(Direction::ClientToServer);
                self.store_batch(event.flow_id, event.timestamp, client);
                let server = decoder.finish(Direction::ServerToClient);
                self.store_batch(event.flow_id, event.timestamp, server);
            }
            self.pending_requests
                .retain(|(flow_id, _), _| *flow_id != event.flow_id);
        }

        let mut state = self
            .state
            .write()
            .unwrap_or_else(|error| error.into_inner());
        match event.kind {
            ObservationKind::Opened {
                client,
                upstream,
                protocol,
            } => {
                if state.flows.len() == self.max_flows {
                    let evicted_flow_id = state
                        .flows
                        .pop_front()
                        .and_then(|flow| flow.record.envelope.flow_id);
                    if let Some(evicted_flow_id) = evicted_flow_id {
                        self.decoders.remove(&evicted_flow_id);
                        self.pending_requests
                            .retain(|(flow_id, _), _| *flow_id != evicted_flow_id);
                    }
                    state.evicted = state.evicted.saturating_add(1);
                }
                let envelope = EventEnvelope::new("flow.opened", self.run_id, EventSource::Proxy)
                    .with_flow_id(event.flow_id)
                    .with_timestamps(event.timestamp.mono_nanos, event.timestamp.wall_nanos);
                let mut record = FlowRecord::new(envelope, client, upstream);
                if let Some(protocol) = protocol {
                    record = record.with_protocol(protocol);
                }
                state.flows.push_back(StoredFlow {
                    record,
                    client_to_upstream_bytes: 0,
                    upstream_to_client_bytes: 0,
                    failure: None,
                    decoder_error: None,
                    messages: Vec::new(),
                });
                match state
                    .flows
                    .back()
                    .and_then(|flow| flow.record.protocol.as_deref())
                {
                    Some("http1") => {
                        self.decoders.insert(
                            event.flow_id,
                            ProtocolDecoder::Http1(Box::new(Http1Decoder::new(self.max_body))),
                        );
                    }
                    Some("http2" | "grpc") => {
                        self.decoders.insert(
                            event.flow_id,
                            ProtocolDecoder::Http2(Box::new(Http2Decoder::new(self.max_body))),
                        );
                    }
                    Some("postgres") => {
                        self.decoders.insert(
                            event.flow_id,
                            ProtocolDecoder::Postgres(Box::new(PostgresDecoder::new(
                                self.max_body,
                            ))),
                        );
                    }
                    Some("redis") => {
                        self.decoders.insert(
                            event.flow_id,
                            ProtocolDecoder::Redis(Box::new(RedisDecoder::new(self.max_body))),
                        );
                    }
                    _ => {}
                }
            }
            ObservationKind::Identified { identity } => {
                if let Some(flow) = find_flow_mut(&mut state.flows, event.flow_id) {
                    flow.record.identity = Some(identity);
                }
            }
            ObservationKind::ProtocolDetected { protocol } => {
                if let Some(flow) = find_flow_mut(&mut state.flows, event.flow_id) {
                    flow.record.protocol = Some(protocol.clone());
                }
                let decoder = match protocol.as_str() {
                    "http1" => Some(ProtocolDecoder::Http1(Box::new(Http1Decoder::new(
                        self.max_body,
                    )))),
                    "http2" | "grpc" => Some(ProtocolDecoder::Http2(Box::new(Http2Decoder::new(
                        self.max_body,
                    )))),
                    "postgres" => Some(ProtocolDecoder::Postgres(Box::new(PostgresDecoder::new(
                        self.max_body,
                    )))),
                    "redis" => Some(ProtocolDecoder::Redis(Box::new(RedisDecoder::new(
                        self.max_body,
                    )))),
                    _ => None,
                };
                if let Some(decoder) = decoder {
                    self.decoders.insert(event.flow_id, decoder);
                } else {
                    self.decoders.remove(&event.flow_id);
                }
            }
            ObservationKind::Transferred { direction, bytes } => {
                if let Some(flow) = find_flow_mut(&mut state.flows, event.flow_id) {
                    match direction {
                        Direction::ClientToServer => {
                            flow.client_to_upstream_bytes =
                                flow.client_to_upstream_bytes.saturating_add(bytes);
                        }
                        Direction::ServerToClient => {
                            flow.upstream_to_client_bytes =
                                flow.upstream_to_client_bytes.saturating_add(bytes);
                        }
                    }
                }
            }
            ObservationKind::Data { .. } => unreachable!("handled before locking the store"),
            ObservationKind::Closed => {
                if let Some(flow) = find_flow_mut(&mut state.flows, event.flow_id) {
                    flow.record.state = FlowState::Closed;
                }
            }
            ObservationKind::Failed { reason } => {
                if let Some(flow) = find_flow_mut(&mut state.flows, event.flow_id) {
                    flow.record.state = FlowState::Failed;
                    flow.failure = Some(reason);
                }
            }
        }
    }

    fn store_batch(
        &mut self,
        flow_id: FlowId,
        timestamp: lens_core::TimestampPair,
        batch: DecodeBatch,
    ) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(reason) = batch.desynchronized {
            if let Some(flow) = find_flow_mut(&mut state.flows, flow_id) {
                flow.decoder_error = Some(reason);
            }
        }
        for decoded in batch.messages {
            let stream_id = decoded
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("lens-stream-id"))
                .map_or_else(String::new, |(_, value)| value.clone());
            let request_key = (flow_id, stream_id);
            let decoded_protocol = decoded
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("lens-protocol"))
                .map(|(_, value)| value.clone());
            let boundary = decoded
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("lens-boundary"))
                .map(|(_, value)| value.as_str());
            let latency_nanos = match boundary {
                Some("request") => {
                    self.pending_requests
                        .entry(request_key.clone())
                        .or_default()
                        .push_back(timestamp.mono_nanos);
                    None
                }
                Some("response") => self
                    .pending_requests
                    .get_mut(&request_key)
                    .and_then(VecDeque::pop_front)
                    .map(|started| timestamp.mono_nanos.saturating_sub(started)),
                _ => None,
            };
            state.next_message_id = state.next_message_id.saturating_add(1);
            let message_id = MessageId::new(state.next_message_id);
            let direction = decoded.direction;
            let truncated = decoded.truncated;
            let outcome = self.redactor.redact(decoded);
            let sensitivity = if self.reveal {
                Sensitivity::Secret
            } else if outcome.redacted {
                Sensitivity::Redacted
            } else {
                Sensitivity::Public
            };
            let envelope = EventEnvelope::new("message.decoded", self.run_id, EventSource::Decoder)
                .with_flow_id(flow_id)
                .with_message_id(message_id)
                .with_direction(direction)
                .with_timestamps(timestamp.mono_nanos, timestamp.wall_nanos)
                .with_sensitivity(sensitivity);
            let message = MessageRecord::new(
                envelope,
                outcome.message.summary(),
                outcome.message.render(),
            )
            .with_truncated(truncated)
            .with_latency_nanos(latency_nanos);
            if let Some(flow) = find_flow_mut(&mut state.flows, flow_id) {
                if decoded_protocol.as_deref() == Some("grpc") {
                    flow.record.protocol = Some("grpc".to_string());
                }
                flow.record.push_message_id(message_id);
                flow.messages.push(message);
            }
        }
    }
}

fn find_flow_mut(flows: &mut VecDeque<StoredFlow>, flow_id: FlowId) -> Option<&mut StoredFlow> {
    flows
        .iter_mut()
        .find(|flow| flow.record.envelope.flow_id == Some(flow_id))
}

fn json_string(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn identity_json(identity: Option<&ServiceIdentity>) -> String {
    let Some(identity) = identity else {
        return "null".to_string();
    };
    format!(
        "{{\"pid\":{},\"process\":{},\"service\":{},\"container\":{}}}",
        identity
            .pid
            .map_or_else(|| "null".to_string(), |pid| pid.to_string()),
        json_string(identity.process.as_deref()),
        json_string(identity.service.as_deref()),
        json_string(identity.container.as_deref())
    )
}

fn messages_json(messages: &[MessageRecord]) -> String {
    let values = messages
        .iter()
        .map(|message| {
            format!(
                "{{\"message_id\":{},\"direction\":{},\"summary\":\"{}\",\"body\":\"{}\",\"wire_base64\":\"{}\",\"truncated\":{},\"latency_nanos\":{},\"sensitivity\":\"{}\"}}",
                message.envelope.message_id.unwrap_or_default().get(),
                json_string(message.envelope.direction.map(|value| value.to_string()).as_deref()),
                escape_json(&message.summary),
                escape_json(&String::from_utf8_lossy(&message.body)),
                BASE64.encode(&message.body),
                message.truncated,
                message.latency_nanos.map_or_else(|| "null".to_string(), |value| value.to_string()),
                message.envelope.sensitivity
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{values}]")
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use httlib_hpack::Encoder;
    use lens_core::{Endpoint, TimestampPair};

    fn opened(flow_id: u64) -> ObservationEvent {
        opened_with_protocol(flow_id, "http1", 80)
    }

    fn opened_with_protocol(flow_id: u64, protocol: &str, port: u16) -> ObservationEvent {
        ObservationEvent::new(
            FlowId::new(flow_id),
            TimestampPair::new(flow_id * 10, flow_id * 20),
            ObservationKind::Opened {
                client: Endpoint::new("127.0.0.1", 5000 + flow_id as u16),
                upstream: Endpoint::new("example.test", port),
                protocol: Some(protocol.to_string()),
            },
        )
    }

    fn postgres_startup() -> Vec<u8> {
        let mut payload = 196_608_u32.to_be_bytes().to_vec();
        payload.extend_from_slice(b"user\0alice\0database\0app\0\0");
        let mut frame = ((payload.len() + 4) as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame
    }

    fn postgres_message(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![tag];
        frame.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn redis_command(arguments: &[&str]) -> Vec<u8> {
        let mut frame = format!("*{}\r\n", arguments.len()).into_bytes();
        for argument in arguments {
            frame.extend_from_slice(format!("${}\r\n{}\r\n", argument.len(), argument).as_bytes());
        }
        frame
    }

    fn http2_frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let length = payload.len();
        let mut frame = vec![
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
            kind,
            flags,
        ];
        frame.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn hpack_headers(encoder: &mut Encoder<'_>, values: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for (name, value) in values {
            encoder
                .encode(
                    (
                        name.to_vec(),
                        value.to_vec(),
                        Encoder::WITH_INDEXING | Encoder::BEST_FORMAT,
                    ),
                    &mut encoded,
                )
                .unwrap();
        }
        encoded
    }

    #[tokio::test]
    async fn stores_lifecycle_and_transfer_counters_in_order() {
        let (actor, handle) = StoreActor::new(4, RunId::new(9));
        let (sender, receiver) = mpsc::channel(8);
        let task = tokio::spawn(actor.run(receiver));

        sender.send(opened(1)).await.unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(11, 21),
                ObservationKind::Transferred {
                    direction: Direction::ClientToServer,
                    bytes: 17,
                },
            ))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(12, 22),
                ObservationKind::Closed,
            ))
            .await
            .unwrap();
        drop(sender);
        task.await.unwrap();

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.flows.len(), 1);
        assert_eq!(snapshot.flows[0].record.state, FlowState::Closed);
        assert_eq!(snapshot.flows[0].client_to_upstream_bytes, 17);
        assert_eq!(snapshot.flows[0].record.envelope.run_id, RunId::new(9));
        assert!(snapshot.flows[0].to_json_line().contains("\"flow_id\":1"));
    }

    #[tokio::test]
    async fn evicts_the_oldest_flow_at_capacity() {
        let (actor, handle) = StoreActor::new(2, RunId::new(1));
        let (sender, receiver) = mpsc::channel(4);
        let task = tokio::spawn(actor.run(receiver));

        sender.send(opened(1)).await.unwrap();
        sender.send(opened(2)).await.unwrap();
        sender.send(opened(3)).await.unwrap();
        drop(sender);
        task.await.unwrap();

        let snapshot = handle.snapshot();
        let ids = snapshot
            .flows
            .iter()
            .map(|flow| flow.record.envelope.flow_id.unwrap().get())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec![2, 3]);
        assert_eq!(snapshot.evicted, 1);
    }

    #[tokio::test]
    async fn retention_remains_bounded_during_a_large_flow_burst() {
        const CAPACITY: usize = 128;
        const TOTAL: u64 = 4_096;
        let (actor, handle) = StoreActor::new(CAPACITY, RunId::new(1));
        let (sender, receiver) = mpsc::channel(64);
        let task = tokio::spawn(actor.run(receiver));

        for flow_id in 1..=TOTAL {
            sender.send(opened(flow_id)).await.unwrap();
        }
        drop(sender);
        task.await.unwrap();

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.flows.len(), CAPACITY);
        assert_eq!(snapshot.evicted, TOTAL - CAPACITY as u64);
        assert_eq!(
            snapshot.flows.first().unwrap().record.envelope.flow_id,
            Some(FlowId::new(TOTAL - CAPACITY as u64 + 1))
        );
        assert_eq!(
            snapshot.flows.last().unwrap().record.envelope.flow_id,
            Some(FlowId::new(TOTAL))
        );
    }

    #[tokio::test]
    async fn decoder_failure_is_contained_to_one_flow() {
        let (actor, handle) = StoreActor::with_inspection(4, RunId::new(5), 1024, false);
        let (sender, receiver) = mpsc::channel(8);
        let task = tokio::spawn(actor.run(receiver));

        sender.send(opened(1)).await.unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(11, 21),
                ObservationKind::Data {
                    direction: Direction::ClientToServer,
                    bytes: b"GET / HTTP/1.1\r\ninvalid-header\r\n\r\n".to_vec(),
                },
            ))
            .await
            .unwrap();
        sender.send(opened(2)).await.unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(2),
                TimestampPair::new(12, 22),
                ObservationKind::Data {
                    direction: Direction::ClientToServer,
                    bytes: b"GET /healthy HTTP/1.1\r\nHost: local\r\n\r\n".to_vec(),
                },
            ))
            .await
            .unwrap();
        drop(sender);
        task.await.unwrap();

        let snapshot = handle.snapshot();
        assert!(snapshot.flows[0].decoder_error.is_some());
        assert!(snapshot.flows[0].messages.is_empty());
        assert_eq!(snapshot.flows[1].messages.len(), 1);
        assert_eq!(
            snapshot.flows[1].messages[0].summary,
            "GET /healthy HTTP/1.1"
        );
    }

    #[tokio::test]
    async fn decodes_and_redacts_http_messages_before_storage() {
        let (actor, handle) = StoreActor::with_inspection(4, RunId::new(2), 1024, false);
        let (sender, receiver) = mpsc::channel(8);
        let task = tokio::spawn(actor.run(receiver));

        sender.send(opened(1)).await.unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(11, 21),
                ObservationKind::Data {
                    direction: Direction::ClientToServer,
                    bytes: b"POST /login?token=query-secret HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer header-secret\r\nContent-Type: application/json\r\nContent-Length: 39\r\n\r\n{\"password\":\"body-secret\",\"name\":\"Ada\"}"
                        .to_vec(),
                },
            ))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(12, 22),
                ObservationKind::Data {
                    direction: Direction::ServerToClient,
                    bytes: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
                },
            ))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(13, 23),
                ObservationKind::Closed,
            ))
            .await
            .unwrap();
        drop(sender);
        task.await.unwrap();

        let snapshot = handle.snapshot();
        let flow = &snapshot.flows[0];
        assert_eq!(flow.messages.len(), 2);
        assert_eq!(flow.record.message_ids.len(), 2);
        assert_eq!(flow.messages[0].envelope.sensitivity, Sensitivity::Redacted);
        assert_eq!(flow.messages[1].envelope.sensitivity, Sensitivity::Public);
        let exported = flow.to_json_line();
        assert!(exported.contains("\"schema_version\":\"1.2\""));
        assert!(exported.contains("\"wire_base64\":"));
        assert!(!exported.contains("query-secret"));
        assert!(!exported.contains("header-secret"));
        assert!(!exported.contains("body-secret"));
        assert!(exported.contains("[REDACTED]"));
        assert!(exported.contains("POST /login?token=[REDACTED] HTTP/1.1"));
        assert!(exported.contains("HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn body_limit_is_visible_and_reveal_mode_is_marked_secret() {
        let (actor, handle) = StoreActor::with_inspection(2, RunId::new(3), 4, true);
        let (sender, receiver) = mpsc::channel(4);
        let task = tokio::spawn(actor.run(receiver));

        sender.send(opened(1)).await.unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(11, 21),
                ObservationKind::Data {
                    direction: Direction::ClientToServer,
                    bytes: b"POST /?token=visible HTTP/1.1\r\nAuthorization: Bearer visible\r\nContent-Length: 8\r\n\r\nabcdefgh".to_vec(),
                },
            ))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(12, 22),
                ObservationKind::Closed,
            ))
            .await
            .unwrap();
        drop(sender);
        task.await.unwrap();

        let message = &handle.snapshot().flows[0].messages[0];
        assert!(message.truncated);
        assert_eq!(message.envelope.sensitivity, Sensitivity::Secret);
        assert!(message.summary.contains("token=visible"));
        let rendered = String::from_utf8_lossy(&message.body);
        assert!(rendered.contains("Bearer visible"));
        assert!(rendered.ends_with("abcd"));
    }

    #[tokio::test]
    async fn postgres_queries_are_redacted_and_paired_with_latency() {
        let (actor, handle) = StoreActor::with_inspection(2, RunId::new(4), 1024, false);
        let (sender, receiver) = mpsc::channel(8);
        let task = tokio::spawn(actor.run(receiver));

        sender
            .send(opened_with_protocol(1, "postgres", 5432))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(100, 200),
                ObservationKind::Data {
                    direction: Direction::ClientToServer,
                    bytes: postgres_startup(),
                },
            ))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(110, 210),
                ObservationKind::Data {
                    direction: Direction::ClientToServer,
                    bytes: postgres_message(
                        b'Q',
                        b"SELECT * FROM users WHERE token = 'secret' AND id = 42\0",
                    ),
                },
            ))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(175, 275),
                ObservationKind::Data {
                    direction: Direction::ServerToClient,
                    bytes: postgres_message(b'C', b"SELECT 1\0"),
                },
            ))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(180, 280),
                ObservationKind::Closed,
            ))
            .await
            .unwrap();
        drop(sender);
        task.await.unwrap();

        let snapshot = handle.snapshot();
        let flow = &snapshot.flows[0];
        assert_eq!(flow.record.protocol.as_deref(), Some("postgres"));
        assert_eq!(flow.messages.len(), 3);
        assert_eq!(flow.messages[1].envelope.sensitivity, Sensitivity::Redacted);
        assert_eq!(flow.messages[2].latency_nanos, Some(65));
        let exported = flow.to_json_line();
        assert!(!exported.contains("secret"));
        assert!(exported.contains("token = '?' AND id = ?"));
        assert!(exported.contains("\"latency_nanos\":65"));
    }

    #[tokio::test]
    async fn redis_credentials_and_response_values_are_redacted_before_storage() {
        let (actor, handle) = StoreActor::with_inspection(2, RunId::new(7), 1024, false);
        let (sender, receiver) = mpsc::channel(8);
        let task = tokio::spawn(actor.run(receiver));

        sender
            .send(opened_with_protocol(1, "redis", 6379))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(100, 200),
                ObservationKind::Data {
                    direction: Direction::ClientToServer,
                    bytes: redis_command(&["AUTH", "alice", "hunter2"]),
                },
            ))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(125, 225),
                ObservationKind::Data {
                    direction: Direction::ServerToClient,
                    bytes: b"$13\r\nprivate-value\r\n".to_vec(),
                },
            ))
            .await
            .unwrap();
        drop(sender);
        task.await.unwrap();

        let snapshot = handle.snapshot();
        let flow = &snapshot.flows[0];
        assert_eq!(flow.record.protocol.as_deref(), Some("redis"));
        assert_eq!(flow.messages.len(), 2);
        assert_eq!(flow.messages[0].envelope.sensitivity, Sensitivity::Redacted);
        assert_eq!(flow.messages[1].envelope.sensitivity, Sensitivity::Redacted);
        assert_eq!(flow.messages[1].latency_nanos, Some(25));
        let exported = flow.to_json_line();
        assert!(!exported.contains("hunter2"));
        assert!(!exported.contains("private-value"));
        assert!(exported.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn http2_multiplexed_latency_is_paired_by_stream() {
        let (actor, handle) = StoreActor::with_inspection(2, RunId::new(8), 1024, false);
        let (sender, receiver) = mpsc::channel(16);
        let task = tokio::spawn(actor.run(receiver));
        sender
            .send(opened_with_protocol(1, "http2", 443))
            .await
            .unwrap();

        let mut request_encoder = Encoder::default();
        let request_one = hpack_headers(
            &mut request_encoder,
            &[
                (&b":method"[..], &b"GET"[..]),
                (&b":path"[..], &b"/slow"[..]),
                (&b"authorization"[..], &b"Bearer stream-secret"[..]),
            ],
        );
        let request_three = hpack_headers(
            &mut request_encoder,
            &[
                (&b":method"[..], &b"GET"[..]),
                (&b":path"[..], &b"/fast"[..]),
            ],
        );
        let mut first = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        first.extend(http2_frame(1, 0x5, 1, &request_one));
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(100, 200),
                ObservationKind::Data {
                    direction: Direction::ClientToServer,
                    bytes: first,
                },
            ))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(200, 300),
                ObservationKind::Data {
                    direction: Direction::ClientToServer,
                    bytes: http2_frame(1, 0x5, 3, &request_three),
                },
            ))
            .await
            .unwrap();

        let mut response_encoder = Encoder::default();
        let response = hpack_headers(&mut response_encoder, &[(b":status", b"200")]);
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(250, 350),
                ObservationKind::Data {
                    direction: Direction::ServerToClient,
                    bytes: http2_frame(1, 0x5, 3, &response),
                },
            ))
            .await
            .unwrap();
        let response = hpack_headers(&mut response_encoder, &[(b":status", b"200")]);
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(400, 500),
                ObservationKind::Data {
                    direction: Direction::ServerToClient,
                    bytes: http2_frame(1, 0x5, 1, &response),
                },
            ))
            .await
            .unwrap();
        drop(sender);
        task.await.unwrap();

        let flow = &handle.snapshot().flows[0];
        assert_eq!(flow.messages.len(), 4);
        assert_eq!(flow.messages[2].summary, "HTTP/2 200");
        assert_eq!(flow.messages[2].latency_nanos, Some(50));
        assert_eq!(flow.messages[3].latency_nanos, Some(300));
        let exported = flow.to_json_line();
        assert!(!exported.contains("stream-secret"));
        assert!(exported.contains("authorization: [REDACTED]"));
    }

    #[tokio::test]
    async fn identity_enriches_exports_and_the_service_map() {
        let (actor, handle) = StoreActor::new(4, RunId::new(5));
        let (sender, receiver) = mpsc::channel(8);
        let task = tokio::spawn(actor.run(receiver));

        sender.send(opened(1)).await.unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(11, 21),
                ObservationKind::Identified {
                    identity: ServiceIdentity::new()
                        .with_pid(731)
                        .with_process("python")
                        .with_service("checkout-api"),
                },
            ))
            .await
            .unwrap();
        sender
            .send(ObservationEvent::new(
                FlowId::new(1),
                TimestampPair::new(12, 22),
                ObservationKind::Failed {
                    reason: "fixture failure".to_string(),
                },
            ))
            .await
            .unwrap();
        drop(sender);
        task.await.unwrap();

        let snapshot = handle.snapshot();
        let identity = snapshot.flows[0].record.identity.as_ref().unwrap();
        assert_eq!(identity.pid, Some(731));
        assert_eq!(identity.display_name(), "checkout-api");
        let exported = snapshot.flows[0].to_json_line();
        assert!(exported.contains("\"identity\":{\"pid\":731"));
        assert!(exported.contains("\"service\":\"checkout-api\""));

        let services = snapshot.service_map();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].service, "checkout-api");
        assert_eq!(services[0].processes, vec!["python"]);
        assert_eq!(services[0].pids, vec![731]);
        assert_eq!((services[0].flows, services[0].failed), (1, 1));
        assert_eq!(services[0].upstreams[0].upstream, "example.test:80");
    }

    #[test]
    fn snapshot_exports_are_deterministic_and_jsonl_has_one_flow_per_line() {
        let mut snapshot = StoreSnapshot {
            flows: Vec::new(),
            evicted: 2,
        };
        let envelope = EventEnvelope::new("flow.opened", RunId::new(1), EventSource::Proxy)
            .with_flow_id(FlowId::new(7));
        snapshot.flows.push(StoredFlow {
            record: FlowRecord::new(
                envelope,
                Endpoint::new("127.0.0.1", 5000),
                Endpoint::new("example.test", 443),
            )
            .with_protocol("http1"),
            client_to_upstream_bytes: 4,
            upstream_to_client_bytes: 8,
            failure: None,
            decoder_error: None,
            messages: Vec::new(),
        });

        assert_eq!(snapshot.to_jsonl().lines().count(), 1);
        assert_eq!(
            snapshot.to_json(),
            format!("{{\"evicted\":2,\"flows\":[{}]}}", snapshot.to_jsonl())
        );
    }
}
