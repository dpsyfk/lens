//! Bounded, single-writer in-memory flow store.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use lens_core::{
    Direction, EventEnvelope, EventSource, FlowId, FlowRecord, FlowState, MessageId, MessageRecord,
    ObservationEvent, ObservationKind, RunId, Sensitivity,
};
use lens_proto_http1::Http1Decoder;
use lens_proto_postgres::PostgresDecoder;
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
            "{{\"flow_id\":{},\"client\":\"{}\",\"upstream\":\"{}\",\"protocol\":{},\"state\":\"{}\",\"client_to_upstream_bytes\":{},\"upstream_to_client_bytes\":{},\"failure\":{},\"decoder_error\":{},\"messages\":{}}}",
            self.record
                .envelope
                .flow_id
                .unwrap_or_default()
                .get(),
            escape_json(&self.record.client.to_string()),
            escape_json(&self.record.upstream.to_string()),
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

impl StoreSnapshot {
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
    Postgres(Box<PostgresDecoder>),
}

impl ProtocolDecoder {
    fn push(&mut self, direction: Direction, bytes: &[u8]) -> DecodeBatch {
        match self {
            Self::Http1(decoder) => decoder.push(direction, bytes),
            Self::Postgres(decoder) => decoder.push(direction, bytes),
        }
    }

    fn finish(&mut self, direction: Direction) -> DecodeBatch {
        match self {
            Self::Http1(decoder) => decoder.finish(direction),
            Self::Postgres(decoder) => decoder.finish(direction),
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
    pending_requests: HashMap<FlowId, VecDeque<u64>>,
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
            self.pending_requests.remove(&event.flow_id);
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
                        self.pending_requests.remove(&evicted_flow_id);
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
                    Some("postgres") => {
                        self.decoders.insert(
                            event.flow_id,
                            ProtocolDecoder::Postgres(Box::new(PostgresDecoder::new(
                                self.max_body,
                            ))),
                        );
                    }
                    _ => {}
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
            let boundary = decoded
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("lens-boundary"))
                .map(|(_, value)| value.as_str());
            let latency_nanos = match boundary {
                Some("request") => {
                    self.pending_requests
                        .entry(flow_id)
                        .or_default()
                        .push_back(timestamp.mono_nanos);
                    None
                }
                Some("response") => self
                    .pending_requests
                    .get_mut(&flow_id)
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

fn messages_json(messages: &[MessageRecord]) -> String {
    let values = messages
        .iter()
        .map(|message| {
            format!(
                "{{\"message_id\":{},\"direction\":{},\"summary\":\"{}\",\"body\":\"{}\",\"truncated\":{},\"latency_nanos\":{},\"sensitivity\":\"{}\"}}",
                message.envelope.message_id.unwrap_or_default().get(),
                json_string(message.envelope.direction.map(|value| value.to_string()).as_deref()),
                escape_json(&message.summary),
                escape_json(&String::from_utf8_lossy(&message.body)),
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
