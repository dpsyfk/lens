//! Bounded, single-writer in-memory flow store.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use lens_core::{
    Direction, EventEnvelope, EventSource, FlowId, FlowRecord, FlowState, ObservationEvent,
    ObservationKind, RunId,
};
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
}

impl StoredFlow {
    /// Renders a compact JSONL-compatible summary without payload data.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"flow_id\":{},\"client\":\"{}\",\"upstream\":\"{}\",\"protocol\":{},\"state\":\"{}\",\"client_to_upstream_bytes\":{},\"upstream_to_client_bytes\":{},\"failure\":{}}}",
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
            json_string(self.failure.as_deref())
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

#[derive(Debug, Default)]
struct StoreState {
    flows: VecDeque<StoredFlow>,
    evicted: u64,
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
}

impl StoreActor {
    /// Creates a bounded actor and its read-only handle.
    #[must_use]
    pub fn new(max_flows: usize, run_id: RunId) -> (Self, StoreHandle) {
        assert!(max_flows > 0, "max_flows must be positive");
        let state = Arc::new(RwLock::new(StoreState::default()));
        (
            Self {
                state: Arc::clone(&state),
                max_flows,
                run_id,
            },
            StoreHandle { state },
        )
    }

    /// Consumes observations until every sender is dropped.
    pub async fn run(self, mut receiver: mpsc::Receiver<ObservationEvent>) {
        while let Some(event) = receiver.recv().await {
            self.apply(event);
        }
    }

    fn apply(&self, event: ObservationEvent) {
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
                    state.flows.pop_front();
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
                });
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
        ObservationEvent::new(
            FlowId::new(flow_id),
            TimestampPair::new(flow_id * 10, flow_id * 20),
            ObservationKind::Opened {
                client: Endpoint::new("127.0.0.1", 5000 + flow_id as u16),
                upstream: Endpoint::new("example.test", 80),
                protocol: Some("http1".to_string()),
            },
        )
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
}
