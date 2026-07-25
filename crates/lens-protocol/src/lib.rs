//! Runtime-neutral contracts for incremental protocol decoders.

use lens_core::Direction;

/// A complete protocol message emitted by a streaming decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedMessage {
    /// Traffic direction relative to the client.
    pub direction: Direction,
    /// Request/status line or equivalent protocol summary.
    pub start_line: String,
    /// Parsed headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Decoded, capped body bytes.
    pub body: Vec<u8>,
    /// True when the body exceeded the configured capture cap.
    pub truncated: bool,
}

impl DecodedMessage {
    /// Produces a stable human-facing summary.
    #[must_use]
    pub fn summary(&self) -> String {
        self.start_line.clone()
    }

    /// Renders headers and captured body for storage and export.
    #[must_use]
    pub fn render(&self) -> Vec<u8> {
        let mut rendered = Vec::new();
        for (name, value) in &self.headers {
            rendered.extend_from_slice(name.as_bytes());
            rendered.extend_from_slice(b": ");
            rendered.extend_from_slice(value.as_bytes());
            rendered.extend_from_slice(b"\r\n");
        }
        rendered.extend_from_slice(b"\r\n");
        rendered.extend_from_slice(&self.body);
        rendered
    }
}

/// Result of feeding one byte fragment to a decoder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecodeBatch {
    /// Zero or more complete messages recovered from this fragment.
    pub messages: Vec<DecodedMessage>,
    /// Recoverable parser desynchronization, when detected.
    pub desynchronized: Option<String>,
}

impl DecodeBatch {
    /// Creates an empty "need more bytes" result.
    #[must_use]
    pub const fn need_more() -> Self {
        Self {
            messages: Vec::new(),
            desynchronized: None,
        }
    }
}

/// Incremental, per-flow decoder contract.
pub trait StreamingDecoder: Send {
    /// Stable protocol label.
    fn protocol(&self) -> &'static str;

    /// Feeds a possibly partial fragment into one traffic direction.
    fn push(&mut self, direction: Direction, bytes: &[u8]) -> DecodeBatch;

    /// Signals EOF for a direction and flushes any close-delimited message.
    fn finish(&mut self, direction: Direction) -> DecodeBatch;
}
