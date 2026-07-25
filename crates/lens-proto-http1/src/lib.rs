//! Incremental HTTP/1 request and response decoder.

use std::collections::VecDeque;

use lens_core::Direction;
use lens_protocol::{DecodeBatch, DecodedMessage, StreamingDecoder};

const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 1024;

/// Streaming HTTP/1 decoder with independent directional buffers.
#[derive(Debug)]
pub struct Http1Decoder {
    max_body: usize,
    client: DirectionState,
    server: DirectionState,
    request_methods: VecDeque<String>,
}

impl Http1Decoder {
    /// Creates a decoder with a per-message captured-body cap.
    #[must_use]
    pub fn new(max_body: usize) -> Self {
        assert!(max_body > 0, "max_body must be positive");
        Self {
            max_body,
            client: DirectionState::default(),
            server: DirectionState::default(),
            request_methods: VecDeque::new(),
        }
    }

    fn process(&mut self, direction: Direction, bytes: &[u8]) -> DecodeBatch {
        self.state_mut(direction).buffer.extend_from_slice(bytes);
        let mut batch = DecodeBatch::need_more();

        loop {
            let response_to_head = direction == Direction::ServerToClient
                && self
                    .request_methods
                    .front()
                    .is_some_and(|method| method.eq_ignore_ascii_case("HEAD"));
            let max_body = self.max_body;
            let step = self
                .state_mut(direction)
                .step(direction, max_body, response_to_head);
            match step {
                Step::NeedMore => break,
                Step::Progress => continue,
                Step::Message(message) => {
                    self.track_exchange(&message);
                    batch.messages.push(message);
                }
                Step::Desynchronized(reason) => {
                    batch.desynchronized = Some(reason);
                    break;
                }
            }
        }
        batch
    }

    fn state_mut(&mut self, direction: Direction) -> &mut DirectionState {
        match direction {
            Direction::ClientToServer => &mut self.client,
            Direction::ServerToClient => &mut self.server,
        }
    }

    fn track_exchange(&mut self, message: &DecodedMessage) {
        match message.direction {
            Direction::ClientToServer => {
                if let Some(method) = message.start_line.split_whitespace().next() {
                    self.request_methods.push_back(method.to_string());
                }
            }
            Direction::ServerToClient => {
                let status = message
                    .start_line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|value| value.parse::<u16>().ok());
                if status.is_some_and(|status| status >= 200 || status == 101) {
                    self.request_methods.pop_front();
                }
            }
        }
    }
}

impl StreamingDecoder for Http1Decoder {
    fn protocol(&self) -> &'static str {
        "http1"
    }

    fn push(&mut self, direction: Direction, bytes: &[u8]) -> DecodeBatch {
        self.process(direction, bytes)
    }

    fn finish(&mut self, direction: Direction) -> DecodeBatch {
        let mut batch = DecodeBatch::need_more();
        if let Some((message, incomplete)) = self.state_mut(direction).finish(direction) {
            self.track_exchange(&message);
            batch.messages.push(message);
            if incomplete {
                batch.desynchronized =
                    Some("HTTP message ended before its declared body".to_string());
            }
        }
        batch
    }
}

#[derive(Debug, Default)]
struct DirectionState {
    buffer: Vec<u8>,
    pending: Option<PendingBody>,
}

impl DirectionState {
    fn step(&mut self, direction: Direction, max_body: usize, response_to_head: bool) -> Step {
        if let Some(pending) = self.pending.take() {
            return self.consume_pending(pending, max_body);
        }

        let Some(head_end) = find_bytes(&self.buffer, b"\r\n\r\n") else {
            if self.buffer.len() > MAX_HEAD_BYTES {
                self.buffer.clear();
                return Step::Desynchronized("HTTP headers exceed 65536 bytes".to_string());
            }
            return Step::NeedMore;
        };
        let head_bytes = self.buffer[..head_end].to_vec();
        self.buffer.drain(..head_end + 4);
        let parsed = match ParsedHead::parse(&head_bytes) {
            Ok(parsed) => parsed,
            Err(reason) => {
                self.buffer.clear();
                return Step::Desynchronized(reason);
            }
        };
        let message = DecodedMessage {
            direction,
            start_line: parsed.start_line,
            headers: parsed.headers,
            body: Vec::new(),
            truncated: false,
        };

        if response_to_head || parsed.no_body_status {
            return Step::Message(message);
        }
        if parsed.chunked {
            self.pending = Some(PendingBody::Chunked {
                message,
                phase: ChunkPhase::Size,
            });
            return Step::Progress;
        }
        if let Some(length) = parsed.content_length {
            if length == 0 {
                return Step::Message(message);
            }
            self.pending = Some(PendingBody::Fixed {
                message,
                remaining: length,
            });
            return Step::Progress;
        }
        if parsed.is_response {
            self.pending = Some(PendingBody::UntilEof { message });
            return Step::Progress;
        }
        Step::Message(message)
    }

    fn consume_pending(&mut self, mut pending: PendingBody, max_body: usize) -> Step {
        match &mut pending {
            PendingBody::Fixed { message, remaining } => {
                let consumed = (*remaining).min(self.buffer.len());
                capture(message, &self.buffer[..consumed], max_body);
                self.buffer.drain(..consumed);
                *remaining -= consumed;
                if *remaining == 0 {
                    return Step::Message(pending.into_message());
                }
                self.pending = Some(pending);
                Step::NeedMore
            }
            PendingBody::UntilEof { message } => {
                capture(message, &self.buffer, max_body);
                self.buffer.clear();
                self.pending = Some(pending);
                Step::NeedMore
            }
            PendingBody::Chunked { message, phase } => loop {
                match phase {
                    ChunkPhase::Size => {
                        let Some(line_end) = find_bytes(&self.buffer, b"\r\n") else {
                            if self.buffer.len() > MAX_CHUNK_LINE_BYTES {
                                self.buffer.clear();
                                return Step::Desynchronized(
                                    "HTTP chunk-size line exceeds 1024 bytes".to_string(),
                                );
                            }
                            self.pending = Some(pending);
                            return Step::NeedMore;
                        };
                        let line = match std::str::from_utf8(&self.buffer[..line_end]) {
                            Ok(line) => line,
                            Err(_) => {
                                self.buffer.clear();
                                return Step::Desynchronized(
                                    "HTTP chunk-size line is not ASCII".to_string(),
                                );
                            }
                        };
                        let size_text = line.split(';').next().unwrap_or_default().trim();
                        let size = match usize::from_str_radix(size_text, 16) {
                            Ok(size) => size,
                            Err(_) => {
                                self.buffer.clear();
                                return Step::Desynchronized("invalid HTTP chunk size".to_string());
                            }
                        };
                        self.buffer.drain(..line_end + 2);
                        *phase = if size == 0 {
                            ChunkPhase::Trailers
                        } else {
                            ChunkPhase::Data { remaining: size }
                        };
                    }
                    ChunkPhase::Data { remaining } => {
                        let consumed = (*remaining).min(self.buffer.len());
                        capture(message, &self.buffer[..consumed], max_body);
                        self.buffer.drain(..consumed);
                        *remaining -= consumed;
                        if *remaining > 0 {
                            self.pending = Some(pending);
                            return Step::NeedMore;
                        }
                        *phase = ChunkPhase::DataCrlf;
                    }
                    ChunkPhase::DataCrlf => {
                        if self.buffer.len() < 2 {
                            self.pending = Some(pending);
                            return Step::NeedMore;
                        }
                        if &self.buffer[..2] != b"\r\n" {
                            self.buffer.clear();
                            return Step::Desynchronized(
                                "HTTP chunk data is missing CRLF".to_string(),
                            );
                        }
                        self.buffer.drain(..2);
                        *phase = ChunkPhase::Size;
                    }
                    ChunkPhase::Trailers => {
                        if self.buffer.starts_with(b"\r\n") {
                            self.buffer.drain(..2);
                            return Step::Message(pending.into_message());
                        }
                        if let Some(end) = find_bytes(&self.buffer, b"\r\n\r\n") {
                            self.buffer.drain(..end + 4);
                            return Step::Message(pending.into_message());
                        }
                        if self.buffer.len() > MAX_HEAD_BYTES {
                            self.buffer.clear();
                            return Step::Desynchronized(
                                "HTTP chunk trailers exceed 65536 bytes".to_string(),
                            );
                        }
                        self.pending = Some(pending);
                        return Step::NeedMore;
                    }
                }
            },
        }
    }

    fn finish(&mut self, _direction: Direction) -> Option<(DecodedMessage, bool)> {
        let pending = self.pending.take()?;
        let incomplete = !matches!(pending, PendingBody::UntilEof { .. });
        let mut message = pending.into_message();
        // `step` has already captured every body byte it could classify. Any
        // remainder here is incomplete framing (for example, half a chunk-size
        // line), not payload, and must not bypass the configured body cap.
        self.buffer.clear();
        message.truncated |= incomplete;
        Some((message, incomplete))
    }
}

#[derive(Debug)]
enum PendingBody {
    Fixed {
        message: DecodedMessage,
        remaining: usize,
    },
    Chunked {
        message: DecodedMessage,
        phase: ChunkPhase,
    },
    UntilEof {
        message: DecodedMessage,
    },
}

impl PendingBody {
    fn into_message(self) -> DecodedMessage {
        match self {
            Self::Fixed { message, .. }
            | Self::Chunked { message, .. }
            | Self::UntilEof { message } => message,
        }
    }
}

#[derive(Debug)]
enum ChunkPhase {
    Size,
    Data { remaining: usize },
    DataCrlf,
    Trailers,
}

#[derive(Debug)]
enum Step {
    NeedMore,
    Progress,
    Message(DecodedMessage),
    Desynchronized(String),
}

#[derive(Debug)]
struct ParsedHead {
    start_line: String,
    headers: Vec<(String, String)>,
    is_response: bool,
    no_body_status: bool,
    content_length: Option<usize>,
    chunked: bool,
}

impl ParsedHead {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "HTTP headers are not valid UTF-8".to_string())?;
        let mut lines = text.split("\r\n");
        let start_line = lines.next().unwrap_or_default().trim().to_string();
        if start_line.is_empty() {
            return Err("HTTP start line is empty".to_string());
        }
        let is_response = start_line.starts_with("HTTP/1.");
        if !is_response {
            let mut parts = start_line.split_whitespace();
            if parts.next().is_none()
                || parts.next().is_none()
                || !parts
                    .next()
                    .is_some_and(|version| version.starts_with("HTTP/1."))
                || parts.next().is_some()
            {
                return Err("invalid HTTP/1 request line".to_string());
            }
        }
        let status = if is_response {
            start_line
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or_else(|| "invalid HTTP/1 status line".to_string())?
        } else {
            0
        };
        let no_body_status =
            is_response && ((100..200).contains(&status) || status == 204 || status == 304);

        let mut headers = Vec::new();
        let mut content_length = None;
        let mut chunked = false;
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| "invalid HTTP header line".to_string())?;
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| "invalid HTTP Content-Length".to_string())?;
                if content_length.is_some_and(|current| current != parsed) {
                    return Err("conflicting HTTP Content-Length values".to_string());
                }
                content_length = Some(parsed);
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"))
            {
                chunked = true;
            }
            headers.push((name, value));
        }
        Ok(Self {
            start_line,
            headers,
            is_response,
            no_body_status,
            content_length,
            chunked,
        })
    }
}

fn capture(message: &mut DecodedMessage, bytes: &[u8], max_body: usize) {
    let remaining = max_body.saturating_sub(message.body.len());
    let captured = remaining.min(bytes.len());
    message.body.extend_from_slice(&bytes[..captured]);
    message.truncated |= captured < bytes.len();
}

fn find_bytes(buffer: &[u8], needle: &[u8]) -> Option<usize> {
    buffer
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_content_length_request_is_emitted_once_complete() {
        let mut decoder = Http1Decoder::new(1024);
        assert!(decoder
            .push(
                Direction::ClientToServer,
                b"POST /api HTTP/1.1\r\nContent-L"
            )
            .messages
            .is_empty());
        let batch = decoder.push(
            Direction::ClientToServer,
            b"ength: 5\r\nX-Test: yes\r\n\r\nhello",
        );
        assert_eq!(batch.messages.len(), 1);
        assert_eq!(batch.messages[0].start_line, "POST /api HTTP/1.1");
        assert_eq!(batch.messages[0].body, b"hello");
        assert!(!batch.messages[0].truncated);
    }

    #[test]
    fn pipelined_requests_are_emitted_in_wire_order() {
        let mut decoder = Http1Decoder::new(1024);
        let batch = decoder.push(
            Direction::ClientToServer,
            b"GET /one HTTP/1.1\r\nHost: x\r\n\r\nGET /two HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        let lines = batch
            .messages
            .iter()
            .map(|message| message.start_line.as_str())
            .collect::<Vec<_>>();
        assert_eq!(lines, vec!["GET /one HTTP/1.1", "GET /two HTTP/1.1"]);
    }

    #[test]
    fn chunked_response_is_decoded_across_fragments() {
        let mut decoder = Http1Decoder::new(1024);
        decoder.push(
            Direction::ClientToServer,
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(decoder
            .push(
                Direction::ServerToClient,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWi"
            )
            .messages
            .is_empty());
        let batch = decoder.push(Direction::ServerToClient, b"ki\r\n5\r\npedia\r\n0\r\n\r\n");
        assert_eq!(batch.messages.len(), 1);
        assert_eq!(batch.messages[0].body, b"Wikipedia");
    }

    #[test]
    fn body_capture_is_capped_without_losing_framing() {
        let mut decoder = Http1Decoder::new(4);
        let batch = decoder.push(
            Direction::ClientToServer,
            b"POST / HTTP/1.1\r\nContent-Length: 8\r\n\r\nabcdefghGET /next HTTP/1.1\r\n\r\n",
        );
        assert_eq!(batch.messages.len(), 2);
        assert_eq!(batch.messages[0].body, b"abcd");
        assert!(batch.messages[0].truncated);
        assert_eq!(batch.messages[1].start_line, "GET /next HTTP/1.1");
    }

    #[test]
    fn close_delimited_response_flushes_at_eof() {
        let mut decoder = Http1Decoder::new(1024);
        decoder.push(Direction::ClientToServer, b"GET / HTTP/1.0\r\n\r\n");
        let batch = decoder.push(Direction::ServerToClient, b"HTTP/1.0 200 OK\r\n\r\nbody");
        assert!(batch.messages.is_empty());
        let finished = decoder.finish(Direction::ServerToClient);
        assert_eq!(finished.messages[0].body, b"body");
        assert!(finished.desynchronized.is_none());
    }

    #[test]
    fn head_response_ignores_declared_body_length() {
        let mut decoder = Http1Decoder::new(1024);
        decoder.push(
            Direction::ClientToServer,
            b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        let batch = decoder.push(
            Direction::ServerToClient,
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n",
        );
        assert_eq!(batch.messages.len(), 1);
        assert!(batch.messages[0].body.is_empty());
    }

    #[test]
    fn malformed_chunk_reports_recoverable_desync() {
        let mut decoder = Http1Decoder::new(1024);
        let batch = decoder.push(
            Direction::ServerToClient,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnope\r\n",
        );
        assert_eq!(
            batch.desynchronized.as_deref(),
            Some("invalid HTTP chunk size")
        );
    }

    #[test]
    fn incomplete_chunk_framing_is_not_stored_as_body() {
        let mut decoder = Http1Decoder::new(4);
        let batch = decoder.push(
            Direction::ServerToClient,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n123",
        );
        assert!(batch.messages.is_empty());
        let finished = decoder.finish(Direction::ServerToClient);
        assert_eq!(finished.messages[0].body, b"");
        assert!(finished.messages[0].truncated);
        assert!(finished.desynchronized.is_some());
    }
}
