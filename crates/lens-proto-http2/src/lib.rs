//! Bounded HTTP/2 and gRPC streaming observation decoder.
//!
//! The decoder never participates in forwarding. It understands the HTTP/2
//! frame boundary, stateful HPACK blocks, multiplexed stream identifiers, and
//! the five-byte gRPC message envelope. Protobuf payloads are emitted with a
//! structural marker so the default redactor can remove them before storage.

use std::collections::HashMap;
use std::fmt;

use httlib_hpack::Decoder as HpackDecoder;
use lens_core::Direction;
use lens_protocol::{DecodeBatch, DecodedMessage, StreamingDecoder};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_BYTES: usize = 9;
const MAX_OBSERVED_FRAME_PAYLOAD: usize = 1024 * 1024;
const MAX_HEADER_BLOCK: usize = 64 * 1024;
const MAX_DECODED_HEADERS: usize = 128 * 1024;
const MAX_TRACKED_STREAMS: usize = 256;
const MAX_INFLIGHT_CAPTURE: usize = 4 * 1024 * 1024;

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_CONTINUATION: u8 = 0x9;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// Incremental HTTP/2 decoder with per-direction HPACK state.
pub struct Http2Decoder {
    client: DirectionState,
    server: DirectionState,
    streams: HashMap<u32, StreamState>,
    max_body: usize,
    retained_body_bytes: usize,
}

impl fmt::Debug for Http2Decoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http2Decoder")
            .field("client_buffer", &self.client.buffer.len())
            .field("server_buffer", &self.server.buffer.len())
            .field("streams", &self.streams.len())
            .field("max_body", &self.max_body)
            .field("retained_body_bytes", &self.retained_body_bytes)
            .finish()
    }
}

impl Http2Decoder {
    /// Creates a decoder with a per-message captured-body cap.
    #[must_use]
    pub fn new(max_body: usize) -> Self {
        Self {
            client: DirectionState::new(true),
            server: DirectionState::new(false),
            streams: HashMap::new(),
            max_body,
            retained_body_bytes: 0,
        }
    }

    fn state_mut(&mut self, direction: Direction) -> &mut DirectionState {
        match direction {
            Direction::ClientToServer => &mut self.client,
            Direction::ServerToClient => &mut self.server,
        }
    }

    fn decode_available(&mut self, direction: Direction) -> DecodeBatch {
        let mut batch = DecodeBatch::need_more();
        loop {
            let next = self.state_mut(direction).next_frame();
            match next {
                NextFrame::Frame(frame) => match self.handle_frame(direction, frame) {
                    Ok(messages) => batch.messages.extend(messages),
                    Err(reason) => {
                        batch.desynchronized = Some(reason);
                        self.state_mut(direction).continuation = None;
                    }
                },
                NextFrame::Skipped(reason) => batch.desynchronized = Some(reason),
                NextFrame::NeedMore => break,
                NextFrame::Invalid(reason) => {
                    batch.desynchronized = Some(reason);
                    break;
                }
            }
        }
        batch
    }

    fn handle_frame(
        &mut self,
        direction: Direction,
        frame: Frame,
    ) -> Result<Vec<DecodedMessage>, String> {
        if self.state_mut(direction).continuation.is_some() && frame.kind != FRAME_CONTINUATION {
            self.state_mut(direction).continuation = None;
            return Err("HTTP/2 header block was interrupted before END_HEADERS".to_string());
        }
        match frame.kind {
            FRAME_HEADERS => self.handle_headers(direction, frame),
            FRAME_CONTINUATION => self.handle_continuation(direction, frame),
            FRAME_DATA => self.handle_data(direction, frame),
            FRAME_RST_STREAM => {
                self.streams.remove(&frame.stream_id);
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn handle_headers(
        &mut self,
        direction: Direction,
        frame: Frame,
    ) -> Result<Vec<DecodedMessage>, String> {
        if frame.stream_id == 0 {
            return Err("HTTP/2 HEADERS frame used stream 0".to_string());
        }
        let fragment = header_fragment(&frame)?;
        let mut block = HeaderBlock {
            stream_id: frame.stream_id,
            end_stream: frame.flags & FLAG_END_STREAM != 0,
            bytes: Vec::new(),
            exceeded: false,
        };
        block.extend(fragment);
        if frame.flags & FLAG_END_HEADERS == 0 {
            self.state_mut(direction).continuation = Some(block);
            return Ok(Vec::new());
        }
        self.complete_header_block(direction, block)
    }

    fn handle_continuation(
        &mut self,
        direction: Direction,
        frame: Frame,
    ) -> Result<Vec<DecodedMessage>, String> {
        let Some(mut block) = self.state_mut(direction).continuation.take() else {
            return Err("unexpected HTTP/2 CONTINUATION frame".to_string());
        };
        if frame.stream_id != block.stream_id {
            return Err("HTTP/2 CONTINUATION changed stream identifiers".to_string());
        }
        block.extend(&frame.payload);
        if frame.flags & FLAG_END_HEADERS == 0 {
            self.state_mut(direction).continuation = Some(block);
            return Ok(Vec::new());
        }
        self.complete_header_block(direction, block)
    }

    fn complete_header_block(
        &mut self,
        direction: Direction,
        block: HeaderBlock,
    ) -> Result<Vec<DecodedMessage>, String> {
        if block.exceeded {
            return Err("HTTP/2 header block exceeded 64 KiB and was skipped".to_string());
        }
        let mut encoded = block.bytes;
        let mut decoded = Vec::new();
        self.state_mut(direction)
            .hpack
            .decode(&mut encoded, &mut decoded)
            .map_err(|error| format!("HPACK decode failed: {error:?}"))?;
        let decoded_size = decoded.iter().try_fold(0_usize, |total, (name, value, _)| {
            total.checked_add(name.len())?.checked_add(value.len())
        });
        if decoded_size.is_none_or(|size| size > MAX_DECODED_HEADERS) {
            return Err("decoded HTTP/2 headers exceeded 128 KiB".to_string());
        }
        let headers = decoded
            .into_iter()
            .map(|(name, value, _)| {
                (
                    String::from_utf8_lossy(&name).into_owned(),
                    String::from_utf8_lossy(&value).into_owned(),
                )
            })
            .collect::<Vec<_>>();
        self.apply_headers(direction, block.stream_id, block.end_stream, headers)
    }

    fn apply_headers(
        &mut self,
        direction: Direction,
        stream_id: u32,
        end_stream: bool,
        headers: Vec<(String, String)>,
    ) -> Result<Vec<DecodedMessage>, String> {
        let method = header(&headers, ":method").map(str::to_string);
        let path = header(&headers, ":path").map(str::to_string);
        let status = header(&headers, ":status").map(str::to_string);
        let content_type = header(&headers, "content-type").unwrap_or_default();
        if !self.streams.contains_key(&stream_id) && self.streams.len() >= MAX_TRACKED_STREAMS {
            return Err("HTTP/2 connection exceeded 256 tracked streams".to_string());
        }
        let stream = self.streams.entry(stream_id).or_default();
        if let Some(path) = path.clone() {
            stream.path = Some(path);
        }
        stream.grpc |= content_type
            .to_ascii_lowercase()
            .starts_with("application/grpc");

        if stream.grpc {
            let mut message_headers = headers;
            message_headers.push(("lens-protocol".to_string(), "grpc".to_string()));
            message_headers.push(("lens-stream-id".to_string(), stream_id.to_string()));
            let start_line = if let Some(method) = method {
                message_headers.push(("lens-boundary".to_string(), "request".to_string()));
                format!(
                    "gRPC {method} {}",
                    path.or_else(|| stream.path.clone())
                        .unwrap_or_else(|| "/unknown".to_string())
                )
            } else if let Some(status) = status {
                format!("gRPC response HTTP {status}")
            } else {
                if direction == Direction::ServerToClient {
                    message_headers.push(("lens-boundary".to_string(), "response".to_string()));
                }
                let grpc_status = header(&message_headers, "grpc-status").unwrap_or("unknown");
                format!("gRPC trailers status={grpc_status}")
            };
            let message = DecodedMessage {
                direction,
                start_line,
                headers: message_headers,
                body: Vec::new(),
                truncated: false,
            };
            if end_stream && direction == Direction::ServerToClient {
                self.remove_stream(stream_id);
            }
            return Ok(vec![message]);
        }

        let start_line = if let Some(method) = method {
            format!(
                "{method} {} HTTP/2",
                path.unwrap_or_else(|| "/".to_string())
            )
        } else if let Some(status) = status {
            format!("HTTP/2 {status}")
        } else {
            let pending = stream
                .pending_mut(direction)
                .as_mut()
                .ok_or_else(|| "HTTP/2 trailers arrived before initial headers".to_string())?;
            pending.headers.extend(headers);
            if end_stream {
                let completed = stream.take_pending(direction).map(|mut message| {
                    add_http2_metadata(&mut message, stream_id, direction);
                    message
                });
                if let Some(message) = &completed {
                    self.retained_body_bytes =
                        self.retained_body_bytes.saturating_sub(message.body.len());
                }
                if direction == Direction::ServerToClient {
                    self.remove_stream(stream_id);
                }
                return Ok(completed.into_iter().collect());
            }
            return Ok(Vec::new());
        };
        let pending = PendingMessage {
            direction,
            start_line,
            headers,
            body: Vec::new(),
            truncated: false,
        };
        *stream.pending_mut(direction) = Some(pending);
        if end_stream {
            let mut message = stream
                .take_pending(direction)
                .expect("pending HTTP/2 message was just inserted");
            add_http2_metadata(&mut message, stream_id, direction);
            return Ok(vec![message]);
        }
        Ok(Vec::new())
    }

    fn handle_data(
        &mut self,
        direction: Direction,
        frame: Frame,
    ) -> Result<Vec<DecodedMessage>, String> {
        if frame.stream_id == 0 {
            return Err("HTTP/2 DATA frame used stream 0".to_string());
        }
        let data = data_fragment(&frame)?;
        let global_remaining = MAX_INFLIGHT_CAPTURE.saturating_sub(self.retained_body_bytes);
        let Some(stream) = self.streams.get_mut(&frame.stream_id) else {
            return Err("HTTP/2 DATA arrived before HEADERS".to_string());
        };
        if stream.grpc {
            let path = stream
                .path
                .clone()
                .unwrap_or_else(|| "/unknown".to_string());
            let retained_before = stream.grpc_mut(direction).retained();
            let capture_limit = self
                .max_body
                .min(retained_before.saturating_add(global_remaining));
            let mut messages = stream.grpc_mut(direction).push(
                direction,
                frame.stream_id,
                &path,
                data,
                capture_limit,
            )?;
            let retained_after = stream.grpc_mut(direction).retained();
            self.retained_body_bytes = self
                .retained_body_bytes
                .saturating_sub(retained_before)
                .saturating_add(retained_after);
            if frame.flags & FLAG_END_STREAM != 0 {
                if stream.grpc_mut(direction).has_incomplete() {
                    return Err("gRPC stream ended inside a message envelope".to_string());
                }
                if direction == Direction::ServerToClient {
                    let mut headers = vec![
                        ("lens-protocol".to_string(), "grpc".to_string()),
                        ("lens-stream-id".to_string(), frame.stream_id.to_string()),
                        ("lens-boundary".to_string(), "response".to_string()),
                    ];
                    headers.push(("grpc-status".to_string(), "missing".to_string()));
                    messages.push(DecodedMessage {
                        direction,
                        start_line: "gRPC stream ended without trailers".to_string(),
                        headers,
                        body: Vec::new(),
                        truncated: true,
                    });
                    self.remove_stream(frame.stream_id);
                }
            }
            return Ok(messages);
        }

        let pending = stream
            .pending_mut(direction)
            .as_mut()
            .ok_or_else(|| "HTTP/2 DATA arrived without message headers".to_string())?;
        let remaining = self
            .max_body
            .saturating_sub(pending.body.len())
            .min(global_remaining);
        let captured = remaining.min(data.len());
        pending.body.extend_from_slice(&data[..captured]);
        pending.truncated |= captured < data.len();
        self.retained_body_bytes = self.retained_body_bytes.saturating_add(captured);
        if frame.flags & FLAG_END_STREAM != 0 {
            let mut message = stream
                .take_pending(direction)
                .expect("pending HTTP/2 message exists");
            add_http2_metadata(&mut message, frame.stream_id, direction);
            self.retained_body_bytes = self.retained_body_bytes.saturating_sub(message.body.len());
            if direction == Direction::ServerToClient {
                self.remove_stream(frame.stream_id);
            }
            return Ok(vec![message]);
        }
        Ok(Vec::new())
    }

    fn remove_stream(&mut self, stream_id: u32) {
        if let Some(stream) = self.streams.remove(&stream_id) {
            self.retained_body_bytes = self
                .retained_body_bytes
                .saturating_sub(stream.retained_body_bytes());
        }
    }
}

impl StreamingDecoder for Http2Decoder {
    fn protocol(&self) -> &'static str {
        "http2"
    }

    fn push(&mut self, direction: Direction, bytes: &[u8]) -> DecodeBatch {
        self.state_mut(direction).buffer.extend_from_slice(bytes);
        self.decode_available(direction)
    }

    fn finish(&mut self, direction: Direction) -> DecodeBatch {
        let mut batch = self.decode_available(direction);
        let state = self.state_mut(direction);
        if !state.buffer.is_empty() || state.continuation.is_some() || state.skip_payload > 0 {
            state.buffer.clear();
            state.continuation = None;
            state.skip_payload = 0;
            batch.desynchronized = Some("HTTP/2 stream ended inside a frame".to_string());
        }
        batch
    }
}

struct DirectionState {
    buffer: Vec<u8>,
    expect_client_preface: bool,
    hpack: HpackDecoder<'static>,
    continuation: Option<HeaderBlock>,
    skip_payload: usize,
}

impl DirectionState {
    fn new(expect_client_preface: bool) -> Self {
        let hpack = HpackDecoder::with_dynamic_size(4096);
        Self {
            buffer: Vec::new(),
            expect_client_preface,
            hpack,
            continuation: None,
            skip_payload: 0,
        }
    }

    fn next_frame(&mut self) -> NextFrame {
        if self.expect_client_preface {
            let compared = self.buffer.len().min(CLIENT_PREFACE.len());
            if self.buffer[..compared] != CLIENT_PREFACE[..compared] {
                self.buffer.clear();
                return NextFrame::Invalid("invalid HTTP/2 client connection preface".to_string());
            }
            if self.buffer.len() < CLIENT_PREFACE.len() {
                return NextFrame::NeedMore;
            }
            self.buffer.drain(..CLIENT_PREFACE.len());
            self.expect_client_preface = false;
        }
        if self.skip_payload > 0 {
            let consumed = self.skip_payload.min(self.buffer.len());
            self.buffer.drain(..consumed);
            self.skip_payload -= consumed;
            if self.skip_payload > 0 {
                return NextFrame::NeedMore;
            }
        }
        if self.buffer.len() < FRAME_HEADER_BYTES {
            return NextFrame::NeedMore;
        }
        let length = (usize::from(self.buffer[0]) << 16)
            | (usize::from(self.buffer[1]) << 8)
            | usize::from(self.buffer[2]);
        let kind = self.buffer[3];
        let flags = self.buffer[4];
        let stream_id = u32::from_be_bytes([
            self.buffer[5] & 0x7f,
            self.buffer[6],
            self.buffer[7],
            self.buffer[8],
        ]);
        if length > MAX_OBSERVED_FRAME_PAYLOAD {
            self.buffer.drain(..FRAME_HEADER_BYTES);
            let consumed = length.min(self.buffer.len());
            self.buffer.drain(..consumed);
            self.skip_payload = length - consumed;
            return NextFrame::Skipped(format!(
                "HTTP/2 frame payload of {length} bytes exceeded the 1 MiB observation cap"
            ));
        }
        let total = FRAME_HEADER_BYTES + length;
        if self.buffer.len() < total {
            return NextFrame::NeedMore;
        }
        let payload = self.buffer[FRAME_HEADER_BYTES..total].to_vec();
        self.buffer.drain(..total);
        NextFrame::Frame(Frame {
            kind,
            flags,
            stream_id,
            payload,
        })
    }
}

enum NextFrame {
    Frame(Frame),
    Skipped(String),
    NeedMore,
    Invalid(String),
}

struct Frame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

struct HeaderBlock {
    stream_id: u32,
    end_stream: bool,
    bytes: Vec<u8>,
    exceeded: bool,
}

impl HeaderBlock {
    fn extend(&mut self, fragment: &[u8]) {
        let remaining = MAX_HEADER_BLOCK.saturating_sub(self.bytes.len());
        let captured = remaining.min(fragment.len());
        self.bytes.extend_from_slice(&fragment[..captured]);
        self.exceeded |= captured < fragment.len();
    }
}

#[derive(Default)]
struct StreamState {
    request: Option<PendingMessage>,
    response: Option<PendingMessage>,
    grpc: bool,
    path: Option<String>,
    grpc_request: GrpcParser,
    grpc_response: GrpcParser,
}

impl StreamState {
    fn pending_mut(&mut self, direction: Direction) -> &mut Option<PendingMessage> {
        match direction {
            Direction::ClientToServer => &mut self.request,
            Direction::ServerToClient => &mut self.response,
        }
    }

    fn take_pending(&mut self, direction: Direction) -> Option<DecodedMessage> {
        self.pending_mut(direction)
            .take()
            .map(PendingMessage::finish)
    }

    fn grpc_mut(&mut self, direction: Direction) -> &mut GrpcParser {
        match direction {
            Direction::ClientToServer => &mut self.grpc_request,
            Direction::ServerToClient => &mut self.grpc_response,
        }
    }

    fn retained_body_bytes(&self) -> usize {
        self.request
            .as_ref()
            .map_or(0, |message| message.body.len())
            + self
                .response
                .as_ref()
                .map_or(0, |message| message.body.len())
            + self.grpc_request.retained()
            + self.grpc_response.retained()
    }
}

struct PendingMessage {
    direction: Direction,
    start_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    truncated: bool,
}

impl PendingMessage {
    fn finish(self) -> DecodedMessage {
        DecodedMessage {
            direction: self.direction,
            start_line: self.start_line,
            headers: self.headers,
            body: self.body,
            truncated: self.truncated,
        }
    }
}

#[derive(Default)]
struct GrpcParser {
    prefix: Vec<u8>,
    pending: Option<GrpcPayload>,
}

impl GrpcParser {
    fn push(
        &mut self,
        direction: Direction,
        stream_id: u32,
        path: &str,
        mut bytes: &[u8],
        max_body: usize,
    ) -> Result<Vec<DecodedMessage>, String> {
        let mut messages = Vec::new();
        while !bytes.is_empty() {
            if let Some(pending) = &mut self.pending {
                let consumed = pending.remaining.min(bytes.len());
                let captured = max_body.saturating_sub(pending.body.len()).min(consumed);
                pending.body.extend_from_slice(&bytes[..captured]);
                pending.remaining -= consumed;
                bytes = &bytes[consumed..];
                if pending.remaining == 0 {
                    let pending = self.pending.take().expect("gRPC payload exists");
                    messages.push(pending.finish(direction, stream_id, path));
                }
                continue;
            }
            let needed = 5 - self.prefix.len();
            let consumed = needed.min(bytes.len());
            self.prefix.extend_from_slice(&bytes[..consumed]);
            bytes = &bytes[consumed..];
            if self.prefix.len() < 5 {
                break;
            }
            let compressed = match self.prefix[0] {
                0 => false,
                1 => true,
                _ => {
                    self.prefix.clear();
                    return Err("invalid gRPC compressed-message flag".to_string());
                }
            };
            let length = u32::from_be_bytes([
                self.prefix[1],
                self.prefix[2],
                self.prefix[3],
                self.prefix[4],
            ]) as usize;
            self.prefix.clear();
            self.pending = Some(GrpcPayload {
                compressed,
                length,
                remaining: length,
                body: Vec::with_capacity(length.min(max_body)),
                max_body,
            });
            if length == 0 {
                let pending = self.pending.take().expect("empty gRPC payload exists");
                messages.push(pending.finish(direction, stream_id, path));
            }
        }
        Ok(messages)
    }

    fn has_incomplete(&self) -> bool {
        !self.prefix.is_empty() || self.pending.is_some()
    }

    fn retained(&self) -> usize {
        self.pending
            .as_ref()
            .map_or(0, |pending| pending.body.len())
    }
}

struct GrpcPayload {
    compressed: bool,
    length: usize,
    remaining: usize,
    body: Vec<u8>,
    max_body: usize,
}

impl GrpcPayload {
    fn finish(self, direction: Direction, stream_id: u32, path: &str) -> DecodedMessage {
        let role = match direction {
            Direction::ClientToServer => "request",
            Direction::ServerToClient => "response",
        };
        DecodedMessage {
            direction,
            start_line: format!("gRPC {role} {path} message {} bytes", self.length),
            headers: vec![
                ("lens-protocol".to_string(), "grpc".to_string()),
                ("lens-content".to_string(), "protobuf".to_string()),
                ("lens-stream-id".to_string(), stream_id.to_string()),
                ("grpc-compressed".to_string(), self.compressed.to_string()),
                ("grpc-message-bytes".to_string(), self.length.to_string()),
            ],
            body: self.body,
            truncated: self.length > self.max_body,
        }
    }
}

fn header_fragment(frame: &Frame) -> Result<&[u8], String> {
    let mut start = 0;
    let mut end = frame.payload.len();
    if frame.flags & FLAG_PADDED != 0 {
        let Some(&padding) = frame.payload.first() else {
            return Err("padded HTTP/2 HEADERS frame was empty".to_string());
        };
        start += 1;
        end = end
            .checked_sub(usize::from(padding))
            .ok_or_else(|| "HTTP/2 HEADERS padding exceeded its payload".to_string())?;
    }
    if frame.flags & FLAG_PRIORITY != 0 {
        start += 5;
    }
    if start > end {
        return Err("HTTP/2 HEADERS metadata exceeded its payload".to_string());
    }
    Ok(&frame.payload[start..end])
}

fn data_fragment(frame: &Frame) -> Result<&[u8], String> {
    if frame.flags & FLAG_PADDED == 0 {
        return Ok(&frame.payload);
    }
    let Some(&padding) = frame.payload.first() else {
        return Err("padded HTTP/2 DATA frame was empty".to_string());
    };
    let end = frame
        .payload
        .len()
        .checked_sub(usize::from(padding))
        .ok_or_else(|| "HTTP/2 DATA padding exceeded its payload".to_string())?;
    if end < 1 {
        return Err("HTTP/2 DATA padding consumed its length byte".to_string());
    }
    Ok(&frame.payload[1..end])
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn add_http2_metadata(message: &mut DecodedMessage, stream_id: u32, direction: Direction) {
    message
        .headers
        .push(("lens-protocol".to_string(), "http2".to_string()));
    message
        .headers
        .push(("lens-stream-id".to_string(), stream_id.to_string()));
    message.headers.push((
        "lens-boundary".to_string(),
        match direction {
            Direction::ClientToServer => "request",
            Direction::ServerToClient => "response",
        }
        .to_string(),
    ));
}

#[cfg(test)]
mod tests {
    use httlib_hpack::Encoder;

    use super::*;

    fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
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

    fn headers(encoder: &mut Encoder<'_>, values: &[(&[u8], &[u8])]) -> Vec<u8> {
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

    #[test]
    fn decodes_fragmented_http2_request_and_response() {
        let mut client_encoder = Encoder::default();
        let mut server_encoder = Encoder::default();
        let request_headers = headers(
            &mut client_encoder,
            &[
                (b":method", b"POST"),
                (b":path", b"/v1/items"),
                (b"content-type", b"application/json"),
                (b"authorization", b"Bearer secret"),
            ],
        );
        let response_headers = headers(
            &mut server_encoder,
            &[(b":status", b"200"), (b"content-type", b"application/json")],
        );
        let mut client = CLIENT_PREFACE.to_vec();
        client.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &request_headers));
        client.extend(frame(FRAME_DATA, FLAG_END_STREAM, 1, br#"{"name":"Ada"}"#));
        let mut server = frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &response_headers);
        server.extend(frame(FRAME_DATA, FLAG_END_STREAM, 1, b"{}"));

        let mut decoder = Http2Decoder::new(1024);
        let split = 17;
        assert!(decoder
            .push(Direction::ClientToServer, &client[..split])
            .messages
            .is_empty());
        let request = decoder.push(Direction::ClientToServer, &client[split..]);
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.messages[0].summary(), "POST /v1/items HTTP/2");
        assert_eq!(request.messages[0].body, br#"{"name":"Ada"}"#);
        assert!(request.messages[0]
            .headers
            .contains(&("lens-stream-id".to_string(), "1".to_string())));

        let response = decoder.push(Direction::ServerToClient, &server);
        assert_eq!(response.messages.len(), 1);
        assert_eq!(response.messages[0].summary(), "HTTP/2 200");
        assert_eq!(response.messages[0].body, b"{}");
    }

    #[test]
    fn reassembles_continuation_and_hpack_dynamic_state() {
        let mut encoder = Encoder::default();
        let first = headers(
            &mut encoder,
            &[
                (b":method", b"GET"),
                (b":path", b"/one"),
                (b"x-custom", b"value"),
            ],
        );
        let second = headers(
            &mut encoder,
            &[
                (b":method", b"GET"),
                (b":path", b"/two"),
                (b"x-custom", b"value"),
            ],
        );
        let cut = first.len() / 2;
        let mut bytes = CLIENT_PREFACE.to_vec();
        bytes.extend(frame(FRAME_HEADERS, FLAG_END_STREAM, 1, &first[..cut]));
        bytes.extend(frame(
            FRAME_CONTINUATION,
            FLAG_END_HEADERS,
            1,
            &first[cut..],
        ));
        bytes.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            3,
            &second,
        ));
        let mut decoder = Http2Decoder::new(1024);
        let batch = decoder.push(Direction::ClientToServer, &bytes);
        assert_eq!(batch.messages.len(), 2);
        assert_eq!(batch.messages[0].summary(), "GET /one HTTP/2");
        assert_eq!(batch.messages[1].summary(), "GET /two HTTP/2");
    }

    #[test]
    fn decodes_fragmented_grpc_envelopes_and_trailers() {
        let mut client_encoder = Encoder::default();
        let mut server_encoder = Encoder::default();
        let request_headers = headers(
            &mut client_encoder,
            &[
                (b":method", b"POST"),
                (b":path", b"/hello.Greeter/SayHello"),
                (b"content-type", b"application/grpc"),
                (b"authorization", b"Bearer secret"),
            ],
        );
        let response_headers = headers(
            &mut server_encoder,
            &[(b":status", b"200"), (b"content-type", b"application/grpc")],
        );
        let trailers = headers(
            &mut server_encoder,
            &[(b"grpc-status", b"0"), (b"grpc-message", b"done")],
        );
        let mut request = CLIENT_PREFACE.to_vec();
        request.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &request_headers));
        let grpc_payload = [0, 0, 0, 0, 4, 0x0a, 0x02, b'h', b'i'];
        request.extend(frame(FRAME_DATA, 0, 1, &grpc_payload[..3]));
        request.extend(frame(FRAME_DATA, FLAG_END_STREAM, 1, &grpc_payload[3..]));

        let mut response = frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &response_headers);
        response.extend(frame(FRAME_DATA, 0, 1, &grpc_payload));
        response.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &trailers,
        ));

        let mut decoder = Http2Decoder::new(1024);
        let request_batch = decoder.push(Direction::ClientToServer, &request);
        assert_eq!(request_batch.messages.len(), 2);
        assert_eq!(
            request_batch.messages[0].summary(),
            "gRPC POST /hello.Greeter/SayHello"
        );
        assert_eq!(request_batch.messages[1].body, [0x0a, 0x02, b'h', b'i']);

        let response_batch = decoder.push(Direction::ServerToClient, &response);
        assert_eq!(response_batch.messages.len(), 3);
        assert_eq!(
            response_batch.messages[1].summary(),
            "gRPC response /hello.Greeter/SayHello message 4 bytes"
        );
        assert_eq!(
            response_batch.messages[2].summary(),
            "gRPC trailers status=0"
        );
        assert!(response_batch.messages[2]
            .headers
            .contains(&("lens-boundary".to_string(), "response".to_string())));
    }

    #[test]
    fn skips_oversized_frames_without_buffering_the_payload() {
        let mut decoder = Http2Decoder::new(64);
        let mut header = CLIENT_PREFACE.to_vec();
        let length = MAX_OBSERVED_FRAME_PAYLOAD + 1;
        header.extend([
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
            FRAME_DATA,
            0,
            0,
            0,
            0,
            1,
        ]);
        let batch = decoder.push(Direction::ClientToServer, &header);
        assert!(batch.desynchronized.is_some());
        assert_eq!(decoder.client.skip_payload, length);
        assert!(decoder.client.buffer.is_empty());
    }
}
