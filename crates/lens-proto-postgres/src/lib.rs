//! Bounded incremental decoder for the PostgreSQL frontend/backend protocol.
//!
//! Passwords, SASL payloads, bind values, row values, COPY payloads, and
//! backend key material are deliberately never retained. TLS negotiation is
//! reported, but accepted TLS becomes opaque instead of being downgraded.

use lens_core::Direction;
use lens_protocol::{DecodeBatch, DecodedMessage, StreamingDecoder};

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const SSL_REQUEST_CODE: u32 = 80_877_103;
const CANCEL_REQUEST_CODE: u32 = 80_877_102;
const GSSENC_REQUEST_CODE: u32 = 80_877_104;

/// Streaming PostgreSQL decoder with independent directional buffers.
#[derive(Debug)]
pub struct PostgresDecoder {
    max_body: usize,
    client: Vec<u8>,
    server: Vec<u8>,
    phase: Phase,
}

impl PostgresDecoder {
    /// Creates a decoder with a cap for retained SQL text and safe metadata.
    #[must_use]
    pub fn new(max_body: usize) -> Self {
        assert!(max_body > 0, "max_body must be positive");
        Self {
            max_body,
            client: Vec::new(),
            server: Vec::new(),
            phase: Phase::Startup,
        }
    }

    fn process(&mut self, direction: Direction, bytes: &[u8]) -> DecodeBatch {
        if self.phase == Phase::Opaque {
            return DecodeBatch::need_more();
        }
        self.buffer_mut(direction).extend_from_slice(bytes);
        if self.buffer_mut(direction).len() > MAX_FRAME_BYTES + 5 {
            self.client.clear();
            self.server.clear();
            self.phase = Phase::Opaque;
            return DecodeBatch {
                messages: Vec::new(),
                desynchronized: Some("PostgreSQL buffered data exceeds 16777221 bytes".to_string()),
            };
        }
        let mut batch = DecodeBatch::need_more();

        loop {
            let step = match (self.phase, direction) {
                (Phase::Startup, Direction::ClientToServer) => self.step_startup(),
                (Phase::AwaitingEncryptionResponse, Direction::ServerToClient) => {
                    self.step_encryption_response()
                }
                (Phase::Typed, _) => self.step_typed(direction),
                _ => Step::NeedMore,
            };
            match step {
                Step::NeedMore => break,
                Step::Message(message) => batch.messages.push(message),
                Step::MessageAndPhase(message, phase) => {
                    self.phase = phase;
                    batch.messages.push(message);
                    if phase == Phase::Opaque {
                        self.client.clear();
                        self.server.clear();
                        break;
                    }
                }
                Step::Desynchronized(reason) => {
                    self.client.clear();
                    self.server.clear();
                    self.phase = Phase::Opaque;
                    batch.desynchronized = Some(reason);
                    break;
                }
            }
        }
        batch
    }

    fn step_startup(&mut self) -> Step {
        if self.client.len() < 4 {
            return Step::NeedMore;
        }
        let length = u32::from_be_bytes(self.client[..4].try_into().expect("four bytes")) as usize;
        if !(8..=MAX_FRAME_BYTES).contains(&length) {
            return Step::Desynchronized(format!(
                "invalid PostgreSQL startup frame length {length}"
            ));
        }
        if self.client.len() < length {
            return Step::NeedMore;
        }
        let frame = self.client[..length].to_vec();
        self.client.drain(..length);
        let code = u32::from_be_bytes(frame[4..8].try_into().expect("four bytes"));
        match code {
            SSL_REQUEST_CODE => Step::MessageAndPhase(
                message(Direction::ClientToServer, "SSLRequest"),
                Phase::AwaitingEncryptionResponse,
            ),
            GSSENC_REQUEST_CODE => Step::MessageAndPhase(
                message(Direction::ClientToServer, "GSSENCRequest"),
                Phase::AwaitingEncryptionResponse,
            ),
            CANCEL_REQUEST_CODE => Step::MessageAndPhase(
                message(
                    Direction::ClientToServer,
                    "CancelRequest (key material omitted)",
                ),
                Phase::Opaque,
            ),
            version => match startup_message(version, &frame[8..]) {
                Ok(message) => Step::MessageAndPhase(message, Phase::Typed),
                Err(reason) => Step::Desynchronized(reason),
            },
        }
    }

    fn step_encryption_response(&mut self) -> Step {
        let Some(response) = self.server.first().copied() else {
            return Step::NeedMore;
        };
        self.server.drain(..1);
        match response {
            b'S' | b'G' => Step::MessageAndPhase(
                message(
                    Direction::ServerToClient,
                    if response == b'S' {
                        "EncryptionResponse accepted (traffic opaque)"
                    } else {
                        "GSSENCResponse accepted (traffic opaque)"
                    },
                ),
                Phase::Opaque,
            ),
            b'N' => Step::MessageAndPhase(
                message(Direction::ServerToClient, "EncryptionResponse rejected"),
                Phase::Startup,
            ),
            _ => Step::Desynchronized("invalid PostgreSQL encryption response".to_string()),
        }
    }

    fn step_typed(&mut self, direction: Direction) -> Step {
        let buffer = self.buffer_mut(direction);
        if buffer.len() < 5 {
            return Step::NeedMore;
        }
        let tag = buffer[0];
        let length = u32::from_be_bytes(buffer[1..5].try_into().expect("four bytes")) as usize;
        if !(4..=MAX_FRAME_BYTES).contains(&length) {
            return Step::Desynchronized(format!(
                "invalid PostgreSQL message length {length} for tag 0x{tag:02x}"
            ));
        }
        let total = length.saturating_add(1);
        if buffer.len() < total {
            return Step::NeedMore;
        }
        let payload = buffer[5..total].to_vec();
        buffer.drain(..total);
        match decode_typed(direction, tag, &payload, self.max_body) {
            Ok(message) => Step::Message(message),
            Err(reason) => Step::Desynchronized(reason),
        }
    }

    fn buffer_mut(&mut self, direction: Direction) -> &mut Vec<u8> {
        match direction {
            Direction::ClientToServer => &mut self.client,
            Direction::ServerToClient => &mut self.server,
        }
    }
}

impl StreamingDecoder for PostgresDecoder {
    fn protocol(&self) -> &'static str {
        "postgres"
    }

    fn push(&mut self, direction: Direction, bytes: &[u8]) -> DecodeBatch {
        self.process(direction, bytes)
    }

    fn finish(&mut self, direction: Direction) -> DecodeBatch {
        let remaining = self.buffer_mut(direction).len();
        self.buffer_mut(direction).clear();
        if remaining == 0 || self.phase == Phase::Opaque {
            DecodeBatch::need_more()
        } else {
            DecodeBatch {
                messages: Vec::new(),
                desynchronized: Some(format!(
                    "PostgreSQL stream ended with {remaining} incomplete bytes"
                )),
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    Startup,
    AwaitingEncryptionResponse,
    Typed,
    Opaque,
}

#[derive(Debug)]
enum Step {
    NeedMore,
    Message(DecodedMessage),
    MessageAndPhase(DecodedMessage, Phase),
    Desynchronized(String),
}

fn message(direction: Direction, start_line: impl Into<String>) -> DecodedMessage {
    DecodedMessage {
        direction,
        start_line: start_line.into(),
        headers: vec![("lens-protocol".to_string(), "postgres".to_string())],
        body: Vec::new(),
        truncated: false,
    }
}

fn with_kind(mut message: DecodedMessage, kind: &str) -> DecodedMessage {
    message
        .headers
        .push(("lens-kind".to_string(), kind.to_string()));
    message
}

fn with_boundary(mut message: DecodedMessage, boundary: &str) -> DecodedMessage {
    message
        .headers
        .push(("lens-boundary".to_string(), boundary.to_string()));
    message
}

fn startup_message(version: u32, payload: &[u8]) -> Result<DecodedMessage, String> {
    let major = version >> 16;
    let minor = version & 0xffff;
    if major != 3 {
        return Err(format!(
            "unsupported PostgreSQL protocol version {major}.{minor}"
        ));
    }
    let fields = cstrings(payload)?;
    if fields.len() % 2 != 0 {
        return Err("PostgreSQL startup parameters are not key/value pairs".to_string());
    }
    let mut message = with_kind(
        message(
            Direction::ClientToServer,
            format!("StartupMessage protocol={major}.{minor}"),
        ),
        "startup",
    );
    for pair in fields.chunks_exact(2) {
        let name = String::from_utf8_lossy(pair[0]).into_owned();
        let value = if is_startup_secret(&name) {
            "[REDACTED]".to_string()
        } else {
            String::from_utf8_lossy(pair[1]).into_owned()
        };
        message.headers.push((name, value));
    }
    Ok(message)
}

fn decode_typed(
    direction: Direction,
    tag: u8,
    payload: &[u8],
    max_body: usize,
) -> Result<DecodedMessage, String> {
    if direction == Direction::ClientToServer {
        decode_frontend(tag, payload, max_body)
    } else {
        decode_backend(tag, payload, max_body)
    }
}

fn decode_frontend(tag: u8, payload: &[u8], max_body: usize) -> Result<DecodedMessage, String> {
    let mut result = match tag {
        b'Q' => {
            let sql = first_cstring(payload)?;
            let mut message = with_boundary(
                with_kind(message(Direction::ClientToServer, "Query"), "query"),
                "request",
            );
            capture(&mut message, sql, max_body);
            message.headers.push(("lens-content".into(), "sql".into()));
            message
        }
        b'P' => {
            let (name, rest) = take_cstring(payload)?;
            let (sql, _) = take_cstring(rest)?;
            let mut message = with_kind(
                message(
                    Direction::ClientToServer,
                    format!("Parse statement={}", display_name(name)),
                ),
                "parse",
            );
            capture(&mut message, sql, max_body);
            message.headers.push(("lens-content".into(), "sql".into()));
            message
        }
        b'B' => {
            let (portal, rest) = take_cstring(payload)?;
            let (statement, rest) = take_cstring(rest)?;
            if rest.len() < 2 {
                return Err("truncated PostgreSQL Bind message".to_string());
            }
            let format_count =
                u16::from_be_bytes(rest[..2].try_into().expect("two bytes")) as usize;
            let formats_bytes = format_count
                .checked_mul(2)
                .and_then(|value| value.checked_add(2))
                .ok_or_else(|| "invalid PostgreSQL Bind format count".to_string())?;
            if rest.len() < formats_bytes + 2 {
                return Err("truncated PostgreSQL Bind formats".to_string());
            }
            let parameter_count = u16::from_be_bytes(
                rest[formats_bytes..formats_bytes + 2]
                    .try_into()
                    .expect("two bytes"),
            );
            with_kind(
                message(
                    Direction::ClientToServer,
                    format!(
                        "Bind portal={} statement={} parameters={} (values omitted)",
                        display_name(portal),
                        display_name(statement),
                        parameter_count
                    ),
                ),
                "bind",
            )
        }
        b'E' => {
            let (portal, rest) = take_cstring(payload)?;
            if rest.len() != 4 {
                return Err("invalid PostgreSQL Execute message".to_string());
            }
            let max_rows = u32::from_be_bytes(rest.try_into().expect("four bytes"));
            with_boundary(
                with_kind(
                    message(
                        Direction::ClientToServer,
                        format!(
                            "Execute portal={} max_rows={max_rows}",
                            display_name(portal)
                        ),
                    ),
                    "execute",
                ),
                "request",
            )
        }
        b'p' => with_kind(
            message(
                Direction::ClientToServer,
                "AuthenticationResponse (credentials omitted)",
            ),
            "authentication-response",
        ),
        b'C' => with_kind(message(Direction::ClientToServer, "Close"), "close"),
        b'D' => with_kind(message(Direction::ClientToServer, "Describe"), "describe"),
        b'F' => with_kind(
            message(
                Direction::ClientToServer,
                "FunctionCall (arguments omitted)",
            ),
            "function-call",
        ),
        b'd' => with_kind(
            message(Direction::ClientToServer, "CopyData (payload omitted)"),
            "copy-data",
        ),
        b'c' => with_kind(message(Direction::ClientToServer, "CopyDone"), "copy-done"),
        b'f' => with_kind(
            message(Direction::ClientToServer, "CopyFail (detail omitted)"),
            "copy-fail",
        ),
        b'H' => with_kind(message(Direction::ClientToServer, "Flush"), "flush"),
        b'S' => with_kind(message(Direction::ClientToServer, "Sync"), "sync"),
        b'X' => with_kind(message(Direction::ClientToServer, "Terminate"), "terminate"),
        _ => with_kind(
            message(
                Direction::ClientToServer,
                format!("FrontendMessage tag=0x{tag:02x} bytes={}", payload.len()),
            ),
            "unknown",
        ),
    };
    result
        .headers
        .push(("wire-bytes".into(), (payload.len() + 5).to_string()));
    Ok(result)
}

fn decode_backend(tag: u8, payload: &[u8], max_body: usize) -> Result<DecodedMessage, String> {
    let mut result = match tag {
        b'R' => {
            if payload.len() < 4 {
                return Err("truncated PostgreSQL Authentication message".to_string());
            }
            let code = u32::from_be_bytes(payload[..4].try_into().expect("four bytes"));
            with_kind(
                message(
                    Direction::ServerToClient,
                    format!("Authentication {}", authentication_name(code)),
                ),
                "authentication",
            )
        }
        b'S' => {
            let fields = cstrings(payload)?;
            if fields.len() < 2 {
                return Err("invalid PostgreSQL ParameterStatus".to_string());
            }
            let name = String::from_utf8_lossy(fields[0]);
            let value = if is_startup_secret(&name) {
                "[REDACTED]".to_string()
            } else {
                String::from_utf8_lossy(fields[1]).into_owned()
            };
            let mut message = with_kind(
                message(Direction::ServerToClient, "ParameterStatus"),
                "parameter-status",
            );
            message.headers.push((name.into_owned(), value));
            message
        }
        b'K' => with_kind(
            message(
                Direction::ServerToClient,
                "BackendKeyData (key material omitted)",
            ),
            "backend-key-data",
        ),
        b'Z' => {
            let status = payload.first().copied().unwrap_or(b'?') as char;
            with_kind(
                message(
                    Direction::ServerToClient,
                    format!("ReadyForQuery status={status}"),
                ),
                "ready",
            )
        }
        b'C' => {
            let tag = String::from_utf8_lossy(first_cstring(payload)?);
            with_boundary(
                with_kind(
                    message(Direction::ServerToClient, format!("CommandComplete {tag}")),
                    "command-complete",
                ),
                "response",
            )
        }
        b'E' | b'N' => {
            let kind = if tag == b'E' { "error" } else { "notice" };
            let title = if tag == b'E' {
                "ErrorResponse"
            } else {
                "NoticeResponse"
            };
            let mut message = with_kind(message(Direction::ServerToClient, title), kind);
            for (code, value) in error_fields(payload)? {
                let name = match code {
                    b'S' | b'V' => "severity",
                    b'C' => "sqlstate",
                    b'M' => "message",
                    b'D' => "detail",
                    b'H' => "hint",
                    b'W' => "where",
                    _ => continue,
                };
                let mut value = value.to_vec();
                if value.len() > max_body {
                    value.truncate(max_body);
                    message.truncated = true;
                }
                message.headers.push((
                    name.to_string(),
                    String::from_utf8_lossy(&value).into_owned(),
                ));
            }
            if tag == b'E' {
                message = with_boundary(message, "response");
            }
            message
        }
        b'T' => row_description(payload)?,
        b'D' => {
            let columns = payload
                .get(..2)
                .map(|bytes| u16::from_be_bytes(bytes.try_into().expect("two bytes")))
                .ok_or_else(|| "truncated PostgreSQL DataRow".to_string())?;
            with_kind(
                message(
                    Direction::ServerToClient,
                    format!("DataRow columns={columns} (values omitted)"),
                ),
                "data-row",
            )
        }
        b'1' => with_kind(
            message(Direction::ServerToClient, "ParseComplete"),
            "parse-complete",
        ),
        b'2' => with_kind(
            message(Direction::ServerToClient, "BindComplete"),
            "bind-complete",
        ),
        b'3' => with_kind(
            message(Direction::ServerToClient, "CloseComplete"),
            "close-complete",
        ),
        b'n' => with_kind(message(Direction::ServerToClient, "NoData"), "no-data"),
        b's' => with_boundary(
            with_kind(
                message(Direction::ServerToClient, "PortalSuspended"),
                "portal-suspended",
            ),
            "response",
        ),
        b'I' => with_boundary(
            with_kind(
                message(Direction::ServerToClient, "EmptyQueryResponse"),
                "empty-query",
            ),
            "response",
        ),
        b'A' => with_kind(
            message(
                Direction::ServerToClient,
                "NotificationResponse (payload omitted)",
            ),
            "notification",
        ),
        b'G' | b'H' | b'W' => with_kind(
            message(Direction::ServerToClient, "CopyResponse"),
            "copy-response",
        ),
        b'd' => with_kind(
            message(Direction::ServerToClient, "CopyData (payload omitted)"),
            "copy-data",
        ),
        b'c' => with_boundary(
            with_kind(message(Direction::ServerToClient, "CopyDone"), "copy-done"),
            "response",
        ),
        _ => with_kind(
            message(
                Direction::ServerToClient,
                format!("BackendMessage tag=0x{tag:02x} bytes={}", payload.len()),
            ),
            "unknown",
        ),
    };
    result
        .headers
        .push(("wire-bytes".into(), (payload.len() + 5).to_string()));
    Ok(result)
}

fn row_description(payload: &[u8]) -> Result<DecodedMessage, String> {
    if payload.len() < 2 {
        return Err("truncated PostgreSQL RowDescription".to_string());
    }
    let columns = u16::from_be_bytes(payload[..2].try_into().expect("two bytes")) as usize;
    let mut rest = &payload[2..];
    let mut names = Vec::with_capacity(columns.min(32));
    for _ in 0..columns {
        let (name, after_name) = take_cstring(rest)?;
        if after_name.len() < 18 {
            return Err("truncated PostgreSQL RowDescription field".to_string());
        }
        if names.len() < 32 {
            names.push(String::from_utf8_lossy(name).into_owned());
        }
        rest = &after_name[18..];
    }
    let mut message = with_kind(
        message(
            Direction::ServerToClient,
            format!("RowDescription columns={columns}"),
        ),
        "row-description",
    );
    if !names.is_empty() {
        message.headers.push(("columns".into(), names.join(",")));
    }
    Ok(message)
}

fn authentication_name(code: u32) -> &'static str {
    match code {
        0 => "Ok",
        2 => "KerberosV5",
        3 => "CleartextPassword",
        5 => "MD5Password",
        6 => "SCMCredential",
        7 => "GSS",
        8 => "GSSContinue",
        9 => "SSPI",
        10 => "SASL",
        11 => "SASLContinue",
        12 => "SASLFinal",
        _ => "Unknown",
    }
}

fn capture(message: &mut DecodedMessage, bytes: &[u8], max_body: usize) {
    let captured = bytes.len().min(max_body);
    message.body.extend_from_slice(&bytes[..captured]);
    message.truncated = bytes.len() > captured;
}

fn display_name(value: &[u8]) -> String {
    if value.is_empty() {
        "<unnamed>".to_string()
    } else {
        String::from_utf8_lossy(value).into_owned()
    }
}

fn first_cstring(payload: &[u8]) -> Result<&[u8], String> {
    take_cstring(payload).map(|(value, _)| value)
}

fn take_cstring(payload: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let end = payload
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "unterminated PostgreSQL string".to_string())?;
    Ok((&payload[..end], &payload[end + 1..]))
}

fn cstrings(mut payload: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut values = Vec::new();
    while !payload.is_empty() {
        if payload == [0] {
            break;
        }
        let (value, rest) = take_cstring(payload)?;
        values.push(value);
        payload = rest;
    }
    Ok(values)
}

fn error_fields(mut payload: &[u8]) -> Result<Vec<(u8, &[u8])>, String> {
    let mut fields = Vec::new();
    while let Some((&code, rest)) = payload.split_first() {
        if code == 0 {
            return Ok(fields);
        }
        let (value, remaining) = take_cstring(rest)?;
        fields.push((code, value));
        payload = remaining;
    }
    Err("unterminated PostgreSQL error fields".to_string())
}

fn is_startup_secret(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "password" | "passfile" | "sslpassword" | "token" | "secret" | "options"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn startup(user: &str, database: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&196_608_u32.to_be_bytes());
        payload.extend_from_slice(b"user\0");
        payload.extend_from_slice(user.as_bytes());
        payload.push(0);
        payload.extend_from_slice(b"database\0");
        payload.extend_from_slice(database.as_bytes());
        payload.extend_from_slice(b"\0\0");
        let mut frame = ((payload.len() + 4) as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame
    }

    fn typed(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![tag];
        frame.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn decodes_fragmented_startup_and_simple_query() {
        let mut decoder = PostgresDecoder::new(1024);
        let startup = startup("alice", "app");
        assert!(decoder
            .push(Direction::ClientToServer, &startup[..3])
            .messages
            .is_empty());
        let batch = decoder.push(Direction::ClientToServer, &startup[3..]);
        assert_eq!(batch.messages[0].start_line, "StartupMessage protocol=3.0");
        assert!(batch.messages[0]
            .headers
            .contains(&("user".to_string(), "alice".to_string())));

        let query = typed(b'Q', b"SELECT * FROM users WHERE id = 42\0");
        let batch = decoder.push(Direction::ClientToServer, &query);
        assert_eq!(batch.messages[0].start_line, "Query");
        assert_eq!(batch.messages[0].body, b"SELECT * FROM users WHERE id = 42");
        assert!(batch.messages[0]
            .headers
            .contains(&("lens-boundary".to_string(), "request".to_string())));
    }

    #[test]
    fn ssl_acceptance_marks_the_remaining_stream_opaque() {
        let mut decoder = PostgresDecoder::new(1024);
        let mut request = 8_u32.to_be_bytes().to_vec();
        request.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
        assert_eq!(
            decoder.push(Direction::ClientToServer, &request).messages[0].start_line,
            "SSLRequest"
        );
        let batch = decoder.push(Direction::ServerToClient, b"S");
        assert!(batch.messages[0].start_line.contains("traffic opaque"));
        assert!(decoder
            .push(Direction::ClientToServer, b"encrypted bytes")
            .messages
            .is_empty());
        assert!(decoder
            .finish(Direction::ClientToServer)
            .desynchronized
            .is_none());
    }

    #[test]
    fn rejects_oversized_frames_without_retaining_them() {
        let mut decoder = PostgresDecoder::new(1024);
        let batch = decoder.push(
            Direction::ClientToServer,
            &((MAX_FRAME_BYTES as u32 + 1).to_be_bytes()),
        );
        assert!(batch
            .desynchronized
            .as_deref()
            .is_some_and(|reason| reason.contains("startup frame length")));
    }

    #[test]
    fn never_retains_auth_bind_or_row_values() {
        let mut decoder = PostgresDecoder::new(1024);
        decoder.push(Direction::ClientToServer, &startup("alice", "app"));

        let auth = decoder.push(Direction::ClientToServer, &typed(b'p', b"hunter2\0"));
        assert!(!String::from_utf8_lossy(&auth.messages[0].render()).contains("hunter2"));

        let bind = typed(b'B', b"\0\0\0\x00\x01\x00\x00\x00\x06secret\x00\x00");
        let bind = decoder.push(Direction::ClientToServer, &bind);
        assert!(!String::from_utf8_lossy(&bind.messages[0].render()).contains("secret"));

        let row = typed(b'D', b"\x00\x01\x00\x00\x00\x06secret");
        let row = decoder.push(Direction::ServerToClient, &row);
        assert!(!String::from_utf8_lossy(&row.messages[0].render()).contains("secret"));
    }

    #[test]
    fn query_capture_limit_is_visible_without_losing_next_frame() {
        let mut decoder = PostgresDecoder::new(6);
        decoder.push(Direction::ClientToServer, &startup("alice", "app"));
        let mut frames = typed(b'Q', b"SELECT secret\0");
        frames.extend_from_slice(&typed(b'S', b""));
        let batch = decoder.push(Direction::ClientToServer, &frames);
        assert_eq!(batch.messages.len(), 2);
        assert_eq!(batch.messages[0].body, b"SELECT");
        assert!(batch.messages[0].truncated);
        assert_eq!(batch.messages[1].start_line, "Sync");
    }

    #[test]
    fn malformed_corpus_is_safe_at_every_fragment_boundary() {
        const CORPUS: &[&[u8]] = &[
            b"",
            b"\0\0\0\0",
            b"\0\0\0\x08\xff\xff\xff\xff",
            b"\0\0\0\x09\0\x03\0\0x",
            b"Q\0\0\0\x03",
            b"B\xff\xff\xff\xff",
            b"D\0\0\0\x08\0\x01\xff\xff\xff",
        ];

        for sample in CORPUS {
            for split in 0..=sample.len() {
                let mut decoder = PostgresDecoder::new(64);
                let _ = decoder.push(Direction::ClientToServer, &sample[..split]);
                let _ = decoder.push(Direction::ClientToServer, &sample[split..]);
                let _ = decoder.push(Direction::ServerToClient, &sample[..split]);
                let _ = decoder.push(Direction::ServerToClient, &sample[split..]);
                let _ = decoder.finish(Direction::ClientToServer);
                let _ = decoder.finish(Direction::ServerToClient);
            }
        }
    }
}
