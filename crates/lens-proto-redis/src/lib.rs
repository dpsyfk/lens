//! Bounded incremental Redis RESP2/RESP3 decoder.

use lens_core::Direction;
use lens_protocol::{DecodeBatch, DecodedMessage, StreamingDecoder};

const MAX_NESTING: usize = 32;
const MAX_AGGREGATE_ITEMS: usize = 4096;
const FRAME_OVERHEAD_BUDGET: usize = 64 * 1024;

/// Streaming Redis decoder with independent directional buffers.
#[derive(Debug)]
pub struct RedisDecoder {
    client: Vec<u8>,
    server: Vec<u8>,
    max_body: usize,
}

impl RedisDecoder {
    /// Creates a decoder with a per-message retained-value cap.
    #[must_use]
    pub const fn new(max_body: usize) -> Self {
        Self {
            client: Vec::new(),
            server: Vec::new(),
            max_body,
        }
    }

    fn state_mut(&mut self, direction: Direction) -> &mut Vec<u8> {
        match direction {
            Direction::ClientToServer => &mut self.client,
            Direction::ServerToClient => &mut self.server,
        }
    }

    fn decode_available(&mut self, direction: Direction) -> DecodeBatch {
        let max_body = self.max_body;
        let buffer = self.state_mut(direction);
        let mut batch = DecodeBatch::need_more();
        loop {
            if buffer.is_empty() {
                break;
            }
            match parse_value(buffer, 0) {
                Parse::Complete(value, consumed) => {
                    batch.messages.push(to_message(direction, &value, max_body));
                    buffer.drain(..consumed);
                }
                Parse::Incomplete => {
                    if buffer.len() > max_body.saturating_add(FRAME_OVERHEAD_BUDGET) {
                        buffer.clear();
                        batch.desynchronized =
                            Some("Redis frame exceeded the bounded observation buffer".to_string());
                    }
                    break;
                }
                Parse::Invalid(reason) => {
                    buffer.clear();
                    batch.desynchronized = Some(reason);
                    break;
                }
            }
        }
        batch
    }
}

impl StreamingDecoder for RedisDecoder {
    fn protocol(&self) -> &'static str {
        "redis"
    }

    fn push(&mut self, direction: Direction, bytes: &[u8]) -> DecodeBatch {
        self.state_mut(direction).extend_from_slice(bytes);
        self.decode_available(direction)
    }

    fn finish(&mut self, direction: Direction) -> DecodeBatch {
        let mut batch = self.decode_available(direction);
        let state = self.state_mut(direction);
        if !state.is_empty() {
            state.clear();
            batch.desynchronized = Some("Redis stream ended inside a RESP frame".to_string());
        }
        batch
    }
}

#[derive(Clone, Debug)]
enum RespValue {
    Simple(Vec<u8>),
    Error(Vec<u8>),
    Integer(Vec<u8>),
    Bulk(Option<Vec<u8>>),
    Array(Option<Vec<RespValue>>),
    Null,
    Boolean(bool),
    Double(Vec<u8>),
    BigNumber(Vec<u8>),
    BulkError(Vec<u8>),
    Verbatim(Vec<u8>),
    Map(Vec<RespValue>),
    Set(Vec<RespValue>),
    Push(Vec<RespValue>),
    Attribute(Vec<RespValue>),
    Inline(Vec<Vec<u8>>),
}

enum Parse {
    Complete(RespValue, usize),
    Incomplete,
    Invalid(String),
}

fn parse_value(bytes: &[u8], depth: usize) -> Parse {
    if bytes.is_empty() {
        return Parse::Incomplete;
    }
    if depth >= MAX_NESTING {
        return Parse::Invalid("Redis nesting exceeds the decoder limit".to_string());
    }
    match bytes[0] {
        b'+' => parse_line_value(bytes, RespValue::Simple),
        b'-' => parse_line_value(bytes, RespValue::Error),
        b':' => parse_line_value(bytes, RespValue::Integer),
        b',' => parse_line_value(bytes, RespValue::Double),
        b'(' => parse_line_value(bytes, RespValue::BigNumber),
        b'_' => match expect_empty_line(bytes) {
            Some(true) => Parse::Complete(RespValue::Null, 3),
            Some(false) => Parse::Invalid("invalid RESP3 null frame".to_string()),
            None => Parse::Incomplete,
        },
        b'#' => match line(bytes) {
            Some((value, consumed)) if value == b"t" => {
                Parse::Complete(RespValue::Boolean(true), consumed)
            }
            Some((value, consumed)) if value == b"f" => {
                Parse::Complete(RespValue::Boolean(false), consumed)
            }
            Some(_) => Parse::Invalid("invalid RESP3 boolean frame".to_string()),
            None => Parse::Incomplete,
        },
        b'$' => parse_blob(
            bytes,
            |value| RespValue::Bulk(Some(value)),
            || RespValue::Bulk(None),
        ),
        b'!' => parse_blob(bytes, RespValue::BulkError, || {
            RespValue::BulkError(Vec::new())
        }),
        b'=' => parse_blob(bytes, RespValue::Verbatim, || {
            RespValue::Verbatim(Vec::new())
        }),
        b'*' => parse_aggregate(bytes, depth, RespValue::Array, true),
        b'%' => parse_flat_aggregate(bytes, depth, RespValue::Map, 2),
        b'~' => parse_flat_aggregate(bytes, depth, RespValue::Set, 1),
        b'>' => parse_flat_aggregate(bytes, depth, RespValue::Push, 1),
        b'|' => parse_flat_aggregate(bytes, depth, RespValue::Attribute, 2),
        _ => parse_inline(bytes),
    }
}

fn parse_line_value(bytes: &[u8], constructor: fn(Vec<u8>) -> RespValue) -> Parse {
    match line(bytes) {
        Some((value, consumed)) => Parse::Complete(constructor(value.to_vec()), consumed),
        None => Parse::Incomplete,
    }
}

fn parse_blob<F, N>(bytes: &[u8], constructor: F, null: N) -> Parse
where
    F: FnOnce(Vec<u8>) -> RespValue,
    N: FnOnce() -> RespValue,
{
    let Some((length, header)) = line(bytes) else {
        return Parse::Incomplete;
    };
    let Ok(length) = parse_signed(length) else {
        return Parse::Invalid("invalid Redis blob length".to_string());
    };
    if length == -1 {
        return Parse::Complete(null(), header);
    }
    let Ok(length) = usize::try_from(length) else {
        return Parse::Invalid("negative Redis blob length".to_string());
    };
    let Some(end) = header.checked_add(length) else {
        return Parse::Invalid("Redis blob length overflow".to_string());
    };
    let Some(total) = end.checked_add(2) else {
        return Parse::Invalid("Redis blob length overflow".to_string());
    };
    if bytes.len() < total {
        return Parse::Incomplete;
    }
    if &bytes[end..total] != b"\r\n" {
        return Parse::Invalid("Redis blob is missing its CRLF terminator".to_string());
    }
    Parse::Complete(constructor(bytes[header..end].to_vec()), total)
}

fn parse_aggregate(
    bytes: &[u8],
    depth: usize,
    constructor: fn(Option<Vec<RespValue>>) -> RespValue,
    nullable: bool,
) -> Parse {
    let Some((count, mut consumed)) = line(bytes) else {
        return Parse::Incomplete;
    };
    let Ok(count) = parse_signed(count) else {
        return Parse::Invalid("invalid Redis aggregate length".to_string());
    };
    if nullable && count == -1 {
        return Parse::Complete(constructor(None), consumed);
    }
    let Ok(count) = usize::try_from(count) else {
        return Parse::Invalid("negative Redis aggregate length".to_string());
    };
    if count > MAX_AGGREGATE_ITEMS {
        return Parse::Invalid("Redis aggregate exceeds the item limit".to_string());
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        match parse_value(&bytes[consumed..], depth + 1) {
            Parse::Complete(value, used) => {
                consumed += used;
                values.push(value);
            }
            Parse::Incomplete => return Parse::Incomplete,
            Parse::Invalid(reason) => return Parse::Invalid(reason),
        }
    }
    Parse::Complete(constructor(Some(values)), consumed)
}

fn parse_flat_aggregate(
    bytes: &[u8],
    depth: usize,
    constructor: fn(Vec<RespValue>) -> RespValue,
    multiplier: usize,
) -> Parse {
    let Some((count, mut consumed)) = line(bytes) else {
        return Parse::Incomplete;
    };
    let Ok(count) = parse_signed(count) else {
        return Parse::Invalid("invalid RESP3 aggregate length".to_string());
    };
    let Ok(count) = usize::try_from(count) else {
        return Parse::Invalid("negative RESP3 aggregate length".to_string());
    };
    let Some(items) = count.checked_mul(multiplier) else {
        return Parse::Invalid("RESP3 aggregate length overflow".to_string());
    };
    if items > MAX_AGGREGATE_ITEMS {
        return Parse::Invalid("RESP3 aggregate exceeds the item limit".to_string());
    }
    let mut values = Vec::with_capacity(items);
    for _ in 0..items {
        match parse_value(&bytes[consumed..], depth + 1) {
            Parse::Complete(value, used) => {
                consumed += used;
                values.push(value);
            }
            Parse::Incomplete => return Parse::Incomplete,
            Parse::Invalid(reason) => return Parse::Invalid(reason),
        }
    }
    Parse::Complete(constructor(values), consumed)
}

fn parse_inline(bytes: &[u8]) -> Parse {
    let Some(end) = find_crlf(bytes) else {
        return Parse::Incomplete;
    };
    let line = &bytes[..end];
    if line
        .iter()
        .any(|byte| byte.is_ascii_control() && *byte != b'\t')
    {
        return Parse::Invalid("invalid inline Redis command".to_string());
    }
    let values = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|value| !value.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Parse::Invalid("empty inline Redis command".to_string());
    }
    Parse::Complete(RespValue::Inline(values), end + 2)
}

fn line(bytes: &[u8]) -> Option<(&[u8], usize)> {
    let end = find_crlf(bytes.get(1..)?)? + 1;
    Some((&bytes[1..end], end + 2))
}

fn expect_empty_line(bytes: &[u8]) -> Option<bool> {
    if bytes.len() < 3 {
        None
    } else {
        Some(&bytes[1..3] == b"\r\n")
    }
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

fn parse_signed(bytes: &[u8]) -> Result<i64, ()> {
    std::str::from_utf8(bytes)
        .map_err(|_| ())?
        .parse::<i64>()
        .map_err(|_| ())
}

fn to_message(direction: Direction, value: &RespValue, max_body: usize) -> DecodedMessage {
    match direction {
        Direction::ClientToServer => request_message(value, max_body),
        Direction::ServerToClient => response_message(value, max_body),
    }
}

fn request_message(value: &RespValue, max_body: usize) -> DecodedMessage {
    let arguments = match value {
        RespValue::Array(Some(values)) => {
            values.iter().filter_map(scalar_bytes).collect::<Vec<_>>()
        }
        RespValue::Inline(values) => values.iter().map(Vec::as_slice).collect(),
        _ => Vec::new(),
    };
    let command = arguments
        .first()
        .map(|value| String::from_utf8_lossy(value).to_ascii_uppercase())
        .unwrap_or_else(|| "UNKNOWN".to_string());
    let mut retained = 0_usize;
    let mut truncated = false;
    let mut headers = vec![
        ("lens-protocol".to_string(), "redis".to_string()),
        ("lens-boundary".to_string(), "request".to_string()),
        ("redis-command".to_string(), command.clone()),
    ];
    for argument in arguments.iter().skip(1) {
        let rendered = render_bytes(argument);
        let remaining = max_body.saturating_sub(retained);
        let captured = truncate_utf8(&rendered, remaining);
        retained = retained.saturating_add(captured.len());
        truncated |= captured.len() < rendered.len();
        headers.push(("redis-arg".to_string(), captured));
    }
    let summary = redis_request_summary(&command, &headers);
    DecodedMessage {
        direction: Direction::ClientToServer,
        start_line: summary,
        headers,
        body: Vec::new(),
        truncated,
    }
}

fn response_message(value: &RespValue, max_body: usize) -> DecodedMessage {
    let (kind, summary) = response_summary(value);
    let rendered = render_value(value);
    let body = rendered.as_bytes()[..rendered.len().min(max_body)].to_vec();
    let mut headers = vec![
        ("lens-protocol".to_string(), "redis".to_string()),
        ("redis-kind".to_string(), kind.to_string()),
        ("lens-content".to_string(), "redis-value".to_string()),
    ];
    if !matches!(value, RespValue::Push(_)) {
        headers.push(("lens-boundary".to_string(), "response".to_string()));
    }
    DecodedMessage {
        direction: Direction::ServerToClient,
        start_line: summary,
        headers,
        body,
        truncated: rendered.len() > max_body,
    }
}

fn scalar_bytes(value: &RespValue) -> Option<&[u8]> {
    match value {
        RespValue::Simple(value)
        | RespValue::Error(value)
        | RespValue::Integer(value)
        | RespValue::Bulk(Some(value))
        | RespValue::Double(value)
        | RespValue::BigNumber(value)
        | RespValue::BulkError(value)
        | RespValue::Verbatim(value) => Some(value),
        _ => None,
    }
}

fn redis_request_summary(command: &str, headers: &[(String, String)]) -> String {
    let arguments = headers
        .iter()
        .filter(|(name, _)| name == "redis-arg")
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    if arguments.is_empty() {
        format!("Redis {command}")
    } else {
        format!("Redis {command} {}", arguments.join(" "))
    }
}

fn response_summary(value: &RespValue) -> (&'static str, String) {
    match value {
        RespValue::Simple(value) => ("simple-string", format!("Redis {}", render_bytes(value))),
        RespValue::Error(value) => ("error", format!("Redis error {}", render_bytes(value))),
        RespValue::Integer(value) => ("integer", format!("Redis integer {}", render_bytes(value))),
        RespValue::Bulk(Some(value)) => {
            ("bulk-string", format!("Redis bulk {} bytes", value.len()))
        }
        RespValue::Bulk(None) | RespValue::Null => ("null", "Redis null".to_string()),
        RespValue::Array(Some(values)) => ("array", format!("Redis array {} items", values.len())),
        RespValue::Array(None) => ("null", "Redis null array".to_string()),
        RespValue::Boolean(value) => ("boolean", format!("Redis boolean {value}")),
        RespValue::Double(value) => ("double", format!("Redis double {}", render_bytes(value))),
        RespValue::BigNumber(value) => (
            "big-number",
            format!("Redis big number {}", render_bytes(value)),
        ),
        RespValue::BulkError(value) => (
            "bulk-error",
            format!("Redis bulk error {} bytes", value.len()),
        ),
        RespValue::Verbatim(value) => ("verbatim", format!("Redis verbatim {} bytes", value.len())),
        RespValue::Map(values) => ("map", format!("Redis map {} pairs", values.len() / 2)),
        RespValue::Set(values) => ("set", format!("Redis set {} items", values.len())),
        RespValue::Push(values) => ("push", format!("Redis push {} items", values.len())),
        RespValue::Attribute(values) => (
            "attribute",
            format!("Redis attribute {} pairs", values.len() / 2),
        ),
        RespValue::Inline(values) => ("inline", format!("Redis inline {} items", values.len())),
    }
}

fn render_value(value: &RespValue) -> String {
    match value {
        RespValue::Simple(value)
        | RespValue::Error(value)
        | RespValue::Integer(value)
        | RespValue::Bulk(Some(value))
        | RespValue::Double(value)
        | RespValue::BigNumber(value)
        | RespValue::BulkError(value)
        | RespValue::Verbatim(value) => render_bytes(value),
        RespValue::Bulk(None) | RespValue::Array(None) | RespValue::Null => "null".to_string(),
        RespValue::Boolean(value) => value.to_string(),
        RespValue::Array(Some(values))
        | RespValue::Map(values)
        | RespValue::Set(values)
        | RespValue::Push(values)
        | RespValue::Attribute(values) => format!(
            "[{}]",
            values
                .iter()
                .map(render_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        RespValue::Inline(values) => values
            .iter()
            .map(|value| render_bytes(value))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn render_bytes(value: &[u8]) -> String {
    let mut rendered = String::new();
    for &byte in value {
        match byte {
            b' '..=b'~' if byte != b'\\' => rendered.push(char::from(byte)),
            b'\\' => rendered.push_str("\\\\"),
            b'\n' => rendered.push_str("\\n"),
            b'\r' => rendered.push_str("\\r"),
            b'\t' => rendered.push_str("\\t"),
            _ => rendered.push_str(&format!("\\x{byte:02x}")),
        }
    }
    rendered
}

fn truncate_utf8(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(arguments: &[&str]) -> Vec<u8> {
        let mut frame = format!("*{}\r\n", arguments.len()).into_bytes();
        for argument in arguments {
            frame.extend_from_slice(format!("${}\r\n{}\r\n", argument.len(), argument).as_bytes());
        }
        frame
    }

    #[test]
    fn decodes_fragmented_pipelined_commands() {
        let mut decoder = RedisDecoder::new(1024);
        let mut bytes = command(&["GET", "session:1"]);
        bytes.extend(command(&["SET", "session:1", "secret"]));
        let split = 11;
        assert!(decoder
            .push(Direction::ClientToServer, &bytes[..split])
            .messages
            .is_empty());
        let batch = decoder.push(Direction::ClientToServer, &bytes[split..]);
        assert_eq!(batch.messages.len(), 2);
        assert_eq!(batch.messages[0].summary(), "Redis GET session:1");
        assert_eq!(batch.messages[1].summary(), "Redis SET session:1 secret");
    }

    #[test]
    fn decodes_resp3_push_without_response_boundary() {
        let mut decoder = RedisDecoder::new(1024);
        let batch = decoder.push(
            Direction::ServerToClient,
            b">3\r\n+message\r\n+channel\r\n+payload\r\n",
        );
        let message = &batch.messages[0];
        assert_eq!(message.summary(), "Redis push 3 items");
        assert!(!message
            .headers
            .iter()
            .any(|(name, _)| name == "lens-boundary"));
    }

    #[test]
    fn caps_retained_values_and_reports_incomplete_eof() {
        let mut decoder = RedisDecoder::new(4);
        let batch = decoder.push(Direction::ServerToClient, b"$8\r\nabcdefgh\r\n");
        assert_eq!(batch.messages[0].body, b"abcd");
        assert!(batch.messages[0].truncated);

        decoder.push(Direction::ClientToServer, b"*2\r\n$3\r\nGET\r\n$5\r\nab");
        assert!(decoder
            .finish(Direction::ClientToServer)
            .desynchronized
            .is_some());
    }

    #[test]
    fn rejects_aggregate_bombs_without_panicking() {
        let mut decoder = RedisDecoder::new(1024);
        let batch = decoder.push(Direction::ClientToServer, b"*999999999\r\n");
        assert!(batch.desynchronized.is_some());
    }
}
