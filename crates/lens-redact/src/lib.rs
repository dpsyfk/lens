//! Default-safe redaction for decoded protocol messages.

use lens_protocol::DecodedMessage;
use regex::{Captures, Regex};

const REPLACEMENT: &str = "[REDACTED]";

/// Result of applying the default redaction policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionOutcome {
    /// Message safe for storage and display under the selected policy.
    pub message: DecodedMessage,
    /// Whether at least one sensitive value was replaced.
    pub redacted: bool,
}

/// Redacts common HTTP, PostgreSQL, Redis, and gRPC secrets unless reveal mode is enabled.
#[derive(Clone, Debug)]
pub struct Redactor {
    reveal: bool,
    json_secret: Regex,
}

impl Redactor {
    /// Creates the default redactor. `reveal` must come from an explicit user opt-in.
    #[must_use]
    pub fn new(reveal: bool) -> Self {
        Self {
            reveal,
            json_secret: Regex::new(
                r#"(?i)(\"(?:password|passwd|token|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\"\s*:\s*)(\"(?:\\.|[^\"])*\"|[^,}\s]+)"#,
            )
            .expect("static secret regex is valid"),
        }
    }

    /// Applies HTTP structural redaction and PostgreSQL SQL-literal redaction.
    #[must_use]
    pub fn redact(&self, mut message: DecodedMessage) -> RedactionOutcome {
        if self.reveal {
            return RedactionOutcome {
                message,
                redacted: false,
            };
        }

        let postgres = message.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("lens-protocol") && value.eq_ignore_ascii_case("postgres")
        });
        let redis = message.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("lens-protocol") && value.eq_ignore_ascii_case("redis")
        });
        let grpc = message.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("lens-protocol") && value.eq_ignore_ascii_case("grpc")
        });
        let sql_body = postgres
            && message.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("lens-content") && value.eq_ignore_ascii_case("sql")
            });

        let mut redacted = if redis {
            redact_redis(&mut message)
        } else {
            redact_start_line(&mut message.start_line)
        };
        for (name, value) in &mut message.headers {
            if is_sensitive_name(name) && value != REPLACEMENT {
                *value = REPLACEMENT.to_string();
                redacted = true;
            } else if postgres
                && matches!(
                    name.to_ascii_lowercase().as_str(),
                    "message" | "detail" | "hint" | "where"
                )
            {
                let (safe, changed) = redact_sql_literals(value);
                if changed {
                    *value = safe;
                    redacted = true;
                }
            }
        }

        if sql_body {
            if let Ok(sql) = std::str::from_utf8(&message.body) {
                let (safe, changed) = redact_sql_literals(sql);
                if changed {
                    message.body = safe.into_bytes();
                    redacted = true;
                }
            }
            return RedactionOutcome { message, redacted };
        }

        if redis {
            let response_value = message.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("lens-content")
                    && value.eq_ignore_ascii_case("redis-value")
            });
            if response_value && !message.body.is_empty() {
                message.body = REPLACEMENT.as_bytes().to_vec();
                redacted = true;
            }
            return RedactionOutcome { message, redacted };
        }

        if grpc
            && message.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("lens-content") && value.eq_ignore_ascii_case("protobuf")
            })
            && !message.body.is_empty()
        {
            message.body = REPLACEMENT.as_bytes().to_vec();
            redacted = true;
            return RedactionOutcome { message, redacted };
        }

        let content_type = message
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.to_ascii_lowercase())
            .unwrap_or_default();
        if content_type.contains("application/x-www-form-urlencoded") {
            if let Ok(body) = std::str::from_utf8(&message.body) {
                let (safe, changed) = redact_pairs(body, '&');
                if changed {
                    message.body = safe.into_bytes();
                    redacted = true;
                }
            }
        } else if content_type.contains("json")
            || message
                .body
                .first()
                .is_some_and(|byte| matches!(byte, b'{' | b'['))
        {
            if let Ok(body) = std::str::from_utf8(&message.body) {
                let changed = self.json_secret.is_match(body);
                if changed {
                    let safe = self
                        .json_secret
                        .replace_all(body, |captures: &Captures<'_>| {
                            format!("{}\"{REPLACEMENT}\"", &captures[1])
                        });
                    message.body = safe.into_owned().into_bytes();
                    redacted = true;
                }
            }
        }

        RedactionOutcome { message, redacted }
    }
}

fn redact_redis(message: &mut DecodedMessage) -> bool {
    let command = message
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("redis-command"))
        .map(|(_, value)| value.to_ascii_uppercase());
    let Some(command) = command else {
        return false;
    };
    let argument_indices = message
        .headers
        .iter()
        .enumerate()
        .filter_map(|(index, (name, _))| name.eq_ignore_ascii_case("redis-arg").then_some(index))
        .collect::<Vec<_>>();
    let arguments = argument_indices
        .iter()
        .map(|index| message.headers[*index].1.clone())
        .collect::<Vec<_>>();
    let mut changed = false;
    for (position, header_index) in argument_indices.iter().copied().enumerate() {
        if redis_argument_is_sensitive(&command, position, &arguments)
            && message.headers[header_index].1 != REPLACEMENT
        {
            message.headers[header_index].1 = REPLACEMENT.to_string();
            changed = true;
        }
    }
    let safe_arguments = argument_indices
        .iter()
        .map(|index| message.headers[*index].1.as_str())
        .collect::<Vec<_>>();
    message.start_line = if safe_arguments.is_empty() {
        format!("Redis {command}")
    } else {
        format!("Redis {command} {}", safe_arguments.join(" "))
    };
    changed
}

fn redis_argument_is_sensitive(command: &str, position: usize, arguments: &[String]) -> bool {
    match command {
        "AUTH" => return true,
        "HELLO" => {
            return position > 0
                && arguments
                    .get(position.saturating_sub(2))
                    .is_some_and(|value| value.eq_ignore_ascii_case("AUTH"));
        }
        "SET" | "SETNX" | "GETSET" | "APPEND" | "SETRANGE" | "SETEX" | "PSETEX" => {
            return position > 0;
        }
        "MSET" | "MSETNX" => return position % 2 == 1,
        "HSET" | "HSETNX" | "HMSET" => {
            return position >= 2 && position.is_multiple_of(2);
        }
        "JSON.SET" => return position >= 2,
        "EVAL" | "EVALSHA" | "FCALL" | "FCALL_RO" => return true,
        "CONFIG" => {
            return arguments
                .first()
                .is_some_and(|value| value.eq_ignore_ascii_case("SET"))
                && position >= 2;
        }
        "ACL" => {
            return arguments
                .first()
                .is_some_and(|value| value.eq_ignore_ascii_case("SETUSER"))
                && arguments.get(position).is_some_and(|value| {
                    value.starts_with('>') || value.starts_with('#') || value.starts_with('<')
                });
        }
        _ => {}
    }
    let current = arguments
        .get(position)
        .map(String::as_str)
        .unwrap_or_default();
    let previous = position
        .checked_sub(1)
        .and_then(|index| arguments.get(index))
        .map(String::as_str)
        .unwrap_or_default();
    is_sensitive_name(current)
        || is_sensitive_name(previous)
        || matches!(previous.to_ascii_uppercase().as_str(), "AUTH" | "AUTH2")
}

/// Replaces PostgreSQL literal values and comment contents while preserving SQL shape.
fn redact_sql_literals(sql: &str) -> (String, bool) {
    let bytes = sql.as_bytes();
    let mut safe = String::with_capacity(sql.len());
    let mut index = 0;
    let mut changed = false;

    while index < bytes.len() {
        if bytes[index] == b'"' {
            let mut end = index + 1;
            while end < bytes.len() {
                if bytes[end] == b'"' {
                    end += 1;
                    if bytes.get(end) == Some(&b'"') {
                        end += 1;
                        continue;
                    }
                    break;
                }
                end += 1;
            }
            safe.push_str(&sql[index..end]);
            index = end;
            continue;
        }

        if bytes[index] == b'\'' {
            let mut end = index + 1;
            while end < bytes.len() {
                if bytes[end] == b'\'' {
                    if bytes.get(end + 1) == Some(&b'\'') {
                        end += 2;
                        continue;
                    }
                    end += 1;
                    break;
                }
                end += 1;
            }
            safe.push_str("'?'");
            index = end;
            changed = true;
            continue;
        }

        if bytes[index..].starts_with(b"--") {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| index + offset);
            safe.push_str("-- [REDACTED]");
            if end < bytes.len() {
                safe.push('\n');
                index = end + 1;
            } else {
                index = end;
            }
            changed = true;
            continue;
        }

        if bytes[index..].starts_with(b"/*") {
            let end = find_bytes(&bytes[index + 2..], b"*/")
                .map_or(bytes.len(), |offset| index + 2 + offset + 2);
            safe.push_str("/* [REDACTED] */");
            index = end;
            changed = true;
            continue;
        }

        if bytes[index] == b'$' {
            if let Some(delimiter_end) = dollar_delimiter_end(&bytes[index..]) {
                let delimiter = &sql[index..index + delimiter_end];
                let content_start = index + delimiter_end;
                if let Some(content_len) = sql[content_start..].find(delimiter) {
                    safe.push_str(delimiter);
                    safe.push('?');
                    safe.push_str(delimiter);
                    index = content_start + content_len + delimiter.len();
                    changed = true;
                    continue;
                }
            }
        }

        if is_number_start(bytes, index) {
            let mut end = index + 1;
            while end < bytes.len()
                && (bytes[end].is_ascii_digit()
                    || matches!(bytes[end], b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                end += 1;
            }
            safe.push('?');
            index = end;
            changed = true;
            continue;
        }

        let character = sql[index..].chars().next().expect("valid UTF-8 boundary");
        safe.push(character);
        index += character.len_utf8();
    }

    (safe, changed)
}

fn is_number_start(bytes: &[u8], index: usize) -> bool {
    if !bytes[index].is_ascii_digit() {
        return false;
    }
    let previous = index
        .checked_sub(1)
        .and_then(|value| bytes.get(value))
        .copied();
    let next = bytes.get(index + 1).copied();
    !previous.is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
        && !next.is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
}

fn dollar_delimiter_end(bytes: &[u8]) -> Option<usize> {
    if bytes.first() != Some(&b'$') {
        return None;
    }
    for (offset, byte) in bytes.iter().enumerate().skip(1) {
        if *byte == b'$' {
            return Some(offset + 1);
        }
        if !byte.is_ascii_alphanumeric() && *byte != b'_' {
            return None;
        }
    }
    None
}

fn find_bytes(buffer: &[u8], needle: &[u8]) -> Option<usize> {
    buffer
        .windows(needle.len())
        .position(|window| window == needle)
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new(false)
    }
}

fn redact_start_line(start_line: &mut String) -> bool {
    let mut parts = start_line.split_whitespace();
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    if method.starts_with("HTTP/") || !version.starts_with("HTTP/") {
        return false;
    }
    let Some((path, query)) = target.split_once('?') else {
        return false;
    };
    let (query, fragment) = query
        .split_once('#')
        .map_or((query, None), |(query, fragment)| (query, Some(fragment)));
    let (safe, changed) = redact_pairs(query, '&');
    if changed {
        *start_line = format!(
            "{method} {path}?{safe}{} {version}",
            fragment.map_or_else(String::new, |fragment| format!("#{fragment}"))
        );
    }
    changed
}

fn redact_pairs(value: &str, separator: char) -> (String, bool) {
    let mut changed = false;
    let safe = value
        .split(separator)
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if is_sensitive_name(&percent_decode_name(name)) {
                changed = true;
                format!("{name}={REPLACEMENT}")
            } else if pair.contains('=') {
                format!("{name}={value}")
            } else {
                name.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(&separator.to_string());
    (safe, changed)
}

fn percent_decode_name(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                decoded.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        decoded.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_sensitive_name(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "password"
            | "passwd"
            | "token"
            | "secret"
            | "api_key"
            | "api-key"
            | "apikey"
            | "access_token"
            | "access-token"
            | "refresh_token"
            | "refresh-token"
            | "client_secret"
            | "client-secret"
            | "private_key"
            | "private-key"
            | "session_id"
            | "session-id"
            | "jwt"
            | "grpc-message"
    ) || [
        "_password",
        "-password",
        "_token",
        "-token",
        "_secret",
        "-secret",
        "_api_key",
        "-api-key",
        "_private_key",
        "-private-key",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use lens_core::Direction;

    use super::*;

    fn message(start_line: &str, content_type: &str, body: &[u8]) -> DecodedMessage {
        DecodedMessage {
            direction: Direction::ClientToServer,
            start_line: start_line.to_string(),
            headers: vec![
                (
                    "Authorization".to_string(),
                    "Bearer super-secret".to_string(),
                ),
                ("Content-Type".to_string(), content_type.to_string()),
            ],
            body: body.to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn redacts_headers_query_and_json_by_default() {
        let outcome = Redactor::default().redact(message(
            "POST /login?token=abc&safe=yes HTTP/1.1",
            "application/json",
            br#"{"password":"hunter2","name":"Ada"}"#,
        ));
        assert!(outcome.redacted);
        assert_eq!(outcome.message.headers[0].1, REPLACEMENT);
        assert!(outcome.message.start_line.contains("token=[REDACTED]"));
        let body = String::from_utf8(outcome.message.body).unwrap();
        assert!(body.contains(r#""password":"[REDACTED]""#));
        assert!(body.contains(r#""name":"Ada""#));
    }

    #[test]
    fn redacts_form_values_and_percent_encoded_names() {
        let outcome = Redactor::default().redact(message(
            "POST / HTTP/1.1",
            "application/x-www-form-urlencoded",
            b"user=ada&api%5Fkey=abc",
        ));
        assert_eq!(
            String::from_utf8(outcome.message.body).unwrap(),
            "user=ada&api%5Fkey=[REDACTED]"
        );
    }

    #[test]
    fn redacts_common_prefixed_secret_names() {
        let outcome = Redactor::default().redact(message(
            "GET /?oauth_token=abc&client-secret=def&safe_key=shown HTTP/1.1",
            "text/plain",
            b"",
        ));
        assert!(outcome
            .message
            .start_line
            .contains("oauth_token=[REDACTED]"));
        assert!(outcome
            .message
            .start_line
            .contains("client-secret=[REDACTED]"));
        assert!(outcome.message.start_line.contains("safe_key=shown"));
    }

    #[test]
    fn reveal_mode_preserves_sensitive_values() {
        let original = message(
            "GET /?token=abc HTTP/1.1",
            "application/json",
            br#"{"password":"hunter2"}"#,
        );
        let outcome = Redactor::new(true).redact(original.clone());
        assert!(!outcome.redacted);
        assert_eq!(outcome.message, original);
    }

    #[test]
    fn redacts_postgres_literals_and_comments_but_keeps_placeholders() {
        let message = DecodedMessage {
            direction: Direction::ClientToServer,
            start_line: "Query".to_string(),
            headers: vec![
                ("lens-protocol".to_string(), "postgres".to_string()),
                ("lens-content".to_string(), "sql".to_string()),
            ],
            body: b"SELECT * FROM users_2 WHERE id = 42 AND name = 'Ada' AND ref = $1 -- token abc"
                .to_vec(),
            truncated: false,
        };
        let outcome = Redactor::default().redact(message);
        let sql = String::from_utf8(outcome.message.body).unwrap();
        assert!(outcome.redacted);
        assert_eq!(
            sql,
            "SELECT * FROM users_2 WHERE id = ? AND name = '?' AND ref = $1 -- [REDACTED]"
        );
    }

    #[test]
    fn postgres_reveal_preserves_sql_but_decoder_metadata_stays_safe() {
        let message = DecodedMessage {
            direction: Direction::ClientToServer,
            start_line: "Query".to_string(),
            headers: vec![
                ("lens-protocol".to_string(), "postgres".to_string()),
                ("lens-content".to_string(), "sql".to_string()),
            ],
            body: b"SELECT 'visible', 42".to_vec(),
            truncated: false,
        };
        let outcome = Redactor::new(true).redact(message.clone());
        assert!(!outcome.redacted);
        assert_eq!(outcome.message, message);
    }

    #[test]
    fn redis_credentials_and_write_values_are_redacted_structurally() {
        let auth = DecodedMessage {
            direction: Direction::ClientToServer,
            start_line: "Redis AUTH alice hunter2".to_string(),
            headers: vec![
                ("lens-protocol".to_string(), "redis".to_string()),
                ("redis-command".to_string(), "AUTH".to_string()),
                ("redis-arg".to_string(), "alice".to_string()),
                ("redis-arg".to_string(), "hunter2".to_string()),
            ],
            body: Vec::new(),
            truncated: false,
        };
        let outcome = Redactor::default().redact(auth);
        assert!(outcome.redacted);
        assert_eq!(
            outcome.message.start_line,
            "Redis AUTH [REDACTED] [REDACTED]"
        );
        assert!(!outcome
            .message
            .render()
            .windows(7)
            .any(|value| value == b"hunter2"));

        let set = DecodedMessage {
            direction: Direction::ClientToServer,
            start_line: "Redis SET session:1 bearer-token EX 60".to_string(),
            headers: vec![
                ("lens-protocol".to_string(), "redis".to_string()),
                ("redis-command".to_string(), "SET".to_string()),
                ("redis-arg".to_string(), "session:1".to_string()),
                ("redis-arg".to_string(), "bearer-token".to_string()),
                ("redis-arg".to_string(), "EX".to_string()),
                ("redis-arg".to_string(), "60".to_string()),
            ],
            body: Vec::new(),
            truncated: false,
        };
        let outcome = Redactor::default().redact(set);
        assert!(outcome
            .message
            .start_line
            .starts_with("Redis SET session:1 "));
        assert!(!outcome.message.start_line.contains("bearer-token"));
    }

    #[test]
    fn redis_responses_and_grpc_protobuf_are_hidden_unless_revealed() {
        let redis = DecodedMessage {
            direction: Direction::ServerToClient,
            start_line: "Redis bulk 12 bytes".to_string(),
            headers: vec![
                ("lens-protocol".to_string(), "redis".to_string()),
                ("lens-content".to_string(), "redis-value".to_string()),
            ],
            body: b"private-value".to_vec(),
            truncated: false,
        };
        assert_eq!(
            Redactor::default().redact(redis).message.body,
            b"[REDACTED]"
        );

        let grpc = DecodedMessage {
            direction: Direction::ClientToServer,
            start_line: "gRPC request /hello.Greeter/SayHello message 4 bytes".to_string(),
            headers: vec![
                ("lens-protocol".to_string(), "grpc".to_string()),
                ("lens-content".to_string(), "protobuf".to_string()),
            ],
            body: vec![0x0a, 0x02, b'h', b'i'],
            truncated: false,
        };
        assert_eq!(
            Redactor::default().redact(grpc.clone()).message.body,
            b"[REDACTED]"
        );
        assert_eq!(Redactor::new(true).redact(grpc.clone()).message, grpc);
    }
}
