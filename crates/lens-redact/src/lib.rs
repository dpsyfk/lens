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

/// Redacts common HTTP secrets unless reveal mode is explicitly enabled.
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

    /// Applies header, query-string, form, and JSON secret redaction.
    #[must_use]
    pub fn redact(&self, mut message: DecodedMessage) -> RedactionOutcome {
        if self.reveal {
            return RedactionOutcome {
                message,
                redacted: false,
            };
        }

        let mut redacted = redact_start_line(&mut message.start_line);
        for (name, value) in &mut message.headers {
            if is_sensitive_name(name) && value != REPLACEMENT {
                *value = REPLACEMENT.to_string();
                redacted = true;
            }
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
}
