//! Safe, explicit HTTP request replay from Lens JSON and JSONL exports.

use std::fmt;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use http::{HeaderName, HeaderValue, Method, Uri};
use serde::Deserialize;

const MAX_CAPTURE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_REPLAY_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const REDACTED: &str = "[REDACTED]";

type HeaderList = Vec<(String, String)>;

/// One-based flow and request selection inside a capture.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplaySelection {
    /// Flow ID, or the only HTTP flow when omitted.
    pub flow_id: Option<u64>,
    /// One-based request number within the selected flow.
    pub request: usize,
}

impl ReplaySelection {
    /// Creates a validated selection.
    pub fn new(flow_id: Option<u64>, request: usize) -> Result<Self, ReplayError> {
        if request == 0 {
            return Err(ReplayError::new("request index must be at least 1"));
        }
        Ok(Self { flow_id, request })
    }
}

/// Explicit acknowledgements required before network execution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReplayPolicy {
    /// Permit methods other than GET, HEAD, and OPTIONS.
    pub allow_unsafe: bool,
    /// Permit a capture produced with reveal mode.
    pub allow_secrets: bool,
    /// Permit sending literal redaction placeholders.
    pub allow_redacted: bool,
    /// Permit a target other than loopback.
    pub allow_remote: bool,
    /// End-to-end request deadline.
    pub timeout: Duration,
}

impl Default for ReplayPolicy {
    fn default() -> Self {
        Self {
            allow_unsafe: false,
            allow_secrets: false,
            allow_redacted: false,
            allow_remote: false,
            timeout: Duration::from_secs(10),
        }
    }
}

/// A reconstructed request that is safe to preview without printing values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayPlan {
    /// Selected flow ID.
    pub flow_id: u64,
    /// One-based request number.
    pub request: usize,
    /// HTTP method.
    pub method: String,
    /// Captured origin-form path and query.
    pub path_and_query: String,
    /// Replayable end-to-end headers after hop-by-hop stripping.
    pub headers: Vec<(String, String)>,
    /// Captured request body.
    pub body: Vec<u8>,
    /// Whether the captured request was truncated.
    pub truncated: bool,
    /// Capture sensitivity label.
    pub sensitivity: String,
    /// Whether redaction placeholders remain in the request.
    pub redacted: bool,
    /// Whether this came from an older text-only export.
    pub legacy_text_encoding: bool,
    captured_response: Option<CapturedResponse>,
}

impl ReplayPlan {
    /// Returns header names only, suitable for a secret-safe preview.
    #[must_use]
    pub fn header_names(&self) -> Vec<&str> {
        self.headers.iter().map(|(name, _)| name.as_str()).collect()
    }

    /// Returns the terminal captured response status, when available.
    #[must_use]
    pub fn captured_status(&self) -> Option<u16> {
        self.captured_response
            .as_ref()
            .map(|response| response.status)
    }

    /// Builds the final replay URL and validates target shape.
    pub fn target_url(&self, target: &str) -> Result<String, ReplayError> {
        let uri = parse_target_origin(target)?;
        Ok(format!(
            "{}://{}{}",
            uri.scheme_str().expect("validated target scheme"),
            uri.authority().expect("validated target authority"),
            self.path_and_query
        ))
    }

    /// Builds a URL suitable for terminal preview without exposing reveal-mode paths.
    pub fn preview_target_url(&self, target: &str) -> Result<String, ReplayError> {
        if self.sensitivity != "secret" {
            return self.target_url(target);
        }
        let uri = parse_target_origin(target)?;
        Ok(format!(
            "{}://{}/[secret path omitted]",
            uri.scheme_str().expect("validated target scheme"),
            uri.authority().expect("validated target authority")
        ))
    }

    /// Applies all execution guards. Previewing never requires these opt-ins.
    pub fn validate_execution(
        &self,
        target: &str,
        policy: ReplayPolicy,
    ) -> Result<String, ReplayError> {
        let target_uri = parse_target_origin(target)?;
        if !is_loopback_target(&target_uri) && !policy.allow_remote {
            return Err(ReplayError::new(
                "remote replay target requires --allow-remote",
            ));
        }
        if self.truncated {
            return Err(ReplayError::new(
                "truncated requests cannot be replayed; capture again with a sufficient --max-body",
            ));
        }
        if self.legacy_text_encoding {
            return Err(ReplayError::new(
                "legacy text-only exports are preview-only; capture again with the current Lens version",
            ));
        }
        if self.sensitivity == "secret" && !policy.allow_secrets {
            return Err(ReplayError::new(
                "secret-bearing capture requires --allow-secrets",
            ));
        }
        if self.redacted && !policy.allow_redacted {
            return Err(ReplayError::new(
                "redacted request requires --allow-redacted to send placeholders",
            ));
        }
        if !is_preview_safe_method(&self.method) && !policy.allow_unsafe {
            return Err(ReplayError::new(format!(
                "{} may change server state; execution requires --allow-unsafe",
                self.method
            )));
        }
        self.target_url(target)
    }
}

/// Result of an executed replay and deterministic comparison with the capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayReport {
    /// Final URL sent to the transport.
    pub target_url: String,
    /// HTTP response status.
    pub status: u16,
    /// Total elapsed time in milliseconds.
    pub elapsed_ms: u128,
    /// Captured response status, when present.
    pub captured_status: Option<u16>,
    /// Whether replay and capture statuses match.
    pub status_match: MatchState,
    /// Whether replay and capture bodies match exactly.
    pub body_match: MatchState,
    /// Whether the replay response exceeded the comparison cap.
    pub response_truncated: bool,
}

/// A comparison that can be unavailable for a documented reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchState {
    /// Values are identical.
    Match,
    /// Values differ.
    Different,
    /// Comparison is unsafe or impossible.
    Unavailable(&'static str),
}

impl fmt::Display for MatchState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Match => formatter.write_str("match"),
            Self::Different => formatter.write_str("different"),
            Self::Unavailable(reason) => write!(formatter, "unavailable ({reason})"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CapturedResponse {
    status: u16,
    body: Vec<u8>,
    truncated: bool,
    redacted: bool,
    legacy_text_encoding: bool,
}

#[derive(Debug, Deserialize)]
struct CaptureDocument {
    flows: Vec<CaptureFlow>,
}

#[derive(Debug, Deserialize)]
struct CaptureFlow {
    flow_id: u64,
    protocol: Option<String>,
    #[serde(default)]
    messages: Vec<CaptureMessage>,
}

#[derive(Debug, Deserialize)]
struct CaptureMessage {
    direction: Option<String>,
    summary: String,
    #[serde(default)]
    body: String,
    wire_base64: Option<String>,
    #[serde(default)]
    truncated: bool,
    #[serde(default = "public_sensitivity")]
    sensitivity: String,
}

fn public_sensitivity() -> String {
    "public".to_string()
}

/// Reads a bounded JSON or JSONL capture and constructs one replay plan.
pub fn load_plan(path: &Path, selection: ReplaySelection) -> Result<ReplayPlan, ReplayError> {
    let metadata = fs::metadata(path).map_err(|error| {
        ReplayError::new(format!("cannot read capture {}: {error}", path.display()))
    })?;
    if metadata.len() > MAX_CAPTURE_BYTES {
        return Err(ReplayError::new(format!(
            "capture exceeds the {} MiB replay input limit",
            MAX_CAPTURE_BYTES / 1024 / 1024
        )));
    }
    let contents = fs::read(path).map_err(|error| {
        ReplayError::new(format!("cannot read capture {}: {error}", path.display()))
    })?;
    parse_plan(&contents, selection)
}

/// Parses a bounded capture in memory, primarily for deterministic tests.
pub fn parse_plan(contents: &[u8], selection: ReplaySelection) -> Result<ReplayPlan, ReplayError> {
    if contents.len() as u64 > MAX_CAPTURE_BYTES {
        return Err(ReplayError::new("capture exceeds replay input limit"));
    }
    let flows = parse_flows(contents)?;
    let candidates = flows
        .iter()
        .filter(|flow| flow.protocol.as_deref() == Some("http1"))
        .collect::<Vec<_>>();
    let flow = match selection.flow_id {
        Some(flow_id) => candidates
            .into_iter()
            .find(|flow| flow.flow_id == flow_id)
            .ok_or_else(|| ReplayError::new(format!("HTTP flow {flow_id} was not found")))?,
        None if candidates.len() == 1 => candidates[0],
        None if candidates.is_empty() => {
            return Err(ReplayError::new("capture contains no HTTP/1 flows"))
        }
        None => {
            return Err(ReplayError::new(
                "capture contains multiple HTTP/1 flows; select one with --flow",
            ))
        }
    };
    plan_from_flow(flow, selection.request)
}

fn parse_flows(contents: &[u8]) -> Result<Vec<CaptureFlow>, ReplayError> {
    let text = std::str::from_utf8(contents)
        .map_err(|_| ReplayError::new("capture is not valid UTF-8 JSON"))?;
    let first = text.chars().find(|character| !character.is_whitespace());
    if first == Some('[') {
        return serde_json::from_str(text)
            .map_err(|error| ReplayError::new(format!("invalid capture JSON: {error}")));
    }
    if first == Some('{') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            if value.get("flows").is_some() {
                let document: CaptureDocument = serde_json::from_value(value)
                    .map_err(|error| ReplayError::new(format!("invalid snapshot JSON: {error}")))?;
                return Ok(document.flows);
            }
            let flow: CaptureFlow = serde_json::from_value(value)
                .map_err(|error| ReplayError::new(format!("invalid flow JSON: {error}")))?;
            return Ok(vec![flow]);
        }
    }

    let mut flows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let flow = serde_json::from_str(line).map_err(|error| {
            ReplayError::new(format!("invalid JSONL flow on line {}: {error}", index + 1))
        })?;
        flows.push(flow);
    }
    if flows.is_empty() {
        return Err(ReplayError::new("capture is empty"));
    }
    Ok(flows)
}

fn plan_from_flow(flow: &CaptureFlow, request_index: usize) -> Result<ReplayPlan, ReplayError> {
    if request_index == 0 {
        return Err(ReplayError::new("request index must be at least 1"));
    }
    let requests = flow
        .messages
        .iter()
        .filter(|message| message.direction.as_deref() == Some("client_to_server"))
        .collect::<Vec<_>>();
    let request = requests.get(request_index - 1).ok_or_else(|| {
        ReplayError::new(format!(
            "HTTP flow {} has {} request(s); request {} does not exist",
            flow.flow_id,
            requests.len(),
            request_index
        ))
    })?;
    let (method, path_and_query) = parse_request_line(&request.summary)?;
    let (wire, legacy_text_encoding) = decode_wire(request)?;
    let (headers, body) = parse_wire(&wire)?;
    if body.len() > MAX_REPLAY_BODY_BYTES {
        return Err(ReplayError::new(format!(
            "captured request body exceeds the {} MiB replay limit",
            MAX_REPLAY_BODY_BYTES / 1024 / 1024
        )));
    }
    let headers = replay_headers(headers)?;
    let redacted = request.sensitivity == "redacted"
        || request.summary.contains(REDACTED)
        || wire
            .windows(REDACTED.len())
            .any(|value| value == REDACTED.as_bytes());
    let captured_response = terminal_responses(flow)
        .get(request_index - 1)
        .map(|message| captured_response(message))
        .transpose()?;

    Ok(ReplayPlan {
        flow_id: flow.flow_id,
        request: request_index,
        method,
        path_and_query,
        headers,
        body,
        truncated: request.truncated,
        sensitivity: request.sensitivity.clone(),
        redacted,
        legacy_text_encoding,
        captured_response,
    })
}

fn terminal_responses(flow: &CaptureFlow) -> Vec<&CaptureMessage> {
    flow.messages
        .iter()
        .filter(|message| message.direction.as_deref() == Some("server_to_client"))
        .filter(|message| {
            status_from_line(&message.summary).is_some_and(|status| status >= 200 || status == 101)
        })
        .collect()
}

fn captured_response(message: &CaptureMessage) -> Result<CapturedResponse, ReplayError> {
    let status = status_from_line(&message.summary)
        .ok_or_else(|| ReplayError::new("captured response has an invalid status line"))?;
    let (wire, legacy_text_encoding) = decode_wire(message)?;
    let (_, body) = parse_wire(&wire)?;
    Ok(CapturedResponse {
        status,
        body,
        truncated: message.truncated,
        redacted: message.sensitivity == "redacted" || wire_contains_redaction(&wire),
        legacy_text_encoding,
    })
}

fn decode_wire(message: &CaptureMessage) -> Result<(Vec<u8>, bool), ReplayError> {
    match &message.wire_base64 {
        Some(value) => BASE64
            .decode(value)
            .map(|bytes| (bytes, false))
            .map_err(|error| ReplayError::new(format!("invalid wire_base64: {error}"))),
        None => Ok((message.body.as_bytes().to_vec(), true)),
    }
}

fn parse_request_line(summary: &str) -> Result<(String, String), ReplayError> {
    let mut parts = summary.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || target.is_empty()
        || !version.starts_with("HTTP/1.")
        || parts.next().is_some()
    {
        return Err(ReplayError::new("captured request line is invalid"));
    }
    method
        .parse::<Method>()
        .map_err(|_| ReplayError::new("captured HTTP method is invalid"))?;
    let path_and_query = if target.starts_with('/') {
        target.to_string()
    } else {
        let uri = target
            .parse::<Uri>()
            .map_err(|_| ReplayError::new("captured request target is invalid"))?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
            return Err(ReplayError::new(
                "captured request is not an origin-form or absolute-form HTTP request",
            ));
        }
        uri.path_and_query()
            .map(|value| value.as_str().to_string())
            .ok_or_else(|| ReplayError::new("captured request has no path"))?
    };
    if !path_and_query.starts_with('/') {
        return Err(ReplayError::new(
            "captured request is not an origin-form or absolute-form HTTP request",
        ));
    }
    Ok((method.to_string(), path_and_query))
}

fn parse_wire(wire: &[u8]) -> Result<(HeaderList, Vec<u8>), ReplayError> {
    let boundary = find_bytes(wire, b"\r\n\r\n")
        .ok_or_else(|| ReplayError::new("captured message has no header/body boundary"))?;
    let head = std::str::from_utf8(&wire[..boundary])
        .map_err(|_| ReplayError::new("captured headers are not valid UTF-8"))?;
    let mut headers = Vec::new();
    if !head.is_empty() {
        for line in head.split("\r\n") {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| ReplayError::new("captured header line is invalid"))?;
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok((headers, wire[boundary + 4..].to_vec()))
}

fn replay_headers(headers: Vec<(String, String)>) -> Result<Vec<(String, String)>, ReplayError> {
    let connection_tokens = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut replayable = Vec::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if is_hop_by_hop(&lower)
            || connection_tokens.iter().any(|token| token == &lower)
            || lower.starts_with("lens-")
        {
            continue;
        }
        name.parse::<HeaderName>()
            .map_err(|_| ReplayError::new(format!("invalid captured header name: {name}")))?;
        HeaderValue::from_str(&value)
            .map_err(|_| ReplayError::new(format!("invalid captured value for header {name}")))?;
        replayable.push((name, value));
    }
    Ok(replayable)
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "content-length"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn parse_target_origin(target: &str) -> Result<Uri, ReplayError> {
    let uri = target
        .parse::<Uri>()
        .map_err(|_| ReplayError::new("target must be an HTTP(S) origin URL"))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
        return Err(ReplayError::new("target must be an HTTP(S) origin URL"));
    }
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(ReplayError::new("target must not contain user information"));
    }
    if uri
        .path_and_query()
        .is_some_and(|value| value.as_str() != "/")
    {
        return Err(ReplayError::new(
            "target must be an origin without a path or query",
        ));
    }
    Ok(uri)
}

fn is_loopback_target(uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn is_preview_safe_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

fn status_from_line(summary: &str) -> Option<u16> {
    let mut parts = summary.split_whitespace();
    let version = parts.next()?;
    let status = parts.next()?.parse().ok()?;
    version.starts_with("HTTP/1.").then_some(status)
}

fn wire_contains_redaction(wire: &[u8]) -> bool {
    wire.windows(REDACTED.len())
        .any(|value| value == REDACTED.as_bytes())
}

fn find_bytes(buffer: &[u8], needle: &[u8]) -> Option<usize> {
    buffer
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Executes one validated request without following redirects.
pub fn execute(
    plan: &ReplayPlan,
    target: &str,
    policy: ReplayPolicy,
) -> Result<ReplayReport, ReplayError> {
    let target_url = plan.validate_execution(target, policy)?;
    let agent = ureq::AgentBuilder::new()
        .timeout(policy.timeout)
        .redirects(0)
        .build();
    let mut request = agent.request(&plan.method, &target_url);
    for (name, value) in &plan.headers {
        request = request.set(name, value);
    }
    let started = Instant::now();
    let result = if plan.body.is_empty() {
        request.call()
    } else {
        request.send_bytes(&plan.body)
    };
    let response = match result {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(_) => {
            return Err(ReplayError::new(
                "request failed before receiving an HTTP response",
            ))
        }
    };
    let elapsed_ms = started.elapsed().as_millis();
    let status = response.status();
    let mut limited = response
        .into_reader()
        .take((MAX_RESPONSE_BODY_BYTES + 1) as u64);
    let mut body = Vec::new();
    limited
        .read_to_end(&mut body)
        .map_err(|error| ReplayError::new(format!("failed to read response: {error}")))?;
    let response_truncated = body.len() > MAX_RESPONSE_BODY_BYTES;
    body.truncate(MAX_RESPONSE_BODY_BYTES);

    let captured_status = plan.captured_status();
    let status_match = match captured_status {
        Some(expected) if expected == status => MatchState::Match,
        Some(_) => MatchState::Different,
        None => MatchState::Unavailable("capture has no terminal response"),
    };
    let body_match = compare_body(plan.captured_response.as_ref(), &body, response_truncated);
    Ok(ReplayReport {
        target_url,
        status,
        elapsed_ms,
        captured_status,
        status_match,
        body_match,
        response_truncated,
    })
}

fn compare_body(
    captured: Option<&CapturedResponse>,
    replayed: &[u8],
    replayed_truncated: bool,
) -> MatchState {
    let Some(captured) = captured else {
        return MatchState::Unavailable("capture has no terminal response");
    };
    if captured.truncated || replayed_truncated {
        return MatchState::Unavailable("a response body is truncated");
    }
    if captured.redacted {
        return MatchState::Unavailable("captured response is redacted");
    }
    if captured.legacy_text_encoding {
        return MatchState::Unavailable("capture uses legacy text encoding");
    }
    if captured.body == replayed {
        MatchState::Match
    } else {
        MatchState::Different
    }
}

/// User-facing replay failure with no secret-bearing debug payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayError {
    message: String,
}

impl ReplayError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ReplayError {}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    fn encoded(value: &[u8]) -> String {
        BASE64.encode(value)
    }

    fn capture(method: &str, request_wire: &[u8], sensitivity: &str) -> String {
        format!(
            r#"{{"flow_id":7,"protocol":"http1","messages":[{{"direction":"client_to_server","summary":"{method} /items?token=[REDACTED] HTTP/1.1","body":"","wire_base64":"{}","truncated":false,"sensitivity":"{sensitivity}"}},{{"direction":"server_to_client","summary":"HTTP/1.1 200 OK","body":"","wire_base64":"{}","truncated":false,"sensitivity":"public"}}]}}"#,
            encoded(request_wire),
            encoded(b"Content-Length: 2\r\n\r\nok")
        )
    }

    #[test]
    fn parses_jsonl_and_strips_hop_by_hop_headers() {
        let input = capture(
            "GET",
            b"Host: old.example\r\nConnection: X-Remove\r\nX-Remove: yes\r\nX-Keep: ok\r\n\r\n",
            "redacted",
        );
        let plan = parse_plan(input.as_bytes(), ReplaySelection::new(None, 1).unwrap()).unwrap();

        assert_eq!(plan.flow_id, 7);
        assert_eq!(plan.header_names(), vec!["X-Keep"]);
        assert!(plan.redacted);
        assert!(!plan.legacy_text_encoding);
        assert_eq!(plan.captured_status(), Some(200));
    }

    #[test]
    fn execution_requires_specific_acknowledgements() {
        let input = capture(
            "POST",
            b"Authorization: [REDACTED]\r\nContent-Length: 2\r\n\r\n{}",
            "secret",
        );
        let plan = parse_plan(input.as_bytes(), ReplaySelection::new(Some(7), 1).unwrap()).unwrap();
        let preview = plan.preview_target_url("https://staging.example").unwrap();
        assert_eq!(preview, "https://staging.example/[secret path omitted]");
        assert!(!preview.contains("token"));

        let error = plan
            .validate_execution("https://staging.example", ReplayPolicy::default())
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "remote replay target requires --allow-remote"
        );

        let mut policy = ReplayPolicy {
            allow_remote: true,
            ..ReplayPolicy::default()
        };
        assert!(plan
            .validate_execution("https://staging.example", policy)
            .unwrap_err()
            .to_string()
            .contains("--allow-secrets"));
        policy.allow_secrets = true;
        assert!(plan
            .validate_execution("https://staging.example", policy)
            .unwrap_err()
            .to_string()
            .contains("--allow-redacted"));
        policy.allow_redacted = true;
        assert!(plan
            .validate_execution("https://staging.example", policy)
            .unwrap_err()
            .to_string()
            .contains("--allow-unsafe"));
        policy.allow_unsafe = true;
        assert!(plan
            .validate_execution("https://staging.example", policy)
            .is_ok());
    }

    #[test]
    fn legacy_and_truncated_captures_are_preview_only() {
        let legacy = br#"{"flow_id":1,"protocol":"http1","messages":[{"direction":"client_to_server","summary":"GET / HTTP/1.1","body":"Host: x\r\n\r\n","truncated":false,"sensitivity":"public"}]}"#;
        let plan = parse_plan(legacy, ReplaySelection::new(None, 1).unwrap()).unwrap();
        assert!(plan.legacy_text_encoding);
        assert!(plan
            .validate_execution("http://127.0.0.1:8000", ReplayPolicy::default())
            .unwrap_err()
            .to_string()
            .contains("legacy"));

        let input = capture("GET", b"\r\n\r\npartial", "public")
            .replace("\"truncated\":false", "\"truncated\":true");
        let plan = parse_plan(input.as_bytes(), ReplaySelection::new(None, 1).unwrap()).unwrap();
        assert!(plan
            .validate_execution("http://127.0.0.1:8000", ReplayPolicy::default())
            .unwrap_err()
            .to_string()
            .contains("truncated"));
    }

    #[test]
    fn executes_against_loopback_and_compares_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            while !request.windows(4).any(|value| value == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("GET /items?token=[REDACTED] HTTP/1.1"));
            assert!(request.contains("X-Test: yes"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        let input = capture("GET", b"X-Test: yes\r\n\r\n", "redacted");
        let plan = parse_plan(input.as_bytes(), ReplaySelection::new(None, 1).unwrap()).unwrap();
        let report = execute(
            &plan,
            &format!("http://{address}"),
            ReplayPolicy {
                allow_redacted: true,
                ..ReplayPolicy::default()
            },
        )
        .unwrap();

        server.join().unwrap();
        assert_eq!(report.status, 200);
        assert_eq!(report.status_match, MatchState::Match);
        assert_eq!(report.body_match, MatchState::Match);
    }

    #[test]
    fn multiple_http_flows_require_an_explicit_flow() {
        let one = capture("GET", b"\r\n", "public");
        let two = one.replace("\"flow_id\":7", "\"flow_id\":8");
        let input = format!("{one}\n{two}");
        let error =
            parse_plan(input.as_bytes(), ReplaySelection::new(None, 1).unwrap()).unwrap_err();
        assert!(error.to_string().contains("--flow"));
    }

    #[test]
    fn connect_and_asterisk_targets_are_not_replayable_requests() {
        for summary in ["CONNECT api.example:443 HTTP/1.1", "OPTIONS * HTTP/1.1"] {
            let input = capture("GET", b"\r\n", "public")
                .replace("GET /items?token=[REDACTED] HTTP/1.1", summary);
            let error =
                parse_plan(input.as_bytes(), ReplaySelection::new(None, 1).unwrap()).unwrap_err();
            assert!(error.to_string().contains("origin-form or absolute-form"));
        }
    }
}
