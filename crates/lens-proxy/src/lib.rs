//! Explicit HTTP and fixed-target proxy runtime.
//!
//! Forwarding is the data plane. Observations use non-blocking `try_send`, so
//! decoding, storage, or UI stalls can drop diagnostic detail but cannot stall
//! application traffic.

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http::uri::Authority;
use http::Uri;
use lens_core::{
    Clock, CoreError, Direction, Endpoint, FlowId, ObservationEvent, ObservationKind, SystemClock,
};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;

const MAX_HTTP_HEAD_BYTES: usize = 64 * 1024;

/// How the proxy expects traffic to arrive.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProxyMode {
    /// Application points at Lens (HTTP_PROXY / connection string).
    Explicit,
    /// OS-level redirection, reserved for a later platform milestone.
    Transparent,
}

impl fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Explicit => "explicit",
            Self::Transparent => "transparent",
        })
    }
}

/// Validated listener configuration for the explicit proxy path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerConfig {
    /// Bind address.
    pub addr: SocketAddr,
    /// Traffic arrival mode.
    pub mode: ProxyMode,
}

impl ListenerConfig {
    /// Parses and validates a listen address string.
    pub fn parse(listen: &str, mode: ProxyMode) -> Result<Self, CoreError> {
        let addr = listen.parse::<SocketAddr>().map_err(|_| {
            CoreError::invalid_argument("listen", listen, "addr:port, for example 127.0.0.1:8888")
        })?;
        Self::new(addr, mode)
    }

    /// Validates a socket address for proxy binding.
    pub const fn new(addr: SocketAddr, mode: ProxyMode) -> Result<Self, CoreError> {
        Ok(Self { addr, mode })
    }

    /// Returns true for the portable userspace path.
    #[must_use]
    pub const fn is_explicit(&self) -> bool {
        matches!(self.mode, ProxyMode::Explicit)
    }
}

/// Bound TCP listener for the explicit proxy path.
#[derive(Debug)]
pub struct ProxyListener {
    listener: TcpListener,
    config: ListenerConfig,
}

impl ProxyListener {
    /// Binds a TCP listener for explicit proxy traffic.
    pub fn bind(config: ListenerConfig) -> Result<Self, CoreError> {
        if !config.is_explicit() {
            return Err(CoreError::operation_failed(
                "bind",
                "transparent mode is not implemented; use --mode explicit",
            ));
        }
        let listener = TcpListener::bind(config.addr).map_err(|error| {
            CoreError::operation_failed("bind", format!("{} ({})", config.addr, error))
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|error| CoreError::operation_failed("local_addr", error.to_string()))?;
        Ok(Self {
            listener,
            config: ListenerConfig {
                addr: local_addr,
                mode: config.mode,
            },
        })
    }

    /// Returns the bound local address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.config.addr
    }

    /// Returns the active listener configuration.
    #[must_use]
    pub const fn config(&self) -> &ListenerConfig {
        &self.config
    }

    /// Returns a reference to the underlying TCP listener.
    #[must_use]
    pub const fn tcp(&self) -> &TcpListener {
        &self.listener
    }

    /// Consumes the wrapper and returns the raw listener.
    #[must_use]
    pub fn into_tcp(self) -> TcpListener {
        self.listener
    }

    /// Attempts a single blocking accept.
    pub fn accept(&self) -> io::Result<(std::net::TcpStream, SocketAddr)> {
        self.listener.accept()
    }
}

/// How an accepted connection chooses its upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyTarget {
    /// Every connection uses one configured TCP endpoint.
    Fixed(Endpoint),
    /// The first HTTP absolute-form request or CONNECT line selects the target.
    Http,
}

/// Runtime settings for a forwarding session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyRuntimeConfig {
    /// Target selection behavior.
    pub target: ProxyTarget,
    /// Maximum time allowed to establish an upstream connection.
    pub connect_timeout: Duration,
    /// Time allowed for active connection tasks to finish after shutdown.
    pub shutdown_grace: Duration,
}

impl ProxyRuntimeConfig {
    /// Creates fixed-target settings, retained for TCP and future Postgres use.
    #[must_use]
    pub fn new(upstream: SocketAddr) -> Self {
        Self::fixed(Endpoint::new(upstream.ip().to_string(), upstream.port()))
    }

    /// Creates fixed-target settings for a hostname or IP endpoint.
    #[must_use]
    pub fn fixed(upstream: Endpoint) -> Self {
        Self {
            target: ProxyTarget::Fixed(upstream),
            connect_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(5),
        }
    }

    /// Creates explicit HTTP proxy settings.
    #[must_use]
    pub const fn http() -> Self {
        Self {
            target: ProxyTarget::Http,
            connect_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// Non-blocking sender used by the proxy data plane.
#[derive(Clone, Debug)]
pub struct ObservationSink {
    sender: mpsc::Sender<ObservationEvent>,
    dropped: Arc<AtomicU64>,
}

impl ObservationSink {
    /// Creates a bounded observation channel.
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<ObservationEvent>) {
        assert!(capacity > 0, "observation capacity must be positive");
        let (sender, receiver) = mpsc::channel(capacity);
        (
            Self {
                sender,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            receiver,
        )
    }

    fn emit(&self, event: ObservationEvent) {
        if self.sender.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns the number of events dropped because the channel was unavailable.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Final counters returned when a proxy session shuts down.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyStats {
    /// Connections accepted from clients.
    pub accepted: u64,
    /// Connections that completed forwarding successfully.
    pub completed: u64,
    /// Connections that failed to route, connect, or forward.
    pub failed: u64,
    /// Bytes copied from clients to upstreams.
    pub client_to_upstream_bytes: u64,
    /// Bytes copied from upstreams back to clients.
    pub upstream_to_client_bytes: u64,
    /// Observation events dropped without blocking forwarding.
    pub observations_dropped: u64,
}

#[derive(Debug, Default)]
struct RuntimeCounters {
    accepted: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    client_to_upstream_bytes: AtomicU64,
    upstream_to_client_bytes: AtomicU64,
}

impl RuntimeCounters {
    fn snapshot(&self, observations_dropped: u64) -> ProxyStats {
        ProxyStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            client_to_upstream_bytes: self.client_to_upstream_bytes.load(Ordering::Relaxed),
            upstream_to_client_bytes: self.upstream_to_client_bytes.load(Ordering::Relaxed),
            observations_dropped,
        }
    }
}

/// Asynchronous explicit proxy server.
#[derive(Debug)]
pub struct ProxyServer {
    listener: tokio::net::TcpListener,
    local_addr: SocketAddr,
    config: ProxyRuntimeConfig,
    observer: Option<ObservationSink>,
    clock: SystemClock,
}

impl ProxyServer {
    /// Converts a bound listener into an async proxy server.
    pub fn from_listener(
        listener: ProxyListener,
        config: ProxyRuntimeConfig,
    ) -> Result<Self, CoreError> {
        let local_addr = listener.local_addr();
        let listener = listener.into_tcp();
        listener
            .set_nonblocking(true)
            .map_err(|error| CoreError::operation_failed("set_nonblocking", error.to_string()))?;
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|error| CoreError::operation_failed("async_listener", error.to_string()))?;
        Ok(Self {
            listener,
            local_addr,
            config,
            observer: None,
            clock: SystemClock::new(),
        })
    }

    /// Attaches a non-blocking observation sink.
    #[must_use]
    pub fn with_observer(mut self, observer: ObservationSink) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Returns the bound local address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accepts and forwards connections until the shutdown sender fires or drops.
    pub async fn run_until(
        self,
        mut shutdown: oneshot::Receiver<()>,
    ) -> Result<ProxyStats, CoreError> {
        let counters = Arc::new(RuntimeCounters::default());
        let mut connections = JoinSet::new();
        tracing::info!(listen = %self.local_addr, target = ?self.config.target, "proxy runtime started");

        loop {
            match shutdown.try_recv() {
                Ok(()) | Err(oneshot::error::TryRecvError::Closed) => break,
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            while let Some(result) = connections.try_join_next() {
                if let Err(error) = result {
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(error = %error, "connection task terminated unexpectedly");
                }
            }
            match timeout(Duration::from_millis(50), self.listener.accept()).await {
                Ok(accepted) => {
                    let (client, peer) = accepted.map_err(|error| {
                        CoreError::operation_failed("accept", error.to_string())
                    })?;
                    let flow_id =
                        FlowId::new(counters.accepted.fetch_add(1, Ordering::Relaxed) + 1);
                    let config = self.config.clone();
                    let task_counters = Arc::clone(&counters);
                    let observer = self.observer.clone();
                    let clock = self.clock.clone();
                    connections.spawn(async move {
                        if let Err(error) = forward_connection(
                            client,
                            peer,
                            flow_id,
                            config,
                            observer.as_ref(),
                            &clock,
                            &task_counters,
                        ).await {
                            task_counters.failed.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(flow_id = %flow_id, peer = %peer, error = %error, "connection forwarding failed");
                        }
                    });
                }
                Err(_) => continue,
            }
        }

        tracing::info!(
            active_connections = connections.len(),
            "proxy shutdown requested"
        );
        let drained = timeout(self.config.shutdown_grace, async {
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(error = %error, "connection task terminated unexpectedly");
                }
            }
        })
        .await
        .is_ok();

        if !drained {
            let unfinished = connections.len() as u64;
            counters.failed.fetch_add(unfinished, Ordering::Relaxed);
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            tracing::warn!(
                unfinished,
                "connection tasks exceeded shutdown grace period"
            );
        }

        let observations_dropped = self.observer.as_ref().map_or(0, ObservationSink::dropped);
        let stats = counters.snapshot(observations_dropped);
        tracing::info!(
            accepted = stats.accepted,
            completed = stats.completed,
            failed = stats.failed,
            observations_dropped,
            "proxy runtime stopped"
        );
        Ok(stats)
    }
}

#[derive(Debug)]
enum RouteBehavior {
    Fixed,
    Forward(Vec<u8>),
    Connect(Vec<u8>),
}

#[derive(Debug)]
struct Route {
    upstream: Endpoint,
    protocol: &'static str,
    behavior: RouteBehavior,
}

async fn forward_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    flow_id: FlowId,
    config: ProxyRuntimeConfig,
    observer: Option<&ObservationSink>,
    clock: &SystemClock,
    counters: &RuntimeCounters,
) -> Result<(), CoreError> {
    let route = match &config.target {
        ProxyTarget::Fixed(upstream) => Route {
            upstream: upstream.clone(),
            protocol: "tcp",
            behavior: RouteBehavior::Fixed,
        },
        ProxyTarget::Http => match read_http_route(&mut client).await {
            Ok(route) => route,
            Err(error) => {
                let _ = write_http_error(&mut client, 400, "Bad Request").await;
                return Err(error);
            }
        },
    };

    emit(
        observer,
        ObservationEvent::new(
            flow_id,
            clock.now(),
            ObservationKind::Opened {
                client: Endpoint::new(peer.ip().to_string(), peer.port()),
                upstream: route.upstream.clone(),
                protocol: Some(route.protocol.to_string()),
            },
        ),
    );
    tracing::info!(flow_id = %flow_id, peer = %peer, upstream = %route.upstream, protocol = route.protocol, "flow opened");

    let mut upstream = match timeout(
        config.connect_timeout,
        TcpStream::connect((route.upstream.host.as_str(), route.upstream.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            let reason = format!("connect {} ({error})", route.upstream);
            emit_failed(observer, flow_id, clock, &reason);
            if !matches!(route.behavior, RouteBehavior::Fixed) {
                let _ = write_http_error(&mut client, 502, "Bad Gateway").await;
            }
            return Err(CoreError::operation_failed("connect", reason));
        }
        Err(_) => {
            let reason = format!("connect {} timed out", route.upstream);
            emit_failed(observer, flow_id, clock, &reason);
            if !matches!(route.behavior, RouteBehavior::Fixed) {
                let _ = write_http_error(&mut client, 504, "Gateway Timeout").await;
            }
            return Err(CoreError::operation_failed("connect", reason));
        }
    };

    let initial_client_bytes = match route.behavior {
        RouteBehavior::Fixed => 0,
        RouteBehavior::Forward(request) => {
            let bytes = request.len() as u64;
            upstream.write_all(&request).await.map_err(|error| {
                CoreError::operation_failed("forward request", error.to_string())
            })?;
            bytes
        }
        RouteBehavior::Connect(prefetched) => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .map_err(|error| {
                    CoreError::operation_failed("CONNECT response", error.to_string())
                })?;
            upstream.write_all(&prefetched).await.map_err(|error| {
                CoreError::operation_failed("forward CONNECT preface", error.to_string())
            })?;
            prefetched.len() as u64
        }
    };

    let (client_to_upstream, upstream_to_client) =
        match copy_bidirectional(&mut client, &mut upstream).await {
            Ok(counts) => counts,
            Err(error) => {
                let reason = format!("forward ({error})");
                emit_failed(observer, flow_id, clock, &reason);
                return Err(CoreError::operation_failed("forward", error.to_string()));
            }
        };
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
    let client_to_upstream = client_to_upstream.saturating_add(initial_client_bytes);
    counters
        .client_to_upstream_bytes
        .fetch_add(client_to_upstream, Ordering::Relaxed);
    counters
        .upstream_to_client_bytes
        .fetch_add(upstream_to_client, Ordering::Relaxed);
    counters.completed.fetch_add(1, Ordering::Relaxed);
    emit(
        observer,
        ObservationEvent::new(
            flow_id,
            clock.now(),
            ObservationKind::Transferred {
                direction: Direction::ClientToServer,
                bytes: client_to_upstream,
            },
        ),
    );
    emit(
        observer,
        ObservationEvent::new(
            flow_id,
            clock.now(),
            ObservationKind::Transferred {
                direction: Direction::ServerToClient,
                bytes: upstream_to_client,
            },
        ),
    );
    emit(
        observer,
        ObservationEvent::new(flow_id, clock.now(), ObservationKind::Closed),
    );
    tracing::info!(flow_id = %flow_id, client_to_upstream, upstream_to_client, "flow closed");
    Ok(())
}

fn emit(observer: Option<&ObservationSink>, event: ObservationEvent) {
    if let Some(observer) = observer {
        observer.emit(event);
    }
}

fn emit_failed(
    observer: Option<&ObservationSink>,
    flow_id: FlowId,
    clock: &SystemClock,
    reason: &str,
) {
    emit(
        observer,
        ObservationEvent::new(
            flow_id,
            clock.now(),
            ObservationKind::Failed {
                reason: reason.to_string(),
            },
        ),
    );
}

async fn read_http_route(client: &mut TcpStream) -> Result<Route, CoreError> {
    let mut buffer = Vec::with_capacity(4096);
    let header_end = loop {
        if buffer.len() >= MAX_HTTP_HEAD_BYTES {
            return Err(CoreError::operation_failed(
                "HTTP routing",
                "request headers exceed 65536 bytes",
            ));
        }
        let mut chunk = [0_u8; 4096];
        let read = client
            .read(&mut chunk)
            .await
            .map_err(|error| CoreError::operation_failed("read HTTP request", error.to_string()))?;
        if read == 0 {
            return Err(CoreError::operation_failed(
                "HTTP routing",
                "client closed before request headers",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = find_header_end(&buffer) {
            break end;
        }
    };

    let head = std::str::from_utf8(&buffer[..header_end]).map_err(|_| {
        CoreError::operation_failed("HTTP routing", "request headers are not valid UTF-8")
    })?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || target.is_empty()
        || !version.starts_with("HTTP/1.")
        || parts.next().is_some()
    {
        return Err(CoreError::operation_failed(
            "HTTP routing",
            "invalid HTTP/1 request line",
        ));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let authority = target.parse::<Authority>().map_err(|_| {
            CoreError::operation_failed("HTTP routing", "invalid CONNECT authority")
        })?;
        return Ok(Route {
            upstream: endpoint_from_authority(&authority, 443),
            protocol: "http-connect",
            behavior: RouteBehavior::Connect(buffer[header_end + 4..].to_vec()),
        });
    }

    let uri = target
        .parse::<Uri>()
        .map_err(|_| CoreError::operation_failed("HTTP routing", "invalid absolute request URI"))?;
    if uri.scheme_str() != Some("http") {
        return Err(CoreError::operation_failed(
            "HTTP routing",
            "non-CONNECT proxy requests must use an http absolute URI",
        ));
    }
    let authority = uri.authority().ok_or_else(|| {
        CoreError::operation_failed("HTTP routing", "absolute request URI has no authority")
    })?;
    let path = uri.path_and_query().map_or("/", |value| value.as_str());
    let mut rewritten = format!("{method} {path} {version}\r\n").into_bytes();
    for line in lines {
        let name = line.split_once(':').map_or(line, |(name, _)| name).trim();
        if name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        rewritten.extend_from_slice(line.as_bytes());
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"\r\n");
    rewritten.extend_from_slice(&buffer[header_end + 4..]);

    Ok(Route {
        upstream: endpoint_from_authority(authority, 80),
        protocol: "http1",
        behavior: RouteBehavior::Forward(rewritten),
    })
}

fn endpoint_from_authority(authority: &Authority, default_port: u16) -> Endpoint {
    Endpoint::new(
        authority.host().trim_matches(['[', ']']),
        authority.port_u16().unwrap_or(default_port),
    )
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn write_http_error(client: &mut TcpStream, status: u16, reason: &str) -> io::Result<()> {
    let body = format!("{status} {reason}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    fn bind_server(config: ProxyRuntimeConfig) -> ProxyServer {
        let listener =
            ProxyListener::bind(ListenerConfig::parse("127.0.0.1:0", ProxyMode::Explicit).unwrap())
                .unwrap();
        ProxyServer::from_listener(listener, config).unwrap()
    }

    async fn run_server(
        server: ProxyServer,
    ) -> (
        SocketAddr,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<ProxyStats, CoreError>>,
    ) {
        let address = server.local_addr();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.run_until(shutdown_rx));
        (address, shutdown_tx, task)
    }

    async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0_u8; 256];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&chunk[..read]);
            if find_header_end(&bytes).is_some() {
                return bytes;
            }
        }
    }

    #[test]
    fn parse_rejects_invalid_listen_addresses() {
        let error = ListenerConfig::parse("not-an-addr", ProxyMode::Explicit).unwrap_err();
        assert_eq!(error.class(), lens_core::ErrorClass::User);
    }

    #[test]
    fn bind_rejects_transparent_mode() {
        let config = ListenerConfig::parse("127.0.0.1:0", ProxyMode::Transparent).unwrap();
        assert!(ProxyListener::bind(config)
            .unwrap_err()
            .to_string()
            .contains("transparent"));
    }

    #[tokio::test]
    async fn forwards_fixed_target_bytes_and_reports_stats() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
        });
        let (address, shutdown, task) =
            run_server(bind_server(ProxyRuntimeConfig::new(upstream_addr))).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        drop(client);
        upstream_task.await.unwrap();
        shutdown.send(()).unwrap();
        let stats = task.await.unwrap().unwrap();
        assert_eq!((stats.accepted, stats.completed, stats.failed), (1, 1, 0));
    }

    #[tokio::test]
    async fn routes_absolute_http_and_rewrites_origin_form() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let request = read_head(&mut stream).await;
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /health?full=1 HTTP/1.1\r\n"));
            assert!(!request.to_ascii_lowercase().contains("proxy-connection"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let (observer, receiver) = ObservationSink::channel(16);
        let server = bind_server(ProxyRuntimeConfig::http()).with_observer(observer);
        let (address, shutdown, task) = run_server(server).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        let request = format!(
            "GET http://{upstream_addr}/health?full=1 HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Connection: keep-alive\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 200 OK"));
        drop(client);
        upstream_task.await.unwrap();
        shutdown.send(()).unwrap();
        let stats = task.await.unwrap().unwrap();
        drop(receiver);
        assert_eq!((stats.accepted, stats.completed, stats.failed), (1, 1, 0));
        assert_eq!(stats.observations_dropped, 0);
    }

    #[tokio::test]
    async fn connect_establishes_a_bidirectional_tunnel() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let (address, shutdown, task) = run_server(bind_server(ProxyRuntimeConfig::http())).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_head(&mut client).await;
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 200"));
        client.write_all(b"ping").await.unwrap();
        let mut pong = [0_u8; 4];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        drop(client);
        upstream_task.await.unwrap();
        shutdown.send(()).unwrap();
        assert_eq!(task.await.unwrap().unwrap().completed, 1);
    }

    #[tokio::test]
    async fn malformed_http_request_receives_bad_request() {
        let (address, shutdown, task) = run_server(bind_server(ProxyRuntimeConfig::http())).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"definitely not HTTP\r\n\r\n")
            .await
            .unwrap();
        let response = read_head(&mut client).await;
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 400"));
        drop(client);
        shutdown.send(()).unwrap();
        assert_eq!(task.await.unwrap().unwrap().failed, 1);
    }

    #[test]
    fn observation_channel_drops_instead_of_blocking() {
        let (sink, _receiver) = ObservationSink::channel(1);
        let event = ObservationEvent::new(
            FlowId::new(1),
            lens_core::TimestampPair::new(1, 2),
            ObservationKind::Closed,
        );
        sink.emit(event.clone());
        sink.emit(event);
        assert_eq!(sink.dropped(), 1);
    }

    #[tokio::test]
    async fn shutdown_aborts_connections_after_the_grace_period() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (_stream, _) = upstream_listener.accept().await.unwrap();
            accepted_tx.send(()).unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut config = ProxyRuntimeConfig::new(upstream_addr);
        config.shutdown_grace = Duration::from_millis(20);
        let (address, shutdown, task) = run_server(bind_server(config)).await;
        let client = TcpStream::connect(address).await.unwrap();
        accepted_rx.await.unwrap();
        shutdown.send(()).unwrap();
        let stats = task.await.unwrap().unwrap();
        drop(client);
        upstream_task.abort();
        assert_eq!((stats.accepted, stats.completed, stats.failed), (1, 0, 1));
    }
}
