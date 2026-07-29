//! Explicit HTTP and fixed-target proxy runtime.
//!
//! Forwarding is the data plane. Observations use non-blocking `try_send`, so
//! decoding, storage, or UI stalls can drop diagnostic detail but cannot stall
//! application traffic.

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::uri::Authority;
use http::Uri;
use lens_core::{
    Clock, CoreError, Direction, Endpoint, FlowId, ObservationEvent, ObservationKind,
    ServiceIdentity, SystemClock,
};
use lens_tls::{platform_client_config, CertificateAuthority};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_HTTP_HEAD_BYTES: usize = 64 * 1024;

/// How the proxy expects traffic to arrive.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProxyMode {
    /// Application points at Lens (HTTP_PROXY / connection string).
    Explicit,
    /// OS-level redirection with a platform original-destination lookup.
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

/// Validated listener configuration for a proxy listener.
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
}

/// Bound TCP listener for explicit or platform-redirected traffic.
#[derive(Debug)]
pub struct ProxyListener {
    listener: TcpListener,
    config: ListenerConfig,
}

impl ProxyListener {
    /// Binds a TCP listener. Native filter activation is handled separately.
    pub fn bind(config: ListenerConfig) -> Result<Self, CoreError> {
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
    /// A platform callback recovers the destination captured before redirection.
    Transparent,
}

/// Protocol classification for fixed-target connections.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FixedProtocol {
    /// Opaque TCP forwarding without payload observations.
    Tcp,
    /// PostgreSQL forwarding with bounded protocol observations.
    Postgres,
    /// HTTP/1 forwarding with bounded protocol observations.
    Http1,
}

impl FixedProtocol {
    const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Postgres => "postgres",
            Self::Http1 => "http1",
        }
    }
}

/// How Lens handles HTTPS `CONNECT` tunnels.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum HttpsMode {
    /// Terminate TLS, verify the upstream, and observe decrypted HTTP/1.1.
    Intercept,
    /// Forward encrypted bytes without inspection, for pinned clients.
    Passthrough,
    /// Refuse HTTPS tunnels explicitly.
    Reject,
}

impl fmt::Display for HttpsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Intercept => "intercept",
            Self::Passthrough => "passthrough",
            Self::Reject => "reject",
        })
    }
}

/// Certificate authority and upstream verifier used for HTTPS interception.
#[derive(Clone)]
pub struct TlsInterception {
    authority: Arc<CertificateAuthority>,
    upstream: Arc<ClientConfig>,
}

impl fmt::Debug for TlsInterception {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsInterception")
            .field("authority", &self.authority)
            .field("upstream_verifier", &"platform-or-explicit-roots")
            .finish()
    }
}

impl TlsInterception {
    /// Uses normal platform trust for upstream HTTPS servers.
    pub fn with_platform_verifier(
        authority: Arc<CertificateAuthority>,
    ) -> Result<Self, lens_tls::TlsError> {
        Ok(Self {
            authority,
            upstream: platform_client_config()?,
        })
    }

    /// Uses an explicit upstream verifier, primarily for isolated integration tests.
    #[must_use]
    pub fn new(authority: Arc<CertificateAuthority>, upstream: Arc<ClientConfig>) -> Self {
        Self {
            authority,
            upstream,
        }
    }
}

/// Runtime settings for a forwarding session.
#[derive(Clone, Debug)]
pub struct ProxyRuntimeConfig {
    /// Target selection behavior.
    pub target: ProxyTarget,
    /// Protocol label and inspection policy for a fixed target.
    pub fixed_protocol: FixedProtocol,
    /// Maximum time allowed to establish an upstream connection.
    pub connect_timeout: Duration,
    /// Time allowed for active connection tasks to finish after shutdown.
    pub shutdown_grace: Duration,
    /// HTTPS CONNECT behavior.
    pub https_mode: HttpsMode,
    /// TLS authority and upstream verifier when interception is enabled.
    pub tls: Option<TlsInterception>,
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
            fixed_protocol: FixedProtocol::Tcp,
            connect_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(5),
            https_mode: HttpsMode::Passthrough,
            tls: None,
        }
    }

    /// Creates explicit HTTP proxy settings.
    #[must_use]
    pub const fn http() -> Self {
        Self {
            target: ProxyTarget::Http,
            fixed_protocol: FixedProtocol::Tcp,
            connect_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(5),
            https_mode: HttpsMode::Passthrough,
            tls: None,
        }
    }

    /// Creates explicit PostgreSQL forwarding settings for one upstream.
    #[must_use]
    pub fn postgres(upstream: Endpoint) -> Self {
        let mut config = Self::fixed(upstream);
        config.fixed_protocol = FixedProtocol::Postgres;
        config
    }

    /// Creates transparent routing settings for one inspected protocol family.
    #[must_use]
    pub const fn transparent(protocol: FixedProtocol) -> Self {
        Self {
            target: ProxyTarget::Transparent,
            fixed_protocol: protocol,
            connect_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(5),
            https_mode: HttpsMode::Passthrough,
            tls: None,
        }
    }

    /// Enables HTTPS interception with the supplied CA and upstream verifier.
    #[must_use]
    pub fn with_tls_interception(mut self, tls: TlsInterception) -> Self {
        self.https_mode = HttpsMode::Intercept;
        self.tls = Some(tls);
        self
    }

    /// Selects an explicit CONNECT mode. Interception still requires TLS state.
    #[must_use]
    pub fn with_https_mode(mut self, mode: HttpsMode) -> Self {
        self.https_mode = mode;
        self
    }
}

/// Non-blocking sender used by the proxy data plane.
#[derive(Clone, Debug)]
pub struct ObservationSink {
    sender: mpsc::Sender<ObservationEvent>,
    dropped: Arc<AtomicU64>,
}

/// Cloneable blocking identity callback invoked away from forwarding tasks.
#[derive(Clone)]
pub struct FlowIdentityLookup {
    resolver: Arc<dyn Fn(SocketAddr, SocketAddr) -> Option<ServiceIdentity> + Send + Sync>,
}

impl FlowIdentityLookup {
    /// Wraps a platform socket-owner resolver.
    #[must_use]
    pub fn new<F>(resolver: F) -> Self
    where
        F: Fn(SocketAddr, SocketAddr) -> Option<ServiceIdentity> + Send + Sync + 'static,
    {
        Self {
            resolver: Arc::new(resolver),
        }
    }

    fn resolve(&self, client: SocketAddr, listener: SocketAddr) -> Option<ServiceIdentity> {
        (self.resolver)(client, listener)
    }
}

impl fmt::Debug for FlowIdentityLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FlowIdentityLookup(platform callback)")
    }
}

/// Cloneable platform callback that recovers a redirected socket's destination.
#[derive(Clone)]
pub struct FlowTargetLookup {
    resolver: Arc<dyn Fn(&TcpStream) -> Result<Endpoint, CoreError> + Send + Sync>,
}

impl FlowTargetLookup {
    /// Wraps an OS-specific original-destination query.
    #[must_use]
    pub fn new<F>(resolver: F) -> Self
    where
        F: Fn(&TcpStream) -> Result<Endpoint, CoreError> + Send + Sync + 'static,
    {
        Self {
            resolver: Arc::new(resolver),
        }
    }

    fn resolve(&self, stream: &TcpStream) -> Result<Endpoint, CoreError> {
        (self.resolver)(stream)
    }
}

impl fmt::Debug for FlowTargetLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FlowTargetLookup(platform callback)")
    }
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

/// Asynchronous explicit or native-redirect proxy server.
#[derive(Debug)]
pub struct ProxyServer {
    listener: tokio::net::TcpListener,
    local_addr: SocketAddr,
    config: ProxyRuntimeConfig,
    observer: Option<ObservationSink>,
    identity_lookup: Option<FlowIdentityLookup>,
    target_lookup: Option<FlowTargetLookup>,
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
            identity_lookup: None,
            target_lookup: None,
            clock: SystemClock::new(),
        })
    }

    /// Attaches a non-blocking observation sink.
    #[must_use]
    pub fn with_observer(mut self, observer: ObservationSink) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Attaches best-effort client process identity enrichment.
    #[must_use]
    pub fn with_identity_lookup(mut self, lookup: FlowIdentityLookup) -> Self {
        self.identity_lookup = Some(lookup);
        self
    }

    /// Attaches the platform original-destination lookup for transparent mode.
    #[must_use]
    pub fn with_target_lookup(mut self, lookup: FlowTargetLookup) -> Self {
        self.target_lookup = Some(lookup);
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
                Ok(Ok((client, peer))) => {
                    let flow_id =
                        FlowId::new(counters.accepted.fetch_add(1, Ordering::Relaxed) + 1);
                    let config = self.config.clone();
                    let task_counters = Arc::clone(&counters);
                    let observer = self.observer.clone();
                    let identity_lookup = self.identity_lookup.clone();
                    let target_lookup = self.target_lookup.clone();
                    let clock = self.clock.clone();
                    let listener = self.local_addr;
                    connections.spawn(async move {
                        if let Err(error) = forward_connection(
                            client,
                            peer,
                            flow_id,
                            config,
                            observer.as_ref(),
                            IdentityContext {
                                lookup: identity_lookup,
                                listener,
                            },
                            target_lookup,
                            &clock,
                            &task_counters,
                        ).await {
                            task_counters.failed.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(flow_id = %flow_id, peer = %peer, error = %error, "connection forwarding failed");
                        }
                    });
                }
                Ok(Err(error)) => {
                    // A transient descriptor or network error must not terminate every
                    // healthy flow already owned by this process. Back off briefly so a
                    // persistent OS error also cannot create a busy loop.
                    tracing::warn!(error = %error, "connection accept failed; retrying");
                    tokio::time::sleep(Duration::from_millis(10)).await;
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
    identity: IdentityContext,
    target_lookup: Option<FlowTargetLookup>,
    clock: &SystemClock,
    counters: &RuntimeCounters,
) -> Result<(), CoreError> {
    let route = match &config.target {
        ProxyTarget::Fixed(upstream) => Route {
            upstream: upstream.clone(),
            protocol: config.fixed_protocol.label(),
            behavior: RouteBehavior::Fixed,
        },
        ProxyTarget::Http => match read_http_route(&mut client).await {
            Ok(route) => route,
            Err(error) => {
                let _ = write_http_error(&mut client, 400, "Bad Request").await;
                return Err(error);
            }
        },
        ProxyTarget::Transparent => Route {
            upstream: target_lookup
                .as_ref()
                .ok_or_else(|| {
                    CoreError::operation_failed(
                        "transparent route",
                        "platform original-destination lookup is unavailable",
                    )
                })?
                .resolve(&client)?,
            protocol: config.fixed_protocol.label(),
            behavior: RouteBehavior::Fixed,
        },
    };

    let is_connect = matches!(&route.behavior, RouteBehavior::Connect(_));
    let protocol = if is_connect && config.https_mode == HttpsMode::Intercept {
        "http1"
    } else {
        route.protocol
    };

    emit(
        observer,
        ObservationEvent::new(
            flow_id,
            clock.now(),
            ObservationKind::Opened {
                client: Endpoint::new(peer.ip().to_string(), peer.port()),
                upstream: route.upstream.clone(),
                protocol: Some(protocol.to_string()),
            },
        ),
    );
    if let (Some(lookup), Some(observer)) = (identity.lookup, observer.cloned()) {
        let listener = identity.listener;
        let identity_clock = clock.clone();
        tokio::spawn(async move {
            let resolved =
                tokio::task::spawn_blocking(move || lookup.resolve(peer, listener)).await;
            if let Ok(Some(identity)) = resolved {
                emit(
                    Some(&observer),
                    ObservationEvent::new(
                        flow_id,
                        identity_clock.now(),
                        ObservationKind::Identified { identity },
                    ),
                );
            }
        });
    }
    tracing::info!(flow_id = %flow_id, peer = %peer, upstream = %route.upstream, protocol, "flow opened");

    if is_connect && config.https_mode == HttpsMode::Reject {
        let reason = "HTTPS CONNECT rejected by configured policy";
        let _ = write_http_error(&mut client, 403, "HTTPS CONNECT Rejected").await;
        emit_failed(observer, flow_id, clock, reason);
        return Err(CoreError::operation_failed("CONNECT", reason));
    }
    if is_connect && config.https_mode == HttpsMode::Intercept && config.tls.is_none() {
        let reason = "HTTPS interception is enabled but CA state is unavailable";
        let _ = write_http_error(&mut client, 503, "HTTPS Interception Unavailable").await;
        emit_failed(observer, flow_id, clock, reason);
        return Err(CoreError::operation_failed("CONNECT", reason));
    }

    let upstream = match timeout(
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

    let upstream_endpoint = route.upstream.clone();
    let counts = match route.behavior {
        RouteBehavior::Fixed => {
            mirror_bidirectional(
                client,
                upstream,
                flow_id,
                observer.cloned(),
                clock.clone(),
                protocol != "tcp",
            )
            .await
        }
        RouteBehavior::Forward(request) => {
            let mut upstream = upstream;
            let bytes = request.len() as u64;
            if let Err(error) = upstream.write_all(&request).await {
                Err(CoreError::operation_failed(
                    "forward request",
                    error.to_string(),
                ))
            } else {
                emit(
                    observer,
                    ObservationEvent::new(
                        flow_id,
                        clock.now(),
                        ObservationKind::Data {
                            direction: Direction::ClientToServer,
                            bytes: request,
                        },
                    ),
                );
                mirror_bidirectional(
                    client,
                    upstream,
                    flow_id,
                    observer.cloned(),
                    clock.clone(),
                    true,
                )
                .await
                .map(|(client_to_upstream, upstream_to_client)| {
                    (client_to_upstream.saturating_add(bytes), upstream_to_client)
                })
            }
        }
        RouteBehavior::Connect(prefetched) => match config.https_mode {
            HttpsMode::Passthrough => {
                if let Err(error) = client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                {
                    Err(CoreError::operation_failed(
                        "CONNECT response",
                        error.to_string(),
                    ))
                } else {
                    let mut upstream = upstream;
                    let prefetched_bytes = prefetched.len() as u64;
                    if let Err(error) = upstream.write_all(&prefetched).await {
                        Err(CoreError::operation_failed(
                            "forward CONNECT preface",
                            error.to_string(),
                        ))
                    } else {
                        mirror_bidirectional(
                            client,
                            upstream,
                            flow_id,
                            observer.cloned(),
                            clock.clone(),
                            false,
                        )
                        .await
                        .map(|(client_to_upstream, upstream_to_client)| {
                            (
                                client_to_upstream.saturating_add(prefetched_bytes),
                                upstream_to_client,
                            )
                        })
                    }
                }
            }
            HttpsMode::Intercept => {
                intercept_connect(
                    client,
                    upstream,
                    prefetched,
                    InterceptContext {
                        endpoint: &upstream_endpoint,
                        tls: config.tls.as_ref().expect("TLS state checked above"),
                        handshake_timeout: config.connect_timeout,
                        flow_id,
                        observer: observer.cloned(),
                        clock: clock.clone(),
                    },
                )
                .await
            }
            HttpsMode::Reject => unreachable!("rejected before connecting upstream"),
        },
    };

    let (client_to_upstream, upstream_to_client) = match counts {
        Ok(counts) => counts,
        Err(error) => {
            emit_failed(observer, flow_id, clock, &error.to_string());
            return Err(error);
        }
    };
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

#[derive(Clone, Debug)]
struct IdentityContext {
    lookup: Option<FlowIdentityLookup>,
    listener: SocketAddr,
}

struct InterceptContext<'a> {
    endpoint: &'a Endpoint,
    tls: &'a TlsInterception,
    handshake_timeout: Duration,
    flow_id: FlowId,
    observer: Option<ObservationSink>,
    clock: SystemClock,
}

async fn intercept_connect(
    mut client: TcpStream,
    upstream: TcpStream,
    prefetched: Vec<u8>,
    context: InterceptContext<'_>,
) -> Result<(u64, u64), CoreError> {
    let InterceptContext {
        endpoint,
        tls,
        handshake_timeout,
        flow_id,
        observer,
        clock,
    } = context;
    let server_config = tls
        .authority
        .server_config(&endpoint.host)
        .map_err(|error| {
            CoreError::operation_failed("issue HTTPS certificate", error.to_string())
        })?;
    let server_name = ServerName::try_from(endpoint.host.clone()).map_err(|error| {
        CoreError::operation_failed("validate HTTPS upstream name", error.to_string())
    })?;
    let upstream_tls = match timeout(
        handshake_timeout,
        TlsConnector::from(Arc::clone(&tls.upstream)).connect(server_name, upstream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            let _ = write_http_error(&mut client, 502, "Upstream TLS Failed").await;
            return Err(CoreError::operation_failed(
                "verify upstream TLS",
                error.to_string(),
            ));
        }
        Err(_) => {
            let _ = write_http_error(&mut client, 504, "Upstream TLS Timeout").await;
            return Err(CoreError::operation_failed(
                "verify upstream TLS",
                "handshake timed out",
            ));
        }
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|error| CoreError::operation_failed("CONNECT response", error.to_string()))?;
    let client = PrefixedIo::new(client, prefetched);
    let client_tls = match timeout(
        handshake_timeout,
        TlsAcceptor::from(server_config).accept(client),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            return Err(CoreError::operation_failed(
                "accept client TLS",
                format!("{error}; the client may not trust Lens or may use certificate pinning"),
            ));
        }
        Err(_) => {
            return Err(CoreError::operation_failed(
                "accept client TLS",
                "handshake timed out; the client may use certificate pinning",
            ));
        }
    };

    mirror_bidirectional(client_tls, upstream_tls, flow_id, observer, clock, true).await
}

async fn mirror_bidirectional<C, U>(
    client: C,
    upstream: U,
    flow_id: FlowId,
    observer: Option<ObservationSink>,
    clock: SystemClock,
    inspect: bool,
) -> Result<(u64, u64), CoreError>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let mut pumps = JoinSet::new();
    pumps.spawn(pump(
        client_read,
        upstream_write,
        Direction::ClientToServer,
        flow_id,
        observer.clone(),
        clock.clone(),
        inspect,
    ));
    pumps.spawn(pump(
        upstream_read,
        client_write,
        Direction::ServerToClient,
        flow_id,
        observer,
        clock,
        inspect,
    ));

    let mut client_to_upstream = 0;
    let mut upstream_to_client = 0;
    while let Some(result) = pumps.join_next().await {
        let (direction, transferred) = result
            .map_err(|error| CoreError::operation_failed("forward task", error.to_string()))?;
        let transferred = match transferred {
            Ok(transferred) => transferred,
            Err(error) => {
                pumps.abort_all();
                while pumps.join_next().await.is_some() {}
                return Err(CoreError::operation_failed("forward", error.to_string()));
            }
        };
        match direction {
            Direction::ClientToServer => client_to_upstream = transferred,
            Direction::ServerToClient => upstream_to_client = transferred,
        }
    }
    Ok((client_to_upstream, upstream_to_client))
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    flow_id: FlowId,
    observer: Option<ObservationSink>,
    clock: SystemClock,
    inspect: bool,
) -> (Direction, io::Result<u64>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let result = async {
        let mut transferred = 0_u64;
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let read = match reader.read(&mut buffer).await {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => 0,
                Err(error) => return Err(error),
            };
            if read == 0 {
                // The peer may already have closed its write side after all bytes were
                // delivered. TLS peers also commonly close without a close_notify,
                // which rustls reports as UnexpectedEof. Half-close is best effort
                // and must not turn a successfully transferred flow into a failure.
                let _ = writer.shutdown().await;
                return Ok(transferred);
            }
            writer.write_all(&buffer[..read]).await?;
            transferred = transferred.saturating_add(read as u64);
            if inspect {
                emit(
                    observer.as_ref(),
                    ObservationEvent::new(
                        flow_id,
                        clock.now(),
                        ObservationKind::Data {
                            direction,
                            bytes: buffer[..read].to_vec(),
                        },
                    ),
                );
            }
        }
    }
    .await;
    (direction, result)
}

#[derive(Debug)]
struct PrefixedIo<S> {
    inner: S,
    prefix: Vec<u8>,
    offset: usize,
}

impl<S> PrefixedIo<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let available = &self.prefix[self.offset..];
            let copied = available.len().min(buffer.remaining());
            buffer.put_slice(&available[..copied]);
            self.offset += copied;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
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
    use std::path::Path;

    use lens_tls::CaPaths;
    use rcgen::generate_simple_self_signed;
    use tokio::sync::oneshot;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{RootCertStore, ServerConfig};

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

    async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
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

    fn test_tls_server(host: &str) -> (Arc<ServerConfig>, CertificateDer<'static>) {
        let generated = generate_simple_self_signed(vec![host.to_string()]).unwrap();
        let certificate = generated.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        (Arc::new(config), certificate)
    }

    fn test_tls_interception(
        directory: &Path,
        upstream_certificate: CertificateDer<'static>,
    ) -> (Arc<CertificateAuthority>, TlsInterception) {
        let authority = Arc::new(
            CertificateAuthority::load_or_create(CaPaths::from_directory(directory)).unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(upstream_certificate).unwrap();
        let mut upstream = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        upstream.alpn_protocols = vec![b"http/1.1".to_vec()];
        let interception = TlsInterception::new(Arc::clone(&authority), Arc::new(upstream));
        (authority, interception)
    }

    #[test]
    fn parse_rejects_invalid_listen_addresses() {
        let error = ListenerConfig::parse("not-an-addr", ProxyMode::Explicit).unwrap_err();
        assert_eq!(error.class(), lens_core::ErrorClass::User);
    }

    #[test]
    fn bind_accepts_transparent_mode_without_activating_platform_filters() {
        let config = ListenerConfig::parse("127.0.0.1:0", ProxyMode::Transparent).unwrap();
        let listener = ProxyListener::bind(config).unwrap();
        assert_eq!(listener.config().mode, ProxyMode::Transparent);
    }

    #[tokio::test]
    async fn transparent_lookup_routes_to_original_destination() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
        });
        let server = bind_server(ProxyRuntimeConfig::transparent(FixedProtocol::Tcp))
            .with_target_lookup(FlowTargetLookup::new(move |_| {
                Ok(Endpoint::new(
                    upstream_addr.ip().to_string(),
                    upstream_addr.port(),
                ))
            }));
        let (address, shutdown, task) = run_server(server).await;
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
    async fn process_identity_is_resolved_without_blocking_forwarding() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
        });
        let (observer, mut observations) = ObservationSink::channel(16);
        let lookup = FlowIdentityLookup::new(|client, listener| {
            assert!(client.port() > 0);
            assert!(listener.port() > 0);
            Some(
                ServiceIdentity::new()
                    .with_pid(731)
                    .with_process("fixture")
                    .with_service("checkout-api"),
            )
        });
        let server = bind_server(ProxyRuntimeConfig::new(upstream_addr))
            .with_observer(observer)
            .with_identity_lookup(lookup);
        let (address, shutdown, task) = run_server(server).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        let identity = timeout(Duration::from_secs(2), async {
            while let Some(event) = observations.recv().await {
                if let ObservationKind::Identified { identity } = event.kind {
                    return identity;
                }
            }
            panic!("observation channel closed before identity enrichment");
        })
        .await
        .unwrap();
        assert_eq!(identity.pid, Some(731));
        assert_eq!(identity.display_name(), "checkout-api");

        drop(client);
        upstream_task.await.unwrap();
        shutdown.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn postgres_fixed_target_is_labeled_and_observed() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
        });
        let config = ProxyRuntimeConfig::postgres(Endpoint::new(
            upstream_addr.ip().to_string(),
            upstream_addr.port(),
        ));
        let (observer, mut observations) = ObservationSink::channel(16);
        let server = bind_server(config).with_observer(observer);
        let (address, shutdown, task) = run_server(server).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        drop(client);
        upstream_task.await.unwrap();
        shutdown.send(()).unwrap();
        task.await.unwrap().unwrap();

        let mut protocol = None;
        let mut data_events = 0;
        while let Some(event) = observations.recv().await {
            match event.kind {
                ObservationKind::Opened {
                    protocol: observed, ..
                } => protocol = observed,
                ObservationKind::Data { .. } => data_events += 1,
                _ => {}
            }
        }
        assert_eq!(protocol.as_deref(), Some("postgres"));
        assert_eq!(data_events, 2);
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
        let (observer, mut receiver) = ObservationSink::channel(16);
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
        client.shutdown().await.unwrap();
        drop(client);
        upstream_task.await.unwrap();
        shutdown.send(()).unwrap();
        let stats = task.await.unwrap().unwrap();
        let mut request_observed = false;
        let mut response_observed = false;
        while let Some(event) = receiver.recv().await {
            if let ObservationKind::Data { direction, bytes } = event.kind {
                match direction {
                    Direction::ClientToServer => {
                        request_observed |= bytes.starts_with(b"GET /health?full=1 HTTP/1.1");
                    }
                    Direction::ServerToClient => {
                        response_observed |= bytes.starts_with(b"HTTP/1.1 200 OK");
                    }
                }
            }
        }
        assert_eq!((stats.accepted, stats.completed, stats.failed), (1, 1, 0));
        assert_eq!(stats.observations_dropped, 0);
        assert!(request_observed);
        assert!(response_observed);
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
    async fn rejected_https_mode_returns_a_clear_proxy_error() {
        let config = ProxyRuntimeConfig::http().with_https_mode(HttpsMode::Reject);
        let (address, shutdown, task) = run_server(bind_server(config)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
            .await
            .unwrap();
        let response = String::from_utf8(read_head(&mut client).await).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 HTTPS CONNECT Rejected"));
        drop(client);
        shutdown.send(()).unwrap();
        assert_eq!(task.await.unwrap().unwrap().failed, 1);
    }

    #[tokio::test]
    async fn https_interception_requires_explicit_client_trust() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let (upstream_config, upstream_certificate) = test_tls_server("127.0.0.1");
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(upstream_config)
                .accept(stream)
                .await
                .unwrap();
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte).await;
        });
        let temporary = tempfile::tempdir().unwrap();
        let (_authority, interception) =
            test_tls_interception(temporary.path(), upstream_certificate);
        let config = ProxyRuntimeConfig::http().with_tls_interception(interception);
        let (address, shutdown, task) = run_server(bind_server(config)).await;

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

        let roots = RootCertStore::empty();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
        let error = TlsConnector::from(Arc::new(client_config))
            .connect(server_name, client)
            .await
            .unwrap_err();
        assert!(error.to_string().to_ascii_lowercase().contains("issuer"));

        upstream_task.await.unwrap();
        shutdown.send(()).unwrap();
        let stats = task.await.unwrap().unwrap();
        assert_eq!((stats.accepted, stats.completed, stats.failed), (1, 0, 1));
    }

    #[tokio::test]
    async fn trusted_https_is_forwarded_and_observed_as_plain_http() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let (upstream_config, upstream_certificate) = test_tls_server("127.0.0.1");
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(upstream_config)
                .accept(stream)
                .await
                .unwrap();
            let request = String::from_utf8(read_head(&mut stream).await).unwrap();
            assert!(request.starts_with("GET /secure HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure",
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        let temporary = tempfile::tempdir().unwrap();
        let (authority, interception) =
            test_tls_interception(temporary.path(), upstream_certificate);
        let (observer, mut receiver) = ObservationSink::channel(32);
        let server = bind_server(ProxyRuntimeConfig::http().with_tls_interception(interception))
            .with_observer(observer);
        let (address, shutdown, task) = run_server(server).await;

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

        let mut roots = RootCertStore::empty();
        roots.add(authority.certificate_der()).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
        let mut client = TlsConnector::from(Arc::new(client_config))
            .connect(server_name, client)
            .await
            .unwrap();
        client
            .write_all(
                b"GET /secure HTTP/1.1\r\nHost: local.test\r\nAuthorization: Bearer secret\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 200 OK"));
        drop(client);

        upstream_task.await.unwrap();
        shutdown.send(()).unwrap();
        let stats = task.await.unwrap().unwrap();
        let mut opened_as_http = false;
        let mut client_data = Vec::new();
        let mut server_data = Vec::new();
        while let Some(event) = receiver.recv().await {
            match event.kind {
                ObservationKind::Opened { protocol, .. } => {
                    opened_as_http |= protocol.as_deref() == Some("http1");
                }
                ObservationKind::Data { direction, bytes } => match direction {
                    Direction::ClientToServer => client_data.extend(bytes),
                    Direction::ServerToClient => server_data.extend(bytes),
                },
                _ => {}
            }
        }
        assert_eq!((stats.accepted, stats.completed, stats.failed), (1, 1, 0));
        assert!(opened_as_http);
        assert!(client_data.starts_with(b"GET /secure HTTP/1.1"));
        assert!(server_data.starts_with(b"HTTP/1.1 200 OK"));
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

    #[tokio::test]
    async fn failed_flow_does_not_terminate_the_accept_loop() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let request = String::from_utf8(read_head(&mut stream).await).unwrap();
            assert!(request.starts_with("GET /healthy HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let (address, shutdown, task) = run_server(bind_server(ProxyRuntimeConfig::http())).await;
        let mut malformed = TcpStream::connect(address).await.unwrap();
        malformed.write_all(b"not HTTP\r\n\r\n").await.unwrap();
        assert!(String::from_utf8(read_head(&mut malformed).await)
            .unwrap()
            .starts_with("HTTP/1.1 400"));
        drop(malformed);

        let mut healthy = TcpStream::connect(address).await.unwrap();
        healthy
            .write_all(
                format!(
                    "GET http://{upstream_addr}/healthy HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        healthy.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"\r\n\r\nok"));
        healthy.shutdown().await.unwrap();
        drop(healthy);

        upstream_task.await.unwrap();
        shutdown.send(()).unwrap();
        let stats = task.await.unwrap().unwrap();
        assert_eq!((stats.accepted, stats.completed, stats.failed), (2, 1, 1));
    }

    #[tokio::test]
    async fn upstream_failure_does_not_terminate_the_accept_loop() {
        let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unavailable_addr = unavailable.local_addr().unwrap();
        drop(unavailable);

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let _ = read_head(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let (address, shutdown, task) = run_server(bind_server(ProxyRuntimeConfig::http())).await;
        let mut failed = TcpStream::connect(address).await.unwrap();
        failed
            .write_all(
                format!(
                    "GET http://{unavailable_addr}/ HTTP/1.1\r\nHost: {unavailable_addr}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(String::from_utf8(read_head(&mut failed).await)
            .unwrap()
            .starts_with("HTTP/1.1 502"));
        drop(failed);

        let mut healthy = TcpStream::connect(address).await.unwrap();
        healthy
            .write_all(
                format!(
                    "GET http://{upstream_addr}/ HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        healthy.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 204"));
        healthy.shutdown().await.unwrap();
        drop(healthy);

        upstream_task.await.unwrap();
        shutdown.send(()).unwrap();
        let stats = task.await.unwrap().unwrap();
        assert_eq!((stats.accepted, stats.completed, stats.failed), (2, 1, 1));
    }

    #[tokio::test]
    async fn bounded_observation_stays_off_the_data_plane_under_load() {
        const CONNECTIONS: usize = 32;
        const PAYLOAD_BYTES: usize = 32 * 1024;

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            for _ in 0..CONNECTIONS {
                let (mut stream, _) = upstream_listener.accept().await.unwrap();
                connections.spawn(async move {
                    let mut payload = Vec::new();
                    stream.read_to_end(&mut payload).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                    payload.len()
                });
            }
            let mut received = 0;
            while let Some(result) = connections.join_next().await {
                received += result.unwrap();
            }
            received
        });

        let (observer, _observations) = ObservationSink::channel(1);
        let server = bind_server(ProxyRuntimeConfig::new(upstream_addr)).with_observer(observer);
        let (address, shutdown, task) = run_server(server).await;
        let mut clients = JoinSet::new();
        for id in 0..CONNECTIONS {
            clients.spawn(async move {
                let payload = vec![id as u8; PAYLOAD_BYTES];
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut echoed = Vec::new();
                stream.read_to_end(&mut echoed).await.unwrap();
                assert_eq!(echoed, payload);
            });
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(result) = clients.join_next().await {
                result.unwrap();
            }
        })
        .await
        .expect("load test exceeded its deadline");

        assert_eq!(upstream_task.await.unwrap(), CONNECTIONS * PAYLOAD_BYTES);
        shutdown.send(()).unwrap();
        let stats = task.await.unwrap().unwrap();
        assert_eq!(stats.accepted, CONNECTIONS as u64);
        assert_eq!(stats.completed, CONNECTIONS as u64);
        assert_eq!(stats.failed, 0);
        assert!(stats.observations_dropped > 0);
        assert_eq!(
            stats.client_to_upstream_bytes,
            (CONNECTIONS * PAYLOAD_BYTES) as u64
        );
        assert_eq!(
            stats.upstream_to_client_bytes,
            (CONNECTIONS * PAYLOAD_BYTES) as u64
        );
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
