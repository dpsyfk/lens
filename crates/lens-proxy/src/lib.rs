//! Explicit proxy listener and asynchronous forwarding runtime.
//!
//! The runtime owns only the data plane: accepting connections, connecting to
//! an upstream, and pumping bytes in both directions. Observation and decoding
//! are intentionally kept out of this path so they cannot block forwarding.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lens_core::CoreError;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// How the proxy expects traffic to arrive.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProxyMode {
    /// Application points at Lens (HTTP_PROXY / connection string).
    Explicit,
    /// OS-level redirection (platform-specific; not used by the bind path yet).
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
    /// Proxy mode. Only explicit mode opens sockets in the v1 userspace path.
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

    /// Returns true when this config is the explicit userspace path.
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
    /// Binds a TCP listener for the explicit proxy path.
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

/// Runtime settings for a fixed-upstream forwarding session.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProxyRuntimeConfig {
    /// Address each accepted connection is forwarded to.
    pub upstream: SocketAddr,
    /// Maximum time allowed to establish the upstream connection.
    pub connect_timeout: Duration,
    /// Time allowed for active connection tasks to finish after shutdown.
    pub shutdown_grace: Duration,
}

impl ProxyRuntimeConfig {
    /// Creates runtime settings with conservative developer-tool defaults.
    #[must_use]
    pub const fn new(upstream: SocketAddr) -> Self {
        Self {
            upstream,
            connect_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// Final counters returned when a proxy session shuts down.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyStats {
    /// Connections accepted from clients.
    pub accepted: u64,
    /// Connections that completed bidirectional forwarding successfully.
    pub completed: u64,
    /// Connections that failed to connect or forward.
    pub failed: u64,
    /// Bytes copied from clients to the upstream.
    pub client_to_upstream_bytes: u64,
    /// Bytes copied from the upstream back to clients.
    pub upstream_to_client_bytes: u64,
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
    fn snapshot(&self) -> ProxyStats {
        ProxyStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            client_to_upstream_bytes: self.client_to_upstream_bytes.load(Ordering::Relaxed),
            upstream_to_client_bytes: self.upstream_to_client_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Asynchronous fixed-upstream proxy server.
#[derive(Debug)]
pub struct ProxyServer {
    listener: tokio::net::TcpListener,
    local_addr: SocketAddr,
    config: ProxyRuntimeConfig,
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
        })
    }

    /// Returns the bound local address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accepts and forwards connections until `shutdown` resolves.
    pub async fn run_until<F>(self, shutdown: F) -> Result<ProxyStats, CoreError>
    where
        F: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let counters = Arc::new(RuntimeCounters::default());
        let mut connections = JoinSet::new();

        tracing::info!(
            listen = %self.local_addr,
            upstream = %self.config.upstream,
            "proxy runtime started"
        );

        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        counters.failed.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(error = %error, "connection task terminated unexpectedly");
                    }
                }
                accepted = self.listener.accept() => {
                    let (client, peer) = accepted.map_err(|error| {
                        CoreError::operation_failed("accept", error.to_string())
                    })?;
                    counters.accepted.fetch_add(1, Ordering::Relaxed);
                    let config = self.config;
                    let task_counters = Arc::clone(&counters);
                    connections.spawn(async move {
                        if let Err(error) = forward_connection(client, peer, config, &task_counters).await {
                            task_counters.failed.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(peer = %peer, error = %error, "connection forwarding failed");
                        }
                    });
                }
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

        let stats = counters.snapshot();
        tracing::info!(
            accepted = stats.accepted,
            completed = stats.completed,
            failed = stats.failed,
            "proxy runtime stopped"
        );
        Ok(stats)
    }
}

async fn forward_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    config: ProxyRuntimeConfig,
    counters: &RuntimeCounters,
) -> Result<(), CoreError> {
    let mut upstream = timeout(config.connect_timeout, TcpStream::connect(config.upstream))
        .await
        .map_err(|_| {
            CoreError::operation_failed("connect", format!("{} timed out", config.upstream))
        })?
        .map_err(|error| {
            CoreError::operation_failed("connect", format!("{} ({error})", config.upstream))
        })?;

    tracing::debug!(peer = %peer, upstream = %config.upstream, "connection established");
    let (client_to_upstream, upstream_to_client) = copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(|error| CoreError::operation_failed("forward", error.to_string()))?;

    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
    counters
        .client_to_upstream_bytes
        .fetch_add(client_to_upstream, Ordering::Relaxed);
    counters
        .upstream_to_client_bytes
        .fetch_add(upstream_to_client, Ordering::Relaxed);
    counters.completed.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(
        peer = %peer,
        client_to_upstream,
        upstream_to_client,
        "connection completed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    #[test]
    fn parse_rejects_invalid_listen_addresses() {
        let err = ListenerConfig::parse("not-an-addr", ProxyMode::Explicit).unwrap_err();
        assert_eq!(err.class(), lens_core::ErrorClass::User);
        assert!(err.to_string().contains("listen"));
    }

    #[test]
    fn parse_accepts_loopback_with_port() {
        let config = ListenerConfig::parse("127.0.0.1:8888", ProxyMode::Explicit).unwrap();
        assert_eq!(config.addr, "127.0.0.1:8888".parse().unwrap());
        assert!(config.is_explicit());
        assert_eq!(config.mode.to_string(), "explicit");
    }

    #[test]
    fn bind_explicit_listener_on_ephemeral_port() {
        let config = ListenerConfig::parse("127.0.0.1:0", ProxyMode::Explicit).unwrap();
        let listener = ProxyListener::bind(config).unwrap();
        let addr = listener.local_addr();

        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
        assert_eq!(listener.config().mode, ProxyMode::Explicit);
    }

    #[test]
    fn bind_rejects_transparent_mode() {
        let config = ListenerConfig::parse("127.0.0.1:0", ProxyMode::Transparent).unwrap();
        let err = ProxyListener::bind(config).unwrap_err();
        assert_eq!(err.class(), lens_core::ErrorClass::Operational);
        assert!(err.to_string().contains("transparent"));
    }

    #[tokio::test]
    async fn forwards_bytes_in_both_directions_and_reports_stats() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let listener =
            ProxyListener::bind(ListenerConfig::parse("127.0.0.1:0", ProxyMode::Explicit).unwrap())
                .unwrap();
        let server =
            ProxyServer::from_listener(listener, ProxyRuntimeConfig::new(upstream_addr)).unwrap();
        let proxy_addr = server.local_addr();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        drop(client);
        upstream_task.await.unwrap();
        shutdown_tx.send(()).unwrap();

        let stats = server_task.await.unwrap().unwrap();
        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.client_to_upstream_bytes, 4);
        assert_eq!(stats.upstream_to_client_bytes, 4);
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

        let listener =
            ProxyListener::bind(ListenerConfig::parse("127.0.0.1:0", ProxyMode::Explicit).unwrap())
                .unwrap();
        let mut config = ProxyRuntimeConfig::new(upstream_addr);
        config.shutdown_grace = Duration::from_millis(20);
        let server = ProxyServer::from_listener(listener, config).unwrap();
        let proxy_addr = server.local_addr();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        let client = TcpStream::connect(proxy_addr).await.unwrap();
        accepted_rx.await.unwrap();
        shutdown_tx.send(()).unwrap();
        let stats = server_task.await.unwrap().unwrap();
        drop(client);
        upstream_task.abort();

        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.completed, 0);
        assert_eq!(stats.failed, 1);
    }
}
