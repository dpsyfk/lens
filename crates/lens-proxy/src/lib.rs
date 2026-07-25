//! Explicit proxy listener and bind path.
//!
//! Sprint 11: bind address validation and listener setup for explicit mode.
//! Accept loop, upstream resolution, and TLS arrive in later sprints.

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener};

use lens_core::CoreError;

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
    /// Proxy mode. Sprint 11 only opens sockets for [`ProxyMode::Explicit`].
    pub mode: ProxyMode,
}

impl ListenerConfig {
    /// Parses and validates a listen address string.
    ///
    /// Accepts forms like `127.0.0.1:8888` or `[::1]:8888`.
    pub fn parse(listen: &str, mode: ProxyMode) -> Result<Self, CoreError> {
        let addr = listen.parse::<SocketAddr>().map_err(|_| {
            CoreError::invalid_argument("listen", listen, "addr:port, for example 127.0.0.1:8888")
        })?;
        Self::new(addr, mode)
    }

    /// Validates a socket address for proxy binding.
    pub fn new(addr: SocketAddr, mode: ProxyMode) -> Result<Self, CoreError> {
        if addr.port() == 0 && mode == ProxyMode::Transparent {
            // Transparent mode needs a fixed port for redirection rules; port 0 is fine for tests.
        }
        // Reject unspecified ephemeral binds only for transparent mode in a later sprint.
        // Explicit mode may use port 0 in tests to pick a free port.
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
    ///
    /// Transparent mode is rejected until the platform redirection path lands.
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

    /// Returns the bound local address (useful when the config used port 0).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.config.addr
    }

    /// Returns the active listener configuration.
    #[must_use]
    pub fn config(&self) -> &ListenerConfig {
        &self.config
    }

    /// Returns a reference to the underlying TCP listener.
    #[must_use]
    pub fn tcp(&self) -> &TcpListener {
        &self.listener
    }

    /// Consumes the wrapper and returns the raw listener.
    #[must_use]
    pub fn into_tcp(self) -> TcpListener {
        self.listener
    }

    /// Attempts a single accept (blocking). Used by tests and the future accept loop.
    pub fn accept(&self) -> io::Result<(std::net::TcpStream, SocketAddr)> {
        self.listener.accept()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

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

    #[test]
    fn bound_listener_accepts_a_connection() {
        let config = ListenerConfig::parse("127.0.0.1:0", ProxyMode::Explicit).unwrap();
        let listener = ProxyListener::bind(config).unwrap();
        let addr = listener.local_addr();

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream.write_all(b"ping").expect("write");
            stream
        });

        // Brief pause so the connect is in flight; accept is blocking.
        thread::sleep(Duration::from_millis(20));
        let (mut server, peer) = listener.accept().expect("accept");
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"ping");
        assert_eq!(peer.ip().to_string(), "127.0.0.1");
        drop(client.join().expect("client thread"));
    }
}
