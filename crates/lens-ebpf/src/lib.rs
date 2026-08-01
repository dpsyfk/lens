//! Optional Linux eBPF connection discovery for Lens.
//!
//! The portable cache and record parser are always available. Kernel loading is
//! compiled only with the `runtime` feature on Linux. Discovery observes tuple
//! and process metadata only; it cannot read payloads or affect forwarding.

use lens_core::ServiceIdentity;
use std::{
    collections::VecDeque,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

/// Fixed userspace/kernel event size. The ABI uses byte parsing, never pointers.
pub const EVENT_SIZE: usize = 72;
/// Default number of recent connection identities retained.
pub const DEFAULT_CACHE_CAPACITY: usize = 4096;

/// One completed outbound TCP connection discovered by the Linux probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionRecord {
    /// Kernel monotonic timestamp in nanoseconds.
    pub timestamp_nanos: u64,
    /// Originating process identifier.
    pub pid: u32,
    /// Originating numeric user identifier. Not copied into normal flow exports.
    pub uid: u32,
    /// Local socket endpoint after connect completed.
    pub local: SocketAddr,
    /// Remote endpoint selected by the application.
    pub remote: SocketAddr,
    /// Kernel process name, bounded to 15 visible bytes.
    pub process: String,
}

impl ConnectionRecord {
    /// Parses the fixed-width pointer-free ring-buffer ABI.
    pub fn parse(bytes: &[u8]) -> Result<Self, DiscoveryError> {
        if bytes.len() != EVENT_SIZE {
            return Err(DiscoveryError::InvalidEvent(format!(
                "expected {EVENT_SIZE} bytes, received {}",
                bytes.len()
            )));
        }
        let timestamp_nanos = u64::from_ne_bytes(bytes[0..8].try_into().expect("fixed slice"));
        let pid = u32::from_ne_bytes(bytes[8..12].try_into().expect("fixed slice"));
        let uid = u32::from_ne_bytes(bytes[12..16].try_into().expect("fixed slice"));
        let family = u16::from_ne_bytes(bytes[16..18].try_into().expect("fixed slice"));
        let local_port = u16::from_ne_bytes(bytes[18..20].try_into().expect("fixed slice"));
        let remote_port = u16::from_ne_bytes(bytes[20..22].try_into().expect("fixed slice"));
        let local = parse_endpoint(family, &bytes[24..40], local_port)?;
        let remote = parse_endpoint(family, &bytes[40..56], remote_port)?;
        let process_end = bytes[56..72]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(16);
        let process = std::str::from_utf8(&bytes[56..56 + process_end])
            .map_err(|_| DiscoveryError::InvalidEvent("process name is not UTF-8".to_string()))?
            .to_string();
        Ok(Self {
            timestamp_nanos,
            pid,
            uid,
            local,
            remote,
            process,
        })
    }

    /// Produces safe identity metadata for the canonical Lens flow model.
    #[must_use]
    pub fn identity(&self) -> ServiceIdentity {
        ServiceIdentity::new()
            .with_pid(self.pid)
            .with_process(&self.process)
            .with_service(&self.process)
    }
}

/// Bounded most-recent connection cache used by the proxy identity callback.
#[derive(Clone, Debug)]
pub struct DiscoveryCache {
    capacity: usize,
    records: VecDeque<ConnectionRecord>,
    evicted: u64,
}

impl DiscoveryCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "discovery cache capacity must be positive");
        Self {
            capacity,
            records: VecDeque::new(),
            evicted: 0,
        }
    }

    /// Inserts one record, excluding Lens itself to avoid self-attribution.
    pub fn insert(&mut self, record: ConnectionRecord, lens_pid: u32) {
        if record.pid == lens_pid {
            return;
        }
        if self.records.len() == self.capacity {
            self.records.pop_front();
            self.evicted = self.evicted.saturating_add(1);
        }
        self.records.push_back(record);
    }

    /// Resolves and consumes the newest exact client tuple match.
    pub fn take_identity(&mut self, local: SocketAddr) -> Option<ServiceIdentity> {
        let index = self
            .records
            .iter()
            .rposition(|record| endpoints_match(record.local, local))?;
        self.records.remove(index).map(|record| record.identity())
    }

    /// Returns retained record count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true when no records are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Number of oldest records evicted by the bound.
    #[must_use]
    pub const fn evicted(&self) -> u64 {
        self.evicted
    }
}

impl Default for DiscoveryCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_CAPACITY)
    }
}

fn endpoints_match(discovered: SocketAddr, accepted: SocketAddr) -> bool {
    discovered == accepted
        || (discovered.port() == accepted.port()
            && discovered.ip().is_unspecified()
            && discovered.is_ipv4() == accepted.is_ipv4())
}

fn parse_endpoint(family: u16, address: &[u8], port: u16) -> Result<SocketAddr, DiscoveryError> {
    let ip = match family {
        2 => IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        )),
        10 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(address).expect("fixed address slice"),
        )),
        value => {
            return Err(DiscoveryError::InvalidEvent(format!(
                "unsupported address family {value}"
            )));
        }
    };
    Ok(SocketAddr::new(ip, port))
}

/// Runtime configuration for opt-in Linux discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryConfig {
    /// Cgroup v2 directory whose descendants may be observed.
    pub cgroup: PathBuf,
    /// Maximum recent identities retained for correlation.
    pub capacity: usize,
    /// Lens process identifier excluded from results.
    pub lens_pid: u32,
}

impl DiscoveryConfig {
    /// Builds a cgroup-scoped configuration.
    #[must_use]
    pub fn new(cgroup: impl Into<PathBuf>) -> Self {
        Self {
            cgroup: cgroup.into(),
            capacity: DEFAULT_CACHE_CAPACITY,
            lens_pid: std::process::id(),
        }
    }

    /// Sets the bounded cache capacity.
    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }
}

/// Discovery startup, ABI, or kernel failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    /// Probe events did not match the fixed ABI.
    InvalidEvent(String),
    /// The optional backend is absent on this build/platform.
    Unavailable(String),
    /// Loading, attaching, or reading the kernel probe failed.
    Runtime(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvent(detail) => write!(formatter, "invalid eBPF event: {detail}"),
            Self::Unavailable(detail) => write!(formatter, "eBPF discovery unavailable: {detail}"),
            Self::Runtime(detail) => write!(formatter, "eBPF discovery failed: {detail}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

#[cfg(all(target_os = "linux", feature = "runtime"))]
mod runtime {
    use super::*;
    use aya::{
        maps::{MapData, RingBuf},
        programs::{CgroupAttachMode, CgroupSockAddr, SockOps},
        Ebpf,
    };
    use std::fs::File;

    const PROBE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/lens-discovery.bpf.o"));

    /// Active cgroup-scoped discovery session. Dropping it detaches every link.
    pub struct DiscoverySession {
        _ebpf: Ebpf,
        ring: RingBuf<MapData>,
        cache: DiscoveryCache,
        lens_pid: u32,
        invalid_events: u64,
    }

    impl fmt::Debug for DiscoverySession {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("DiscoverySession")
                .field("cache", &self.cache)
                .field("lens_pid", &self.lens_pid)
                .field("invalid_events", &self.invalid_events)
                .finish_non_exhaustive()
        }
    }

    impl DiscoverySession {
        /// Loads the embedded probe and attaches it to the explicitly selected cgroup.
        pub fn start(config: DiscoveryConfig) -> Result<Self, DiscoveryError> {
            if config.capacity == 0 {
                return Err(DiscoveryError::Runtime(
                    "cache capacity must be positive".to_string(),
                ));
            }
            let cgroup = File::open(&config.cgroup).map_err(|error| {
                DiscoveryError::Runtime(format!("open {}: {error}", config.cgroup.display()))
            })?;
            let mut ebpf =
                Ebpf::load(PROBE).map_err(|error| DiscoveryError::Runtime(error.to_string()))?;
            attach_address(&mut ebpf, "lens_connect4", &cgroup)?;
            attach_address(&mut ebpf, "lens_connect6", &cgroup)?;
            let established: &mut SockOps = ebpf
                .program_mut("lens_established")
                .ok_or_else(|| DiscoveryError::Runtime("missing lens_established".to_string()))?
                .try_into()
                .map_err(|error: aya::programs::ProgramError| {
                    DiscoveryError::Runtime(error.to_string())
                })?;
            established
                .load()
                .and_then(|()| {
                    established
                        .attach(&cgroup, CgroupAttachMode::AllowMultiple)
                        .map(|_| ())
                })
                .map_err(|error| DiscoveryError::Runtime(error.to_string()))?;
            let map = ebpf
                .take_map("EVENTS")
                .ok_or_else(|| DiscoveryError::Runtime("missing EVENTS ring buffer".to_string()))?;
            let ring = RingBuf::try_from(map)
                .map_err(|error| DiscoveryError::Runtime(error.to_string()))?;
            Ok(Self {
                _ebpf: ebpf,
                ring,
                cache: DiscoveryCache::new(config.capacity),
                lens_pid: config.lens_pid,
                invalid_events: 0,
            })
        }

        /// Drains at most `limit` ready events without blocking.
        pub fn poll(&mut self, limit: usize) -> usize {
            let mut accepted = 0;
            for _ in 0..limit {
                let Some(item) = self.ring.next() else {
                    break;
                };
                match ConnectionRecord::parse(&item) {
                    Ok(record) => {
                        self.cache.insert(record, self.lens_pid);
                        accepted += 1;
                    }
                    Err(_) => self.invalid_events = self.invalid_events.saturating_add(1),
                }
            }
            accepted
        }

        /// Mutable access for exact tuple correlation after polling.
        pub fn cache_mut(&mut self) -> &mut DiscoveryCache {
            &mut self.cache
        }

        /// Number of malformed records discarded.
        pub const fn invalid_events(&self) -> u64 {
            self.invalid_events
        }
    }

    fn attach_address(ebpf: &mut Ebpf, name: &str, cgroup: &File) -> Result<(), DiscoveryError> {
        let program: &mut CgroupSockAddr = ebpf
            .program_mut(name)
            .ok_or_else(|| DiscoveryError::Runtime(format!("missing {name}")))?
            .try_into()
            .map_err(|error: aya::programs::ProgramError| {
                DiscoveryError::Runtime(error.to_string())
            })?;
        program
            .load()
            .and_then(|()| {
                program
                    .attach(cgroup, CgroupAttachMode::AllowMultiple)
                    .map(|_| ())
            })
            .map_err(|error| DiscoveryError::Runtime(error.to_string()))
    }
}

#[cfg(all(target_os = "linux", feature = "runtime"))]
pub use runtime::DiscoverySession;

#[cfg(not(all(target_os = "linux", feature = "runtime")))]
/// Portable unavailable backend; keeps non-Linux/default builds rootless and dependency-free.
#[derive(Debug)]
pub struct DiscoverySession {
    cache: DiscoveryCache,
}

#[cfg(not(all(target_os = "linux", feature = "runtime")))]
impl DiscoverySession {
    /// Reports the exact platform/feature requirement without attempting privilege changes.
    pub fn start(_config: DiscoveryConfig) -> Result<Self, DiscoveryError> {
        Err(DiscoveryError::Unavailable(
            "requires Linux, a cgroup v2 path, privilege to attach BPF programs, and a binary built with the `runtime` feature"
                .to_string(),
        ))
    }

    /// Portable no-op retained so callers compile without platform branching.
    pub const fn poll(&mut self, _limit: usize) -> usize {
        0
    }

    /// Returns the unreachable empty cache for portable composition code.
    pub fn cache_mut(&mut self) -> &mut DiscoveryCache {
        &mut self.cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_event(family: u16, pid: u32, local_port: u16, remote_port: u16) -> [u8; EVENT_SIZE] {
        let mut bytes = [0_u8; EVENT_SIZE];
        bytes[0..8].copy_from_slice(&7_u64.to_ne_bytes());
        bytes[8..12].copy_from_slice(&pid.to_ne_bytes());
        bytes[12..16].copy_from_slice(&1000_u32.to_ne_bytes());
        bytes[16..18].copy_from_slice(&family.to_ne_bytes());
        bytes[18..20].copy_from_slice(&local_port.to_ne_bytes());
        bytes[20..22].copy_from_slice(&remote_port.to_ne_bytes());
        if family == 2 {
            bytes[24..28].copy_from_slice(&[127, 0, 0, 1]);
            bytes[40..44].copy_from_slice(&[10, 0, 0, 9]);
        } else {
            bytes[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            bytes[40..56].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        }
        bytes[56..60].copy_from_slice(b"curl");
        bytes
    }

    #[test]
    fn parses_pointer_free_ipv4_and_ipv6_records() {
        let ipv4 = ConnectionRecord::parse(&raw_event(2, 42, 50000, 8888)).expect("IPv4");
        assert_eq!(ipv4.local, "127.0.0.1:50000".parse().expect("address"));
        assert_eq!(ipv4.remote, "10.0.0.9:8888".parse().expect("address"));
        assert_eq!(ipv4.process, "curl");
        let ipv6 = ConnectionRecord::parse(&raw_event(10, 43, 50001, 443)).expect("IPv6");
        assert!(ipv6.local.is_ipv6());
    }

    #[test]
    fn exact_tuple_correlation_is_consuming_and_bounded() {
        let mut cache = DiscoveryCache::new(2);
        for pid in 10..13 {
            cache.insert(
                ConnectionRecord::parse(&raw_event(2, pid, 40000 + pid as u16, 8888))
                    .expect("record"),
                999,
            );
        }
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.evicted(), 1);
        let identity = cache
            .take_identity("127.0.0.1:40012".parse().expect("address"))
            .expect("identity");
        assert_eq!(identity.pid, Some(12));
        assert!(cache
            .take_identity("127.0.0.1:40012".parse().expect("address"))
            .is_none());
    }

    #[test]
    fn lens_process_is_excluded() {
        let mut cache = DiscoveryCache::new(1);
        cache.insert(
            ConnectionRecord::parse(&raw_event(2, 77, 50000, 8888)).expect("record"),
            77,
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn malformed_event_is_rejected() {
        let error = ConnectionRecord::parse(&[0_u8; 8]).expect_err("short event");
        assert!(matches!(error, DiscoveryError::InvalidEvent(_)));
    }
}
