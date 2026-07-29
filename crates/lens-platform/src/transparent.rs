//! Platform capability and versioned control records for transparent capture.
//!
//! Privileged redirectors are deliberately kept behind this module. The proxy,
//! decoder, store, and UI continue to run as ordinary user-space components.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::{Command, Output};

use crate::PlatformKind;

/// ABI version shared with the first-party Windows WFP driver.
pub const LENS_WFP_ABI_VERSION: u16 = 1;
const ABI_HEADER_SIZE: u16 = 8;
const CONFIG_SIZE: u16 = 32;
const STATUS_SIZE: u16 = 40;
const REDIRECT_CONTEXT_SIZE: u16 = 48;

const OP_CONFIGURE: u32 = 1;
const OP_STATUS: u32 = 3;
const OP_REDIRECT_CONTEXT: u32 = 4;

/// Native redirect implementation selected for the current operating system.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransparentBackend {
    /// First-party Windows Filtering Platform callout driver.
    WindowsWfp,
    /// Linux nftables redirector with marked upstream sockets.
    LinuxNftables,
    /// Dedicated macOS PF anchor.
    MacOsPf,
    /// No native adapter is defined for this target.
    Unsupported,
}

impl fmt::Display for TransparentBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WindowsWfp => "windows-wfp",
            Self::LinuxNftables => "linux-nftables",
            Self::MacOsPf => "macos-pf",
            Self::Unsupported => "unsupported",
        })
    }
}

/// Safe lifecycle state exposed by `lens doctor` and future control commands.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransparentPhase {
    /// The operating system has no Lens adapter.
    Unsupported,
    /// The platform facility is unavailable.
    Unavailable,
    /// The facility exists, but Lens has not installed its isolated adapter.
    NotInstalled,
    /// The adapter is installed but inactive.
    Stopped,
    /// The adapter is running and can accept configuration.
    Ready,
    /// Redirect filters are active.
    Active,
    /// State could not be reconciled and requires explicit cleanup.
    RecoveryRequired,
}

impl fmt::Display for TransparentPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
            Self::NotInstalled => "not-installed",
            Self::Stopped => "stopped",
            Self::Ready => "ready",
            Self::Active => "active",
            Self::RecoveryRequired => "recovery-required",
        })
    }
}

/// Non-sensitive transparent-mode diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentStatus {
    /// Selected platform adapter.
    pub backend: TransparentBackend,
    /// Current lifecycle state.
    pub phase: TransparentPhase,
    /// Whether setup or activation requires elevation.
    pub requires_admin: bool,
    /// Safe remediation without command lines, usernames, or paths.
    pub detail: String,
}

/// Validated configuration encoded for the Windows driver.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TransparentConfig {
    /// PID of the user-space Lens proxy. Its outbound sockets are excluded.
    pub proxy_pid: u64,
    /// Loopback port receiving redirected TCP connections.
    pub listen_port: u16,
    /// Monotonic control-plane generation used to reject stale state.
    pub generation: u32,
    /// Per-session nonce preventing stale configuration reuse.
    pub session_nonce: u64,
}

impl TransparentConfig {
    /// Builds a configuration only when loop prevention and routing are usable.
    pub fn new(
        proxy_pid: u64,
        listen_port: u16,
        generation: u32,
        session_nonce: u64,
    ) -> Result<Self, TransparentError> {
        if proxy_pid == 0 {
            return Err(TransparentError::new("proxy PID must be non-zero"));
        }
        if listen_port == 0 {
            return Err(TransparentError::new("listen port must be non-zero"));
        }
        if generation == 0 {
            return Err(TransparentError::new("generation must be non-zero"));
        }
        if session_nonce == 0 {
            return Err(TransparentError::new("session nonce must be non-zero"));
        }
        Ok(Self {
            proxy_pid,
            listen_port,
            generation,
            session_nonce,
        })
    }

    /// Encodes the fixed-width, pointer-free driver record.
    #[must_use]
    pub fn encode(self) -> [u8; CONFIG_SIZE as usize] {
        let mut bytes = [0_u8; CONFIG_SIZE as usize];
        write_header(&mut bytes, CONFIG_SIZE, OP_CONFIGURE);
        bytes[8..16].copy_from_slice(&self.proxy_pid.to_le_bytes());
        bytes[16..18].copy_from_slice(&self.listen_port.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.generation.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.session_nonce.to_le_bytes());
        bytes
    }
}

/// Status returned by the Windows driver's read-only IOCTL.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TransparentDriverStatus {
    /// Whether the driver currently accepts redirect classifications.
    pub active: bool,
    /// Active control-plane generation, or zero while disabled.
    pub generation: u64,
    /// Successfully redirected connections since driver load.
    pub redirected_connections: u64,
    /// Redirect failures that were permitted fail-open.
    pub redirect_errors: u64,
}

impl TransparentDriverStatus {
    /// Decodes a fixed-width status record returned by the driver.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransparentError> {
        read_header(bytes, STATUS_SIZE, OP_STATUS)?;
        let state = read_u32(bytes, 8)?;
        if !matches!(state, 1 | 2) {
            return Err(TransparentError::new("driver returned an invalid state"));
        }
        if read_u32(bytes, 12)? != 0 {
            return Err(TransparentError::new(
                "driver returned unknown status flags",
            ));
        }
        Ok(Self {
            active: state == 2,
            generation: read_u64(bytes, 16)?,
            redirected_connections: read_u64(bytes, 24)?,
            redirect_errors: read_u64(bytes, 32)?,
        })
    }
}

/// Original destination supplied by a native redirect adapter.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RedirectContext {
    /// Destination before native redirection.
    pub destination: SocketAddr,
    /// PID reported by the native connection-authorisation layer.
    pub process_id: u64,
    /// Configuration generation that produced this context.
    pub generation: u64,
}

impl RedirectContext {
    /// Decodes a pointer-free redirect context returned by the WFP socket API.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransparentError> {
        read_header(bytes, REDIRECT_CONTEXT_SIZE, OP_REDIRECT_CONTEXT)?;
        let family = read_u16(bytes, 8)?;
        let protocol = *bytes
            .get(10)
            .ok_or_else(|| TransparentError::new("redirect context is truncated"))?;
        if protocol != 6 {
            return Err(TransparentError::new(
                "redirect context is not a TCP connection",
            ));
        }
        let port = u16::from_be_bytes(read_array(bytes, 12)?);
        let address = read_array::<16>(bytes, 16)?;
        let ip = match family {
            2 => IpAddr::V4(Ipv4Addr::new(
                address[0], address[1], address[2], address[3],
            )),
            23 => IpAddr::V6(Ipv6Addr::from(address)),
            _ => return Err(TransparentError::new("unsupported address family")),
        };
        Ok(Self {
            destination: SocketAddr::new(ip, port),
            process_id: read_u64(bytes, 32)?,
            generation: read_u64(bytes, 40)?,
        })
    }
}

/// Read-only transparent-mode platform facade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentController {
    platform: PlatformKind,
}

impl TransparentController {
    /// Selects the adapter for the current operating system.
    #[must_use]
    pub const fn current() -> Self {
        Self::new(PlatformKind::current())
    }

    /// Builds a deterministic controller for tests and diagnostics.
    #[must_use]
    pub const fn new(platform: PlatformKind) -> Self {
        Self { platform }
    }

    /// Returns the native backend family.
    #[must_use]
    pub const fn backend(&self) -> TransparentBackend {
        match self.platform {
            PlatformKind::Windows => TransparentBackend::WindowsWfp,
            PlatformKind::Linux => TransparentBackend::LinuxNftables,
            PlatformKind::MacOs => TransparentBackend::MacOsPf,
            PlatformKind::Unsupported => TransparentBackend::Unsupported,
        }
    }

    /// Reports capability without installing filters or changing networking.
    #[must_use]
    pub fn status(&self) -> TransparentStatus {
        match self.platform {
            PlatformKind::Windows => {
                windows_status(command_output("sc.exe", &["query", "LensWfp"]))
            }
            PlatformKind::Linux => utility_status(
                self.backend(),
                command_output("nft", &["--version"]),
                "nftables is available; the Lens ruleset is not installed",
                "install nftables before enabling transparent mode",
            ),
            PlatformKind::MacOs => utility_status(
                self.backend(),
                command_output("pfctl", &["-s", "info"]),
                "PF is available; the isolated Lens anchor is not installed",
                "PF is unavailable on this macOS host",
            ),
            PlatformKind::Unsupported => TransparentStatus {
                backend: TransparentBackend::Unsupported,
                phase: TransparentPhase::Unsupported,
                requires_admin: true,
                detail: "this operating system has no Lens transparent adapter".to_string(),
            },
        }
    }
}

fn windows_status(output: Option<Output>) -> TransparentStatus {
    let backend = TransparentBackend::WindowsWfp;
    let Some(output) = output else {
        return TransparentStatus {
            backend,
            phase: TransparentPhase::Unavailable,
            requires_admin: true,
            detail: "Windows Service Control Manager is unavailable".to_string(),
        };
    };
    if !output.status.success() {
        return TransparentStatus {
            backend,
            phase: TransparentPhase::NotInstalled,
            requires_admin: true,
            detail: "the first-party Lens WFP driver is not installed".to_string(),
        };
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_uppercase();
    let (phase, detail) = if stdout.contains("RUNNING") {
        (
            TransparentPhase::Ready,
            "the Lens WFP driver is running; redirect filters are not yet activated",
        )
    } else if stdout.contains("STOPPED") {
        (
            TransparentPhase::Stopped,
            "the Lens WFP driver is installed but stopped",
        )
    } else {
        (
            TransparentPhase::RecoveryRequired,
            "the Lens WFP driver reported an unexpected service state",
        )
    };
    TransparentStatus {
        backend,
        phase,
        requires_admin: true,
        detail: detail.to_string(),
    }
}

fn utility_status(
    backend: TransparentBackend,
    output: Option<Output>,
    available: &str,
    unavailable: &str,
) -> TransparentStatus {
    let usable = output.is_some();
    TransparentStatus {
        backend,
        phase: if usable {
            TransparentPhase::NotInstalled
        } else {
            TransparentPhase::Unavailable
        },
        requires_admin: true,
        detail: if usable { available } else { unavailable }.to_string(),
    }
}

fn command_output(program: &str, arguments: &[&str]) -> Option<Output> {
    Command::new(program).args(arguments).output().ok()
}

fn write_header(bytes: &mut [u8], size: u16, operation: u32) {
    bytes[0..2].copy_from_slice(&LENS_WFP_ABI_VERSION.to_le_bytes());
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes[4..8].copy_from_slice(&operation.to_le_bytes());
}

fn read_header(bytes: &[u8], size: u16, operation: u32) -> Result<(), TransparentError> {
    if bytes.len() != usize::from(size) || size < ABI_HEADER_SIZE {
        return Err(TransparentError::new("driver record has an invalid size"));
    }
    if read_u16(bytes, 0)? != LENS_WFP_ABI_VERSION {
        return Err(TransparentError::new("driver ABI version does not match"));
    }
    if read_u16(bytes, 2)? != size {
        return Err(TransparentError::new(
            "driver record size field does not match",
        ));
    }
    if read_u32(bytes, 4)? != operation {
        return Err(TransparentError::new(
            "driver record operation does not match",
        ));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, TransparentError> {
    Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, TransparentError> {
    Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, TransparentError> {
    Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], TransparentError> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(|| TransparentError::new("driver record is truncated"))?
        .try_into()
        .map_err(|_| TransparentError::new("driver record is truncated"))
}

/// Safe transparent control or ABI failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentError {
    detail: String,
}

impl TransparentError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for TransparentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for TransparentError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_encoding_is_fixed_width_and_pointer_free() {
        let config = TransparentConfig::new(731, 8_888, 9, 42).unwrap();
        let encoded = config.encode();
        assert_eq!(encoded.len(), usize::from(CONFIG_SIZE));
        assert_eq!(read_u16(&encoded, 0).unwrap(), LENS_WFP_ABI_VERSION);
        assert_eq!(read_u16(&encoded, 2).unwrap(), CONFIG_SIZE);
        assert_eq!(read_u32(&encoded, 4).unwrap(), OP_CONFIGURE);
        assert_eq!(read_u64(&encoded, 8).unwrap(), 731);
        assert_eq!(read_u16(&encoded, 16).unwrap(), 8_888);
        assert_eq!(read_u32(&encoded, 20).unwrap(), 9);
        assert_eq!(read_u64(&encoded, 24).unwrap(), 42);
    }

    #[test]
    fn invalid_config_cannot_disable_loop_prevention() {
        assert!(TransparentConfig::new(0, 8_888, 1, 1).is_err());
        assert!(TransparentConfig::new(1, 0, 1, 1).is_err());
        assert!(TransparentConfig::new(1, 8_888, 0, 1).is_err());
        assert!(TransparentConfig::new(1, 8_888, 1, 0).is_err());
    }

    #[test]
    fn redirect_context_decodes_ipv4_and_rejects_wrong_versions() {
        let mut bytes = [0_u8; REDIRECT_CONTEXT_SIZE as usize];
        write_header(&mut bytes, REDIRECT_CONTEXT_SIZE, OP_REDIRECT_CONTEXT);
        bytes[8..10].copy_from_slice(&2_u16.to_le_bytes());
        bytes[10] = 6;
        bytes[12..14].copy_from_slice(&443_u16.to_be_bytes());
        bytes[16..20].copy_from_slice(&[203, 0, 113, 7]);
        bytes[32..40].copy_from_slice(&731_u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&9_u64.to_le_bytes());

        let context = RedirectContext::decode(&bytes).unwrap();
        assert_eq!(context.destination, "203.0.113.7:443".parse().unwrap());
        assert_eq!(context.process_id, 731);
        assert_eq!(context.generation, 9);

        bytes[0..2].copy_from_slice(&99_u16.to_le_bytes());
        assert!(RedirectContext::decode(&bytes).is_err());
    }

    #[test]
    fn backend_selection_is_explicit_for_every_supported_platform() {
        assert_eq!(
            TransparentController::new(PlatformKind::Windows).backend(),
            TransparentBackend::WindowsWfp
        );
        assert_eq!(
            TransparentController::new(PlatformKind::Linux).backend(),
            TransparentBackend::LinuxNftables
        );
        assert_eq!(
            TransparentController::new(PlatformKind::MacOs).backend(),
            TransparentBackend::MacOsPf
        );
    }

    #[test]
    fn status_record_decodes_counters_and_rejects_unknown_flags() {
        let mut bytes = [0_u8; STATUS_SIZE as usize];
        write_header(&mut bytes, STATUS_SIZE, OP_STATUS);
        bytes[8..12].copy_from_slice(&2_u32.to_le_bytes());
        bytes[16..24].copy_from_slice(&9_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&31_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&2_u64.to_le_bytes());
        assert_eq!(
            TransparentDriverStatus::decode(&bytes).unwrap(),
            TransparentDriverStatus {
                active: true,
                generation: 9,
                redirected_connections: 31,
                redirect_errors: 2,
            }
        );
        bytes[12] = 1;
        assert!(TransparentDriverStatus::decode(&bytes).is_err());
    }
}
