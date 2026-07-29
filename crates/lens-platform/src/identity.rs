//! Best-effort socket owner resolution kept off the forwarding data plane.

use std::ffi::OsString;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use lens_core::ServiceIdentity;

use crate::PlatformKind;

const MAX_LABEL_CHARS: usize = 128;

/// Safe result of a best-effort process lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// Identity attached to the flow when a socket owner was found.
    pub identity: Option<ServiceIdentity>,
    /// Non-sensitive diagnostic category.
    pub detail: &'static str,
}

/// Platform socket-owner resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessResolver {
    platform: PlatformKind,
    service: Option<String>,
    proc_root: PathBuf,
}

impl ProcessResolver {
    /// Creates a resolver for the current operating system.
    #[must_use]
    pub fn current(service: Option<String>) -> Self {
        Self::new(PlatformKind::current(), service, PathBuf::from("/proc"))
    }

    /// Creates a deterministic resolver for tests and diagnostics.
    #[must_use]
    pub fn new(platform: PlatformKind, service: Option<String>, proc_root: PathBuf) -> Self {
        Self {
            platform,
            service: service.map(|value| safe_label(&value)),
            proc_root,
        }
    }

    /// Resolves the process owning the client half of an accepted proxy socket.
    ///
    /// This method performs filesystem or child-process I/O and must be called
    /// from a blocking worker, never from the forwarding task.
    #[must_use]
    pub fn resolve(&self, client: SocketAddr, listener: SocketAddr) -> Resolution {
        let owner = match self.platform {
            PlatformKind::Linux => resolve_linux(&self.proc_root, client, listener),
            PlatformKind::Windows => resolve_windows(client, listener),
            PlatformKind::MacOs => resolve_macos(client, listener),
            PlatformKind::Unsupported => None,
        };
        match owner {
            Some((pid, process)) => {
                let process = safe_label(&process);
                let service = self.service.clone().unwrap_or_else(|| process.clone());
                Resolution {
                    identity: Some(
                        ServiceIdentity::new()
                            .with_pid(pid)
                            .with_process(process)
                            .with_service(service),
                    ),
                    detail: "resolved",
                }
            }
            None => Resolution {
                identity: self.service.as_ref().map(|service| {
                    ServiceIdentity::new()
                        .with_process("unknown")
                        .with_service(service.clone())
                }),
                detail: match self.platform {
                    PlatformKind::Unsupported => "unsupported-platform",
                    _ => "owner-unavailable",
                },
            },
        }
    }
}

fn resolve_linux(
    proc_root: &Path,
    client: SocketAddr,
    listener: SocketAddr,
) -> Option<(u32, String)> {
    let inode = ["tcp", "tcp6"].into_iter().find_map(|table| {
        let contents = fs::read_to_string(proc_root.join("net").join(table)).ok()?;
        find_linux_inode(&contents, client.port(), listener.port())
    })?;
    for entry in fs::read_dir(proc_root).ok()?.flatten() {
        let pid = entry.file_name().to_string_lossy().parse::<u32>().ok();
        let Some(pid) = pid else { continue };
        let descriptors = match fs::read_dir(entry.path().join("fd")) {
            Ok(descriptors) => descriptors,
            Err(_) => continue,
        };
        let owns_socket = descriptors.flatten().any(|descriptor| {
            fs::read_link(descriptor.path()).is_ok_and(|target| {
                target.as_os_str() == OsString::from(format!("socket:[{inode}]"))
            })
        });
        if !owns_socket {
            continue;
        }
        let process = fs::read_to_string(entry.path().join("comm"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        return Some((pid, process));
    }
    None
}

fn find_linux_inode(contents: &str, client_port: u16, listener_port: u16) -> Option<u64> {
    for line in contents.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() <= 9 || fields[3] != "01" {
            continue;
        }
        let local_port = socket_table_port(fields[1])?;
        let remote_port = socket_table_port(fields[2])?;
        if local_port == client_port && remote_port == listener_port {
            if let Ok(inode) = fields[9].parse() {
                return Some(inode);
            }
        }
    }
    None
}

fn socket_table_port(value: &str) -> Option<u16> {
    u16::from_str_radix(value.rsplit_once(':')?.1, 16).ok()
}

fn resolve_windows(client: SocketAddr, listener: SocketAddr) -> Option<(u32, String)> {
    let script = format!(
        "$c=Get-NetTCPConnection -State Established -LocalAddress '{}' -LocalPort {} -RemoteAddress '{}' -RemotePort {} -ErrorAction SilentlyContinue | Select-Object -First 1; if($c){{$p=Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; if($p){{'{{0}}`t{{1}}' -f $c.OwningProcess,$p.ProcessName}}}}",
        client.ip(),
        client.port(),
        listener.ip(),
        listener.port()
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| parse_owner_line(&String::from_utf8_lossy(&output.stdout)))
        .flatten()
}

fn resolve_macos(client: SocketAddr, listener: SocketAddr) -> Option<(u32, String)> {
    let output = Command::new("lsof")
        .args([
            "-nP".to_string(),
            "-a".to_string(),
            format!("-iTCP:{}", client.port()),
            "-sTCP:ESTABLISHED".to_string(),
            "-Fpcn".to_string(),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_lsof_owner(&String::from_utf8_lossy(&output.stdout), client, listener)
}

fn parse_owner_line(value: &str) -> Option<(u32, String)> {
    let (pid, process) = value.trim().split_once('\t')?;
    let process = process.trim();
    if process.is_empty() {
        return None;
    }
    Some((pid.trim().parse().ok()?, process.to_string()))
}

fn parse_lsof_owner(
    value: &str,
    client: SocketAddr,
    listener: SocketAddr,
) -> Option<(u32, String)> {
    let expected = format!("{client}->{listener}");
    let mut pid = None;
    let mut process = None;
    for line in value.lines() {
        match line.as_bytes().first() {
            Some(b'p') => pid = line[1..].parse::<u32>().ok(),
            Some(b'c') => process = Some(line[1..].to_string()),
            Some(b'n') if line[1..].contains(&expected) => {
                if let (Some(pid), Some(process)) = (pid, process.take()) {
                    return Some((pid, process));
                }
            }
            _ => {}
        }
    }
    None
}

fn safe_label(value: &str) -> String {
    let basename = Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(value);
    basename
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_LABEL_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_socket_owner_inode() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:C350 0100007F:22B8 01 00000000:00000000 00:00000000 00000000  1000 0 424242 1 0000000000000000\n";
        assert_eq!(find_linux_inode(table, 50_000, 8_888), Some(424_242));
        assert_eq!(find_linux_inode(table, 50_001, 8_888), None);
    }

    #[test]
    fn parses_windows_owner_without_command_line_data() {
        assert_eq!(
            parse_owner_line("731\tpython\r\n"),
            Some((731, "python".to_string()))
        );
        assert_eq!(parse_owner_line(""), None);
    }

    #[test]
    fn parses_matching_lsof_tuple() {
        let client = "127.0.0.1:50000".parse().unwrap();
        let listener = "127.0.0.1:8888".parse().unwrap();
        let output = "p731\ncpython\nf3\nn127.0.0.1:50000->127.0.0.1:8888\n";
        assert_eq!(
            parse_lsof_owner(output, client, listener),
            Some((731, "python".to_string()))
        );
    }

    #[test]
    fn explicit_service_survives_an_unavailable_owner() {
        let resolver = ProcessResolver::new(
            PlatformKind::Unsupported,
            Some("checkout-api".to_string()),
            PathBuf::from("unused"),
        );
        let resolution = resolver.resolve(
            "127.0.0.1:50000".parse().unwrap(),
            "127.0.0.1:8888".parse().unwrap(),
        );
        let identity = resolution.identity.unwrap();
        assert_eq!(identity.display_name(), "checkout-api");
        assert_eq!(identity.process.as_deref(), Some("unknown"));
    }

    #[test]
    fn labels_drop_paths_controls_and_excess_length() {
        assert_eq!(safe_label("/usr/bin/py\nthon"), "python");
        assert_eq!(safe_label(&"a".repeat(200)).len(), MAX_LABEL_CHARS);
    }
}
