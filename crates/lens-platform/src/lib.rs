//! User-scoped platform trust-store adapters.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use lens_tls::CA_COMMON_NAME;

/// Supported trust-store implementation family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PlatformKind {
    /// Current-user Windows certificate store.
    Windows,
    /// Current user's macOS login keychain.
    MacOs,
    /// Current user's NSS database, used by many Linux developer clients.
    Linux,
    /// No adapter is available.
    Unsupported,
}

impl PlatformKind {
    /// Detects the compile target.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Unsupported
        }
    }
}

impl fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Windows => "windows-current-user",
            Self::MacOs => "macos-login-keychain",
            Self::Linux => "linux-user-nss",
            Self::Unsupported => "unsupported",
        })
    }
}

/// Result of checking the operating-system trust adapter.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TrustState {
    /// The Lens root is present in the selected user trust store.
    Installed,
    /// The adapter is available but the root is absent.
    NotInstalled,
    /// The platform or its required command-line utility is unavailable.
    Unavailable,
}

impl fmt::Display for TrustState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Installed => "installed",
            Self::NotInstalled => "not-installed",
            Self::Unavailable => "unavailable",
        })
    }
}

/// Safe trust diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustReport {
    /// Adapter used for the check.
    pub platform: PlatformKind,
    /// Current trust state.
    pub state: TrustState,
    /// Safe remediation detail.
    pub detail: String,
}

/// Executable and arguments used by an adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    /// Program resolved through the process path.
    pub program: OsString,
    /// Arguments passed without shell interpolation.
    pub args: Vec<OsString>,
}

impl CommandSpec {
    fn new(program: impl Into<OsString>, args: Vec<OsString>) -> Self {
        Self {
            program: program.into(),
            args,
        }
    }
}

/// Current-user CA trust-store facade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserTrustStore {
    platform: PlatformKind,
    home: PathBuf,
}

impl UserTrustStore {
    /// Resolves the current platform and user profile directory.
    pub fn current() -> Result<Self, TrustError> {
        let home = env::var_os("HOME")
            .or_else(|| env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .ok_or_else(|| {
                TrustError::new("resolve user trust store", "home directory is unavailable")
            })?;
        Ok(Self::new(PlatformKind::current(), home))
    }

    /// Constructs a deterministic adapter, useful for tests and diagnostics.
    #[must_use]
    pub fn new(platform: PlatformKind, home: impl Into<PathBuf>) -> Self {
        Self {
            platform,
            home: home.into(),
        }
    }

    /// Returns the selected platform adapter.
    #[must_use]
    pub const fn platform(&self) -> PlatformKind {
        self.platform
    }

    /// Checks whether the Lens CA is trusted for the current user.
    #[must_use]
    pub fn status(&self) -> TrustReport {
        let Some(spec) = self.status_command() else {
            return TrustReport {
                platform: self.platform,
                state: TrustState::Unavailable,
                detail: "this operating system has no Lens trust-store adapter".to_string(),
            };
        };
        match execute(&spec) {
            Ok(output) if output.status.success() => TrustReport {
                platform: self.platform,
                state: TrustState::Installed,
                detail: format!("{CA_COMMON_NAME} is trusted for the current user"),
            },
            Ok(_) => TrustReport {
                platform: self.platform,
                state: TrustState::NotInstalled,
                detail: "run `lens cert install` before inspecting HTTPS".to_string(),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => TrustReport {
                platform: self.platform,
                state: TrustState::Unavailable,
                detail: self.missing_tool_remediation(),
            },
            Err(error) => TrustReport {
                platform: self.platform,
                state: TrustState::Unavailable,
                detail: format!("trust status failed: {error}"),
            },
        }
    }

    /// Installs a public Lens CA certificate into the current-user store.
    pub fn install(&self, certificate: &Path) -> Result<TrustReport, TrustError> {
        if !certificate.is_file() {
            return Err(TrustError::new(
                "install trust",
                format!("certificate does not exist: {}", certificate.display()),
            ));
        }
        if self.platform == PlatformKind::Linux {
            self.initialize_linux_nss()?;
        }
        let spec = self.install_command(certificate).ok_or_else(|| {
            TrustError::new("install trust", "this operating system is unsupported")
        })?;
        run_required("install trust", &spec)?;
        let report = self.status();
        if report.state != TrustState::Installed {
            return Err(TrustError::new(
                "install trust",
                "the platform command completed but the CA was not found afterward",
            ));
        }
        Ok(report)
    }

    /// Removes the Lens CA from the current-user store without deleting its key.
    pub fn uninstall(&self) -> Result<TrustReport, TrustError> {
        let status = self.status();
        if status.state == TrustState::NotInstalled {
            return Ok(status);
        }
        if status.state == TrustState::Unavailable {
            return Err(TrustError::new("uninstall trust", status.detail));
        }
        let spec = self.uninstall_command().ok_or_else(|| {
            TrustError::new("uninstall trust", "this operating system is unsupported")
        })?;
        run_required("uninstall trust", &spec)?;
        let report = self.status();
        if report.state == TrustState::Installed {
            return Err(TrustError::new(
                "uninstall trust",
                "the CA is still present after the platform command completed",
            ));
        }
        Ok(report)
    }

    /// Command used to inspect trust state.
    #[must_use]
    pub fn status_command(&self) -> Option<CommandSpec> {
        match self.platform {
            PlatformKind::Windows => Some(CommandSpec::new(
                "certutil",
                os_args(["-user", "-store", "Root", CA_COMMON_NAME]),
            )),
            PlatformKind::MacOs => Some(CommandSpec::new(
                "security",
                vec![
                    "find-certificate".into(),
                    "-c".into(),
                    CA_COMMON_NAME.into(),
                    self.macos_keychain().into_os_string(),
                ],
            )),
            PlatformKind::Linux => Some(CommandSpec::new(
                "certutil",
                vec![
                    "-L".into(),
                    "-d".into(),
                    self.linux_nss_database().into(),
                    "-n".into(),
                    CA_COMMON_NAME.into(),
                ],
            )),
            PlatformKind::Unsupported => None,
        }
    }

    /// Command used to install the public root.
    #[must_use]
    pub fn install_command(&self, certificate: &Path) -> Option<CommandSpec> {
        match self.platform {
            PlatformKind::Windows => Some(CommandSpec::new(
                "certutil",
                vec![
                    "-user".into(),
                    "-addstore".into(),
                    "Root".into(),
                    certificate.as_os_str().to_owned(),
                ],
            )),
            PlatformKind::MacOs => Some(CommandSpec::new(
                "security",
                vec![
                    "add-trusted-cert".into(),
                    "-r".into(),
                    "trustRoot".into(),
                    "-k".into(),
                    self.macos_keychain().into_os_string(),
                    certificate.as_os_str().to_owned(),
                ],
            )),
            PlatformKind::Linux => Some(CommandSpec::new(
                "certutil",
                vec![
                    "-A".into(),
                    "-d".into(),
                    self.linux_nss_database().into(),
                    "-n".into(),
                    CA_COMMON_NAME.into(),
                    "-t".into(),
                    "C,,".into(),
                    "-i".into(),
                    certificate.as_os_str().to_owned(),
                ],
            )),
            PlatformKind::Unsupported => None,
        }
    }

    /// Command used to remove the public root.
    #[must_use]
    pub fn uninstall_command(&self) -> Option<CommandSpec> {
        match self.platform {
            PlatformKind::Windows => Some(CommandSpec::new(
                "certutil",
                os_args(["-user", "-delstore", "Root", CA_COMMON_NAME]),
            )),
            PlatformKind::MacOs => Some(CommandSpec::new(
                "security",
                vec![
                    "delete-certificate".into(),
                    "-c".into(),
                    CA_COMMON_NAME.into(),
                    self.macos_keychain().into_os_string(),
                ],
            )),
            PlatformKind::Linux => Some(CommandSpec::new(
                "certutil",
                vec![
                    "-D".into(),
                    "-d".into(),
                    self.linux_nss_database().into(),
                    "-n".into(),
                    CA_COMMON_NAME.into(),
                ],
            )),
            PlatformKind::Unsupported => None,
        }
    }

    fn initialize_linux_nss(&self) -> Result<(), TrustError> {
        let database = self.home.join(".pki").join("nssdb");
        fs::create_dir_all(&database).map_err(|error| {
            TrustError::new(
                "initialize Linux trust store",
                format!("{}: {error}", database.display()),
            )
        })?;
        if database.join("cert9.db").exists() {
            return Ok(());
        }
        let spec = CommandSpec::new(
            "certutil",
            vec![
                "-N".into(),
                "--empty-password".into(),
                "-d".into(),
                self.linux_nss_database().into(),
            ],
        );
        run_required("initialize Linux NSS database", &spec)
    }

    fn macos_keychain(&self) -> PathBuf {
        self.home
            .join("Library")
            .join("Keychains")
            .join("login.keychain-db")
    }

    fn linux_nss_database(&self) -> String {
        format!("sql:{}", self.home.join(".pki").join("nssdb").display())
    }

    fn missing_tool_remediation(&self) -> String {
        match self.platform {
            PlatformKind::Linux => {
                "NSS certutil is unavailable; install `libnss3-tools` (Debian/Ubuntu) or `nss-tools` (Fedora)"
                    .to_string()
            }
            PlatformKind::Windows => "Windows certutil is unavailable".to_string(),
            PlatformKind::MacOs => "macOS security utility is unavailable".to_string(),
            PlatformKind::Unsupported => {
                "this operating system has no Lens trust-store adapter".to_string()
            }
        }
    }
}

fn os_args<const N: usize>(values: [&str; N]) -> Vec<OsString> {
    values.into_iter().map(OsString::from).collect()
}

fn execute(spec: &CommandSpec) -> io::Result<Output> {
    Command::new(&spec.program).args(&spec.args).output()
}

fn run_required(operation: &str, spec: &CommandSpec) -> Result<(), TrustError> {
    let output = execute(spec).map_err(|error| {
        let detail = if error.kind() == io::ErrorKind::NotFound {
            format!(
                "required utility `{}` was not found",
                spec.program.to_string_lossy()
            )
        } else {
            error.to_string()
        };
        TrustError::new(operation, detail)
    })?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    let detail = detail.trim();
    Err(TrustError::new(
        operation,
        if detail.is_empty() {
            format!("platform command exited with {}", output.status)
        } else {
            detail.chars().take(512).collect()
        },
    ))
}

/// Safe platform adapter failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustError {
    operation: String,
    detail: String,
}

impl TrustError {
    fn new(operation: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.operation, self.detail)
    }
}

impl std::error::Error for TrustError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(spec: CommandSpec) -> Vec<String> {
        spec.args
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn windows_commands_are_current_user_scoped() {
        let store = UserTrustStore::new(PlatformKind::Windows, "C:/Users/dev");
        assert_eq!(
            args(store.install_command(Path::new("C:/ca.pem")).unwrap()),
            vec!["-user", "-addstore", "Root", "C:/ca.pem"]
        );
        assert_eq!(
            args(store.uninstall_command().unwrap()),
            vec!["-user", "-delstore", "Root", CA_COMMON_NAME]
        );
    }

    #[test]
    fn macos_commands_target_the_login_keychain() {
        let store = UserTrustStore::new(PlatformKind::MacOs, "/Users/dev");
        let expected_keychain = store.login_keychain().to_string_lossy().into_owned();
        let command = args(store.install_command(Path::new("/tmp/ca.pem")).unwrap());
        assert!(command.contains(&"trustRoot".to_string()));
        assert!(command.contains(&expected_keychain));
    }

    #[test]
    fn linux_commands_target_the_user_nss_database() {
        let store = UserTrustStore::new(PlatformKind::Linux, "/home/dev");
        let expected_database = format!("sql:{}", store.nss_database().display());
        let command = args(store.install_command(Path::new("/tmp/ca.pem")).unwrap());
        assert!(command.contains(&expected_database));
        assert!(command.contains(&"C,,".to_string()));
    }

    #[test]
    fn unsupported_platform_has_no_mutating_commands() {
        let store = UserTrustStore::new(PlatformKind::Unsupported, "/tmp");
        assert!(store.install_command(Path::new("/tmp/ca.pem")).is_none());
        assert!(store.uninstall_command().is_none());
        assert_eq!(store.status().state, TrustState::Unavailable);
    }
}
