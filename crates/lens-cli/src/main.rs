use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use lens_core::{Endpoint, RunId};
use lens_platform::{PlatformKind, TrustState, UserTrustStore};
use lens_proxy::{
    HttpsMode, ListenerConfig, ObservationSink, ProxyListener, ProxyMode as ProxyListenMode,
    ProxyRuntimeConfig, ProxyServer, TlsInterception,
};
use lens_store::StoreActor;
use lens_tls::{CaPaths, CaStatus, CertificateAuthority};

const DEFAULT_LISTEN: &str = "127.0.0.1:8888";
const DEFAULT_MODE: ProxyMode = ProxyMode::Explicit;
const DEFAULT_MAX_FLOWS: usize = 10_000;
const DEFAULT_MAX_BODY: usize = 262_144;
const DEFAULT_HTTPS_MODE: HttpsMode = HttpsMode::Intercept;

fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt().with_target(false).try_init();
    match run_from_env() {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn run_from_env() -> Result<String, CliError> {
    let raw_args = env::args().skip(1);
    let env_vars = env::vars().collect::<BTreeMap<_, _>>();
    run(raw_args, &env_vars, read_config_file, true)
}

fn run<I, S, F>(
    raw_args: I,
    env_vars: &BTreeMap<String, String>,
    read_config: F,
    bind_listener: bool,
) -> Result<String, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    F: Fn(&Path) -> Result<Option<String>, CliError>,
{
    let parsed = Cli::parse(raw_args)?;
    if matches!(parsed.command, Command::Help) {
        return Ok(HELP_TEXT.to_string());
    }
    if matches!(parsed.command, Command::Version) {
        return Ok(format!("lens {}", env!("CARGO_PKG_VERSION")));
    }

    let file_values = match &parsed.config_path {
        Some(path) => Some(parse_config_file(
            &read_config(path)?.ok_or_else(|| CliError::ConfigNotFound(path.clone()))?,
        )),
        None => None,
    };
    let env_values = ConfigValues::from_env(env_vars);
    let config =
        ResolvedConfig::resolve(file_values.as_ref(), Some(&env_values), Some(&parsed.flags))?;

    match parsed.command {
        Command::Run => run_proxy_session(&config, bind_listener),
        Command::Doctor { check } => Ok(render_doctor_report(&config, check)),
        Command::Cert { action } => run_cert_command(action, bind_listener),
        Command::Help | Command::Version => unreachable!("handled before configuration"),
    }
}

/// Runs an HTTP or fixed-upstream forwarding session until Ctrl-C.
fn run_proxy_session(config: &ResolvedConfig, bind_listener: bool) -> Result<String, CliError> {
    let plan = render_run_plan(config);
    if !bind_listener {
        return Ok(plan);
    }

    let mode = match config.mode {
        ProxyMode::Explicit => ProxyListenMode::Explicit,
        ProxyMode::Transparent => ProxyListenMode::Transparent,
    };
    let listener_config =
        ListenerConfig::new(config.listen_addr, mode).map_err(|error| CliError::InvalidValue {
            name: "--listen".to_string(),
            value: config.listen.clone(),
            expected: error.to_string(),
        })?;
    let listener = ProxyListener::bind(listener_config).map_err(|error| CliError::BindFailed {
        addr: config.listen.clone(),
        source: error.to_string(),
    })?;
    let local_addr = listener.local_addr();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::RuntimeFailed(error.to_string()))?;
    let runtime_config = match config.protocol {
        TrafficProtocol::Tcp => ProxyRuntimeConfig::fixed(
            config
                .upstream_endpoint
                .clone()
                .expect("TCP configuration requires an upstream"),
        ),
        TrafficProtocol::Postgres => ProxyRuntimeConfig::postgres(
            config
                .upstream_endpoint
                .clone()
                .expect("PostgreSQL configuration requires an upstream"),
        ),
        TrafficProtocol::Http => match config.https_mode {
            HttpsMode::Intercept => {
                let paths = CaPaths::for_user()
                    .map_err(|error| CliError::Certificate(error.to_string()))?;
                let authority = Arc::new(
                    CertificateAuthority::load_or_create(paths)
                        .map_err(|error| CliError::Certificate(error.to_string()))?,
                );
                let interception = TlsInterception::with_platform_verifier(authority)
                    .map_err(|error| CliError::Certificate(error.to_string()))?;
                ProxyRuntimeConfig::http().with_tls_interception(interception)
            }
            mode => ProxyRuntimeConfig::http().with_https_mode(mode),
        },
    };
    let (observer, observations) = ObservationSink::channel(1024);
    let (store_actor, store_handle) = StoreActor::with_inspection(
        config.max_flows,
        RunId::new(1),
        config.max_body,
        config.reveal,
    );
    let server = runtime
        .block_on(async { ProxyServer::from_listener(listener, runtime_config) })
        .map_err(|error| CliError::ProxyFailed(error.to_string()))?;
    let server = server.with_observer(observer);

    println!("{plan}\nbound: {local_addr}\nstatus: forwarding; press Ctrl-C to stop");
    let (stats, snapshot) = runtime
        .block_on(async move {
            let store_task = tokio::spawn(store_actor.run(observations));
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            let signal_task = tokio::spawn(async move {
                if let Err(error) = tokio::signal::ctrl_c().await {
                    eprintln!("lens: failed to wait for Ctrl-C: {error}");
                }
                let _ = shutdown_tx.send(());
            });
            let stats = server.run_until(shutdown_rx).await?;
            signal_task.abort();
            store_task.await.map_err(|error| {
                lens_core::CoreError::operation_failed("store actor", error.to_string())
            })?;
            Ok::<_, lens_core::CoreError>((stats, store_handle.snapshot()))
        })
        .map_err(|error| CliError::ProxyFailed(error.to_string()))?;

    let mut output = format!(
        "lens stopped\naccepted: {}\ncompleted: {}\nfailed: {}\nobservations_dropped: {}\nevicted: {}\nbytes: client->upstream {}, upstream->client {}",
        stats.accepted,
        stats.completed,
        stats.failed,
        stats.observations_dropped,
        snapshot.evicted,
        stats.client_to_upstream_bytes,
        stats.upstream_to_client_bytes
    );
    if config.headless {
        for flow in snapshot.flows {
            output.push('\n');
            output.push_str(&flow.to_json_line());
        }
    }
    Ok(output)
}

fn run_cert_command(action: CertAction, execute: bool) -> Result<String, CliError> {
    let paths = CaPaths::for_user().map_err(|error| CliError::Certificate(error.to_string()))?;
    if !execute {
        return Ok(format!(
            "lens cert {action}\ncertificate: {}\nstatus: dry-run; no trust-store changes made",
            paths.certificate.display()
        ));
    }
    let trust = UserTrustStore::current().map_err(|error| CliError::Trust(error.to_string()))?;
    match action {
        CertAction::Install => {
            let authority = CertificateAuthority::load_or_create(paths)
                .map_err(|error| CliError::Certificate(error.to_string()))?;
            let linux_bundle = if trust.platform() == PlatformKind::Linux {
                Some(
                    authority
                        .write_linux_client_bundle()
                        .map_err(|error| CliError::Certificate(error.to_string()))?
                        .to_path_buf(),
                )
            } else {
                None
            };
            let (trust_state, trust_detail) = match trust.install(authority.certificate_path()) {
                Ok(report) => (report.state, report.detail),
                Err(error) if trust.platform() == PlatformKind::Linux => (
                    TrustState::Unavailable,
                    format!(
                        "NSS installation unavailable ({error}); use SSL_CERT_FILE={} for OpenSSL-based clients",
                        linux_bundle
                            .as_deref()
                            .expect("Linux bundle created above")
                            .display()
                    ),
                ),
                Err(error) => return Err(CliError::Trust(error.to_string())),
            };
            Ok(format!(
                "lens cert install\nmaterial: ready\ncertificate: {}\nfingerprint: {}\nclient_bundle: {}\ntrust: {}; {}",
                authority.certificate_path().display(),
                authority.status().fingerprint.unwrap_or_default(),
                linux_bundle
                    .as_deref()
                    .map_or("not required".to_string(), |path| path.display().to_string()),
                trust_state,
                trust_detail
            ))
        }
        CertAction::Uninstall => {
            let (trust_state, trust_detail) = match trust.uninstall() {
                Ok(report) => (report.state, report.detail),
                Err(error) if trust.platform() == PlatformKind::Linux => (
                    TrustState::Unavailable,
                    format!(
                        "NSS removal unavailable ({error}); unset SSL_CERT_FILE to remove environment trust"
                    ),
                ),
                Err(error) => return Err(CliError::Trust(error.to_string())),
            };
            Ok(format!(
                "lens cert uninstall\ntrust: {}; {}\nmaterial: retained; the local CA key was not deleted",
                trust_state, trust_detail
            ))
        }
        CertAction::Status => {
            let material = CaStatus::inspect(paths);
            let report = trust.status();
            Ok(render_cert_status(&material, report.state, &report.detail))
        }
    }
}

fn render_cert_status(material: &CaStatus, trust: TrustState, trust_detail: &str) -> String {
    format!(
        "lens cert status\nmaterial: {}; {}\ncertificate: {}\nclient_bundle: {} ({})\nfingerprint: {}\nvalid_now: {}\ntrust: {}; {}",
        material.state,
        material.detail,
        material.paths.certificate.display(),
        material.paths.client_bundle.display(),
        if material.paths.client_bundle.is_file() { "ready" } else { "not-created" },
        material.fingerprint.as_deref().unwrap_or("unavailable"),
        material
            .valid_now
            .map_or("unknown", |value| if value { "yes" } else { "no" }),
        trust,
        trust_detail
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cli {
    command: Command,
    config_path: Option<PathBuf>,
    flags: ConfigValues,
}

impl Cli {
    fn parse<I, S>(raw_args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut command = None;
        let mut doctor_check = None;
        let mut config_path = None;
        let mut flags = ConfigValues::default();
        let mut args = raw_args.into_iter().map(Into::into).peekable();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "run" => set_command(&mut command, Command::Run)?,
                "doctor" => set_command(
                    &mut command,
                    Command::Doctor {
                        check: DoctorCheck::All,
                    },
                )?,
                "cert" => {
                    let action = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("cert action".to_string()))?
                        .parse()?;
                    set_command(&mut command, Command::Cert { action })?;
                }
                "--check" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--check".to_string()))?;
                    doctor_check = Some(value.parse()?);
                }
                "--help" | "-h" => set_command(&mut command, Command::Help)?,
                "--version" | "-V" => set_command(&mut command, Command::Version)?,
                "--config" => {
                    config_path =
                        Some(PathBuf::from(args.next().ok_or_else(|| {
                            CliError::MissingValue("--config".to_string())
                        })?));
                }
                "--listen" => {
                    flags.listen = Some(
                        args.next()
                            .ok_or_else(|| CliError::MissingValue("--listen".to_string()))?,
                    );
                }
                "--upstream" => {
                    flags.upstream = Some(
                        args.next()
                            .ok_or_else(|| CliError::MissingValue("--upstream".to_string()))?,
                    );
                }
                "--protocol" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--protocol".to_string()))?;
                    flags.protocol = Some(value.parse()?);
                }
                "--mode" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--mode".to_string()))?;
                    flags.mode = Some(value.parse()?);
                }
                "--https" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--https".to_string()))?;
                    flags.https_mode = Some(parse_https_mode(&value)?);
                }
                "--reveal" => flags.reveal = Some(true),
                "--redact" => flags.reveal = Some(false),
                "--headless" => flags.headless = Some(true),
                "--max-flows" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--max-flows".to_string()))?;
                    flags.max_flows = Some(parse_positive_usize("--max-flows", &value)?);
                }
                "--max-body" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--max-body".to_string()))?;
                    flags.max_body = Some(parse_positive_usize("--max-body", &value)?);
                }
                value if value.starts_with('-') => {
                    return Err(CliError::UnknownOption(value.to_string()));
                }
                value => return Err(CliError::UnknownCommand(value.to_string())),
            }
        }

        let command = command.unwrap_or(Command::Run);
        let command = match command {
            Command::Doctor { .. } => Command::Doctor {
                check: doctor_check.unwrap_or(DoctorCheck::All),
            },
            _ if doctor_check.is_some() => {
                return Err(CliError::OptionRequiresCommand {
                    option: "--check".to_string(),
                    command: "doctor".to_string(),
                })
            }
            command => command,
        };

        Ok(Self {
            command,
            config_path,
            flags,
        })
    }
}

fn set_command(target: &mut Option<Command>, command: Command) -> Result<(), CliError> {
    if target.replace(command).is_some() {
        return Err(CliError::MultipleCommands);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Command {
    Run,
    Doctor { check: DoctorCheck },
    Cert { action: CertAction },
    Help,
    Version,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CertAction {
    Install,
    Uninstall,
    Status,
}

impl fmt::Display for CertAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Install => "install",
            Self::Uninstall => "uninstall",
            Self::Status => "status",
        })
    }
}

impl std::str::FromStr for CertAction {
    type Err = CliError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "install" => Ok(Self::Install),
            "uninstall" => Ok(Self::Uninstall),
            "status" => Ok(Self::Status),
            _ => Err(CliError::InvalidValue {
                name: "cert action".to_string(),
                value: value.to_string(),
                expected: "install, uninstall, or status".to_string(),
            }),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DoctorCheck {
    All,
    Config,
    Network,
    Trust,
    Platform,
}

impl std::str::FromStr for DoctorCheck {
    type Err = CliError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "config" => Ok(Self::Config),
            "network" => Ok(Self::Network),
            "trust" => Ok(Self::Trust),
            "platform" => Ok(Self::Platform),
            _ => Err(CliError::InvalidValue {
                name: "--check".to_string(),
                value: value.to_string(),
                expected: "all, config, network, trust, or platform".to_string(),
            }),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ProxyMode {
    Explicit,
    Transparent,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum TrafficProtocol {
    Http,
    Tcp,
    Postgres,
}

impl fmt::Display for TrafficProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Http => "http",
            Self::Tcp => "tcp",
            Self::Postgres => "postgres",
        })
    }
}

impl std::str::FromStr for TrafficProtocol {
    type Err = CliError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "http" => Ok(Self::Http),
            "tcp" => Ok(Self::Tcp),
            "postgres" | "postgresql" => Ok(Self::Postgres),
            _ => Err(CliError::InvalidValue {
                name: "--protocol".to_string(),
                value: value.to_string(),
                expected: "http, tcp, or postgres".to_string(),
            }),
        }
    }
}

impl fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Explicit => "explicit",
            Self::Transparent => "transparent",
        })
    }
}

impl std::str::FromStr for ProxyMode {
    type Err = CliError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "explicit" => Ok(Self::Explicit),
            "transparent" => Ok(Self::Transparent),
            _ => Err(CliError::InvalidValue {
                name: "--mode".to_string(),
                value: value.to_string(),
                expected: "explicit or transparent".to_string(),
            }),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ConfigValues {
    listen: Option<String>,
    upstream: Option<String>,
    protocol: Option<TrafficProtocol>,
    mode: Option<ProxyMode>,
    https_mode: Option<HttpsMode>,
    reveal: Option<bool>,
    max_flows: Option<usize>,
    max_body: Option<usize>,
    headless: Option<bool>,
}

impl ConfigValues {
    fn from_env(env_vars: &BTreeMap<String, String>) -> Self {
        Self {
            listen: env_vars.get("LENS_LISTEN").cloned(),
            upstream: env_vars.get("LENS_UPSTREAM").cloned(),
            protocol: env_vars
                .get("LENS_PROTOCOL")
                .and_then(|value| value.parse().ok()),
            mode: env_vars
                .get("LENS_MODE")
                .and_then(|value| value.parse().ok()),
            https_mode: env_vars
                .get("LENS_HTTPS")
                .and_then(|value| parse_https_mode(value).ok()),
            reveal: env_vars
                .get("LENS_REVEAL")
                .and_then(|value| parse_bool(value).ok()),
            max_flows: env_vars
                .get("LENS_MAX_FLOWS")
                .and_then(|value| parse_positive_usize("LENS_MAX_FLOWS", value).ok()),
            max_body: env_vars
                .get("LENS_MAX_BODY")
                .and_then(|value| parse_positive_usize("LENS_MAX_BODY", value).ok()),
            headless: env_vars
                .get("LENS_HEADLESS")
                .and_then(|value| parse_bool(value).ok()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedConfig {
    listen: String,
    listen_addr: SocketAddr,
    upstream: Option<String>,
    upstream_endpoint: Option<Endpoint>,
    protocol: TrafficProtocol,
    mode: ProxyMode,
    https_mode: HttpsMode,
    reveal: bool,
    max_flows: usize,
    max_body: usize,
    headless: bool,
}

impl ResolvedConfig {
    fn resolve(
        file: Option<&ConfigValues>,
        env_vars: Option<&ConfigValues>,
        flags: Option<&ConfigValues>,
    ) -> Result<Self, CliError> {
        let listen = pick(
            flags.and_then(|values| values.listen.clone()),
            env_vars.and_then(|values| values.listen.clone()),
            file.and_then(|values| values.listen.clone()),
            DEFAULT_LISTEN.to_string(),
        );
        let listen_addr = listen.parse().map_err(|_| CliError::InvalidValue {
            name: "--listen".to_string(),
            value: listen.clone(),
            expected: "addr:port, for example 127.0.0.1:8888".to_string(),
        })?;
        let upstream = flags
            .and_then(|values| values.upstream.clone())
            .or_else(|| env_vars.and_then(|values| values.upstream.clone()))
            .or_else(|| file.and_then(|values| values.upstream.clone()));
        let upstream_endpoint = upstream.as_deref().map(parse_endpoint).transpose()?;
        let requested_protocol = flags
            .and_then(|values| values.protocol)
            .or_else(|| env_vars.and_then(|values| values.protocol))
            .or_else(|| file.and_then(|values| values.protocol));
        let protocol = requested_protocol.unwrap_or(if upstream_endpoint.is_some() {
            TrafficProtocol::Tcp
        } else {
            TrafficProtocol::Http
        });
        match (protocol, upstream_endpoint.is_some()) {
            (TrafficProtocol::Http, true) => {
                return Err(CliError::InvalidValue {
                    name: "--upstream".to_string(),
                    value: upstream.clone().unwrap_or_default(),
                    expected: "no fixed upstream when --protocol http is selected".to_string(),
                });
            }
            (TrafficProtocol::Tcp | TrafficProtocol::Postgres, false) => {
                return Err(CliError::InvalidValue {
                    name: "--protocol".to_string(),
                    value: protocol.to_string(),
                    expected: "--upstream host:port for fixed-target protocols".to_string(),
                });
            }
            _ => {}
        }

        Ok(Self {
            listen,
            listen_addr,
            upstream,
            upstream_endpoint,
            protocol,
            mode: pick(
                flags.and_then(|values| values.mode),
                env_vars.and_then(|values| values.mode),
                file.and_then(|values| values.mode),
                DEFAULT_MODE,
            ),
            https_mode: pick(
                flags.and_then(|values| values.https_mode),
                env_vars.and_then(|values| values.https_mode),
                file.and_then(|values| values.https_mode),
                DEFAULT_HTTPS_MODE,
            ),
            reveal: pick(
                flags.and_then(|values| values.reveal),
                env_vars.and_then(|values| values.reveal),
                file.and_then(|values| values.reveal),
                false,
            ),
            max_flows: pick(
                flags.and_then(|values| values.max_flows),
                env_vars.and_then(|values| values.max_flows),
                file.and_then(|values| values.max_flows),
                DEFAULT_MAX_FLOWS,
            ),
            max_body: pick(
                flags.and_then(|values| values.max_body),
                env_vars.and_then(|values| values.max_body),
                file.and_then(|values| values.max_body),
                DEFAULT_MAX_BODY,
            ),
            headless: pick(
                flags.and_then(|values| values.headless),
                env_vars.and_then(|values| values.headless),
                file.and_then(|values| values.headless),
                false,
            ),
        })
    }
}

fn pick<T>(flags: Option<T>, env_vars: Option<T>, file: Option<T>, default: T) -> T {
    flags.or(env_vars).or(file).unwrap_or(default)
}

fn read_config_file(path: &Path) -> Result<Option<String>, CliError> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::ConfigRead {
            path: path.to_path_buf(),
            source: error.to_string(),
        }),
    }
}

fn parse_config_file(contents: &str) -> ConfigValues {
    let mut values = ConfigValues::default();

    for raw_line in contents.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "listen" => values.listen = Some(value.to_string()),
            "upstream" => values.upstream = Some(value.to_string()),
            "protocol" => values.protocol = value.parse().ok(),
            "mode" => values.mode = value.parse().ok(),
            "https" => values.https_mode = parse_https_mode(value).ok(),
            "reveal" => values.reveal = parse_bool(value).ok(),
            "max_flows" => values.max_flows = parse_positive_usize(key, value).ok(),
            "max_body" => values.max_body = parse_positive_usize(key, value).ok(),
            "headless" => values.headless = parse_bool(value).ok(),
            _ => {}
        }
    }

    values
}

fn parse_bool(value: &str) -> Result<bool, CliError> {
    match value {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(CliError::InvalidValue {
            name: "boolean".to_string(),
            value: value.to_string(),
            expected: "true, false, 1, 0, yes, no, on, or off".to_string(),
        }),
    }
}

fn parse_endpoint(value: &str) -> Result<Endpoint, CliError> {
    let invalid = || CliError::InvalidValue {
        name: "--upstream".to_string(),
        value: value.to_string(),
        expected: "host:port, for example db.example.com:5432".to_string(),
    };
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        rest.split_once("]:").ok_or_else(&invalid)?
    } else {
        value.rsplit_once(':').ok_or_else(&invalid)?
    };
    let port = port.parse::<u16>().map_err(|_| invalid())?;
    if host.is_empty()
        || host.chars().any(char::is_whitespace)
        || host.contains('/')
        || host.contains(':') && !value.starts_with('[')
    {
        return Err(invalid());
    }
    Ok(Endpoint::new(host, port))
}

fn parse_https_mode(value: &str) -> Result<HttpsMode, CliError> {
    match value {
        "intercept" => Ok(HttpsMode::Intercept),
        "passthrough" => Ok(HttpsMode::Passthrough),
        "reject" => Ok(HttpsMode::Reject),
        _ => Err(CliError::InvalidValue {
            name: "--https".to_string(),
            value: value.to_string(),
            expected: "intercept, passthrough, or reject".to_string(),
        }),
    }
}

fn parse_positive_usize(name: &str, value: &str) -> Result<usize, CliError> {
    let parsed = value.parse::<usize>().map_err(|_| CliError::InvalidValue {
        name: name.to_string(),
        value: value.to_string(),
        expected: "a positive integer".to_string(),
    })?;
    if parsed == 0 {
        return Err(CliError::InvalidValue {
            name: name.to_string(),
            value: value.to_string(),
            expected: "a positive integer".to_string(),
        });
    }
    Ok(parsed)
}

fn render_run_plan(config: &ResolvedConfig) -> String {
    format!(
        "lens run\nmode: {}\nprotocol: {}\nlisten: {}\nupstream: {}\nhttps: {}\nredaction: {}\nheadless: {}\nmax_flows: {}\nmax_body: {} bytes",
        config.mode,
        config.protocol,
        config.listen,
        config
            .upstream
            .as_deref()
            .unwrap_or("selected from HTTP request"),
        config.https_mode,
        if config.reveal { "revealed" } else { "enabled" },
        config.headless,
        config.max_flows,
        config.max_body
    )
}

fn render_doctor_report(config: &ResolvedConfig, check: DoctorCheck) -> String {
    let mut lines = Vec::new();
    lines.push("lens doctor".to_string());

    if matches!(check, DoctorCheck::All | DoctorCheck::Config) {
        lines.push(format!(
            "config: ok; mode={}, protocol={}, listen={}, https={}, redaction={}",
            config.mode,
            config.protocol,
            config.listen,
            config.https_mode,
            if config.reveal { "revealed" } else { "enabled" }
        ));
    }
    if matches!(check, DoctorCheck::All | DoctorCheck::Network) {
        lines.push(format!(
            "network: ok; bind address {}; upstream {}",
            config.listen_addr,
            config
                .upstream
                .as_deref()
                .unwrap_or("selected from HTTP request")
        ));
    }
    if matches!(check, DoctorCheck::All | DoctorCheck::Trust) {
        let material = CaPaths::for_user()
            .map(CaStatus::inspect)
            .map(|status| {
                format!(
                    "material={}, valid_now={}, client_bundle={}",
                    status.state,
                    status
                        .valid_now
                        .map_or("unknown", |value| if value { "yes" } else { "no" }),
                    if status.paths.client_bundle.is_file() {
                        status.paths.client_bundle.display().to_string()
                    } else {
                        "not-created".to_string()
                    }
                )
            })
            .unwrap_or_else(|error| format!("material=unavailable ({error})"));
        let trust = UserTrustStore::current()
            .map(|store| store.status())
            .map(|report| format!("{}; {}", report.state, report.detail))
            .unwrap_or_else(|error| format!("unavailable; {error}"));
        lines.push(format!("trust: {trust}; {material}"));
    }
    if matches!(check, DoctorCheck::All | DoctorCheck::Platform) {
        lines.push(format!(
            "platform: {}; userspace explicit proxy mode is supported",
            env::consts::OS
        ));
    }

    lines.join("\n")
}

#[derive(Debug, PartialEq, Eq)]
enum CliError {
    MissingValue(String),
    UnknownCommand(String),
    UnknownOption(String),
    MultipleCommands,
    OptionRequiresCommand {
        option: String,
        command: String,
    },
    InvalidValue {
        name: String,
        value: String,
        expected: String,
    },
    ConfigRead {
        path: PathBuf,
        source: String,
    },
    ConfigNotFound(PathBuf),
    BindFailed {
        addr: String,
        source: String,
    },
    RuntimeFailed(String),
    ProxyFailed(String),
    Certificate(String),
    Trust(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue(name) => write!(f, "lens: missing value for {name}"),
            Self::UnknownCommand(command) => write!(f, "lens: unknown command `{command}`"),
            Self::UnknownOption(option) => write!(f, "lens: unknown option `{option}`"),
            Self::MultipleCommands => write!(f, "lens: only one command can be run at a time"),
            Self::OptionRequiresCommand { option, command } => {
                write!(f, "lens: {option} requires the `{command}` command")
            }
            Self::InvalidValue {
                name,
                value,
                expected,
            } => {
                write!(
                    f,
                    "lens: invalid value for {name}: `{value}`; expected {expected}"
                )
            }
            Self::ConfigRead { path, source } => {
                write!(
                    f,
                    "lens: failed to read config {}: {source}",
                    path.display()
                )
            }
            Self::ConfigNotFound(path) => {
                write!(f, "lens: config file not found: {}", path.display())
            }
            Self::BindFailed { addr, source } => {
                write!(f, "lens: failed to bind {addr}: {source}")
            }
            Self::RuntimeFailed(source) => write!(f, "lens: failed to start runtime: {source}"),
            Self::ProxyFailed(source) => write!(f, "lens: proxy session failed: {source}"),
            Self::Certificate(source) => write!(f, "lens: certificate operation failed: {source}"),
            Self::Trust(source) => write!(f, "lens: trust-store operation failed: {source}"),
        }
    }
}

const HELP_TEXT: &str = "\
lens
Local-first traffic inspection for developer debugging.

USAGE:
  lens [COMMAND] [OPTIONS]

COMMANDS:
  run        Start a live capture session (default)
  doctor     Check config, platform, trust, and network readiness
  cert       Manage the explicit local CA: install, uninstall, or status

GLOBAL OPTIONS:
  --config <path>            Read simple key = value configuration
  --listen <addr:port>       Listen address [default: 127.0.0.1:8888]
  --upstream <host:port>     Fixed target for TCP or PostgreSQL mode
  --protocol <http|tcp|postgres>
                             Protocol to route and inspect [auto-detected from upstream]
  --mode <explicit|transparent>
                             How traffic reaches Lens [default: explicit]
  --https <intercept|passthrough|reject>
                             CONNECT behavior [default: intercept]
  --reveal                   Disable redaction for this run
  --redact                   Force redaction on
  --headless                 Run without the TUI
  --max-flows <n>            Maximum retained flows [default: 10000]
  --max-body <bytes>         Per-message body cap [default: 262144]
  --help                     Print help
  --version                  Print version

EXAMPLES:
  lens
  lens cert install
  lens cert status
  HTTP_PROXY=http://127.0.0.1:8888 lens run --headless
  lens run --listen 127.0.0.1:8888 --upstream 127.0.0.1:8080
  lens run --protocol postgres --listen 127.0.0.1:15432 --upstream db.example.com:5432 --headless
  lens doctor --check all
";

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_env() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn no_args_defaults_to_run() {
        let output = run(Vec::<String>::new(), &empty_env(), |_| Ok(None), false).unwrap();

        assert!(output.starts_with("lens run"));
        assert!(output.contains("mode: explicit"));
        assert!(output.contains("listen: 127.0.0.1:8888"));
        assert!(output.contains("https: intercept"));
        assert!(output.contains("redaction: enabled"));
    }

    #[test]
    fn run_flags_override_env_file_and_defaults() {
        let mut env_vars = empty_env();
        env_vars.insert("LENS_LISTEN".to_string(), "127.0.0.1:7777".to_string());
        env_vars.insert("LENS_MODE".to_string(), "transparent".to_string());

        let output = run(
            vec![
                "--config",
                "lens.toml",
                "run",
                "--listen",
                "127.0.0.1:9999",
                "--upstream",
                "127.0.0.1:8080",
                "--mode",
                "explicit",
                "--https",
                "passthrough",
                "--reveal",
                "--headless",
                "--max-flows",
                "25",
                "--max-body",
                "128",
            ],
            &env_vars,
            |_| {
                Ok(Some(
                    r#"
listen = "127.0.0.1:6666"
mode = "transparent"
reveal = false
max_flows = 5
max_body = 64
"#
                    .to_string(),
                ))
            },
            false,
        )
        .unwrap();

        assert!(output.contains("listen: 127.0.0.1:9999"));
        assert!(output.contains("upstream: 127.0.0.1:8080"));
        assert!(output.contains("protocol: tcp"));
        assert!(output.contains("mode: explicit"));
        assert!(output.contains("https: passthrough"));
        assert!(output.contains("redaction: revealed"));
        assert!(output.contains("headless: true"));
        assert!(output.contains("max_flows: 25"));
        assert!(output.contains("max_body: 128 bytes"));
    }

    #[test]
    fn env_overrides_file_values() {
        let mut env_vars = empty_env();
        env_vars.insert("LENS_MAX_FLOWS".to_string(), "40".to_string());

        let output = run(
            vec!["--config", "lens.toml", "run"],
            &env_vars,
            |_| Ok(Some("max_flows = 10".to_string())),
            false,
        )
        .unwrap();

        assert!(output.contains("max_flows: 40"));
    }

    #[test]
    fn help_output_has_stable_contract() {
        let output = run(
            vec!["--help", "--config", "missing.conf"],
            &empty_env(),
            |_| Err(CliError::ConfigNotFound(PathBuf::from("missing.conf"))),
            false,
        )
        .unwrap();

        assert!(output.contains("USAGE:"));
        assert!(output.contains("COMMANDS:"));
        assert!(output.contains("lens run --listen 127.0.0.1:8888 --upstream 127.0.0.1:8080"));
    }

    #[test]
    fn explicit_config_path_must_exist() {
        let error = run(
            vec!["run", "--config", "missing.conf"],
            &empty_env(),
            |_| Ok(None),
            false,
        )
        .unwrap_err();

        assert_eq!(
            error,
            CliError::ConfigNotFound(PathBuf::from("missing.conf"))
        );
    }

    #[test]
    fn doctor_reports_platform_and_trust_state() {
        let output = run(
            vec!["doctor", "--listen", "127.0.0.1:8888", "--check", "all"],
            &empty_env(),
            |_| Ok(None),
            false,
        )
        .unwrap();

        assert!(output.contains("lens doctor"));
        assert!(output.contains("config: ok"));
        assert!(output.contains("network: ok; bind address 127.0.0.1:8888"));
        assert!(output.contains("trust:"));
        assert!(output.contains("material="));
        assert!(output.contains("platform:"));
    }

    #[test]
    fn run_without_fixed_upstream_selects_http_targets() {
        let output = run(
            vec!["run", "--listen", "127.0.0.1:0", "--mode", "explicit"],
            &empty_env(),
            |_| Ok(None),
            false,
        )
        .unwrap();

        assert!(output.contains("upstream: selected from HTTP request"));
        assert!(output.contains("protocol: http"));
        assert!(output.contains("https: intercept"));
    }

    #[test]
    fn postgres_mode_accepts_a_hostname_upstream() {
        let output = run(
            vec![
                "run",
                "--protocol",
                "postgres",
                "--listen",
                "127.0.0.1:15432",
                "--upstream",
                "db.example.com:5432",
                "--headless",
            ],
            &empty_env(),
            |_| Ok(None),
            false,
        )
        .unwrap();

        assert!(output.contains("protocol: postgres"));
        assert!(output.contains("upstream: db.example.com:5432"));
        assert_eq!(
            parse_endpoint("[::1]:5432").unwrap(),
            Endpoint::new("::1", 5432)
        );
    }

    #[test]
    fn postgres_mode_requires_an_upstream() {
        let error = run(
            vec!["run", "--protocol", "postgres"],
            &empty_env(),
            |_| Ok(None),
            false,
        )
        .unwrap_err();

        assert_eq!(
            error,
            CliError::InvalidValue {
                name: "--protocol".to_string(),
                value: "postgres".to_string(),
                expected: "--upstream host:port for fixed-target protocols".to_string(),
            }
        );
    }

    #[test]
    fn certificate_commands_have_a_non_mutating_dry_run() {
        let output = run(vec!["cert", "install"], &empty_env(), |_| Ok(None), false).unwrap();

        assert!(output.starts_with("lens cert install"));
        assert!(output.contains("dry-run; no trust-store changes made"));
    }

    #[test]
    fn invalid_certificate_action_is_rejected() {
        let error = run(vec!["cert", "rotate"], &empty_env(), |_| Ok(None), false).unwrap_err();

        assert_eq!(
            error,
            CliError::InvalidValue {
                name: "cert action".to_string(),
                value: "rotate".to_string(),
                expected: "install, uninstall, or status".to_string(),
            }
        );
    }

    #[test]
    fn invalid_listen_address_is_rejected() {
        let error = run(
            vec!["run", "--listen", "not-an-address"],
            &empty_env(),
            |_| Ok(None),
            false,
        )
        .unwrap_err();

        assert_eq!(
            error,
            CliError::InvalidValue {
                name: "--listen".to_string(),
                value: "not-an-address".to_string(),
                expected: "addr:port, for example 127.0.0.1:8888".to_string()
            }
        );
    }
}
