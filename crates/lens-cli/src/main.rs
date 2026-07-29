use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lens_core::{Endpoint, RunId};
use lens_platform::{
    redirect_context_from_raw_socket, PlatformKind, ProcessResolver, TransparentConfig,
    TransparentController, TrustState, UserTrustStore,
};
use lens_proxy::{
    FixedProtocol, FlowIdentityLookup, FlowTargetLookup, HttpsMode, ListenerConfig,
    ObservationSink, ProxyListener, ProxyMode as ProxyListenMode, ProxyRuntimeConfig, ProxyServer,
    TlsInterception,
};
use lens_replay::{execute as execute_replay, load_plan, ReplayPolicy, ReplaySelection};
use lens_store::{StoreActor, StoreSnapshot};
use lens_tls::{CaPaths, CaStatus, CertificateAuthority};
use lens_tui::TuiConfig;

const DEFAULT_LISTEN: &str = "127.0.0.1:8888";
const DEFAULT_MODE: ProxyMode = ProxyMode::Explicit;
const DEFAULT_MAX_FLOWS: usize = 10_000;
const DEFAULT_MAX_BODY: usize = 262_144;
const DEFAULT_HTTPS_MODE: HttpsMode = HttpsMode::Intercept;
const DEFAULT_REFRESH_MS: usize = 250;

fn main() -> ExitCode {
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
    if matches!(parsed.command, Command::Quickstart) {
        return Ok(render_quickstart());
    }
    if matches!(parsed.command, Command::Replay) {
        return run_replay_command(&parsed.replay, bind_listener);
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
        Command::Help | Command::Version | Command::Quickstart | Command::Replay => {
            unreachable!("handled before configuration")
        }
    }
}

fn run_replay_command(options: &ReplayArgs, allow_network: bool) -> Result<String, CliError> {
    let input = options
        .input
        .as_deref()
        .expect("replay input validated during parsing");
    let target = options
        .target
        .as_deref()
        .expect("replay target validated during parsing");
    let selection = ReplaySelection::new(options.flow, options.request)
        .map_err(|error| CliError::Replay(error.to_string()))?;
    let plan = load_plan(input, selection).map_err(|error| CliError::Replay(error.to_string()))?;
    let target_url = plan
        .preview_target_url(target)
        .map_err(|error| CliError::Replay(error.to_string()))?;
    let header_names = if plan.headers.is_empty() {
        "none".to_string()
    } else {
        plan.header_names().join(", ")
    };
    let warnings = [
        plan.redacted.then_some("redacted placeholders are present"),
        (plan.sensitivity == "secret").then_some("capture contains revealed secrets"),
        plan.truncated
            .then_some("request is truncated and cannot execute"),
        plan.legacy_text_encoding
            .then_some("legacy text-only capture is preview-only"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("; ");

    let preview = format!(
        "lens replay\nmode: preview\ninput: {}\nflow: {}\nrequest: {}\nmethod: {}\ntarget: {}\nheaders: {}\nbody: {} bytes\nsensitivity: {}\ncaptured_status: {}\nwarnings: {}",
        input.display(),
        plan.flow_id,
        plan.request,
        plan.method,
        target_url,
        header_names,
        plan.body.len(),
        plan.sensitivity,
        plan.captured_status()
            .map_or_else(|| "unavailable".to_string(), |status| status.to_string()),
        if warnings.is_empty() { "none" } else { &warnings }
    );
    if !options.execute || !allow_network {
        return Ok(format!(
            "{preview}\nnetwork: not sent; pass --execute after reviewing the plan"
        ));
    }

    let report = execute_replay(
        &plan,
        target,
        ReplayPolicy {
            allow_unsafe: options.allow_unsafe,
            allow_secrets: options.allow_secrets,
            allow_redacted: options.allow_redacted,
            allow_remote: options.allow_remote,
            timeout: Duration::from_millis(options.timeout_ms),
        },
    )
    .map_err(|error| CliError::Replay(error.to_string()))?;
    Ok(format!(
        "{preview}\nmode: executed\nstatus: {}\nelapsed_ms: {}\nstatus_compare: {}\nbody_compare: {}\nresponse_truncated: {}\nredirects: not followed",
        report.status,
        report.elapsed_ms,
        report.status_match,
        report.body_match,
        report.response_truncated
    ))
}

/// Runs an HTTP or fixed-upstream forwarding session until Ctrl-C.
fn run_proxy_session(config: &ResolvedConfig, bind_listener: bool) -> Result<String, CliError> {
    let plan = render_run_plan(config);
    if !bind_listener {
        return Ok(plan);
    }

    let interactive = !config.headless && lens_tui::stdout_is_terminal();
    if !interactive {
        let _ = tracing_subscriber::fmt().with_target(false).try_init();
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
    let runtime_config = if config.mode == ProxyMode::Transparent {
        ProxyRuntimeConfig::transparent(match config.protocol {
            TrafficProtocol::Tcp => FixedProtocol::Tcp,
            TrafficProtocol::Postgres => FixedProtocol::Postgres,
            TrafficProtocol::Http => FixedProtocol::Http1,
        })
    } else {
        match config.protocol {
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
        }
    };
    let (observer, observations) = ObservationSink::channel(1024);
    let (store_actor, store_handle) = StoreActor::with_inspection(
        config.max_flows,
        RunId::new(1),
        config.max_body,
        config.reveal,
    );
    let mut server = runtime
        .block_on(async { ProxyServer::from_listener(listener, runtime_config) })
        .map_err(|error| CliError::ProxyFailed(error.to_string()))?;
    let process_resolver = ProcessResolver::current(config.service.clone());
    let identity_lookup = FlowIdentityLookup::new(move |client, listener| {
        process_resolver.resolve(client, listener).identity
    });
    server = server
        .with_observer(observer.clone())
        .with_identity_lookup(identity_lookup);
    let _transparent_session = if config.mode == ProxyMode::Transparent {
        let generation = 1_u32;
        let native_config = TransparentConfig::new(
            u64::from(std::process::id()),
            local_addr.port(),
            generation,
            transparent_nonce(),
        )
        .map_err(|error| CliError::ProxyFailed(error.to_string()))?;
        server = server.with_target_lookup(transparent_target_lookup(u64::from(generation))?);
        Some(
            TransparentController::current()
                .activate(native_config)
                .map_err(|error| CliError::ProxyFailed(error.to_string()))?,
        )
    } else {
        None
    };

    let (stats, snapshot) = if interactive {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = runtime.spawn(server.run_until(shutdown_rx));
        let store_task = runtime.spawn(store_actor.run(observations));
        let tui_result = lens_tui::run(
            &store_handle,
            TuiConfig::new(
                Duration::from_millis(config.refresh_ms as u64),
                config.reveal,
            ),
            || observer.dropped(),
        );
        let _ = shutdown_tx.send(());
        drop(observer);
        let session = runtime
            .block_on(async move {
                let stats = server_task.await.map_err(|error| {
                    lens_core::CoreError::operation_failed("proxy task", error.to_string())
                })??;
                store_task.await.map_err(|error| {
                    lens_core::CoreError::operation_failed("store actor", error.to_string())
                })?;
                Ok::<_, lens_core::CoreError>((stats, store_handle.snapshot()))
            })
            .map_err(|error| CliError::ProxyFailed(error.to_string()))?;
        tui_result.map_err(|error| CliError::Terminal(error.to_string()))?;
        session
    } else {
        println!("{plan}\nbound: {local_addr}\nstatus: forwarding; press Ctrl-C to stop");
        drop(observer);
        runtime
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
            .map_err(|error| CliError::ProxyFailed(error.to_string()))?
    };

    let export = config
        .export
        .as_deref()
        .map(|path| write_snapshot(path, config.export_format, &snapshot))
        .transpose()?;

    let mut output = format!(
        "lens stopped\nbound: {}\naccepted: {}\ncompleted: {}\nfailed: {}\nobservations_dropped: {}\nevicted: {}\nbytes: client->upstream {}, upstream->client {}",
        local_addr,
        stats.accepted,
        stats.completed,
        stats.failed,
        stats.observations_dropped,
        snapshot.evicted,
        stats.client_to_upstream_bytes,
        stats.upstream_to_client_bytes
    );
    if let Some(path) = export {
        output.push_str(&format!(
            "\nexport: {} ({})",
            path.display(),
            config.export_format
        ));
    }
    if !interactive {
        for flow in snapshot.flows {
            output.push('\n');
            output.push_str(&flow.to_json_line());
        }
    }
    Ok(output)
}

fn transparent_nonce() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nonce =
        elapsed.as_secs() ^ u64::from(elapsed.subsec_nanos()) ^ u64::from(std::process::id());
    nonce.max(1)
}

fn transparent_target_lookup(expected_generation: u64) -> Result<FlowTargetLookup, CliError> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;

        Ok(FlowTargetLookup::new(move |stream| {
            let context =
                redirect_context_from_raw_socket(stream.as_raw_socket()).map_err(|error| {
                    lens_core::CoreError::operation_failed("WFP context", error.to_string())
                })?;
            if context.generation != expected_generation {
                return Err(lens_core::CoreError::operation_failed(
                    "WFP context",
                    "redirect generation does not match the active session",
                ));
            }
            Ok(Endpoint::new(
                context.destination.ip().to_string(),
                context.destination.port(),
            ))
        }))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (expected_generation, redirect_context_from_raw_socket(0));
        Err(CliError::ProxyFailed(
            "native transparent activation is currently available only on Windows".to_string(),
        ))
    }
}

fn write_snapshot(
    path: &Path,
    format: ExportFormat,
    snapshot: &StoreSnapshot,
) -> Result<PathBuf, CliError> {
    let contents = match format {
        ExportFormat::Json => snapshot.to_json(),
        ExportFormat::Jsonl => snapshot.to_jsonl(),
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| CliError::Export {
            path: path.to_path_buf(),
            source: error.to_string(),
        })?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|error| CliError::Export {
            path: path.to_path_buf(),
            source: error.to_string(),
        })?;
    Ok(path.to_path_buf())
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
    replay: ReplayArgs,
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
        let mut replay = ReplayArgs::default();
        let mut args = raw_args.into_iter().map(Into::into).peekable();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "run" => set_command(&mut command, Command::Run)?,
                "replay" => set_command(&mut command, Command::Replay)?,
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
                "quickstart" => set_command(&mut command, Command::Quickstart)?,
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
                "--service" => {
                    flags.service = Some(
                        args.next()
                            .ok_or_else(|| CliError::MissingValue("--service".to_string()))?,
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
                "--refresh-ms" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--refresh-ms".to_string()))?;
                    flags.refresh_ms = Some(parse_positive_usize("--refresh-ms", &value)?);
                }
                "--export" => {
                    flags.export = Some(
                        args.next()
                            .ok_or_else(|| CliError::MissingValue("--export".to_string()))?,
                    );
                }
                "--export-format" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--export-format".to_string()))?;
                    flags.export_format = Some(value.parse()?);
                }
                "--allow-secret-export" => flags.allow_secret_export = Some(true),
                "--input" => {
                    replay.used = true;
                    replay.input =
                        Some(PathBuf::from(args.next().ok_or_else(|| {
                            CliError::MissingValue("--input".to_string())
                        })?));
                }
                "--flow" => {
                    replay.used = true;
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--flow".to_string()))?;
                    replay.flow = Some(parse_positive_u64("--flow", &value)?);
                }
                "--request" => {
                    replay.used = true;
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--request".to_string()))?;
                    replay.request = parse_positive_usize("--request", &value)?;
                }
                "--target" => {
                    replay.used = true;
                    replay.target = Some(
                        args.next()
                            .ok_or_else(|| CliError::MissingValue("--target".to_string()))?,
                    );
                }
                "--execute" => {
                    replay.used = true;
                    replay.execute = true;
                }
                "--dry-run" => {
                    replay.used = true;
                    replay.execute = false;
                }
                "--allow-unsafe" => {
                    replay.used = true;
                    replay.allow_unsafe = true;
                }
                "--allow-secrets" => {
                    replay.used = true;
                    replay.allow_secrets = true;
                }
                "--allow-redacted" => {
                    replay.used = true;
                    replay.allow_redacted = true;
                }
                "--allow-remote" => {
                    replay.used = true;
                    replay.allow_remote = true;
                }
                "--timeout-ms" => {
                    replay.used = true;
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--timeout-ms".to_string()))?;
                    replay.timeout_ms = parse_positive_u64("--timeout-ms", &value)?;
                }
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
        if matches!(command, Command::Replay) {
            if replay.input.is_none() {
                return Err(CliError::MissingValue("--input".to_string()));
            }
            if replay.target.is_none() {
                return Err(CliError::MissingValue("--target".to_string()));
            }
        } else if replay.used {
            return Err(CliError::OptionRequiresCommand {
                option: "replay options".to_string(),
                command: "replay".to_string(),
            });
        }

        Ok(Self {
            command,
            config_path,
            flags,
            replay,
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
    Replay,
    Doctor { check: DoctorCheck },
    Cert { action: CertAction },
    Quickstart,
    Help,
    Version,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayArgs {
    input: Option<PathBuf>,
    flow: Option<u64>,
    request: usize,
    target: Option<String>,
    execute: bool,
    allow_unsafe: bool,
    allow_secrets: bool,
    allow_redacted: bool,
    allow_remote: bool,
    timeout_ms: u64,
    used: bool,
}

impl Default for ReplayArgs {
    fn default() -> Self {
        Self {
            input: None,
            flow: None,
            request: 1,
            target: None,
            execute: false,
            allow_unsafe: false,
            allow_secrets: false,
            allow_redacted: false,
            allow_remote: false,
            timeout_ms: 10_000,
            used: false,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum ExportFormat {
    Json,
    #[default]
    Jsonl,
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
        })
    }
}

impl std::str::FromStr for ExportFormat {
    type Err = CliError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "json" => Ok(Self::Json),
            "jsonl" => Ok(Self::Jsonl),
            _ => Err(CliError::InvalidValue {
                name: "--export-format".to_string(),
                value: value.to_string(),
                expected: "json or jsonl".to_string(),
            }),
        }
    }
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
    Transparent,
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
            "transparent" => Ok(Self::Transparent),
            _ => Err(CliError::InvalidValue {
                name: "--check".to_string(),
                value: value.to_string(),
                expected: "all, config, network, trust, platform, or transparent".to_string(),
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
    service: Option<String>,
    protocol: Option<TrafficProtocol>,
    mode: Option<ProxyMode>,
    https_mode: Option<HttpsMode>,
    reveal: Option<bool>,
    max_flows: Option<usize>,
    max_body: Option<usize>,
    headless: Option<bool>,
    refresh_ms: Option<usize>,
    export: Option<String>,
    export_format: Option<ExportFormat>,
    allow_secret_export: Option<bool>,
}

impl ConfigValues {
    fn from_env(env_vars: &BTreeMap<String, String>) -> Self {
        Self {
            listen: env_vars.get("LENS_LISTEN").cloned(),
            upstream: env_vars.get("LENS_UPSTREAM").cloned(),
            service: env_vars.get("LENS_SERVICE").cloned(),
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
            refresh_ms: env_vars
                .get("LENS_REFRESH_MS")
                .and_then(|value| parse_positive_usize("LENS_REFRESH_MS", value).ok()),
            export: env_vars.get("LENS_EXPORT").cloned(),
            export_format: env_vars
                .get("LENS_EXPORT_FORMAT")
                .and_then(|value| value.parse().ok()),
            allow_secret_export: env_vars
                .get("LENS_ALLOW_SECRET_EXPORT")
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
    service: Option<String>,
    protocol: TrafficProtocol,
    mode: ProxyMode,
    https_mode: HttpsMode,
    reveal: bool,
    max_flows: usize,
    max_body: usize,
    headless: bool,
    refresh_ms: usize,
    export: Option<PathBuf>,
    export_format: ExportFormat,
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
        let service = flags
            .and_then(|values| values.service.clone())
            .or_else(|| env_vars.and_then(|values| values.service.clone()))
            .or_else(|| file.and_then(|values| values.service.clone()))
            .map(validate_service_label)
            .transpose()?;
        let requested_protocol = flags
            .and_then(|values| values.protocol)
            .or_else(|| env_vars.and_then(|values| values.protocol))
            .or_else(|| file.and_then(|values| values.protocol));
        let protocol = requested_protocol.unwrap_or(if upstream_endpoint.is_some() {
            TrafficProtocol::Tcp
        } else {
            TrafficProtocol::Http
        });
        let mode = pick(
            flags.and_then(|values| values.mode),
            env_vars.and_then(|values| values.mode),
            file.and_then(|values| values.mode),
            DEFAULT_MODE,
        );
        if mode == ProxyMode::Transparent && !listen_addr.ip().is_loopback() {
            return Err(CliError::InvalidValue {
                name: "--listen".to_string(),
                value: listen.clone(),
                expected: "a loopback address for transparent mode".to_string(),
            });
        }
        match (mode, protocol, upstream_endpoint.is_some()) {
            (ProxyMode::Transparent, _, true) => {
                return Err(CliError::InvalidValue {
                    name: "--upstream".to_string(),
                    value: upstream.clone().unwrap_or_default(),
                    expected: "no fixed upstream in transparent mode".to_string(),
                });
            }
            (ProxyMode::Explicit, TrafficProtocol::Http, true) => {
                return Err(CliError::InvalidValue {
                    name: "--upstream".to_string(),
                    value: upstream.clone().unwrap_or_default(),
                    expected: "no fixed upstream when --protocol http is selected".to_string(),
                });
            }
            (ProxyMode::Explicit, TrafficProtocol::Tcp | TrafficProtocol::Postgres, false) => {
                return Err(CliError::InvalidValue {
                    name: "--protocol".to_string(),
                    value: protocol.to_string(),
                    expected: "--upstream host:port for fixed-target protocols".to_string(),
                });
            }
            _ => {}
        }
        let reveal = pick(
            flags.and_then(|values| values.reveal),
            env_vars.and_then(|values| values.reveal),
            file.and_then(|values| values.reveal),
            false,
        );
        let export = flags
            .and_then(|values| values.export.clone())
            .or_else(|| env_vars.and_then(|values| values.export.clone()))
            .or_else(|| file.and_then(|values| values.export.clone()))
            .map(PathBuf::from);
        let allow_secret_export = pick(
            flags.and_then(|values| values.allow_secret_export),
            env_vars.and_then(|values| values.allow_secret_export),
            file.and_then(|values| values.allow_secret_export),
            false,
        );
        if reveal && export.is_some() && !allow_secret_export {
            return Err(CliError::InvalidValue {
                name: "--export".to_string(),
                value: export
                    .as_deref()
                    .map_or_else(String::new, |path| path.display().to_string()),
                expected: "--allow-secret-export when --reveal is active".to_string(),
            });
        }

        Ok(Self {
            listen,
            listen_addr,
            upstream,
            upstream_endpoint,
            service,
            protocol,
            mode,
            https_mode: pick(
                flags.and_then(|values| values.https_mode),
                env_vars.and_then(|values| values.https_mode),
                file.and_then(|values| values.https_mode),
                DEFAULT_HTTPS_MODE,
            ),
            reveal,
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
            refresh_ms: pick(
                flags.and_then(|values| values.refresh_ms),
                env_vars.and_then(|values| values.refresh_ms),
                file.and_then(|values| values.refresh_ms),
                DEFAULT_REFRESH_MS,
            )
            .clamp(50, 2_000),
            export,
            export_format: pick(
                flags.and_then(|values| values.export_format),
                env_vars.and_then(|values| values.export_format),
                file.and_then(|values| values.export_format),
                ExportFormat::default(),
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
            "service" => values.service = Some(value.to_string()),
            "protocol" => values.protocol = value.parse().ok(),
            "mode" => values.mode = value.parse().ok(),
            "https" => values.https_mode = parse_https_mode(value).ok(),
            "reveal" => values.reveal = parse_bool(value).ok(),
            "max_flows" => values.max_flows = parse_positive_usize(key, value).ok(),
            "max_body" => values.max_body = parse_positive_usize(key, value).ok(),
            "headless" => values.headless = parse_bool(value).ok(),
            "refresh_ms" => values.refresh_ms = parse_positive_usize(key, value).ok(),
            "export" => values.export = Some(value.to_string()),
            "export_format" => values.export_format = value.parse().ok(),
            "allow_secret_export" => values.allow_secret_export = parse_bool(value).ok(),
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

fn validate_service_label(value: String) -> Result<String, CliError> {
    let value = value.trim().to_string();
    if value.is_empty() || value.chars().count() > 128 || value.chars().any(char::is_control) {
        return Err(CliError::InvalidValue {
            name: "--service".to_string(),
            value,
            expected: "a non-empty label of at most 128 printable characters".to_string(),
        });
    }
    Ok(value)
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

fn parse_positive_u64(name: &str, value: &str) -> Result<u64, CliError> {
    let parsed = value.parse::<u64>().map_err(|_| CliError::InvalidValue {
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
        "lens run\nmode: {}\nprotocol: {}\nlisten: {}\nupstream: {}\nservice: {}\nhttps: {}\nredaction: {}\nheadless: {}\nrefresh: {} ms\nexport: {} ({})\nmax_flows: {}\nmax_body: {} bytes",
        config.mode,
        config.protocol,
        config.listen,
        config
            .upstream
            .as_deref()
            .unwrap_or(if config.mode == ProxyMode::Transparent {
                "selected from native redirect context"
            } else {
                "selected from HTTP request"
            }),
        config.service.as_deref().unwrap_or("auto-detect"),
        config.https_mode,
        if config.reveal { "revealed" } else { "enabled" },
        config.headless,
        config.refresh_ms,
        config
            .export
            .as_deref()
            .map_or("disabled".to_string(), |path| path.display().to_string()),
        config.export_format,
        config.max_flows,
        config.max_body
    )
}

fn render_quickstart() -> String {
    "lens quickstart\n\
1. Check readiness:        lens doctor --check all\n\
2. Trust HTTPS inspection: lens cert install\n\
3. Start the live TUI:     lens run --listen 127.0.0.1:8888\n\
4. Point HTTP clients at:  HTTP_PROXY=http://127.0.0.1:8888\n\
                           HTTPS_PROXY=http://127.0.0.1:8888\n\
5. PostgreSQL locally:     lens run --protocol postgres --listen 127.0.0.1:15432 --upstream 127.0.0.1:5432\n\
6. Safe diagnostic file:   lens run --headless --export lens-flows.jsonl\n\n\
Windows transparent TCP (signed driver required):\n\
                           lens run --mode transparent --protocol http --listen 127.0.0.1:8888\n\n\
TUI controls: j/k select, p protocol, s status, l latency, / search, x clear, q quit.\n\
Redaction is always on unless --reveal is explicit. Secret exports additionally require --allow-secret-export."
        .to_string()
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
    if matches!(check, DoctorCheck::All | DoctorCheck::Transparent) {
        let status = TransparentController::current().status();
        lines.push(format!(
            "transparent: {}; backend={}; admin={}; {}",
            status.phase,
            status.backend,
            if status.requires_admin {
                "required"
            } else {
                "not-required"
            },
            status.detail
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
    Terminal(String),
    Replay(String),
    Export {
        path: PathBuf,
        source: String,
    },
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
            Self::Terminal(source) => write!(f, "lens: terminal UI failed: {source}"),
            Self::Replay(source) => write!(f, "lens replay: {source}"),
            Self::Export { path, source } => {
                write!(
                    f,
                    "lens: failed to safely export {}: {source}",
                    path.display()
                )
            }
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
  replay     Preview or explicitly execute one captured HTTP/1 request
  doctor     Check config, platform, trust, and network readiness
  cert       Manage the explicit local CA: install, uninstall, or status
  quickstart Show the first-run HTTP, HTTPS, PostgreSQL, and export path

GLOBAL OPTIONS:
  --config <path>            Read simple key = value configuration
  --listen <addr:port>       Listen address [default: 127.0.0.1:8888]
  --upstream <host:port>     Fixed target for TCP or PostgreSQL mode
  --service <name>           Override the auto-detected client service label
  --protocol <http|tcp|postgres>
                             Protocol to route and inspect [auto-detected from upstream]
  --mode <explicit|transparent>
                             How traffic reaches Lens [default: explicit]
  --https <intercept|passthrough|reject>
                             CONNECT behavior [default: intercept]
  --reveal                   Disable redaction for this run
  --redact                   Force redaction on
  --headless                 Run without the TUI
  --refresh-ms <n>           TUI refresh interval, clamped to 50-2000 [default: 250]
  --export <path>            Safely create a snapshot file when Lens stops
  --export-format <json|jsonl>
                             Snapshot format [default: jsonl]
  --allow-secret-export      Required with both --reveal and --export
  --max-flows <n>            Maximum retained flows [default: 10000]
  --max-body <bytes>         Per-message body cap [default: 262144]
  --help                     Print help
  --version                  Print version

REPLAY OPTIONS:
  --input <path>             JSON or JSONL capture [required]
  --flow <id>                Flow ID [required when multiple HTTP flows exist]
  --request <n>              One-based request in the flow [default: 1]
  --target <origin>          Explicit http:// or https:// replay origin [required]
  --execute                  Send after preview validation [default: preview only]
  --allow-unsafe             Permit methods that may change server state
  --allow-secrets            Permit capture data produced with --reveal
  --allow-redacted           Permit literal [REDACTED] placeholders
  --allow-remote             Permit a non-loopback target
  --timeout-ms <n>           Replay deadline [default: 10000]

EXAMPLES:
  lens
  lens cert install
  lens cert status
  lens quickstart
  lens replay --input lens-flows.jsonl --flow 1 --target http://127.0.0.1:8080
  HTTP_PROXY=http://127.0.0.1:8888 lens run --headless
  lens run --listen 127.0.0.1:8888 --upstream 127.0.0.1:8080
  lens run --protocol postgres --listen 127.0.0.1:15432 --upstream db.example.com:5432 --headless
  lens doctor --check all
";

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
        assert!(output.contains("quickstart"));
        assert!(output.contains("replay"));
        assert!(output.contains("lens run --listen 127.0.0.1:8888 --upstream 127.0.0.1:8080"));
    }

    #[test]
    fn quickstart_does_not_require_configuration() {
        let output = run(
            vec!["quickstart", "--config", "missing.conf"],
            &empty_env(),
            |_| Err(CliError::ConfigNotFound(PathBuf::from("missing.conf"))),
            false,
        )
        .unwrap();

        assert!(output.contains("lens doctor --check all"));
        assert!(output.contains("lens cert install"));
        assert!(output.contains("TUI controls:"));
    }

    #[test]
    fn replay_defaults_to_a_secret_safe_network_free_preview() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("flows.jsonl");
        fs::write(
            &path,
            r#"{"schema_version":"1.1","flow_id":7,"protocol":"http1","messages":[{"direction":"client_to_server","summary":"GET /health HTTP/1.1","body":"X-Test: private\r\n\r\n","wire_base64":"WC1UZXN0OiBwcml2YXRlDQoNCg==","truncated":false,"sensitivity":"public"},{"direction":"server_to_client","summary":"HTTP/1.1 200 OK","body":"Content-Length: 2\r\n\r\nok","wire_base64":"Q29udGVudC1MZW5ndGg6IDINCg0Kb2s=","truncated":false,"sensitivity":"public"}]}"#,
        )
        .unwrap();

        let output = run(
            vec![
                "replay".to_string(),
                "--input".to_string(),
                path.display().to_string(),
                "--target".to_string(),
                "http://127.0.0.1:8080".to_string(),
            ],
            &empty_env(),
            |_| Err(CliError::ConfigNotFound(PathBuf::from("must-not-read"))),
            false,
        )
        .unwrap();

        assert!(output.contains("mode: preview"));
        assert!(output.contains("network: not sent"));
        assert!(output.contains("headers: X-Test"));
        assert!(!output.contains("private"));
        assert!(output.contains("captured_status: 200"));
    }

    #[test]
    fn replay_requires_an_input_and_explicit_target() {
        assert_eq!(
            run(vec!["replay"], &empty_env(), |_| Ok(None), false).unwrap_err(),
            CliError::MissingValue("--input".to_string())
        );
        assert_eq!(
            run(
                vec!["replay", "--input", "capture.jsonl"],
                &empty_env(),
                |_| Ok(None),
                false,
            )
            .unwrap_err(),
            CliError::MissingValue("--target".to_string())
        );
    }

    #[test]
    fn replay_options_are_rejected_for_other_commands() {
        let error = run(
            vec!["doctor", "--target", "http://127.0.0.1"],
            &empty_env(),
            |_| Ok(None),
            false,
        )
        .unwrap_err();
        assert!(matches!(error, CliError::OptionRequiresCommand { .. }));
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
        assert!(output.contains("transparent:"));
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
    fn transparent_mode_uses_native_destination_without_an_upstream() {
        let output = run(
            vec!["run", "--mode", "transparent", "--protocol", "tcp"],
            &empty_env(),
            |_| Ok(None),
            false,
        )
        .unwrap();

        assert!(output.contains("mode: transparent"));
        assert!(output.contains("protocol: tcp"));
        assert!(output.contains("upstream: selected from native redirect context"));
    }

    #[test]
    fn refresh_is_bounded_and_secret_export_needs_two_opt_ins() {
        let output = run(
            vec!["run", "--refresh-ms", "1"],
            &empty_env(),
            |_| Ok(None),
            false,
        )
        .unwrap();
        assert!(output.contains("refresh: 50 ms"));

        let error = run(
            vec!["run", "--reveal", "--export", "flows.jsonl"],
            &empty_env(),
            |_| Ok(None),
            false,
        )
        .unwrap_err();
        assert_eq!(
            error,
            CliError::InvalidValue {
                name: "--export".to_string(),
                value: "flows.jsonl".to_string(),
                expected: "--allow-secret-export when --reveal is active".to_string(),
            }
        );
    }

    #[test]
    fn snapshot_export_refuses_to_overwrite() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("flows.json");
        write_snapshot(&path, ExportFormat::Json, &StoreSnapshot::default()).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "{\"evicted\":0,\"flows\":[]}\n");

        let error =
            write_snapshot(&path, ExportFormat::Json, &StoreSnapshot::default()).unwrap_err();
        assert!(matches!(error, CliError::Export { .. }));
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
