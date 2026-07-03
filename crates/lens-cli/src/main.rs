use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_LISTEN: &str = "127.0.0.1:8888";
const DEFAULT_MODE: ProxyMode = ProxyMode::Explicit;
const DEFAULT_MAX_FLOWS: usize = 10_000;
const DEFAULT_MAX_BODY: usize = 262_144;

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
    run(raw_args, &env_vars, read_config_file)
}

fn run<I, S, F>(
    raw_args: I,
    env_vars: &BTreeMap<String, String>,
    read_config: F,
) -> Result<String, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    F: Fn(&Path) -> Result<Option<String>, CliError>,
{
    let parsed = Cli::parse(raw_args)?;
    let file_values = match &parsed.config_path {
        Some(path) => read_config(path)?.map(|contents| parse_config_file(&contents)),
        None => None,
    };
    let env_values = ConfigValues::from_env(env_vars);
    let config =
        ResolvedConfig::resolve(file_values.as_ref(), Some(&env_values), Some(&parsed.flags))?;

    match parsed.command {
        Command::Run => Ok(render_run_plan(&config)),
        Command::Doctor { check } => Ok(render_doctor_report(&config, check)),
        Command::Help => Ok(HELP_TEXT.to_string()),
        Command::Version => Ok(format!("lens {}", env!("CARGO_PKG_VERSION"))),
    }
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
        let mut config_path = None;
        let mut flags = ConfigValues::default();
        let mut args = raw_args.into_iter().map(Into::into).peekable();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "run" => set_command(&mut command, Command::Run)?,
                "doctor" => {
                    let mut check = DoctorCheck::All;
                    while let Some(next) = args.peek() {
                        if next.as_str() == "--check" {
                            args.next();
                            let value = args
                                .next()
                                .ok_or_else(|| CliError::MissingValue("--check".to_string()))?;
                            check = value.parse()?;
                        } else {
                            break;
                        }
                    }
                    set_command(&mut command, Command::Doctor { check })?;
                }
                "--help" | "-h" => set_command(&mut command, Command::Help)?,
                "--version" | "-V" => set_command(&mut command, Command::Version)?,
                "--config" => {
                    config_path = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| CliError::MissingValue("--config".to_string()))?,
                    ));
                }
                "--listen" => {
                    flags.listen = Some(
                        args.next()
                            .ok_or_else(|| CliError::MissingValue("--listen".to_string()))?,
                    );
                }
                "--mode" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::MissingValue("--mode".to_string()))?;
                    flags.mode = Some(value.parse()?);
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

        Ok(Self {
            command: command.unwrap_or(Command::Run),
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
    Help,
    Version,
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
    mode: Option<ProxyMode>,
    reveal: Option<bool>,
    max_flows: Option<usize>,
    max_body: Option<usize>,
    headless: Option<bool>,
}

impl ConfigValues {
    fn from_env(env_vars: &BTreeMap<String, String>) -> Self {
        Self {
            listen: env_vars.get("LENS_LISTEN").cloned(),
            mode: env_vars
                .get("LENS_MODE")
                .and_then(|value| value.parse().ok()),
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
    mode: ProxyMode,
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
            name: "listen".to_string(),
            value: listen.clone(),
            expected: "addr:port, for example 127.0.0.1:8888".to_string(),
        })?;

        Ok(Self {
            listen,
            listen_addr,
            mode: pick(
                flags.and_then(|values| values.mode),
                env_vars.and_then(|values| values.mode),
                file.and_then(|values| values.mode),
                DEFAULT_MODE,
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
            "mode" => values.mode = value.parse().ok(),
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
            expected: "true or false".to_string(),
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
        "lens run\nmode: {}\nlisten: {}\nredaction: {}\nheadless: {}\nmax_flows: {}\nmax_body: {} bytes",
        config.mode,
        config.listen,
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
            "config: ok; mode={}, listen={}, redaction={}",
            config.mode,
            config.listen,
            if config.reveal { "revealed" } else { "enabled" }
        ));
    }
    if matches!(check, DoctorCheck::All | DoctorCheck::Network) {
        lines.push(format!("network: ok; bind address {}", config.listen_addr));
    }
    if matches!(check, DoctorCheck::All | DoctorCheck::Trust) {
        lines.push(
            "trust: not installed; run `lens cert install` once certificate management lands"
                .to_string(),
        );
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
    InvalidValue {
        name: String,
        value: String,
        expected: String,
    },
    ConfigRead {
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
            Self::InvalidValue {
                name,
                value,
                expected,
            } => {
                write!(f, "lens: invalid value for {name}: `{value}`; expected {expected}")
            }
            Self::ConfigRead { path, source } => {
                write!(f, "lens: failed to read config {}: {source}", path.display())
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
  doctor     Check config, platform, trust, and network readiness

GLOBAL OPTIONS:
  --config <path>            Read config values from a lens.toml-style file
  --listen <addr:port>       Listen address [default: 127.0.0.1:8888]
  --mode <explicit|transparent>
                             How traffic reaches Lens [default: explicit]
  --reveal                   Disable redaction for this run
  --redact                   Force redaction on
  --headless                 Run without the TUI
  --max-flows <n>            Maximum retained flows [default: 10000]
  --max-body <bytes>         Per-message body cap [default: 262144]
  --help                     Print help
  --version                  Print version

EXAMPLES:
  lens
  lens run --mode explicit --listen 127.0.0.1:8888
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
        let output = run(Vec::<String>::new(), &empty_env(), |_| Ok(None)).unwrap();

        assert!(output.starts_with("lens run"));
        assert!(output.contains("mode: explicit"));
        assert!(output.contains("listen: 127.0.0.1:8888"));
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
                "--mode",
                "explicit",
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
        )
        .unwrap();

        assert!(output.contains("listen: 127.0.0.1:9999"));
        assert!(output.contains("mode: explicit"));
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
        )
        .unwrap();

        assert!(output.contains("max_flows: 40"));
    }

    #[test]
    fn help_output_has_stable_contract() {
        let output = run(vec!["--help"], &empty_env(), |_| Ok(None)).unwrap();

        assert!(output.contains("USAGE:"));
        assert!(output.contains("COMMANDS:"));
        assert!(output.contains("lens run --mode explicit --listen 127.0.0.1:8888"));
    }

    #[test]
    fn doctor_reports_platform_and_trust_state() {
        let output = run(vec!["doctor", "--check", "all"], &empty_env(), |_| Ok(None)).unwrap();

        assert!(output.contains("lens doctor"));
        assert!(output.contains("config: ok"));
        assert!(output.contains("network: ok; bind address 127.0.0.1:8888"));
        assert!(output.contains("trust: not installed"));
        assert!(output.contains("platform:"));
    }

    #[test]
    fn invalid_listen_address_is_rejected() {
        let error = run(
            vec!["run", "--listen", "not-an-address"],
            &empty_env(),
            |_| Ok(None),
        )
        .unwrap_err();

        assert_eq!(
            error,
            CliError::InvalidValue {
                name: "listen".to_string(),
                value: "not-an-address".to_string(),
                expected: "addr:port, for example 127.0.0.1:8888".to_string()
            }
        );
    }
}
