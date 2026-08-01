//! Capability-limited WebAssembly plugins for Lens.
//!
//! Plugins are explicitly installed and receive only the already-redacted JSON
//! event supplied by the host. ABI v1 deliberately exposes no imports, WASI,
//! filesystem, network, clock, random, or process capability.

use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Current Lens plugin ABI.
pub const ABI_VERSION: u32 = 1;
/// Largest plugin module accepted by the installer and loader.
pub const MAX_MODULE_BYTES: usize = 4 * 1024 * 1024;
/// Largest redacted event copied into one plugin invocation.
pub const MAX_INPUT_BYTES: usize = 256 * 1024;
/// Largest annotation copied out of a plugin invocation.
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024;
/// Maximum guest linear memory per invocation.
pub const MAX_MEMORY_BYTES: usize = 8 * 1024 * 1024;
/// Deterministic CPU budget assigned to one invocation.
pub const FUEL_PER_INVOCATION: u64 = 5_000_000;

const MANIFEST_FILE: &str = "plugin.manifest";
const MODULE_FILE: &str = "plugin.wasm";

/// Metadata persisted beside an installed module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginManifest {
    /// Stable installation name.
    pub name: String,
    /// Publisher-provided semantic version string.
    pub version: String,
    /// Lens ABI required by the module.
    pub abi_version: u32,
    /// Lowercase SHA-256 of the installed module.
    pub sha256: String,
}

impl PluginManifest {
    fn render(&self) -> String {
        format!(
            "name={}\nversion={}\nabi={}\nsha256={}\nmodule={}\n",
            self.name, self.version, self.abi_version, self.sha256, MODULE_FILE
        )
    }

    fn parse(contents: &str) -> Result<Self, PluginError> {
        let value = |key: &str| {
            contents
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{key}=")))
                .ok_or_else(|| PluginError::InvalidManifest(format!("missing {key}")))
        };
        let name = value("name")?.to_string();
        validate_name(&name)?;
        let version = value("version")?.to_string();
        validate_version(&version)?;
        let abi_version = value("abi")?
            .parse::<u32>()
            .map_err(|_| PluginError::InvalidManifest("abi is not an integer".to_string()))?;
        let sha256 = value("sha256")?.to_string();
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PluginError::InvalidManifest(
                "sha256 must contain 64 hexadecimal characters".to_string(),
            ));
        }
        if value("module")? != MODULE_FILE {
            return Err(PluginError::InvalidManifest(
                "module must be plugin.wasm".to_string(),
            ));
        }
        Ok(Self {
            name,
            version,
            abi_version,
            sha256: sha256.to_ascii_lowercase(),
        })
    }
}

/// One bounded annotation emitted by a plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginAnnotation {
    /// Installed plugin name.
    pub plugin: String,
    /// UTF-8 annotation returned by the guest.
    pub value: String,
}

/// Per-event execution summary. Failures are contained to the named plugin.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PluginRunReport {
    /// Successful non-empty annotations.
    pub annotations: Vec<PluginAnnotation>,
    /// Safe failure messages keyed by plugin name.
    pub failures: Vec<(String, String)>,
}

/// Explicit plugin installation directory.
#[derive(Clone, Debug)]
pub struct PluginDirectory {
    root: PathBuf,
}

impl PluginDirectory {
    /// Uses the supplied directory without searching the current working tree.
    #[must_use]
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the configured root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Validates and installs a module. Existing installations are never overwritten.
    pub fn install(
        &self,
        source: &Path,
        name: &str,
        version: &str,
    ) -> Result<PluginManifest, PluginError> {
        validate_name(name)?;
        validate_version(version)?;
        let bytes = read_bounded(source, MAX_MODULE_BYTES)?;
        PluginEngine::new()?.compile(&bytes)?;
        let manifest = PluginManifest {
            name: name.to_string(),
            version: version.to_string(),
            abi_version: ABI_VERSION,
            sha256: sha256(&bytes),
        };
        fs::create_dir_all(&self.root).map_err(|error| PluginError::Io {
            path: self.root.clone(),
            detail: error.to_string(),
        })?;
        let target = self.root.join(name);
        fs::create_dir(&target).map_err(|error| PluginError::Io {
            path: target.clone(),
            detail: if error.kind() == std::io::ErrorKind::AlreadyExists {
                "plugin is already installed; remove it explicitly before reinstalling".to_string()
            } else {
                error.to_string()
            },
        })?;
        let result = (|| {
            write_new(&target.join(MODULE_FILE), &bytes)?;
            write_new(&target.join(MANIFEST_FILE), manifest.render().as_bytes())?;
            Ok(manifest)
        })();
        if result.is_err() {
            let _ = fs::remove_file(target.join(MODULE_FILE));
            let _ = fs::remove_file(target.join(MANIFEST_FILE));
            let _ = fs::remove_dir(&target);
        }
        result
    }

    /// Lists verified installations in deterministic name order.
    pub fn list(&self) -> Result<Vec<PluginManifest>, PluginError> {
        let mut manifests = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(manifests),
            Err(error) => {
                return Err(PluginError::Io {
                    path: self.root.clone(),
                    detail: error.to_string(),
                });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|error| PluginError::Io {
                path: self.root.clone(),
                detail: error.to_string(),
            })?;
            if !entry
                .file_type()
                .map_err(|error| PluginError::Io {
                    path: entry.path(),
                    detail: error.to_string(),
                })?
                .is_dir()
            {
                continue;
            }
            let manifest_path = entry.path().join(MANIFEST_FILE);
            let manifest =
                PluginManifest::parse(&fs::read_to_string(&manifest_path).map_err(|error| {
                    PluginError::Io {
                        path: manifest_path,
                        detail: error.to_string(),
                    }
                })?)?;
            let module_path = entry.path().join(MODULE_FILE);
            let bytes = read_bounded(&module_path, MAX_MODULE_BYTES)?;
            if sha256(&bytes) != manifest.sha256 {
                return Err(PluginError::Integrity {
                    name: manifest.name,
                });
            }
            manifests.push(manifest);
        }
        manifests.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(manifests)
    }

    /// Removes only the two known files and then the empty installation directory.
    pub fn remove(&self, name: &str) -> Result<(), PluginError> {
        validate_name(name)?;
        let target = self.root.join(name);
        for file in [MANIFEST_FILE, MODULE_FILE] {
            let path = target.join(file);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(PluginError::Io {
                        path,
                        detail: error.to_string(),
                    });
                }
            }
        }
        fs::remove_dir(&target).map_err(|error| PluginError::Io {
            path: target,
            detail: error.to_string(),
        })
    }

    /// Loads every verified installation into one host.
    pub fn load(&self) -> Result<PluginHost, PluginError> {
        let engine = PluginEngine::new()?;
        let mut plugins = Vec::new();
        for manifest in self.list()? {
            if manifest.abi_version != ABI_VERSION {
                return Err(PluginError::UnsupportedAbi(manifest.abi_version));
            }
            let bytes = read_bounded(
                &self.root.join(&manifest.name).join(MODULE_FILE),
                MAX_MODULE_BYTES,
            )?;
            let module = engine.compile(&bytes)?;
            plugins.push(LoadedPlugin { manifest, module });
        }
        Ok(PluginHost { engine, plugins })
    }
}

#[derive(Debug)]
struct HostState {
    limits: StoreLimits,
}

#[derive(Clone, Debug)]
struct PluginEngine {
    engine: Engine,
}

impl PluginEngine {
    fn new() -> Result<Self, PluginError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine =
            Engine::new(&config).map_err(|error| PluginError::Runtime(error.to_string()))?;
        Ok(Self { engine })
    }

    fn compile(&self, bytes: &[u8]) -> Result<Module, PluginError> {
        if bytes.len() > MAX_MODULE_BYTES {
            return Err(PluginError::Limit("module exceeds 4 MiB".to_string()));
        }
        let module = Module::new(&self.engine, bytes)
            .map_err(|error| PluginError::InvalidModule(error.to_string()))?;
        if let Some(import) = module.imports().next() {
            return Err(PluginError::ForbiddenImport(format!(
                "{}::{}",
                import.module(),
                import.name()
            )));
        }
        self.validate_abi(&module)?;
        Ok(module)
    }

    fn validate_abi(&self, module: &Module) -> Result<(), PluginError> {
        let mut store = limited_store(&self.engine)?;
        let instance = Instance::new(&mut store, module, &[])
            .map_err(|error| PluginError::Runtime(error.to_string()))?;
        let abi = instance
            .get_typed_func::<(), i32>(&mut store, "lens_abi_version")
            .map_err(|_| PluginError::MissingExport("lens_abi_version"))?;
        let guest_abi = abi
            .call(&mut store, ())
            .map_err(|error| PluginError::Runtime(error.to_string()))?;
        if guest_abi != ABI_VERSION as i32 {
            return Err(PluginError::UnsupportedAbi(guest_abi.max(0) as u32));
        }
        instance
            .get_memory(&mut store, "memory")
            .ok_or(PluginError::MissingExport("memory"))?;
        instance
            .get_typed_func::<i32, i32>(&mut store, "lens_alloc")
            .map_err(|_| PluginError::MissingExport("lens_alloc"))?;
        instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "lens_process")
            .map_err(|_| PluginError::MissingExport("lens_process"))?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct LoadedPlugin {
    manifest: PluginManifest,
    module: Module,
}

/// Loaded capability-free plugins. The host is intentionally independent of the proxy.
#[derive(Clone, Debug)]
pub struct PluginHost {
    engine: PluginEngine,
    plugins: Vec<LoadedPlugin>,
}

impl PluginHost {
    /// Number of loaded modules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Returns true when no plugin is enabled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Runs all plugins against one already-redacted event.
    #[must_use]
    pub fn process(&self, redacted_json: &[u8]) -> PluginRunReport {
        let mut report = PluginRunReport::default();
        if redacted_json.len() > MAX_INPUT_BYTES {
            report.failures.push((
                "host".to_string(),
                "redacted event exceeds the 256 KiB plugin input limit".to_string(),
            ));
            return report;
        }
        for plugin in &self.plugins {
            match self.invoke(plugin, redacted_json) {
                Ok(value) if !value.is_empty() => report.annotations.push(PluginAnnotation {
                    plugin: plugin.manifest.name.clone(),
                    value,
                }),
                Ok(_) => {}
                Err(error) => report
                    .failures
                    .push((plugin.manifest.name.clone(), error.to_string())),
            }
        }
        report
    }

    fn invoke(&self, plugin: &LoadedPlugin, input: &[u8]) -> Result<String, PluginError> {
        let mut store = limited_store(&self.engine.engine)?;
        let instance = Instance::new(&mut store, &plugin.module, &[])
            .map_err(|error| PluginError::Runtime(error.to_string()))?;
        let abi = instance
            .get_typed_func::<(), i32>(&mut store, "lens_abi_version")
            .map_err(|_| PluginError::MissingExport("lens_abi_version"))?;
        let guest_abi = abi
            .call(&mut store, ())
            .map_err(|error| PluginError::Runtime(error.to_string()))?;
        if guest_abi != ABI_VERSION as i32 {
            return Err(PluginError::UnsupportedAbi(guest_abi.max(0) as u32));
        }
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(PluginError::MissingExport("memory"))?;
        let allocate = instance
            .get_typed_func::<i32, i32>(&mut store, "lens_alloc")
            .map_err(|_| PluginError::MissingExport("lens_alloc"))?;
        let process = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "lens_process")
            .map_err(|_| PluginError::MissingExport("lens_process"))?;
        let input_len = i32::try_from(input.len())
            .map_err(|_| PluginError::Limit("plugin input is too large".to_string()))?;
        let input_ptr = allocate
            .call(&mut store, input_len)
            .map_err(|error| PluginError::Runtime(error.to_string()))?;
        let input_offset = usize::try_from(input_ptr)
            .map_err(|_| PluginError::InvalidOutput("negative input pointer".to_string()))?;
        memory
            .write(&mut store, input_offset, input)
            .map_err(|error| PluginError::Runtime(error.to_string()))?;
        let packed = process
            .call(&mut store, (input_ptr, input_len))
            .map_err(|error| PluginError::Runtime(error.to_string()))? as u64;
        let output_ptr = usize::try_from(packed >> 32)
            .map_err(|_| PluginError::InvalidOutput("output pointer overflow".to_string()))?;
        let output_len = usize::try_from(packed & u64::from(u32::MAX))
            .map_err(|_| PluginError::InvalidOutput("output length overflow".to_string()))?;
        if output_len > MAX_OUTPUT_BYTES {
            return Err(PluginError::Limit(
                "plugin output exceeds the 4 KiB limit".to_string(),
            ));
        }
        let mut output = vec![0_u8; output_len];
        memory
            .read(&store, output_ptr, &mut output)
            .map_err(|error| PluginError::InvalidOutput(error.to_string()))?;
        String::from_utf8(output)
            .map_err(|_| PluginError::InvalidOutput("output is not UTF-8".to_string()))
    }
}

fn limited_store(engine: &Engine) -> Result<Store<HostState>, PluginError> {
    let limits = StoreLimitsBuilder::new()
        .memory_size(MAX_MEMORY_BYTES)
        .memories(1)
        .instances(1)
        .tables(1)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(engine, HostState { limits });
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(FUEL_PER_INVOCATION)
        .map_err(|error| PluginError::Runtime(error.to_string()))?;
    Ok(store)
}

/// Plugin installation, validation, or execution failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginError {
    /// Invalid installation name or manifest field.
    InvalidManifest(String),
    /// File operation failure.
    Io { path: PathBuf, detail: String },
    /// Module exceeds a configured resource limit.
    Limit(String),
    /// WebAssembly validation failed.
    InvalidModule(String),
    /// The module requested an ambient capability.
    ForbiddenImport(String),
    /// Required ABI export is absent or has the wrong signature.
    MissingExport(&'static str),
    /// Guest and host ABI versions do not match.
    UnsupportedAbi(u32),
    /// Installed bytes no longer match the manifest digest.
    Integrity { name: String },
    /// Guest trapped or the runtime rejected execution.
    Runtime(String),
    /// Guest returned an invalid result pointer, length, or encoding.
    InvalidOutput(String),
}

impl fmt::Display for PluginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest(detail) => write!(formatter, "invalid plugin metadata: {detail}"),
            Self::Io { path, detail } => {
                write!(formatter, "plugin file {}: {detail}", path.display())
            }
            Self::Limit(detail) => write!(formatter, "plugin resource limit: {detail}"),
            Self::InvalidModule(detail) => {
                write!(formatter, "invalid WebAssembly module: {detail}")
            }
            Self::ForbiddenImport(name) => {
                write!(
                    formatter,
                    "plugin import {name} is forbidden; ABI v1 has no imports"
                )
            }
            Self::MissingExport(name) => write!(formatter, "plugin is missing ABI export {name}"),
            Self::UnsupportedAbi(version) => {
                write!(
                    formatter,
                    "plugin ABI {version} is unsupported; host requires {ABI_VERSION}"
                )
            }
            Self::Integrity { name } => {
                write!(formatter, "plugin {name} failed SHA-256 verification")
            }
            Self::Runtime(detail) => write!(formatter, "plugin execution failed: {detail}"),
            Self::InvalidOutput(detail) => {
                write!(formatter, "plugin returned invalid output: {detail}")
            }
        }
    }
}

impl std::error::Error for PluginError {}

fn validate_name(value: &str) -> Result<(), PluginError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(PluginError::InvalidManifest(
            "name must be 1-64 ASCII letters, digits, '-' or '_'".to_string(),
        ));
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), PluginError> {
    if value.is_empty()
        || value.len() > 64
        || value
            .chars()
            .any(|character| character.is_control() || character == '=')
    {
        return Err(PluginError::InvalidManifest(
            "version must be 1-64 printable characters without '='".to_string(),
        ));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, PluginError> {
    let metadata = fs::metadata(path).map_err(|error| PluginError::Io {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(PluginError::Io {
            path: path.to_path_buf(),
            detail: "not a regular file".to_string(),
        });
    }
    if metadata.len() > limit as u64 {
        return Err(PluginError::Limit(format!(
            "{} exceeds the {} byte limit",
            path.display(),
            limit
        )));
    }
    fs::read(path).map_err(|error| PluginError::Io {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), PluginError> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| PluginError::Io {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
    file.write_all(bytes).map_err(|error| PluginError::Io {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

    fn echo_module() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (memory (export "memory") 1 128)
                (global $next (mut i32) (i32.const 4096))
                (func (export "lens_abi_version") (result i32) i32.const 1)
                (func (export "lens_alloc") (param $len i32) (result i32)
                  (local $ptr i32)
                  global.get $next
                  local.tee $ptr
                  local.get $len
                  i32.add
                  global.set $next
                  local.get $ptr)
                (func (export "lens_process") (param $ptr i32) (param $len i32) (result i64)
                  local.get $ptr
                  i64.extend_i32_u
                  i64.const 32
                  i64.shl
                  local.get $len
                  i64.extend_i32_u
                  i64.or))"#,
        )
        .expect("valid WAT")
    }

    fn test_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "lens-plugin-test-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create test directory");
        path
    }

    #[test]
    fn import_free_plugin_runs_with_bounded_io() {
        let engine = PluginEngine::new().expect("engine");
        let module = engine.compile(&echo_module()).expect("module");
        let host = PluginHost {
            engine,
            plugins: vec![LoadedPlugin {
                manifest: PluginManifest {
                    name: "echo".to_string(),
                    version: "1.0.0".to_string(),
                    abi_version: ABI_VERSION,
                    sha256: "0".repeat(64),
                },
                module,
            }],
        };
        let report = host.process(br#"{"flow_id":7,"secret":"[REDACTED]"}"#);
        assert!(report.failures.is_empty());
        assert_eq!(report.annotations.len(), 1);
        assert_eq!(report.annotations[0].plugin, "echo");
        assert!(report.annotations[0].value.contains("[REDACTED]"));
    }

    #[test]
    fn ambient_import_is_rejected() {
        let bytes =
            wat::parse_str(r#"(module (import "wasi_snapshot_preview1" "sock_open" (func)))"#)
                .expect("valid WAT");
        let error = PluginEngine::new()
            .expect("engine")
            .compile(&bytes)
            .expect_err("imports must fail");
        assert!(matches!(error, PluginError::ForbiddenImport(_)));
    }

    #[test]
    fn install_is_explicit_integrity_checked_and_non_overwriting() {
        let root = test_dir();
        let source = root.join("source.wasm");
        fs::write(&source, echo_module()).expect("write source");
        let directory = PluginDirectory::at(root.join("installed"));
        let manifest = directory
            .install(&source, "safe_echo", "1.0.0")
            .expect("install");
        assert_eq!(manifest.abi_version, ABI_VERSION);
        assert_eq!(directory.list().expect("list"), vec![manifest]);
        let duplicate = directory.install(&source, "safe_echo", "1.0.0");
        assert!(duplicate.is_err());
        directory.remove("safe_echo").expect("remove");
        assert!(directory.list().expect("empty list").is_empty());
        fs::remove_file(source).expect("remove source");
        fs::remove_dir(root.join("installed")).expect("remove install root");
        fs::remove_dir(root).expect("remove test root");
    }

    #[test]
    fn fuel_exhaustion_is_contained() {
        let bytes = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "lens_abi_version") (result i32) i32.const 1)
                (func (export "lens_alloc") (param i32) (result i32) i32.const 0)
                (func (export "lens_process") (param i32 i32) (result i64)
                  (loop $again br $again)
                  i64.const 0))"#,
        )
        .expect("valid WAT");
        let engine = PluginEngine::new().expect("engine");
        let module = engine.compile(&bytes).expect("module");
        let host = PluginHost {
            engine,
            plugins: vec![LoadedPlugin {
                manifest: PluginManifest {
                    name: "loop".to_string(),
                    version: "1".to_string(),
                    abi_version: ABI_VERSION,
                    sha256: "0".repeat(64),
                },
                module,
            }],
        };
        let report = host.process(b"{}");
        assert!(report.annotations.is_empty());
        assert_eq!(report.failures.len(), 1);
    }
}
