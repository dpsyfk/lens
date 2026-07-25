//! Local certificate authority and bounded leaf-certificate cache.
//!
//! The CA is explicit, user-scoped state. Its private key is never returned by
//! diagnostics or included in `Debug` output.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use directories::ProjectDirs;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_platform_verifier::ConfigVerifierExt;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// Subject and trust-store nickname used for the local Lens root.
pub const CA_COMMON_NAME: &str = "Lens Local Development CA";
/// Default number of per-host server configurations retained in memory.
pub const DEFAULT_LEAF_CACHE_CAPACITY: usize = 256;

/// Files that make up the persistent local CA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaPaths {
    /// User-scoped Lens TLS directory.
    pub directory: PathBuf,
    /// Public root certificate in PEM form.
    pub certificate: PathBuf,
    /// Secret PKCS#8 signing key in PEM form.
    pub private_key: PathBuf,
    /// Merged system + Lens roots for rootless Linux `SSL_CERT_FILE` use.
    pub client_bundle: PathBuf,
}

impl CaPaths {
    /// Resolves the standard per-user Lens TLS directory for this platform.
    pub fn for_user() -> Result<Self, TlsError> {
        let project = ProjectDirs::from("dev", "Lens", "Lens").ok_or_else(|| {
            TlsError::new(
                "resolve CA directory",
                "the operating system did not provide a user configuration directory",
            )
        })?;
        Ok(Self::from_directory(project.config_dir().join("tls")))
    }

    /// Uses an explicit directory, primarily for isolated tests and portable setups.
    #[must_use]
    pub fn from_directory(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        Self {
            certificate: directory.join("lens-ca.pem"),
            private_key: directory.join("lens-ca-key.pem"),
            client_bundle: directory.join("lens-ca-bundle.pem"),
            directory,
        }
    }
}

/// Persistent CA material state used by `lens cert status` and `lens doctor`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CaMaterialState {
    /// Neither certificate nor private key exists.
    Missing,
    /// Both files exist and are valid matching material.
    Ready,
    /// Only one of the two required files exists.
    Incomplete,
    /// Both files exist but cannot be loaded safely.
    Invalid,
}

impl fmt::Display for CaMaterialState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "missing",
            Self::Ready => "ready",
            Self::Incomplete => "incomplete",
            Self::Invalid => "invalid",
        })
    }
}

/// Safe certificate diagnostics with no key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaStatus {
    /// Location and filenames inspected.
    pub paths: CaPaths,
    /// Material completeness and validity.
    pub state: CaMaterialState,
    /// SHA-256 fingerprint of the certificate DER, when readable.
    pub fingerprint: Option<String>,
    /// Whether the certificate is currently within its validity window.
    pub valid_now: Option<bool>,
    /// Safe remediation-oriented detail.
    pub detail: String,
}

impl CaStatus {
    /// Inspects material without creating or modifying it.
    #[must_use]
    pub fn inspect(paths: CaPaths) -> Self {
        let certificate_exists = paths.certificate.is_file();
        let key_exists = paths.private_key.is_file();
        match (certificate_exists, key_exists) {
            (false, false) => Self {
                paths,
                state: CaMaterialState::Missing,
                fingerprint: None,
                valid_now: None,
                detail: "run `lens cert install` to create and trust the local CA".to_string(),
            },
            (true, false) | (false, true) => Self {
                paths,
                state: CaMaterialState::Incomplete,
                fingerprint: None,
                valid_now: None,
                detail: "CA material is incomplete; move the remaining file aside and run `lens cert install` again"
                    .to_string(),
            },
            (true, true) => match load_material(&paths) {
                Ok(material) => Self {
                    paths,
                    state: CaMaterialState::Ready,
                    fingerprint: Some(fingerprint(&material.certificate_der)),
                    valid_now: Some(material.valid_now),
                    detail: "local CA material is valid".to_string(),
                },
                Err(error) => Self {
                    paths,
                    state: CaMaterialState::Invalid,
                    fingerprint: None,
                    valid_now: None,
                    detail: error.to_string(),
                },
            },
        }
    }
}

/// Loaded CA and bounded cache of issued leaf server configurations.
pub struct CertificateAuthority {
    paths: CaPaths,
    issuer: Issuer<'static, KeyPair>,
    certificate_der: CertificateDer<'static>,
    fingerprint: String,
    cache: Mutex<LeafCache>,
}

impl fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("paths", &self.paths)
            .field("fingerprint", &self.fingerprint)
            .field("private_key", &"[elided]")
            .finish_non_exhaustive()
    }
}

impl CertificateAuthority {
    /// Loads existing material or creates a new CA when both files are absent.
    pub fn load_or_create(paths: CaPaths) -> Result<Self, TlsError> {
        Self::load_or_create_with_capacity(paths, DEFAULT_LEAF_CACHE_CAPACITY)
    }

    /// Loads or creates a CA with an explicit leaf cache capacity.
    pub fn load_or_create_with_capacity(
        paths: CaPaths,
        cache_capacity: usize,
    ) -> Result<Self, TlsError> {
        if cache_capacity == 0 {
            return Err(TlsError::new(
                "configure leaf cache",
                "capacity must be positive",
            ));
        }
        ensure_crypto_provider();
        let certificate_exists = paths.certificate.exists();
        let key_exists = paths.private_key.exists();
        match (certificate_exists, key_exists) {
            (false, false) => create_material(&paths)?,
            (true, true) => {}
            _ => {
                return Err(TlsError::new(
                    "load local CA",
                    "certificate and private key must either both exist or both be absent",
                ));
            }
        }
        let material = load_material(&paths)?;
        if !material.valid_now {
            return Err(TlsError::new(
                "load local CA",
                "certificate is outside its validity window",
            ));
        }
        Ok(Self {
            fingerprint: fingerprint(&material.certificate_der),
            paths,
            issuer: material.issuer,
            certificate_der: material.certificate_der,
            cache: Mutex::new(LeafCache::new(cache_capacity)),
        })
    }

    /// Returns safe diagnostics for the loaded authority.
    #[must_use]
    pub fn status(&self) -> CaStatus {
        CaStatus {
            paths: self.paths.clone(),
            state: CaMaterialState::Ready,
            fingerprint: Some(self.fingerprint.clone()),
            valid_now: Some(true),
            detail: "local CA material is valid".to_string(),
        }
    }

    /// Public root certificate DER for test clients or explicit trust configuration.
    #[must_use]
    pub fn certificate_der(&self) -> CertificateDer<'static> {
        self.certificate_der.clone()
    }

    /// Public root certificate path used by platform trust adapters.
    #[must_use]
    pub fn certificate_path(&self) -> &Path {
        &self.paths.certificate
    }

    /// Creates a public system + Lens bundle for rootless Linux clients.
    pub fn write_linux_client_bundle(&self) -> Result<&Path, TlsError> {
        if !cfg!(target_os = "linux") {
            return Err(TlsError::new(
                "create client CA bundle",
                "the bundle fallback is only required on Linux",
            ));
        }
        let system_bundle = system_ca_bundle(&self.paths.client_bundle).ok_or_else(|| {
            TlsError::new(
                "create client CA bundle",
                "no system CA bundle was found; configure the client with the Lens CA explicitly",
            )
        })?;
        let mut contents = fs::read(&system_bundle)
            .map_err(|error| TlsError::io("read system CA bundle", &system_bundle, error))?;
        if !contents.ends_with(b"\n") {
            contents.push(b'\n');
        }
        contents.extend(fs::read(&self.paths.certificate).map_err(|error| {
            TlsError::io("read Lens CA certificate", &self.paths.certificate, error)
        })?);
        write_public_replace(&self.paths.client_bundle, &contents)?;
        Ok(&self.paths.client_bundle)
    }

    /// Returns a cached or newly issued HTTP/1.1 server configuration for `host`.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, TlsError> {
        let host = normalize_host(host)?;
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(config) = cache.get(&host) {
            return Ok(config);
        }

        let key =
            KeyPair::generate().map_err(|error| TlsError::source("generate leaf key", error))?;
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(vec![host.clone()])
            .map_err(|error| TlsError::source("configure leaf certificate", error))?;
        params
            .distinguished_name
            .push(DnType::CommonName, host.clone());
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(30);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|error| TlsError::source("issue leaf certificate", error))?;
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone(), self.certificate_der.clone()],
                private_key,
            )
            .map_err(|error| TlsError::source("build TLS server configuration", error))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        cache.insert(host, Arc::clone(&config));
        Ok(config)
    }

    /// Number of cached host configurations, for diagnostics and tests.
    #[must_use]
    pub fn cached_leaf_count(&self) -> usize {
        self.cache
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entries
            .len()
    }
}

/// Builds an upstream client configuration that uses normal platform trust.
pub fn platform_client_config() -> Arc<ClientConfig> {
    ensure_crypto_provider();
    let mut config = ClientConfig::with_platform_verifier();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

struct LoadedMaterial {
    issuer: Issuer<'static, KeyPair>,
    certificate_der: CertificateDer<'static>,
    valid_now: bool,
}

fn load_material(paths: &CaPaths) -> Result<LoadedMaterial, TlsError> {
    let certificate_pem = fs::read_to_string(&paths.certificate)
        .map_err(|error| TlsError::io("read CA certificate", &paths.certificate, error))?;
    let private_key_pem = fs::read_to_string(&paths.private_key)
        .map_err(|error| TlsError::io("read CA private key", &paths.private_key, error))?;
    let key = KeyPair::from_pem(&private_key_pem)
        .map_err(|error| TlsError::source("parse CA private key", error))?;
    let certificate_der = first_certificate(&certificate_pem)?;
    let parsed = parse_ca_certificate(certificate_der.as_ref())?;
    if parsed.subject_public_key_info != key.public_key_der().as_slice() {
        return Err(TlsError::new(
            "load local CA",
            "certificate does not match the stored private key",
        ));
    }
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate_der.clone())
        .map_err(|error| TlsError::source("validate CA certificate", error))?;
    let valid_now = parsed.valid_now;
    let issuer = Issuer::new(ca_parameters(OffsetDateTime::now_utc()), key);
    Ok(LoadedMaterial {
        issuer,
        certificate_der,
        valid_now,
    })
}

fn first_certificate(pem: &str) -> Result<CertificateDer<'static>, TlsError> {
    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .map_err(|error| TlsError::source("decode CA certificate PEM", error))?
        .ok_or_else(|| TlsError::new("decode CA certificate PEM", "no certificate was found"))
}

fn create_material(paths: &CaPaths) -> Result<(), TlsError> {
    fs::create_dir_all(&paths.directory)
        .map_err(|error| TlsError::io("create CA directory", &paths.directory, error))?;
    secure_directory(&paths.directory)?;

    let key = KeyPair::generate().map_err(|error| TlsError::source("generate CA key", error))?;
    let params = ca_parameters(OffsetDateTime::now_utc());
    let certificate = params
        .self_signed(&key)
        .map_err(|error| TlsError::source("generate CA certificate", error))?;

    write_secret_new(&paths.private_key, key.serialize_pem().as_bytes())?;
    write_public_new(&paths.certificate, certificate.pem().as_bytes())?;
    Ok(())
}

fn ca_parameters(now: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(3650);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params
}

struct ParsedCa<'a> {
    subject_public_key_info: &'a [u8],
    valid_now: bool,
}

fn parse_ca_certificate(der: &[u8]) -> Result<ParsedCa<'_>, TlsError> {
    let certificate = expect_tlv(der, 0x30, "certificate")?;
    let tbs = expect_tlv(certificate.content, 0x30, "TBSCertificate")?;
    let mut offset = 0;
    if tbs.content.first() == Some(&0xA0) {
        offset = read_tlv(tbs.content, offset, "version")?.next;
    }
    offset = read_tlv(tbs.content, offset, "serial number")?.next;
    offset = read_tlv(tbs.content, offset, "signature algorithm")?.next;
    offset = read_tlv(tbs.content, offset, "issuer")?.next;
    let validity = read_tlv(tbs.content, offset, "validity")?;
    if validity.tag != 0x30 {
        return Err(TlsError::new(
            "parse CA certificate",
            "validity is not a sequence",
        ));
    }
    offset = validity.next;
    offset = read_tlv(tbs.content, offset, "subject")?.next;
    let spki = read_tlv(tbs.content, offset, "subject public key info")?;
    if spki.tag != 0x30 {
        return Err(TlsError::new(
            "parse CA certificate",
            "subject public key info is not a sequence",
        ));
    }
    let not_before = read_tlv(validity.content, 0, "notBefore")?;
    let not_after = read_tlv(validity.content, not_before.next, "notAfter")?;
    let now = generalized_time(OffsetDateTime::now_utc());
    let not_before = normalized_asn1_time(not_before.tag, not_before.content)?;
    let not_after = normalized_asn1_time(not_after.tag, not_after.content)?;
    Ok(ParsedCa {
        subject_public_key_info: &tbs.content[spki.start..spki.next],
        valid_now: not_before <= now && now <= not_after,
    })
}

struct Tlv<'a> {
    tag: u8,
    start: usize,
    content: &'a [u8],
    next: usize,
}

fn expect_tlv<'a>(input: &'a [u8], tag: u8, field: &str) -> Result<Tlv<'a>, TlsError> {
    let value = read_tlv(input, 0, field)?;
    if value.tag != tag {
        return Err(TlsError::new(
            "parse CA certificate",
            format!("{field} has an unexpected ASN.1 tag"),
        ));
    }
    Ok(value)
}

fn read_tlv<'a>(input: &'a [u8], start: usize, field: &str) -> Result<Tlv<'a>, TlsError> {
    let tag = *input
        .get(start)
        .ok_or_else(|| TlsError::new("parse CA certificate", format!("{field} is missing")))?;
    let first_length = *input.get(start + 1).ok_or_else(|| {
        TlsError::new("parse CA certificate", format!("{field} length is missing"))
    })?;
    let (length, header_length) = if first_length & 0x80 == 0 {
        (usize::from(first_length), 2)
    } else {
        let octets = usize::from(first_length & 0x7F);
        if octets == 0 || octets > std::mem::size_of::<usize>() {
            return Err(TlsError::new(
                "parse CA certificate",
                format!("{field} uses an unsupported length"),
            ));
        }
        let mut length = 0usize;
        for byte in input.get(start + 2..start + 2 + octets).ok_or_else(|| {
            TlsError::new(
                "parse CA certificate",
                format!("{field} length is truncated"),
            )
        })? {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| {
                    TlsError::new("parse CA certificate", format!("{field} is too large"))
                })?;
        }
        (length, 2 + octets)
    };
    let content_start = start.checked_add(header_length).ok_or_else(|| {
        TlsError::new("parse CA certificate", format!("{field} offset overflowed"))
    })?;
    let next = content_start.checked_add(length).ok_or_else(|| {
        TlsError::new("parse CA certificate", format!("{field} length overflowed"))
    })?;
    let content = input
        .get(content_start..next)
        .ok_or_else(|| TlsError::new("parse CA certificate", format!("{field} is truncated")))?;
    Ok(Tlv {
        tag,
        start,
        content,
        next,
    })
}

fn normalized_asn1_time(tag: u8, value: &[u8]) -> Result<String, TlsError> {
    let value = std::str::from_utf8(value)
        .map_err(|error| TlsError::source("parse CA certificate time", error))?;
    let normalized = match tag {
        0x17 if value.len() == 13 && value.ends_with('Z') => {
            let year = value[..2]
                .parse::<u8>()
                .map_err(|error| TlsError::source("parse CA certificate UTC year", error))?;
            let century = if year >= 50 { "19" } else { "20" };
            format!("{century}{value}")
        }
        0x18 if value.len() == 15 && value.ends_with('Z') => value.to_string(),
        _ => {
            return Err(TlsError::new(
                "parse CA certificate time",
                "expected UTC or generalized Zulu time",
            ));
        }
    };
    Ok(normalized)
}

fn generalized_time(value: OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    )
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), TlsError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| TlsError::io("secure CA directory", path, error))
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), TlsError> {
    // User configuration directories inherit the current user's ACL on Windows.
    Ok(())
}

#[cfg(unix)]
fn write_secret_new(path: &Path, contents: &[u8]) -> Result<(), TlsError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    write_new_file(path, contents, options)
}

#[cfg(not(unix))]
fn write_secret_new(path: &Path, contents: &[u8]) -> Result<(), TlsError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    write_new_file(path, contents, options)
}

#[cfg(unix)]
fn write_public_new(path: &Path, contents: &[u8]) -> Result<(), TlsError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o644);
    write_new_file(path, contents, options)
}

#[cfg(not(unix))]
fn write_public_new(path: &Path, contents: &[u8]) -> Result<(), TlsError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    write_new_file(path, contents, options)
}

fn write_new_file(path: &Path, contents: &[u8], options: OpenOptions) -> Result<(), TlsError> {
    let mut file = options
        .open(path)
        .map_err(|error| TlsError::io("create CA file", path, error))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| TlsError::io("write CA file", path, error))
}

#[cfg(unix)]
fn write_public_replace(path: &Path, contents: &[u8]) -> Result<(), TlsError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o644);
    write_replace_file(path, contents, options)
}

#[cfg(not(unix))]
fn write_public_replace(path: &Path, contents: &[u8]) -> Result<(), TlsError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    write_replace_file(path, contents, options)
}

fn write_replace_file(path: &Path, contents: &[u8], options: OpenOptions) -> Result<(), TlsError> {
    let mut file = options
        .open(path)
        .map_err(|error| TlsError::io("create client CA bundle", path, error))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| TlsError::io("write client CA bundle", path, error))
}

fn system_ca_bundle(excluded: &Path) -> Option<PathBuf> {
    std::env::var_os("SSL_CERT_FILE")
        .map(PathBuf::from)
        .filter(|path| path != excluded && path.is_file())
        .or_else(|| {
            [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            ]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
        })
}

fn normalize_host(host: &str) -> Result<String, TlsError> {
    let host = host.trim().trim_matches(['[', ']']).trim_end_matches('.');
    if host.is_empty() {
        return Err(TlsError::new("issue leaf certificate", "host is empty"));
    }
    Ok(host.to_ascii_lowercase())
}

fn fingerprint(certificate: &CertificateDer<'_>) -> String {
    Sha256::digest(certificate.as_ref())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Debug)]
struct LeafCache {
    capacity: usize,
    entries: HashMap<String, Arc<ServerConfig>>,
    order: VecDeque<String>,
}

impl LeafCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, host: &str) -> Option<Arc<ServerConfig>> {
        let value = self.entries.get(host).cloned()?;
        self.order.retain(|entry| entry != host);
        self.order.push_back(host.to_string());
        Some(value)
    }

    fn insert(&mut self, host: String, config: Arc<ServerConfig>) {
        if self.entries.len() == self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(host.clone());
        self.entries.insert(host, config);
    }
}

/// Safe TLS lifecycle error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsError {
    operation: String,
    detail: String,
}

impl TlsError {
    fn new(operation: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            detail: detail.into(),
        }
    }

    fn source(operation: impl Into<String>, error: impl fmt::Display) -> Self {
        Self::new(operation, error.to_string())
    }

    fn io(operation: &str, path: &Path, error: io::Error) -> Self {
        Self::new(operation, format!("{}: {error}", path.display()))
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.operation, self.detail)
    }
}

impl std::error::Error for TlsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reloads_the_same_user_ca() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = CaPaths::from_directory(temporary.path().join("tls"));
        let first = CertificateAuthority::load_or_create(paths.clone()).unwrap();
        let first_status = first.status();
        let second = CertificateAuthority::load_or_create(paths.clone()).unwrap();

        assert_eq!(first_status.state, CaMaterialState::Ready);
        assert_eq!(first_status.fingerprint, second.status().fingerprint);
        assert_eq!(CaStatus::inspect(paths).state, CaMaterialState::Ready);
    }

    #[test]
    fn refuses_incomplete_or_mismatched_material() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = CaPaths::from_directory(temporary.path().join("tls"));
        fs::create_dir_all(&paths.directory).unwrap();
        fs::write(&paths.certificate, "not a certificate").unwrap();

        let error = CertificateAuthority::load_or_create(paths.clone()).unwrap_err();
        assert!(error.to_string().contains("must either both exist"));
        assert_eq!(CaStatus::inspect(paths).state, CaMaterialState::Incomplete);
    }

    #[test]
    fn leaf_cache_hits_and_evicts_at_capacity() {
        let temporary = tempfile::tempdir().unwrap();
        let authority = CertificateAuthority::load_or_create_with_capacity(
            CaPaths::from_directory(temporary.path()),
            1,
        )
        .unwrap();

        let first = authority.server_config("Example.Test").unwrap();
        let hit = authority.server_config("example.test.").unwrap();
        assert!(Arc::ptr_eq(&first, &hit));
        authority.server_config("other.test").unwrap();
        let reissued = authority.server_config("example.test").unwrap();
        assert!(!Arc::ptr_eq(&first, &reissued));
        assert_eq!(authority.cached_leaf_count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let paths = CaPaths::from_directory(temporary.path().join("tls"));
        CertificateAuthority::load_or_create(paths.clone()).unwrap();
        assert_eq!(
            fs::metadata(paths.private_key)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_client_bundle_preserves_system_roots_and_adds_lens() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = CaPaths::from_directory(temporary.path().join("tls"));
        let authority = CertificateAuthority::load_or_create(paths.clone()).unwrap();
        let bundle = authority.write_linux_client_bundle().unwrap();
        let contents = fs::read(bundle).unwrap();
        let lens = fs::read(paths.certificate).unwrap();
        assert!(contents.len() > lens.len());
        assert!(contents.ends_with(&lens));
    }
}
