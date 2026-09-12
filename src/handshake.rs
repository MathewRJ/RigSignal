//! Read-only W1 handshake probe.  This intentionally does not share the shipper:
//! delivery accepts some 4xx responses whereas handshake classification is closed.

use clap::{Args, Subcommand};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};
use tokio::time::{timeout_at, Instant as TokioInstant};

use crate::detectors::contract::diagnosis_event::DIAGNOSIS_SCHEMA_VERSION;

const BODY_LIMIT: usize = 65_536;
const TEMPLATE_PATH: &str = "/_component_template/logs-rigsignal.diagnosis-mappings?filter_path=component_templates.name,component_templates.component_template._meta.accepted_schema_versions";
const MAPPING_PATH: &str = "/logs-rigsignal.diagnosis-default/_mapping";

#[derive(Args, Clone, Debug)]
pub struct CheckArgs {
    #[arg(long)]
    pub endpoint: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub ca_file: Option<PathBuf>,
    #[arg(long)]
    pub expected_cluster_uuid: Option<String>,
    #[arg(long)]
    pub pending_enrollment: bool,
    #[arg(long)]
    pub target_generation: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub credentials_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum HandshakeAction {
    Check(CheckArgs),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElasticsearchClusterUuid(String);
impl ElasticsearchClusterUuid {
    fn parse(value: &str) -> Option<Self> {
        (value.len() == 22
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        .then(|| Self(value.to_owned()))
    }
}
impl fmt::Display for ElasticsearchClusterUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetGeneration([u8; 32]);
impl TargetGeneration {
    fn parse(value: &str) -> Option<Self> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut bytes = [0; 32];
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            bytes[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
        }
        Some(Self(bytes))
    }
}
fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
impl fmt::Display for TargetGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ready,
    PendingEnrollment,
    Failed,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Ready,
    PendingEnrollment,
    LocalConfig,
    Connectivity,
    Auth,
    Destination,
    Compatibility,
    #[serde(rename = "unclassified_4xx")]
    Unclassified4xx,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailedStage {
    None,
    Local,
    RootInfo,
    TemplateRead,
    MappingRead,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClassifiedProbe {
    probe_schema_version: u8,
    diagnosis_schema_version: u32,
    outcome: Outcome,
    reason: Reason,
    failed_stage: FailedStage,
    target_generation: Option<String>,
    observed_cluster_uuid: Option<String>,
    accepted_set_digest: Option<String>,
}
impl ClassifiedProbe {
    fn failure(
        reason: Reason,
        stage: FailedStage,
        generation: Option<&TargetGeneration>,
        observed: Option<&ElasticsearchClusterUuid>,
        digest: Option<String>,
    ) -> Self {
        Self {
            probe_schema_version: 1,
            diagnosis_schema_version: DIAGNOSIS_SCHEMA_VERSION,
            outcome: Outcome::Failed,
            reason,
            failed_stage: stage,
            target_generation: generation.map(ToString::to_string),
            observed_cluster_uuid: observed.map(ToString::to_string),
            accepted_set_digest: digest,
        }
    }
    fn success(
        pending: bool,
        generation: &TargetGeneration,
        observed: &ElasticsearchClusterUuid,
        digest: String,
    ) -> Self {
        Self {
            probe_schema_version: 1,
            diagnosis_schema_version: DIAGNOSIS_SCHEMA_VERSION,
            outcome: if pending {
                Outcome::PendingEnrollment
            } else {
                Outcome::Ready
            },
            reason: if pending {
                Reason::PendingEnrollment
            } else {
                Reason::Ready
            },
            failed_stage: FailedStage::None,
            target_generation: Some(generation.to_string()),
            observed_cluster_uuid: Some(observed.to_string()),
            accepted_set_digest: Some(digest),
        }
    }
    pub fn exit_code(&self) -> u8 {
        match self.reason {
            Reason::Ready => 0,
            Reason::PendingEnrollment => 10,
            Reason::LocalConfig => 11,
            Reason::Connectivity => 12,
            Reason::Auth => 13,
            Reason::Destination => 14,
            Reason::Compatibility => 15,
            Reason::Unclassified4xx => 16,
        }
    }
    pub fn json_line(&self) -> Result<String, serde_json::Error> {
        Ok(format!("{}\n", serde_json::to_string(self)?))
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ProtectedConfig {
    elasticsearch: Option<ProtectedElasticsearch>,
    shipping: Option<ProtectedShipping>,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ProtectedElasticsearch {
    endpoint: Option<String>,
    ca_cert: Option<PathBuf>,
    api_key: Option<String>,
    username: Option<String>,
    password: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialFile {
    elasticsearch: CredentialValues,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialValues {
    api_key: Option<String>,
    username: Option<String>,
    password: Option<String>,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ProtectedShipping {
    expected_cluster_uuid: Option<String>,
    pending_enrollment: Option<bool>,
    target_generation: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShippingPolicyV1 {
    ship_mode: String,
    install_profile: String,
    outbox_root: PathBuf,
    target_generation: String,
    expected_cluster_uuid: String,
}
#[derive(Clone)]
enum Credentials {
    ApiKey(String),
    Basic(String, String),
}
enum Affinity {
    Expected(ElasticsearchClusterUuid),
    Pending,
}
pub(crate) struct Preflight {
    origin: String,
    ca: Option<Vec<reqwest::Certificate>>,
    credential: Credentials,
    affinity: Affinity,
    generation: TargetGeneration,
}

/// The handshake's non-secret process and file inputs.  Keeping this narrow
/// makes resolution deterministic in tests and prevents legacy environment
/// resolution from accidentally reaching the probe.
pub(crate) trait Environment {
    /// `Err` means the variable exists but cannot safely be interpreted as UTF-8.
    /// Such a value is present at its precedence tier and must not fall through.
    fn value(&self, name: &str) -> Result<Option<String>, ()>;
    fn read_public(&self, path: &Path) -> Result<Vec<u8>, ()>;
    fn read_protected(&self, path: &Path) -> Result<String, ()>;
    fn read_optional_protected(&self, path: &Path) -> Result<Option<String>, ()>;
}

pub(crate) struct ProcessEnvironment;
impl Environment for ProcessEnvironment {
    fn value(&self, name: &str) -> Result<Option<String>, ()> {
        std::env::var_os(name)
            .map(|value| value.into_string().map_err(|_| ()))
            .transpose()
    }
    // Orchestrator ruling: the CA file is public material, not a credential source.
    fn read_public(&self, path: &Path) -> Result<Vec<u8>, ()> {
        std::fs::read(path).map_err(|_| ())
    }
    fn read_protected(&self, path: &Path) -> Result<String, ()> {
        protected_read(path)
    }
    fn read_optional_protected(&self, path: &Path) -> Result<Option<String>, ()> {
        if !path.exists() {
            return Ok(None);
        }
        self.read_protected(path).map(Some)
    }
}

pub(crate) trait Clock {
    fn deadline_after(&self, duration: Duration) -> TokioInstant;
}

pub(crate) struct SystemClock;
impl Clock for SystemClock {
    fn deadline_after(&self, duration: Duration) -> TokioInstant {
        TokioInstant::from_std(Instant::now() + duration)
    }
}

/// An unexpected invariant failure from the seam-driven probe. All expected
/// configuration and protocol observations are represented by ClassifiedProbe.
#[derive(Debug)]
pub struct InternalError;

/// Run the probe. Every expected preflight or transport failure is converted to a
/// stable report; callers never receive credential or response-body text.
pub(crate) async fn run_check<E: Environment, C: Clock, T: Transport>(
    args: CheckArgs,
    environment: &E,
    clock: &C,
    transport: &mut T,
) -> Result<ClassifiedProbe, InternalError> {
    let preflight = match preflight(environment, &args) {
        Ok(value) => value,
        Err(()) => {
            return Ok(ClassifiedProbe::failure(
                Reason::LocalConfig,
                FailedStage::Local,
                None,
                None,
                None,
            ))
        }
    };
    if transport.prepare(&preflight).is_err() {
        return Ok(ClassifiedProbe::failure(
            Reason::LocalConfig,
            FailedStage::Local,
            None,
            None,
            None,
        ));
    }
    let deadline = clock.deadline_after(Duration::from_secs(10));
    let generation = &preflight.generation;
    let root = match classify_http(
        transport.exchange("/", deadline).await,
        FailedStage::RootInfo,
        generation,
        None,
        None,
    ) {
        Ok(body) => body,
        Err(report) => return Ok(report),
    };
    let observed = match root_uuid(&root) {
        Some(uuid) => uuid,
        None => {
            return Ok(ClassifiedProbe::failure(
                Reason::Compatibility,
                FailedStage::RootInfo,
                Some(generation),
                None,
                None,
            ))
        }
    };
    match &preflight.affinity {
        Affinity::Expected(expected) if expected != &observed => {
            return Ok(ClassifiedProbe::failure(
                Reason::Destination,
                FailedStage::RootInfo,
                Some(generation),
                Some(&observed),
                None,
            ))
        }
        Affinity::Expected(_) => {}
        Affinity::Pending => {}
    }
    let pending = matches!(preflight.affinity, Affinity::Pending);
    let template = match classify_http(
        transport.exchange(TEMPLATE_PATH, deadline).await,
        FailedStage::TemplateRead,
        generation,
        Some(&observed),
        None,
    ) {
        Ok(body) => body,
        Err(report) => return Ok(report),
    };
    let (digest, member) = match template_set(&template) {
        Some(value) => value,
        None => {
            return Ok(ClassifiedProbe::failure(
                Reason::Compatibility,
                FailedStage::TemplateRead,
                Some(generation),
                Some(&observed),
                None,
            ))
        }
    };
    if !member {
        return Ok(ClassifiedProbe::failure(
            Reason::Compatibility,
            FailedStage::TemplateRead,
            Some(generation),
            Some(&observed),
            Some(digest),
        ));
    }
    let mapping = match classify_http(
        transport.exchange(MAPPING_PATH, deadline).await,
        FailedStage::MappingRead,
        generation,
        Some(&observed),
        Some(digest.clone()),
    ) {
        Ok(body) => body,
        Err(report) => return Ok(report),
    };
    if !is_json_object(&mapping) {
        return Ok(ClassifiedProbe::failure(
            Reason::Compatibility,
            FailedStage::MappingRead,
            Some(generation),
            Some(&observed),
            Some(digest),
        ));
    }
    Ok(ClassifiedProbe::success(
        pending, generation, &observed, digest,
    ))
}

fn preflight(environment: &impl Environment, args: &CheckArgs) -> Result<Preflight, ()> {
    let config = match &args.config {
        Some(path) => parse_protected(environment, path)?,
        None => ProtectedConfig::default(),
    };
    let es = config.elasticsearch.unwrap_or_default();
    let shipping = config.shipping.unwrap_or_default();
    let capsule = match &args.config {
        Some(path) => read_shipping_policy(environment, path)?,
        None => None,
    };
    let endpoint = match &args.endpoint {
        Some(value) => value.clone(),
        None => environment
            .value("RIGSIGNAL_ES_ENDPOINT")?
            .or(es.endpoint)
            .ok_or(())?,
    };
    let origin = endpoint_origin(&endpoint).ok_or(())?;
    let generation = match &args.target_generation {
        Some(value) => Some(value.clone()),
        None => environment
            .value("RIGSIGNAL_TARGET_GENERATION")?
            .or(capsule
                .as_ref()
                .map(|policy| policy.target_generation.clone()))
            .or(shipping.target_generation.clone()),
    }
    .and_then(|s| TargetGeneration::parse(&s))
    .ok_or(())?;
    let affinity = resolve_affinity(environment, args, &shipping, capsule.as_ref())?;
    let ca_path = match &args.ca_file {
        Some(path) => Some(path.clone()),
        None => environment
            .value("RIGSIGNAL_ES_CA_FILE")?
            .map(PathBuf::from)
            .or(es.ca_cert),
    };
    let ca = match ca_path {
        Some(path) => {
            let ca = ca_certificate_bundle(&environment.read_public(&path)?)?;
            // Validate before a report is allowed to expose any preflight value.
            let mut builder = reqwest::Client::builder().redirect(Policy::none());
            for certificate in &ca {
                builder = builder.add_root_certificate(certificate.clone());
            }
            builder.build().map_err(|_| ())?;
            Some(ca)
        }
        None => None,
    };
    let dedicated = match &args.credentials_file {
        Some(path) => Some(path.clone()),
        None => environment
            .value("RIGSIGNAL_ES_CREDENTIALS_FILE")?
            .map(PathBuf::from),
    };
    let credential = match dedicated {
        Some(path) => credentials_from_file(environment, &path)?,
        None => credentials_from_values(es.api_key, es.username, es.password)?,
    };
    Ok(Preflight {
        origin,
        ca,
        credential,
        affinity,
        generation,
    })
}
pub(crate) fn ca_certificate_bundle(bytes: &[u8]) -> Result<Vec<reqwest::Certificate>, ()> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut remainder = std::str::from_utf8(bytes).map_err(|_| ())?.trim();
    if remainder.is_empty() {
        return Err(());
    }
    while !remainder.is_empty() {
        let certificate = remainder.strip_prefix(BEGIN).ok_or(())?;
        let end = certificate.find(END).ok_or(())? + END.len();
        remainder = certificate[end..].trim();
    }
    let certificates = reqwest::Certificate::from_pem_bundle(bytes).map_err(|_| ())?;
    (!certificates.is_empty()).then_some(certificates).ok_or(())
}
fn resolve_affinity(
    environment: &impl Environment,
    args: &CheckArgs,
    shipping: &ProtectedShipping,
    capsule: Option<&ShippingPolicyV1>,
) -> Result<Affinity, ()> {
    let flag = affinity_pair(
        args.expected_cluster_uuid.clone(),
        args.pending_enrollment.then_some(true),
    )?;
    if let Some(v) = flag {
        return Ok(v);
    }
    let pending_env = match environment.value("RIGSIGNAL_PENDING_ENROLLMENT")? {
        Some(value) if value == "1" => Some(true),
        Some(_) => return Err(()),
        None => None,
    };
    if let Some(v) = affinity_pair(
        environment.value("RIGSIGNAL_EXPECTED_CLUSTER_UUID")?,
        pending_env,
    )? {
        return Ok(v);
    }
    affinity_pair(
        capsule.map(|policy| policy.expected_cluster_uuid.clone()),
        None,
    )?
    .or(affinity_pair(
        shipping.expected_cluster_uuid.clone(),
        shipping.pending_enrollment,
    )?)
    .ok_or(())
}

fn read_shipping_policy(
    environment: &impl Environment,
    config_path: &Path,
) -> Result<Option<ShippingPolicyV1>, ()> {
    let parent = config_path.parent().ok_or(())?;
    let Some(text) =
        environment.read_optional_protected(&parent.join("shipping-policy-v1.toml"))?
    else {
        return Ok(None);
    };
    let policy: ShippingPolicyV1 = toml::from_str(&text).map_err(|_| ())?;
    if policy.ship_mode != "on"
        || policy.install_profile != "user"
        || !policy.outbox_root.is_absolute()
        || TargetGeneration::parse(&policy.target_generation).is_none()
        || ElasticsearchClusterUuid::parse(&policy.expected_cluster_uuid).is_none()
    {
        return Err(());
    }
    Ok(Some(policy))
}
fn affinity_pair(uuid: Option<String>, pending: Option<bool>) -> Result<Option<Affinity>, ()> {
    match (uuid, pending) {
        (Some(_), Some(_)) => Err(()),
        (Some(value), None) => ElasticsearchClusterUuid::parse(&value)
            .map(Affinity::Expected)
            .map(Some)
            .ok_or(()),
        (None, Some(true)) => Ok(Some(Affinity::Pending)),
        (None, Some(false)) => Err(()),
        (None, None) => Ok(None),
    }
}
/// Reduce an endpoint to a bare `scheme://host[:port]` origin, or `None`.
///
/// REJECTS rather than sanitises: any userinfo, username, password, query,
/// fragment or non-root path yields `None`. That is why it is safe to render
/// into an error message -- there is no list of credential-bearing forms to keep
/// complete, because anything unusual fails closed instead of being stripped.
/// Also used by `shipper::ping` for exactly that property.
pub(crate) fn endpoint_origin(value: &str) -> Option<String> {
    let url = reqwest::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url_has_userinfo(value, &url)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return None;
    }
    let host = url.host_str()?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Some(match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    })
}

fn url_has_userinfo(input: &str, url: &reqwest::Url) -> bool {
    // Url normalizes an empty username away when serialized, so inspect the
    // parsed input's authority rather than `Url::username()` alone.
    let Some(authority) = input
        .get(url.scheme().len() + 1..)
        .and_then(|rest| rest.strip_prefix("//"))
    else {
        return true;
    };
    let authority_end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    authority[..authority_end].contains('@')
}
fn credentials_from_values(
    api_key: Option<String>,
    username: Option<String>,
    password: Option<String>,
) -> Result<Credentials, ()> {
    match api_key {
        Some(key)
            if !key.is_empty()
                && reqwest::header::HeaderValue::from_bytes(format!("ApiKey {key}").as_bytes())
                    .is_ok() =>
        {
            Ok(Credentials::ApiKey(key))
        }
        Some(_) => Err(()),
        None => match (username, password) {
            (Some(user), Some(password)) if !user.is_empty() && !password.is_empty() => {
                Ok(Credentials::Basic(user, password))
            }
            _ => Err(()),
        },
    }
}
fn parse_protected(environment: &impl Environment, path: &Path) -> Result<ProtectedConfig, ()> {
    let text = environment.read_protected(path)?;
    toml::from_str(&text).map_err(|_| ())
}
fn credentials_from_file(environment: &impl Environment, path: &Path) -> Result<Credentials, ()> {
    let text = environment.read_protected(path)?;
    let config: CredentialFile = toml::from_str(&text).map_err(|_| ())?;
    let values = config.elasticsearch;
    // A dedicated credential file is a capability file, not a precedence
    // layer.  Accept exactly one credential grammar so an accidentally
    // appended Basic pair cannot be silently ignored behind an API key.
    match (values.api_key, values.username, values.password) {
        (Some(key), None, None) => credentials_from_values(Some(key), None, None),
        (None, Some(username), Some(password)) => {
            credentials_from_values(None, Some(username), Some(password))
        }
        _ => Err(()),
    }
}

#[cfg(unix)]
fn protected_read(path: &Path) -> Result<String, ()> {
    use std::os::fd::FromRawFd;
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.contains(&0) {
        return Err(());
    }
    let cpath = std::ffi::CString::new(bytes).map_err(|_| ())?;
    // SAFETY: fd is checked before File takes ownership; the C string is NUL terminated.
    // O_NONBLOCK ensures a hostile FIFO cannot stall preflight before fstat
    // rejects it as non-regular. It has no effect on regular files.
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(());
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes stat for the valid descriptor.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        unsafe { libc::close(fd) };
        return Err(());
    }
    let stat = unsafe { stat.assume_init() };
    if !protected_metadata_valid(
        stat.st_mode & 0o7777,
        stat.st_uid,
        unsafe { libc::geteuid() },
        (stat.st_mode & libc::S_IFMT) == libc::S_IFREG,
    ) {
        unsafe { libc::close(fd) };
        return Err(());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut text = String::new();
    use std::io::Read;
    file.read_to_string(&mut text).map_err(|_| ())?;
    Ok(text)
}
#[cfg(unix)]
fn protected_metadata_valid(mode: u32, uid: u32, euid: u32, regular: bool) -> bool {
    regular && uid == euid && (mode & 0o077) == 0
}
#[cfg(not(unix))]
fn protected_read(_: &Path) -> Result<String, ()> {
    Err(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BodyRead {
    CapExceeded,
    Transport,
}
#[derive(Clone, Debug)]
pub(crate) enum TransportFailure {
    Dns,
    TlsPeer,
    Connect,
    Reset,
    Read,
    MidBody,
    Deadline,
}
#[derive(Clone, Debug)]
pub(crate) struct Received {
    status: u16,
    encoding: ContentEncoding,
    body: Result<Vec<u8>, BodyRead>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentEncoding {
    AbsentOrIdentity,
    Unsupported,
}

/// Handshake request seam.  The production transport is reqwest; tests use a
/// scripted implementation so classification never depends on a live peer.
pub(crate) trait Transport {
    fn prepare(&mut self, preflight: &Preflight) -> Result<(), ()>;
    fn exchange<'a>(
        &'a mut self,
        path: &'a str,
        deadline: TokioInstant,
    ) -> Pin<Box<dyn Future<Output = Result<Received, TransportFailure>> + 'a>>;
}

#[derive(Default)]
pub(crate) struct ReqwestTransport {
    client: Option<reqwest::Client>,
    origin: String,
    credentials: Option<Credentials>,
}
impl Transport for ReqwestTransport {
    fn prepare(&mut self, preflight: &Preflight) -> Result<(), ()> {
        let mut builder = reqwest::Client::builder().redirect(Policy::none());
        if let Some(certificates) = &preflight.ca {
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate.clone());
            }
        }
        self.client = Some(builder.build().map_err(|_| ())?);
        self.origin = preflight.origin.clone();
        self.credentials = Some(preflight.credential.clone());
        Ok(())
    }
    fn exchange<'a>(
        &'a mut self,
        path: &'a str,
        deadline: TokioInstant,
    ) -> Pin<Box<dyn Future<Output = Result<Received, TransportFailure>> + 'a>> {
        Box::pin(async move {
            let client = self.client.as_ref().ok_or(TransportFailure::Connect)?;
            let credentials = self.credentials.as_ref().ok_or(TransportFailure::Connect)?;
            let url = format!("{}{}", self.origin, path);
            let request = match credentials {
                Credentials::ApiKey(key) => client
                    .get(url)
                    .header("Authorization", format!("ApiKey {key}")),
                Credentials::Basic(user, password) => {
                    client.get(url).basic_auth(user, Some(password))
                }
            }
            .header("Accept-Encoding", "identity");
            let response = timeout_at(deadline, request.send())
                .await
                .map_err(|_| TransportFailure::Deadline)?
                .map_err(|_| TransportFailure::Connect)?;
            let status = response.status().as_u16();
            let encoding = content_encoding(response.headers());
            // A received status remains authoritative if the bounded drain later expires.
            let body = match timeout_at(deadline, read_body(response)).await {
                Ok(body) => body,
                Err(_) => Err(BodyRead::Transport),
            };
            Ok(Received {
                status,
                encoding,
                body,
            })
        })
    }
}
async fn read_body(mut response: reqwest::Response) -> Result<Vec<u8>, BodyRead> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| BodyRead::Transport)? {
        if body.len().saturating_add(chunk.len()) > BODY_LIMIT {
            return Err(BodyRead::CapExceeded);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
fn classify_http(
    response: Result<Received, TransportFailure>,
    stage: FailedStage,
    generation: &TargetGeneration,
    observed: Option<&ElasticsearchClusterUuid>,
    digest: Option<String>,
) -> Result<Vec<u8>, ClassifiedProbe> {
    let response = response.map_err(|_| {
        ClassifiedProbe::failure(
            Reason::Connectivity,
            stage,
            Some(generation),
            observed,
            digest.clone(),
        )
    })?;
    if response.status != 200 {
        return Err(ClassifiedProbe::failure(
            status_reason(response.status, stage),
            stage,
            Some(generation),
            observed,
            digest,
        ));
    }
    if response.encoding == ContentEncoding::Unsupported {
        return Err(ClassifiedProbe::failure(
            Reason::Compatibility,
            stage,
            Some(generation),
            observed,
            digest,
        ));
    }
    response.body.map_err(|error| {
        ClassifiedProbe::failure(
            if matches!(error, BodyRead::CapExceeded) {
                Reason::Compatibility
            } else {
                Reason::Connectivity
            },
            stage,
            Some(generation),
            observed,
            digest,
        )
    })
}
fn status_reason(status: u16, stage: FailedStage) -> Reason {
    match status {
        401 | 403 => Reason::Auth,
        408 | 429 | 500..=599 => Reason::Connectivity,
        300..=399 => Reason::Destination,
        400 | 413 => Reason::Compatibility,
        404 if matches!(stage, FailedStage::RootInfo | FailedStage::MappingRead) => {
            Reason::Destination
        }
        404 => Reason::Compatibility,
        400..=499 => Reason::Unclassified4xx,
        _ => Reason::Compatibility,
    }
}
fn root_uuid(body: &[u8]) -> Option<ElasticsearchClusterUuid> {
    let value = checked_json_stage(body, ProtectedStage::Root)?;
    value
        .as_object()?
        .get("cluster_uuid")?
        .as_str()
        .and_then(ElasticsearchClusterUuid::parse)
}
fn template_set(body: &[u8]) -> Option<(String, bool)> {
    let value = checked_json_stage(body, ProtectedStage::Template)?;
    let templates = value.get("component_templates")?.as_array()?;
    if templates.len() != 1
        || templates[0].get("name")?.as_str()? != "logs-rigsignal.diagnosis-mappings"
    {
        return None;
    }
    let versions = templates[0]
        .get("component_template")?
        .get("_meta")?
        .get("accepted_schema_versions")?
        .as_array()?;
    let strings: Vec<&str> = versions.iter().map(Value::as_str).collect::<Option<_>>()?;
    let canonical = accepted_set(&strings)?;
    Some((canonical.0, canonical.1))
}
fn is_json_object(body: &[u8]) -> bool {
    checked_json_stage(body, ProtectedStage::Mapping).is_some_and(|value| value.is_object())
}

// Scanner tokens are punctuation, complete strings, complete numbers, and literals.
// It bounds nesting, token count, and decoded UTF-8 string bytes before serde parses.
fn checked_json(body: &[u8]) -> Option<Value> {
    scan_json(body)?;
    serde_json::from_slice(body).ok()
}
#[derive(Clone, Copy)]
enum ProtectedStage {
    Root,
    Template,
    Mapping,
}

fn content_encoding(headers: &reqwest::header::HeaderMap) -> ContentEncoding {
    for value in headers.get_all(reqwest::header::CONTENT_ENCODING) {
        let Ok(value) = value.to_str() else {
            return ContentEncoding::Unsupported;
        };
        for coding in value.split(',') {
            let coding = coding.trim_matches([' ', '\t']);
            if coding.is_empty() || !coding.eq_ignore_ascii_case("identity") {
                return ContentEncoding::Unsupported;
            }
        }
    }
    ContentEncoding::AbsentOrIdentity
}

fn checked_json_stage(body: &[u8], stage: ProtectedStage) -> Option<Value> {
    let value = checked_json(body)?;
    let mut parser = DuplicateParser {
        bytes: body,
        cursor: 0,
        stage,
    };
    parser.value(&[])?;
    parser.ws();
    (parser.cursor == body.len()).then_some(value)
}

/// A second, tiny structural walk deliberately runs after the bounded scanner
/// but before the deserializer result is trusted. It retains no values; it only
/// rejects duplicates of keys which drive a handshake decision. Other duplicate
/// JSON keys remain legal as required by the frozen contract.
struct DuplicateParser<'a> {
    bytes: &'a [u8],
    cursor: usize,
    stage: ProtectedStage,
}
impl DuplicateParser<'_> {
    fn ws(&mut self) {
        while matches!(
            self.bytes.get(self.cursor),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.cursor += 1;
        }
    }
    fn value(&mut self, path: &[PathSegment]) -> Option<()> {
        self.ws();
        match *self.bytes.get(self.cursor)? {
            b'{' => self.object(path),
            b'[' => self.array(path),
            b'"' => self.string().map(|_| ()),
            b'-' | b'0'..=b'9' => {
                self.scalar();
                Some(())
            }
            b't' if self.take(b"true") => Some(()),
            b'f' if self.take(b"false") => Some(()),
            b'n' if self.take(b"null") => Some(()),
            _ => None,
        }
    }
    fn object(&mut self, path: &[PathSegment]) -> Option<()> {
        self.cursor += 1;
        self.ws();
        let mut seen = HashSet::new();
        if self.bytes.get(self.cursor) == Some(&b'}') {
            self.cursor += 1;
            return Some(());
        }
        loop {
            let key = self.string()?;
            if self.protected(path, &key) && !seen.insert(key.clone()) {
                return None;
            }
            self.ws();
            if self.bytes.get(self.cursor) != Some(&b':') {
                return None;
            }
            self.cursor += 1;
            let mut child = path.to_vec();
            child.push(PathSegment::Key(key));
            self.value(&child)?;
            self.ws();
            match self.bytes.get(self.cursor)? {
                b',' => {
                    self.cursor += 1;
                    self.ws();
                }
                b'}' => {
                    self.cursor += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }
    fn array(&mut self, path: &[PathSegment]) -> Option<()> {
        self.cursor += 1;
        self.ws();
        if self.bytes.get(self.cursor) == Some(&b']') {
            self.cursor += 1;
            return Some(());
        }
        let mut child = path.to_vec();
        child.push(PathSegment::ArrayElement);
        loop {
            self.value(&child)?;
            self.ws();
            match self.bytes.get(self.cursor)? {
                b',' => {
                    self.cursor += 1;
                    self.ws();
                }
                b']' => {
                    self.cursor += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }
    fn string(&mut self) -> Option<String> {
        self.ws();
        let start = self.cursor;
        if self.bytes.get(self.cursor) != Some(&b'"') {
            return None;
        }
        self.cursor = scan_string(self.bytes, self.cursor + 1)?;
        serde_json::from_slice(&self.bytes[start..self.cursor]).ok()
    }
    fn scalar(&mut self) {
        while !matches!(
            self.bytes.get(self.cursor),
            None | Some(b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}')
        ) {
            self.cursor += 1;
        }
    }
    fn take(&mut self, word: &[u8]) -> bool {
        if self.bytes.get(self.cursor..self.cursor + word.len()) == Some(word) {
            self.cursor += word.len();
            true
        } else {
            false
        }
    }
    fn protected(&self, path: &[PathSegment], key: &str) -> bool {
        match self.stage {
            ProtectedStage::Root => path.is_empty() && key == "cluster_uuid",
            ProtectedStage::Template => {
                (path.is_empty() && key == "component_templates")
                    || (template_path(path, &[]) && matches!(key, "name" | "component_template"))
                    || (template_path(path, &["component_template"]) && key == "_meta")
                    || (template_path(path, &["component_template", "_meta"])
                        && key == "accepted_schema_versions")
            }
            ProtectedStage::Mapping => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PathSegment {
    Key(String),
    ArrayElement,
}

fn template_path(path: &[PathSegment], suffix: &[&str]) -> bool {
    path.len() == suffix.len() + 2
        && matches!(path.first(), Some(PathSegment::Key(key)) if key == "component_templates")
        && matches!(path.get(1), Some(PathSegment::ArrayElement))
        && path[2..]
            .iter()
            .zip(suffix)
            .all(|(actual, expected)| matches!(actual, PathSegment::Key(key) if key == expected))
}
fn scan_json(bytes: &[u8]) -> Option<()> {
    let mut i = 0;
    let mut depth = 0usize;
    let mut tokens = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\n' | b'\r' | b'\t' => i += 1,
            b'{' | b'[' => {
                depth += 1;
                tokens += 1;
                if depth > 32 {
                    return None;
                }
                i += 1
            }
            b'}' | b']' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                tokens += 1;
                i += 1
            }
            b':' | b',' => {
                tokens += 1;
                i += 1
            }
            b'"' => {
                tokens += 1;
                i = scan_string(bytes, i + 1)?;
            }
            b'-' | b'0'..=b'9' => {
                tokens += 1;
                i += 1;
                while i < bytes.len()
                    && !matches!(bytes[i], b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}')
                {
                    i += 1;
                }
            }
            b't' if bytes.get(i..i + 4) == Some(b"true") => {
                tokens += 1;
                i += 4
            }
            b'f' if bytes.get(i..i + 5) == Some(b"false") => {
                tokens += 1;
                i += 5
            }
            b'n' if bytes.get(i..i + 4) == Some(b"null") => {
                tokens += 1;
                i += 4
            }
            _ => return None,
        }
        if tokens > 4096 {
            return None;
        }
    }
    (depth == 0).then_some(())
}
fn scan_string(bytes: &[u8], mut i: usize) -> Option<usize> {
    let mut decoded = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return (decoded <= 4096).then_some(i + 1),
            b'\\' => {
                i += 1;
                let esc = *bytes.get(i)?;
                match esc {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => decoded += 1,
                    b'u' => {
                        let hexes = bytes.get(i + 1..i + 5)?;
                        let value =
                            u16::from_str_radix(std::str::from_utf8(hexes).ok()?, 16).ok()?;
                        i += 4;
                        if (0xD800..=0xDBFF).contains(&value) {
                            if bytes.get(i + 1) != Some(&b'\\') || bytes.get(i + 2) != Some(&b'u') {
                                return None;
                            }
                            let low = u16::from_str_radix(
                                std::str::from_utf8(bytes.get(i + 3..i + 7)?).ok()?,
                                16,
                            )
                            .ok()?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return None;
                            }
                            i += 6;
                            let scalar =
                                0x10000 + (((value as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                            decoded += char::from_u32(scalar)?.len_utf8();
                        } else if (0xDC00..=0xDFFF).contains(&value) {
                            return None;
                        } else {
                            decoded += char::from_u32(value as u32)?.len_utf8();
                        }
                    }
                    _ => return None,
                }
            }
            byte if byte >= 0x20 => {
                let width = std::str::from_utf8(&bytes[i..])
                    .ok()?
                    .chars()
                    .next()?
                    .len_utf8();
                decoded += width;
                i += width - 1
            }
            _ => return None,
        }
        if decoded > 4096 {
            return None;
        }
        i += 1
    }
    None
}

fn accepted_set(values: &[&str]) -> Option<(String, bool)> {
    if values.is_empty() || values.len() > 256 {
        return None;
    }
    let mut entries: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
    if entries.iter().any(|value| !valid_version(value)) {
        return None;
    }
    entries.sort();
    entries.dedup();
    let digest = digest_entries(&entries);
    let member = entries
        .iter()
        .any(|value| value == &DIAGNOSIS_SCHEMA_VERSION.to_string());
    Some((digest, member))
}
fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 10
        && value.bytes().all(|b| b.is_ascii_digit())
        && !value.starts_with('0')
        && value.parse::<u32>().is_ok()
}
fn digest_entries(entries: &[String]) -> String {
    let mut frame = b"rigsignal:w1:accepted-schema-versions:digest:v1\0".to_vec();
    frame.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for entry in entries {
        frame.extend_from_slice(&(entry.len() as u32).to_be_bytes());
        frame.extend_from_slice(entry.as_bytes());
    }
    sha256_hex(&frame)
}

// Minimal local SHA-256 avoids widening the agent dependency graph for one digest.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut message = data.to_vec();
    let bits = (message.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bits.to_be_bytes());
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in message.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            w[i] = w[i - 16]
                .wrapping_add(
                    w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3),
                )
                .wrapping_add(w[i - 7])
                .wrapping_add(
                    w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10),
                );
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = (*slot).wrapping_add(value);
        }
    }
    h.iter().map(|word| format!("{word:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const UUID: &str = "KUrXRgwRRQu-RikmIJhm0Q";
    const GEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct ScriptedTransport {
        replies: VecDeque<Result<Received, TransportFailure>>,
        delays: VecDeque<Duration>,
        paths: Vec<String>,
    }
    impl ScriptedTransport {
        fn new(replies: Vec<Result<Received, TransportFailure>>) -> Self {
            let count = replies.len();
            Self {
                replies: replies.into(),
                delays: std::iter::repeat_n(Duration::ZERO, count).collect(),
                paths: Vec::new(),
            }
        }
        fn with_delays(
            replies: Vec<Result<Received, TransportFailure>>,
            delays: Vec<Duration>,
        ) -> Self {
            Self {
                replies: replies.into(),
                delays: delays.into(),
                paths: Vec::new(),
            }
        }
    }
    impl Transport for ScriptedTransport {
        fn prepare(&mut self, _: &Preflight) -> Result<(), ()> {
            Ok(())
        }
        fn exchange<'a>(
            &'a mut self,
            path: &'a str,
            deadline: TokioInstant,
        ) -> Pin<Box<dyn Future<Output = Result<Received, TransportFailure>> + 'a>> {
            self.paths.push(path.to_owned());
            let reply = self
                .replies
                .pop_front()
                .unwrap_or(Err(TransportFailure::Reset));
            let delay = self.delays.pop_front().unwrap_or_default();
            Box::pin(async move {
                if timeout_at(deadline, tokio::time::sleep(delay))
                    .await
                    .is_err()
                {
                    Err(TransportFailure::Deadline)
                } else {
                    reply
                }
            })
        }
    }
    #[derive(Default)]
    struct TestEnvironment {
        values: std::collections::HashMap<String, String>,
        public: std::collections::HashMap<PathBuf, Vec<u8>>,
        protected: std::collections::HashMap<PathBuf, String>,
        invalid_values: std::collections::HashSet<String>,
    }
    impl Environment for TestEnvironment {
        fn value(&self, name: &str) -> Result<Option<String>, ()> {
            if self.invalid_values.contains(name) {
                Err(())
            } else {
                Ok(self.values.get(name).cloned())
            }
        }
        fn read_public(&self, path: &Path) -> Result<Vec<u8>, ()> {
            self.public.get(path).cloned().ok_or(())
        }
        fn read_protected(&self, path: &Path) -> Result<String, ()> {
            self.protected
                .get(path)
                .cloned()
                .or_else(|| {
                    (path == Path::new("creds.toml"))
                        .then(|| "[elasticsearch]\napi_key = 'test-key'\n".to_owned())
                })
                .ok_or(())
        }
        fn read_optional_protected(&self, path: &Path) -> Result<Option<String>, ()> {
            Ok(self.protected.get(path).cloned())
        }
    }
    fn args(pending: bool) -> CheckArgs {
        CheckArgs {
            endpoint: Some("https://example.test".into()),
            ca_file: None,
            expected_cluster_uuid: (!pending).then(|| UUID.into()),
            pending_enrollment: pending,
            target_generation: Some(GEN.into()),
            credentials_file: Some("creds.toml".into()),
            config: None,
        }
    }
    async fn run_test(transport: &mut ScriptedTransport, pending: bool) -> ClassifiedProbe {
        run_check(
            args(pending),
            &TestEnvironment::default(),
            &SystemClock,
            transport,
        )
        .await
        .unwrap()
    }
    struct FixedClock;
    impl Clock for FixedClock {
        fn deadline_after(&self, duration: Duration) -> TokioInstant {
            TokioInstant::now() + duration
        }
    }
    async fn run_test_with_clock(
        transport: &mut ScriptedTransport,
        clock: &impl Clock,
    ) -> ClassifiedProbe {
        run_check(args(false), &TestEnvironment::default(), clock, transport)
            .await
            .unwrap()
    }
    fn received(status: u16, body: impl AsRef<[u8]>) -> Received {
        Received {
            status,
            encoding: ContentEncoding::AbsentOrIdentity,
            body: Ok(body.as_ref().to_vec()),
        }
    }
    fn encoded(status: u16, body: impl AsRef<[u8]>) -> Received {
        Received {
            status,
            encoding: ContentEncoding::Unsupported,
            body: Ok(body.as_ref().to_vec()),
        }
    }
    fn root() -> Received {
        received(200, format!(r#"{{"cluster_uuid":"{UUID}"}}"#))
    }
    fn template() -> Received {
        received(
            200,
            r#"{"component_templates":[{"name":"logs-rigsignal.diagnosis-mappings","component_template":{"_meta":{"accepted_schema_versions":["1"]}}}]}"#,
        )
    }
    fn mapping() -> Received {
        received(200, "{}")
    }
    fn generation() -> TargetGeneration {
        TargetGeneration::parse(GEN).unwrap()
    }
    async fn probe_for(
        stage: FailedStage,
        reply: Result<Received, TransportFailure>,
    ) -> ClassifiedProbe {
        let replies = match stage {
            FailedStage::RootInfo => vec![reply],
            FailedStage::TemplateRead => vec![Ok(root()), reply],
            FailedStage::MappingRead => vec![Ok(root()), Ok(template()), reply],
            _ => unreachable!(),
        };
        run_test(&mut ScriptedTransport::new(replies), false).await
    }

    #[test]
    fn accepted_set_vectors_and_boundaries() {
        assert_eq!(
            accepted_set(&["1"]).unwrap().0,
            "e3109e79014641e8d92907f3030bcbc187e991df02b1ab0893e15578302c1d0a"
        );
        assert_eq!(
            accepted_set(&["2", "1", "2"]).unwrap().0,
            "45051fcac43b37be314619cdfb3530ecd45c8a500b0521f29567857cd75b9df9"
        );
        assert!(accepted_set(&["01", "1"]).is_none());
        assert!(accepted_set(&["00"]).is_none());
    }
    #[test]
    fn uuid_and_generation_grammar() {
        assert!(ElasticsearchClusterUuid::parse("KUrXRgwRRQu-RikmIJhm0Q").is_some());
        assert!(ElasticsearchClusterUuid::parse("short").is_none());
        assert_eq!(
            TargetGeneration::parse(&"a".repeat(64))
                .unwrap()
                .to_string(),
            "a".repeat(64)
        );
    }
    #[test]
    fn status_rows_are_closed() {
        assert_eq!(
            status_reason(404, FailedStage::RootInfo),
            Reason::Destination
        );
        assert_eq!(
            status_reason(404, FailedStage::TemplateRead),
            Reason::Compatibility
        );
        assert_eq!(
            status_reason(404, FailedStage::MappingRead),
            Reason::Destination
        );
        assert_eq!(status_reason(401, FailedStage::MappingRead), Reason::Auth);
        assert_eq!(
            status_reason(418, FailedStage::MappingRead),
            Reason::Unclassified4xx
        );
    }
    #[test]
    fn scanner_boundaries() {
        assert!(checked_json(br#"{"x":"\uD83D\uDE00"}"#).is_some());
        assert!(checked_json(br#"{"x":"\uD800"}"#).is_none());
        assert!(checked_json(b"[]").is_some());
    }

    #[tokio::test]
    async fn per_stage_status_matrix_and_all_transport_failures() {
        let statuses = [
            100, 199, 200, 201, 299, 300, 399, 400, 401, 403, 404, 408, 413, 429, 418, 500, 599,
        ];
        for stage in [
            FailedStage::RootInfo,
            FailedStage::TemplateRead,
            FailedStage::MappingRead,
        ] {
            for status in statuses {
                if status == 200 {
                    let mut transport =
                        ScriptedTransport::new(vec![Ok(root()), Ok(template()), Ok(mapping())]);
                    let report = run_test(&mut transport, false).await;
                    assert_eq!(report.reason, Reason::Ready, "{stage:?} 200");
                    continue;
                }
                let reply = Ok(received(status, b"malformed"));
                let report = probe_for(stage, reply).await;
                let expected_reason = match status {
                    200 => unreachable!(),
                    401 | 403 => Reason::Auth,
                    408 | 429 | 500..=599 => Reason::Connectivity,
                    300..=399 => Reason::Destination,
                    400 | 413 => Reason::Compatibility,
                    404 if matches!(stage, FailedStage::RootInfo | FailedStage::MappingRead) => {
                        Reason::Destination
                    }
                    404 => Reason::Compatibility,
                    400..=499 => Reason::Unclassified4xx,
                    _ => Reason::Compatibility,
                };
                assert_eq!(report.reason, expected_reason, "{stage:?} {status}");
                if status != 200 {
                    assert_eq!(report.failed_stage, stage);
                }
            }
            for failure in [
                TransportFailure::Dns,
                TransportFailure::TlsPeer,
                TransportFailure::Connect,
                TransportFailure::Reset,
                TransportFailure::Read,
                TransportFailure::MidBody,
                TransportFailure::Deadline,
            ] {
                let report = probe_for(stage, Err(failure)).await;
                assert_eq!(
                    (report.reason, report.failed_stage),
                    (Reason::Connectivity, stage)
                );
            }
        }
    }

    #[test]
    fn compound_status_body_precedence_and_content_encoding() {
        let gen = generation();
        for stage in [
            FailedStage::RootInfo,
            FailedStage::TemplateRead,
            FailedStage::MappingRead,
        ] {
            let auth =
                classify_http(Ok(received(401, b"{bad")), stage, &gen, None, None).unwrap_err();
            assert_eq!(auth.reason, Reason::Auth);
            let unavailable = classify_http(
                Ok(Received {
                    status: 503,
                    encoding: ContentEncoding::Unsupported,
                    body: Err(BodyRead::CapExceeded),
                }),
                stage,
                &gen,
                None,
                None,
            )
            .unwrap_err();
            assert_eq!(unavailable.reason, Reason::Connectivity);
            let over = classify_http(
                Ok(Received {
                    status: 200,
                    encoding: ContentEncoding::AbsentOrIdentity,
                    body: Err(BodyRead::CapExceeded),
                }),
                stage,
                &gen,
                None,
                None,
            )
            .unwrap_err();
            assert_eq!(over.reason, Reason::Compatibility);
            let partial = classify_http(
                Ok(Received {
                    status: 200,
                    encoding: ContentEncoding::AbsentOrIdentity,
                    body: Err(BodyRead::Transport),
                }),
                stage,
                &gen,
                None,
                None,
            )
            .unwrap_err();
            assert_eq!(partial.reason, Reason::Connectivity);
            let compressed =
                classify_http(Ok(encoded(200, b"{}")), stage, &gen, None, None).unwrap_err();
            assert_eq!(compressed.reason, Reason::Compatibility);
            let ignored_encoding =
                classify_http(Ok(encoded(401, b"{}")), stage, &gen, None, None).unwrap_err();
            assert_eq!(ignored_encoding.reason, Reason::Auth);
        }
    }

    #[test]
    fn content_encoding_checks_all_header_values() {
        use reqwest::header::{HeaderMap, HeaderValue, CONTENT_ENCODING};

        let mut headers = HeaderMap::new();
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("identity"));
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert_eq!(content_encoding(&headers), ContentEncoding::Unsupported);

        let mut identity_with_ows = HeaderMap::new();
        identity_with_ows.append(CONTENT_ENCODING, HeaderValue::from_static(" identity\t"));
        identity_with_ows.append(CONTENT_ENCODING, HeaderValue::from_static("IDENTITY"));
        assert_eq!(
            content_encoding(&identity_with_ows),
            ContentEncoding::AbsentOrIdentity
        );

        let mut malformed = HeaderMap::new();
        malformed.append(
            CONTENT_ENCODING,
            HeaderValue::from_bytes(b"\xff").expect("header bytes are representable"),
        );
        assert_eq!(content_encoding(&malformed), ContentEncoding::Unsupported);
    }

    #[tokio::test]
    async fn request_sequence_exact_paths_and_no_redirect_follow() {
        let mut success = ScriptedTransport::new(vec![Ok(root()), Ok(template()), Ok(mapping())]);
        let report = run_test(&mut success, false).await;
        assert_eq!(report.reason, Reason::Ready);
        assert_eq!(success.paths, ["/", TEMPLATE_PATH, MAPPING_PATH]);

        let mut redirect = ScriptedTransport::new(vec![Ok(received(302, b"")), Ok(root())]);
        let report = run_test(&mut redirect, false).await;
        assert_eq!(report.reason, Reason::Destination);
        assert_eq!(redirect.paths, ["/"]);

        let mut e1_fails = ScriptedTransport::new(vec![Err(TransportFailure::Dns)]);
        run_test(&mut e1_fails, false).await;
        assert_eq!(e1_fails.paths, ["/"]);
        let mut e2_fails = ScriptedTransport::new(vec![Ok(root()), Ok(received(404, b""))]);
        run_test(&mut e2_fails, false).await;
        assert_eq!(e2_fails.paths, ["/", TEMPLATE_PATH]);
    }

    #[tokio::test]
    async fn pending_requires_successful_template_and_mapping() {
        let mut success = ScriptedTransport::new(vec![Ok(root()), Ok(template()), Ok(mapping())]);
        let ready_pending = run_test(&mut success, true).await;
        assert_eq!(ready_pending.reason, Reason::PendingEnrollment);
        let mut template_transport =
            ScriptedTransport::new(vec![Ok(root()), Ok(received(404, b""))]);
        let template_failure = run_test(&mut template_transport, true).await;
        assert_eq!(template_failure.reason, Reason::Compatibility);
        let mut mapping_transport =
            ScriptedTransport::new(vec![Ok(root()), Ok(template()), Ok(received(200, b"[]"))]);
        let mapping_failure = run_test(&mut mapping_transport, true).await;
        assert_eq!(
            (mapping_failure.reason, mapping_failure.failed_stage),
            (Reason::Compatibility, FailedStage::MappingRead)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shared_deadline_slow_body() {
        let mut transport =
            ScriptedTransport::with_delays(vec![Ok(root())], vec![Duration::from_secs(11)]);
        let report = run_test_with_clock(&mut transport, &FixedClock).await;
        assert_eq!(
            (report.reason, report.failed_stage),
            (Reason::Connectivity, FailedStage::RootInfo)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn e1_consumes_budget_for_e2() {
        let mut transport = ScriptedTransport::with_delays(
            vec![Ok(root()), Ok(template())],
            vec![Duration::from_secs(9), Duration::from_secs(2)],
        );
        let report = run_test_with_clock(&mut transport, &FixedClock).await;
        assert_eq!(
            (report.reason, report.failed_stage),
            (Reason::Connectivity, FailedStage::TemplateRead)
        );
        assert_eq!(transport.paths, ["/", TEMPLATE_PATH]);
    }

    #[tokio::test]
    async fn mid_body_deadline() {
        let mut mid_body = ScriptedTransport::new(vec![
            Ok(root()),
            Ok(Received {
                status: 200,
                encoding: ContentEncoding::AbsentOrIdentity,
                body: Err(BodyRead::Transport),
            }),
        ]);
        let report = run_test(&mut mid_body, false).await;
        assert_eq!(
            (report.reason, report.failed_stage),
            (Reason::Connectivity, FailedStage::TemplateRead)
        );
    }

    #[tokio::test]
    async fn real_read_body_enforces_the_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn response(body: Vec<u8>) -> Option<reqwest::Response> {
            let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
                // The restricted build sandbox prohibits listeners; CI executes this path.
                return None;
            };
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                // Drain the request head before responding: closing a socket with
                // unread inbound bytes raises RST, and Windows discards the buffered
                // response on RST (WSAECONNABORTED 10053) where Linux delivers it.
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..n]);
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.ok();
            });
            Some(
                reqwest::Client::new()
                    .get(format!("http://{address}"))
                    .send()
                    .await
                    .unwrap(),
            )
        }
        let Some(small) = response(vec![b'x'; BODY_LIMIT]).await else {
            return;
        };
        let Some(large) = response(vec![b'x'; BODY_LIMIT + 1]).await else {
            return;
        };
        assert_eq!(read_body(small).await.unwrap().len(), BODY_LIMIT);
        assert_eq!(read_body(large).await, Err(BodyRead::CapExceeded));
    }

    #[tokio::test]
    async fn malformed_ca_is_local_with_all_nullable_fields_null() {
        let mut environment = TestEnvironment::default();
        environment.public.insert(
            PathBuf::from("bad-ca.pem"),
            b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n".to_vec(),
        );
        let mut check_args = args(false);
        check_args.ca_file = Some("bad-ca.pem".into());
        let mut transport = ScriptedTransport::new(vec![Ok(root())]);
        let report = run_check(check_args, &environment, &SystemClock, &mut transport)
            .await
            .unwrap();
        assert_eq!(report.json_line().unwrap(), "{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"failed\",\"reason\":\"local_config\",\"failed_stage\":\"local\",\"target_generation\":null,\"observed_cluster_uuid\":null,\"accepted_set_digest\":null}\n");
        assert!(transport.paths.is_empty());
    }

    const CA_ONE: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIC/TCCAeWgAwIBAgIUNuVEiOSIO+MeY0tGUf7Rb2eA6DAwDQYJKoZIhvcNAQEL\nBQAwDjEMMAoGA1UEAwwDb25lMB4XDTI2MDczMTA3NTgwOFoXDTI2MDgwMTA3NTgw\nOFowDjEMMAoGA1UEAwwDb25lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAu13Avf5Xg8yJKV7Hn/cVH7EL3ukUcgVhv5dLAnRh/D30vJXDzUtxC616YvPZ\ntrA5gfQtY5T+wSNqNtgCOxLtMokcCL4ztKecl1Bfc53RG4ZLyfwC4dctlzibONlt\njjIdEVvCHgvBcxxulNdQPjbhr9ojzyxufnW3Qe7tmAPCp6vAF7aF01eDT7TGxMOP\nZFuWIgddCh5++6srD/GWnACGYi7W7K1MiHPVi76nrCdFm7Hz3PU5NX8yXUdqZnxS\nQUdlpyZFPGZEKj7vkr5/326JYaSQV0aAxb4Th59FuygpRcJBveQyDoz9eIBveUAQ\n515potgPkOW8MJGRWncYog5JLwIDAQABo1MwUTAdBgNVHQ4EFgQUW5sFmg3PLdp5\n5TH8AdGJ42i5keIwHwYDVR0jBBgwFoAUW5sFmg3PLdp55TH8AdGJ42i5keIwDwYD\nVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAO2ijKSGHun5zFsuym24r\nXG8AFWOFdmcS71waIAQYhnabaOcgao1yKIuXm29EECWe91NfKqphuEOOOWBuTvhi\n0awbR/cjNoClj+rz34Nf0gs7sbCmtzFhYR03OzftvPdO7xUu9l5AbV4ygxhL22E9\nANAFiJFQC21zk3ggM2sgug8YixLst22RPufAPRKT/fw7SPdSb3/Pu1Fct7ytfRe+\nZAoADS2RqkcDHNZt37SE6KyfkqUG//MIpYcEkSNuo27pDTHverlI799Ivn8I53Eu\nw1wiyPx3+TbNwxavRwy2yIBfd3/v1dOxfNvUUhOVdQYIh2cYroiW94Bk+ROtzhf+\ngg==\n-----END CERTIFICATE-----\n";
    const CA_TWO: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIC/TCCAeWgAwIBAgIUD8IdcYEKVQp0Z6tvR8hLQWBy++cwDQYJKoZIhvcNAQEL\nBQAwDjEMMAoGA1UEAwwDdHdvMB4XDTI2MDczMTA3NTgwOFoXDTI2MDgwMTA3NTgw\nOFowDjEMMAoGA1UEAwwDdHdvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAkJbqFlqs0sWFsuRmcJMgEEdU1Cpf0LJLty/5h920NTS8Kc2OsQ/kJL5WzPdv\n1WgEo9n+WIQqfu9R/laK34e0cCi+2ckGHqwEro1X3PITooaRUoCxTZOKAyngnd1A\n90Qw31Qv/4/fVibqrR0WHWkd6hT12j2tmiY36/K5oOikYjSO4bkWX0P7nfe23LaQ\nY7b+YZjA4lDyrbKN4gE6Cdfts5Gfd2LcclWp4sooVbgvIyhu7mQq2Aa6I/QQWxgl\nbPJkW6uz69XCfz8aN8G3gUQUzS+PBpfxbdsEwwwy+J65Y4Y0Ihf0/aYUt3JV3clH\nKB+aL2SM7jGCfYFNljmTfIwuMQIDAQABo1MwUTAdBgNVHQ4EFgQUuguqua9iEiqi\n6hFW0D2vx1CDt0wwHwYDVR0jBBgwFoAUuguqua9iEiqi6hFW0D2vx1CDt0wwDwYD\nVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAUX/NA+mC9sgjZDI8/6xo\nZ2Cntvg/g+78ekBvZnH+EtT9kHqTjfu0R5BeTc1y20Alu3Dy0V9McCfpTQKCgQH6\nxsg80Dh4dtfysZtxRcYuk+hWCpWj0Ms1EfowyWrf1xHdXtXGhaU5RVfFo92z4PNm\nBmCtit2n+VietNHpcBPEdN1G3RiN/xdD/6yP6dDmoQmwkrPj6uZoY2Mn42KBQznI\nuQOXAMa318rGM7u8ZbJ9MgY8d7hCGp+oV6aXnUOb+Bhu7DbgRlmfgE/+z+0CAFWW\nDFJ9gmBMfXV2dMjhJ9IQpq3yvJpLfeBESTuKPcpRMVizUpZc96E904TecZerss58\nXg==\n-----END CERTIFICATE-----\n";

    #[tokio::test]
    async fn two_certificate_ca_bundle_is_accepted() {
        let mut environment = TestEnvironment::default();
        environment
            .public
            .insert(PathBuf::from("ca-bundle.pem"), [CA_ONE, CA_TWO].concat());
        let mut check_args = args(false);
        check_args.ca_file = Some("ca-bundle.pem".into());
        let mut transport = ScriptedTransport::new(vec![Ok(root()), Ok(template()), Ok(mapping())]);
        let report = run_check(check_args, &environment, &SystemClock, &mut transport)
            .await
            .unwrap();
        assert_eq!(report.reason, Reason::Ready);
        assert_eq!(transport.paths, ["/", TEMPLATE_PATH, MAPPING_PATH]);
    }

    #[tokio::test]
    async fn empty_or_malformed_ca_bundle_is_local_before_transport() {
        for (name, ca) in [
            ("empty.pem", Vec::new()),
            ("garbage.pem", b"not a PEM certificate".to_vec()),
            ("trailing.pem", [CA_ONE, b"trailing junk"].concat()),
            (
                "private-key.pem",
                [
                    CA_ONE,
                    b"-----BEGIN PRIVATE KEY-----\njunk\n-----END PRIVATE KEY-----\n",
                ]
                .concat(),
            ),
        ] {
            let mut environment = TestEnvironment::default();
            environment.public.insert(PathBuf::from(name), ca);
            let mut check_args = args(false);
            check_args.ca_file = Some(name.into());
            let mut transport = ScriptedTransport::new(vec![Ok(root())]);
            let report = run_check(check_args, &environment, &SystemClock, &mut transport)
                .await
                .unwrap();
            assert_eq!(report.json_line().unwrap(), "{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"failed\",\"reason\":\"local_config\",\"failed_stage\":\"local\",\"target_generation\":null,\"observed_cluster_uuid\":null,\"accepted_set_digest\":null}\n");
            assert!(transport.paths.is_empty());
        }
    }

    #[tokio::test]
    async fn legacy_env_ignored() {
        let mut environment = TestEnvironment::default();
        for (key, value) in [
            ("RIGSIGNAL_CONFIG", "wrong.toml"),
            ("ES_API_KEY", "wrong-key"),
            ("ES_URL", "https://wrong.test"),
            ("ES_CA_CERT", "wrong-ca.pem"),
        ] {
            environment.values.insert(key.into(), value.into());
        }
        let mut transport = ScriptedTransport::new(vec![Ok(root()), Ok(template()), Ok(mapping())]);
        let report = run_check(args(false), &environment, &SystemClock, &mut transport)
            .await
            .unwrap();
        assert_eq!(report.reason, Reason::Ready);
        assert_eq!(transport.paths, ["/", TEMPLATE_PATH, MAPPING_PATH]);
    }

    #[test]
    fn scanner_boundaries_duplicates_and_chunks() {
        let nested = |depth: usize| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert!(checked_json(nested(32).as_bytes()).is_some());
        assert!(checked_json(nested(33).as_bytes()).is_none());
        // This isolates the scanner accounting (syntax validity is established
        // separately by serde after scanning): each colon is one token.
        assert!(scan_json(&vec![b':'; 4096]).is_some());
        assert!(scan_json(&vec![b':'; 4097]).is_none());
        assert!(checked_json(format!(r#""{}""#, "a".repeat(4096)).as_bytes()).is_some());
        assert!(checked_json(format!(r#""{}""#, "a".repeat(4097)).as_bytes()).is_none());
        assert!(checked_json(br#""a\n\uD83D\uDE00""#).is_some());
        assert!(checked_json(br#""\uD800""#).is_none());
        assert!(checked_json(&vec![b' '; BODY_LIMIT]).is_none());
        assert!(checked_json(&vec![b' '; BODY_LIMIT + 1]).is_none());
        let body = br#"{"cluster_uuid":"KUrXRgwRRQu-RikmIJhm0Q"}"#;
        for split in 0..=body.len() {
            let joined = [&body[..split], &body[split..]].concat();
            assert!(root_uuid(&joined).is_some());
        }
        assert!(root_uuid(
            br#"{"cluster_uuid":"KUrXRgwRRQu-RikmIJhm0Q","cluster_uuid":"KUrXRgwRRQu-RikmIJhm0Q"}"#
        )
        .is_none());
        assert!(template_set(br#"{"component_templates":[],"component_templates":[]}"#).is_none());
        assert!(template_set(br#"{"component_templates":[{"name":"logs-rigsignal.diagnosis-mappings","name":"logs-rigsignal.diagnosis-mappings","component_template":{"_meta":{"accepted_schema_versions":["1"]}}}]}"#).is_none());
        assert!(template_set(br#"{"component_templates":[{"name":"logs-rigsignal.diagnosis-mappings","component_template":{"_meta":{"accepted_schema_versions":["1"]}},"component_template":{"_meta":{"accepted_schema_versions":["1"]}}}]}"#).is_none());
        assert!(template_set(br#"{"component_templates":[{"name":"logs-rigsignal.diagnosis-mappings","component_template":{"_meta":{"accepted_schema_versions":["1"],"accepted_schema_versions":["1"]}}}]}"#).is_none());
        assert!(template_set(br#"{"component_templates":[{"name":"logs-rigsignal.diagnosis-mappings","component_template":{"_meta":{"accepted_schema_versions":["1"]},"_meta":{"accepted_schema_versions":["1"]}}}]}"#).is_none());
        // A protected spelling below an extra array level is not on the
        // protected path. The shape check, rather than duplicate detection,
        // rejects this response.
        let different_nesting = br#"{"component_templates":[[{"name":"a","name":"b"}]]}"#;
        assert!(checked_json_stage(different_nesting, ProtectedStage::Template).is_some());
        assert!(template_set(different_nesting).is_none());
        assert!(
            root_uuid(br#"{"other":1,"other":2,"cluster_uuid":"KUrXRgwRRQu-RikmIJhm0Q"}"#)
                .is_some()
        );
    }

    #[test]
    fn accepted_set_full_grammar_and_framing() {
        let entries: Vec<String> = (1..=256).map(|n| n.to_string()).collect();
        let refs: Vec<&str> = entries.iter().map(String::as_str).collect();
        assert!(accepted_set(&refs).is_some());
        let too_many: Vec<String> = (1..=257).map(|n| n.to_string()).collect();
        assert!(accepted_set(&too_many.iter().map(String::as_str).collect::<Vec<_>>()).is_none());
        for invalid in ["4294967296", "12345678901", "0", "00", "01", "١", ""] {
            assert!(accepted_set(&[invalid]).is_none(), "{invalid:?}");
        }
        assert!(valid_version("4294967295"));
        assert!(valid_version("1234567890"));
        assert_eq!(
            accepted_set(&["10", "2"]).unwrap().0,
            digest_entries(&["10".to_owned(), "2".to_owned()])
        );
        assert_eq!(
            accepted_set(&["2", "1", "2"]).unwrap().0,
            accepted_set(&["1", "2"]).unwrap().0
        );
        assert_eq!(
            digest_entries(&["01".to_owned(), "1".to_owned()]),
            "ef6b086833d882eb0b66911d50184c24f593cae0b24acec0bba9f25166928dd6"
        );
        assert!(template_set(br#"{"component_templates":[{"name":"logs-rigsignal.diagnosis-mappings","component_template":{"_meta":{"accepted_schema_versions":[1]}}}]}"#).is_none());
    }

    #[test]
    fn report_nullability_and_golden_json_lines() {
        let gen = generation();
        let observed = ElasticsearchClusterUuid::parse(UUID).unwrap();
        let local =
            ClassifiedProbe::failure(Reason::LocalConfig, FailedStage::Local, None, None, None);
        assert_eq!(local.json_line().unwrap(), "{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"failed\",\"reason\":\"local_config\",\"failed_stage\":\"local\",\"target_generation\":null,\"observed_cluster_uuid\":null,\"accepted_set_digest\":null}\n");
        let mismatch = ClassifiedProbe::failure(
            Reason::Destination,
            FailedStage::RootInfo,
            Some(&gen),
            Some(&observed),
            None,
        );
        assert_eq!(mismatch.observed_cluster_uuid.as_deref(), Some(UUID));
        let nonmember = ClassifiedProbe::failure(
            Reason::Compatibility,
            FailedStage::TemplateRead,
            Some(&gen),
            Some(&observed),
            Some("digest".into()),
        );
        assert_eq!(nonmember.accepted_set_digest.as_deref(), Some("digest"));
        let wrong_name = ClassifiedProbe::failure(
            Reason::Compatibility,
            FailedStage::TemplateRead,
            Some(&gen),
            Some(&observed),
            None,
        );
        assert!(wrong_name.accepted_set_digest.is_none());
        for reason in [
            Reason::Connectivity,
            Reason::Auth,
            Reason::Destination,
            Reason::Compatibility,
            Reason::Unclassified4xx,
        ] {
            let e3 = ClassifiedProbe::failure(
                reason,
                FailedStage::MappingRead,
                Some(&gen),
                Some(&observed),
                Some("digest".into()),
            );
            assert_eq!(
                (
                    e3.failed_stage,
                    e3.observed_cluster_uuid.as_deref(),
                    e3.accepted_set_digest.as_deref()
                ),
                (FailedStage::MappingRead, Some(UUID), Some("digest"))
            );
        }
        let digest = "e3109e79014641e8d92907f3030bcbc187e991df02b1ab0893e15578302c1d0a";
        let fixtures = [
            (ClassifiedProbe::success(false, &gen, &observed, digest.into()), format!("{{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"ready\",\"reason\":\"ready\",\"failed_stage\":\"none\",\"target_generation\":\"{GEN}\",\"observed_cluster_uuid\":\"{UUID}\",\"accepted_set_digest\":\"{digest}\"}}\n")),
            (ClassifiedProbe::success(true, &gen, &observed, digest.into()), format!("{{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"pending_enrollment\",\"reason\":\"pending_enrollment\",\"failed_stage\":\"none\",\"target_generation\":\"{GEN}\",\"observed_cluster_uuid\":\"{UUID}\",\"accepted_set_digest\":\"{digest}\"}}\n")),
            (ClassifiedProbe::failure(Reason::LocalConfig, FailedStage::Local, None, None, None), "{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"failed\",\"reason\":\"local_config\",\"failed_stage\":\"local\",\"target_generation\":null,\"observed_cluster_uuid\":null,\"accepted_set_digest\":null}\n".into()),
            (ClassifiedProbe::failure(Reason::Connectivity, FailedStage::RootInfo, Some(&gen), None, None), format!("{{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"failed\",\"reason\":\"connectivity\",\"failed_stage\":\"root_info\",\"target_generation\":\"{GEN}\",\"observed_cluster_uuid\":null,\"accepted_set_digest\":null}}\n")),
            (ClassifiedProbe::failure(Reason::Auth, FailedStage::TemplateRead, Some(&gen), Some(&observed), None), format!("{{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"failed\",\"reason\":\"auth\",\"failed_stage\":\"template_read\",\"target_generation\":\"{GEN}\",\"observed_cluster_uuid\":\"{UUID}\",\"accepted_set_digest\":null}}\n")),
            (ClassifiedProbe::failure(Reason::Destination, FailedStage::RootInfo, Some(&gen), Some(&observed), None), format!("{{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"failed\",\"reason\":\"destination\",\"failed_stage\":\"root_info\",\"target_generation\":\"{GEN}\",\"observed_cluster_uuid\":\"{UUID}\",\"accepted_set_digest\":null}}\n")),
            (ClassifiedProbe::failure(Reason::Compatibility, FailedStage::TemplateRead, Some(&gen), Some(&observed), None), format!("{{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"failed\",\"reason\":\"compatibility\",\"failed_stage\":\"template_read\",\"target_generation\":\"{GEN}\",\"observed_cluster_uuid\":\"{UUID}\",\"accepted_set_digest\":null}}\n")),
            (ClassifiedProbe::failure(Reason::Unclassified4xx, FailedStage::TemplateRead, Some(&gen), Some(&observed), None), format!("{{\"probe_schema_version\":1,\"diagnosis_schema_version\":1,\"outcome\":\"failed\",\"reason\":\"unclassified_4xx\",\"failed_stage\":\"template_read\",\"target_generation\":\"{GEN}\",\"observed_cluster_uuid\":\"{UUID}\",\"accepted_set_digest\":null}}\n")),
        ];
        for (probe, fixture) in fixtures {
            assert_eq!(probe.json_line().unwrap(), fixture);
        }
    }

    #[test]
    fn endpoint_affinity_and_secret_resolution_rules() {
        for bad in [
            "ftp://host",
            "http://",
            "http://@host",
            "http://u:p@host",
            "http://host/x",
            "http://host/?x",
            "http://host/#x",
        ] {
            assert!(endpoint_origin(bad).is_none(), "{bad}");
        }
        assert_eq!(
            endpoint_origin("https://host:9200/").as_deref(),
            Some("https://host:9200")
        );
        let mut check_args = CheckArgs {
            endpoint: None,
            ca_file: None,
            expected_cluster_uuid: None,
            pending_enrollment: false,
            target_generation: None,
            credentials_file: None,
            config: None,
        };
        let shipping = ProtectedShipping::default();
        assert!(
            resolve_affinity(&TestEnvironment::default(), &check_args, &shipping, None).is_err()
        );
        check_args.expected_cluster_uuid = Some(UUID.into());
        assert!(matches!(
            resolve_affinity(&TestEnvironment::default(), &check_args, &shipping, None),
            Ok(Affinity::Expected(_))
        ));
        check_args.pending_enrollment = true;
        assert!(
            resolve_affinity(&TestEnvironment::default(), &check_args, &shipping, None).is_err()
        );
        assert!(
            credentials_from_values(Some("".into()), Some("user".into()), Some("pass".into()))
                .is_err()
        );
        assert!(credentials_from_values(Some("bad\r\nkey".into()), None, None).is_err());
        assert!(credentials_from_values(None, Some("user".into()), None).is_err());
        let mut invalid_env = TestEnvironment::default();
        invalid_env
            .invalid_values
            .insert("RIGSIGNAL_ES_ENDPOINT".into());
        let mut env_endpoint_args = args(false);
        env_endpoint_args.endpoint = None;
        assert!(preflight(&invalid_env, &env_endpoint_args).is_err());
        let sentinel = "SENTINEL-CREDENTIAL-MUST-NOT-LEAK";
        let report = ClassifiedProbe::failure(
            Reason::Connectivity,
            FailedStage::RootInfo,
            Some(&generation()),
            None,
            None,
        );
        assert!(!report.json_line().unwrap().contains(sentinel));
    }

    #[cfg(unix)]
    #[test]
    fn protected_source_metadata_negatives() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let uid = unsafe { libc::geteuid() };
        assert!(protected_metadata_valid(0o600, uid, uid, true));
        assert!(protected_metadata_valid(0o400, uid, uid, true));
        assert!(!protected_metadata_valid(0o644, uid, uid, true));
        assert!(!protected_metadata_valid(
            0o600,
            uid.wrapping_add(1),
            uid,
            true
        ));
        assert!(!protected_metadata_valid(0o600, uid, uid, false));
        let stem = std::env::temp_dir().join(format!("rigsignal-handshake-{}", std::process::id()));
        let file = stem.with_extension("toml");
        let link = stem.with_extension("link");
        let directory = stem.with_extension("dir");
        let missing = stem.with_extension("missing");
        let fifo = stem.with_extension("fifo");
        let write = |text: &str, mode: u32| {
            std::fs::write(&file, text).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        assert!(credentials_from_file(&ProcessEnvironment, &missing).is_err());
        std::fs::create_dir_all(&directory).unwrap();
        assert!(credentials_from_file(&ProcessEnvironment, &directory).is_err());
        let fifo_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        // O_NONBLOCK makes this return immediately; fstat then rejects the FIFO.
        assert!(credentials_from_file(&ProcessEnvironment, &fifo).is_err());
        assert!(credentials_from_file(&ProcessEnvironment, Path::new("/dev/null")).is_err());
        write("[elasticsearch]\napi_key = 'key'\n", 0o644);
        assert!(credentials_from_file(&ProcessEnvironment, &file).is_err());
        write("not toml = [", 0o600);
        assert!(credentials_from_file(&ProcessEnvironment, &file).is_err());
        write("[elasticsearch]\napi_key = 'key'\nunknown = 'x'\n", 0o600);
        assert!(credentials_from_file(&ProcessEnvironment, &file).is_err());
        write(
            "[elasticsearch]\napi_key = 'key'\n[unexpected]\nvalue = 'x'\n",
            0o600,
        );
        assert!(credentials_from_file(&ProcessEnvironment, &file).is_err());
        write("[elasticsearch]\nusername = 'user'\n", 0o600);
        assert!(credentials_from_file(&ProcessEnvironment, &file).is_err());
        write("[elasticsearch]\napi_key = 'key'\n", 0o600);
        symlink(&file, &link).unwrap();
        assert!(credentials_from_file(&ProcessEnvironment, &link).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_file(&fifo).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn protected_shipping_schema_rejects_unknown_keys() {
        let mut environment = TestEnvironment::default();
        environment.protected.insert(
            PathBuf::from("config.toml"),
            "[shipping]\nunknown = 'must-not-be-ignored'\n".into(),
        );
        assert!(parse_protected(&environment, Path::new("config.toml")).is_err());
    }

    #[test]
    fn protected_config_and_dedicated_credentials_reject_ambiguous_fields() {
        let mut environment = TestEnvironment::default();
        environment.protected.insert(
            PathBuf::from("config.toml"),
            "[elasticsearch]\nendpoint = 'https://example.test'\nunknown = 'x'\n".into(),
        );
        assert!(parse_protected(&environment, Path::new("config.toml")).is_err());
        environment.protected.insert(
            PathBuf::from("creds.toml"),
            "[elasticsearch]\napi_key = 'key'\nusername = 'user'\npassword = 'pass'\n".into(),
        );
        assert!(credentials_from_file(&environment, Path::new("creds.toml")).is_err());
    }

    #[test]
    fn classified_exit_map_is_closed() {
        assert_eq!(
            [
                Reason::Ready,
                Reason::PendingEnrollment,
                Reason::LocalConfig,
                Reason::Connectivity,
                Reason::Auth,
                Reason::Destination,
                Reason::Compatibility,
                Reason::Unclassified4xx
            ]
            .map(|reason| ClassifiedProbe::failure(
                reason,
                FailedStage::Local,
                None,
                None,
                None
            )
            .exit_code()),
            [0, 10, 11, 12, 13, 14, 15, 16]
        );
    }
}
