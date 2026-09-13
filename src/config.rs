/// Configuration — reads the shared rigsignal.toml file.
///
/// Mirrors the Python collector's config.py exactly so both agents
/// read the same file without conflict.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::warn;

static SPOOL_RETENTION_DEPRECATION_WARNED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub elasticsearch: ElasticsearchConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub collection: CollectionConfig,
    #[serde(default)]
    pub privacy: PrivacyConfig,
    #[serde(default)]
    pub session: SessionConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutputMode {
    #[default]
    Elasticsearch,
    Spool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutputConfig {
    #[serde(default)]
    pub mode: OutputMode,
    #[serde(default = "default_spool_dir")]
    pub spool_dir: PathBuf,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    #[serde(default = "default_max_file_age_secs")]
    pub max_file_age_secs: u64,
    /// Deprecated for final spool retention. The separately installed helper owns
    /// delivery-proof-gated final cleanup; the producer uses this only for recovery
    /// quarantine debris.
    #[serde(default = "default_spool_retention_hours")]
    pub spool_retention_hours: u64,
}

fn default_spool_dir() -> PathBuf {
    if let Some(home) = home_dir() {
        home.join(".local/state/rigsignal/spool")
    } else {
        PathBuf::from(".local/state/rigsignal/spool")
    }
}

fn default_max_file_bytes() -> u64 {
    10_485_760
}

fn default_max_file_age_secs() -> u64 {
    300
}

fn default_spool_retention_hours() -> u64 {
    72
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            mode: OutputMode::Elasticsearch,
            spool_dir: default_spool_dir(),
            max_file_bytes: default_max_file_bytes(),
            max_file_age_secs: default_max_file_age_secs(),
            spool_retention_hours: default_spool_retention_hours(),
        }
    }
}

/// Optional per-session metadata the user can set in rigsignal.toml.
///
/// [session]
/// label = "after-driver-update"
///
/// [session.settings]
/// preset = "ultra"
/// upscaler_tech = "dlss"
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SessionConfig {
    /// A short human-readable annotation for this session (e.g. "proton-9-test").
    /// Written to every doc as rigsignal.session.label for easy dashboard filtering.
    pub label: Option<String>,
    #[serde(default)]
    pub settings: SessionSettingsConfig,
    pub target_pid: Option<u32>,
    pub target_name: Option<String>,
}

/// Tier 1 manual settings capture — populated from [session.settings] in the config
/// and/or CLI flags. All fields optional; unset fields are omitted from session docs.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SessionSettingsConfig {
    pub preset: Option<String>,
    pub upscaler_tech: Option<String>,
    pub upscaler_preset: Option<String>,
    pub frame_gen_tech: Option<String>,
    pub features_active: Option<Vec<String>>,
    pub render_resolution_output: Option<String>,
    pub render_vsync: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ElasticsearchConfig {
    pub endpoint: String,
    pub api_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// PEM CA bundle for a self-signed Elasticsearch TLS endpoint (same convention
    /// as the eBPF daemon's elasticsearch.ca_cert).
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    #[serde(default = "default_index_prefix")]
    pub index_prefix: String,
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_index_prefix() -> String {
    "rigsignal".to_string()
}
fn default_flush_interval_secs() -> u64 {
    5
}
fn default_batch_size() -> usize {
    100
}

impl Default for ElasticsearchConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:9200".to_string(),
            api_key: None,
            username: None,
            password: None,
            ca_cert: None,
            index_prefix: default_index_prefix(),
            flush_interval_secs: default_flush_interval_secs(),
            batch_size: default_batch_size(),
        }
    }
}

impl ElasticsearchConfig {
    /// Event tail delivery needs an authenticated direct bulk path even when
    /// metrics are configured for spool output.
    pub fn has_delivery_credentials(&self) -> bool {
        self.api_key
            .as_ref()
            .is_some_and(|key| !key.trim().is_empty())
            || matches!((&self.username, &self.password), (Some(user), Some(password)) if !user.is_empty() && !password.is_empty())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CollectionConfig {
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_true")]
    pub cpu: bool,
    #[serde(default = "default_true")]
    pub memory: bool,
    #[serde(default = "default_true")]
    pub gpu: bool,
    #[serde(default = "default_true")]
    pub storage: bool,
    #[serde(default = "default_true")]
    pub network: bool,
    #[serde(default)]
    pub ebpf: bool,
    #[serde(default = "default_true")]
    pub frame_timing: bool,
    #[serde(default = "default_true")]
    pub game_detection: bool,
    #[serde(default = "default_sample_interval")]
    pub sample_interval_secs: u64,
}

fn default_interval_ms() -> u64 {
    1000
}
fn default_true() -> bool {
    true
}
fn default_sample_interval() -> u64 {
    1
}

impl Default for CollectionConfig {
    fn default() -> Self {
        Self {
            interval_ms: default_interval_ms(),
            cpu: true,
            memory: true,
            gpu: true,
            storage: true,
            network: true,
            ebpf: false,
            frame_timing: true,
            game_detection: true,
            sample_interval_secs: default_sample_interval(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PrivacyConfig {
    #[serde(default)]
    pub opt_in_public: bool,
    #[serde(default)]
    pub share_ebpf: bool,
    #[serde(default)]
    pub share_network: bool,
}

impl Config {
    /// Load config from an explicit path or the first found default location.
    ///
    /// Search order:
    ///   1. `path` argument (from --config CLI flag)
    ///   2. $RIGSIGNAL_CONFIG env var
    ///
    /// Linux fallback chain (when neither of the above is set):
    ///   3. $XDG_CONFIG_HOME/rigsignal/rigsignal.toml (or ~/.config when unset)
    ///   4. /etc/rigsignal/rigsignal.toml
    ///
    /// Windows fallback chain (when neither of the above is set):
    ///   3. %APPDATA%\RigSignal\rigsignal.toml          (per-user)
    ///   4. %PROGRAMDATA%\RigSignal\rigsignal.toml      (system-wide)
    pub fn load(path: Option<&PathBuf>) -> Result<Self> {
        let candidates: Vec<PathBuf> = if let Some(p) = path {
            vec![p.clone()]
        } else if let Ok(env_path) = std::env::var("RIGSIGNAL_CONFIG") {
            vec![PathBuf::from(env_path)]
        } else {
            let mut v = Vec::new();
            #[cfg(windows)]
            {
                if let Ok(appdata) = std::env::var("APPDATA") {
                    v.push(
                        PathBuf::from(appdata)
                            .join("RigSignal")
                            .join("rigsignal.toml"),
                    );
                }
                if let Ok(programdata) = std::env::var("PROGRAMDATA") {
                    v.push(
                        PathBuf::from(programdata)
                            .join("RigSignal")
                            .join("rigsignal.toml"),
                    );
                }
            }
            #[cfg(not(windows))]
            {
                if let Some(user_config) = user_config_path() {
                    v.push(user_config);
                }
                v.push(PathBuf::from("/etc/rigsignal/rigsignal.toml"));
            }
            v
        };

        for candidate in &candidates {
            if candidate.exists() {
                let mut config = Self::load_from(candidate)?;
                config.apply_env_overrides();
                return Ok(config);
            }
        }
        anyhow::bail!(
            "no config file found; searched: {}",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    /// The configured endpoint reduced to a bare `scheme://host[:port]` origin,
    /// or the literal `<redacted>` when it cannot be shown to be credential-free.
    ///
    /// `endpoint` is an unvalidated bare `String` that need not be a URL at all,
    /// and it may carry a credential in userinfo or in a query parameter. The
    /// reduction REJECTS rather than sanitises, so anything it cannot prove clean
    /// is withheld entirely.
    ///
    /// NOTE THE COST, because it is not free: an endpoint with a path -- a
    /// legitimate reverse-proxied deployment, say `https://host/es/` -- is not
    /// provably credential-free by this test and renders as `<redacted>` too. The
    /// operator loses the host in that case. That is the conservative direction
    /// and it is deliberate, but it is a real diagnostic loss, not a free win.
    pub fn endpoint_for_display(&self) -> String {
        crate::handshake::endpoint_origin(&self.elasticsearch.endpoint)
            .unwrap_or_else(|| "<redacted>".to_string())
    }

    /// Return a clone suitable for display: api_key / username / password are
    /// replaced with "<redacted>", and the endpoint is reduced by
    /// `endpoint_for_display`, so the output is safe to print or log.
    ///
    /// The endpoint reduction was added after a review found this helper's NAME
    /// was doing the work its CODE did not: it redacted three fields and left the
    /// endpoint raw, and a caller printed that raw endpoint under a heading that
    /// read as redacted.
    pub fn redacted_for_display(&self) -> Self {
        let mut out = self.clone();
        out.elasticsearch.endpoint = self.endpoint_for_display();
        let es = &mut out.elasticsearch;
        if es.api_key.is_some() {
            es.api_key = Some("<redacted>".to_string());
        }
        if es.username.is_some() {
            es.username = Some("<redacted>".to_string());
        }
        if es.password.is_some() {
            es.password = Some("<redacted>".to_string());
        }
        out
    }

    /// Apply ES_API_KEY and ES_URL env vars on top of whatever was in the TOML file.
    /// Env vars win — allows key rotation without editing config files.
    fn apply_env_overrides(&mut self) {
        if let Ok(key) = std::env::var("ES_API_KEY") {
            if !key.is_empty() {
                self.elasticsearch.api_key = Some(key);
            }
        }
        if let Ok(url) = std::env::var("ES_URL") {
            if !url.is_empty() {
                self.elasticsearch.endpoint = url;
            }
        }
        if let Ok(ca_cert) = std::env::var("ES_CA_CERT") {
            if !ca_cert.is_empty() {
                self.elasticsearch.ca_cert = Some(PathBuf::from(ca_cert));
            }
        }
    }

    fn load_from(path: &PathBuf) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file: {}", path.display()))?;
        let value: toml::Value = toml::from_str(&text)
            .with_context(|| format!("parsing config file: {}", path.display()))?;
        let spool_retention_hours_set = value
            .get("output")
            .and_then(toml::Value::as_table)
            .is_some_and(|output| output.contains_key("spool_retention_hours"));
        let config: Self = value
            .try_into()
            .with_context(|| format!("parsing config file: {}", path.display()))?;
        if spool_retention_hours_set {
            warn_spool_retention_deprecation();
        }
        Ok(config)
    }
}

fn warn_spool_retention_deprecation() -> bool {
    if SPOOL_RETENTION_DEPRECATION_WARNED.swap(true, Ordering::Relaxed) {
        return false;
    }
    warn!("output.spool_retention_hours is deprecated for final spool retention; rigsignal-spool-retention handles delivery-proof-gated final cleanup");
    true
}

#[cfg(not(windows))]
fn user_config_path() -> Option<PathBuf> {
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        let config_home = PathBuf::from(config_home);
        if config_home.is_absolute() {
            return Some(config_home.join("rigsignal/rigsignal.toml"));
        }
    }
    home_dir().map(|home| home.join(".config/rigsignal/rigsignal.toml"))
}

fn home_dir() -> Option<PathBuf> {
    // When running via sudo, HOME is /root but config lives in the invoking
    // user's home. Prefer SUDO_USER → /home/<user> over HOME.
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() {
            let p = PathBuf::from("/home").join(&sudo_user);
            if p.exists() {
                return Some(p);
            }
        }
    }
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::sync::Mutex;
    use tracing::{Event, Level, Subscriber};
    use tracing_subscriber::{layer::Context, prelude::*, Layer};

    #[cfg(not(windows))]
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    static SPOOL_RETENTION_WARN_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn redacted_for_display_withholds_an_endpoint_it_cannot_prove_clean() {
        // A credential in userinfo AND one in a query parameter. Neither may
        // survive into a printed or logged config.
        let cfg: Config = toml::from_str(
            "[elasticsearch]\nendpoint = 'https://u:hunter2@es.example:9200/?api_key=CANARY'\n",
        )
        .unwrap();

        assert_eq!(cfg.endpoint_for_display(), "<redacted>");

        let shown = cfg.redacted_for_display();
        let rendered = toml::to_string_pretty(&shown).unwrap();
        for leak in ["hunter2", "CANARY", "u:hunter2"] {
            assert!(
                !rendered.contains(leak),
                "redacted config still carries {leak}: {rendered}"
            );
        }
    }

    #[test]
    fn redacted_for_display_keeps_an_endpoint_that_is_provably_clean() {
        // The common case must NOT be degraded: a bare origin survives verbatim,
        // otherwise this change would cost every operator their endpoint.
        for endpoint in [
            "https://es.example:9200",
            "https://es.example:9200/",
            "http://127.0.0.1:9200",
        ] {
            let cfg: Config =
                toml::from_str(&format!("[elasticsearch]\nendpoint = '{endpoint}'\n")).unwrap();
            assert_eq!(
                cfg.endpoint_for_display(),
                endpoint.trim_end_matches('/'),
                "clean endpoint was degraded: {endpoint}"
            );
        }
    }

    #[test]
    fn redacted_for_display_withholds_a_path_bearing_endpoint_and_that_is_a_real_cost() {
        // Documenting the CONSEQUENCE, not celebrating it. A reverse-proxied
        // deployment is credential-free but not provably so by this test, and the
        // operator loses the host from the report. If that becomes a support
        // burden, the fix is a richer reduction, not printing the raw value.
        let cfg: Config =
            toml::from_str("[elasticsearch]\nendpoint = 'https://host/es/'\n").unwrap();
        assert_eq!(cfg.endpoint_for_display(), "<redacted>");
    }

    #[derive(Clone)]
    struct WarnCounter(Arc<AtomicUsize>);

    impl<S: Subscriber> Layer<S> for WarnCounter {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            if *event.metadata().level() == Level::WARN {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[test]
    fn config_defaults_output_when_absent() {
        let cfg: Config = toml::from_str(
            r#"
            [elasticsearch]
            endpoint = "http://localhost:9200"
            "#,
        )
        .unwrap();

        assert_eq!(cfg.output.mode, OutputMode::Elasticsearch);
        assert!(cfg
            .output
            .spool_dir
            .ends_with(".local/state/rigsignal/spool"));
        assert_eq!(cfg.output.max_file_bytes, 10_485_760);
        assert_eq!(cfg.output.max_file_age_secs, 300);
        assert_eq!(cfg.output.spool_retention_hours, 72);
    }

    #[test]
    fn config_deserializes_spool_output() {
        let cfg: Config = toml::from_str(
            r#"
            [elasticsearch]
            endpoint = "http://localhost:9200"

            [output]
            mode = "spool"
            spool_dir = "/tmp/rigsignal-spool"
            max_file_bytes = 1024
            max_file_age_secs = 30
            spool_retention_hours = 24
            "#,
        )
        .unwrap();

        assert_eq!(cfg.output.mode, OutputMode::Spool);
        assert_eq!(cfg.output.spool_dir, PathBuf::from("/tmp/rigsignal-spool"));
        assert_eq!(cfg.output.max_file_bytes, 1024);
        assert_eq!(cfg.output.max_file_age_secs, 30);
        assert_eq!(cfg.output.spool_retention_hours, 24);
    }

    #[test]
    fn spool_retention_hours_deprecation_warns_once_when_explicitly_configured() -> Result<()> {
        let _lock = SPOOL_RETENTION_WARN_LOCK.lock().unwrap();
        SPOOL_RETENTION_DEPRECATION_WARNED.store(false, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rigsignal-spool-retention-deprecation-{}.toml",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            r#"
            [elasticsearch]
            endpoint = "http://localhost:9200"

            [output]
            spool_retention_hours = 24
            "#,
        )?;
        let warnings = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(WarnCounter(warnings.clone()));
        tracing::subscriber::with_default(subscriber, || -> Result<()> {
            let config = Config::load_from(&path)?;
            assert_eq!(config.output.spool_retention_hours, 24);
            Config::load_from(&path)?;
            Ok(())
        })?;
        std::fs::remove_file(&path)?;
        assert_eq!(warnings.load(Ordering::Relaxed), 1);
        SPOOL_RETENTION_DEPRECATION_WARNED.store(false, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(not(windows))]
    #[test]
    fn user_config_path_honors_absolute_xdg_config_home() {
        let _lock = ENV_LOCK.lock().unwrap();
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/rigsignal-xdg-config-test");

        assert_eq!(
            user_config_path(),
            Some(PathBuf::from(
                "/tmp/rigsignal-xdg-config-test/rigsignal/rigsignal.toml"
            ))
        );

        match previous {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn user_config_path_ignores_empty_xdg_config_home() {
        let _lock = ENV_LOCK.lock().unwrap();
        let previous_xdg = std::env::var_os("XDG_CONFIG_HOME");
        let previous_home = std::env::var_os("HOME");
        std::env::set_var("XDG_CONFIG_HOME", "");
        std::env::set_var("HOME", "/tmp/rigsignal-home-empty-xdg");

        assert_eq!(
            user_config_path(),
            Some(PathBuf::from(
                "/tmp/rigsignal-home-empty-xdg/.config/rigsignal/rigsignal.toml"
            ))
        );

        restore_env("XDG_CONFIG_HOME", previous_xdg);
        restore_env("HOME", previous_home);
    }

    #[cfg(not(windows))]
    #[test]
    fn user_config_path_ignores_relative_xdg_config_home() {
        let _lock = ENV_LOCK.lock().unwrap();
        let previous_xdg = std::env::var_os("XDG_CONFIG_HOME");
        let previous_home = std::env::var_os("HOME");
        std::env::set_var("XDG_CONFIG_HOME", "relative/config");
        std::env::set_var("HOME", "/tmp/rigsignal-home-relative-xdg");

        assert_eq!(
            user_config_path(),
            Some(PathBuf::from(
                "/tmp/rigsignal-home-relative-xdg/.config/rigsignal/rigsignal.toml"
            ))
        );

        restore_env("XDG_CONFIG_HOME", previous_xdg);
        restore_env("HOME", previous_home);
    }

    #[cfg(not(windows))]
    fn restore_env(name: &str, value: Option<std::ffi::OsString>) {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
}
