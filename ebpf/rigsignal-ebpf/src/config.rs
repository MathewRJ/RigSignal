/// Configuration — reads the shared rigsignal.toml file used by the Python collector.
///
/// The [ebpf] section is new; all other sections are read-only from the daemon's
/// perspective (we only need elasticsearch.* credentials and endpoint).
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub elasticsearch: ElasticsearchConfig,
    #[serde(default)]
    pub ebpf: EbpfConfig,
}

#[derive(Debug, Deserialize)]
pub struct ElasticsearchConfig {
    pub endpoint: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct EbpfConfig {
    /// Path to the compiled BPF object file (rigsignal-ebpf-probes ELF).
    /// Defaults to the workspace-relative target path after `cargo xtask build-ebpf`.
    #[serde(default = "default_probe_path")]
    pub probe_path: PathBuf,

    /// Which probes to enable. Defaults to all Sprint-1 probes.
    #[serde(default = "default_enabled_probes")]
    #[allow(dead_code)]
    pub enabled_probes: Vec<String>,

    /// Aggregate and ship once per this many seconds.
    #[serde(default = "default_interval_s")]
    pub interval_s: u64,

    /// When true, emit system-wide scheduler/IO baseline metrics even when no
    /// game session is active (at reduced rate: 1 doc per 10 × interval_s).
    #[serde(default)]
    pub background_baseline: bool,
}

fn default_probe_path() -> PathBuf {
    // Walk up from the daemon binary to find the workspace root (the directory
    // that contains rigsignal-ebpf/ as a child).
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let workspace = exe
        .ancestors()
        .find(|p| p.join("rigsignal-ebpf").exists())
        .unwrap_or_else(|| exe.parent().unwrap_or(std::path::Path::new(".")));

    // Match the BPF probe profile to the daemon profile so `cargo xtask build-ebpf`
    // (debug, default) and `cargo xtask build-ebpf --release` both work without
    // needing --probe-path.
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    workspace
        .join("target/bpfel-unknown-none")
        .join(profile)
        .join("rigsignal-ebpf-probes")
}

fn default_enabled_probes() -> Vec<String> {
    vec!["schedlatency".to_string()]
}

fn default_interval_s() -> u64 {
    1
}

impl Default for EbpfConfig {
    fn default() -> Self {
        EbpfConfig {
            probe_path: default_probe_path(),
            enabled_probes: default_enabled_probes(),
            interval_s: default_interval_s(),
            background_baseline: false,
        }
    }
}

impl Config {
    /// Load from the standard rigsignal.toml path.
    /// Search order:
    ///   1. $RIGSIGNAL_CONFIG env var
    ///   2. ~/.config/rigsignal/rigsignal.toml
    ///   3. /etc/rigsignal/rigsignal.toml
    pub fn load() -> Result<Self> {
        let path = if let Ok(env_path) = std::env::var("RIGSIGNAL_CONFIG") {
            PathBuf::from(env_path)
        } else if let Some(home) = dirs_or_home() {
            home.join(".config/rigsignal/rigsignal.toml")
        } else {
            PathBuf::from("/etc/rigsignal/rigsignal.toml")
        };

        Self::load_from(&path)
    }

    /// Apply ES_API_KEY and ES_URL env vars on top of whatever was in the TOML file.
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

    pub fn load_from(path: &PathBuf) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file: {}", path.display()))?;
        let mut config: Self = toml::from_str(&text)
            .with_context(|| format!("parsing config file: {}", path.display()))?;
        config.apply_env_overrides();
        Ok(config)
    }
}

fn dirs_or_home() -> Option<PathBuf> {
    // When running via sudo, HOME is /root but the config lives in the
    // invoking user's home. Prefer SUDO_USER → /home/<user> over HOME.
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() {
            let path = PathBuf::from("/home").join(&sudo_user);
            if path.exists() {
                return Some(path);
            }
        }
    }
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Reduce an endpoint to a bare `scheme://host[:port]` origin, or `None`.
///
/// DELIBERATELY SEPARATE FROM THE AGENT'S `handshake::endpoint_origin`, which is
/// its sibling and does the same job. They are not shared, and the reason is not
/// that sharing was hard -- the daemon already has `reqwest::Url` in reach, so a
/// shared crate would have cost no new dependency.
///
/// The agent's copy serves TWO consumers with OPPOSITE failure preferences: in
/// its startup preflight a `None` is FATAL, so the function is a VALIDATOR there,
/// while in its shipper a `None` merely costs a word in a log line. Its own doc
/// says a change that improves one regresses the other. This crate needs only the
/// REDACTOR half and is never fatal, so binding the daemon's logging to the
/// agent's validator across a workspace boundary would let a future relaxation
/// made for a log line silently widen what the agent's handshake ACCEPTS.
///
/// The cost of that choice is drift, and it is real: the agent's copy shipped an
/// IPv6 double-bracketing bug. The mitigation is that the tests below pin the SAME
/// rejection vectors as the agent's, so the two can be diffed by eye.
///
/// REJECTS rather than sanitises: userinfo, a username, a password, a query, a
/// fragment, a non-`http(s)` scheme, or a path that does not NORMALISE to empty or
/// `/` all yield `None`. Note *normalise*: `http://host/a/..` collapses to `/` and
/// is accepted, returning `http://host` -- the segment is dropped, not echoed. The
/// guarantee is "the output is assembled only from scheme, host and port", NOT
/// "any input with a path is refused".
pub fn endpoint_origin_for_log(value: &str) -> Option<String> {
    let url = reqwest::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || has_userinfo(value, &url)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return None;
    }
    // `Url::host_str` already returns an IPv6 authority bracketed (`[::1]`), so it
    // is used as-is. Bracketing it again is the bug the agent's copy shipped.
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    })
}

/// `Url` normalises an empty username away when serialised, so inspect the parsed
/// input's authority rather than `Url::username()` alone. Fails CLOSED: anything it
/// cannot slice is treated as carrying userinfo.
fn has_userinfo(input: &str, url: &reqwest::Url) -> bool {
    let Some(authority) = input
        .get(url.scheme().len() + 1..)
        .and_then(|rest| rest.strip_prefix("//"))
    else {
        return true;
    };
    // SURPLUS AUTHORITY SLASHES. For a special scheme the WHATWG parser consumes
    // `//` and then IGNORES any further `/` or `\` before the authority, so in
    // `http:///@host` the parser's authority is `@host` while this scan, having
    // removed exactly two slashes, sees a delimiter at index 0, reads an EMPTY
    // authority and reports no `@`. The parsed username/password checks then pass
    // too, because the userinfo is empty. Measured: `http:///@host`,
    // `http:////@host` and `http:///:@host` all reached the log as `http://host`,
    // defeating the deliberate rejection of even empty userinfo that the
    // `http://@host` case exists to pin.
    //
    // Refuse the ambiguous shape outright rather than re-implementing the
    // parser's slash skipping here. A scan written to mirror a parser is a second
    // implementation of it, and the two drift -- which is the whole defect above,
    // in miniature. Refusing strictly WIDENS rejection, so it stays on the
    // fail-closed side of this function's contract.
    if authority.starts_with('/') || authority.starts_with('\\') {
        return true;
    }
    let authority_end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    authority[..authority_end].contains('@')
}

/// The endpoint as it may appear in a log line: a bare origin, or `<redacted>`.
///
/// Never fatal and never partial -- an endpoint that cannot be shown to be
/// credential-free is withheld entirely rather than scrubbed.
pub fn endpoint_for_log(value: &str) -> String {
    endpoint_origin_for_log(value).unwrap_or_else(|| "<redacted>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These vectors are kept IDENTICAL to the agent's `endpoint_origin` tests on
    /// purpose. The two functions are deliberate duplicates, so the defence against
    /// them drifting apart is that their test tables can be compared line by line.
    /// If you change one, change the other or record why they now differ.
    #[test]
    fn rejects_every_endpoint_it_cannot_prove_credential_free() {
        for bad in [
            "ftp://host",
            "http://",
            "http://@host",
            "http://u:p@host",
            "http://host/x",
            "http://host/?x",
            "http://host/#x",
            // Surplus authority slashes. The parser ignores them and reads the
            // userinfo the raw scan could not see, so all three of these reached
            // the log as `http://host` before the scan refused the shape. They
            // are the regression for that, and they carry no credential on
            // purpose: the contract rejects EVEN EMPTY userinfo, so a vector
            // that leaks nothing is exactly the one that pins the contract
            // rather than the consequence.
            "http:///@host",
            "http:////@host",
            "http:///:@host",
        ] {
            assert!(endpoint_origin_for_log(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn keeps_an_endpoint_that_is_provably_clean() {
        assert_eq!(
            endpoint_origin_for_log("https://host:9200/").as_deref(),
            Some("https://host:9200")
        );
        assert_eq!(
            endpoint_origin_for_log("http://127.0.0.1:9200").as_deref(),
            Some("http://127.0.0.1:9200")
        );
    }

    #[test]
    fn the_output_is_ASSEMBLED_from_scheme_host_port_and_is_never_the_INPUT() {
        // The doc promises "the output is assembled only from scheme, host and
        // port". Nothing tested that. An implementation that returns the INPUT
        // once the checks pass satisfies every other test in this module, and a
        // non-author review demonstrated exactly that mutant passing the whole
        // 30-test workspace while the real daemon printed the secret.
        //
        // `Url` NORMALISES `/secretcanary/..` away to `/`, so the path check sees
        // a clean root and accepts. That is the point: acceptance is correct here
        // and returning the raw input is still a disclosure. Only an equality
        // assertion against the ASSEMBLED origin can tell the two apart --
        // asserting `is_some()` cannot.
        assert_eq!(
            endpoint_origin_for_log("http://host/secretcanary/..").as_deref(),
            Some("http://host")
        );
        assert_eq!(
            endpoint_origin_for_log("http://host/%2e%2e/secretcanary/..").as_deref(),
            Some("http://host")
        );
        // The wrapper carries the same guarantee, so pin it at that level too.
        assert_eq!(endpoint_for_log("http://host/secretcanary/.."), "http://host");
    }

    #[test]
    fn the_wrapper_SHOWS_a_clean_endpoint_rather_than_redacting_everything() {
        // A positive control. Every other wrapper assertion in this module checks
        // that something is WITHHELD, so a wrapper that returned "<redacted>"
        // unconditionally would satisfy all of them -- it would be maximally
        // "safe" and completely useless, and no test would notice. Measured by a
        // non-author review as mutant M11.
        for clean in [
            "http://127.0.0.1:9200",
            "https://host:9200/",
            "https://[::1]:9200/",
        ] {
            let shown = endpoint_for_log(clean);
            assert_ne!(
                shown, "<redacted>",
                "a provably clean endpoint must be shown, not withheld: {clean}"
            );
            assert_eq!(
                Some(shown.as_str()),
                endpoint_origin_for_log(clean).as_deref(),
                "the wrapper must return the origin verbatim for {clean}"
            );
        }
    }

    #[test]
    fn brackets_ipv6_exactly_once() {
        // Written correctly here from the start. The agent's sibling shipped
        // `[[::1]]`, which is not a parseable URL once a path is appended.
        assert_eq!(
            endpoint_origin_for_log("https://[::1]:9200/").as_deref(),
            Some("https://[::1]:9200")
        );
        let origin = endpoint_origin_for_log("https://[2001:db8::1]/").expect("origin");
        assert_eq!(origin, "https://[2001:db8::1]");
        assert!(reqwest::Url::parse(&format!("{origin}/_bulk")).is_ok());
    }

    #[test]
    fn a_credential_bearing_endpoint_is_withheld_whole() {
        let cfg_endpoint = "https://u:hunter2@es.example:9200/?api_key=CANARY";
        assert!(endpoint_origin_for_log(cfg_endpoint).is_none());
        let shown = endpoint_for_log(cfg_endpoint);
        for leak in ["hunter2", "CANARY"] {
            assert!(!shown.contains(leak), "{leak} survived into {shown}");
        }
        assert_eq!(shown, "<redacted>");
    }

    #[test]
    fn a_non_url_endpoint_is_withheld_rather_than_echoed() {
        // `endpoint` is an unvalidated bare String and need not be a URL at all.
        for junk in ["", "not a url", "es.example:9200", "file:///etc/passwd"] {
            assert_eq!(endpoint_for_log(junk), "<redacted>", "{junk}");
        }
    }
}
