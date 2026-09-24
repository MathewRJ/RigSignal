// RigSignal production agent — Phase 6 main loop.
//
// Wires all 8 collectors into a 1-second tick loop, handles game detection,
// writes session.json for the eBPF daemon, ships docs to Elasticsearch, and
// builds a session summary document on shutdown.
//
// Mirrors the structure of collector/rigsignal/cli.py exactly.

#[cfg(all(feature = "ebpf", not(target_os = "linux")))]
compile_error!(
    "the 'ebpf' feature is only supported on Linux (aya/BPF syscalls have no Windows equivalent)"
);

mod collectors;
mod config;
mod detectors;
mod diagnose;
mod dllscan;
mod handshake;
mod host;
mod launchers_windows;
mod log_safe;
mod profiles;
#[cfg(target_os = "linux")]
mod remote_connections;
mod session;
mod shipper;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use collectors::Collector;
use config::OutputMode;
use detectors::contract::diagnosis_event::{
    DiagnosisEvent, EventContext, InputMode, ValidationError,
};
use detectors::contract::{DetectorContract, Disposition, Outcome};
use serde::Deserialize;
use serde_json::{json, Value};
use session::SessionEvent;
use shipper::SpoolWriter;
use std::path::PathBuf;
use std::process::ExitCode;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const BUILD_COMMIT: &str = env!("RIGSIGNAL_BUILD_COMMIT");

/// Marker on the lines about Elasticsearch delivery health that are SAFE to
/// surface outside the journal, so one grep finds the outage story: each repeat
/// while the endpoint stays unreachable, and the recovery.
///
/// A failed startup preflight no longer aborts the process. That removed the
/// crash loop an operator could see in `systemctl status`, so these lines are
/// what replaces it -- without them a permanently misconfigured endpoint would
/// simply be quiet.
///
/// Lines carrying this marker are built only from a timestamp and a count. They
/// deliberately carry NO error text, and the reason is no longer the one this
/// comment used to give. The preflight context no longer interpolates the
/// configured endpoint (see `shipper::ping`), so the outermost layer is now
/// credential-free on its own.
///
/// The split still earns its place for two reasons that outlive that fix:
/// `rigsignal status` echoes the most recent marked line to stdout, so keeping
/// it free of variable error text keeps a machine-read line stable; and the
/// DEEPER layers of the error chain still carry the full request URL, so any
/// future change from `{}` to `{:#}` or `{:?}` at the unmarked site would put a
/// query-borne credential back in the journal. Error detail stays on unmarked
/// lines precisely so that blast radius stays off the stdout-echoed one.
const ES_DELIVERY_MARKER: &str = "ES_DELIVERY";

/// Minimum gap between repeats of the unreachable warning. The warning is
/// rate-limited but never suppressed: it keeps repeating for as long as the
/// condition holds, because an operator may attach to the log at any time.
const ES_UNREACHABLE_REPEAT_SECS: u64 = 60;

// Bounds on the window, enforced at COMPILE time because they are properties of
// the constant rather than of any run. Too long and an operator attaching to the
// log waits out an outage in silence; too short and the warning is a flood. An
// earlier revision asserted these in a test that divided 3600 by the same
// constant, so widening the window to a day made the test assert 0 == 0 and pass.
const _: () = assert!(
    ES_UNREACHABLE_REPEAT_SECS >= 5 && ES_UNREACHABLE_REPEAT_SECS <= 300,
    "the unreachable warning must repeat between every 5s and every 5min"
);

/// One emission of the persistent unreachable warning.
struct EsUnreachable {
    since_unix: u64,
    attempts: u64,
}

impl EsUnreachable {
    fn since_rfc3339(&self) -> String {
        chrono::DateTime::from_timestamp(self.since_unix as i64, 0)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_else(|| format!("unix:{}", self.since_unix))
    }
}

/// The outage currently in progress.
struct Outage {
    since_unix: u64,
    attempts: u64,
    /// Whether the operator has been told about THIS outage. Recovery is only
    /// announced for an outage that was announced: without that, an endpoint
    /// that fails and succeeds alternately emits a failure and a recovery line
    /// every tick forever, and a sustained 50% loss reads as healthy.
    announced: bool,
}

#[derive(Default)]
struct EsDeliveryState {
    outage: Option<Outage>,
    /// When a failure line was last emitted, kept ACROSS outage boundaries so
    /// the rate limit cannot be defeated by alternation rather than volume.
    last_spoke_unix: Option<u64>,
}

/// Consecutive-failure tracker for Elasticsearch delivery.
///
/// Tick shipping runs in detached tasks, so this is shared across tasks. It is
/// ONE mutex rather than several atomics, and that is a correctness choice. With
/// separate atomics, a `record_success` landing between a `record_failure`'s
/// claim of the outage start and its re-read of that field made the warning print
/// the epoch; another interleaving left a stale last-warned stamp behind a
/// cleared outage and silenced the first 59 s of the NEXT outage; a third let
/// "recovered" print after "failing", which is the line `rigsignal status` then
/// shows. All three were reachable, and all three are gone once the fields move
/// under one lock. It is taken once per delivery against a 1 Hz tick.
#[derive(Default)]
struct EsDeliveryHealth {
    state: std::sync::Mutex<EsDeliveryState>,
}

impl EsDeliveryHealth {
    /// Record one failed delivery.
    ///
    /// Returns `Some` when the caller should emit the persistent warning: at most
    /// once per `ES_UNREACHABLE_REPEAT_SECS`, counted across outages.
    fn record_failure(&self, now_unix: u64) -> Option<EsUnreachable> {
        // A panicking ship task must not wedge the tracker: recovering the guard
        // is strictly better than never warning again.
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let due = match g.last_spoke_unix {
            None => true,
            // `now_unix < last` is the backward-clock guard and is load-bearing.
            // An earlier revision used `saturating_sub`, so a clock STEP backwards
            // saturated the difference to zero and nothing was due until real time
            // caught up: measured at 7259 consecutive failed ticks silent after a
            // two-hour step. The clock is CLOCK_REALTIME and the units are ordered
            // `After=network.target`, not `After=time-sync.target`, so a step
            // correction shortly after boot is the ordinary path.
            Some(last) => now_unix < last || now_unix - last >= ES_UNREACHABLE_REPEAT_SECS,
        };
        let outage = g.outage.get_or_insert(Outage {
            since_unix: now_unix,
            attempts: 0,
            announced: false,
        });
        outage.attempts += 1;
        if !due {
            return None;
        }
        outage.announced = true;
        let emission = EsUnreachable {
            since_unix: outage.since_unix,
            attempts: outage.attempts,
        };
        g.last_spoke_unix = Some(now_unix);
        Some(emission)
    }

    /// Record one successful delivery. Returns the number of failures it ended,
    /// or `None` if nothing was wrong or the outage was never announced.
    fn record_success(&self) -> Option<u64> {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match g.outage.take() {
            Some(o) if o.announced => Some(o.attempts),
            _ => None,
        }
    }

    /// Attempts recorded against the outage in progress, or `None` if there is
    /// none. Test-only: emission is rate-limited across outages, so "did this
    /// count?" and "did this print?" are different questions and a test that can
    /// only see the second cannot check the first.
    #[cfg(test)]
    fn outage_attempts(&self) -> Option<u64> {
        let g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        g.outage.as_ref().map(|o| o.attempts)
    }

    /// Account for a failed delivery and say so if a line is due.
    fn note_failure(&self) {
        if let Some(state) = self.record_failure(now_unix_secs()) {
            tracing::warn!(
                "{} Elasticsearch delivery failing since {}, {} consecutive failed \
                 deliveries — documents are being dropped",
                ES_DELIVERY_MARKER,
                state.since_rfc3339(),
                state.attempts
            );
        }
    }

    /// Account for a delivery in which every document landed.
    ///
    /// Recovery is `warn!` rather than `info!` on purpose: the units ship
    /// `Environment=RIGSIGNAL_LOG=info`, and at any level where the failures are
    /// visible the line saying they stopped must be visible too.
    fn note_success(&self) {
        if let Some(after) = self.record_success() {
            tracing::warn!(
                "{} Elasticsearch delivery recovered after {} consecutive failed deliveries",
                ES_DELIVERY_MARKER,
                after
            );
        }
    }

    /// Account for one bulk outcome.
    ///
    /// A partial or total REJECTION is a delivery failure even though the
    /// request itself succeeded. `ship_documents` returns `Err` only for
    /// transport errors and a non-2xx status; when Elasticsearch crosses its
    /// flood-stage watermark and sets `index.blocks.read_only_allow_delete`, or
    /// when a field mapping conflicts, the bulk returns HTTP 200 with every item
    /// rejected. An earlier revision called this SUCCESS before looking at
    /// `failed`, so total document loss was reported to the operator as
    /// "recovered" — surviving loudly and wrongly, which is worse than the quiet
    /// failure this instrumentation exists to prevent.
    fn observe(&self, outcome: &Result<shipper::ShipResult>) {
        match outcome {
            Ok(r) if r.failed == 0 => self.note_success(),
            _ => self.note_failure(),
        }
    }
}

/// Seconds since the Unix epoch.
fn now_unix_secs() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

fn build_info_json(name: &str) -> String {
    json!({
        "name": name,
        "version": env!("CARGO_PKG_VERSION"),
        "commit": BUILD_COMMIT,
    })
    .to_string()
}

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // Diagnose owns its Clap action payload.
enum Commands {
    /// Construct frozen fixture event bytes through the production validator.
    #[command(hide = true)]
    FixtureEventBytes {
        #[arg(long, value_name = "PATH")]
        input: PathBuf,
        #[arg(long, value_name = "PATH")]
        context: PathBuf,
    },
    /// Verify the configured Elasticsearch destination and diagnosis schema.
    Handshake {
        #[command(subcommand)]
        action: handshake::HandshakeAction,
    },
    /// Collect a bug-report snapshot: kernel, GPU driver, ES reachability, and
    /// a log of every probe step. Prints to stdout; use --output for a file.
    Diagnose {
        /// Write the report to a file instead of stdout.
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        #[command(subcommand)]
        action: Option<DiagnoseAction>,
    },

    /// Dump the loaded-module list and Tier 2 detection result for a target
    /// process. Reads loaded module paths using the platform-specific scanner.
    /// Useful for debugging upscaler / frame-gen / graphics-API
    /// auto-detection without launching a full session.
    Dllscan {
        /// Process ID to inspect.
        #[arg(value_name = "PID")]
        pid: u32,
    },
}

#[derive(Subcommand)]
enum DiagnoseAction {
    /// Validate gamescope modes.cfg overrides against DRM display state.
    Display {
        #[arg(long, value_name = "PATH")]
        modes_cfg: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        drm_state: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "NAME")]
        host: Option<String>,
    },
    /// Diagnose GPU enumeration across boots using PCI sysfs and journald.
    GpuBoot {
        #[arg(long)]
        offline: bool,
        #[arg(long, value_name = "PATH")]
        journal_current: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        journal_prior_kernel: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        journal_prior_tail: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        pci_snapshot: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        boot_list: Option<PathBuf>,
        #[arg(long, value_name = "ID")]
        current_boot_id: Option<String>,
        #[arg(long, value_name = "PATH")]
        state_file: Option<PathBuf>,
        #[arg(long, value_name = "BDF")]
        slot: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "NAME")]
        host: Option<String>,
        #[arg(long)]
        learn_baseline: bool,
        #[arg(long)]
        reset_baseline: bool,
    },
}

#[derive(Parser)]
#[command(
    name = "rigsignal-agent",
    version,
    about = "RigSignal cross-platform gaming telemetry agent"
)]
struct Cli {
    /// Path to config file. If unset, searches platform defaults:
    /// Linux: ${XDG_CONFIG_HOME:-~/.config}/rigsignal/rigsignal.toml then /etc/rigsignal/rigsignal.toml.
    /// Windows: %APPDATA%\RigSignal\rigsignal.toml then %PROGRAMDATA%\RigSignal\rigsignal.toml.
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Run one collection cycle, print output, exit without shipping to ES
    #[arg(long)]
    dry_run: bool,

    /// Enable debug-level logging. Equivalent to --log-level debug.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Log verbosity level: error | warn | info | debug | trace
    /// Overrides --verbose and RIGSIGNAL_LOG when set.
    #[arg(long, value_name = "LEVEL", value_parser = ["error", "warn", "info", "debug", "trace"])]
    log_level: Option<String>,

    /// Print the resolved configuration (credentials redacted) to stdout and exit.
    #[arg(long)]
    print_config: bool,

    /// Print machine-readable build provenance and exit.
    #[arg(long)]
    build_info_json: bool,

    /// Short annotation for this session (e.g. "after-driver-update").
    /// Overrides [session].label in the config file.
    #[arg(long, value_name = "TEXT")]
    label: Option<String>,

    // ── Tier 1 settings flags (B.7) ───────────────────────────────────────────
    /// Graphics preset: low | medium | high | ultra | custom | unknown
    #[arg(long, value_name = "VALUE")]
    preset: Option<String>,

    /// Upscaler technology and optional quality preset: tech[:preset]
    /// e.g. dlss:quality  fsr:balanced  xess
    #[arg(long, value_name = "TECH[:PRESET]")]
    upscaler: Option<String>,

    /// Frame generation technology: dlss3 | fsr3 | afmf | lossless-scaling | none
    #[arg(long, value_name = "TECH")]
    frame_gen: Option<String>,

    /// Comma-separated list of active features
    /// e.g. ray_tracing,path_tracing,direct_storage
    #[arg(long, value_name = "FEATURE,...")]
    features: Option<String>,

    /// Output render resolution, e.g. 3440x1440
    #[arg(long, value_name = "WxH")]
    resolution: Option<String>,

    /// VSync mode: off | on | adaptive | fast
    #[arg(long, value_name = "off|on|adaptive|fast")]
    vsync: Option<String>,

    /// Free-text notes for this session, e.g. "engineering sample GPU"
    #[arg(long, value_name = "TEXT")]
    notes: Option<String>,

    // ── Target override (B2.7) ────────────────────────────────────────────────
    /// Skip auto-detection and monitor a specific process ID.
    /// The process must be running when the agent starts.
    #[arg(long, value_name = "PID")]
    target_pid: Option<u32>,

    /// Skip auto-detection; find a process by name (matched against process name
    /// and executable basename, case-insensitive). First match wins.
    #[arg(long, value_name = "NAME")]
    target_name: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

// ── Utilities ──────────────────────────────────────────────────────────────────

/// RFC3339 UTC timestamp matching Python's datetime.datetime.now(utc).isoformat()
fn utc_now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Recursively deep-merge `overlay` into `base`. Later values win on scalar
/// conflicts; nested objects are merged rather than replaced.
/// Matches Python _merge_docs() in cli.py exactly.
fn deep_merge(mut base: Value, overlay: Value) -> Value {
    match (&mut base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            for (k, v) in overlay_map {
                match base_map.get_mut(&k) {
                    Some(existing) if existing.is_object() && v.is_object() => {
                        let owned = existing.take();
                        *existing = deep_merge(owned, v);
                    }
                    _ => {
                        base_map.insert(k, v);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
    base
}

/// Check liveness of a user-pinned target and synthesise the appropriate SessionEvent.
fn poll_pinned_target(
    pinned: &session::Target,
    current: &mut Option<session::Target>,
) -> session::SessionEvent {
    let mut system = System::new();
    let pid = Pid::from_u32(pinned.pid);
    let alive = system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    ) > 0;
    match (current.is_some(), alive) {
        (false, true) => {
            *current = Some(pinned.clone());
            session::SessionEvent::GameStarted(pinned.clone())
        }
        (true, false) => {
            let old = current.take().unwrap();
            session::SessionEvent::GameEnded(old)
        }
        _ => session::SessionEvent::NoChange,
    }
}

/// Add data_stream routing fields to a doc so the shipper can derive the index.
fn add_data_stream(doc: &mut Value, dataset: &str) {
    if let Some(obj) = doc.as_object_mut() {
        obj.insert(
            "data_stream".to_string(),
            json!({
                "type": "metrics",
                "dataset": dataset,
                "namespace": "default",
            }),
        );
    }
}

// ── Tier 1 settings overlay builder (B.7) ────────────────────────────────────

/// Build the `{ "rigsignal": { "settings": { … } } }` overlay from merged
/// CLI and config values. Returns `None` if no settings were provided at all
/// (so the key is simply absent from session docs).
#[allow(clippy::too_many_arguments)]
fn build_settings_overlay(
    preset: Option<&str>,
    upscaler_tech: Option<&str>,
    upscaler_preset: Option<&str>,
    frame_gen_tech: Option<&str>,
    features_active: Option<&[String]>,
    resolution: Option<&str>,
    vsync: Option<&str>,
    notes: Option<&str>,
) -> Option<Value> {
    if preset.is_none()
        && upscaler_tech.is_none()
        && frame_gen_tech.is_none()
        && features_active.is_none()
        && resolution.is_none()
        && vsync.is_none()
        && notes.is_none()
    {
        return None;
    }

    let mut s = serde_json::Map::new();

    if let Some(p) = preset {
        s.insert("preset".into(), Value::String(p.to_string()));
    }

    if upscaler_tech.is_some() || upscaler_preset.is_some() {
        let mut u = serde_json::Map::new();
        if let Some(t) = upscaler_tech {
            u.insert("tech".into(), Value::String(t.to_string()));
        }
        if let Some(p) = upscaler_preset {
            u.insert("preset".into(), Value::String(p.to_string()));
        }
        s.insert("upscaler".into(), Value::Object(u));
    }

    if let Some(ft) = frame_gen_tech {
        let mut fg = serde_json::Map::new();
        fg.insert("tech".into(), Value::String(ft.to_string()));
        s.insert("frame_gen".into(), Value::Object(fg));
    }

    if let Some(feats) = features_active {
        let arr: Vec<Value> = feats.iter().map(|f| Value::String(f.clone())).collect();
        s.insert("features_active".into(), Value::Array(arr));
    }

    if resolution.is_some() || vsync.is_some() {
        let mut r = serde_json::Map::new();
        if let Some(res) = resolution {
            r.insert("resolution_output".into(), Value::String(res.to_string()));
        }
        if let Some(vs) = vsync {
            r.insert("vsync".into(), Value::String(vs.to_string()));
        }
        s.insert("render".into(), Value::Object(r));
    }

    if let Some(n) = notes {
        s.insert("notes".into(), Value::String(n.to_string()));
    }

    s.insert("source".into(), Value::String("manual".to_string()));
    s.insert("confidence".into(), Value::String("high".to_string()));

    Some(json!({ "rigsignal": { "settings": Value::Object(s) } }))
}

/// Parse "--upscaler dlss:quality" into (tech, Option<preset>).
fn parse_upscaler(s: &str) -> (String, Option<String>) {
    match s.find(':') {
        Some(pos) => {
            let tech = s[..pos].to_string();
            let preset = s[pos + 1..].to_string();
            (
                tech,
                if preset.is_empty() {
                    None
                } else {
                    Some(preset)
                },
            )
        }
        None => (s.to_string(), None),
    }
}

// ── Session document builders ─────────────────────────────────────────────────

/// Ship a session-start document when the agent comes online.
fn build_session_start_doc(
    session: &session::SessionManager,
    host_snapshot: &Value,
    hostname: &str,
) -> Value {
    let base = session.base_doc(hostname);
    let ts = json!({ "@timestamp": utc_now() });
    let mut doc = deep_merge(deep_merge(ts, base), host_snapshot.clone());
    if let Some(settings) = &session.settings_overlay {
        doc = deep_merge(doc, settings.clone());
    }
    add_data_stream(&mut doc, "rigsignal.session");
    doc
}

/// Ship an updated session document when a target is first detected.
fn build_game_detected_doc(
    session: &session::SessionManager,
    host_snapshot: &Value,
    hostname: &str,
    target: &session::Target,
) -> Value {
    let base = session.base_doc(hostname);
    let ts = json!({ "@timestamp": utc_now() });
    let mut compat = serde_json::Map::new();
    if let Some(v) = &target.proton_version {
        compat.insert("proton_version".to_string(), Value::String(v.clone()));
    }
    if let Some(v) = &target.dxvk_version {
        compat.insert("dxvk_version".to_string(), Value::String(v.clone()));
    }
    let compat_overlay = if compat.is_empty() {
        json!({})
    } else {
        json!({ "rigsignal": { "compatibility": compat } })
    };
    let mut doc = deep_merge(
        deep_merge(deep_merge(ts, base), host_snapshot.clone()),
        compat_overlay,
    );
    if let Some(settings) = &session.settings_overlay {
        doc = deep_merge(doc, settings.clone());
    }
    add_data_stream(&mut doc, "rigsignal.session");
    doc
}

// ── Accumulator helpers ───────────────────────────────────────────────────────

struct SessionAccumulators {
    fps_samples: Vec<f64>,
    frametime_samples: Vec<f64>,
    stutter_total: i64,
    peak_gpu_temp: Option<f64>,
    peak_cpu_temp: Option<f64>,
    peak_gpu_power: Option<f64>,
    gpu_bottleneck_ticks: i64,
    cpu_bottleneck_ticks: i64,
    balanced_ticks: i64,
}

impl SessionAccumulators {
    fn new() -> Self {
        SessionAccumulators {
            fps_samples: Vec::new(),
            frametime_samples: Vec::new(),
            stutter_total: 0,
            peak_gpu_temp: None,
            peak_cpu_temp: None,
            peak_gpu_power: None,
            gpu_bottleneck_ticks: 0,
            cpu_bottleneck_ticks: 0,
            balanced_ticks: 0,
        }
    }

    /// Update accumulators from the tick's doc list.
    fn update(&mut self, docs: &[Value]) {
        let mut tick_gpu_util: Option<f64> = None;
        let mut tick_cpu_util: Option<f64> = None;

        for doc in docs {
            let gp = match doc.get("rigsignal").and_then(|g| g.as_object()) {
                Some(g) => g,
                None => continue,
            };

            if let Some(gpu) = gp.get("gpu").and_then(|g| g.as_object()) {
                tick_gpu_util = gpu.get("utilisation_pct").and_then(|v| v.as_f64());
                if let Some(t) = gpu.get("temperature_c").and_then(|v| v.as_f64()) {
                    self.peak_gpu_temp = Some(self.peak_gpu_temp.map_or(t, |p: f64| p.max(t)));
                }
                if let Some(p) = gpu.get("power_w").and_then(|v| v.as_f64()) {
                    self.peak_gpu_power =
                        Some(self.peak_gpu_power.map_or(p, |prev: f64| prev.max(p)));
                }
            }

            if let Some(cpu) = gp.get("cpu").and_then(|g| g.as_object()) {
                tick_cpu_util = cpu.get("total_utilisation_pct").and_then(|v| v.as_f64());
                if let Some(t) = cpu.get("temperature_c").and_then(|v| v.as_f64()) {
                    self.peak_cpu_temp = Some(self.peak_cpu_temp.map_or(t, |p: f64| p.max(t)));
                }
            }

            if let Some(fps) = gp.get("fps").and_then(|g| g.as_object()) {
                if let Some(avg) = fps.get("avg_1s").and_then(|v| v.as_f64()) {
                    self.fps_samples.push(avg);
                }
                if let Some(sc) = fps.get("stutter_count").and_then(|v| v.as_i64()) {
                    self.stutter_total += sc;
                }
                if let Some(ft) = fps.get("frametime_ms").and_then(|v| v.as_f64()) {
                    self.frametime_samples.push(ft);
                }
            }
        }

        if let (Some(gpu_util), Some(cpu_util)) = (tick_gpu_util, tick_cpu_util) {
            if gpu_util > 90.0 {
                self.gpu_bottleneck_ticks += 1;
            } else if cpu_util > 90.0 {
                self.cpu_bottleneck_ticks += 1;
            } else {
                self.balanced_ticks += 1;
            }
        }
    }

    fn bottleneck_dominant(&self) -> Option<&'static str> {
        let total = self.gpu_bottleneck_ticks + self.cpu_bottleneck_ticks + self.balanced_ticks;
        if total == 0 {
            return None;
        }
        if self.gpu_bottleneck_ticks >= self.cpu_bottleneck_ticks
            && self.gpu_bottleneck_ticks >= self.balanced_ticks
        {
            Some("gpu")
        } else if self.cpu_bottleneck_ticks >= self.balanced_ticks {
            Some("cpu")
        } else {
            Some("balanced")
        }
    }
}

/// Build the session-end summary document. Matches Python cli.py finally block.
fn build_summary_doc(
    session: &session::SessionManager,
    host_snapshot: &Value,
    hostname: &str,
    duration_s: u64,
    acc: &SessionAccumulators,
    last_game: Option<&session::Target>,
) -> Value {
    let interval = 1.0_f64; // 1-second collection interval

    let mut summary = serde_json::Map::new();
    summary.insert("ended".to_string(), Value::Bool(true));
    summary.insert("duration_s".to_string(), Value::from(duration_s));
    summary.insert(
        "fps_coverage_s".to_string(),
        Value::from(acc.fps_samples.len() as i64),
    );
    summary.insert("stutter_count".to_string(), Value::from(acc.stutter_total));

    if !acc.fps_samples.is_empty() {
        let mut sorted = acc.fps_samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let avg_fps = (acc.fps_samples.iter().sum::<f64>() / acc.fps_samples.len() as f64 * 10.0)
            .round()
            / 10.0;
        summary.insert("avg_fps".to_string(), Value::from(avg_fps));
        let n = sorted.len();
        let low_idx = (n as f64 * 0.01) as usize;
        let low_idx = low_idx.saturating_sub(1).min(n - 1);
        summary.insert(
            "low_1pct_fps".to_string(),
            Value::from(sorted[low_idx] as i64),
        );
        let total_frames = (acc.fps_samples.iter().sum::<f64>() * interval).round() as i64;
        summary.insert("total_frames".to_string(), Value::from(total_frames));
    }

    if !acc.frametime_samples.is_empty() {
        let mut ft_sorted = acc.frametime_samples.clone();
        ft_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = ft_sorted.len();
        let p99_idx = (n as f64 * 0.99) as usize;
        let p99_idx = p99_idx.saturating_sub(1).min(n - 1);
        let p99 = (ft_sorted[p99_idx] * 100.0).round() / 100.0;
        summary.insert("p99_frametime_ms".to_string(), Value::from(p99));
    }

    if let Some(t) = acc.peak_gpu_temp {
        summary.insert("peak_gpu_temp_c".to_string(), Value::from(t));
    }
    if let Some(t) = acc.peak_cpu_temp {
        summary.insert("peak_cpu_temp_c".to_string(), Value::from(t));
    }
    if let Some(p) = acc.peak_gpu_power {
        summary.insert("peak_gpu_power_w".to_string(), Value::from(p));
    }
    if let Some(bn) = acc.bottleneck_dominant() {
        summary.insert(
            "bottleneck_dominant".to_string(),
            Value::String(bn.to_string()),
        );
    }

    let mut base = session.base_doc(hostname);

    // If the target exited before the summary is built, session.current_game is None.
    // Inject the last known target fields so rigsignal.game.* appear in the summary.
    if let (Some(target), None) = (last_game, session.current_game.as_ref()) {
        let overlay = json!({ "rigsignal": { "game": session::target_to_game_doc(target) } });
        base = deep_merge(base, overlay);
    }

    let ts = json!({ "@timestamp": utc_now() });
    let summary_overlay = json!({ "rigsignal": { "summary": summary } });
    let mut doc = deep_merge(
        deep_merge(deep_merge(ts, base), host_snapshot.clone()),
        summary_overlay,
    );
    if let Some(settings) = &session.settings_overlay {
        doc = deep_merge(doc, settings.clone());
    }
    add_data_stream(&mut doc, "rigsignal.session");
    doc
}

// ── Collector assembly ────────────────────────────────────────────────────────

/// Build the platform-appropriate set of collectors. Types resolve via the
/// cfg-gated `pub use` in collectors/mod.rs — Linux pulls from `linux::*`,
/// Windows from `windows::*` (PDH/DXGI/WMI/PresentMon collectors).
fn build_collectors(game_pid: Option<u32>) -> Vec<Box<dyn Collector>> {
    // On Linux the dynamic collector re-evaluates Gamescope FIFOs as they
    // appear and otherwise delegates to MangoHud CSV collection.
    #[cfg(target_os = "linux")]
    let frame_collector: Box<dyn Collector> = Box::new(collectors::FrameCollector::new(game_pid));
    #[cfg(not(target_os = "linux"))]
    let frame_collector: Box<dyn Collector> =
        Box::new(collectors::MangoHudCollector::new(game_pid));

    vec![
        Box::new(collectors::CpuCollector::new(game_pid)),
        Box::new(collectors::MemoryCollector::new(game_pid)),
        Box::new(collectors::StorageCollector::new(game_pid)),
        Box::new(collectors::NetworkCollector::new(game_pid)),
        Box::new(collectors::PowerCollector::new(game_pid)),
        Box::new(collectors::AudioCollector::new(game_pid)),
        frame_collector,
        Box::new(collectors::GpuCollector::new(game_pid)),
        #[cfg(target_os = "linux")]
        Box::new(collectors::StreamClientCollector::new()),
    ]
}

// ── Dry-run ───────────────────────────────────────────────────────────────────

async fn dry_run() -> Result<()> {
    tracing::info!("dry-run mode — validating collectors");

    let snapshot = host::collect_snapshot();
    tracing::info!(
        "Host snapshot:\n{}",
        serde_json::to_string_pretty(&snapshot)?
    );

    let mut collectors = build_collectors(None);
    tracing::info!("Loaded {} collectors", collectors.len());

    // Two-tick warmup for delta-based collectors.
    for c in &mut collectors {
        let _ = c.collect();
    }
    std::thread::sleep(std::time::Duration::from_secs(1));

    for c in &mut collectors {
        let dataset = c.dataset();
        match c.collect()? {
            Some(doc) => tracing::info!(
                "{} sample:\n{}",
                dataset,
                serde_json::to_string_pretty(&doc)?
            ),
            None => tracing::info!("{}: no data this tick", dataset),
        }
    }

    tracing::info!(
        "dry-run complete — {} collectors exercised",
        collectors.len()
    );
    Ok(())
}

// ── Main loop ─────────────────────────────────────────────────────────────────

/// Resolve the effective log filter string from CLI flags and environment.
/// Precedence (highest first): --log-level > --verbose > RIGSIGNAL_LOG > "info"
/// Print loaded modules + Tier 2 detection result for `pid`. Implements the
/// `dllscan` debug subcommand. Output goes to stdout; ranges from "0 modules
/// (process gone or access denied)" to a full enumeration with the inferred
/// graphics API + settings overlay.
fn run_dllscan(pid: u32) -> Result<()> {
    let paths = dllscan::read_mapped_paths(pid);
    println!("--- {} modules loaded by pid {} ---", paths.len(), pid);
    for p in &paths {
        println!("  {p}");
    }
    println!();
    println!("graphics_api: {:?}", dllscan::graphics_api_from_maps(pid));
    println!(
        "settings_overlay: {}",
        serde_json::to_string_pretty(&dllscan::settings_overlay_from_maps(pid))?
    );
    Ok(())
}

fn resolve_log_filter(verbose: bool, log_level: Option<&str>) -> String {
    if let Some(level) = log_level {
        return level.to_string();
    }
    if verbose {
        return "debug".to_string();
    }
    std::env::var("RIGSIGNAL_LOG").unwrap_or_else(|_| "info".to_string())
}

/// Write documents to whichever output the configuration selects.
///
/// `es_health` is updated on the Elasticsearch path only. Routing every caller
/// through here is what makes the counter honest: five of the six delivery sites
/// are one-shot documents (session start, game detected, summary on game exit,
/// remote connections, final summary), and while only the tick was instrumented
/// a session-start document lost before the first tick was invisible to
/// `rigsignal status` and did not count, so "N consecutive failed deliveries"
/// under-reported the documents actually dropped.
async fn write_output(
    cfg: &config::Config,
    spool_writer: &mut Option<SpoolWriter>,
    docs: Vec<Value>,
    es_health: &EsDeliveryHealth,
) -> Result<shipper::ShipResult> {
    if let Some(writer) = spool_writer {
        let attempted = docs.len();
        writer.write_docs(&docs)?;
        Ok(shipper::ShipResult {
            attempted,
            succeeded: attempted,
            failed: 0,
        })
    } else {
        let outcome = shipper::ship(cfg, docs).await;
        es_health.observe(&outcome);
        outcome
    }
}

#[derive(Deserialize)]
struct FixtureEventContext {
    event_id: String,
    enqueue_timestamp: String,
    local_host_name: String,
    detector_contract: FixtureDetectorContract,
}

#[derive(Deserialize)]
struct FixtureDetectorContract {
    detector_id: String,
    rule_version: String,
    error_prefix: String,
}

fn fixture_event_bytes(input: &PathBuf, context: &PathBuf) -> Result<ExitCode> {
    let outcome: Outcome =
        serde_json::from_slice(&std::fs::read(input)?).context("fixture input")?;
    let fixture: FixtureEventContext =
        serde_json::from_slice(&std::fs::read(context)?).context("fixture context")?;
    let contract = Box::leak(Box::new(DetectorContract {
        detector_id: Box::leak(fixture.detector_contract.detector_id.into_boxed_str()),
        rule_version: Box::leak(fixture.detector_contract.rule_version.into_boxed_str()),
        error_prefix: Box::leak(fixture.detector_contract.error_prefix.into_boxed_str()),
    }));
    let event_context = EventContext {
        event_id: fixture.event_id,
        enqueue_timestamp: fixture.enqueue_timestamp,
        local_host_name: fixture.local_host_name,
        detector_contract: contract,
        input_mode: InputMode::Fixture,
    };
    match DiagnosisEvent::try_from_outcome(
        outcome.with_disposition(Disposition::Finding),
        &event_context,
    ) {
        Ok(event) => {
            use std::io::Write;
            std::io::stdout().write_all(event.canonical_bytes())?;
            Ok(ExitCode::SUCCESS)
        }
        Err(error @ ValidationError::EventBytesLimitExceeded { .. }) => {
            eprintln!("{error:?}");
            Ok(ExitCode::from(1))
        }
        Err(error) => Err(anyhow::anyhow!(
            "fixture event validation failed: {error:?}"
        )),
    }
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    run().await
}

async fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    if cli.build_info_json {
        println!("{}", build_info_json("rigsignal-agent"));
        return Ok(ExitCode::SUCCESS);
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(resolve_log_filter(
            cli.verbose,
            cli.log_level.as_deref(),
        )))
        .with_writer(std::io::stderr)
        .init();

    // Detector diagnoses are self-contained and must work without RigSignal's
    // telemetry configuration. Keep this before Config::load().
    if let Some(Commands::Diagnose {
        action: Some(action),
        ..
    }) = &cli.command
    {
        return Ok(match action {
            DiagnoseAction::Display {
                modes_cfg,
                drm_state,
                json,
                host,
            } => detectors::d6::run_cli(
                modes_cfg.as_deref(),
                drm_state.as_deref(),
                *json,
                host.clone(),
            ),
            DiagnoseAction::GpuBoot {
                offline,
                journal_current,
                journal_prior_kernel,
                journal_prior_tail,
                pci_snapshot,
                boot_list,
                current_boot_id,
                state_file,
                slot,
                json,
                host,
                learn_baseline,
                reset_baseline,
            } => detectors::d3::run_cli(detectors::d3::CliOptions {
                offline: *offline,
                journal_current: journal_current.clone(),
                journal_prior_kernel: journal_prior_kernel.clone(),
                journal_prior_tail: journal_prior_tail.clone(),
                pci_snapshot: pci_snapshot.clone(),
                boot_list: boot_list.clone(),
                current_boot_id: current_boot_id.clone(),
                state_file: state_file.clone(),
                slot: slot.clone(),
                json: *json,
                host: host.clone(),
                learn_baseline: *learn_baseline,
                reset_baseline: *reset_baseline,
            }),
        });
    }

    if let Some(Commands::FixtureEventBytes { input, context }) = &cli.command {
        return fixture_event_bytes(input, context);
    }

    // Handshake has its own explicit protected-config reader and must run before
    // Config::load(), which performs legacy environment/default-path resolution.
    if let Some(Commands::Handshake {
        action: handshake::HandshakeAction::Check(args),
    }) = &cli.command
    {
        handshake_root_telemetry_guard(&cli)?;
        let environment = handshake::ProcessEnvironment;
        let clock = handshake::SystemClock;
        let mut transport = handshake::ReqwestTransport::default();
        let report = handshake::run_check(args.clone(), &environment, &clock, &mut transport)
            .await
            .map_err(|_| anyhow::anyhow!("handshake invariant failure"))?;
        print!(
            "{}",
            report.json_line().context("serialising handshake report")?
        );
        return Ok(ExitCode::from(report.exit_code()));
    }

    let cfg = config::Config::load(cli.config.as_ref())?;

    if cli.print_config {
        let display = cfg.redacted_for_display();
        print!(
            "{}",
            toml::to_string_pretty(&display).context("serialising config for --print-config")?
        );
        return Ok(ExitCode::SUCCESS);
    }

    match cli.command {
        Some(Commands::Diagnose {
            output,
            action: None,
        }) => {
            diagnose::run(&cfg, cli.config.as_deref(), output.as_deref()).await?;
            return Ok(ExitCode::SUCCESS);
        }
        Some(Commands::Dllscan { pid }) => {
            run_dllscan(pid)?;
            return Ok(ExitCode::SUCCESS);
        }
        // Detector arms returned above, before configuration loading.
        Some(Commands::Diagnose {
            action: Some(_), ..
        }) => unreachable!("display diagnosis was dispatched before Config::load"),
        Some(Commands::Handshake { .. }) => {
            unreachable!("handshake was dispatched before Config::load")
        }
        Some(Commands::FixtureEventBytes { .. }) => {
            unreachable!("fixture bytes were dispatched before Config::load")
        }
        None => {}
    }

    if cli.dry_run {
        dry_run().await?;
        return Ok(ExitCode::SUCCESS);
    }

    let es_health = std::sync::Arc::new(EsDeliveryHealth::default());

    let mut spool_writer = match cfg.output.mode {
        OutputMode::Elasticsearch => {
            // A failed preflight is NOT fatal. The identical failure one tick
            // later is already only a warning, and `rigsignal setup` validates
            // the endpoint, API key, privileges and version floor before any of
            // this — so at every start after the first, aborting here could only
            // convert a transient outage into a crash loop. It cannot tell a
            // blip from a misconfiguration, so it must not act as though it can.
            //
            // Seed the tracker either way: this counts as attempt 1 of the
            // outage, which also means the tick path will not repeat the
            // warning for another ES_UNREACHABLE_REPEAT_SECS.
            if let Err(e) = shipper::ping(&cfg).await {
                let _ = es_health.record_failure(now_unix_secs());
                // Two lines on purpose, and NOT for the reason first written
                // here: `ping`'s outermost context no longer interpolates the
                // endpoint, so this rendering is credential-free by itself.
                //
                // Keep the split anyway. The MARKED line is echoed to stdout by
                // `rigsignal status` and must stay machine-stable, and the error's
                // deeper layers still carry the full request URL -- rendering this
                // with `{:#}` or `{:?}` instead of `{}` would reach them and put a
                // query-borne credential back in the journal. Do not merge these.
                tracing::warn!(
                    "{} startup preflight failed — continuing; documents will be \
                     dropped until Elasticsearch is reachable",
                    ES_DELIVERY_MARKER
                );
                tracing::warn!("Elasticsearch startup preflight error: {}", e);
            }
            None
        }
        OutputMode::Spool => Some(SpoolWriter::new(
            &cfg.output.spool_dir,
            cfg.output.max_file_bytes,
            cfg.output.max_file_age_secs,
            cfg.output.spool_retention_hours,
        )?),
    };

    // Collect host info once at startup
    tracing::info!("Collecting host environment snapshot…");
    let host_snapshot = host::collect_snapshot();
    let hostname = host::hostname();

    // Instantiate all collectors via platform-appropriate builder.
    let mut collectors = build_collectors(None);

    // Session manager — CLI --label overrides [session].label in config.
    let session_label = cli.label.or_else(|| cfg.session.label.clone());

    // Resolve Tier 1 settings: CLI flags override [session.settings] config.
    let (upscaler_tech, upscaler_preset) = cli.upscaler.as_deref().map(parse_upscaler).unwrap_or((
        cfg.session
            .settings
            .upscaler_tech
            .clone()
            .unwrap_or_default(),
        cfg.session.settings.upscaler_preset.clone(),
    ));
    let upscaler_tech_ref = if upscaler_tech.is_empty() {
        None
    } else {
        Some(upscaler_tech.as_str())
    };

    let preset = cli
        .preset
        .as_deref()
        .or(cfg.session.settings.preset.as_deref());
    let frame_gen_tech =
        cli.frame_gen
            .as_deref()
            .or(cfg.session.settings.frame_gen_tech.as_deref());
    let resolution =
        cli.resolution
            .as_deref()
            .or(cfg.session.settings.render_resolution_output.as_deref());
    let vsync = cli
        .vsync
        .as_deref()
        .or(cfg.session.settings.render_vsync.as_deref());
    let notes = cli
        .notes
        .as_deref()
        .or(cfg.session.settings.notes.as_deref());

    // CLI --features overrides config features_active (comma-separated string vs vec).
    let cli_features: Option<Vec<String>> = cli
        .features
        .as_deref()
        .map(|s| s.split(',').map(|f| f.trim().to_string()).collect());
    let features_active: Option<Vec<String>> =
        cli_features.or_else(|| cfg.session.settings.features_active.clone());

    let settings_overlay = build_settings_overlay(
        preset,
        upscaler_tech_ref,
        upscaler_preset.as_deref(),
        frame_gen_tech,
        features_active.as_deref(),
        resolution,
        vsync,
        notes,
    );

    // Resolve CLI/config target override (B2.7) — takes precedence over auto-detection.
    let pinned_pid = cli.target_pid.or(cfg.session.target_pid);
    let pinned_name = cli
        .target_name
        .as_deref()
        .or(cfg.session.target_name.as_deref())
        .map(|s| s.to_string());
    let pinned_target: Option<session::Target> = if pinned_pid.is_some() || pinned_name.is_some() {
        let t = session::resolve_user_target(pinned_pid, pinned_name.as_deref());
        if t.is_none() {
            tracing::warn!("User-specified target not found — falling back to auto-detection");
        }
        t
    } else {
        None
    };

    let mut session = session::SessionManager::new_with_label_and_settings(
        session_label.clone(),
        settings_overlay,
    );

    // Connection events are always direct-ES keyed creates. They intentionally
    // bypass the metric spool because spool/Fleet cannot preserve `_id` or
    // return the per-item acknowledgement needed for the tail checkpoint.
    #[cfg(target_os = "linux")]
    let mut remote_connections_tailer = if cfg.elasticsearch.endpoint.trim().is_empty()
        || !cfg.elasticsearch.has_delivery_credentials()
    {
        tracing::warn!("remote_connections tailer disabled: direct Elasticsearch endpoint and credentials are required");
        None
    } else {
        match remote_connections::RemoteConnectionsTailer::new(hostname.clone()) {
            Ok(tailer) => Some(tailer),
            Err(error) => {
                tracing::warn!(%error, "remote_connections tailer disabled during startup");
                None
            }
        }
    };
    // Keep the CLI+config overlay unchanged so we can restore it after each game ends.
    let base_settings_overlay = session.settings_overlay.clone();
    tracing::info!(
        "Session {} started{}",
        session.session_id,
        session_label
            .as_deref()
            .map(|l| format!(" (label: {l})"))
            .unwrap_or_default()
    );

    // Ship session-start document
    let start_doc = build_session_start_doc(&session, &host_snapshot, &hostname);
    if let Err(e) = write_output(&cfg, &mut spool_writer, vec![start_doc], &es_health).await {
        tracing::warn!("Failed to ship session-start doc: {}", error_for_log(&e));
    }

    // Signal handlers — spawned watcher sends on a oneshot so the select! arm
    // is platform-neutral (tokio's select! macro doesn't support #[cfg] on arms).
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::SignalKind;
        let mut sigterm =
            tokio::signal::unix::signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut sigint =
            tokio::signal::unix::signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received — shutting down"),
            _ = sigint.recv() => tracing::info!("SIGINT received — shutting down"),
        }
        let _ = shutdown_tx.send(());
    });
    #[cfg(not(unix))]
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Ctrl-C received — shutting down");
        let _ = shutdown_tx.send(());
    });

    // Accumulators for summary doc
    let mut session_start = std::time::Instant::now();
    let mut tick: u64 = 0;
    let mut session_tick: u64 = 0; // resets each time a game exits
    let mut acc = SessionAccumulators::new();
    // Track last seen target so summary doc includes game.name even after the target exits.
    let mut last_known_game: Option<session::Target> = None;

    // 1-second tick interval; skip missed ticks (don't burst-catch-up).
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                tick += 1;
                session_tick += 1;
                let ts = utc_now();

                // ── Game detection ────────────────────────────────────────────
                match if let Some(ref pinned) = pinned_target {
                    poll_pinned_target(pinned, &mut session.current_game)
                } else {
                    session.poll()
                } {
                    SessionEvent::GameStarted(target) => {
                        tracing::info!(
                            "Game detected: {} (pid {}, all_pids={:?})",
                            target.display_name, target.pid, target.all_pids
                        );
                        for c in &mut collectors {
                            c.set_game_pid(Some(target.pid));
                        }
                        last_known_game = Some(target.clone());

                        // D.7: augment settings with a game profile (profile fills
                        // gaps; CLI/config overlay takes precedence).
                        if let Some(profile) = profiles::find_profile(&target) {
                            let profile_ov = profiles::to_overlay(&profile);
                            if !profile_ov.is_null() {
                                tracing::info!(
                                    "Applied game profile: {} (source: profile)",
                                    profile.game.name
                                );
                                let base =
                                    base_settings_overlay.clone().unwrap_or(json!({}));
                                // deep_merge(profile_ov, base): base wins on conflicts.
                                session.settings_overlay =
                                    Some(deep_merge(profile_ov, base));
                            }
                        }

                        // D.8: maps auto-detection (upscaler, frame-gen) — lowest precedence.
                        let maps_ov = dllscan::settings_overlay_from_maps(target.pid);
                        if !maps_ov.is_null() {
                            tracing::info!(
                                "Maps auto-detection: upscaler/frame-gen hints applied (pid {})",
                                target.pid
                            );
                            let existing =
                                session.settings_overlay.take().unwrap_or_else(|| json!({}));
                            // existing wins on conflict — profile/CLI/config have higher precedence.
                            session.settings_overlay = Some(deep_merge(maps_ov, existing));
                        }

                        let game_doc = build_game_detected_doc(
                            &session, &host_snapshot, &hostname, &target,
                        );
                        if let Err(e) = write_output(&cfg, &mut spool_writer, vec![game_doc], &es_health).await {
                            tracing::warn!("Failed to ship game-detected doc: {}", error_for_log(&e));
                        }
                    }
                    SessionEvent::GameEnded(target) => {
                        tracing::info!("Game exited: {}", target.display_name);
                        for c in &mut collectors {
                            c.set_game_pid(None);
                        }
                        // Ship summary for the session that just ended.
                        // Summary uses the profile-augmented overlay (session.settings_overlay
                        // still holds the merged value from GameStarted).
                        if session_tick > 0 {
                            let duration_s = session_start.elapsed().as_secs();
                            let summary_doc = build_summary_doc(
                                &session,
                                &host_snapshot,
                                &hostname,
                                duration_s,
                                &acc,
                                Some(&target),
                            );
                            tracing::info!(
                                "Shipping session summary on game exit ({}s, {} ticks)",
                                duration_s, session_tick
                            );
                            if let Err(e) = write_output(&cfg, &mut spool_writer, vec![summary_doc], &es_health).await {
                                tracing::warn!("Failed to ship summary doc on game exit: {}", error_for_log(&e));
                            } else if matches!(cfg.output.mode, OutputMode::Elasticsearch) {
                                if let Err(e) = shipper::trigger_transform_sync(&cfg, "rigsignal-game-timeline").await {
                                    tracing::warn!("transform schedule_now failed (non-fatal): {}", e);
                                }
                            }
                        }
                        // Restore CLI+config overlay so the next game starts clean.
                        session.settings_overlay = base_settings_overlay.clone();
                        // Reset per-session state for next game.
                        acc = SessionAccumulators::new();
                        session_start = std::time::Instant::now();
                        session_tick = 0;
                        last_known_game = Some(target); // keep for shutdown-path fallback
                    }
                    SessionEvent::NoChange => {}
                }

                // This is deliberately separate from the configured metric
                // output mode: stream-boundary events need bulk create ids and
                // an acknowledgement before their durable source checkpoint can
                // advance.
                #[cfg(target_os = "linux")]
                if let Some(tailer) = remote_connections_tailer.as_mut() {
                    match tailer.poll(&session) {
                        Ok(events) if !events.is_empty() => {
                            let token = events[0].token.clone();
                            let docs = events.into_iter().map(|event| shipper::ShipDocument {
                                document: event.document,
                                id: Some(event.id),
                            }).collect();
                            match shipper::ship_documents(&cfg, docs).await {
                                Ok(result) if result.failed == 0 => {
                                    if let Err(error) = tailer.ack_success(&token) {
                                        tracing::warn!(%error, "remote_connections checkpoint acknowledgement failed");
                                    }
                                }
                                Ok(result) => {
                                    tailer.nack();
                                    tracing::warn!(failed = result.failed, "remote_connections bulk batch retained for replay");
                                }
                                Err(error) => {
                                    tailer.nack();
                                    tracing::warn!(%error, "remote_connections bulk transport error; batch retained for replay");
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(error) => tracing::warn!(%error, "remote_connections tail error"),
                    }
                }

                // ── Build base doc for this tick ──────────────────────────────
                let base = deep_merge(
                    json!({ "@timestamp": ts }),
                    session.base_doc(&hostname),
                );

                // ── Collect from all collectors ───────────────────────────────
                let mut tick_docs: Vec<Value> = Vec::with_capacity(collectors.len());
                for c in &mut collectors {
                    let dataset = c.dataset();
                    match c.collect() {
                        Ok(Some(payload)) => {
                            // Stream-client telemetry observes a remote client.  It must
                            // never inherit the agent's generated idle session context.
                            let collector_base = if dataset == "rigsignal.stream_client" {
                                deep_merge(
                                    json!({ "@timestamp": ts }),
                                    session.stream_client_base_doc(&hostname),
                                )
                            } else {
                                base.clone()
                            };
                            let mut doc = deep_merge(collector_base, payload);
                            add_data_stream(&mut doc, dataset);
                            tick_docs.push(doc);
                        }
                        Ok(None) => {}
                        Err(e) => tracing::warn!("{} error: {}", dataset, e),
                    }
                }

                // ── Update session accumulators ───────────────────────────────
                acc.update(&tick_docs);

                // ── Ship (non-blocking) ───────────────────────────────────────
                // Spawn shipping as a separate task so network latency or ES
                // timeouts do not stall the 1-second collection timer.
                if !tick_docs.is_empty() {
                    let n = tick_docs.len();
                    let tick_num = tick;
                    if matches!(cfg.output.mode, OutputMode::Elasticsearch) {
                        let cfg_ship = cfg.clone();
                        let health = es_health.clone();
                        tokio::spawn(async move {
                            let outcome = shipper::ship(&cfg_ship, tick_docs).await;
                            health.observe(&outcome);
                            match &outcome {
                                Ok(r) => {
                                    if r.failed > 0 {
                                        tracing::warn!(
                                            "Tick {}: {}/{} docs failed",
                                            tick_num,
                                            r.failed,
                                            n
                                        );
                                    } else {
                                        tracing::debug!("Tick {}: shipped {} docs", tick_num, n);
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Tick {} bulk error: {}", tick_num, e);
                                }
                            }
                        });
                    } else if let Err(e) = write_output(&cfg, &mut spool_writer, tick_docs, &es_health).await {
                        tracing::warn!("Tick {} spool error: {}", tick_num, error_for_log(&e));
                    } else {
                        tracing::debug!("Tick {}: spooled {} docs", tick_num, n);
                    }
                }

                if let Some(writer) = spool_writer.as_mut() {
                    if let Err(e) = writer.rotate_stale_files() {
                        tracing::warn!("Tick {} spool rotation error: {}", tick, error_for_log(&e));
                    }
                }
            }

            _ = &mut shutdown_rx => {
                break;
            }
        }
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────
    session.remove_session_json();

    let mut summary_written = false;
    if session_tick > 0 {
        let duration_s = session_start.elapsed().as_secs();
        let summary_doc = build_summary_doc(
            &session,
            &host_snapshot,
            &hostname,
            duration_s,
            &acc,
            last_known_game.as_ref(),
        );
        tracing::info!(
            "Shipping session summary ({}s, {} ticks)",
            duration_s,
            session_tick
        );
        if let Err(e) = write_output(&cfg, &mut spool_writer, vec![summary_doc], &es_health).await {
            tracing::warn!("Failed to ship summary doc: {}", error_for_log(&e));
        } else {
            summary_written = true;
        }
        if summary_written && matches!(cfg.output.mode, OutputMode::Elasticsearch) {
            // Trigger an immediate transform sync so the Games dashboard
            // reflects this session within seconds rather than up to 60 s.
            if let Err(e) = shipper::trigger_transform_sync(&cfg, "rigsignal-game-timeline").await {
                tracing::warn!("transform schedule_now failed (non-fatal): {}", e);
            }
        }
    }

    // Finalization is deliberately outside the summary branch: a failed summary
    // write must never strand already-buffered metric batches at shutdown.
    if let Some(writer) = spool_writer.as_mut() {
        if let Err(e) = writer.finalize_all() {
            tracing::warn!(
                "Failed to finalize spool files during shutdown: {}",
                error_for_log(&e)
            );
        }
    }

    tracing::info!("RigSignal agent stopped after {} ticks", tick);
    Ok(ExitCode::SUCCESS)
}

fn handshake_has_root_telemetry_options(cli: &Cli) -> bool {
    cli.config.is_some()
        || cli.dry_run
        || cli.verbose
        || cli.log_level.is_some()
        || cli.print_config
        || cli.label.is_some()
        || cli.preset.is_some()
        || cli.upscaler.is_some()
        || cli.frame_gen.is_some()
        || cli.features.is_some()
        || cli.resolution.is_some()
        || cli.vsync.is_some()
        || cli.notes.is_some()
        || cli.target_pid.is_some()
        || cli.target_name.is_some()
}

fn handshake_root_telemetry_guard(cli: &Cli) -> Result<(), clap::Error> {
    if handshake_has_root_telemetry_options(cli) {
        Err(clap::Error::raw(
            clap::error::ErrorKind::ArgumentConflict,
            "telemetry options cannot be combined with handshake check",
        ))
    } else {
        Ok(())
    }
}

/// Render an error for an operator log: the error's own message, plus the OS
/// error code and its strerror text when one is anywhere in the cause chain,
/// and nothing else. Controls in the outer message are escaped.
///
/// Why this exists, and why it is not simply `{:#}`. On a full disk the spool
/// warnings printed only `flushing spool writer` — the errno never reached the
/// log, because `anyhow` shows the cause chain only under the alternate format.
/// Switching those warnings to `{:#}` does surface the errno, but it also
/// surfaces every other cause verbatim, and a non-author review reproduced three
/// consequences of that: the Elasticsearch URL including a URL-borne credential
/// (four of these call sites also serve direct delivery, where a request failure
/// is wrapped in a static context over a `reqwest::Error`), a spool file path,
/// and a cause containing a newline splitting one log event into two.
///
/// So this takes the errno and refuses the free text. An `io::Error` returns
/// `Some` from `raw_os_error()` only when it holds the OS representation, and
/// that representation's `Display` is the platform error string plus the number
/// — there is no slot in it for caller-supplied text. That is the property being
/// relied on. It is NOT a claim that a syscall produced the value:
/// `from_raw_os_error` lets a caller choose the number. Choosing a misleading
/// errno is a far smaller problem than echoing an arbitrary string, which is the
/// trade this makes. When no OS error is in the chain, text with no control,
/// separator, bidi or backslash character stays byte-identical to the previous
/// `{}` behaviour. A backslash is doubled, so a Windows path logs as
/// `C:\\ProgramData\\...`: that is what keeps a real line break (`\n`, two
/// characters) distinguishable from the literal text `\n` (three).
fn error_for_log(err: &anyhow::Error) -> String {
    let outer_message = err.to_string();
    let outer = log_safe::escape_for_log(&outer_message);
    for (depth, cause) in err.chain().enumerate() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if io_err.raw_os_error().is_some() {
                // At depth 0 the error IS the OS error, so its own Display is
                // already the message; appending would print it twice. Reachable:
                // a failed removal of an empty replacement file propagates a bare
                // io::Error with no context.
                if depth == 0 {
                    return outer.into_owned();
                }
                return format!("{outer}: {io_err}");
            }
        }
    }
    outer.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plausible wall-clock value. Tests use realistic timestamps so they
    /// exercise the same arithmetic the product sees.
    const T0: u64 = 1_757_000_000;

    #[test]
    fn first_failure_of_an_outage_always_warns() {
        let h = EsDeliveryHealth::default();
        let first = h.record_failure(T0).expect("first failure must warn");
        assert_eq!(first.attempts, 1);
        assert_eq!(first.since_unix, T0);
    }

    #[test]
    fn repeats_inside_the_window_are_suppressed_but_still_counted() {
        let h = EsDeliveryHealth::default();
        // Setup assertion: if the first call did not warn, the silence below
        // would prove nothing about rate limiting.
        assert!(h.record_failure(T0).is_some(), "setup: first must warn");

        for offset in [1, 5, 30, ES_UNREACHABLE_REPEAT_SECS - 1] {
            assert!(
                h.record_failure(T0 + offset).is_none(),
                "a repeat {offset}s into a {ES_UNREACHABLE_REPEAT_SECS}s window must not warn"
            );
        }

        let due = h
            .record_failure(T0 + ES_UNREACHABLE_REPEAT_SECS)
            .expect("warning is due once the window elapses");
        assert_eq!(
            due.attempts, 6,
            "all attempts counted, including the suppressed ones"
        );
        assert_eq!(due.since_unix, T0, "the outage start must not move");
    }

    /// The operator-facing property, asserted in ABSOLUTE terms.
    ///
    /// An earlier version of this test asserted
    /// `emissions == 3600 / ES_UNREACHABLE_REPEAT_SECS`, which puts the constant
    /// under test on both sides of the comparison. Widening the window to a day
    /// made it assert `0 == 0` and pass, so "warn once then go quiet for 24 h"
    /// was indistinguishable from the mute-forever case this test exists to
    /// exclude. The numbers below are fixed independently of the constant.
    #[test]
    fn the_warning_is_rate_limited_but_never_suppressed_for_good() {
        let h = EsDeliveryHealth::default();
        assert!(h.record_failure(T0).is_some(), "setup: first must warn");
        let mut emissions = 0;
        for second in 1..=3600 {
            if h.record_failure(T0 + second).is_some() {
                emissions += 1;
            }
        }
        assert!(
            emissions >= 12,
            "an hour of continuous failure produced {emissions} warnings; the outage \
             must stay audible throughout, not be announced once"
        );
    }

    #[test]
    fn success_reports_the_recovery_and_starts_a_fresh_outage_afterwards() {
        let h = EsDeliveryHealth::default();
        assert!(h.record_failure(T0).is_some(), "setup: first must warn");
        assert!(
            h.record_failure(T0 + 1).is_none(),
            "setup: second suppressed"
        );

        assert_eq!(
            h.record_success(),
            Some(2),
            "recovery reports both attempts"
        );
        assert_eq!(h.record_success(), None, "a healthy run says nothing");

        // A later outage is a NEW outage: its `since` is its own start and its
        // count restarts. It is NOT announced immediately, and that is
        // deliberate rather than a regression -- the last-spoke stamp is kept
        // across outage boundaries so an endpoint alternating between failure and
        // success cannot emit a warn/recovery pair on every tick. The cost is
        // that a genuine new outage can wait up to one window to be named; the
        // count is accurate throughout.
        assert!(
            h.record_failure(T0 + 5).is_none(),
            "a new outage inside the window must not re-announce"
        );
        assert_eq!(h.outage_attempts(), Some(1), "but it must still be counted");

        let again = h
            .record_failure(T0 + 5 + ES_UNREACHABLE_REPEAT_SECS)
            .expect("a new outage is named once the window has passed");
        assert_eq!(again.attempts, 2);
        assert_eq!(
            again.since_unix,
            T0 + 5,
            "the new outage reports its OWN start, not the old one"
        );
    }

    /// A clock that steps BACKWARDS must not black out the warning.
    ///
    /// The predicate used `saturating_sub`, so after a backward step the
    /// difference saturated to zero and nothing was due until real time caught
    /// up -- measured at 7259 consecutive silent failures after a two-hour step.
    /// The clock is CLOCK_REALTIME and the units are ordered
    /// `After=network.target`, not `After=time-sync.target`, so a step
    /// correction shortly after boot is the ordinary path.
    #[test]
    fn a_backward_clock_step_does_not_silence_the_warning() {
        for step_back in [1u64, 60, 7200, 86_400] {
            let h = EsDeliveryHealth::default();
            assert!(h.record_failure(T0).is_some(), "setup: first must warn");
            assert!(
                h.record_failure(T0 - step_back).is_some(),
                "a {step_back}s backward clock step silenced the warning"
            );
        }
    }

    #[test]
    fn concurrent_failures_emit_exactly_one_warning_per_window() {
        use std::sync::{Arc, Barrier};
        // Tick shipping runs in detached tasks, so several can fail at once.
        //
        // THE BARRIER IS THE SETUP, not decoration. Spawning threads in a loop
        // does not make them contend: the first finishes before the last is
        // created, each then sees the previous one's stamp, and the single
        // emission that results proves nothing. An earlier version of this test
        // lacked the barrier and passed against a deliberately broken build.
        const THREADS: usize = 16;
        const ROUNDS: usize = 200;
        for _ in 0..ROUNDS {
            let h = Arc::new(EsDeliveryHealth::default());
            let gate = Arc::new(Barrier::new(THREADS));
            let mut handles = Vec::new();
            for _ in 0..THREADS {
                let h = h.clone();
                let gate = gate.clone();
                handles.push(std::thread::spawn(move || {
                    gate.wait();
                    usize::from(h.record_failure(T0).is_some())
                }));
            }
            let emissions: usize = handles.into_iter().map(|t| t.join().expect("join")).sum();
            assert_eq!(emissions, 1, "exactly one task may emit per window");
        }
    }

    /// A recovery landing between a failure's start-of-outage and its own read of
    /// that field used to make the warning print the epoch. Holding one lock for
    /// the whole operation makes that unrepresentable; this pins it.
    #[test]
    fn a_racing_recovery_never_produces_an_epoch_timestamp() {
        use std::sync::Arc;
        let h = Arc::new(EsDeliveryHealth::default());
        let mut handles = Vec::new();
        for i in 0..8 {
            let h = h.clone();
            handles.push(std::thread::spawn(move || {
                let mut bad = Vec::new();
                for n in 0..500u64 {
                    if i % 2 == 0 {
                        if let Some(u) = h.record_failure(T0 + n) {
                            if u.since_unix == 0 {
                                bad.push(u.since_unix);
                            }
                        }
                    } else {
                        h.record_success();
                    }
                }
                bad
            }));
        }
        let bad: Vec<u64> = handles
            .into_iter()
            .flat_map(|t| t.join().expect("join"))
            .collect();
        assert!(
            bad.is_empty(),
            "a racing recovery produced {} epoch timestamps",
            bad.len()
        );
    }

    /// A bulk that returns HTTP 200 while rejecting documents is a DELIVERY
    /// FAILURE, not a success.
    ///
    /// `ship_documents` returns `Err` only for transport errors and a non-2xx
    /// status. When Elasticsearch crosses its flood-stage watermark and sets
    /// `index.blocks.read_only_allow_delete`, or a field mapping conflicts, the
    /// bulk returns 200 with every item rejected. An earlier revision recorded
    /// success before examining `failed`, so total document loss was announced to
    /// the operator as "recovered" -- and that is the line `rigsignal status`
    /// shows.
    ///
    /// Asserted through the attempt COUNT rather than through emission: emission
    /// is rate-limited across outages, so a test keyed on the printed line would
    /// confuse "not counted" with "not due yet".
    #[test]
    fn a_rejected_bulk_is_a_failure_even_though_the_request_succeeded() {
        let rejected = || -> Result<shipper::ShipResult> {
            Ok(shipper::ShipResult {
                attempted: 10,
                succeeded: 0,
                failed: 10,
            })
        };
        let partial = || -> Result<shipper::ShipResult> {
            Ok(shipper::ShipResult {
                attempted: 10,
                succeeded: 7,
                failed: 3,
            })
        };
        let clean = || -> Result<shipper::ShipResult> {
            Ok(shipper::ShipResult {
                attempted: 10,
                succeeded: 10,
                failed: 0,
            })
        };

        let h = EsDeliveryHealth::default();
        assert_eq!(h.outage_attempts(), None, "setup: nothing wrong yet");

        h.observe(&rejected());
        assert_eq!(
            h.outage_attempts(),
            Some(1),
            "a 200-with-every-item-rejected bulk was not counted as a failed delivery"
        );

        h.observe(&partial());
        assert_eq!(
            h.outage_attempts(),
            Some(2),
            "a partially rejected bulk was not counted as a failed delivery"
        );

        h.observe(&clean());
        assert_eq!(
            h.outage_attempts(),
            None,
            "a fully successful bulk must clear the outage"
        );
    }

    /// The rate limit must not be defeated by ALTERNATION rather than volume.
    ///
    /// A half-healthy endpoint — one bad backend behind a load balancer, a node
    /// flapping 503 — fails and succeeds on alternate ticks. With the last-spoke
    /// stamp scoped to a single outage, each new failure started a fresh outage
    /// and warned at once, so the pair repeated every second forever and a
    /// sustained 50% loss read as healthy.
    #[test]
    fn alternating_failure_and_success_cannot_flood_the_log() {
        let h = EsDeliveryHealth::default();
        let mut emissions = 0;
        for second in 0..3600u64 {
            if second % 2 == 0 {
                if h.record_failure(T0 + second).is_some() {
                    emissions += 1;
                }
            } else if h.record_success().is_some() {
                emissions += 1;
            }
        }
        // One hour of alternation, at most one failure line and one recovery line
        // per window. The bound is absolute, not derived from the constant.
        assert!(
            emissions <= 150,
            "an hour of alternating failure produced {emissions} lines; the rate limit is \
             defeated by alternation"
        );
        // ...and it must not go completely silent either.
        assert!(
            emissions >= 2,
            "an hour of alternating failure produced {emissions} lines; a half-healthy \
             endpoint must not read as healthy"
        );
    }

    #[test]
    fn since_renders_as_rfc3339_utc() {
        let u = EsUnreachable {
            since_unix: T0,
            attempts: 1,
        };
        let rendered = u.since_rfc3339();
        assert!(
            rendered.ends_with('Z') && rendered.contains('-'),
            "unexpected rendering: {rendered}"
        );
    }

    /// Every `.rs` file under the crate root that is production source.
    ///
    /// Read from the filesystem at test time rather than enumerated with
    /// `include_str!`, because a hand-written list is exactly the thing that goes
    /// stale: a module added next month would simply not be covered, and nothing
    /// would say so. `CARGO_MANIFEST_DIR` is a compile-time constant pointing at
    /// this crate's own directory, so the walk finds the sources this binary was
    /// built from.
    fn rust_sources(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if path.is_dir() {
                    // `tests/` holds integration tests, `target/` build output.
                    if name == "tests" || name == "target" || name.starts_with('.') {
                        continue;
                    }
                    stack.push(path);
                } else if name.ends_with(".rs") {
                    out.push(path);
                }
            }
        }
        out.sort();
        out
    }

    /// The file with its `#[cfg(test)] mod ... { ... }` blocks removed, and
    /// nothing else removed.
    ///
    /// THE OBVIOUS IMPLEMENTATION IS WRONG AND WAS REJECTED IN REVIEW. Cutting the
    /// file at the first line-anchored `#[cfg(test)]` assumes that marker is the
    /// start of the test module and that nothing production follows it. Both
    /// halves are false in this crate, measured:
    ///
    ///   * `shipper.rs` opens with a `#[cfg(test)] use ...;` -- an idiomatic
    ///     test-only import -- at line 14, so the cut landed there and scanned
    ///     461 of 67,933 bytes. 99.3% of the ES bulk shipper was excluded from a
    ///     guard whose whole subject is what that file logs.
    ///   * `session.rs` places production code AFTER its test module by design,
    ///     with an `#[allow(clippy::items_after_test_module)]` and a comment
    ///     saying so. 60% of it was excluded, including eight warning sites.
    ///
    /// So remove the test MODULES by brace matching and keep everything else. A
    /// `#[cfg(test)]` on a single item has no block and is left alone; it cannot
    /// carry a hazard, and cutting at it costs the rest of the file.
    ///
    /// Removed spans are replaced by newlines rather than deleted, so reported
    /// line numbers still refer to the real file.
    fn production_region(src: &str) -> String {
        let bytes = src.as_bytes();
        let mut out = String::with_capacity(src.len());
        let mut cursor = 0usize;
        for (marker, _) in src.match_indices("#[cfg(test)]") {
            if marker < cursor {
                continue;
            }
            if marker != 0 && bytes[marker - 1] != b'\n' {
                continue; // indented: not a top-level item
            }
            // Only a MODULE is removed. Anything else keeps its place.
            let after = &src[marker + "#[cfg(test)]".len()..];
            let trimmed = after.trim_start();
            if !trimmed.starts_with("mod ") {
                continue;
            }
            // An out-of-line `mod name;` has no body. Never search beyond its
            // semicolon for a brace belonging to a later production item.
            let Some(open_rel) = after.find(['{', ';']) else {
                continue;
            };
            if after.as_bytes()[open_rel] == b';' {
                continue;
            }
            let open = marker + "#[cfg(test)]".len() + open_rel;
            let Some(end) = matching_brace(src, open) else {
                continue;
            };
            out.push_str(&src[cursor..marker]);
            // Preserve line count so line numbers stay true to the file.
            for _ in src[marker..=end].bytes().filter(|b| *b == b'\n') {
                out.push('\n');
            }
            cursor = end + 1;
        }
        out.push_str(&src[cursor..]);
        out
    }

    /// If a raw string starts at `i` (`r"`, `br#"`, `cr##"` ...), the index just
    /// past its closing delimiter.
    ///
    /// Raw strings matter here because a backslash inside one is NOT an escape.
    /// A review found live instances: `config.rs` holds `r#"..."#` TOML fixtures,
    /// and treating them as ordinary strings desynchronises the quote tracker.
    /// They are currently benign only by coincidence -- every embedded string
    /// happens to contribute an even quote count -- which is not a property
    /// anyone maintains on purpose.
    fn raw_string_end(src: &str, i: usize) -> Option<usize> {
        let bytes = src.as_bytes();
        let r = match (bytes.get(i), bytes.get(i + 1)) {
            (Some(b'r'), _) => i,
            (Some(b'b' | b'c'), Some(b'r')) => i + 1,
            _ => return None,
        };
        if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
            return None;
        }
        let mut hashes = 0usize;
        let mut j = r + 1;
        while bytes.get(j) == Some(&b'#') {
            hashes += 1;
            j += 1;
        }
        if bytes.get(j) != Some(&b'"') {
            return None;
        }
        let mut k = j + 1;
        while k < bytes.len() {
            if bytes[k] == b'"' {
                let mut closing = 0usize;
                while closing < hashes && bytes.get(k + 1 + closing) == Some(&b'#') {
                    closing += 1;
                }
                if closing == hashes {
                    return Some(k + 1 + hashes);
                }
            }
            k += 1;
        }
        None
    }

    /// A character literal has one character or one escape, followed by a quote.
    /// A lifetime (`'a`, `'static`) has no closing quote at that position.
    fn char_literal_end(src: &str, i: usize) -> Option<usize> {
        let bytes = src.as_bytes();
        let quote = if bytes.get(i) == Some(&b'b') && bytes.get(i + 1) == Some(&b'\'') {
            i + 1
        } else if bytes.get(i) == Some(&b'\'') {
            i
        } else {
            return None;
        };
        let first = quote + 1;
        let end = if bytes.get(first) == Some(&b'\\') {
            if bytes.get(first + 1) == Some(&b'u') && bytes.get(first + 2) == Some(&b'{') {
                let close = bytes.get(first + 3..)?.iter().position(|&b| b == b'}')? + first + 3;
                close + 1
            } else if bytes.get(first + 1) == Some(&b'x') {
                first + 4
            } else {
                first + 2
            }
        } else {
            first + src.get(first..)?.chars().next()?.len_utf8()
        };
        (bytes.get(end) == Some(&b'\'')).then_some(end + 1)
    }

    /// Index of the `}` closing the `{` at `open`, honouring strings, char
    /// literals and comments so a brace inside any of them cannot end the block.
    fn matching_brace(src: &str, open: usize) -> Option<usize> {
        let bytes = src.as_bytes();
        let mut depth = 0usize;
        let mut i = open;
        let (mut in_str, mut escaped) = (false, false);
        let mut in_line = false;
        let mut block_depth = 0usize;
        while i < bytes.len() {
            let c = bytes[i] as char;
            let next = bytes.get(i + 1).map(|b| *b as char);
            if in_line {
                if c == '\n' {
                    in_line = false;
                }
                i += 1;
                continue;
            }
            if block_depth > 0 {
                // DEPTH, not a flag. Rust block comments nest, and the sibling
                // `strip_comments` already counted depth -- this function was
                // written with a bool and regressed against a correct pattern
                // sitting a few hundred lines away in the same file.
                if c == '/' && next == Some('*') {
                    block_depth += 1;
                    i += 2;
                    continue;
                }
                if c == '*' && next == Some('/') {
                    block_depth -= 1;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            if in_str {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            match c {
                '/' if next == Some('/') => {
                    in_line = true;
                    i += 2;
                    continue;
                }
                '/' if next == Some('*') => {
                    block_depth = 1;
                    i += 2;
                    continue;
                }
                'r' | 'b' | 'c' if raw_string_end(src, i).is_some() => {
                    i = raw_string_end(src, i).expect("checked");
                    continue;
                }
                '\'' | 'b' if char_literal_end(src, i).is_some() => {
                    i = char_literal_end(src, i).expect("checked");
                    continue;
                }
                '"' => in_str = true,
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// TREE-WIDE: no production source anywhere in this crate may render an error
    /// with the ALTERNATE form.
    ///
    /// The guard above covers this file and fully-qualified `tracing::` calls only.
    /// This one covers every module, and deliberately bans a NARROWER set of specs
    /// so it can: the alternate Display `{:#}` and the alternate Debug `{:#?}`,
    /// in every spelling including inline capture, and NOT the plain debug `{:?}`.
    ///
    /// WHY THE DEBUG RENDER IS LEFT OUT, since a wider ban looks strictly safer:
    /// `{:?}` on a `Path` or a `PathBuf` is the idiomatic way to print one, and
    /// `session.rs` alone has about ten such sites -- all benign. Banning it
    /// tree-wide would red on all of them, and the obvious repair, listing them as
    /// exemptions, would add ten waiver rows and dilute the guard toward the
    /// documented-exemption failure this codebase has logged before. The debug ban
    /// therefore stays local to the file whose sites are all error renders. The
    /// alternate forms have no such benign use: `{:#x}`, `{:#b}` and `{:#o}` end in
    /// different closing forms and are unaffected.
    ///
    /// ALTERNATE DEBUG IS INCLUDED even though it is half a debug render, because
    /// `:#?}` contains neither of the other closing forms as a substring, so
    /// leaving it out would reopen exactly the evasion this predicate was widened
    /// to close -- for no benefit, there being zero uses of it anywhere.
    ///
    /// WHAT THIS DOES NOT CATCH, and the first item is the incident that motivated
    /// the whole line of work, so read it before trusting this guard:
    ///   * An alternate render performed in a `format!` whose result is then passed
    ///     to a log macro. That is precisely how the endpoint reached the journal
    ///     from `diagnose`. This check does catch it, because it scans production
    ///     source rather than macro bodies -- but only because it is a TEXT scan of
    ///     the whole region. Move the `format!` into a helper in a file this walk
    ///     skips and it is invisible again.
    ///   * A fill or align character before the flag (`{e:>#}`), which needs a real
    ///     parse of the format spec rather than a substring match.
    ///   * Tracing's `?field` Debug shorthand, which is not a format spec at all.
    ///     Measured at the time of writing: zero such sites in production source.
    ///   * Anything reached through a `Display` impl that itself renders a cause
    ///     chain.
    ///   * ANY SOURCE OUTSIDE THIS CRATE. The walk starts at `CARGO_MANIFEST_DIR`,
    ///     so it covers this crate and nothing else. The eBPF daemon is a separate
    ///     Cargo workspace in a sibling directory and is NOT walked -- and it does
    ///     contain such a site, in its probe loader. Stated rather than left to be
    ///     discovered, because "the tree-wide guard passes" will otherwise be read
    ///     as "the repository is clean", and the repository is larger than the
    ///     crate.
    const ALTERNATE_SPECS: [&str; 2] = [":#}", ":#?}"];

    fn has_alternate_render(line: &str) -> bool {
        ALTERNATE_SPECS.iter().any(|spec| line.contains(spec))
    }

    #[test]
    fn no_production_source_renders_an_error_with_the_alternate_form() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let files = rust_sources(&root);

        // Assert the SETUP. Every assertion below is an ABSENCE check, and an
        // absence check over an empty or truncated file list passes while proving
        // nothing at all.
        assert!(
            files.len() >= 20,
            "the source walk found only {} files under {}; an absence check over \
             too few files is vacuous",
            files.len(),
            root.display()
        );
        assert!(
            files.iter().any(|p| p.ends_with("main.rs")),
            "the walk did not find main.rs, so it is not looking where it thinks"
        );
        let mut scanned_bytes = 0usize;

        let mut findings = Vec::new();
        for path in &files {
            let raw = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            let region = strip_comments(&production_region(&raw));
            scanned_bytes += region.len();
            for (index, line) in region.lines().enumerate() {
                if has_alternate_render(line) {
                    let shown = path.strip_prefix(&root).unwrap_or(path);
                    findings.push(format!("{}:{} {}", shown.display(), index + 1, line.trim()));
                }
            }
        }

        assert!(
            scanned_bytes > 100_000,
            "only {scanned_bytes} bytes of production source were scanned; the cut \
             or the stripper has eaten the corpus"
        );

        // PER-FILE ANCHORS, because the aggregate floor above CANNOT see one file
        // collapsing. A review demonstrated exactly that: the corpus is ~900 KB,
        // so losing 99% of the ES shipper AND 60% of session.rs still cleared both
        // the file count and the byte floor comfortably. An aggregate assertion
        // bounds total collapse and nothing finer, which is less than it looks.
        //
        // Each anchor is a production symbol deep in its file. If the region logic
        // regresses, the anchor vanishes and names the file that went dark.
        //
        // WHAT EACH ONE ACTUALLY DISCRIMINATES, measured rather than assumed,
        // because the first attempt at this list contained an anchor that proved
        // nothing and I did not notice:
        //   shipper.rs    catches the rejected cut-at-first-marker (that file was
        //                 reduced to 0.7% by it)
        //   session.rs    likewise -- but ONLY with a symbol past the test module.
        //                 `Lutris` was the first choice and appears in a doc
        //                 comment on line 4, so the BROKEN region contained it too
        //                 and the anchor was satisfied by both versions.
        //   handshake.rs  does NOT discriminate against that particular
        //                 regression, because the old cut happened to be correct
        //                 for this file. It is forward-looking: it guards against
        //                 a FUTURE change that shortens this file's region.
        //
        // An anchor satisfied by both the fixed and the broken version is not a
        // weak test, it is not a test.
        for (file, anchor) in [
            ("shipper.rs", "fn build_client"),
            // `Lutris` was the first choice and it was BLIND: it appears in a
            // doc comment at session.rs line 4, so the REJECTED implementation's
            // output contained it too. An anchor that both the fixed and the
            // broken version satisfy tests nothing. This symbol exists only past
            // the test module, which is the region that was being lost.
            ("session.rs", "LutrisGameConfig"),
            ("handshake.rs", "fn endpoint_origin"),
        ] {
            let path = root.join(file);
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            assert!(
                raw.contains(anchor),
                "anchor `{anchor}` is no longer in {file}; update the anchor rather \
                 than deleting it, or this check silently stops checking"
            );
            assert!(
                production_region(&raw).contains(anchor),
                "{file} is being scanned only up to some point BEFORE `{anchor}`, so \
                 the tail of that file is unguarded while this test still passes"
            );
        }
        assert!(
            findings.is_empty(),
            "production source renders an error with the alternate form, which \
             prints every cause verbatim -- the mechanism by which a configured \
             endpoint reached the journal. Render with `{{}}` and let the outermost \
             context carry the message:\n{}",
            findings.join("\n")
        );
    }

    /// Replace every Rust comment with spaces, preserving newlines so line numbers
    /// survive.
    ///
    /// Needed because the hazard this file guards against is DISCUSSED in prose all
    /// over this codebase -- the non-test region of this very file names `{:#}` in
    /// four comments -- so a scan that cannot tell code from commentary would fire
    /// on the documentation of the rule it enforces.
    ///
    /// Tracks ordinary, raw, byte and C strings and char literals so comment
    /// markers inside them cannot erase later production source.
    fn strip_comments(src: &str) -> String {
        let bytes = src.as_bytes();
        let mut out = String::with_capacity(src.len());
        let mut i = 0usize;
        let (mut in_str, mut escaped) = (false, false);
        let mut block_depth = 0usize;
        let mut in_line = false;
        while i < bytes.len() {
            let c = bytes[i] as char;
            let next = bytes.get(i + 1).map(|b| *b as char);
            if in_line {
                if c == '\n' {
                    in_line = false;
                    out.push('\n');
                } else {
                    out.push(' ');
                }
                i += 1;
                continue;
            }
            if block_depth > 0 {
                if c == '/' && next == Some('*') {
                    block_depth += 1;
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                if c == '*' && next == Some('/') {
                    block_depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                out.push(if c == '\n' { '\n' } else { ' ' });
                i += 1;
                continue;
            }
            if in_str {
                out.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            if c == '/' && next == Some('/') {
                in_line = true;
                out.push_str("  ");
                i += 2;
                continue;
            }
            if c == '/' && next == Some('*') {
                block_depth = 1;
                out.push_str("  ");
                i += 2;
                continue;
            }
            if matches!(c, 'r' | 'b' | 'c') {
                if let Some(end) = raw_string_end(src, i) {
                    out.push_str(&src[i..end]);
                    i = end;
                    continue;
                }
            }
            if matches!(c, '\'' | 'b') {
                if let Some(end) = char_literal_end(src, i) {
                    out.push_str(&src[i..end]);
                    i = end;
                    continue;
                }
            }
            if c == '"' {
                in_str = true;
            }
            out.push(c);
            i += 1;
        }
        out
    }

    /// `production_region` against the two real shapes that broke its predecessor.
    ///
    /// Its first implementation cut the file at the first line-anchored
    /// `#[cfg(test)]`, which is wrong twice over in this crate, and neither case
    /// was hypothetical -- a review measured both. Only `strip_comments` had a
    /// test; this function did not, and that is why the defect shipped to review.
    #[test]
    fn production_region_removes_test_modules_and_nothing_else() {
        // SHAPE 1: a `#[cfg(test)]` single item BEFORE the real test module. The
        // old cut landed on the import and dropped the rest of the file --
        // measured at 99.3% of the ES shipper.
        let shape_one = concat!(
            "use std::io;\n",
            "#[cfg(test)]\n",
            "use std::collections::HashSet;\n",
            "fn production_one() { let _ = \"KEEP_ONE\"; }\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    fn helper() { let _ = \"DROP_ME\"; }\n",
            "}\n",
        );
        let region = production_region(shape_one);
        assert!(
            region.contains("KEEP_ONE"),
            "production code dropped: {region}"
        );
        assert!(
            region.contains("HashSet"),
            "a cfg(test) single item has no block and must not cut the file: {region}"
        );
        assert!(
            !region.contains("DROP_ME"),
            "test module survived: {region}"
        );

        // SHAPE 2: production code AFTER the test module. session.rs does this
        // deliberately and says so in an allow attribute.
        let shape_two = concat!(
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    fn helper() { let _ = \"DROP_ME\"; }\n",
            "}\n",
            "fn production_two() { let _ = \"KEEP_TWO\"; }\n",
        );
        let region = production_region(shape_two);
        assert!(
            region.contains("KEEP_TWO"),
            "code after the test module was dropped: {region}"
        );
        assert!(
            !region.contains("DROP_ME"),
            "test module survived: {region}"
        );

        // A brace inside a string or a comment must not end the block early.
        let tricky = concat!(
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    fn a() { let _ = \"}\"; }\n",
            "    // }\n",
            "    fn b() { let _ = \"DROP_ME\"; }\n",
            "}\n",
            "fn production_three() { let _ = \"KEEP_THREE\"; }\n",
        );
        let region = production_region(tricky);
        assert!(
            !region.contains("DROP_ME"),
            "brace-matching ended early: {region}"
        );
        assert!(region.contains("KEEP_THREE"), "tail dropped: {region}");

        // A BLOCK COMMENT containing a brace, and a NESTED one. `matching_brace`
        // tracked block comments with a bool until a review pointed out that Rust
        // nests them and that its sibling `strip_comments` already counted depth.
        let blocks = concat!(
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    /* } */\n",
            "    /* outer /* inner } */ still outer } */\n",
            "    fn a() { let _ = \"DROP_ME\"; }\n",
            "}\n",
            "fn production_four() { let _ = \"KEEP_FOUR\"; }\n",
        );
        let region = production_region(blocks);
        assert!(
            !region.contains("DROP_ME"),
            "block comments ended the block early: {region}"
        );
        assert!(region.contains("KEEP_FOUR"), "tail dropped: {region}");

        // A CHAR LITERAL holding a brace.
        let chars = concat!(
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    const C: char = '}';\n",
            "    fn a() { let _ = \"DROP_ME\"; }\n",
            "}\n",
            "fn production_five() { let _ = \"KEEP_FIVE\"; }\n",
        );
        let region = production_region(chars);
        assert!(
            !region.contains("DROP_ME"),
            "a char literal ended the block early: {region}"
        );
        assert!(region.contains("KEEP_FIVE"), "tail dropped: {region}");

        // RAW STRINGS. A backslash inside one is not an escape, and the corpus
        // really contains `r#"..."#` fixtures -- config.rs holds several.
        let raws = concat!(
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    const A: &str = r\"trailing backslash \\\";\n",
            "    const B: &str = r#\"has \"quotes\" and a } brace\"#;\n",
            "    const C: &[u8] = br#\"quoted \" } byte raw\"#;\n",
            "    const D: &std::ffi::CStr = cr#\"quoted \" } C raw\"#;\n",
            "    fn a() { let _ = \"DROP_ME\"; }\n",
            "}\n",
            "fn production_six() { let _ = \"KEEP_SIX\"; }\n",
        );
        let region = production_region(raws);
        assert!(
            !region.contains("DROP_ME"),
            "a raw string desynced the scan: {region}"
        );
        assert!(region.contains("KEEP_SIX"), "tail dropped: {region}");

        // Line numbers must survive for EVERY fixture, not just the first --
        // asserting it once was flagged in review as covering less than it looked.
        for (name, fixture) in [
            ("shape_one", shape_one),
            ("shape_two", shape_two),
            ("tricky", tricky),
            ("blocks", blocks),
            ("chars", chars),
            ("raws", raws),
        ] {
            assert_eq!(
                production_region(fixture).matches('\n').count(),
                fixture.matches('\n').count(),
                "{name}: line count changed, so reported line numbers would be wrong"
            );
        }
    }

    #[test]
    fn the_comment_stripper_keeps_strings_and_drops_prose() {
        let src = concat!(
            "let a = \"keeps // this\";\n",
            "// drops {:#} this\n",
            "let b = \"keeps /* this */ too\";\n",
            "/* drops\n   {e:#} across lines */\n",
            "let c = '\"';\n",
            "let d = \"tail {x:#}\";\n",
        );
        let out = strip_comments(src);
        assert!(
            out.contains("keeps // this"),
            "string content was stripped: {out}"
        );
        assert!(
            out.contains("keeps /* this */ too"),
            "string content was stripped: {out}"
        );
        assert!(
            out.contains("tail {x:#}"),
            "a real hazard in a string was stripped: {out}"
        );
        assert!(
            !out.contains("drops {:#} this"),
            "line comment survived: {out}"
        );
        assert!(!out.contains("{e:#}"), "block comment survived: {out}");
        assert_eq!(
            out.matches('\n').count(),
            src.matches('\n').count(),
            "line count changed, so reported line numbers would be wrong"
        );
    }

    /// Exercise the same preprocessing and line predicate as the tree-wide guard.
    /// Both observations matter: a missing line makes the verdict vacuously safe.
    fn assert_production_render_is_guarded(source: &str) {
        let render = "format!(\"{e:#}\")";
        assert!(source.lines().any(|line| line.trim() == render));
        let preprocessed = strip_comments(&production_region(source));
        let retained = preprocessed.lines().any(|line| line.trim() == render);
        let flagged = preprocessed.lines().any(has_alternate_render);
        assert_eq!(
            (retained, flagged),
            (true, true),
            "production render must survive preprocessing and trigger the guard:\n{preprocessed}"
        );
    }

    #[test]
    fn out_of_line_cfg_test_module_does_not_hide_following_production_render() {
        let source = concat!(
            "#[cfg(test)]\n",
            "mod review_empty;\n",
            "fn review_render(e: &anyhow::Error) -> String {\n",
            "    format!(\"{e:#}\")\n",
            "}\n",
        );
        assert_production_render_is_guarded(source);
    }

    #[test]
    fn raw_string_comment_text_does_not_hide_following_production_render() {
        let source = concat!(
            "fn review_render(e: &anyhow::Error) -> String {\n",
            "    let _ = r#\"quoted \" /* ordinary raw-string contents\"#;\n",
            "    format!(\"{e:#}\")\n",
            "}\n",
        );
        assert_production_render_is_guarded(source);
    }

    #[test]
    fn raw_c_string_comment_text_does_not_hide_following_production_render() {
        let source = concat!(
            "fn review_render(e: &anyhow::Error) -> String {\n",
            "    let _ = cr#\"quoted \" /* ordinary C-string contents\"#;\n",
            "    format!(\"{e:#}\")\n",
            "}\n",
        );
        assert_production_render_is_guarded(source);
    }

    #[test]
    fn nested_block_comment_does_not_hide_following_production_render() {
        let source = concat!(
            "fn review_render(e: &anyhow::Error) -> String {\n",
            "    /* outer /* inner */ still comment \" */\n",
            "    let _ = \"/*\";\n",
            "    format!(\"{e:#}\")\n",
            "}\n",
        );
        assert_production_render_is_guarded(source);
    }

    #[test]
    fn byte_char_literals_do_not_hide_following_production_render() {
        for literal in ["b'\"'", "b'\\''"] {
            // The byte-prefix branch has its own contract: scanning from the
            // apostrophe can otherwise mask a broken scan from the prefix.
            assert_eq!(char_literal_end(literal, 0), Some(literal.len()));
            let source = format!(
                "fn review_render(e: &anyhow::Error) -> String {{\n    let _ = {literal};\n    let _ = \"/*\";\n    format!(\"{{e:#}}\")\n}}\n"
            );
            assert_production_render_is_guarded(&source);
        }
    }

    /// The PREDICATE, against synthetic strings rather than today's corpus.
    ///
    /// Without this, the only exercise the match gets is the real file, so the day
    /// the corpus stops containing a form is the day that form silently stops
    /// being tested. The negative cases matter as much as the positive ones: this
    /// predicate is a substring match and is much broader than the whole
    /// placeholders it replaced.
    #[test]
    fn the_alternate_render_predicate_matches_every_spelling_and_no_width_spec() {
        for caught in [
            "\"x: {:#}\", e",
            "\"x: {e:#}\"",
            "\"x: {0:#}\", e",
            "\"x: {name:#}\"",
            "\"x: {:?}\", e",
            "\"x: {e:?}\"",
            "\"x: {:#?}\", e",
            "\"x: {e:#?}\"",
        ] {
            assert!(
                alternate_or_debug_render(caught).is_some(),
                "not caught: {caught}"
            );
        }
        for allowed in [
            "\"plain {}\", e",
            "\"width {:>8}\", n",
            "\"precision {:.3}\", f",
            "\"named {name}\"",
            "\"hex {:#x}\", n",
            "%error, \"structured field\"",
        ] {
            assert!(
                alternate_or_debug_render(allowed).is_none(),
                "false positive: {allowed}"
            );
        }
    }

    /// The SCANNER itself, against a corpus built to contain what the real file
    /// does not.
    ///
    /// `warning_call_sites` had exactly one caller -- the guard above, passing the
    /// real `main.rs`. So every edge it handles was exercised only to the extent
    /// this one file happens to contain that edge, and the file is a poor corpus:
    /// it holds 26 `tracing::warn!` sites and just 2 `tracing::error!`, and it has
    /// no warning whose body contains a `)` inside a string, or a `'('` char
    /// literal, or a call opened mid-expression. The scanner's handling of each of
    /// those is written down and was never executed against a case that could
    /// distinguish it.
    ///
    /// A guard whose scanner is untested fails in the quiet direction: a dropped
    /// site is not reported as an error, it is simply never checked. The count
    /// cross-check in the guard above catches a drop only for the two patterns it
    /// naively counts, and cannot see a body that was truncated early.
    #[test]
    fn the_call_scanner_sees_every_form_the_corpus_contains() {
        // Assembled from pieces so this corpus is not itself a plausible target of
        // the guard above -- which cuts at the top-level test module anyway, but
        // relying on two things at once is how a fixture goes quietly vacuous.
        let corpus = concat!(
            "fn a() {\n",
            "    tracing::warn!(\"plain\");\n",
            "    if x { tracing::error!(\"not at line start\"); }\n",
            "    tracing::warn!(\n",
            "        \"the multi-line form rustfmt produces: {}\",\n",
            "        err\n",
            "    );\n",
            "    tracing::warn!(\"a close paren ) inside a string\");\n",
            "    tracing::error!(\"a char literal {} here\", '(');\n",
            "    tracing::warn!(\"nested {}\", f(g(1), h(2)));\n",
            "}\n",
        );

        let sites = warning_call_sites(corpus);

        // Assert the SETUP first: if the corpus stopped containing both macro
        // spellings, every assertion below would still pass while checking less.
        assert_eq!(
            corpus.matches("tracing::warn!").count(),
            4,
            "corpus no longer holds the warn! cases this test claims to cover"
        );
        assert_eq!(
            corpus.matches("tracing::error!").count(),
            2,
            "corpus no longer holds the error! cases this test claims to cover"
        );

        assert_eq!(
            sites.len(),
            6,
            "scanner found {} of 6 sites: {sites:?}",
            sites.len()
        );
        for (line_no, body) in &sites {
            assert_ne!(body, "<UNPARSEABLE>", "line {line_no} was not delimited");
        }

        let bodies: Vec<&str> = sites.iter().map(|(_, b)| b.as_str()).collect();

        // `error!` is found at all -- the branch the real file barely exercises.
        assert!(bodies.iter().any(|b| b.contains("not at line start")));
        // A call that does not begin its line is still found, at the right line.
        // Looked up by CONTENT, not by index: the scanner walks one macro spelling
        // to exhaustion before starting the next, so the returned order is
        // pattern-major, not line order. Indexing positionally here would pin that
        // ordering as if it were a promise.
        let mid_line = sites
            .iter()
            .find(|(_, b)| b.contains("not at line start"))
            .expect("the mid-line call was not found at all");
        assert_eq!(mid_line.0, 3, "line number wrong for the mid-line call");
        // The multi-line form is joined into one normalised body.
        assert!(
            bodies.contains(&"\"the multi-line form rustfmt produces: {}\", err"),
            "multi-line body not normalised: {bodies:?}"
        );
        // A `)` inside a string does not end the body early.
        assert!(
            bodies.contains(&"\"a close paren ) inside a string\""),
            "string-internal close paren truncated the body: {bodies:?}"
        );
        // A `'('` char literal does not inflate the depth.
        assert!(
            bodies
                .iter()
                .any(|b| b.contains("a char literal") && b.ends_with("'('")),
            "char literal mis-consumed: {bodies:?}"
        );
        // Nested calls are spanned whole.
        assert!(
            bodies.contains(&"\"nested {}\", f(g(1), h(2))"),
            "nested parens truncated the body: {bodies:?}"
        );
    }

    /// The rejected design must not come back, and partial wiring must not pass.
    ///
    /// A non-author review demonstrated both gaps by mutation: routing only ONE
    /// of the seven warnings through `error_for_log` still passed the
    /// integration test, and replacing all seven with the rejected `{:#}` passed
    /// every test in this file too. The runtime tests cannot see the difference,
    /// because in the fault they install the safe and unsafe renderings happen
    /// to agree. This one looks at the wiring directly.
    ///
    /// It reads this file at compile time, so it holds on every platform and
    /// under root, where the integration test cannot install its fault.
    #[test]
    fn every_warning_is_routed_or_allowlisted() {
        let src = include_str!("main.rs");
        // Exclude this test module: its own source quotes the very literals and
        // macro names being scanned for, and counting those would let the guard
        // satisfy itself.
        // Find the TOP-LEVEL test module, line-ending agnostically. Two traps here,
        // and CI caught the second on Windows after local runs were all green:
        //   * there is an INDENTED `#[cfg(test)]` earlier in this file, so a plain
        //     `find` cuts in the wrong place and hides most of the corpus;
        //   * matching "\n#[cfg(test)]\n" assumes LF. Git for Windows checks out
        //     CRLF by default and this repo has no .gitattributes, so that marker
        //     is absent there and the guard panicked instead of running.
        // Requiring the match to be preceded by '\n' satisfies both: it holds
        // under CRLF too, and an indented occurrence is preceded by a space.
        let cut = src
            .match_indices("#[cfg(test)]")
            .find(|(i, _)| *i == 0 || src.as_bytes()[i - 1] == b'\n')
            .map(|(i, _)| i)
            .expect("top-level test module marker");
        let src = &src[..cut];

        // ── What this guard DOES and DOES NOT cover ─────────────────────────
        // It covers THIS FILE and fully-qualified `tracing::` macros, and nothing
        // else. Other modules log too -- session.rs and the collectors among them
        // -- and are NOT examined here; `remote_connections.rs` even imports the
        // macros unqualified already. Stating the boundary because the previous
        // revision's "every site" was read as tree-wide when it never was.
        for bad in [
            "use tracing::warn",
            "use tracing::error",
            "use tracing::{",
            "use tracing::*",
            "use tracing as ",
            "#[macro_use]",
        ] {
            assert!(
                !src.contains(bad),
                "`{bad}` in main.rs makes an unqualified `warn!`/`error!` possible, \
                 which this guard cannot see. Teach the scan that form BEFORE \
                 landing the import."
            );
        }

        // ── Enumerate EVERY call site, wherever it sits on its line ──────────
        // The previous revision keyed on `line.starts_with(..)`, so any call not
        // beginning its line was unguarded -- measured: 2 of 23 real sites, and a
        // leak in the multi-line form rustfmt produces passed the whole suite.
        let sites = warning_call_sites(src);

        // A NAIVE count cannot fail the way a balanced scan can, so disagreement
        // between them means the scan dropped a site. This replaces a magic
        // minimum, which left silent headroom: a dropped site kept the total
        // inside the floor and the loops below simply never saw it.
        let raw = src.matches("tracing::warn!").count() + src.matches("tracing::error!").count();
        assert_eq!(
            sites.len(),
            raw,
            "the call scanner delimited {} of {} occurrences; a site it cannot \
             delimit must never be silently skipped",
            sites.len(),
            raw
        );
        for (line_no, body) in &sites {
            assert_ne!(
                body, "<UNPARSEABLE>",
                "line {line_no}: the scanner could not delimit this call, so it \
                 was not checked. Fix the scanner rather than the call."
            );
        }

        // ── Each site must be accounted for, by ROUTING or by an exact entry ─
        // Inverted from the previous revision, which enumerated seven GOOD sites
        // and could not see an eighth. Entries are matched with `starts_with` on
        // the NORMALISED CALL BODY, not `contains` on a fragment: a generic
        // fragment like "docs failed" auto-exempts any future message containing
        // those words, which is an auto-accept surface rather than an allowlist.
        const RENDERS_NO_ERROR: [&str; 7] = [
            "\"{} Elasticsearch delivery failing since {}",
            "\"{} Elasticsearch delivery recovered after {}",
            "\"{} startup preflight failed",
            "\"User-specified target not found",
            "\"remote_connections tailer disabled: direct",
            "failed = result.failed, \"remote_connections bulk batch retained",
            "\"Tick {}: {}/{} docs failed\"",
        ];
        // These DO render an error and are deliberately not routed through the
        // safe renderer.
        //
        // THIS IS A WAIVER LIST, NOT A PROOF, and the name says so because the
        // previous revision called it STATIC_OUTERMOST_CONTEXT and asserted that
        // every entry's outermost layer was a static literal. A non-author review
        // falsified that for EVERY entry in the list below, by two distinct routes.
        // (The phrase used to say "all seven". The list was seven entries when that
        // was written and is eight now, so the number is deliberately gone rather
        // than bumped: a count restated in prose beside a compiler-checked array
        // goes stale silently, and this one did.)
        //
        // ROUTE ONE IS NOW CLOSED: `shipper::ping`, `ship_documents` and
        // `trigger_transform_sync` each called `build_client(config)?` with a bare
        // `?`, so a CA-cert read failure made
        // `format!("reading Elasticsearch CA cert: {}", path.display())` the
        // outermost layer. `build_client` now wraps its own body in a static
        // context, so that path no longer surfaces at a `{}` render. It is still
        // present in the DEEPER layers, so `{:#}` or `{:?}` would reach it.
        //
        // ROUTE TWO REMAINS OPEN: the remote_connections entries resolve into
        // path-interpolating contexts of their own (many `with_context(|| format!
        // ("... {}", path.display()))` sites in that file), and closing route one
        // did nothing for them.
        //
        // Nothing here checks a row. A row that claims more than it can show turns
        // a live leak into a documented exemption, which is worse than no row --
        // so the claim is now only that a human looked and waived it, and the
        // outermost-context question is tracked as its own commitment.
        const WAIVED_RENDERS_AN_ERROR: [&str; 8] = [
            "\"Elasticsearch startup preflight error: {}\", e",
            "%error, \"remote_connections tailer disabled during startup\"",
            "\"transform schedule_now failed (non-fatal): {}\", e",
            "%error, \"remote_connections checkpoint acknowledgement failed\"",
            "%error, \"remote_connections bulk transport error",
            "%error, \"remote_connections tail error\"",
            "\"{} error: {}\", dataset, e",
            "\"Tick {} bulk error: {}\", tick_num, e",
        ];

        let mut unclassified = Vec::new();
        for (line_no, body) in &sites {
            let routed = body.contains("error_for_log(");
            let listed = RENDERS_NO_ERROR
                .iter()
                .chain(WAIVED_RENDERS_AN_ERROR.iter())
                .any(|m| body.starts_with(m));
            if !routed && !listed {
                unclassified.push(format!("line {line_no}: {body}"));
            }
        }
        assert!(
            unclassified.is_empty(),
            "warning site(s) render through neither the safe renderer nor a \
             declared entry. Route through `error_for_log`, or add the call's \
             exact leading text to one of the tables above WITH its reason:\n{}",
            unclassified.join("\n")
        );

        // ── No alternate error formatting, at ANY position ───────────────────
        // The alternate render prints every cause verbatim. So does the debug
        // render, which ALSO spans lines -- it is simultaneously the credential
        // leak and the forged second line that
        // `error_for_log_never_emits_a_forged_second_line` exists to prevent. An
        // earlier revision blocked only the alternate one, while the comment at the
        // preflight site named debug as equally harmful; a guard must not be
        // narrower than the hazard its own neighbours describe.
        //
        // MATCH THE CLOSING FORM, NOT THE WHOLE PLACEHOLDER. Rust's inline capture
        // writes the argument inside the braces -- `{e:#}`, not `{:#}` -- so the
        // earlier list of whole placeholders could not see it. Measured: appending
        // `{e:#}` to a site whose allowlist entry matches by PREFIX left this guard
        // GREEN. The runtime integration test did catch that particular case, but
        // this guard exists for the faults the runtime tests cannot see, so being
        // covered there is luck rather than design. `{e:#}` is also the exact form
        // that reached a live surface in `diagnose`.
        //
        // The three closing forms are listed separately because none contains
        // another as a substring.
        for (line_no, body) in &sites {
            if let Some(spec) = alternate_or_debug_render(body) {
                panic!(
                    "line {line_no} uses an alternate/debug render ending `{spec}`, \
                     which prints every cause verbatim. This matches the inline \
                     capture form (`{{e:#}}`) as well as the bare one (`{{:#}}`): \
                     {body}"
                );
            }
        }

        // ── The seven spool warnings specifically must stay routed ───────────
        // The message is pinned together with its format spec, `{message}{}"`,
        // restoring a property the previous rewrite dropped: matching the message
        // alone let a spool site keep the renderer AND gain a second, raw
        // argument, and let its own spec change from `{}` to something else.
        // Measured: three mutants the older guard caught passed the rewrite.
        const SPOOL_WARNINGS: [&str; 7] = [
            "Failed to ship session-start doc: ",
            "Failed to ship game-detected doc: ",
            "Failed to ship summary doc on game exit: ",
            "Tick {} spool error: ",
            "Tick {} spool rotation error: ",
            "Failed to ship summary doc: ",
            "Failed to finalize spool files during shutdown: ",
        ];
        for message in SPOOL_WARNINGS {
            let pinned = format!("{message}{{}}\"");
            let site = sites
                .iter()
                .find(|(_, body)| body.contains(&pinned))
                .unwrap_or_else(|| {
                    panic!(
                        "spool warning missing, or its format spec is no longer `{{}}`: {message}"
                    )
                });
            assert!(
                site.1.contains("error_for_log(&e)"),
                "`{message}` does not render through the safe renderer: {}",
                site.1
            );
        }
    }

    /// Every `tracing::warn!`/`error!` call in `src`, as `(line number, body)`.
    ///
    /// Position-independent, so a call that does not begin its line is still
    /// found, and string-aware, because one message contains a parenthesis
    /// (`"transform schedule_now failed (non-fatal)"`) that terminates a naive
    /// paren count early.
    ///
    /// A call it cannot delimit yields the body `<UNPARSEABLE>` rather than being
    /// skipped. That distinction is the whole safety property: a silent skip is
    /// fail-OPEN, and a `'('` char literal was measured doing exactly that --
    /// inflating the depth, running to EOF, and dropping the site while the total
    /// stayed inside a minimum-count floor.
    /// The alternate or debug render specs, matched by their CLOSING form so the
    /// inline-capture spelling is covered. Returns the spec that matched.
    ///
    /// WHAT THIS DOES NOT CATCH, stated because a guard that hides its edges
    /// invites someone to trust it past them: a fill or align character before the
    /// flag (`{e:>#}`) defeats it, as it defeated the whole-placeholder list this
    /// replaced. That form appears nowhere in the corpus and closing it needs a
    /// real parse of the format spec rather than a substring, so it is recorded
    /// rather than half-handled. Tracing's `?field` Debug shorthand is a different
    /// mechanism again and is not a format spec at all; there are no such sites in
    /// what this guard covers.
    fn alternate_or_debug_render(body: &str) -> Option<&'static str> {
        [":#}", ":?}", ":#?}"]
            .into_iter()
            .find(|spec| body.contains(spec))
    }

    fn warning_call_sites(src: &str) -> Vec<(usize, String)> {
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        for pat in ["tracing::warn!", "tracing::error!"] {
            let mut from = 0;
            while let Some(rel) = src[from..].find(pat) {
                let at = from + rel;
                from = at + pat.len();
                let line_no = src[..at].matches('\n').count() + 1;
                let Some(open) = src[at..].find('(').map(|o| at + o) else {
                    out.push((line_no, "<UNPARSEABLE>".to_string()));
                    continue;
                };
                let mut depth = 0usize;
                let mut in_str = false;
                let mut escaped = false;
                let mut end = None;
                let mut k = open;
                while k < bytes.len() {
                    let c = bytes[k] as char;
                    if in_str {
                        if escaped {
                            escaped = false;
                        } else if c == '\\' {
                            escaped = true;
                        } else if c == '"' {
                            in_str = false;
                        }
                        k += 1;
                        continue;
                    }
                    // A char literal of the form 'X' -- skip it whole, so `'('`
                    // cannot inflate the depth. Deliberately narrow: it matches
                    // only the three-byte form, so a lifetime (`&'a T`) is left
                    // alone rather than mis-consumed.
                    if c == '\'' && k + 2 < bytes.len() && bytes[k + 2] == b'\'' {
                        k += 3;
                        continue;
                    }
                    match c {
                        '"' => in_str = true,
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(k);
                                break;
                            }
                        }
                        _ => {}
                    }
                    k += 1;
                }
                match end {
                    Some(end) => {
                        let body: String = src[open + 1..end]
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ");
                        out.push((line_no, body));
                    }
                    None => out.push((line_no, "<UNPARSEABLE>".to_string())),
                }
            }
        }
        out
    }

    /// The whole point: on a full disk the errno must reach the log.
    ///
    /// This models the real shape — `SpoolWriter::write_docs` wraps its
    /// `io::Error` with `.context("flushing spool writer")` — and asserts the
    /// message an operator would actually see.
    #[cfg(unix)]
    #[test]
    fn error_for_log_surfaces_the_os_error() {
        let err = anyhow::Error::new(std::io::Error::from_raw_os_error(libc::ENOSPC))
            .context("flushing spool writer");

        let rendered = error_for_log(&err);

        assert_eq!(
            rendered,
            "flushing spool writer: No space left on device (os error 28)"
        );
        // The plain form, which is what these call sites used to print, does not.
        assert_eq!(format!("{err}"), "flushing spool writer");
    }

    /// With no OS error anywhere in the chain the output must be byte-identical
    /// to the previous behaviour. Nothing that used to be logged stops being
    /// logged.
    #[test]
    fn error_for_log_is_unchanged_without_an_os_error() {
        let err = anyhow::anyhow!("serialising spool doc").context("writing spool doc");
        assert_eq!(error_for_log(&err), format!("{err}"));
        assert_eq!(error_for_log(&err), "writing spool doc");
    }

    /// NEGATIVE CONTROL 1 — a URL, including a URL-borne credential, must never
    /// reach the log.
    ///
    /// Four of the seven call sites also serve direct Elasticsearch delivery,
    /// where a request failure is wrapped in the static context `sending bulk
    /// request` over a `reqwest::Error` whose `Display` carries the URL. A
    /// non-author review reproduced that exposure under `{:#}`. The errno must
    /// still arrive; the URL must not.
    #[cfg(unix)]
    #[test]
    fn error_for_log_never_logs_a_url_or_its_credential() {
        let err = anyhow::Error::new(std::io::Error::from_raw_os_error(libc::ECONNREFUSED))
            .context("http://127.0.0.1:9/tenant-canary?api_key=URL_CANARY/_bulk")
            .context("sending bulk request");

        let rendered = error_for_log(&err);

        assert!(
            rendered.contains("Connection refused (os error 111)"),
            "the errno must still be reported: {rendered}"
        );
        assert!(
            !rendered.contains("URL_CANARY"),
            "credential leaked: {rendered}"
        );
        assert!(
            !rendered.contains("tenant-canary"),
            "tenant path leaked: {rendered}"
        );
        assert!(!rendered.contains("http://"), "URL leaked: {rendered}");
    }

    /// NEGATIVE CONTROL 2 — a filesystem path carried by a cause must never
    /// reach the log. Reproduced by the same review against the real spool
    /// writer: `opening spool file for padding: <path>: Permission denied`.
    #[cfg(unix)]
    #[test]
    fn error_for_log_never_logs_a_path_from_a_cause() {
        let err = anyhow::Error::new(std::io::Error::from_raw_os_error(libc::EACCES))
            .context("opening spool file for padding: /home/PATH_CANARY/spool/x.ndjson.tmp")
            .context("padding spool file before publication");

        let rendered = error_for_log(&err);

        assert!(
            rendered.contains("Permission denied (os error 13)"),
            "the errno must still be reported: {rendered}"
        );
        assert!(!rendered.contains("PATH_CANARY"), "path leaked: {rendered}");
    }

    /// NEGATIVE CONTROL 3 — a newline in a cause must never split one log event
    /// into two.
    ///
    /// `anyhow` does not escape cause text and the installed tracing sanitizer
    /// leaves newlines alone, so under `{:#}` the review planted a second line
    /// carrying its own marker. A log line an error's content can forge is worse
    /// than one that omits the errno.
    #[cfg(unix)]
    #[test]
    fn error_for_log_never_emits_a_forged_second_line() {
        let err = anyhow::Error::new(std::io::Error::from_raw_os_error(libc::ENOSPC))
            .context("opening spool file\nWARN rigsignal_agent: FORGED_CANARY")
            .context("flushing spool writer");

        let rendered = error_for_log(&err);

        assert!(!rendered.contains('\n'), "output spans lines: {rendered:?}");
        assert!(
            !rendered.contains("FORGED_CANARY"),
            "forged line leaked: {rendered}"
        );
        assert_eq!(
            rendered,
            "flushing spool writer: No space left on device (os error 28)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn error_for_log_escapes_a_forged_line_in_the_outer_spool_path() {
        let err = anyhow::Error::new(std::io::Error::from_raw_os_error(libc::EACCES))
            .context("opening active spool file: /tmp/spool\nWARN rigsignal: FORGED.ndjson");
        let rendered = error_for_log(&err);
        assert!(!rendered.contains('\n'), "{rendered:?}");
        assert!(rendered.contains("spool\\nWARN rigsignal: FORGED.ndjson"));
        assert!(rendered.contains("Permission denied (os error 13)"));
    }

    /// An OS error nested deeper than the first cause is still found: the helper
    /// walks the whole chain, it does not look only one level down.
    #[cfg(unix)]
    #[test]
    fn error_for_log_finds_an_os_error_deep_in_the_chain() {
        let err = anyhow::Error::new(std::io::Error::from_raw_os_error(libc::ENOSPC))
            .context("writing spool doc")
            .context("dataset rigsignal.cpu")
            .context("flushing spool writer");

        assert_eq!(
            error_for_log(&err),
            "flushing spool writer: No space left on device (os error 28)"
        );
    }

    /// An `io::Error` that did NOT come from the OS carries caller-supplied text,
    /// so it must be treated as free text and omitted, not printed.
    #[test]
    fn error_for_log_ignores_a_non_os_io_error() {
        let inner = std::io::Error::other("INNER_CANARY should not be logged");
        assert!(inner.raw_os_error().is_none());
        let err = anyhow::Error::new(inner).context("flushing spool writer");

        let rendered = error_for_log(&err);

        assert_eq!(rendered, "flushing spool writer");
        assert!(
            !rendered.contains("INNER_CANARY"),
            "free text leaked: {rendered}"
        );
    }

    #[test]
    fn handshake_clap_surface_is_subcommand_scoped() {
        let cli = Cli::try_parse_from([
            "rigsignal-agent",
            "handshake",
            "check",
            "--endpoint",
            "https://example.test/",
            "--ca-file",
            "ca.pem",
            "--expected-cluster-uuid",
            "KUrXRgwRRQu-RikmIJhm0Q",
            "--target-generation",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--credentials-file",
            "creds.toml",
            "--config",
            "handshake.toml",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Commands::Handshake { .. })));
        assert!(
            Cli::try_parse_from(["rigsignal-agent", "handshake", "check", "--dry-run"]).is_err()
        );
        assert!(Cli::try_parse_from([
            "rigsignal-agent",
            "handshake",
            "check",
            "--telemetry-endpoint",
            "x"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "rigsignal-agent",
            "handshake",
            "check",
            "--config",
            "x",
            "--pending-enrollment"
        ])
        .is_ok());
    }

    #[test]
    fn handshake_runtime_guard_rejects_root_flag_before_subcommand() {
        let cli =
            Cli::try_parse_from(["rigsignal-agent", "--dry-run", "handshake", "check"]).unwrap();
        assert_eq!(
            handshake_root_telemetry_guard(&cli).unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        assert!(matches!(cli.command, Some(Commands::Handshake { .. })));
    }

    #[test]
    fn test_log_level_from_cli() {
        // --log-level wins over everything
        assert_eq!(resolve_log_filter(false, Some("warn")), "warn");
        assert_eq!(resolve_log_filter(true, Some("warn")), "warn");
        assert_eq!(resolve_log_filter(true, Some("trace")), "trace");

        // --verbose produces "debug" when no --log-level
        assert_eq!(resolve_log_filter(true, None), "debug");

        // Neither flag → falls back to RIGSIGNAL_LOG or "info"
        // Remove the env var so the test is deterministic.
        std::env::remove_var("RIGSIGNAL_LOG");
        assert_eq!(resolve_log_filter(false, None), "info");

        // RIGSIGNAL_LOG is honoured when no CLI flags
        std::env::set_var("RIGSIGNAL_LOG", "error");
        assert_eq!(resolve_log_filter(false, None), "error");
        std::env::remove_var("RIGSIGNAL_LOG");
    }

    #[test]
    fn summary_total_frames_reports_sparse_fps_coverage() {
        let mut acc = SessionAccumulators::new();
        acc.fps_samples = vec![60.0, 30.0, 45.0];

        let summary = build_summary_doc(
            &session::SessionManager::new(),
            &json!({}),
            "test-host",
            10,
            &acc,
            None,
        );
        let summary = &summary["rigsignal"]["summary"];

        assert_eq!(summary["total_frames"], 135);
        assert_eq!(summary["fps_coverage_s"], 3);
    }

    #[test]
    fn summary_fps_coverage_matches_duration_with_full_coverage() {
        let mut acc = SessionAccumulators::new();
        acc.fps_samples = vec![60.0, 60.0, 60.0];

        let summary = build_summary_doc(
            &session::SessionManager::new(),
            &json!({}),
            "test-host",
            3,
            &acc,
            None,
        );
        let summary = &summary["rigsignal"]["summary"];

        assert_eq!(summary["fps_coverage_s"], summary["duration_s"]);
    }

    #[test]
    fn metrics_and_session_documents_normalize_host_name() {
        let session = session::SessionManager::new();
        let hostname = "GamingPC";

        let metric = session.base_doc(hostname);
        let stream_client = session.stream_client_base_doc(hostname);
        let start = build_session_start_doc(&session, &json!({}), hostname);
        let end = build_summary_doc(
            &session,
            &json!({}),
            hostname,
            0,
            &SessionAccumulators::new(),
            None,
        );

        for doc in [metric, stream_client, start, end] {
            assert_eq!(doc["host"]["name"], "gamingpc");
        }
    }
}
