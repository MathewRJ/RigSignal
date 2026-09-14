/// `rigsignal-agent diagnose` — single-file bug-report dump.
///
/// Collects: kernel version, GPU driver, Elasticsearch reachability, and a log
/// of every probe step taken during this run. Output goes to stdout (default)
/// or to a file via `--output`.
use crate::{config::Config, host, shipper};
use anyhow::{Context, Result};
use std::{fmt::Write as FmtWrite, path::Path};

/// Run the diagnostic probe sequence and emit a plain-text report.
///
/// `config_path` is the path that was passed to `Config::load()` — shown in
/// the report so the user knows which file was resolved.
pub async fn run(cfg: &Config, config_path: Option<&Path>, output: Option<&Path>) -> Result<()> {
    let mut log: Vec<String> = Vec::new();
    let mut report = String::new();

    macro_rules! note {
        ($($arg:tt)*) => {{
            let msg = format!($($arg)*);
            tracing::info!("{}", msg);
            log.push(msg);
        }};
    }

    // ── Header ────────────────────────────────────────────────────────────────

    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    writeln!(report, "=== RigSignal Diagnostic Report ===")?;
    writeln!(report, "Generated:  {ts}")?;
    writeln!(report, "Version:    {}", env!("CARGO_PKG_VERSION"))?;
    writeln!(report)?;

    // ── System ────────────────────────────────────────────────────────────────

    note!("collecting host snapshot");
    let snapshot = host::collect_snapshot();

    let get = |path: &[&str]| -> Option<String> {
        let mut cur = &snapshot;
        for &key in path {
            cur = cur.get(key)?;
        }
        cur.as_str().map(|s| s.to_string())
    };
    let get_i64 = |path: &[&str]| -> Option<i64> {
        let mut cur = &snapshot;
        for &key in path {
            cur = cur.get(key)?;
        }
        cur.as_i64()
    };

    let kernel = get(&["host", "os", "kernel"]).unwrap_or_else(|| "unknown".into());
    let os_name = get(&["host", "os", "name"]).unwrap_or_else(|| "unknown".into());
    let os_version = get(&["host", "os", "version"]).unwrap_or_else(|| "".into());
    let hostname = host::hostname();
    note!("kernel {kernel}, OS {os_name} {os_version}");

    let cpu_model = get(&["rigsignal", "hardware", "cpu", "model"]);
    let cpu_cores = get_i64(&["rigsignal", "hardware", "cpu", "cores"]);
    let cpu_threads = get_i64(&["rigsignal", "hardware", "cpu", "threads"]);
    let cpu_boost = get_i64(&["rigsignal", "hardware", "cpu", "boost_clock_mhz"]);
    let ram_total = get_i64(&["rigsignal", "hardware", "ram", "total_mb"]);
    let device_type = get(&["rigsignal", "hardware", "device", "type"]);

    writeln!(report, "System")?;
    writeln!(report, "  Hostname:   {hostname}")?;
    writeln!(report, "  Kernel:     {kernel}")?;
    let os_str = if os_version.is_empty() {
        os_name.clone()
    } else {
        format!("{os_name} {os_version}")
    };
    writeln!(report, "  OS:         {os_str}")?;
    if let Some(dt) = device_type {
        writeln!(report, "  Device:     {dt}")?;
    }
    if let Some(model) = &cpu_model {
        let detail = match (cpu_cores, cpu_threads, cpu_boost) {
            (Some(c), Some(t), Some(b)) => format!("  — {c}c/{t}t  {b} MHz boost"),
            (Some(c), Some(t), None) => format!("  — {c}c/{t}t"),
            _ => String::new(),
        };
        writeln!(report, "  CPU:        {model}{detail}")?;
    }
    if let Some(ram) = ram_total {
        writeln!(report, "  RAM:        {} GiB", ram / 1024)?;
    }
    writeln!(report)?;

    // ── GPU ───────────────────────────────────────────────────────────────────

    let gpu_vendor = get(&["rigsignal", "hardware", "gpu", "vendor"]);
    let gpu_model = get(&["rigsignal", "hardware", "gpu", "model"]);
    let gpu_vram = get_i64(&["rigsignal", "hardware", "gpu", "vram_mb"]);
    let gpu_driver = get(&["rigsignal", "hardware", "gpu", "driver_version"]);
    let gpu_mesa = get(&["rigsignal", "hardware", "gpu", "mesa_version"]);
    let gpu_vulkan = get(&["rigsignal", "hardware", "gpu", "vulkan_driver"]);

    if gpu_vendor.is_some() || gpu_model.is_some() {
        note!(
            "GPU: {} {} driver {}",
            gpu_vendor.as_deref().unwrap_or("unknown"),
            gpu_model.as_deref().unwrap_or(""),
            gpu_driver.as_deref().unwrap_or("n/a"),
        );
        writeln!(report, "GPU")?;
        if let Some(v) = &gpu_vendor {
            writeln!(report, "  Vendor:     {v}")?;
        }
        if let Some(m) = &gpu_model {
            writeln!(report, "  Model:      {m}")?;
        }
        if let Some(vram) = gpu_vram {
            writeln!(report, "  VRAM:       {vram} MiB")?;
        }
        if let Some(drv) = &gpu_driver {
            writeln!(report, "  Driver:     {drv}")?;
        }
        if let Some(mesa) = &gpu_mesa {
            writeln!(report, "  Mesa:       {mesa}")?;
        }
        if let Some(vk) = &gpu_vulkan {
            writeln!(report, "  Vulkan:     {vk}")?;
        }
        writeln!(report)?;
    } else {
        note!("GPU info not detected (no AMD/NVIDIA/Intel DRM card found in /sys/class/drm)");
    }

    // ── Elasticsearch ─────────────────────────────────────────────────────────

    // `note!` is tracing::info! plus a report push, so this reaches the JOURNAL as
    // well as the report. It is the same surface the startup preflight was fixed
    // for, not a milder operator-only one.
    note!("pinging Elasticsearch at {}", cfg.endpoint_for_display());
    let es_status = match shipper::ping(cfg).await {
        Ok(()) => {
            note!("ES ping OK");
            "REACHABLE".to_string()
        }
        Err(e) => {
            // NOT `{e:#}`. The alternate form renders the whole anyhow chain, and
            // one of its middle layers is reqwest's own error, which embeds the
            // FULL REQUEST URL -- query parameters included. Measured with a
            // canary endpoint: `{e:#}` put `?api_key=<canary>` into both the
            // report and the journal, even though the outermost context is static.
            //
            // The outermost layer is static and the DEEPEST layer is the cause the
            // operator actually needs ("Connection refused", "certificate
            // verify failed"); it is the layers in between that carry the request.
            // So render those two and drop the middle.
            let reason = ping_failure_reason(&e);
            let msg = format!("ES ping failed: {reason}");
            note!("{msg}");
            format!("UNREACHABLE — {reason}")
        }
    };

    let auth_kind = match (
        cfg.elasticsearch.api_key.is_some(),
        cfg.elasticsearch.username.is_some(),
    ) {
        (true, _) => "api_key",
        (_, true) => "basic auth",
        _ => "none",
    };

    writeln!(report, "Elasticsearch")?;
    writeln!(report, "  Endpoint:   {}", cfg.endpoint_for_display())?;
    writeln!(report, "  Status:     {es_status}")?;
    writeln!(report, "  Auth:       {auth_kind}")?;
    writeln!(report)?;

    // ── Config ────────────────────────────────────────────────────────────────

    writeln!(report, "Config")?;
    let cfg_display = cfg.redacted_for_display();
    let config_file_str = config_path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| {
            // Reproduce the same default-search logic as Config::load.
            let home_candidate = dirs_next_home()
                .map(|h| h.join(".config/rigsignal/rigsignal.toml"))
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "~/.config/rigsignal/rigsignal.toml".into());
            home_candidate
        });
    writeln!(report, "  File:       {config_file_str}")?;
    writeln!(
        report,
        "  ES endpoint: {}",
        cfg_display.elasticsearch.endpoint
    )?;
    if let Some(k) = &cfg_display.elasticsearch.api_key {
        writeln!(report, "  api_key:    {k}")?;
    }
    writeln!(report)?;

    // ── Diagnostic log ───────────────────────────────────────────────────────

    writeln!(report, "Diagnostic Log")?;
    let tail: Vec<&String> = log
        .iter()
        .rev()
        .take(20)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    for line in tail {
        writeln!(report, "  {line}")?;
    }

    // ── Emit ──────────────────────────────────────────────────────────────────

    if let Some(path) = output {
        std::fs::write(path, &report)
            .with_context(|| format!("writing diagnostic report to {}", path.display()))?;
        eprintln!("diagnostic report written to {}", path.display());
    } else {
        print!("{report}");
    }

    Ok(())
}

/// Mirrors `home_dir()` used by `config.rs` without an extra dep.
fn dirs_next_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

/// Render an ES ping failure as `<outermost>: <root cause>`, skipping the middle
/// of the chain.
///
/// The middle layers are where the request detail lives -- reqwest's error
/// Displays the full URL it was given, query string and all -- while the two ends
/// are the parts an operator reads: what we were doing, and why it failed.
///
/// This is a REDUCTION, not a scrub: nothing is pattern-matched out of a string.
/// If a future error type puts a URL in its ROOT cause, this would not stop it, so
/// the regression test drives a real credential-bearing endpoint end to end rather
/// than asserting on this function alone.
fn ping_failure_reason(error: &anyhow::Error) -> String {
    let outermost = error.to_string();
    match error.chain().skip(1).last() {
        Some(root) => {
            let root = root.to_string();
            if root == outermost {
                outermost
            } else {
                format!("{outermost}: {root}")
            }
        }
        None => outermost,
    }
}
