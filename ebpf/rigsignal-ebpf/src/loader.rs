/// Probe loader — capability checks, BTF check, probe initialisation.
///
/// At startup:
///   1. Checks CAP_BPF / CAP_PERFMON (exits hard if missing)
///   2. Verifies /sys/kernel/btf/vmlinux (CO-RE required)
///   3. Loads the BPF ELF from disk (Ebpf::load_file)
///   4. Iterates probes: checks requirements, calls attach()
///   5. Returns the active probe list and the Ebpf handle
use anyhow::{bail, Context, Result};
use aya::Ebpf;
use tracing::{info, warn};

use crate::probes::{check_requirements, Probe};

/// Result of probe loading — active probes plus statistics.
pub struct LoadedProbes {
    pub ebpf: Ebpf,
    pub probes: Vec<Box<dyn Probe>>,
    pub loaded_count: usize,
    pub skipped_count: usize,
}

/// Load the BPF object and attach all enabled probes.
///
/// `probe_path` — path to the compiled rigsignal-ebpf-probes ELF.
/// `probes`     — candidate probes to attempt (ordered by priority).
pub fn load_probes(
    probe_path: &std::path::Path,
    mut candidates: Vec<Box<dyn Probe>>,
) -> Result<LoadedProbes> {
    check_capabilities()?;
    check_btf()?;

    info!("loading BPF object from {}", probe_path.display());
    let mut ebpf = Ebpf::load_file(probe_path)
        .with_context(|| format!("loading BPF ELF: {}", probe_path.display()))?;

    // Optional: set up aya's kernel log draining to tracing
    #[cfg(debug_assertions)]
    {
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            warn!("could not initialise eBPF logger: {e}");
        }
    }

    let mut active: Vec<Box<dyn Probe>> = Vec::new();
    let mut skipped = 0usize;

    for mut probe in candidates.drain(..) {
        let reqs = probe.requirements();
        match check_requirements(&reqs) {
            Err(e) => {
                warn!("skipping probe '{}': {}", probe.name(), e);
                skipped += 1;
                continue;
            }
            Ok(()) => {}
        }

        match probe.attach(&mut ebpf) {
            Ok(()) => {
                info!("loaded probe '{}'", probe.name());
                active.push(probe);
            }
            Err(e) => {
                // {e:#} prints the full anyhow error chain (cause by cause).
                warn!("failed to attach probe '{}': {e:#}", probe.name());
                skipped += 1;
            }
        }
    }

    let loaded = active.len();
    info!("probes: {}/{} loaded", loaded, loaded + skipped);

    Ok(LoadedProbes {
        ebpf,
        probes: active,
        loaded_count: loaded,
        skipped_count: skipped,
    })
}

/// Verify the process has BPF-related capabilities.
/// Reads CapEff from /proc/self/status and checks CAP_BPF (bit 39) and
/// CAP_PERFMON (bit 38). Skips the check when running as root.
fn check_capabilities() -> Result<()> {
    use nix::unistd::Uid;

    if Uid::effective().is_root() {
        return Ok(());
    }

    // Read effective capability bitmask from /proc/self/status
    let cap_eff = read_cap_eff().unwrap_or(0);
    let has_cap_bpf = (cap_eff >> 39) & 1 == 1;
    let has_cap_perfmon = (cap_eff >> 38) & 1 == 1;

    if !has_cap_bpf || !has_cap_perfmon {
        bail!(
            "insufficient capabilities for BPF (need CAP_BPF + CAP_PERFMON).\n  \
             Run as root, or grant capabilities:\n  \
             sudo setcap 'cap_bpf,cap_perfmon,cap_sys_admin+eip' $(which rigsignal-ebpf)"
        );
    }
    Ok(())
}

fn read_cap_eff() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("CapEff:") {
            let hex = line.split(':').nth(1)?.trim();
            return u64::from_str_radix(hex, 16).ok();
        }
    }
    None
}

/// Verify BTF is available (required for CO-RE relocation).
fn check_btf() -> Result<()> {
    let btf_path = "/sys/kernel/btf/vmlinux";
    if !std::path::Path::new(btf_path).exists() {
        bail!(
            "BTF not available at {}. Minimum kernel 5.8 with CONFIG_DEBUG_INFO_BTF=y required.",
            btf_path
        );
    }
    Ok(())
}
