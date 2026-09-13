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
                // Root-cause render: the outermost context and the DEEPEST
                // cause, with the middle of the chain dropped.
                //
                // Not the plain render, and not the alternate one. The six
                // Windows PDH sites in this change are plain because their
                // errors are a single anyhow layer, so the two renders are
                // identical text there. This site is different: a review showed
                // the plain render keeps the ADDRESS and drops the ANSWER. A
                // tracepoint format mismatch renders as `parsing <path>` while
                // the cause it hides is the diagnosis itself -- "field 'id' has
                // size 4, expected 8". The wrapped causes here are `io::Error`
                // and this crate's `FormatError`, not only aya errors.
                //
                // And not the alternate render `{e:#}`, which walks every cause
                // verbatim. An error chain is not safe to print by default just
                // because today's causes are benign -- that reasoning is what
                // failed for the ES ping, where reqwest embedded the full
                // request URL in its own error. The two ends of a chain are what
                // an operator reads; the middle is where request detail lives.
                warn!(
                    "failed to attach probe '{}': {}",
                    probe.name(),
                    attach_failure_reason(&e)
                );
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

/// Render an error as `<outermost>: <root cause>`, dropping the middle.
///
/// The outermost layer says what we were doing; the deepest says why it failed.
/// The layers between are where request and path detail accumulate, which is the
/// part that must not reach a log by default.
///
/// This is a REDUCTION, not a scrub: nothing is pattern-matched out of a string.
/// If a cause type ever puts sensitive detail in its ROOT, this would not stop it.
fn attach_failure_reason(error: &anyhow::Error) -> String {
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

#[cfg(test)]
mod tests {
    use super::attach_failure_reason;
    use anyhow::{anyhow, Context};

    #[test]
    fn keeps_the_diagnosis_and_drops_the_middle() {
        // The exact shape a non-author review produced as the counterexample to
        // the plain render: the outermost layer names the FILE, a middle layer
        // names the operation, and the root names the actual problem.
        let error = Err::<(), _>(anyhow!("field 'id' has size 4, expected 8"))
            .context("parsing /sys/kernel/tracing/events/gpu_scheduler/format")
            .context("attaching drm_sched_job tracepoint")
            .unwrap_err();

        let rendered = attach_failure_reason(&error);

        assert!(
            rendered.contains("field 'id' has size 4, expected 8"),
            "the diagnosis was dropped: {rendered}"
        );
        assert!(
            rendered.starts_with("attaching drm_sched_job tracepoint"),
            "the outermost context was dropped: {rendered}"
        );
        assert!(
            !rendered.contains("/sys/kernel/tracing"),
            "a middle layer survived, which is what this render exists to drop: {rendered}"
        );
    }

    #[test]
    fn a_single_layer_error_is_not_duplicated() {
        let error = anyhow!("PDH error code: 0x800007D5");
        assert_eq!(attach_failure_reason(&error), "PDH error code: 0x800007D5");
    }
}
