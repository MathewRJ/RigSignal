/// Windows CPU collector.
///
/// Emits `rigsignal.cpu.*` fields matching the Linux collector's schema so
/// ingest pipelines and dashboards require no changes.
///
/// # WMI thermal note
///
/// WMI thermal zones often report ambient or ACPI zone temperature rather than
/// CPU die temperature. For accurate Tdie on AMD (k10temp equivalent), a vendor
/// SDK or direct ring-0 read is required. The hwmon/k10temp upgrade path on Linux
/// is in `src/collectors/linux/cpu.rs temperature_c()`.
///
/// # game_utilisation_pct parity gap
///
/// Per-game CPU utilisation requires ETW kernel callbacks or a Job Object.
/// PDH does not expose per-process counters in a way that works for short-lived
/// game processes. This is documented as a known parity gap vs Linux.
/// TODO(C.1-game-util): implement via ETW or Job Object in a later work package.
use crate::collectors::windows::pdh::{PdhCounter, PdhQuery};
use crate::collectors::windows::wmi;
use crate::collectors::Collector;
use anyhow::Result;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

// ── WMI temperature cache ─────────────────────────────────────────────────────

struct TempCache {
    value: Option<f64>,
    last_queried: Option<Instant>,
}

impl TempCache {
    fn new() -> Self {
        TempCache {
            value: None,
            last_queried: None,
        }
    }

    /// Refresh at most every 5 seconds. Takes the first valid thermal zone
    /// (arbitrary; WMI zone ordering is firmware-defined).
    fn get(&mut self) -> Option<f64> {
        let now = Instant::now();
        let stale = self
            .last_queried
            .map(|t| now.duration_since(t) >= Duration::from_secs(5))
            .unwrap_or(true);

        if stale {
            self.last_queried = Some(now);
            self.value = wmi::query_thermal_zones()
                .into_iter()
                .next()
                .map(|(_, t)| t);
        }
        self.value
    }
}

// ── Collector ─────────────────────────────────────────────────────────────────

pub struct CpuCollector {
    game_pid: Option<u32>,
    query: Option<PdhQuery>,
    counter_total: Option<PdhCounter>,
    counter_per_core: Option<PdhCounter>,
    counter_freq: Option<PdhCounter>,
    initialized: bool,
    temp_cache: TempCache,
}

impl CpuCollector {
    pub fn new(game_pid: Option<u32>) -> Self {
        let mut collector = CpuCollector {
            game_pid,
            query: None,
            counter_total: None,
            counter_per_core: None,
            counter_freq: None,
            initialized: false,
            temp_cache: TempCache::new(),
        };
        collector.init_pdh();
        collector
    }

    fn init_pdh(&mut self) {
        match self.try_init_pdh() {
            Ok(()) => {
                self.initialized = true;
            }
            Err(e) => {
                tracing::warn!("CpuCollector PDH init failed: {e}; will return Ok(None)");
            }
        }
    }

    fn try_init_pdh(&mut self) -> Result<()> {
        let mut query = PdhQuery::new()?;
        let counter_total = query.add_counter(r"\Processor(_Total)\% Processor Time")?;
        let counter_per_core = query.add_counter(r"\Processor(*)\% Processor Time")?;
        let counter_freq =
            query.add_counter(r"\Processor Information(_Total)\Processor Frequency")?;
        // Baseline collect — establishes the rate denominator. First real tick
        // (the next collect() call) will return valid values.
        query.collect()?;
        self.query = Some(query);
        self.counter_total = Some(counter_total);
        self.counter_per_core = Some(counter_per_core);
        self.counter_freq = Some(counter_freq);
        Ok(())
    }
}

impl Collector for CpuCollector {
    fn dataset(&self) -> &'static str {
        "rigsignal.cpu"
    }

    fn set_game_pid(&mut self, pid: Option<u32>) {
        self.game_pid = pid;
    }

    fn collect(&mut self) -> Result<Option<Value>> {
        if !self.initialized {
            return Ok(None);
        }
        let query = match self.query.as_mut() {
            Some(q) => q,
            None => return Ok(None),
        };

        if let Err(e) = query.collect() {
            tracing::warn!("CpuCollector PDH collect failed: {e}");
            return Ok(None);
        }

        let total = match &self.counter_total {
            Some(c) => query.counter_value_f64(c).unwrap_or(0.0),
            None => 0.0,
        };
        let total = (total * 10.0).round() / 10.0;

        let per_core: Vec<f64> = match &self.counter_per_core {
            Some(c) => {
                let mut pairs = query.counter_values_array(c).unwrap_or_default();
                // Remove the _Total instance; keep only numeric-indexed cores.
                pairs.retain(|(name, _)| name != "_Total");
                // Sort by numeric index so per_core[0] = CPU 0, per_core[1] = CPU 1.
                pairs.sort_by(|(a, _), (b, _)| {
                    let ai: i32 = a.parse().unwrap_or(i32::MAX);
                    let bi: i32 = b.parse().unwrap_or(i32::MAX);
                    ai.cmp(&bi)
                });
                pairs
                    .into_iter()
                    .map(|(_, v)| (v * 10.0).round() / 10.0)
                    .collect()
            }
            None => Vec::new(),
        };

        let clock_mhz_avg: Option<u64> = self
            .counter_freq
            .as_ref()
            .and_then(|c| query.counter_value_f64(c).ok())
            .map(|v| v as u64);

        let temperature_c = self.temp_cache.get();

        // boost_state: Windows has no reliable cross-vendor API without a vendor
        // SDK (e.g. AMD ADLX or Intel XTU). Hardcode true — Boost is on by default
        // on all modern Windows gaming systems and users would override in config
        // if needed. See TODO(C.1-game-util) above for the ETW upgrade path.
        let mut cpu = json!({
            "total_utilisation_pct": total,
            "per_core": per_core,
            "boost_state": true,
        });

        let obj = cpu.as_object_mut().unwrap();
        if let Some(mhz) = clock_mhz_avg {
            obj.insert("clock_mhz_avg".to_string(), Value::from(mhz));
        }
        if let Some(temp) = temperature_c {
            obj.insert("temperature_c".to_string(), Value::from(temp));
        }

        Ok(Some(json!({ "rigsignal": { "cpu": cpu } })))
    }
}
