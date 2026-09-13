/// Windows network collector — PDH Network Interface aggregate throughput.
///
/// Sums bytes/sec across all real network interfaces. Tunnel/loopback
/// adapters (isatap*, teredo*, loopback*) are excluded.
///
/// Per-interface breakdown can be added by emitting the
/// counter_values_array result as a nested object rather than summing.
/// The wildcard counter path and counter_values_array are already in
/// place — it is a doc/field schema change, not an API change.
use crate::collectors::windows::pdh::{PdhCounter, PdhQuery};
use crate::collectors::Collector;
use anyhow::Result;
use serde_json::{json, Value};

fn is_excluded(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("isatap") || lower.starts_with("teredo") || lower.contains("loopback")
}

pub struct NetworkCollector {
    _game_pid: Option<u32>,
    query: Option<PdhQuery>,
    counter_sent: Option<PdhCounter>,
    counter_recv: Option<PdhCounter>,
    initialized: bool,
}

impl NetworkCollector {
    pub fn new(game_pid: Option<u32>) -> Self {
        let mut col = NetworkCollector {
            _game_pid: game_pid,
            query: None,
            counter_sent: None,
            counter_recv: None,
            initialized: false,
        };
        col.init_pdh();
        col
    }

    fn init_pdh(&mut self) {
        match self.try_init_pdh() {
            Ok(()) => self.initialized = true,
            Err(e) => tracing::warn!("NetworkCollector PDH init failed: {e}"),
        }
    }

    fn try_init_pdh(&mut self) -> Result<()> {
        let mut query = PdhQuery::new()?;
        let counter_sent = query.add_counter(r"\Network Interface(*)\Bytes Sent/sec")?;
        let counter_recv = query.add_counter(r"\Network Interface(*)\Bytes Received/sec")?;
        query.collect()?;
        self.query = Some(query);
        self.counter_sent = Some(counter_sent);
        self.counter_recv = Some(counter_recv);
        Ok(())
    }
}

impl Collector for NetworkCollector {
    fn dataset(&self) -> &'static str {
        "rigsignal.network"
    }

    fn set_game_pid(&mut self, pid: Option<u32>) {
        self._game_pid = pid;
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
            tracing::warn!("NetworkCollector PDH collect failed: {e}");
            return Ok(None);
        }

        let sent_bps: u64 = self
            .counter_sent
            .as_ref()
            .and_then(|c| query.counter_values_array(c).ok())
            .unwrap_or_default()
            .iter()
            .filter(|(name, _)| !is_excluded(name))
            .map(|(_, v)| *v as u64)
            .sum();

        let recv_bps: u64 = self
            .counter_recv
            .as_ref()
            .and_then(|c| query.counter_values_array(c).ok())
            .unwrap_or_default()
            .iter()
            .filter(|(name, _)| !is_excluded(name))
            .map(|(_, v)| *v as u64)
            .sum();

        Ok(Some(json!({
            "rigsignal": {
                "network": {
                    "bytes_sent_per_sec": sent_bps,
                    "bytes_recv_per_sec": recv_bps,
                }
            }
        })))
    }
}
