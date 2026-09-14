/// Windows storage collector — PDH PhysicalDisk aggregate throughput.
///
/// Emits aggregate read/write bytes/sec across all physical disks.
///
/// Game-scoped IO (game_read_bytes_per_sec etc.) requires ETW
/// kernel-level IO tracing (e.g. Microsoft-Windows-Kernel-FileIO
/// provider). See docs/ROADMAP.md eBPF Sprint 4 notes for the Linux
/// equivalent rationale. The PDH per-disk breakdown can be added by
/// enumerating \PhysicalDisk(*)\... instances via counter_values_array
/// — the infrastructure is in pdh.rs.
use crate::collectors::windows::pdh::{PdhCounter, PdhQuery};
use crate::collectors::Collector;
use anyhow::Result;
use serde_json::{json, Value};

pub struct StorageCollector {
    _game_pid: Option<u32>,
    query: Option<PdhQuery>,
    counter_read: Option<PdhCounter>,
    counter_write: Option<PdhCounter>,
    initialized: bool,
}

impl StorageCollector {
    pub fn new(game_pid: Option<u32>) -> Self {
        let mut col = StorageCollector {
            _game_pid: game_pid,
            query: None,
            counter_read: None,
            counter_write: None,
            initialized: false,
        };
        col.init_pdh();
        col
    }

    fn init_pdh(&mut self) {
        match self.try_init_pdh() {
            Ok(()) => self.initialized = true,
            Err(e) => tracing::warn!("StorageCollector PDH init failed: {e}"),
        }
    }

    fn try_init_pdh(&mut self) -> Result<()> {
        let mut query = PdhQuery::new()?;
        let counter_read = query.add_counter(r"\PhysicalDisk(_Total)\Disk Read Bytes/sec")?;
        let counter_write = query.add_counter(r"\PhysicalDisk(_Total)\Disk Write Bytes/sec")?;
        query.collect()?;
        self.query = Some(query);
        self.counter_read = Some(counter_read);
        self.counter_write = Some(counter_write);
        Ok(())
    }
}

impl Collector for StorageCollector {
    fn dataset(&self) -> &'static str {
        "rigsignal.storage"
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
            tracing::warn!("StorageCollector PDH collect failed: {e}");
            return Ok(None);
        }

        let read_bps = self
            .counter_read
            .as_ref()
            .and_then(|c| query.counter_value_f64(c).ok())
            .unwrap_or(0.0) as u64;

        let write_bps = self
            .counter_write
            .as_ref()
            .and_then(|c| query.counter_value_f64(c).ok())
            .unwrap_or(0.0) as u64;

        Ok(Some(json!({
            "rigsignal": {
                "storage": {
                    "read_bytes_per_sec": read_bps,
                    "write_bytes_per_sec": write_bps,
                }
            }
        })))
    }
}
