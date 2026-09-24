/// Elasticsearch bulk API shipper.
///
/// Batches eBPF documents and POSTs them to the ES bulk endpoint.
/// Uses the same API key and endpoint as the Python collector.
use crate::es_model::EbpfDocument;
use anyhow::{Context, Result};
use reqwest::{Certificate, Client};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

const UNSUPPORTED_PROBE_WARNING_INTERVAL: Duration = Duration::from_secs(5 * 60);
static UNSUPPORTED_PROBE_WARNING_TIMES: OnceLock<Mutex<HashMap<&'static str, Instant>>> =
    OnceLock::new();

pub struct EsShipper {
    client: Client,
    endpoint: String,
    api_key: String,
    /// Pending documents awaiting the next flush.
    pending: Vec<EbpfDocument>,
    /// How many docs to accumulate before forcing a flush.
    #[allow(dead_code)]
    batch_size: usize,
}

impl EsShipper {
    pub fn new(endpoint: &str, api_key: &str, ca_cert: Option<&Path>) -> Result<Self> {
        let mut builder = Client::builder().timeout(std::time::Duration::from_secs(10));

        if let Some(path) = ca_cert {
            let pem = std::fs::read(path)
                .with_context(|| format!("reading Elasticsearch CA cert: {}", path.display()))?;
            let certificates = ca_certificate_bundle(&pem)
                .with_context(|| format!("parsing Elasticsearch CA cert: {}", path.display()))?;
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }

        let client = builder.build().context("building HTTP client")?;

        let endpoint = format!("{}/_bulk", endpoint.trim_end_matches('/'));

        Ok(EsShipper {
            client,
            endpoint,
            api_key: api_key.to_string(),
            pending: Vec::new(),
            batch_size: 100,
        })
    }

    /// Queue a document for the next flush.
    #[allow(dead_code)]
    pub fn queue(&mut self, doc: EbpfDocument) {
        self.pending.extend(filter_supported_docs([doc]));
    }

    /// Queue multiple documents.
    pub fn queue_all(&mut self, docs: Vec<EbpfDocument>) {
        self.pending.extend(filter_supported_docs(docs));
    }

    /// Flush all pending documents to Elasticsearch.
    /// No-op if nothing is queued.
    pub async fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }

        let docs = std::mem::take(&mut self.pending);
        let count = docs.len();
        debug!("flushing {} eBPF docs to ES", count);

        let body = build_bulk_body(&docs)?;

        let resp = self
            .client
            .post(&self.endpoint)
            .header("Content-Type", "application/x-ndjson")
            .header("Authorization", format!("ApiKey {}", self.api_key))
            .body(body)
            .send()
            .await
            .context("sending bulk request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            error!("{}", bulk_failure_message(status, &text));
            // Docs are dropped on error — eBPF telemetry is best-effort.
            return Ok(());
        }

        // Check for per-item errors in the bulk response.
        let resp_body: serde_json::Value = resp.json().await.context("parsing bulk response")?;
        if resp_body
            .get("errors")
            .and_then(|e| e.as_bool())
            .unwrap_or(false)
        {
            if let Some(items) = resp_body.get("items").and_then(|i| i.as_array()) {
                let (conflict_count, real_error_count, first_reason) = items.iter().fold(
                    (0usize, 0usize, None::<&str>),
                    |(conflicts, errors, reason), item| {
                        let Some(op) = item.get("create") else {
                            return (conflicts, errors, reason);
                        };
                        let Some(err) = op.get("error") else {
                            return (conflicts, errors, reason);
                        };
                        let is_conflict = err.get("type").and_then(|t| t.as_str())
                            == Some("version_conflict_engine_exception");
                        if is_conflict {
                            (conflicts + 1, errors, reason)
                        } else {
                            let r = reason.or_else(|| err.get("reason").and_then(|r| r.as_str()));
                            (conflicts, errors + 1, r)
                        }
                    },
                );
                if conflict_count > 0 {
                    debug!(
                        "{}/{} docs skipped — duplicate TSDB id (version conflict)",
                        conflict_count, count
                    );
                }
                if real_error_count > 0 {
                    if let Some(reason) = first_reason {
                        warn!(
                            "{}/{} docs had bulk errors; first reason: {}",
                            real_error_count, count, reason
                        );
                    } else {
                        warn!("{}/{} docs had bulk errors", real_error_count, count);
                    }
                }
            }
        }

        Ok(())
    }
}

fn bulk_failure_message(status: reqwest::StatusCode, body: &str) -> String {
    format!(
        "ES bulk API returned {}: {}",
        status,
        escape_for_log(truncate_chars(body, 500))
    )
}

fn truncate_chars(s: &str, max_bytes: usize) -> &str {
    &s[..s.floor_char_boundary(max_bytes.min(s.len()))]
}

fn escape_for_log(s: &str) -> Cow<'_, str> {
    let needs_escape = |c: char| {
        matches!(c, '\\' | '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}'
            | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}'
            | '\u{2028}' | '\u{2029}' | '\u{2066}'..='\u{2069}')
    };
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if needs_escape(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

fn ca_certificate_bundle(bytes: &[u8]) -> Result<Vec<Certificate>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut remainder = std::str::from_utf8(bytes)?.trim();
    if remainder.is_empty() {
        anyhow::bail!("CA bundle is empty");
    }
    while !remainder.is_empty() {
        let certificate = remainder
            .strip_prefix(BEGIN)
            .ok_or_else(|| anyhow::anyhow!("CA bundle contains non-certificate data"))?;
        let end = certificate
            .find(END)
            .ok_or_else(|| anyhow::anyhow!("CA bundle has an unterminated certificate"))?
            + END.len();
        remainder = certificate[end..].trim();
    }
    let certificates = Certificate::from_pem_bundle(bytes)?;
    (!certificates.is_empty())
        .then_some(certificates)
        .ok_or_else(|| anyhow::anyhow!("CA bundle is empty"))
}

/// Drops documents from unsupported probes before they can create an ES series.
/// The warning is rate-limited per unsupported probe to once every five minutes;
/// the probe value itself is deliberately omitted from the diagnostic.
fn filter_supported_docs(docs: impl IntoIterator<Item = EbpfDocument>) -> Vec<EbpfDocument> {
    docs.into_iter()
        .filter(|doc| {
            if doc.has_named_probe() {
                return true;
            }

            warn_unsupported_probe(doc.probe());
            false
        })
        .collect()
}

fn warn_unsupported_probe(probe: &'static str) {
    let warning_times = UNSUPPORTED_PROBE_WARNING_TIMES.get_or_init(|| Mutex::new(HashMap::new()));
    let now = Instant::now();
    let should_warn = warning_times
        .lock()
        .map(|mut times| match times.get(probe) {
            Some(last_warning) if now.duration_since(*last_warning) < UNSUPPORTED_PROBE_WARNING_INTERVAL => {
                false
            }
            _ => {
                times.insert(probe, now);
                true
            }
        })
        .unwrap_or(false);

    if should_warn {
        warn!(
            category = "unsupported_ebpf_probe",
            rate_limit_minutes = 5,
            "dropped eBPF document for unsupported probe"
        );
    }
}

fn build_bulk_body(docs: &[EbpfDocument]) -> Result<String> {
    let mut body = String::with_capacity(docs.len() * 256);
    for doc in docs {
        let action = format!(r#"{{"create":{{"_index":"{}"}}}}"#, doc.index());
        body.push_str(&action);
        body.push('\n');
        let doc_json = match doc {
            EbpfDocument::Metric(metric) => serde_json::to_string(metric),
            EbpfDocument::Thread(thread) => serde_json::to_string(thread),
        }
        .context("serialising doc")?;
        body.push_str(&doc_json);
        body.push('\n');
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{
        bulk_failure_message, ca_certificate_bundle, escape_for_log, filter_supported_docs,
        truncate_chars,
    };
    use crate::{
        aggregator::{RawSchedEvent, SchedAggregator, EVENT_SWITCH},
        es_model::{EbpfDocument, NAMED_PROBES},
    };

    fn metric_doc(probe: &'static str) -> EbpfDocument {
        let mut aggregator = SchedAggregator::new("host".to_string(), "kernel".to_string());
        aggregator.push(RawSchedEvent {
            event_type: EVENT_SWITCH,
            _pad: [0; 3],
            tid: 1,
            wait_ns: 7_000,
            prev_cpu: 0,
            next_cpu: 0,
            comm: [0; 16],
        });

        let mut doc = aggregator.flush("session").remove(0);
        if let EbpfDocument::Metric(metric) = &mut doc {
            metric.rigsignal.ebpf.probe = probe;
        }
        doc
    }

    #[test]
    fn bulk_failure_message_does_not_forge_a_line() {
        let message = bulk_failure_message(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "ok\nFORGED line",
        );
        assert!(!message.contains('\n'), "{message:?}");
        assert!(message.contains("\\n"));
    }

    #[test]
    fn log_helpers_escape_controls_and_truncate_on_char_boundaries() {
        assert_eq!(
            escape_for_log("\\n\u{85}\u{2028}\u{202e}\u{2066}"),
            "\\\\n\\u{85}\\u{2028}\\u{202e}\\u{2066}"
        );
        let text = format!("{}é", "a".repeat(499));
        assert_eq!(truncate_chars(&text, 500).len(), 499);
    }

    const TEST_CA: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBcTCCARegAwIBAgIUFcCd4QbbalB9vcqsIBvd3Tbhx7kwCgYIKoZIzj0EAwIw\nDjEMMAoGA1UEAwwDb25lMB4XDTI2MDczMTA4MDU0MloXDTI2MDgwMTA4MDU0Mlow\nDjEMMAoGA1UEAwwDb25lMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBB9OC7xC\n6hGn6GNVbHVnsGwfmI0MJHSAiZDAjyHYn71C2EufTKa9yMy9EK53OEhSiOXTm8ob\nK3Z1F8FoTaUWa6NTMFEwHQYDVR0OBBYEFAiHcI/D49ZptsjDCKqSp8S+M5V+MB8G\nA1UdIwQYMBaAFAiHcI/D49ZptsjDCKqSp8S+M5V+MA8GA1UdEwEB/wQFMAMBAf8w\nCgYIKoZIzj0EAwIDSAAwRQIgSu9o44gWsyAvtbeXKuhIi4vUxSn6TU8N/SCPNVag\n5a0CIQD0jGGCQNjrdXYdp+Ai9qnxDgPWuP5S2f6YglCV2U2+LQ==\n-----END CERTIFICATE-----\n";

    #[test]
    fn ca_bundle_accepts_two_certificates_and_rejects_empty_or_garbage() {
        assert_eq!(
            ca_certificate_bundle(&[TEST_CA, TEST_CA].concat())
                .unwrap()
                .len(),
            2
        );
        assert!(ca_certificate_bundle(b"").is_err());
        assert!(ca_certificate_bundle(b"not a certificate").is_err());
    }

    #[test]
    fn unsupported_probes_are_dropped_independently_in_one_tick() {
        let docs = vec![metric_doc("unknown_probe_a"), metric_doc("unknown_probe_b")];

        let shipped = filter_supported_docs(docs);

        assert!(shipped.is_empty());
    }

    #[test]
    fn every_named_probe_passes_the_ten_series_budget() {
        let docs = NAMED_PROBES.into_iter().map(metric_doc);

        let shipped = filter_supported_docs(docs);

        assert_eq!(shipped.len(), 10);
        assert!(shipped.iter().all(EbpfDocument::has_named_probe));
    }
}
