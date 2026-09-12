//! A transient Elasticsearch failure must not abort the agent, and the operator
//! must still be told about it.
//!
//! Before this change the startup preflight was fatal: `shipper::ping(&cfg).await?`
//! propagated, the process exited non-zero, and `Restart=on-failure` turned a
//! blip into a crash loop. These tests pin both halves of the replacement --
//! the process survives, and it says so in a greppable way.

use std::fs;
use std::io::Read;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A TCP port with nothing listening on it.
///
/// Bind to port 0 so the OS picks a free one, learn the number, then drop the
/// listener. The caller MUST verify the refusal rather than assume it.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("read local addr").port();
    drop(listener);
    port
}

/// Assert that a connection to the port does not SUCCEED.
///
/// This is the setup assertion and it is the point of the test rather than
/// decoration: if something were listening, the preflight would SUCCEED and the
/// agent would stay up for a reason unrelated to the change under test. The test
/// would pass while measuring nothing.
///
/// The property is "a connection does not succeed", and that is what is asserted.
/// An earlier version demanded `ErrorKind::ConnectionRefused` specifically, which
/// is a Unix-shaped assumption: on Windows the same closed port reports a
/// different kind, so the assertion panicked on a setup that was in fact
/// perfectly established. It failed CLOSED, which is why it showed up as a red
/// test rather than as a test quietly measuring nothing -- but the right fix is
/// to assert the property rather than to enumerate the error kinds that count.
fn assert_refuses(port: u16) {
    if let Ok(stream) = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().expect("parse addr"),
        Duration::from_millis(500),
    ) {
        let _ = stream.shutdown(Shutdown::Both);
        panic!("port {port} accepted a connection; the unreachable-endpoint setup is void");
    }
}

fn write_config(dir: &Path, port: u16) -> PathBuf {
    let path = dir.join("rigsignal.toml");
    fs::write(
        &path,
        format!(
            "[elasticsearch]\n\
             endpoint = \"http://127.0.0.1:{port}\"\n\
             \n\
             [output]\n\
             mode = \"elasticsearch\"\n"
        ),
    )
    .expect("write config");
    path
}

/// Kill and REAP. `clippy::zombie_processes` is denied in CI, and a neighbouring
/// harness tripped exactly this.
fn kill_and_reap(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn read_log(path: &Path) -> String {
    let mut buf = String::new();
    if let Ok(mut f) = fs::File::open(path) {
        let _ = f.read_to_string(&mut buf);
    }
    buf
}

#[test]
fn unreachable_elasticsearch_does_not_abort_the_agent() {
    // Include the thread id: cargo runs test binaries in parallel, and a bare
    // process id is shared by every test in this binary.
    let tmp = std::env::temp_dir().join(format!(
        "rigsignal-p1-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create temp dir");

    let port = closed_port();
    assert_refuses(port);

    let config = write_config(&tmp, port);
    let log_path = tmp.join("agent.stderr");
    let log = fs::File::create(&log_path).expect("create stderr file");

    // stderr goes to a FILE, not a pipe: nothing reads the pipe while the agent
    // runs, and a full pipe would block the process being measured.
    let mut child = Command::new(env!("CARGO_BIN_EXE_rigsignal-agent"))
        .arg("--config")
        .arg(&config)
        .env("RIGSIGNAL_LOG", "info")
        .env("HOME", &tmp)
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn agent");

    // Connection-refused is the FAST failure path -- the one that aborted
    // immediately before this change.
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut saw_marker = false;
    let mut exited_early = None;
    while Instant::now() < deadline {
        match child.try_wait().expect("poll agent") {
            Some(status) => {
                exited_early = Some(status);
                break;
            }
            None => {
                if read_log(&log_path).contains("ES_DELIVERY") {
                    saw_marker = true;
                    // Keep running a little longer to confirm the marker did not
                    // coincide with the process dying.
                    std::thread::sleep(Duration::from_millis(750));
                    break;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
        }
    }

    let still_running = child.try_wait().expect("poll agent").is_none();
    let log_text = read_log(&log_path);
    kill_and_reap(child);
    let _ = fs::remove_dir_all(&tmp);

    assert!(
        exited_early.is_none(),
        "agent exited on an unreachable endpoint ({exited_early:?}) -- the preflight is still \
         fatal.\nstderr:\n{log_text}"
    );
    assert!(
        still_running,
        "agent was not running after the wait -- the preflight is still fatal.\nstderr:\n{log_text}"
    );
    assert!(
        saw_marker,
        "agent survived but never emitted an ES_DELIVERY line. Surviving QUIETLY is the \
         failure mode this marker exists to prevent.\nstderr:\n{log_text}"
    );
}

/// The marked line is echoed to `rigsignal status` stdout, so it must not carry
/// the error -- the context on this path interpolates the configured endpoint,
/// and an endpoint can carry a credential in a query parameter.
#[test]
fn the_marked_preflight_line_does_not_carry_the_endpoint() {
    let tmp = std::env::temp_dir().join(format!(
        "rigsignal-p1-redact-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create temp dir");

    let port = closed_port();
    assert_refuses(port);

    // A canary that would be a credential in a real deployment.
    let canary = "RIGSIGNAL_URL_CANARY";
    let config = tmp.join("rigsignal.toml");
    fs::write(
        &config,
        format!(
            "[elasticsearch]\n\
             endpoint = \"http://127.0.0.1:{port}/?api_key={canary}\"\n\
             \n[output]\nmode = \"elasticsearch\"\n"
        ),
    )
    .expect("write config");

    let log_path = tmp.join("agent.stderr");
    let log = fs::File::create(&log_path).expect("create stderr file");
    let child = Command::new(env!("CARGO_BIN_EXE_rigsignal-agent"))
        .arg("--config")
        .arg(&config)
        .env("RIGSIGNAL_LOG", "info")
        .env("HOME", &tmp)
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn agent");

    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if read_log(&log_path).contains("ES_DELIVERY") {
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    let log_text = read_log(&log_path);
    kill_and_reap(child);
    let _ = fs::remove_dir_all(&tmp);

    let marked: Vec<&str> = log_text
        .lines()
        .filter(|l| l.contains("ES_DELIVERY"))
        .collect();
    // Setup assertion: an empty set of marked lines would satisfy the check below
    // while proving nothing at all.
    assert!(
        !marked.is_empty(),
        "no marked line was emitted, so this test measured nothing.\nstderr:\n{log_text}"
    );
    for line in &marked {
        assert!(
            !line.contains(canary),
            "a marked line carries the endpoint credential, and `rigsignal status` echoes \
             marked lines to stdout: {line}"
        );
    }
    // And the detail must still reach the journal on an UNMARKED line, or the
    // redaction has cost the operator the diagnosis.
    assert!(
        log_text.contains("startup preflight error"),
        "the unmarked error line is missing; redaction must not remove the \
         diagnosis.\nstderr:\n{log_text}"
    );
}

// ── The unit-file side of the same change ────────────────────────────────────

fn unit_text(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("packaging/systemd")
        .join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// Section-aware, last-wins directive lookup.
///
/// systemd takes the LAST assignment of a key and ignores a key in the wrong
/// section entirely. A first-match, section-blind reader gets both cases wrong,
/// and both are realistic: `StartLimitIntervalSec` lived in `[Service]` before
/// systemd v229 and most surviving documentation still shows it there, so a
/// maintainer tidying it next to `RestartSec` would silently restore the
/// never-trips condition. Measured on systemd 259: with these keys in `[Service]`
/// the effective `StartLimitIntervalUSec` is 10s, the manager default.
fn directive_raw(text: &str, section: &str, key: &str) -> Option<String> {
    let mut current = String::new();
    let mut found = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].to_string();
            continue;
        }
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if current != section {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                found = Some(v.trim().to_string()); // last wins
            }
        }
    }
    found
}

/// Parse a systemd time span to milliseconds. A bare number is seconds.
fn timespan_ms(v: &str) -> Result<u64, String> {
    let v = v.trim();
    if v.is_empty() {
        return Err("empty value".into());
    }
    if let Ok(n) = v.parse::<u64>() {
        return Ok(n * 1000);
    }
    let mut total = 0u64;
    let mut rest = v;
    while !rest.trim().is_empty() {
        rest = rest.trim_start();
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return Err(format!("unparsed time span {v:?}"));
        }
        rest = &rest[digits.len()..];
        let unit: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect();
        rest = &rest[unit.len()..];
        let n: u64 = digits.parse().map_err(|_| format!("bad number in {v:?}"))?;
        let mult = match unit.as_str() {
            "" | "s" | "sec" | "secs" | "second" | "seconds" => 1000,
            "ms" | "msec" | "msecs" => 1,
            "us" | "usec" | "usecs" => 0,
            "min" | "m" | "minute" | "minutes" => 60_000,
            "h" | "hr" | "hour" | "hours" => 3_600_000,
            other => return Err(format!("unknown time unit {other:?} in {v:?}")),
        };
        total += n * mult;
    }
    Ok(total)
}

/// The property, not the literal.
///
/// What has to hold is that a full burst of restarts FITS inside the limiter
/// window: the gaps between `StartLimitBurst` starts total
/// `RestartSec * (burst - 1)`, and that must be strictly less than
/// `StartLimitIntervalSec`. Measured on systemd 259 with the shipped RestartSec=5:
/// at the manager default window of 10s the unit cycled for 45s and reached
/// NRestarts=9 without ever tripping; at 60s it reached `failed` after 5 restarts.
#[test]
fn agent_units_can_actually_trip_their_start_limiter() {
    for unit in [
        "rigsignal-agent.service",
        "rigsignal-agent.user-install.service",
    ] {
        let text = unit_text(unit);

        let restart_raw = directive_raw(&text, "Service", "RestartSec")
            .unwrap_or_else(|| panic!("{unit}: no RestartSec in [Service]"));
        let interval_raw =
            directive_raw(&text, "Unit", "StartLimitIntervalSec").unwrap_or_else(|| {
                panic!(
                    "{unit}: no StartLimitIntervalSec in [Unit]. In any other section systemd \
                 ignores it and the manager default of 10s applies, at which the start \
                 limiter can never trip against RestartSec=5."
                )
            });
        let burst_raw = directive_raw(&text, "Unit", "StartLimitBurst")
            .unwrap_or_else(|| panic!("{unit}: no StartLimitBurst in [Unit]"));

        let restart_ms = timespan_ms(&restart_raw)
            .unwrap_or_else(|e| panic!("{unit}: RestartSec={restart_raw:?}: {e}"));
        let interval_ms = timespan_ms(&interval_raw)
            .unwrap_or_else(|e| panic!("{unit}: StartLimitIntervalSec={interval_raw:?}: {e}"));
        let burst: u64 = burst_raw
            .parse()
            .unwrap_or_else(|e| panic!("{unit}: StartLimitBurst={burst_raw:?}: {e}"));

        assert!(
            interval_ms > 0,
            "{unit}: StartLimitIntervalSec={interval_raw} DISABLES rate limiting entirely"
        );
        assert!(burst >= 2, "{unit}: StartLimitBurst={burst} is degenerate");
        let span_ms = restart_ms * (burst - 1);
        assert!(
            span_ms < interval_ms,
            "{unit}: {burst} starts at RestartSec={restart_raw} span {span_ms}ms, which does \
             not fit inside StartLimitIntervalSec={interval_raw} ({interval_ms}ms) -- the \
             limiter can never trip and a crash loop would run forever"
        );
    }
}

// ── The emission sites themselves ────────────────────────────────────────────

/// Read `main.rs` with line endings NORMALISED.
///
/// A checkout can materialise this file with CRLF, and a scan anchored on
/// "\n}\n" then finds nothing -- which is how the accounting guard failed on
/// Windows while the same guard passed everywhere else. Normalising is the fix;
/// searching for both forms would be enumerating the endings that exist.
fn agent_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("main.rs");
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// Return (macro name, whether the call carries the marker) for the tracing call
/// containing `needle`.
fn emission(src: &str, needle: &str) -> (String, bool) {
    let at = src
        .find(needle)
        .unwrap_or_else(|| panic!("message not found in source: {needle:?}"));
    let head = &src[..at];
    let open = head
        .rfind("tracing::")
        .unwrap_or_else(|| panic!("no tracing macro precedes {needle:?}"));
    let macro_name: String = src[open + "tracing::".len()..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let tail_end = src[at..].find(");").map(|i| at + i).unwrap_or(src.len());
    let carries = src[open..tail_end].contains("ES_DELIVERY_MARKER");
    (macro_name, carries)
}

/// Every delivery-health line must carry the marker, and recovery must be visible
/// wherever the failures were.
///
/// Without this, three separate mutations survived the whole suite: dropping the
/// marker from the recovery line (after which `rigsignal status` pins the last
/// FAILURE line forever and reports an outage that has ended), dropping it from
/// the tick unreachable line (which the integration test cannot see, because it
/// observes the preflight line within ~150 ms), and demoting recovery to
/// `debug!` (invisible at the `Environment=RIGSIGNAL_LOG=info` the units ship).
#[test]
fn every_delivery_health_line_is_marked_and_recovery_is_visible() {
    let src = agent_source();

    let (preflight_macro, preflight_marked) = emission(&src, "startup preflight failed");
    assert!(preflight_marked, "the preflight line lost its marker");
    assert_eq!(
        preflight_macro, "warn",
        "the preflight line must be a warning"
    );

    let (unreachable_macro, unreachable_marked) =
        emission(&src, "Elasticsearch delivery failing since");
    assert!(
        unreachable_marked,
        "the tick unreachable line lost its marker; `rigsignal status` would then never \
         see an outage that began after startup"
    );
    assert_eq!(unreachable_macro, "warn");

    let (recovery_macro, recovery_marked) = emission(&src, "Elasticsearch delivery recovered");
    assert!(
        recovery_marked,
        "the recovery line lost its marker; `rigsignal status` takes the last marked line, \
         so it would report the outage as ongoing forever"
    );
    assert_eq!(
        recovery_macro, "warn",
        "recovery must be warn!, not {recovery_macro}!: the units ship \
         Environment=RIGSIGNAL_LOG=info, and at any level where the failures are visible the \
         line saying they stopped must be visible too"
    );
}

/// Every Elasticsearch delivery must be accounted for, not just the tick.
///
/// Five of the six delivery sites are one-shot documents -- session start, game
/// detected, summary on game exit, remote connections, final summary -- and all
/// of them run through `write_output`. While only the tick was instrumented, a
/// session-start document lost before the first tick was invisible to
/// `rigsignal status` and did not count, so the reported number of failed
/// deliveries under-reported the documents actually dropped.
///
/// This reads the source, which is weaker than a behavioural test and is
/// labelled so: it pins that the accounting call is present on the Elasticsearch
/// branch, not that it produces the right number.
#[test]
fn every_elasticsearch_delivery_is_accounted_for() {
    let src = agent_source();
    let start = src
        .find("async fn write_output(")
        .expect("write_output not found");
    let end = src[start..]
        .find("\n}\n")
        .map(|i| start + i)
        .expect("end of write_output not found");
    let body = &src[start..end];
    assert!(
        body.contains("es_health.observe("),
        "write_output no longer accounts for Elasticsearch deliveries, so the five one-shot \
         document paths would stop counting and `rigsignal status` would under-report"
    );
}
