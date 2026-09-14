//! The daemon's startup log must not carry an endpoint credential.
//!
//! WHY THIS IS A SUBPROCESS TEST AND NOT A UNIT TEST. Every existing test covers
//! the HELPER. A non-author review of PR #49 built a mutant (M18) that changed
//! only the call site in `main.rs` back to the raw endpoint, left the helper and
//! all its tests untouched, and passed the entire 30-test workspace while the
//! real daemon printed both the userinfo and the query credential verbatim. A
//! test of the mechanism is not a test of the step that uses it.
//!
//! WHY NO PRIVILEGED PROBE LOADING AND NO ELASTICSEARCH CONTACT. In `main.rs`
//! the probe load sits AFTER the endpoint log line and BEFORE the ES shipper is
//! constructed, so the daemon reaches the line under test and then exits. It
//! exits for one of two reasons and BOTH are after the log site, which is why
//! this works whether or not the runner is privileged:
//!   - unprivileged: `load_probes` refuses on the CAP_BPF/CAP_PERFMON check;
//!   - privileged (CI has a root job): the capability check passes and the load
//!     then fails on `--probe-path`, which names a file that does not exist.
//! Either way: no capability granted, no BTF, no network.
//!
//! WHICH STREAM. The daemon's tracing subscriber writes to STDOUT -- measured,
//! not assumed. `tracing_subscriber::fmt()` defaults to stdout, and only the
//! anyhow error reaches stderr. The first version of this test asserted on
//! stderr; its setup assertion failed loudly rather than passing vacuously,
//! which is the entire reason the setup assertion is there.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Tokens that must never appear on either output stream.
const USERINFO_SECRET: &str = "CANARYUSERINFO";
const QUERY_SECRET: &str = "CANARYQUERY";
const KEYFIELD_SECRET: &str = "CANARYKEYFIELD";

fn temp_dir(tag: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rigsignal-rs18-{tag}-{unique}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Run the daemon against a config holding `endpoint`, and return (stdout, stderr).
fn start_daemon_with(endpoint: &str, tag: &str) -> (String, String) {
    let dir = temp_dir(tag);
    let config = dir.join("rigsignal.toml");
    fs::write(
        &config,
        format!("[elasticsearch]\nendpoint = \"{endpoint}\"\napi_key = \"{KEYFIELD_SECRET}\"\n"),
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_rigsignal-ebpf"))
        .arg("--config")
        .arg(&config)
        .arg("--probe-path")
        .arg(dir.join("no-such-probe-object.o"))
        .arg("--log")
        .arg("info")
        // The daemon prefers RUST_LOG over --log. Inheriting it from whoever ran
        // the suite would let an unrelated environment silence the line under
        // test, and silence passes every absence assertion below.
        .env_remove("RUST_LOG")
        .output()
        .expect("run rigsignal-ebpf");

    let _ = fs::remove_dir_all(&dir);
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn the_real_startup_log_withholds_a_credential_bearing_endpoint() {
    let (stdout, stderr) = start_daemon_with(
        &format!("http://spooky:{USERINFO_SECRET}@127.0.0.1:9/?api_key={QUERY_SECRET}"),
        "credential",
    );

    // ASSERT THE SETUP FIRST. If the daemon never reached the log site, or the
    // subscriber emitted nothing, every absence check below would pass while
    // proving nothing at all. This is the half that a sibling test in the agent
    // omitted for its stderr surface, leaving three assertions one default away
    // from vacuity.
    assert!(
        !stdout.is_empty(),
        "the daemon logged nothing, so the absence assertions below are vacuous. \
         stderr: {stderr}"
    );
    assert!(
        stdout.contains("RigSignal eBPF daemon starting"),
        "the daemon did not reach its startup banner: {stdout} / {stderr}"
    );
    assert!(
        stdout.contains("ES endpoint:"),
        "the line under test was never emitted, so this test checked nothing: {stdout}"
    );

    // The endpoint is credential-bearing, so it must be withheld WHOLE.
    assert!(
        stdout.contains("ES endpoint: <redacted>"),
        "a credential-bearing endpoint must be withheld whole: {stdout}"
    );

    // Both streams, because a future writer change must not silently relocate a
    // secret rather than remove it.
    for secret in [USERINFO_SECRET, QUERY_SECRET, KEYFIELD_SECRET] {
        assert!(
            !stdout.contains(secret),
            "{secret} reached the daemon's log surface: {stdout}"
        );
        assert!(
            !stderr.contains(secret),
            "{secret} reached the daemon's error surface: {stderr}"
        );
    }
}

#[test]
fn the_real_startup_log_shows_an_endpoint_that_is_provably_clean() {
    // The positive control at the REAL site. Without it, a call site that emitted
    // "<redacted>" unconditionally would satisfy the test above completely.
    let (stdout, stderr) = start_daemon_with("http://127.0.0.1:9200", "clean");

    assert!(
        stdout.contains("ES endpoint:"),
        "the line under test was never emitted: {stdout} / {stderr}"
    );
    assert!(
        stdout.contains("ES endpoint: http://127.0.0.1:9200"),
        "a provably clean endpoint must be shown, not withheld: {stdout}"
    );
}

#[test]
fn a_surplus_slash_authority_is_withheld_at_the_real_site() {
    // The regression for the raw-authority/parser disagreement, asserted where it
    // would actually be disclosed rather than only in the helper. Before the fix
    // this endpoint reached the log as "http://127.0.0.1:9200".
    let (stdout, _stderr) = start_daemon_with("http:///@127.0.0.1:9200", "surplus");

    assert!(
        stdout.contains("ES endpoint:"),
        "the line under test was never emitted: {stdout}"
    );
    assert!(
        stdout.contains("ES endpoint: <redacted>"),
        "an ambiguous authority carrying userinfo must be withheld: {stdout}"
    );
}
