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
//!
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
fn start_daemon_with(endpoint: &str, tag: &str) -> (String, String, String) {
    let dir = temp_dir(tag);
    let config = dir.join("rigsignal.toml");
    fs::write(
        &config,
        format!("[elasticsearch]\nendpoint = \"{endpoint}\"\napi_key = \"{KEYFIELD_SECRET}\"\n"),
    )
    .expect("write config");

    let probe = dir.join("no-such-probe-object.o");
    let output = Command::new(env!("CARGO_BIN_EXE_rigsignal-ebpf"))
        .arg("--config")
        .arg(&config)
        .arg("--probe-path")
        .arg(&probe)
        .arg("--log")
        .arg("info")
        // The daemon prefers RUST_LOG over --log. Inheriting it from whoever ran
        // the suite would let an unrelated environment silence the line under
        // test, and silence passes every absence assertion below.
        .env_remove("RUST_LOG")
        // AND THE VARIABLES THAT REPLACE THE VALUES UNDER TEST. `Config::
        // apply_env_overrides` lets ES_URL, ES_API_KEY and ES_CA_CERT overwrite
        // the endpoint and key this test just wrote into its config file. A
        // non-author review measured the consequence: with ES_URL set, all five
        // assertions of the credential test PASS while the canary endpoint never
        // reaches the log site at all, and with ES_API_KEY set the CANARYKEYFIELD
        // absence check is vacuous and NO test in the suite goes red.
        //
        // The hazard was reasoned about for RUST_LOG, in the comment above, and
        // not carried to the variables that control the values. The setup
        // assertions below answer "did the daemon reach and emit the line"; they
        // do NOT answer "is the line about the endpoint this test supplied",
        // which is what every absence assertion depends on. Removing these is
        // what makes that second question true by construction.
        .env_remove("ES_URL")
        .env_remove("ES_API_KEY")
        .env_remove("ES_CA_CERT")
        .output()
        .expect("run rigsignal-ebpf");

    let marker = probe.to_string_lossy().into_owned();
    let _ = fs::remove_dir_all(&dir);
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        marker,
    )
}

/// Assert the daemon under test actually read THIS test's config, and emitted the
/// line under test.
///
/// The weaker form -- "a line was emitted" -- was measured insufficient: with
/// `ES_URL` set in the environment, every absence assertion passed while the
/// endpoint under test never reached the log site at all. Removing the override
/// variables makes that true by construction; this makes it OBSERVED, by tying
/// the output to a path that exists only for this invocation.
fn assert_setup(stdout: &str, stderr: &str, marker: &str) {
    assert!(
        !stdout.is_empty(),
        "the daemon logged nothing, so every absence assertion is vacuous. stderr: {stderr}"
    );
    assert!(
        stdout.contains("RigSignal eBPF daemon starting"),
        "the daemon did not reach its startup banner: {stdout} / {stderr}"
    );
    assert!(
        stdout.contains(marker),
        "this output is not from THIS test's invocation -- the unique probe path \
         {marker} does not appear, so the config under test may not be the one \
         that was read: {stdout}"
    );
}

/// A PER-TEST positive control: prove THIS test's config path actually reaches the
/// log line, using a clean endpoint on a port unique to the caller.
///
/// Why each withheld-case test needs its own, rather than leaning on the clean
/// test as a sibling: measured, with the `env_remove` calls deleted and `ES_URL`
/// set, only ONE of the four tests here went red -- the clean one. The three
/// withheld cases all passed vacuously, because a withheld endpoint prints
/// `<redacted>` whether it came from this test's config or from an override, and
/// nothing in those tests could tell the difference. `env_remove` closes the
/// channel; this makes each test able to NOTICE if it ever reopens.
fn assert_config_path_is_live(tag: &str, port: u16) {
    let endpoint = format!("http://127.0.0.1:{port}");
    let (stdout, stderr, marker) = start_daemon_with(&endpoint, &format!("{tag}-control"));
    assert_setup(&stdout, &stderr, &marker);
    assert!(
        stdout.contains(&format!("ES endpoint: {endpoint}")),
        "this test's own config did not reach the log line: expected {endpoint}, got {stdout}"
    );
}

#[test]
fn the_real_startup_log_withholds_a_credential_bearing_endpoint() {
    let (stdout, stderr, marker) = start_daemon_with(
        &format!("http://spooky:{USERINFO_SECRET}@127.0.0.1:9/?api_key={QUERY_SECRET}"),
        "credential",
    );
    assert_setup(&stdout, &stderr, &marker);

    // ASSERT THE SETUP FIRST. If the daemon never reached the log site, or the
    // subscriber emitted nothing, every absence check below would pass while
    // proving nothing at all. This is the half that a sibling test in the agent
    // omitted for its stderr surface, leaving three assertions one default away
    // from vacuity.

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

    assert_config_path_is_live("credential", 9301);
}

#[test]
fn the_real_startup_log_shows_an_endpoint_that_is_provably_clean() {
    // The positive control at the REAL site. Without it, a call site that emitted
    // "<redacted>" unconditionally would satisfy the test above completely.
    let (stdout, stderr, marker) = start_daemon_with("http://127.0.0.1:9200", "clean");
    assert_setup(&stdout, &stderr, &marker);

    assert!(
        stdout.contains("ES endpoint: http://127.0.0.1:9200"),
        "a provably clean endpoint must be shown, not withheld: {stdout}"
    );
}

#[test]
fn a_parser_deleted_byte_before_the_slash_is_withheld_at_the_real_site() {
    // The F1 regression. The parser deletes ASCII tab, LF and CR before parsing,
    // so this reaches it as `http:///@127.0.0.1:9200` and its authority is
    // `@127.0.0.1:9200`. Measured emitting `http://127.0.0.1:9200` before the
    // trim-then-refuse guard existed -- the surplus-slash refusal could not see
    // it, because the deleted byte sits in front of the slash.
    let (stdout, stderr, marker) = start_daemon_with("http://\t/@127.0.0.1:9200", "tab");
    assert_setup(&stdout, &stderr, &marker);

    assert!(
        stdout.contains("ES endpoint: <redacted>"),
        "an authority the parser reads as carrying userinfo must be withheld: {stdout}"
    );

    assert_config_path_is_live("tab", 9302);
}

#[test]
fn a_surplus_slash_authority_is_withheld_at_the_real_site() {
    // The regression for the raw-authority/parser disagreement, asserted where it
    // would actually be disclosed rather than only in the helper. Before the fix
    // this endpoint reached the log as "http://127.0.0.1:9200".
    let (stdout, stderr, marker) = start_daemon_with("http:///@127.0.0.1:9200", "surplus");
    assert_setup(&stdout, &stderr, &marker);

    assert!(
        stdout.contains("ES endpoint: <redacted>"),
        "an ambiguous authority carrying userinfo must be withheld: {stdout}"
    );

    assert_config_path_is_live("surplus", 9303);
}
