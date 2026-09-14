//! `diagnose` must not put a credential-bearing endpoint on either of its two
//! surfaces.
//!
//! Both surfaces matter and they are different: the report goes to stdout, and
//! `note!` also emits through the tracing subscriber, which writes to stderr and
//! lands in the journal when the agent runs under a unit.
//!
//! This drives the real binary with a real credential-bearing endpoint rather than
//! asserting on a helper, because the leak this pins did not come from the helper:
//! it came from rendering the anyhow chain, whose middle layer is reqwest's error
//! carrying the full request URL.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Port 9 (discard) is closed on the loopback interface, so the ping fails fast.
/// A host that DROPs instead of refusing would make this a 30 s test (the client
/// timeout), not a failing one.
const CONFIG: &str = "[elasticsearch]\n\
endpoint = \"http://spooky:CANARYUSERINFO@127.0.0.1:9/?api_key=CANARYQUERY\"\n\
api_key = \"CANARYKEYFIELD\"\n";

fn temp_config() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rigsignal-diagnose-redaction-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("rigsignal.toml");
    fs::write(&path, CONFIG).expect("write config");
    path
}

#[test]
fn diagnose_leaks_no_endpoint_credential_to_stdout_or_stderr() {
    let config = temp_config();
    let output = Command::new(env!("CARGO_BIN_EXE_rigsignal-agent"))
        .args(["--config".as_ref(), config.as_os_str()])
        .arg("diagnose")
        .output()
        .expect("diagnose runs");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    // Assert the SETUP, not just the outcome: an empty report would satisfy every
    // absence check below while proving nothing at all.
    assert!(
        stdout.contains("RigSignal Diagnostic Report"),
        "diagnose produced no report; the absence assertions below would be vacuous. \
         stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        stdout.contains("UNREACHABLE"),
        "the ping was expected to fail against a closed port, so the error-rendering \
         path -- the one that actually leaked -- was never exercised. stdout: {stdout}"
    );

    for canary in ["CANARYUSERINFO", "CANARYQUERY", "CANARYKEYFIELD"] {
        assert!(
            !stdout.contains(canary),
            "{canary} reached the diagnose report: {stdout}"
        );
        assert!(
            !stderr.contains(canary),
            "{canary} reached the journal surface: {stderr}"
        );
    }

    let _ = fs::remove_dir_all(config.parent().expect("parent"));
}
