//! Product-path regression: when a spool operation fails with an OS error, the
//! errno must reach the operator's log.
//!
//! The unit tests beside `error_for_log` pin the rendering. This one pins the
//! CALL SITES, which those cannot reach: it runs the real binary, makes real
//! spool operations fail with a real `EACCES`, and reads the real stderr.
//!
//! Measured before this was written, with the same harness: without the helper
//! **0** log lines carried `(os error`; with it, **14** did. The spool path in
//! those lines is unchanged either way — it comes from the outer context and
//! predates this change.

// This whole file is Unix-only: it uses PermissionsExt and libc::geteuid, and
// `libc` is a cfg(unix) dependency of this crate. Without this guard the file is
// still COMPILED on the Windows CI target, where it fails.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c2 in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Runs the agent with a spool it can write to, then revokes write permission on
/// the spool directory so publication cannot create its reserved file. Returns
/// the agent's stderr.
fn run_until_spool_publication_fails(dir: &Path) -> String {
    let spool = dir.join("spool");
    fs::create_dir_all(&spool).expect("create spool dir");

    let config = dir.join("rigsignal.toml");
    // Rotate on every record so publication — which must create a new file in
    // the spool directory — is attempted on each tick.
    fs::write(
        &config,
        format!(
            "[elasticsearch]\nendpoint = \"\"\n\n[output]\nmode = \"spool\"\n\
             spool_dir = \"{}\"\nmax_file_bytes = 1\nmax_file_age_secs = 1\n",
            spool.display()
        ),
    )
    .expect("write config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rigsignal-agent"))
        .arg("--config")
        .arg(&config)
        .arg("--log-level")
        .arg("info")
        .env("XDG_CONFIG_HOME", dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent");

    std::thread::sleep(Duration::from_secs(3));
    fs::set_permissions(&spool, fs::Permissions::from_mode(0o500)).expect("revoke write");
    std::thread::sleep(Duration::from_secs(3));

    let _ = child.kill();
    // wait_with_output reads the pipe to EOF and reaps the child. Killing and
    // then only polling try_wait leaves a zombie on any path that gives up,
    // which is what clippy::zombie_processes objects to.
    let output = child.wait_with_output().expect("reap agent");

    // Restore so the temporary directory can be removed.
    let _ = fs::set_permissions(&spool, fs::Permissions::from_mode(0o700));
    strip_ansi(&String::from_utf8_lossy(&output.stderr))
}

#[test]
fn spool_failure_puts_the_errno_in_the_log() {
    // Permission bits do not constrain root, so the fault this test installs
    // would not fire and every assertion below would pass without testing
    // anything.
    //
    // HONEST LIMITATION, measured rather than assumed: libtest captures this
    // message when the test passes, so under a default `cargo test` this reports
    // `1 passed` with NO skip notice; only `--nocapture` shows it. An earlier
    // version of this comment claimed it "skips loudly" and that was false. The
    // wiring is therefore guarded on every platform and privilege level by
    // `every_spool_warning_is_wired_through_the_safe_renderer`, which reads the
    // source instead of running the binary; this test adds runtime evidence
    // where it can, and nothing where it cannot.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!(
            "SKIPPED spool_failure_puts_the_errno_in_the_log: running as root, \
             where a read-only directory does not deny writes and the fault \
             cannot be installed."
        );
        return;
    }

    let dir = std::env::temp_dir().join(format!("rigsignal-errno-log-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create work dir");

    let stderr = run_until_spool_publication_fails(&dir);

    // ASSERT THE SETUP FIRST. If no spool warning was produced, the fault never
    // fired and everything after this is vacuous.
    let warn_lines: Vec<&str> = stderr
        .lines()
        .filter(|l| {
            l.contains("spool error")
                || l.contains("spool rotation error")
                || l.contains("Failed to ship")
                || l.contains("Failed to finalize spool files")
        })
        .collect();
    assert!(
        !warn_lines.is_empty(),
        "no spool warning was produced, so this test proved nothing. stderr was:\n{stderr}"
    );

    // EVERY warning produced by this fault must name the errno, not merely one
    // of them. Asserting "at least one" let a mutation through that wired only
    // the tick-rotation site and reverted the other six.
    let without_errno: Vec<&&str> = warn_lines
        .iter()
        .filter(|l| !l.contains("(os error"))
        .collect();
    assert!(
        without_errno.is_empty(),
        "{} of {} spool warnings carried no OS error, so those call sites are \
         not wired through the safe renderer:\n{}",
        without_errno.len(),
        warn_lines.len(),
        without_errno
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );
    let with_errno: Vec<&&str> = warn_lines
        .iter()
        .filter(|l| l.contains("(os error"))
        .collect();

    // And the failure really was the permission one this harness installs, not
    // some other error that happens to carry an errno.
    assert!(
        with_errno
            .iter()
            .any(|l| l.contains("Permission denied (os error 13)")),
        "expected the EACCES this harness installs:\n{}",
        with_errno
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );

    let _ = fs::remove_dir_all(&dir);
}
