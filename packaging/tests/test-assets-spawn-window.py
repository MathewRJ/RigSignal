#!/usr/bin/env python3
"""Signal INSIDE the engine spawn/PID-registration window, not after a handshake.

cmt-2026-09-10-rigsignal-8-3.  packaging/rigsignal-launcher.sh spawns the engine
as a background job and assigns ASSETS_ENGINE_PID on the NEXT line.  A signal
delivered between those two statements finds the registration variable at its
initialised empty value, so the interrupt handler takes its no-engine branch,
runs cleanup -- which deletes the one-shot administrator credential -- and exits
reporting success, while the engine it just started is still running and still
expects that file.

Every signal case in test-assets-launcher.sh signals only AFTER a readiness
handshake, so the PID is always registered by then and this window is
structurally unreachable from that harness.

BOTH SIDES OF THE WINDOW ARE THE LAUNCHER'S OWN BYTES.  The handler functions
and the spawn-site block are sliced out of the launcher source; only the engine
invocation itself is replaced by a stand-in, because the real engine cannot run
here.  The ordering that the fix consists of -- declaring the spawn before the
fork and retiring it only after the reap -- is therefore read from the product,
never retyped.  Deleting it from the launcher makes this test fail.

WHAT THIS TEST CANNOT DETECT, stated so its green is not over-read: the probe
supplies its own initialisation of ASSETS_ENGINE_PID/ASSETS_ENGINE_SPAWNED, so
removing the launcher's own initialiser is invisible here.  That statement is
hygiene rather than load-bearing -- the handler reads
${ASSETS_ENGINE_SPAWNED:-0} -- but the reason this test stays green for it is
the fixture, not the default.
"""
from pathlib import Path
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ENGINE_TAIL = '--admin-credentials-file "$ASSETS_CREDENTIAL_FILE" --agent-binary "$ASSETS_AGENT" "$@" &'
ENGINE_HEAD = '    python3 "$ASSETS_ENGINE/install_assets.py"'
HANDLER_START = "assets_restore_terminal() {"
HANDLER_END = "assets_snapshot_ca() {"

# The stand-in engine exits with this when it is NOT cancelled.  A run that
# reaches it in a case that should have been interrupted proves the signal was
# never handled -- which is a false green, not a pass.  See run_case.
NATURAL_EXIT = 17


def refuse(message):
    raise SystemExit(f"spawn-window test: {message}")


def slice_handler(launcher):
    """The launcher's real assets_cleanup / assets_interrupted definitions."""
    for anchor in (HANDLER_START, HANDLER_END):
        if launcher.count(anchor) != 1:
            refuse(f"handler anchor {anchor!r} occurs {launcher.count(anchor)} times, not once")
    return launcher[launcher.index(HANDLER_START) : launcher.index(HANDLER_END)]


def slice_spawn_site(launcher):
    """The launcher's real spawn block, split at the background-job boundary.

    Returns (before, after): everything from the guarding `set +e` up to the
    engine invocation, and everything from the registration assignment through
    the closing `set -e`.  The caller injects the signal between them, which is
    the window.  Only the invocation is dropped; every other statement on both
    sides is the launcher's own text.
    """
    if launcher.count(ENGINE_TAIL) != 1:
        refuse(f"engine invocation occurs {launcher.count(ENGINE_TAIL)} times, not once")
    tail = launcher.index(ENGINE_TAIL)
    after_tail = tail + len(ENGINE_TAIL)
    # The `&` must END its line.  Anything executable after it on the same line
    # would fall inside the discarded region below, and this test would go on
    # passing while the statement it silently dropped reopened the defect.
    if launcher[after_tail : after_tail + 1] != "\n":
        refuse(
            "executable text follows the engine fork on the same line; the slice "
            "would discard it and this test would pass regardless. Put it on its own line."
        )
    fork_end = after_tail + 1
    start = launcher.rindex("\n    set +e\n", 0, tail) + 1
    end = launcher.index("\n    set -e\n", fork_end) + len("\n    set -e\n")
    before, after = launcher[start:fork_end], launcher[fork_end:end]
    if before.count(ENGINE_HEAD) != 1:
        refuse("engine invocation does not begin where expected; the slice anchors have moved")
    # The real engine cannot run here; substitute a stand-in for the invocation
    # only, leaving the flag handling, the fork and the wait exactly as shipped.
    return before[: before.index(ENGINE_HEAD)], after


def settle(path, deadline=4.0):
    """Read a published pid, then report whether it is still running."""
    pid, waited = None, 0.0
    while waited < deadline:
        if path.exists() and path.read_text().strip():
            pid = int(path.read_text().strip())
            break
        time.sleep(0.02)
        waited += 0.02
    if pid is None:
        return None, False
    alive = True
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        alive = False
    return pid, alive


def reap(pid):
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def restore_default_sigint():
    """Give the probe shell a DEFAULT SIGINT disposition.

    A shell that inherits SIGINT ignored cannot enable its own INT trap (POSIX
    2.11), so `kill -INT $$` inside the probe would do nothing, the stand-in
    would run to completion, and every assertion below would accept the result
    -- a false green against an unfixed launcher.  Establish the disposition
    rather than assume it; NATURAL_EXIT then verifies it independently.
    """
    signal.signal(signal.SIGINT, signal.SIG_DFL)


def run_case(launcher, where):
    """Drive one case.  `where` is window | after | none | post-reap.

    post-reap models the hazard the resolution's gate exists for.  Once the
    engine has been reaped, $! still names it, and pid numbers are recycled --
    so an ungated fallback would resolve $! to whatever now holds that number
    and signal a process that is not the engine.  Forcing real pid reuse costs
    millions of children, so the same STATE is reached deterministically
    instead: start an unrelated background job after the reap, which makes $!
    name a live non-engine process, and require that it survives.
    """
    handler = slice_handler(launcher)
    spawn_before, spawn_after = slice_spawn_site(launcher)

    tmp = Path(tempfile.mkdtemp(prefix="rigsignal-spawn-window-"))
    engine_pid = sentinel_pid = None
    try:
        credential = tmp / "admin.toml"
        credential.write_text('[elasticsearch]\nusername = "probe"\npassword = "probe"\n')
        pidfile, sentinelfile = tmp / "engine.pid", tmp / "sentinel.pid"

        # Long-lived only where survival must be observable.  Where the point is
        # that the engine is reaped, it exits at once -- otherwise every such
        # case would pay a full sleep for no signal.  The long form is only ever
        # waited out when the run is already failing.
        outlives = where in ("window", "after")
        body = f"printf %s $$ > {pidfile}; " + (
            f"sleep 30; exit {NATURAL_EXIT}" if outlives else f"exit {NATURAL_EXIT}"
        )
        # Detached stdio: a surviving engine holding the inherited pipes open
        # would make a probe timeout indistinguishable from a launcher that hung.
        stand_in = f"    sh -c '{body}' > {tmp / 'engine.out'} 2>&1 < /dev/null &\n"
        signal_now = "kill -INT $$\n"
        probe = (
            handler
            + f"""
ASSETS_CLEANING=0
ASSETS_CREDENTIAL_FILE={credential}
ASSETS_TMP=
ASSETS_ENGINE_PID="" ASSETS_ENGINE_SPAWNED=0
trap assets_cleanup EXIT
trap 'assets_interrupted INT' INT
"""
            + spawn_before
            + stand_in
            + (signal_now if where == "window" else "")
            + spawn_after.replace(
                '    wait "$ASSETS_ENGINE_PID"\n',
                (signal_now if where == "after" else "") + '    wait "$ASSETS_ENGINE_PID"\n',
            )
            + (
                # The traps stay installed after the engine is reaped, so a
                # signal here is a reachable product state, not a contrived one.
                f"    sh -c 'printf %s $$ > {sentinelfile}; exec sleep 30'"
                f" > {tmp / 'sentinel.out'} 2>&1 < /dev/null &\n" + signal_now
                if where == "post-reap"
                else ""
            )
            + 'exit "$ASSETS_ENGINE_STATUS"\n'
        )

        result = subprocess.run(
            ["dash"],
            input=probe,
            text=True,
            capture_output=True,
            timeout=120,
            preexec_fn=restore_default_sigint,
        )

        engine_pid, engine_alive = settle(pidfile)
        sentinel_alive = None
        if where == "post-reap":
            # A watchdog escalation takes two seconds; do not declare the
            # sentinel dead before the handler would have had time to kill it.
            time.sleep(3)
            sentinel_pid, sentinel_alive = settle(sentinelfile)
        return {
            "status": result.returncode,
            "engine_alive": engine_alive,
            "credential_exists": credential.exists(),
            "sentinel_pid": sentinel_pid,
            "sentinel_alive": sentinel_alive,
            "stderr": result.stderr.strip(),
        }
    finally:
        reap(engine_pid)
        reap(sentinel_pid)
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    launcher = Path(sys.argv[1]).read_text()
    failed = False

    def report(label, case):
        print(
            "{}: status={status} engine_alive={engine_alive} "
            "credential_exists={credential_exists}".format(label, **case)
        )

    def signal_was_handled(label, case):
        """NATURAL_EXIT means the stand-in ran to completion uninterrupted.

        In a case that delivers a signal, that means the signal was never
        handled -- so the assertions below would be judging a run that never
        exercised the handler at all.
        """
        if case["status"] == NATURAL_EXIT:
            print(f"FAIL: {label} never handled its signal (the stand-in ran to completion), "
                  "so this case proved nothing")
            return False
        return True

    # The defect: a signal inside the window must never leave a live engine
    # without its credential.  Either the credential survives for the engine
    # that is still running, or the engine was cancelled.  Both is fine; a
    # deleted credential beside a live engine is the failure.
    window = run_case(launcher, "window")
    report("spawn window", window)
    if not signal_was_handled("spawn window", window):
        failed = True
    elif window["engine_alive"] and not window["credential_exists"]:
        print("FAIL: signal in the spawn/registration window deleted the one-shot "
              "administrator credential while the engine was still running")
        failed = True

    # Control: the handler must still cancel and clean up when the signal
    # arrives after registration, so the fix above cannot be had by disabling
    # cancellation.
    after = run_case(launcher, "after")
    report("after registration", after)
    if not signal_was_handled("after registration", after):
        failed = True
    if after["engine_alive"]:
        print("FAIL: a signal after registration left the engine running")
        failed = True
    if after["credential_exists"]:
        print("FAIL: a signal after registration left the one-shot credential behind")
        failed = True

    # Control: with no signal at all the ordinary path must still reap the
    # engine, preserve its status and clean up, so neither the flag nor the
    # resolution can be had by breaking the uninterrupted case.
    quiet = run_case(launcher, "none")
    report("no signal", quiet)
    if quiet["status"] != NATURAL_EXIT:
        print(f"FAIL: the uninterrupted path returned {quiet['status']}, "
              f"not the engine's own {NATURAL_EXIT}")
        failed = True
    if quiet["engine_alive"]:
        print("FAIL: the uninterrupted path left the engine running")
        failed = True
    if quiet["credential_exists"]:
        print("FAIL: the uninterrupted path left the one-shot credential behind")
        failed = True

    # The resolution must stop the moment the engine has been reaped.  $! goes
    # on naming it, and that number gets recycled, so an ungated fallback would
    # cancel whatever holds it next.  Here an unrelated background job holds it.
    post = run_case(launcher, "post-reap")
    print(
        "post-reap: status={status} sentinel_pid={sentinel_pid} "
        "sentinel_alive={sentinel_alive}".format(**post)
    )
    if post["sentinel_pid"] is None:
        print("FAIL: the post-reap sentinel never started; the case proved nothing")
        failed = True
    elif not post["sentinel_alive"]:
        print("FAIL: a signal after the engine was reaped cancelled an unrelated "
              "process that $! had come to name")
        failed = True

    sys.exit(int(failed))


if __name__ == "__main__":
    main()
