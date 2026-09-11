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
never retyped.  Deleting it from the launcher makes this test fail, which is the
property that stops the test drifting into agreement with itself.
"""
from pathlib import Path
import os
import signal
import subprocess
import sys
import tempfile
import time

ENGINE_TAIL = '--admin-credentials-file "$ASSETS_CREDENTIAL_FILE" --agent-binary "$ASSETS_AGENT" "$@" &'


def slice_handler(launcher):
    """The launcher's real assets_cleanup / assets_interrupted definitions."""
    return launcher[
        launcher.index("assets_restore_terminal() {") : launcher.index("assets_snapshot_ca() {")
    ]


def slice_spawn_site(launcher):
    """The launcher's real spawn block, split at the background-job boundary.

    Returns (before, after): everything from the guarding `set +e` up to and
    including the `&` that forks the engine, and everything from the
    registration assignment through the closing `set -e`.  The caller injects
    the signal between them, which is the window.
    """
    tail = launcher.index(ENGINE_TAIL)
    if launcher.count(ENGINE_TAIL) != 1:
        raise SystemExit("spawn-window test: engine invocation is not unique in the launcher")
    start = launcher.rindex("\n    set +e\n", 0, tail) + 1
    fork_end = launcher.index("\n", tail + len(ENGINE_TAIL)) + 1
    end = launcher.index("\n    set -e\n", fork_end) + len("\n    set -e\n")
    before, after = launcher[start:fork_end], launcher[fork_end:end]
    # The real engine cannot run here; substitute a stand-in for the invocation
    # only, leaving the flag handling, the fork and the wait exactly as shipped.
    engine_start = before.index('    python3 "$ASSETS_ENGINE/install_assets.py"')
    return before[:engine_start], after


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
    credential = tmp / "admin.toml"
    credential.write_text('[elasticsearch]\nusername = "probe"\npassword = "probe"\n')
    pidfile = tmp / "engine.pid"
    sentinelfile = tmp / "sentinel.pid"

    # The stand-in engine publishes its pid and then outlives a launcher that
    # exits without cancelling it, so survival is observable from outside.  Its
    # stdio is detached: a surviving engine holding the inherited pipes open
    # would make a probe timeout indistinguishable from a launcher that hung.
    stand_in = (
        f"    sh -c 'printf %s $$ > {pidfile}; exec sleep 30'"
        f" > {tmp / 'engine.out'} 2>&1 < /dev/null &\n"
    )
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
            # The traps stay installed after the engine is reaped, so a signal
            # here is a reachable product state, not a contrived one.
            f"    sh -c 'printf %s $$ > {sentinelfile}; exec sleep 30'"
            f" > {tmp / 'sentinel.out'} 2>&1 < /dev/null &\n" + signal_now
            if where == "post-reap"
            else ""
        )
        + 'exit "$ASSETS_ENGINE_STATUS"\n'
    )

    result = subprocess.run(["dash"], input=probe, text=True, capture_output=True, timeout=60)

    def settle(path):
        """Read a published pid, then report whether it is still running."""
        pid = None
        for _ in range(200):
            if path.exists() and path.read_text().strip():
                pid = int(path.read_text().strip())
                break
            time.sleep(0.02)
        if pid is None:
            return None, False
        alive = True
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, PermissionError):
            alive = False
        if alive:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        return pid, alive

    _, engine_alive = settle(pidfile)
    sentinel_pid, sentinel_alive = (None, None)
    if where == "post-reap":
        # A watchdog escalation takes two seconds; do not declare the sentinel
        # dead before the handler would have had time to kill it.
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


def main():
    launcher = Path(sys.argv[1]).read_text()
    failed = False

    # The defect: a signal inside the window must never leave a live engine
    # without its credential.  Either the credential survives for the engine
    # that is still running, or the engine was cancelled.  Both is fine; a
    # deleted credential beside a live engine is the failure.
    window = run_case(launcher, "window")
    stranded = window["engine_alive"] and not window["credential_exists"]
    print(
        "spawn window: status={status} engine_alive={engine_alive} "
        "credential_exists={credential_exists}".format(**window)
    )
    if stranded:
        print("FAIL: signal in the spawn/registration window deleted the one-shot "
              "administrator credential while the engine was still running")
        failed = True

    # Control: the handler must still cancel and clean up when the signal
    # arrives after registration, so the fix above cannot be had by disabling
    # cancellation.
    after = run_case(launcher, "after")
    print(
        "after registration: status={status} engine_alive={engine_alive} "
        "credential_exists={credential_exists}".format(**after)
    )
    if after["engine_alive"]:
        print("FAIL: a signal after registration left the engine running")
        failed = True
    if after["credential_exists"]:
        print("FAIL: a signal after registration left the one-shot credential behind")
        failed = True

    # Control: with no signal at all the ordinary path must still reap the
    # engine and clean up, so neither the flag nor the resolution can be had by
    # breaking the uninterrupted case.
    quiet = run_case(launcher, "none")
    print(
        "no signal: status={status} engine_alive={engine_alive} "
        "credential_exists={credential_exists}".format(**quiet)
    )
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
