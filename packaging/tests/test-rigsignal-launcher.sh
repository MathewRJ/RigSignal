#!/usr/bin/env bash
set -euo pipefail

launcher_dir=$(dirname "$0")/..
launcher="$(cd "$launcher_dir"; pwd)/rigsignal-launcher.sh"
generation="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
test_tmp="$(mktemp -d)"

cleanup() {
    rm -rf "$test_tmp"
}
trap cleanup EXIT

plain="$($launcher status 2>&1 || true)"
case "$plain" in *"Agent"*) ;; *) echo "plain status no longer dispatches cmd_status" >&2; exit 1 ;; esac

expect_reserved() {
    local output status
    set +e
    output="$($launcher status "$@" 2>&1)"
    status=$?
    set -e
    [ "$status" -ne 0 ] || { echo "reserved form unexpectedly succeeded: $*" >&2; exit 1; }
    case "$output" in *"not yet available"*) ;; *) echo "valid reserved form was not recognized: $*" >&2; exit 1 ;; esac
}

expect_rejected() {
    local output status
    set +e
    output="$($launcher status "$@" 2>&1)"
    status=$?
    set -e
    [ "$status" -ne 0 ] || { echo "invalid form unexpectedly succeeded: $*" >&2; exit 1; }
    case "$output" in *"Agent"*) echo "invalid form invoked cmd_status: $*" >&2; exit 1 ;; esac
}

expect_reserved handshake recheck
expect_reserved handshake recheck "$generation"
expect_rejected handshake
expect_rejected handshake recheck "${generation^^}"
expect_rejected handshake recheck "${generation:0:63}"
expect_rejected handshake recheck "${generation}a"
expect_rejected handshake recheck "$(printf 'g%.0s' {1..64})"
expect_rejected handshake recheck "$generation" extra
expect_rejected something else

# Positional parameters are never reparsed as shell code, even if a hostile
# launcher environment supplies a surprising IFS value.
marker="$test_tmp/injection-marker"
injection="$(printf '%s%s%s%s' '$' '(touch ' "$marker" ')')"
expect_rejected handshake recheck "$injection"
[ ! -e "$marker" ] || { echo "generation argument was executed by the launcher" >&2; exit 1; }

set +e
ifs_output="$(IFS='/' "$launcher" status handshake recheck "$generation" 2>&1)"
ifs_status=$?
set -e
[ "$ifs_status" -ne 0 ] || { echo "IFS variant unexpectedly succeeded" >&2; exit 1; }
case "$ifs_output" in *"not yet available"*) ;; *) echo "IFS variant was not recognized" >&2; exit 1 ;; esac

test_home="$test_tmp/home"
test_bin="$test_tmp/bin"
mkdir -p "$test_home" "$test_bin"
printf '%s\n' '#!/usr/bin/env bash' \
    'if [ "$1" = "-c" ]; then exec /usr/bin/python3 "$@"; fi' \
    'if [ "${ES_TEST_VERSION:-}" = "__unknown__" ] && [ "$4" = "GET" ]; then printf '\''%s\n'\'' '\''200'\'' '\''{"name":"version-hidden"}'\''; exit; fi' \
    'case "$4" in' \
    "    GET) printf '%s\n' '200' \"{\\\"version\\\":{\\\"number\\\":\\\"\${ES_TEST_VERSION:-9.4.3}\\\"}}\" ;;" \
    "    POST) printf '%s\n' '200' '{\"has_all_requested\":true}' ;;" \
    "    *) printf '%s\n' '404' '{}' ;;" \
    'esac' >"$test_bin/python3"
chmod +x "$test_bin/python3"

expect_setup_version() {
    local version expected_status output status version_home
    version="$1"
    expected_status="$2"
    shift 2
    version_home="$test_tmp/version-$version"
    set +e
    output="$(printf 'http://127.0.0.1:9200\ntest-api-key\n' | \
        env SUDO_USER='' HOME="$version_home" XDG_CONFIG_HOME="$version_home/.config" \
        ES_TEST_VERSION="$version" PATH="$test_bin:/usr/bin:/bin" "$launcher" setup "$@" 2>&1)"
    status=$?
    set -e
    if [ "$expected_status" = "accepted" ]; then
        [ "$status" -eq 0 ] || { echo "Elasticsearch $version was unexpectedly refused: $output" >&2; exit 1; }
    else
        [ "$status" -ne 0 ] || { echo "Elasticsearch $version was unexpectedly accepted" >&2; exit 1; }
        case "$output" in *"requires 9.4.3 or newer"*) ;; *) echo "Elasticsearch $version was not refused by the supported floor: $output" >&2; exit 1 ;; esac
    fi
}

# The supported Elasticsearch floor rejects older releases while accepting the
# floor itself and newer releases.
expect_setup_version 9.4.2 refused
expect_setup_version 9.4.3 accepted
expect_setup_version 9.4.5 accepted

# An unknown version is refused by default, can be accepted explicitly with a
# prominent risk warning, and the escape hatch never rescues a known-old release.
unknown_home="$test_tmp/version-unknown-default"
set +e
unknown_output="$(printf 'http://127.0.0.1:9200\ntest-api-key\n' | \
    env SUDO_USER='' HOME="$unknown_home" XDG_CONFIG_HOME="$unknown_home/.config" \
    ES_TEST_VERSION='__unknown__' PATH="$test_bin:/usr/bin:/bin" "$launcher" setup 2>&1)"
unknown_status=$?
set -e
[ "$unknown_status" -ne 0 ] || { echo "unknown Elasticsearch version was accepted without an override" >&2; exit 1; }
case "$unknown_output" in
    *"requires 9.4.3 or newer"*) ;;
    *) echo "unknown Elasticsearch version refusal did not name the supported floor: $unknown_output" >&2; exit 1 ;;
esac

unknown_override_home="$test_tmp/version-unknown-override"
set +e
unknown_override_output="$(printf 'http://127.0.0.1:9200\ntest-api-key\n' | \
    env SUDO_USER='' HOME="$unknown_override_home" XDG_CONFIG_HOME="$unknown_override_home/.config" \
    ES_TEST_VERSION='__unknown__' PATH="$test_bin:/usr/bin:/bin" "$launcher" setup --allow-unknown-version 2>&1)"
unknown_override_status=$?
set -e
[ "$unknown_override_status" -eq 0 ] || { echo "unknown Elasticsearch version was refused despite the override: $unknown_override_output" >&2; exit 1; }
case "$unknown_override_output" in
    *"floor 9.4.3 could NOT be verified"*"accepting the compatibility risk"*) ;;
    *) echo "unknown Elasticsearch version override did not emit the required risk warning: $unknown_override_output" >&2; exit 1 ;;
esac

expect_setup_version 9.4.2 refused --allow-unknown-version

if ! (
    cd "$test_tmp"
    printf 'http://127.0.0.1:9200\ntest-api-key\n' | \
        env SUDO_USER='' HOME="$test_home" XDG_CONFIG_HOME='relative/config' \
        RIGSIGNAL_DEBUG=0 PATH="$test_bin:/usr/bin:/bin" "$launcher" setup
); then
    echo "relative XDG_CONFIG_HOME setup failed" >&2
    exit 1
fi
[ -f "$test_home/.config/rigsignal/rigsignal.toml" ] || {
    echo "relative XDG_CONFIG_HOME did not fall back to HOME/.config" >&2
    exit 1
}
[ ! -e "$test_tmp/relative/config/rigsignal/rigsignal.toml" ] || {
    echo "relative XDG_CONFIG_HOME was used as a config path" >&2
    exit 1
}

# Setup rejects a malformed API-key token before it can be sent or persisted.
bad_key_home="$test_tmp/bad-key-home"
set +e
bad_key_output="$(printf 'http://127.0.0.1:9200\nbad key\n' | env SUDO_USER='' HOME="$bad_key_home" XDG_CONFIG_HOME="$bad_key_home/.config" PATH="$test_bin:/usr/bin:/bin" "$launcher" setup 2>&1)"
bad_key_status=$?
set -e
if [ "$bad_key_status" -eq 0 ]; then
    echo "malformed API key was accepted" >&2
    exit 1
fi
case "$bad_key_output" in
    *"invalid shape"*) ;;
    *)
        echo "malformed API key was not rejected before validation" >&2
        exit 1
        ;;
esac
[ ! -e "$bad_key_home/.config/rigsignal/rigsignal.toml" ] || { echo "malformed API key was persisted" >&2; exit 1; }

# ── eBPF start must not report success for a daemon that is not staying up ────
#
# `systemctl start` returns as soon as a Type=simple unit has FORKED. The shipped
# ebpf_start reported "[OK] eBPF daemon started" on that alone, taking no sample
# at all; the configuration-sync site took exactly one, immediately, which
# measured 80/80 false success against a unit that was dying.
#
# The shims below model a CLOCK, like the agent-side scenarios: the sleep shim
# advances it and returns at once, and every is-active answer is a function of it.
# A wait loop that stopped spacing its samples would otherwise read one instant
# three times and call a crash loop healthy, and a fixture keyed on call count
# could not tell the difference.

ebpf_tmp="$test_tmp/ebpf"
mkdir -p "$ebpf_tmp/bin" "$ebpf_tmp/state"

cat > "$ebpf_tmp/bin/sleep" <<'SH'
#!/bin/sh
# Record the REQUESTED duration, not merely that a call happened: a loop that
# changed `sleep 1` to `sleep 0` would still satisfy a call-count assertion while
# sampling a single instant repeatedly.
printf '%s\n' "${1-}" >> "$RS_TEST_STATE/durations"
# Also attribute the sleep to a PHASE. cmd_start runs the agent wait and the
# eBPF wait in ONE launcher invocation, so a whole-run count measures both and
# moves whenever either wait changes. The eBPF phase is delimited by the first
# system-scoped systemctl call -- the agent half is entirely `--user` -- which
# is what sets this marker.
[ -f "$RS_TEST_STATE/ebpf-phase" ] &&
    printf '%s\n' "${1-}" >> "$RS_TEST_STATE/durations-ebpf"
t=$(cat "$RS_TEST_STATE/clock" 2>/dev/null || echo 0)
echo $((t + 1)) > "$RS_TEST_STATE/clock"
exit 0
SH
chmod +x "$ebpf_tmp/bin/sleep"

cat > "$ebpf_tmp/bin/sudo" <<'SH'
#!/bin/sh
# Drop sudo's own options and run the rest through the shim PATH, so the
# systemctl shim answers. Records whether -n was used, because the wait samples
# must be non-interactive.
[ "${1-}" = "-n" ] && printf 'n\n' >> "$RS_TEST_STATE/sudo-n"
while [ $# -gt 0 ]; do
    case "$1" in
        -*) shift ;;
        *)  break ;;
    esac
done
exec "$@"
SH
chmod +x "$ebpf_tmp/bin/sudo"

cat > "$ebpf_tmp/bin/systemctl" <<'SH'
#!/bin/sh
scope=system
[ "${1-}" = "--user" ] && { scope=user; shift; }
verb="${1-}"; shift
# Every system-scoped call in cmd_start belongs to ebpf_start, which runs AFTER
# wait_agent_active; the agent half uses `--user` throughout. So the first
# system-scoped call is the phase boundary.
#
# TWO whole-run quantities have to be scoped here, not one. The sleep COUNTER is
# what the assertions read. The CLOCK is what the is-active oracle below answers
# from, and the agent wait advances it before ebpf_start is ever reached -- which
# silently disarms every clock-keyed scenario: `crashloop` (t -eq 0) and
# `twotick` (t -lt 2) both stop firing and collapse into the inactive default,
# so a two-sample streak would ship GREEN. Scoping the counter alone fixes a
# LOUD failure and leaves a silent one.
#
# `[ ! -f ]` is load-bearing: this runs on EVERY system-scoped call, so an
# unguarded reset would restart the clock at each sample.
if [ "$scope" = system ] && [ ! -f "$RS_TEST_STATE/ebpf-phase" ]; then
    : > "$RS_TEST_STATE/ebpf-phase"
    echo 0 > "$RS_TEST_STATE/clock"
fi
t=$(cat "$RS_TEST_STATE/clock" 2>/dev/null || echo 0)
case "$scope:$verb" in
    user:start)     exit 0 ;;
    user:is-active) exit 0 ;;   # the agent is healthy in every scenario here
    system:show)
        # `systemctl show -p ConditionResult --value UNIT`
        case "$RS_EBPF_SCENARIO" in
            skipped) printf 'no\n' ;;
            *)       printf 'yes\n' ;;
        esac
        exit 0 ;;
    system:start)
        case "$RS_EBPF_SCENARIO" in
            nostart) exit 1 ;;
            *)       exit 0 ;;
        esac ;;
    system:is-active)
        case "$RS_EBPF_SCENARIO" in
            healthy)   exit 0 ;;
            # Active at the instant of the fork, cycling thereafter: exactly the
            # shape a single immediate sample cannot distinguish from healthy.
            crashloop) [ "$t" -eq 0 ] && exit 0; exit 3 ;;
            # Never three in a row, but active half the time: a two-sample streak
            # would accept this.
            flap)      [ $((t % 2)) -eq 0 ] && exit 0; exit 3 ;;
            # Active for exactly two consecutive samples, then gone. This is the
            # ONLY scenario that separates a three-sample streak from a
            # two-sample one: crashloop and flap never reach two either, so
            # neither can tell those thresholds apart.
            twotick)   [ "$t" -lt 2 ] && exit 0; exit 3 ;;
            *)         exit 3 ;;
        esac ;;
esac
exit 0
SH
chmod +x "$ebpf_tmp/bin/systemctl"

run_ebpf_scenario() {
    rm -rf "$ebpf_tmp/state"
    mkdir -p "$ebpf_tmp/state"
    RS_TEST_STATE="$ebpf_tmp/state" RS_EBPF_SCENARIO="$1" \
        PATH="$ebpf_tmp/bin:/usr/bin:/bin" "$launcher" start 2>&1
}

ebpf_sleeps() {
    # `wc -l < missing` is a REDIRECT failure reported by the shell, which
    # 2>/dev/null on wc does not suppress; test for the file instead.
    # Counts the eBPF phase ONLY. The unscoped whole-run file counts the agent
    # wait too, so this assertion moved when the consecutive-sample start check
    # landed and took the healthy scenario from 2 sleeps to 4.
    if [ -f "$ebpf_tmp/state/durations-ebpf" ]; then
        wc -l < "$ebpf_tmp/state/durations-ebpf"
    else
        echo 0
    fi
}

# Setup assertion: the agent half must succeed in every scenario, otherwise a
# missing eBPF line would be explained by the launcher never reaching ebpf_start
# rather than by the check under test.
healthy_out="$(run_ebpf_scenario healthy)"
case "$healthy_out" in
    *"Agent started"*) ;;
    *) echo "setup: cmd_start never reached ebpf_start" >&2; exit 1 ;;
esac
case "$healthy_out" in
    *"eBPF daemon started"*) ;;
    *) echo "healthy eBPF daemon was not reported as started" >&2; exit 1 ;;
esac
# Three consecutive samples means exactly two sleeps between them.
#
# This count is eBPF-PHASE-SCOPED (see ebpf_sleeps). It used to read the whole
# run and was justified by "wait_agent_active contributes none here because its
# first sample succeeds" -- a premise that expired when the agent wait began
# requiring consecutive samples, taking this from 2 to 4. Do not reintroduce a
# whole-run measurement here, and do not fix a mismatch by changing the expected
# number: the count must measure the eBPF wait alone.
[ "$(ebpf_sleeps)" -eq 2 ] || {
    echo "healthy scenario took $(ebpf_sleeps) sleeps, expected 2 (three consecutive samples)" >&2
    exit 1
}
# Every sample must be non-interactive; a wait that prompts would hang a start.
[ -s "$ebpf_tmp/state/sudo-n" ] || { echo "eBPF wait sampled without sudo -n" >&2; exit 1; }
# And the samples must be a second apart, not zero.
case "$(sort -u "$ebpf_tmp/state/durations-ebpf")" in
    1) ;;
    *) echo "eBPF wait did not space its samples by one second" >&2; exit 1 ;;
esac

# A daemon that is active only at the instant of the fork must NOT be reported as
# started. The absence assertion gets its own case: shell takes the first matching
# arm, so testing presence and absence in one case would let output carrying both
# the warning and the forbidden success line pass.
crash_out="$(run_ebpf_scenario crashloop)"
case "$crash_out" in
    *"eBPF daemon started ("*)
        echo "crash-looping eBPF daemon was reported as started" >&2; exit 1 ;;
esac
case "$crash_out" in
    *"did not stay active"*) ;;
    *) echo "crash-looping eBPF daemon produced no warning" >&2; exit 1 ;;
esac

# Active half the time but never three samples running is still a failure.
flap_out="$(run_ebpf_scenario flap)"
case "$flap_out" in
    *"eBPF daemon started ("*)
        echo "flapping eBPF daemon was reported as started" >&2; exit 1 ;;
esac

# Two consecutive samples are not enough. Without this scenario the streak
# threshold could be lowered to two and nothing above would notice.
twotick_out="$(run_ebpf_scenario twotick)"
case "$twotick_out" in
    *"eBPF daemon started ("*)
        echo "eBPF daemon active for only two samples was reported as started" >&2; exit 1 ;;
esac

# A unit skipped by its own ConditionPathExists is not a failure to report as one,
# and it must be detected WITHOUT paying the full poll: this is the ordinary case
# on a machine with no eBPF binary, and twelve seconds would be added to every
# `rigsignal start`.
skip_out="$(run_ebpf_scenario skipped)"
case "$skip_out" in
    *"eBPF daemon started ("*)
        echo "skipped eBPF unit was reported as started" >&2; exit 1 ;;
esac
case "$skip_out" in
    *"binary is absent"*) ;;
    *) echo "skipped eBPF unit was not reported as skipped" >&2; exit 1 ;;
esac
[ "$(ebpf_sleeps)" -eq 0 ] || {
    echo "skipped eBPF unit polled $(ebpf_sleeps) times instead of returning at once" >&2
    exit 1
}

# An unstartable unit keeps its existing message.
nostart_out="$(run_ebpf_scenario nostart)"
case "$nostart_out" in
    *"eBPF daemon started ("*)
        echo "unstartable eBPF unit was reported as started" >&2; exit 1 ;;
esac
case "$nostart_out" in
    *"no sudo/polkit"*) ;;
    *) echo "unstartable eBPF unit lost its diagnostic" >&2; exit 1 ;;
esac

# The configuration-sync site cannot be reached by the scenarios above: it sits
# inside synchronize_ebpf_system_config, behind privilege elevation, a read-only
# filesystem toggle and a CA rewrite. It is pinned by reading the source instead,
# which is WEAKER and is labelled as such -- it proves the call shape, not the
# behaviour. Without it the single-sample check could be restored there and every
# scenario above would stay green, because none of them execute that line.
launcher_src="$(cat "$launcher")"
case "$launcher_src" in
    *'systemctl start "$EBPF_UNIT" && '*'is-active'*)
        echo "the eBPF sync site still pairs start with one immediate is-active" >&2
        exit 1 ;;
esac
sync_region="$(sed -n '/^synchronize_ebpf_system_config()/,/^}/p' "$launcher")"
case "$sync_region" in
    *"wait_ebpf_active"*) ;;
    *) echo "the eBPF sync site does not use wait_ebpf_active" >&2; exit 1 ;;
esac
# A skipped unit must not roll the configuration transaction back: an absent
# binary says nothing about the configuration just written.
# Match the variable and its comparison ADJACENTLY. An earlier version of this
# guard allowed anything between them, and the function has more than twenty
# later `= "1"` tests on unrelated variables -- so it matched one of those and
# passed against a mutation of the very comparison it pins. A glob with a gap in
# it asserts far less than it appears to.
case "$sync_region" in
    *'"$_sync_ebpf_rc" = "1"'*) ;;
    *) echo "the eBPF sync site does not separate 'did not stay active' from 'skipped'" >&2; exit 1 ;;
esac

echo "rigsignal eBPF active-check guard: PASS"

echo "rigsignal launcher handshake status guard: PASS"

# ── cmd_start must not report success for a unit that is not staying active ───
#
# A unit under Restart= is genuinely active for a moment on every restart cycle,
# so a single is-active sample is true of a crash-looping unit. systemd reports
# that moment correctly; the launcher's question was the wrong one.
#
# The shims below model a CLOCK rather than a call count: the sleep shim advances
# it and returns immediately, and every scenario answer is a function of it. That
# is deliberate. The fix depends on its samples being separated in time, so a wait
# loop that stopped sleeping would read one tick three times and the crash-loop
# scenario would pass. A fixture keyed on call count could not see that, and would
# assert the outcome while leaving the constraint that produces it untested.

start_tmp="$test_tmp/start"
mkdir -p "$start_tmp/bin" "$start_tmp/state"

cat > "$start_tmp/bin/sleep" <<'SH'
#!/bin/sh
# Record the REQUESTED duration, not merely the fact of a call. A shim that
# ignores its argument cannot tell `sleep 1` from `sleep 0`, so a wait loop that
# stopped spacing its samples would still satisfy a call-count assertion while
# sampling one instant three times.
printf '%s\n' "${1-}" >> "$RS_TEST_STATE/durations"
t=$(cat "$RS_TEST_STATE/clock" 2>/dev/null || echo 0)
echo $((t + 1)) > "$RS_TEST_STATE/clock"
n=$(cat "$RS_TEST_STATE/sleeps" 2>/dev/null || echo 0)
echo $((n + 1)) > "$RS_TEST_STATE/sleeps"
exit 0
SH

# Coverage, MEASURED by mutating one statement of the fix at a time and running
# each scenario ALONE (the suite stops at its first failure, so a whole-suite run
# credits scenarios that never executed). CATCH = that scenario goes red.
#
#  mutation                              healthy fastloop slowfail twotick reset norestarts latestart
#  streak -ge 3 -> -ge 2                    .       .      CATCH   CATCH     .       .         .
#  restart-counter check deleted            .       .      CATCH     .       .       .         .
#  any counter CHANGE is failure (-ne)      .       .        .       .     CATCH     .         .
#  poll bound -lt 12 -> -lt 10              .       .        .       .       .       .       CATCH
#  exit status reverted to always 0         .     CATCH    CATCH   CATCH     .       .         .
#  sleep 1 -> sleep 0                     CATCH   CATCH    CATCH   CATCH   CATCH   CATCH     CATCH
#  warning branch also prints success       .     CATCH    CATCH   CATCH     .       .         .
#  whole fix reverted                       .     CATCH    CATCH   CATCH     .       .         .
#
# Read it this way. twotick pins the sample count at three rather than two --
# fastloop's active window is one sample wide and cannot tell those apart.
# counterreset is the only guard on the difference between a counter that
# INCREASED and one that merely CHANGED, which is the difference between a
# crash loop and a healthy manual start. latestart is the only guard on the poll
# bound. The sleep-duration assertion is what makes `sleep 0` visible at all,
# and it fires everywhere because a loop that does not space its samples
# invalidates every scenario at once.
#
# The full-revert row is deliberately not all CATCH: the old code succeeded for
# a healthy unit, a reset counter, an absent counter and a slow start, and those
# four cells SHOULD stay `.`. Only the three crash-loop scenarios distinguish the
# revisions by outcome. An earlier version of this table showed five CATCHes
# there, but they came from a precondition firing before the output assertion --
# the implementations differing in whether they sleep, not five independent
# detections of false success.
#
start_tmp="$test_tmp/start"
mkdir -p "$start_tmp/bin" "$start_tmp/state"

cat > "$start_tmp/bin/sleep" <<'SH'
#!/bin/sh
# Record the REQUESTED duration, not merely the fact of a call. A shim that
# ignores its argument cannot tell `sleep 1` from `sleep 0`, so a wait loop that
# stopped spacing its samples would still satisfy a call-count assertion while
# sampling one instant three times.
printf '%s\n' "${1-}" >> "$RS_TEST_STATE/durations"
t=$(cat "$RS_TEST_STATE/clock" 2>/dev/null || echo 0)
echo $((t + 1)) > "$RS_TEST_STATE/clock"
n=$(cat "$RS_TEST_STATE/sleeps" 2>/dev/null || echo 0)
echo $((n + 1)) > "$RS_TEST_STATE/sleeps"
exit 0
SH

# Coverage, MEASURED by mutating one statement of the fix at a time and running
# each scenario ALONE (the suite stops at its first failure, so a whole-suite run
# credits scenarios that never executed). CATCH = that scenario goes red.
#
#   mutation                           healthy fastloop slowfail twotick norestarts latestart
#   streak -ge 3 -> -ge 2                 .       .      CATCH    CATCH      .         .
#   restart-counter check deleted         .       .      CATCH      .        .         .
#   counter fail-closed when absent       .       .        .        .      CATCH       .
#   poll bound -lt 12 -> -lt 10           .       .        .        .        .       CATCH
#   exit status reverted to always 0      .     CATCH    CATCH    CATCH      .         .
#   whole fix reverted                  CATCH   CATCH    CATCH    CATCH    CATCH       .
#
# Read it this way: twotick is what pins the sample count at three rather than
# two -- fastloop's active window is one sample wide and cannot tell those
# apart, so without twotick the constant would be unguarded. slowfail catches a
# weakened streak as well as a deleted counter, because the counter can only
# observe a restart if the loop is still sampling when it happens; the two
# halves are not independent. latestart is the only guard on the poll bound, and
# it does not catch a full revert -- correctly, since the old code accepted a
# slow start too.
cat > "$start_tmp/bin/systemctl" <<'SH'
#!/bin/sh
t=$(cat "$RS_TEST_STATE/clock" 2>/dev/null || echo 0)
case " $* " in
    *" is-active "*)
        case "$RS_SCENARIO" in
            fastloop)  if [ $((t % 5)) -eq 0 ]; then exit 0; fi; echo activating; exit 3 ;;
            twotick)   if [ $((t % 5)) -le 1 ]; then exit 0; fi; echo activating; exit 3 ;;
            counterreset) exit 0 ;;
            latestart) if [ "$t" -ge 9 ];        then exit 0; fi; echo inactive;   exit 3 ;;
            *) exit 0 ;;
        esac ;;
    *" NRestarts "*)
        case "$RS_SCENARIO" in
            nonrestarts) printf '' ;;
            slowfail)    if [ "$t" -ge 2 ]; then echo 1; else echo 0; fi ;;
            counterreset) if [ "$t" -eq 0 ]; then echo 7; else echo 0; fi ;;
            *)           echo 0 ;;
        esac
        exit 0 ;;
esac
exit 0
SH

# The privilege helper is stubbed as unavailable so the optional eBPF branch of
# cmd_start degrades instead of reaching the real system.
printf '%s\n' '#!/bin/sh' 'exit 1' > "$start_tmp/bin/sudo"
chmod +x "$start_tmp/bin/sleep" "$start_tmp/bin/systemctl" "$start_tmp/bin/sudo"

expect_start() {   # $1 = scenario, $2 = ok|notok, $3 = description
    local scenario="$1" want="$2" desc="$3" output sleeps status
    echo 0 > "$start_tmp/state/clock"
    echo 0 > "$start_tmp/state/sleeps"
    : > "$start_tmp/state/durations"
    set +e
    output="$(RS_SCENARIO="$scenario" RS_TEST_STATE="$start_tmp/state" \
              PATH="$start_tmp/bin:$PATH" "$launcher" start 2>&1)"
    status=$?
    set -e
    sleeps="$(cat "$start_tmp/state/sleeps" 2>/dev/null || echo 0)"

    # Assert the SETUP, not only the outcome. Two separate things must hold:
    # the loop must sleep between samples, and each sleep must actually request
    # the second the fix depends on. Checking only that sleep was CALLED accepts
    # `sleep 0`, which samples one instant three times and reports a crash loop
    # as healthy.
    while read -r _d; do
        case "$_d" in
            ""|*[!0-9.]*) echo "start/$scenario ($desc): sleep called with a non-numeric duration: '$_d'" >&2; exit 1 ;;
        esac
        awk -v v="$_d" 'BEGIN { exit !(v + 0 >= 1) }' || {
            echo "start/$scenario ($desc): wait loop slept ${_d}s — samples are not separated by the required second" >&2
            exit 1
        }
    done < "$start_tmp/state/durations"

    case "$want" in
        ok)
            case "$output" in
                *"Agent started"*) ;;
                *) echo "start/$scenario ($desc): expected success, got: $output" >&2; exit 1 ;;
            esac
            [ "$status" -eq 0 ] || { echo "start/$scenario ($desc): healthy start exited $status" >&2; exit 1; } ;;
        notok)
            # ABSENCE first, and in its own case. A single case listing both
            # patterns takes whichever arm matches first, so output carrying the
            # warning AND the forbidden success line was accepted by the warning
            # arm before the rejection arm could run.
            case "$output" in
                *"Agent started"*) echo "start/$scenario ($desc): reported success for a unit that is not staying active" >&2; exit 1 ;;
            esac
            case "$output" in
                *"did not stay active"*) ;;
                *) echo "start/$scenario ($desc): expected the not-staying-active warning, got: $output" >&2; exit 1 ;;
            esac
            # An exit status is a report. A warning on stderr paired with exit 0
            # is still a machine-readable claim of success.
            [ "$status" -ne 0 ] || { echo "start/$scenario ($desc): warned on stderr but still exited 0" >&2; exit 1; }
            # A rejection is only meaningful if the loop actually sampled across
            # time. (Asserted here and not for the ok arm: a launcher that
            # returns on the first active sample sleeps zero times and is still
            # correct for a healthy unit, so requiring a sleep there would red
            # the ok cases for the wrong reason.)
            [ "$sleeps" -gt 0 ] || { echo "start/$scenario ($desc): rejected without sampling across time" >&2; exit 1; } ;;
    esac
}

expect_start healthy     ok    "unit active on every sample"
expect_start fastloop    notok "active window shorter than the poll interval (measured: 0.02-0.53 s)"
expect_start slowfail    notok "active on every sample but the restart counter advances"
expect_start twotick     notok "unit stays up for two samples then fails — pins the three-sample requirement"
expect_start counterreset ok   "restart counter goes 7 -> 0: systemd clears it on a manual start, and that is NOT a restart"
expect_start nonrestarts ok    "NRestarts property absent — must degrade, never fail closed"
expect_start latestart   ok    "slow start still tolerated: inactive until t=9"

echo "rigsignal launcher start honesty guard: PASS (7 scenarios)"
