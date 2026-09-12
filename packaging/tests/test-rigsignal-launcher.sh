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
