#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(dirname "$0")/../..
repo=$(cd "$repo_dir"; pwd)
launcher="$repo/packaging/rigsignal-launcher.sh"
corpus="$repo/packaging/tests/sidecar-verifier-corpus.tsv"
python3 "$repo/packaging/tests/test-assets-signal-boundary.py" "$launcher"
python3 "$repo/packaging/tests/test-assets-signal-driver.py" "$repo/packaging/tests/assets-signal-driver.py"
python3 "$repo/packaging/tests/test-assets-signal-reporting.py" "$repo/packaging/tests/assets-signal-driver.py"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
home="$tmp/home"; bin="$home/.local/bin"; engine="$home/.local/lib/rigsignal/engine"
mkdir -p "$bin" "$engine" "$tmp/runtime"
cp "$launcher" "$bin/rigsignal"

fail() { printf 'FAIL: %s\n' "$*" >&2; return 1; }
require_status() { if [ "$1" -ne "$2" ]; then fail "$3 (got status $2, expected $1)"; fi; }
require_grep() { if ! grep -q -- "$1" "$2"; then fail "$3"; fi; }
require_line() { if ! grep -qx -- "$1" "$2"; then fail "$3"; fi; }
require_absent() {
    local marker_one=$1 marker_two=$2 grep_status path
    local -a existing_paths=()
    shift 2
    for path in "$@"; do
        if [ -e "$path" ]; then existing_paths+=("$path"); fi
    done
    # A missing surface cannot contain a credential; inspect every surface
    # that exists and fail if grep itself cannot inspect one of them.
    if [ "${#existing_paths[@]}" -eq 0 ]; then return 0; fi
    if grep -R -F -q -e "$marker_one" -e "$marker_two" "${existing_paths[@]}" 2>/dev/null; then
        fail "credential marker leaked into a searched surface"
        return 1
    else
        grep_status=$?
    fi
    if [ "$grep_status" -ne 1 ]; then
        fail "could not inspect a searched credential surface"
        return 1
    fi
}
require_missing_match() {
    local directory=$1 pattern=$2 message=$3 found
    if found=$(find "$directory" -mindepth 1 -name "$pattern" -print -quit); then
        if [ -n "$found" ]; then
            fail "$message: $found"
            return 1
        fi
    else
        fail "$message: could not inspect $directory"
        return 1
    fi
}
wait_for_file() {
    local file=$1 message=$2 attempt
    for attempt in $(seq 1 100); do
        if [ -e "$file" ]; then return 0; fi
        sleep 0.05
    done
    fail "$message"
    return 1
}
run_status() { set +e; "$@"; RUN_STATUS=$?; set -e; }

printf '%s\n' '#!/bin/sh' 'if [ -n "${RIGSIGNAL_TEST_BUILD_INFO+x}" ]; then printf "%s\\n" "$RIGSIGNAL_TEST_BUILD_INFO"; else printf "%s\\n" "{\"name\":\"rigsignal-agent\",\"version\":\"1.2.3\",\"commit\":\"fixture\"}"; fi' >"$bin/rigsignal-agent"
chmod 755 "$bin/rigsignal-agent"
write_success_engine() {
    printf '%s\n' '#!/usr/bin/env python3' 'import os, sys, tomllib' 'args=sys.argv[1:]' 'open(os.environ["RIGSIGNAL_ASSETS_TEST_ARGS"], "w").write("\n".join(args))' 'path=args[args.index("--admin-credentials-file") + 1]' 'value=tomllib.load(open(path, "rb"))' 'assert set(value) == {"elasticsearch"} and set(value["elasticsearch"]) == {"username", "password"}' 'open(os.environ["RIGSIGNAL_ASSETS_TEST_CREDENTIAL"], "w").write("credential-ok\n")' >"$engine/install_assets.py"
    chmod 755 "$engine/install_assets.py"
}
write_success_engine
printf '# adapter\n' >"$engine/asset_adapters.py"
printf 'ENGINE_VERSION = "1.2.3"\nSOURCE_COMMIT = "fixture"\n' >"$engine/_version.py"
printf 'rigsignal-release\n' >"$engine/channel"
bundle="$tmp/bundle.tar.gz"; printf 'offline fixture\n' >"$bundle"
digest=$(sha256sum "$bundle"); digest=${digest%% *}
printf '%s  bundle.tar.gz\n' "$digest" >"$bundle.sha256"
ca="$tmp/ca.pem"; printf '%s\n' '-----BEGIN CERTIFICATE-----' 'fixture' '-----END CERTIFICATE-----' >"$ca"
credentials="$tmp/admin.toml"; printf '%s\n' '[elasticsearch]' 'username = "elastic"' 'password = "source-secret"' >"$credentials"
args="$tmp/engine.args"; credential_probe="$tmp/credential.probe"

run_noninteractive() {
    HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" RIGSIGNAL_ASSETS_TEST_ARGS="$args" RIGSIGNAL_ASSETS_TEST_CREDENTIAL="$credential_probe" "$bin/rigsignal" assets install --bundle "$bundle" --endpoint http://127.0.0.1:9200 --ca-file "$ca" --kibana-endpoint https://kibana.example.invalid --admin-credentials-file "$credentials" --non-interactive "$@"
}

# T-EXIT-4: this is deliberately a launcher-boundary subprocess test.  The
# fixture engine does no network work; its status must pass through the
# background-child wait path exactly, including the persisted-uncertainty 4.
write_exit_engine() {
    printf '%s\n' '#!/usr/bin/env python3' 'import os, sys' 'raise SystemExit(int(os.environ["RIGSIGNAL_TEST_ENGINE_STATUS"]))' >"$engine/install_assets.py"
    chmod 755 "$engine/install_assets.py"
}
for engine_status in 2 3 4; do
    write_exit_engine
    set +e
    RIGSIGNAL_TEST_ENGINE_STATUS="$engine_status" run_noninteractive >"$tmp/engine-status-$engine_status.out" 2>&1
    RUN_STATUS=$?
    set -e
    require_status "$engine_status" "$RUN_STATUS" "engine status $engine_status was not preserved by launcher wait"
done
write_success_engine

# Every corpus assertion is fail-closed: neither a failed command in an &&
# list nor a bare negated grep can make this test pass.
while IFS=$'\t' read -r name encoded expected; do
    if [ -z "$name" ] || [ "${name#\#}" != "$name" ]; then continue; fi
    python3 -c 'import base64, pathlib, sys; pathlib.Path(sys.argv[2]).write_bytes(base64.b64decode(sys.argv[1]))' "$encoded" "$bundle.sha256"
    run_status run_noninteractive >"$tmp/corpus-$name.out" 2>&1
    require_status 2 "$RUN_STATUS" "sidecar corpus $name"
    if [ "$expected" = 1 ]; then
        require_grep 'bundle checksum verification failed' "$tmp/corpus-$name.out" "valid sidecar $name was rejected"
    else
        require_grep 'invalid bundle checksum sidecar' "$tmp/corpus-$name.out" "invalid sidecar $name was accepted"
    fi
done <"$corpus"
printf '%s  bundle.tar.gz\n' "$digest" >"$bundle.sha256"

# Exercise the complete build-info rejection matrix through the actual resolver.
for build_case in valid wrong-name extra-key missing-key non-string bad-json extra-output invalid-leading-zero invalid-empty-id invalid-numeric-prerelease duplicate-key; do
    case "$build_case" in
        valid) build_info='{"name":"rigsignal-agent","version":"1.2.3-alpha.1+build.7","commit":"fixture"}'; wanted=0 ;;
        wrong-name) build_info='{"name":"not-rigsignal-agent","version":"1.2.3","commit":"fixture"}'; wanted=1 ;;
        extra-key) build_info='{"name":"rigsignal-agent","version":"1.2.3","commit":"fixture","extra":"x"}'; wanted=1 ;;
        missing-key) build_info='{"name":"rigsignal-agent","version":"1.2.3"}'; wanted=1 ;;
        non-string) build_info='{"name":"rigsignal-agent","version":123,"commit":"fixture"}'; wanted=1 ;;
        bad-json) build_info='{not json}'; wanted=1 ;;
        extra-output) build_info=$'{"name":"rigsignal-agent","version":"1.2.3","commit":"fixture"}\nextra'; wanted=1 ;;
        invalid-leading-zero) build_info='{"name":"rigsignal-agent","version":"01.2.3","commit":"fixture"}'; wanted=1 ;;
        invalid-empty-id) build_info='{"name":"rigsignal-agent","version":"1.2.3-..","commit":"fixture"}'; wanted=1 ;;
        invalid-numeric-prerelease) build_info='{"name":"rigsignal-agent","version":"1.2.3-alpha.01","commit":"fixture"}'; wanted=1 ;;
        duplicate-key) build_info='{"name":"rigsignal-agent","name":"rigsignal-agent","version":"1.2.3","commit":"fixture"}'; wanted=1 ;;
    esac
    set +e; RIGSIGNAL_TEST_BUILD_INFO="$build_info" run_noninteractive >"$tmp/build-$build_case.out" 2>&1; RUN_STATUS=$?; set -e
    if [ "$wanted" = 0 ]; then
        require_status 0 "$RUN_STATUS" "valid build-info"
    else
        require_status 2 "$RUN_STATUS" "build-info case $build_case"
        require_grep engine_not_installed "$tmp/build-$build_case.out" "build-info case $build_case did not fail at resolver"
    fi
done

# A launcher outside HOME must use /usr, never nearby user-scope artifacts.
mkdir -p "$tmp/system-bin" "$tmp/system-engine"
cp "$launcher" "$tmp/system-bin/rigsignal"
cp "$bin/rigsignal-agent" "$tmp/system-bin/rigsignal-agent"
cp -a "$engine/." "$tmp/system-engine/"
set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" "$tmp/system-bin/rigsignal" assets install --bundle "$bundle" --non-interactive >"$tmp/opposite-scope.out" 2>&1; RUN_STATUS=$?; set -e
require_status 2 "$RUN_STATUS" "opposite-scope resolver"
require_grep engine_not_installed "$tmp/opposite-scope.out" "opposite-scope resolver used nearby user artifacts"

# Stage the hard-coded /usr paths inside a disposable launcher copy.  This runs
# the system-scope resolver branch with a co-scoped agent and engine, while the
# preceding fixture proves it does not borrow the user-scope artifacts.
system_root="$tmp/system-root"
mkdir -p "$system_root/usr/bin" "$system_root/usr/lib/rigsignal/engine" "$tmp/staged-system-bin"
cp "$bin/rigsignal-agent" "$system_root/usr/bin/rigsignal-agent"
cp -a "$engine/." "$system_root/usr/lib/rigsignal/engine/"
sed -e "s|/usr/bin/rigsignal-agent|$system_root/usr/bin/rigsignal-agent|g" \
    -e "s|/usr/lib/rigsignal/engine|$system_root/usr/lib/rigsignal/engine|g" \
    "$launcher" >"$tmp/staged-system-bin/rigsignal"
chmod 755 "$tmp/staged-system-bin/rigsignal"
run_status env HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" RIGSIGNAL_ASSETS_TEST_ARGS="$args" RIGSIGNAL_ASSETS_TEST_CREDENTIAL="$credential_probe" "$tmp/staged-system-bin/rigsignal" assets install --bundle "$bundle" --endpoint http://127.0.0.1:9200 --ca-file "$ca" --kibana-endpoint https://system-kibana.example.invalid --admin-credentials-file "$credentials" --non-interactive >"$tmp/system-scope.out" 2>&1
require_status 0 "$RUN_STATUS" "co-scoped system resolver"
require_line https://system-kibana.example.invalid "$args" "system-scope engine did not run"

set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" "$bin/rigsignal" assets install --bundle "$bundle" --non-interactive </dev/null >"$tmp/noninteractive.out" 2>&1; RUN_STATUS=$?; set -e
require_status 2 "$RUN_STATUS" "noninteractive missing input"
require_grep 'noninteractive input missing' "$tmp/noninteractive.out" "noninteractive mode prompted or accepted missing input"

mkdir -p "$home/.config/rigsignal"
printf '%s\n' '[elasticsearch]' 'endpoint = "http://127.0.0.1:9201"' "ca_cert = \"$ca\"" '' '[kibana]' 'endpoint = "https://persisted-kibana.invalid"' >"$home/.config/rigsignal/rigsignal.toml"
run_status env HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" RIGSIGNAL_ASSETS_TEST_ARGS="$args" RIGSIGNAL_ASSETS_TEST_CREDENTIAL="$credential_probe" "$bin/rigsignal" assets install --bundle "$bundle" --endpoint http://127.0.0.1:9202 --ca-file "$ca" --kibana-endpoint https://explicit-kibana.invalid --admin-credentials-file "$credentials" --non-interactive >"$tmp/explicit.out" 2>&1
require_status 0 "$RUN_STATUS" "explicit assets install"
require_line http://127.0.0.1:9202 "$args" "explicit ES endpoint was not forwarded"
require_line https://explicit-kibana.invalid "$args" "explicit Kibana endpoint was not forwarded"

# Quotes, backslashes, and control characters are refused before any TOML write.
for invalid_endpoint in 'https://evil".invalid' 'https://evil\\.invalid' $'https://evil\t.invalid'; do
    printf '%s\n' '[kibana]' 'endpoint = "https://old-kibana.invalid"' >"$home/.config/rigsignal/rigsignal.toml"
    before=$(sha256sum "$home/.config/rigsignal/rigsignal.toml")
    set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" "$bin/rigsignal" assets install --bundle "$bundle" --endpoint http://127.0.0.1:9200 --ca-file "$ca" --kibana-endpoint "$invalid_endpoint" --admin-credentials-file "$credentials" --non-interactive >"$tmp/injection.out" 2>&1; RUN_STATUS=$?; set -e
    require_status 2 "$RUN_STATUS" "unsafe Kibana endpoint"
    after=$(sha256sum "$home/.config/rigsignal/rigsignal.toml")
    if [ "$before" != "$after" ]; then fail "unsafe Kibana endpoint mutated TOML"; fi
done

# API-key-shaped credentials are setup credentials, never administrator TOML.
# With no bundle, a curl shim also proves rejection happens before remote work.
api_key_credentials="$tmp/api-key.toml"
printf '%s\n' '[elasticsearch]' 'api_key = "not-an-admin-password"' >"$api_key_credentials"
remote_probe="$tmp/api-key-remote.probe"
mkdir -p "$tmp/no-remote-shim"
printf '%s\n' '#!/bin/sh' 'touch "$RIGSIGNAL_ASSETS_REMOTE_PROBE"' 'exit 1' >"$tmp/no-remote-shim/curl"
chmod 755 "$tmp/no-remote-shim/curl"
set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" PATH="$tmp/no-remote-shim:$PATH" RIGSIGNAL_ASSETS_REMOTE_PROBE="$remote_probe" "$bin/rigsignal" assets install --endpoint http://127.0.0.1:9200 --ca-file "$ca" --kibana-endpoint https://kibana.example.invalid --admin-credentials-file "$api_key_credentials" --non-interactive >"$tmp/api-key-credentials.out" 2>&1; RUN_STATUS=$?; set -e
require_status 2 "$RUN_STATUS" "API-key-shaped administrator credentials"
require_grep 'administrator credentials must be exactly \[elasticsearch\] username/password TOML' "$tmp/api-key-credentials.out" "API-key-shaped administrator credentials were not rejected"
if [ -e "$remote_probe" ]; then
    fail "API-key-shaped administrator credentials reached remote work"
    exit 1
fi

rm -f "$home/.config/rigsignal/rigsignal.toml"
if ! printf 'http://127.0.0.1:9200\n%s\nhttps://kibana.example.invalid\nsuccess-admin-marker\nsuccess-password-marker\n' "$ca" | HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" RIGSIGNAL_DEBUG=1 RIGSIGNAL_ASSETS_TEST_ARGS="$args" RIGSIGNAL_ASSETS_TEST_CREDENTIAL="$credential_probe" "$bin/rigsignal" assets install --bundle "$bundle" >"$tmp/success.out" 2>&1; then fail "interactive success invocation"; fi
require_line credential-ok "$credential_probe" "engine did not parse one-shot credentials"
require_line --assets-only "$args" "assets-only flag missing"
require_line --profile "$args" "profile flag missing"
require_line user "$args" "user profile missing"
snapshot=$(awk 'previous == "--bundle" { print; exit } { previous=$0 }' "$args")
case "$snapshot" in "$tmp/runtime"/*) ;; *) fail "bundle was not snapshotted into private TMPDIR";; esac
if [ -e "$snapshot" ]; then fail "bundle snapshot survived cleanup"; fi
require_grep '^endpoint = "https://kibana.example.invalid"$' "$home/.config/rigsignal/rigsignal.toml" "Kibana endpoint was not persisted"
journal_start='2 minutes ago'; journalctl --user --since "$journal_start" -o cat >"$tmp/success.journal" 2>/dev/null || :
require_absent success-admin-marker success-password-marker "$home/.config" "$home/.local/share/rigsignal" "$args" "$tmp/runtime" "$tmp/success.journal"

# This shim reaches both root replacements, then fails the durability stage;
# S4 must restore root and user state and delete privileged temporary files.
mkdir -p "$tmp/ebpf-shim" "$tmp/fake-etc/rigsignal/certs"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$tmp/ebpf-shim/rigsignal-ebpf"
printf '%s\n' '#!/bin/sh' 'root=$RIGSIGNAL_ASSETS_SYSTEM_ROOT; log=$RIGSIGNAL_ASSETS_SUDO_LOG' 'map() { case "$1" in /etc/rigsignal*) printf "%s%s" "$root" "${1#/etc/rigsignal}";; *) printf "%s" "$1";; esac; }' 'op=$1; shift; printf "%s %s\\n" "$op" "$*" >> "$log"' 'case "$op" in' 'steamos-readonly) exit 0;; systemctl) if [ "$1" = is-active ]; then exit 1; fi; exit 0;; python3) exit 1;; mktemp) p=$(map "$1"); mkdir -p "$(dirname "$p")"; mktemp "$p";; *) set -- "$@"; mapped=""; for a in "$@"; do mapped="$mapped $(map "$a")"; done; eval "set -- $mapped"; command "$op" "$@";; esac' >"$tmp/ebpf-shim/sudo"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$tmp/ebpf-shim/steamos-readonly"
chmod 755 "$tmp/ebpf-shim/rigsignal-ebpf" "$tmp/ebpf-shim/sudo" "$tmp/ebpf-shim/steamos-readonly"
printf 'old-root-config\n' >"$tmp/fake-etc/rigsignal/rigsignal.toml"; printf 'old-root-ca\n' >"$tmp/fake-etc/rigsignal/certs/elasticsearch-ca.pem"
printf '%s\n' '[kibana]' 'endpoint = "https://old-kibana.invalid"' >"$home/.config/rigsignal/rigsignal.toml"
sudo_log="$tmp/ebpf-sudo.log"
set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" PATH="$tmp/ebpf-shim:$PATH" RIGSIGNAL_ASSETS_SYSTEM_ROOT="$tmp/fake-etc/rigsignal" RIGSIGNAL_ASSETS_SUDO_LOG="$sudo_log" RIGSIGNAL_ASSETS_TEST_ARGS="$args" RIGSIGNAL_ASSETS_TEST_CREDENTIAL="$credential_probe" "$bin/rigsignal" assets install --bundle "$bundle" --endpoint http://127.0.0.1:9200 --ca-file "$ca" --kibana-endpoint https://new-kibana.invalid --admin-credentials-file "$credentials" --non-interactive >"$tmp/ebpf-fail.out" 2>&1; RUN_STATUS=$?; set -e
require_status 2 "$RUN_STATUS" "late eBPF durability failure"
require_grep 'mv .* /etc/rigsignal/rigsignal.toml' "$sudo_log" "eBPF test failed before root config replacement"
require_grep '^endpoint = "https://old-kibana.invalid"$' "$home/.config/rigsignal/rigsignal.toml" "user config was not rolled back after restored root transaction"
require_grep '^old-root-config$' "$tmp/fake-etc/rigsignal/rigsignal.toml" "root config was not rolled back"
require_line 'steamos-readonly disable' "$sudo_log" "SteamOS readonly disable missing"
require_line 'steamos-readonly enable' "$sudo_log" "SteamOS readonly enable missing"
# These are the exact mktemp templates used by synchronize_ebpf_system_config.
require_missing_match "$tmp/fake-etc/rigsignal/certs" '.elasticsearch-ca.pem.*' "privileged eBPF CA temporary file survived rollback"
require_missing_match "$tmp/fake-etc/rigsignal" '.rigsignal.toml.*' "privileged eBPF config temporary file survived rollback"
require_missing_match "$home/.config/rigsignal" '.rigsignal.toml.assets.*' "user Kibana transaction temporary file survived rollback"
require_missing_match "$home/.config/rigsignal" '.rigsignal-system.*' "user system-sync temporary file survived rollback"

run_status run_noninteractive --repair --upgrade --allow-downgrade >"$tmp/flags.out" 2>&1
require_status 0 "$RUN_STATUS" "transition flag invocation"
require_line --repair "$args" "repair flag missing"; require_line --upgrade "$args" "upgrade flag missing"; require_line --allow-downgrade "$args" "allow-downgrade flag missing"

printf '%s\n' '#!/usr/bin/env python3' 'import sys' 'print("engine fixture stderr", file=sys.stderr)' 'raise SystemExit(2)' >"$engine/install_assets.py"
set +e; printf 'failure-admin-marker\nfailure-password-marker\n' | HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" RIGSIGNAL_ASSETS_TEST_ARGS="$args" RIGSIGNAL_ASSETS_TEST_CREDENTIAL="$credential_probe" "$bin/rigsignal" assets install --bundle "$bundle" --endpoint http://127.0.0.1:9200 --ca-file "$ca" --kibana-endpoint https://kibana.example.invalid >"$tmp/status.out" 2>&1; RUN_STATUS=$?; set -e
require_status 2 "$RUN_STATUS" "engine failure status"
require_grep 'engine fixture stderr' "$tmp/status.out" "engine stderr was lost"
journalctl --user --since "$journal_start" -o cat >"$tmp/failure.journal" 2>/dev/null || :
require_absent failure-admin-marker failure-password-marker "$home/.config" "$home/.local/share/rigsignal" "$args" "$tmp/runtime" "$tmp/failure.journal"

write_signal_engine() {
    printf '%s\n' '#!/usr/bin/env python3' \
        'import os, signal, sys, time' \
        'def interrupted(signum, _frame):' \
        '    with open(os.environ["RIGSIGNAL_ASSETS_SIGNAL_SEEN"], "w", encoding="utf-8") as handle: handle.write(signal.Signals(signum).name + "\n")' \
        '    raise SystemExit(42)' \
        'for item in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM): signal.signal(item, interrupted)' \
        'open(os.environ["RIGSIGNAL_ASSETS_SIGNAL_READY"], "w", encoding="utf-8").write("ready\n")' \
        'while True: time.sleep(1)' >"$engine/install_assets.py"
    chmod 755 "$engine/install_assets.py"
}
signal_driver="$repo/packaging/tests/assets-signal-driver.py"
export RIGSIGNAL_ASSETS_TEST_SCRIPT="$repo/packaging/tests/test-assets-launcher.sh"
export RIGSIGNAL_ASSETS_FIXTURE="$engine/install_assets.py"

# The launcher must forward every supported signal to the engine, then return
# the engine's actual status rather than a trap/cleanup status.
run_signal_status_case() {
    local signal_name ready seen result case_name expected_status expected_signal
    signal_name=$1
    case_name=${2:-$signal_name}
    expected_status=${3:-42}
    expected_signal=${4:-SIG$signal_name}
    ready="$tmp/$case_name.ready"
    seen="$tmp/$case_name.seen"
    rm -f "$ready" "$seen"
    write_signal_engine
    case "$case_name" in
        inherited-int-reproducer|repeated-int-hardening|ignore-hup-hardening|ignore-term-hardening)
            # Preserve the async child's inherited SIG_IGN for INT.
            sed -i 's/(signal.SIGHUP, signal.SIGINT, signal.SIGTERM)/(signal.SIGHUP, signal.SIGTERM)/' "$engine/install_assets.py"
            ;;
    esac
    case "$case_name" in
        ignore-hup-hardening) sed -i '/open(os.environ\["RIGSIGNAL_ASSETS_SIGNAL_READY"\]/i signal.signal(signal.SIGHUP, signal.SIG_IGN)' "$engine/install_assets.py" ;;
        ignore-term-hardening) sed -i '/open(os.environ\["RIGSIGNAL_ASSETS_SIGNAL_READY"\]/i signal.signal(signal.SIGTERM, signal.SIG_IGN)' "$engine/install_assets.py" ;;
    esac
    result="$tmp/$case_name.result"
    rm -f "$result"
    HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" RIGSIGNAL_ASSETS_TEST_ARGS="$args" RIGSIGNAL_ASSETS_TEST_CREDENTIAL="$credential_probe" RIGSIGNAL_ASSETS_SIGNAL_READY="$ready" RIGSIGNAL_ASSETS_SIGNAL_SEEN="$seen" RIGSIGNAL_ASSETS_SIGNAL_RESULT="$result" RIGSIGNAL_ASSETS_SIGNAL_OUT="$tmp/$signal_name.out" RIGSIGNAL_ASSETS_LAUNCHER="$bin/rigsignal" RIGSIGNAL_ASSETS_BUNDLE="$bundle" RIGSIGNAL_ASSETS_CA="$ca" RIGSIGNAL_ASSETS_CREDENTIALS="$credentials" python3 "$signal_driver" "$signal_name" || return $?
    require_line "status=$expected_status" "$result" "$case_name preserved engine status"
    if [ "$expected_signal" = absent ]; then
        if [ -e "$seen" ]; then fail "$case_name unexpectedly acknowledged a signal"; fi
    else
        require_line "$expected_signal" "$seen" "$case_name engine acknowledgement"
    fi
    require_missing_match "$tmp/runtime" 'rigsignal-assets.*' "$signal_name cleanup left the private assets directory"
    printf 'PASS: %s status=%s acknowledgement=%s\n' "$case_name" "$expected_status" "$expected_signal"
}
# Faithful reproduction: INT stays inherited SIG_IGN; TERM escalation is
# acknowledged with exit 42.
run_signal_status_case INT inherited-int-reproducer 42 SIGTERM
# Hardening is separate from the inherited-INT production reproducer.
# A second INT must not interrupt parent reaping.
RIGSIGNAL_ASSETS_REPEAT_SIGNAL=1 run_signal_status_case INT repeated-int-hardening 42 SIGTERM
run_signal_status_case HUP ignore-hup-hardening 42 SIGTERM
run_signal_status_case INT ignore-term-hardening 137 absent

# Prove finally on TimeoutExpired, including when capture itself fails.
for failure in timeout capture; do
    set +e
    RIGSIGNAL_ASSETS_HARNESS_FAILURE="$failure" run_signal_status_case INT "harness-$failure" >"$tmp/harness-$failure.log" 2>&1
    failure_status=$?
    set -e
    require_status 1 "$failure_status" "harness $failure must fail"
    require_grep TimeoutExpired "$tmp/harness-$failure.log" "timeout was not re-raised"
    require_grep 'FINALLY process group absent' "$tmp/harness-$failure.log" "finally did not clean the process group"
    require_grep 'descendants=\[[0-9]' "$tmp/harness-$failure.log" "finally did not reap the orphan engine"
    require_grep 'sha256 ' "$tmp/harness-$failure.log" "timeout hashes missing"
    require_grep SigBlk "$tmp/harness-$failure.log" "timeout signal masks missing"
    if [ "$failure" = capture ]; then
        require_grep 'capture failed:.*injected capture failure' "$tmp/harness-$failure.log" "capture failure was not exercised"
    fi
    printf 'PASS: harness-%s exit=%s; finally reaped descendants and removed group\n' "$failure" "$failure_status"
    # Failed launcher cannot clean its credentials after SIGKILL.
    rm -rf "$tmp/runtime"/rigsignal-assets.*
done
run_signal_status_case HUP
run_signal_status_case INT
run_signal_status_case TERM

# Hold the first cleanup rm long enough to deliver a second signal.  The
# launcher must keep the first engine status and still finish exactly once.
mkdir -p "$tmp/cleanup-shim"
cleanup_ready="$tmp/cleanup.ready"; cleanup_log="$tmp/cleanup.log"
printf '%s\n' '#!/bin/sh' 'for arg in "$@"; do case "$arg" in *"/rigsignal-assets."*) if [ ! -e "$RIGSIGNAL_ASSETS_CLEANUP_READY" ]; then touch "$RIGSIGNAL_ASSETS_CLEANUP_READY"; printf "cleanup\\n" >> "$RIGSIGNAL_ASSETS_CLEANUP_LOG"; kill -INT "$PPID"; sleep 1; fi;; esac; done' 'exec /bin/rm "$@"' >"$tmp/cleanup-shim/rm"
chmod 755 "$tmp/cleanup-shim/rm"
second_ready="$tmp/second.ready"; second_seen="$tmp/second.seen"; second_result="$tmp/second.result"
rm -f "$cleanup_ready" "$cleanup_log" "$second_ready" "$second_seen" "$second_result"
write_signal_engine
HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" PATH="$tmp/cleanup-shim:$PATH" RIGSIGNAL_ASSETS_TEST_ARGS="$args" RIGSIGNAL_ASSETS_TEST_CREDENTIAL="$credential_probe" RIGSIGNAL_ASSETS_SIGNAL_READY="$second_ready" RIGSIGNAL_ASSETS_SIGNAL_SEEN="$second_seen" RIGSIGNAL_ASSETS_SIGNAL_RESULT="$second_result" RIGSIGNAL_ASSETS_SIGNAL_OUT="$tmp/second-signal.out" RIGSIGNAL_ASSETS_LAUNCHER="$bin/rigsignal" RIGSIGNAL_ASSETS_BUNDLE="$bundle" RIGSIGNAL_ASSETS_CA="$ca" RIGSIGNAL_ASSETS_CREDENTIALS="$credentials" RIGSIGNAL_ASSETS_CLEANUP_READY="$cleanup_ready" RIGSIGNAL_ASSETS_CLEANUP_LOG="$cleanup_log" python3 "$signal_driver" TERM
require_line status=42 "$second_result" "second signal during cleanup preserved engine status"
require_line SIGTERM "$second_seen" "first signal was not forwarded before cleanup"
require_line cleanup "$cleanup_log" "second-signal fixture did not observe cleanup"
require_missing_match "$tmp/runtime" 'rigsignal-assets.*' "second signal during cleanup left the private assets directory"

# A real pseudo-terminal proves echo is restored after an interrupt between
# disabling echo and reading the password.
mkdir -p "$tmp/password-stty-shim"
password_stty_ready="$tmp/password-stty.ready"
printf '%s\n' '#!/bin/sh' 'if [ "$1" = "-echo" ]; then /bin/stty -echo; result=$?; touch "$RIGSIGNAL_ASSETS_STTY_READY"; exit "$result"; fi' 'exec /bin/stty "$@"' >"$tmp/password-stty-shim/stty"
chmod 755 "$tmp/password-stty-shim/stty"
password_driver="$tmp/password-pty.py"; password_result="$tmp/password.result"
printf '%s\n' '#!/usr/bin/env python3' \
    'import fcntl, os, pty, signal, subprocess, sys, termios, time' \
    'master, slave = pty.openpty()' \
    'def controlling_tty():' \
    '    os.setsid()' \
    '    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)' \
    'command = [os.environ["RIGSIGNAL_ASSETS_LAUNCHER"], "assets", "install", "--bundle", os.environ["RIGSIGNAL_ASSETS_BUNDLE"], "--endpoint", "http://127.0.0.1:9200", "--ca-file", os.environ["RIGSIGNAL_ASSETS_CA"], "--kibana-endpoint", "https://kibana.example.invalid"]' \
    'child = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, preexec_fn=controlling_tty, close_fds=True)' \
    'os.close(slave)' \
    'os.write(master, b"prompt-user\n")' \
    'deadline = time.monotonic() + float(os.environ.get("RIGSIGNAL_LAUNCHER_WAIT_SECS", "60"))' \
    'while not os.path.exists(os.environ["RIGSIGNAL_ASSETS_STTY_READY"]) and time.monotonic() < deadline: time.sleep(0.05)' \
    'if not os.path.exists(os.environ["RIGSIGNAL_ASSETS_STTY_READY"]): child.kill(); child.wait(); raise SystemExit("password prompt did not disable echo")' \
    'child.send_signal(signal.SIGINT)' \
    'status = child.wait(timeout=float(os.environ.get("RIGSIGNAL_LAUNCHER_WAIT_SECS", "60")))' \
    'echo_restored = bool(termios.tcgetattr(master)[3] & termios.ECHO)' \
    'open(os.environ["RIGSIGNAL_ASSETS_PASSWORD_RESULT"], "w", encoding="utf-8").write(f"status={status} echo={int(echo_restored)}\n")' \
    'os.close(master)' >"$password_driver"
chmod 755 "$password_driver"
HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" PATH="$tmp/password-stty-shim:$PATH" RIGSIGNAL_ASSETS_LAUNCHER="$bin/rigsignal" RIGSIGNAL_ASSETS_BUNDLE="$bundle" RIGSIGNAL_ASSETS_CA="$ca" RIGSIGNAL_ASSETS_STTY_READY="$password_stty_ready" RIGSIGNAL_ASSETS_PASSWORD_RESULT="$password_result" python3 "$password_driver" >"$tmp/password-console.out" 2>&1
require_grep 'echo=1$' "$password_result" "terminal echo was not restored after password-prompt interruption"

# The waited child status is the assets command status: all contract codes
# must pass through unchanged, with stderr left untouched by the launcher.
write_status_engine() {
    printf '%s\n' '#!/usr/bin/env python3' 'import sys' 'print("engine-status-" + sys.argv[1], file=sys.stderr)' 'raise SystemExit(int(sys.argv[1]))' >"$engine/install_assets.py"
    chmod 755 "$engine/install_assets.py"
}
for engine_status in 0 2 3 4; do
    write_status_engine
    # The fixture reads the requested status from a harmless first argument
    # injected by its filename-independent script body below.
    sed -i "s/sys.argv\[1\]/\"$engine_status\"/g" "$engine/install_assets.py"
    run_status run_noninteractive >"$tmp/forward-$engine_status.out" 2>&1
    require_status "$engine_status" "$RUN_STATUS" "engine status $engine_status forwarding"
    require_grep "engine-status-$engine_status" "$tmp/forward-$engine_status.out" "engine status $engine_status stderr forwarding"
done
set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" "$bin/rigsignal" assets install --unknown-flag >"$tmp/assets-local-exit.out" 2>&1; RUN_STATUS=$?; set -e
require_status 2 "$RUN_STATUS" "launcher-local assets usage exit"

# A pre-engine acquisition/argument failure is redacted as uncertainty only
# for a strict canonical protected record.  A substring spoof must remain the
# ordinary local exit-2 path.
uncertain_state="$tmp/uncertain-state"
mkdir -p "$uncertain_state/rigsignal/assets"
chmod 700 "$uncertain_state/rigsignal/assets"
python3 - "$uncertain_state/rigsignal/assets/assets-marker.json" <<'PY'
import json, sys
targets = [{"key": f"es/component-template/t{i:02d}", "digest": "a" * 64} for i in range(66)]
value = {
  "asset_set_sha256": "b225e4afc1eee7df188a943b236f0422ed6e815299a8dc8933f569b13d8120e4", "bundle_sha256": "c" * 64, "bundle_version": "1.2.3",
  "caller_obligations": ["assets-66"], "cluster_uuid": "0123456789ABCDEFGHIJKL",
  "created_at": "2026-08-04T12:34:56Z", "destination_map": [], "kibana_target": {"origin": "https://kb", "spaces": ["default", "rigsignal"]},
  "ownership_profile": "default", "possible_mutation": True, "predecessor": None,
  "progress": {item["key"]: "planned" for item in targets}, "schema_version": 2,
  "source_commit": "d" * 40, "state": "installing", "targets": targets,
  "transaction_id": "01234567-89ab-4cde-8fab-0123456789ab",
}
open(sys.argv[1], "wb").write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
PY
chmod 600 "$uncertain_state/rigsignal/assets/assets-marker.json"
set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_STATE_HOME="$uncertain_state" TMPDIR="$tmp/runtime" "$bin/rigsignal" assets install --unknown-flag >"$tmp/launcher-canonical-uncertain.out" 2>&1; RUN_STATUS=$?; set -e
require_status 4 "$RUN_STATUS" "canonical uncertainty did not redact pre-engine failure"
require_grep 'RIGSIGNAL_RECOVERY_STATE partial-remote-possible transaction=<redacted>' "$tmp/launcher-canonical-uncertain.out" "canonical uncertainty token missing"
cp "$uncertain_state/rigsignal/assets/assets-marker.json" "$tmp/valid-uncertainty.json"
# Canonical bytes and protected ownership alone are not uncertainty authority:
# each malformed binding below must remain on the normal pre-engine exit-2
# path.  These cases mirror the engine's installing-record grammar.
for malformed in target-digest source-commit target-key timestamp destination predecessor; do
    cp "$tmp/valid-uncertainty.json" "$uncertain_state/rigsignal/assets/assets-marker.json"
    python3 - "$uncertain_state/rigsignal/assets/assets-marker.json" "$malformed" <<'PY'
import json, sys
path, case = sys.argv[1:]
value = json.load(open(path, encoding="utf-8"))
if case == "target-digest": value["asset_set_sha256"] = "0" * 64
elif case == "source-commit": value["source_commit"] = "not-a-commit"
elif case == "target-key": value["targets"][0]["key"] = "es/component-template/bad/key"
elif case == "timestamp": value["created_at"] = "2026-02-30T12:34:56Z"
elif case == "destination": value["destination_map"] = [{"submitted_key": "bad", "destination_key": "kibana/default/dashboard/x"}]
elif case == "predecessor": value["predecessor"] = {"state": "installed"}
open(path, "w", encoding="utf-8").write(json.dumps(value, sort_keys=True, separators=(",", ":")))
PY
    chmod 600 "$uncertain_state/rigsignal/assets/assets-marker.json"
    set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_STATE_HOME="$uncertain_state" TMPDIR="$tmp/runtime" "$bin/rigsignal" assets install --unknown-flag >"$tmp/launcher-$malformed.out" 2>&1; RUN_STATUS=$?; set -e
    require_status 2 "$RUN_STATUS" "canonical malformed $malformed was accepted as uncertainty"
    if grep -q 'RIGSIGNAL_RECOVERY_STATE' "$tmp/launcher-$malformed.out"; then fail "canonical malformed $malformed emitted uncertainty token"; fi
done
printf '%s' '{"note":"substring spoof \\"schema_version\\":2 \\"state\\":\\"installing\\" \\"possible_mutation\\":true"}' >"$uncertain_state/rigsignal/assets/assets-marker.json"
chmod 600 "$uncertain_state/rigsignal/assets/assets-marker.json"
set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_STATE_HOME="$uncertain_state" TMPDIR="$tmp/runtime" "$bin/rigsignal" assets install --unknown-flag >"$tmp/launcher-substring-spoof.out" 2>&1; RUN_STATUS=$?; set -e
require_status 2 "$RUN_STATUS" "substring spoof was accepted as uncertainty"
if grep -q 'RIGSIGNAL_RECOVERY_STATE' "$tmp/launcher-substring-spoof.out"; then fail "substring spoof emitted uncertainty token"; fi

printf 'rigsignal-git\n' >"$engine/channel"; curl_log="$tmp/curl.log"; mkdir "$tmp/shim"
printf '%s\n' '#!/bin/sh' 'printf request >> "$RIGSIGNAL_ASSETS_CURL_LOG"' 'exit 1' >"$tmp/shim/curl"; chmod 755 "$tmp/shim/curl"
set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" PATH="$tmp/shim:$PATH" RIGSIGNAL_ASSETS_CURL_LOG="$curl_log" "$bin/rigsignal" assets install --ownership-profile fleet-coexist >"$tmp/fleet.out" 2>&1; RUN_STATUS=$?; set -e
require_status 3 "$RUN_STATUS" "fleet coexist"
require_grep fleet_coexist_requires_full_flow "$tmp/fleet.out" "fleet coexist did not fail closed"
if [ -e "$curl_log" ]; then fail "fleet coexist attempted a release download"; fi
set +e; HOME="$home" XDG_CONFIG_HOME="$home/.config" TMPDIR="$tmp/runtime" PATH="$tmp/shim:$PATH" RIGSIGNAL_ASSETS_CURL_LOG="$curl_log" "$bin/rigsignal" assets install --endpoint http://127.0.0.1:9200 --ca-file "$ca" --kibana-endpoint https://kibana.example.invalid --admin-credentials-file "$credentials" --non-interactive >"$tmp/git.out" 2>&1; RUN_STATUS=$?; set -e
require_status 2 "$RUN_STATUS" "git assets without bundle"
require_grep 'rigsignal-git requires --bundle' "$tmp/git.out" "git install did not remain offline-only"
if [ -e "$curl_log" ]; then fail "git assets lookup invoked curl"; fi

echo 'rigsignal assets launcher: PASS'
