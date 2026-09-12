#!/bin/sh
# rigsignal — unified launcher CLI for the RigSignal telemetry agent.
#
# Usage:
#   rigsignal setup [--ca-file <path> [--ca-sha256 <hex>]] [--allow-unknown-version]
#                                  First-run: configure ES endpoint + API key
#   rigsignal start              Start agent (+ eBPF if sudo available)
#   rigsignal stop               Stop both services gracefully
#   rigsignal status             Show service state + last session label
#   rigsignal run %command%      Steam launch option: start → game → stop
#   rigsignal assets install     Download/verify and install released assets
#
# Steam integration:
#   In game Properties → Launch Options:  rigsignal run %command%

AGENT_UNIT="rigsignal-agent"
EBPF_UNIT="rigsignal-ebpf"

# Elasticsearch compatibility policy. The supported floor is intentionally kept in
# one place so setup messaging and the version gate cannot drift.
ES_SUPPORTED_FLOOR_VERSION="9.4.3"

# User config path — mirrors what the Rust agent's Config::load() searches first.
# The agent also reads /etc/rigsignal/rigsignal.toml (system-wide), but setup
# writes the user config so credentials stay per-user and never world-readable.
case "${XDG_CONFIG_HOME:-}" in
    /*) CONFIG_HOME=$XDG_CONFIG_HOME ;;
    *) CONFIG_HOME=$HOME/.config ;;
esac
CONFIG_DIR="$CONFIG_HOME/rigsignal"
CONFIG_FILE="$CONFIG_DIR/rigsignal.toml"
CERT_DIR="$CONFIG_DIR/certs"
CERT_FILE="$CERT_DIR/elasticsearch-ca.pem"

# ── Launcher debug log ─────────────────────────────────────────────────────────
# _llog always writes timestamped entries to a persistent file so Gaming Mode
# decisions (invisible at launch time) are readable afterwards in Desktop Mode:
#   cat ~/.local/share/rigsignal/launcher.log
#
# Set RIGSIGNAL_DEBUG=1 in Steam launch options to also capture the full shell
# trace (set -x) in the same file — every branch, every command:
#   RIGSIGNAL_DEBUG=1 rigsignal run %command%

_LOG_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/rigsignal"
_LOG_FILE="$_LOG_DIR/launcher.log"
_llog() { printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$*" >> "$_LOG_FILE" 2>/dev/null || true; }

mkdir -p "$_LOG_DIR" 2>/dev/null || true
# Rotate log at 1 MB so it doesn't grow unbounded.
if [ -f "$_LOG_FILE" ]; then
    _lsz=$(wc -c < "$_LOG_FILE" 2>/dev/null || echo 0)
    [ "${_lsz:-0}" -gt 1048576 ] && mv "$_LOG_FILE" "${_LOG_FILE}.old" 2>/dev/null || true
fi

if [ "${RIGSIGNAL_DEBUG:-0}" = "1" ]; then
    # Redirect stderr to the log file before set -x so the shell trace lands there.
    # The game process will inherit fd 2 → its stderr also goes to the log in this mode.
    exec 2>>"$_LOG_FILE"
    set -x
fi

# ── Output helpers ─────────────────────────────────────────────────────────────
# Use colors only when stdout is a terminal and not running under systemd.

if [ -t 1 ] && [ -z "$JOURNAL_STREAM" ]; then
    _GRN='\033[0;32m'
    _YLW='\033[0;33m'
    _RED='\033[0;31m'
    _NC='\033[0m'
else
    _GRN='' _YLW='' _RED='' _NC=''
fi

_ok()   { printf "${_GRN}[OK]${_NC}   %s\n" "$*"; }
_warn() { printf "${_YLW}[WARN]${_NC} %s\n" "$*" >&2; }
_err()  { printf "${_RED}[ERR]${_NC}  %s\n" "$*" >&2; }
_info() { printf "       %s\n" "$*"; }
_die()  { _err "$*"; exit 1; }

# ── TOML helpers ───────────────────────────────────────────────────────────────

# Extract value from a  key = "value"  TOML line. Strips surrounding quotes.
# Works for the simple flat values rigsignal.toml uses (no multiline, no escapes).
toml_get() {
    # $1 = key name, $2 = file path
    awk -v key="$1" '
        /^\[elasticsearch\][ \t]*(#.*)?$/ { in_es=1; next }
        /^\[[^]]+\]/ { in_es=0 }
        in_es && $0 ~ "^[ \t]*" key "[ \t]*=" { print; exit }
    ' "$2" 2>/dev/null \
        | sed 's/^[^=]*=[[:space:]]*//' \
        | sed 's/[[:space:]]*#.*$//' \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
        | tr -d '"' \
        | tr -d "'"
}

# Elasticsearch API keys must never be sent to an arbitrary clear-text host.
# Plain HTTP is retained only for loopback development endpoints.
validate_endpoint() {
    _endpoint="$1"
    case "$_endpoint" in
        https://?* )
            validate_url_origin "$_endpoint" || {
                _err "Elasticsearch endpoint must be a URL origin with a valid host and optional port."
                return 1
            }
            return 0 ;;
        http://* )
            _http_authority=${_endpoint#http://}
            _http_authority=${_http_authority%%/*}
            _http_authority=${_http_authority%%\?*}
            _http_authority=${_http_authority%%\#*}
            case "$_http_authority" in
                ''|*@*)
                    _err "Refusing clear-text HTTP Elasticsearch endpoint outside loopback; use HTTPS (HTTP is allowed only for localhost development)."
                    return 1 ;;
                localhost|localhost:[0-9]*|[[]::1[]]|[[]::1[]]:[0-9]*)
                    validate_url_origin "$_endpoint" || {
                        _err "Elasticsearch endpoint must be a URL origin with a valid host and optional port."
                        return 1
                    }
                    return 0 ;;
                127.*) ;;
                *)
                    _err "Refusing clear-text HTTP Elasticsearch endpoint outside loopback; use HTTPS (HTTP is allowed only for localhost development)."
                    return 1 ;;
            esac
            _http_host=${_http_authority%%:*}
            if printf '%s\n' "$_http_host" | awk -F. 'NF == 4 && $1 == 127 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ && $2 <= 255 && $3 <= 255 && $4 <= 255 { exit 0 } { exit 1 }'; then
                validate_url_origin "$_endpoint" || {
                    _err "Elasticsearch endpoint must be a URL origin with a valid host and optional port."
                    return 1
                }
                return 0
            fi
            _err "Refusing clear-text HTTP Elasticsearch endpoint outside loopback; use HTTPS (HTTP is allowed only for localhost development)."
            return 1 ;;
        * )
            _err "Elasticsearch endpoint must start with https:// (or http:// for a loopback development endpoint)."
            return 1 ;;
    esac
}

# Reject only characters unsafe in a quoted TOML value.  Scheme, authority, and
# loopback policy remain the responsibility of validate_endpoint above so its
# established acceptance rules and refusal messages are preserved.
validate_url_origin() {
    case "$1" in
        *\"*|*\\*|*[[:space:][:cntrl:]]*) return 1 ;;
        *) return 0 ;;
    esac
}

# Elasticsearch API keys are opaque base64-like tokens. Reject whitespace and
# control characters before they can be placed in a header or persisted TOML;
# retain URL-safe/base64 punctuation for both Elastic-generated key variants.
validate_api_key_shape() {
    case "$1" in
        ''|*[!A-Za-z0-9._~+=/-]*) _err "API key has an invalid shape (whitespace and control characters are not allowed)."; return 1 ;;
        *) return 0 ;;
    esac
}

# ── Connectivity test ──────────────────────────────────────────────────────────

# Sets ES_STATUS and ES_BODY. Requests deliberately keep credentials out of
# output; callers report only an HTTP status and a safe remediation hint.
es_request() {
    endpoint="$1"
    api_key="$2"
    method="$3"
    path="$4"
    payload="$5"
    ca_file="$6"
    request_url="${endpoint%/}${path}"
    curl_failed=0

    if [ "${RIGSIGNAL_TEST_DISABLE_REQUEST_PYTHON:-0}" != "1" ] && command -v python3 >/dev/null 2>&1; then
        response=$(python3 - "$request_url" "$api_key" "$method" "$payload" "$ca_file" <<'PYEOF'
import ssl
import sys
import urllib.error
import urllib.request

url, key, method, payload, ca_file = sys.argv[1:]
body = payload.encode() if payload else None
headers = {"Authorization": f"ApiKey {key}"}
if body is not None:
    headers["Content-Type"] = "application/json"
request = urllib.request.Request(url, data=body, headers=headers, method=method)
context = ssl.create_default_context(cafile=ca_file or None)
class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise urllib.error.URLError("refusing Elasticsearch redirect")
opener = urllib.request.build_opener(RefuseRedirects(), urllib.request.HTTPSHandler(context=context))
try:
    with opener.open(request, timeout=8) as result:
        print(result.status)
        print(result.read().decode("utf-8", "replace").replace("\n", " "))
except urllib.error.HTTPError as error:
    print(error.code)
    print(error.read().decode("utf-8", "replace").replace("\n", " "))
except Exception as error:
    print(0)
    print(f"{type(error).__name__}: {error}")
PYEOF
)
    elif command -v curl >/dev/null 2>&1; then
        if [ -n "$payload" ]; then
            if [ -n "$ca_file" ]; then
                response=$(curl -q -sS --cacert "$ca_file" --max-time 8 -X "$method" \
                    -H "Authorization: ApiKey $api_key" -H "Content-Type: application/json" \
                    --data "$payload" -w '\n%{http_code}' "$request_url" 2>&1) || curl_failed=1
            else
                response=$(curl -q -sS --max-time 8 -X "$method" \
                    -H "Authorization: ApiKey $api_key" -H "Content-Type: application/json" \
                    --data "$payload" -w '\n%{http_code}' "$request_url" 2>&1) || curl_failed=1
            fi
            if [ "${curl_failed:-0}" = "1" ]; then
                ES_STATUS=0
                ES_BODY="$response"
                return 0
            fi
        else
            if [ -n "$ca_file" ]; then
                response=$(curl -q -sS --cacert "$ca_file" --max-time 8 -X "$method" \
                    -H "Authorization: ApiKey $api_key" -w '\n%{http_code}' "$request_url" 2>&1) || curl_failed=1
            else
                response=$(curl -q -sS --max-time 8 -X "$method" \
                    -H "Authorization: ApiKey $api_key" -w '\n%{http_code}' "$request_url" 2>&1) || curl_failed=1
            fi
            if [ "${curl_failed:-0}" = "1" ]; then
                ES_STATUS=0
                ES_BODY="$response"
                return 0
            fi
        fi
        ES_STATUS=$(printf '%s\n' "$response" | tail -n 1)
        ES_BODY=$(printf '%s\n' "$response" | sed '$d')
        return 0
    else
        ES_STATUS=0
        ES_BODY="Neither Python 3 nor curl is available for a verified Elasticsearch request."
        return 0
    fi

    ES_STATUS=$(printf '%s\n' "$response" | sed -n '1p')
    ES_BODY=$(printf '%s\n' "$response" | sed -n '2p')
}

is_2xx() {
    case "$1" in
        2??) return 0 ;;
        *) return 1 ;;
    esac
}

json_has_all_requested() {
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$1" | python3 -c '
import json, sys
try:
    print("true" if json.load(sys.stdin).get("has_all_requested") is True else "false")
except (json.JSONDecodeError, AttributeError):
    print("false")
'
    else
        # No python3: emit true/false on stdout (matching the python branch's
        # contract). grep -q alone only sets exit status, which the caller —
        # which reads stdout via command substitution — would see as empty.
        if printf '%s\n' "$1" | grep -Eq '"has_all_requested"[[:space:]]*:[[:space:]]*true'; then
            printf 'true\n'
        else
            printf 'false\n'
        fi
    fi
}

json_version_number() {
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$1" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin)["version"]["number"])
except (json.JSONDecodeError, KeyError, TypeError):
    pass
'
    else
        printf '%s\n' "$1" | sed -n 's/.*"number"[[:space:]]*:[[:space:]]*"\([0-9][0-9.]*\)".*/\1/p' | head -1
    fi
}

version_at_least() {
    actual="$1"
    required="$2"
    awk -v actual="$actual" -v required="$required" 'BEGIN {
        split(actual, a, "."); split(required, r, ".");
        for (i = 1; i <= 3; i++) {
            av = (a[i] == "" ? 0 : a[i]) + 0;
            rv = (r[i] == "" ? 0 : r[i]) + 0;
            if (av > rv) exit 0;
            if (av < rv) exit 1;
        }
        exit 0;
    }'
}

validate_elasticsearch() {
    endpoint="$1"
    api_key="$2"
    ca_file="$3"
    privileges='{"index":[{"names":["metrics-rigsignal.*","logs-rigsignal.*"],"privileges":["create_doc"]}]}'

    es_request "$endpoint" "$api_key" GET "/_security/_authenticate" "" "$ca_file"
    if ! is_2xx "$ES_STATUS"; then
        _err "Elasticsearch authentication failed (HTTP status: ${ES_STATUS:-0})."
        [ -n "${ES_BODY:-}" ] && _info "$ES_BODY"
        [ "${ES_STATUS:-0}" = "0" ] && _info "For an HTTPS IP endpoint, issue a server certificate with an IP subjectAltName or use its DNS name."
        _info "Check the endpoint and API key; the key must be active and authorized."
        return 1
    fi

    es_request "$endpoint" "$api_key" POST "/_security/user/_has_privileges" "$privileges" "$ca_file"
    if ! is_2xx "$ES_STATUS"; then
        _err "Elasticsearch privilege check failed (HTTP status: ${ES_STATUS:-0})."
        _info "Check that the API key may check privileges; it needs create_doc on RigSignal data streams."
        return 1
    fi
    if [ "$(json_has_all_requested "$ES_BODY")" != "true" ]; then
        _err "API key is missing create_doc privilege for metrics-rigsignal.* and/or logs-rigsignal.*."
        _info "Create or update the key with create_doc on both RigSignal data streams."
        return 1
    fi

    es_request "$endpoint" "$api_key" GET "/" "" "$ca_file"
    if ! is_2xx "$ES_STATUS"; then
        _err "Elasticsearch version check failed (HTTP status: ${ES_STATUS:-0})."
        _info "Check the endpoint and API key; setup needs a successful Elasticsearch response."
        return 1
    fi
    es_version=$(json_version_number "$ES_BODY")
    if [ -z "$es_version" ]; then
        if [ "${SETUP_ALLOW_UNKNOWN_VERSION:-0}" = "1" ]; then
            _warn "Elasticsearch version could NOT be determined, so the supported floor ${ES_SUPPORTED_FLOOR_VERSION} could NOT be verified. By using --allow-unknown-version, you are accepting the compatibility risk."
            return 0
        fi
        _err "Could not determine Elasticsearch version; RigSignal requires ${ES_SUPPORTED_FLOOR_VERSION} or newer and setup cannot verify that supported floor. Rerun with --allow-unknown-version only if you accept this risk."
        return 1
    fi
    if ! version_at_least "$es_version" "$ES_SUPPORTED_FLOOR_VERSION"; then
        _err "Elasticsearch ${es_version} is unsupported; RigSignal requires ${ES_SUPPORTED_FLOOR_VERSION} or newer."
        return 1
    fi
}

# ── Service control ────────────────────────────────────────────────────────────

# Wait up to 10 seconds for a user service to become active.
wait_agent_active() {
    i=0
    while [ "$i" -lt 10 ]; do
        if systemctl --user is-active "$AGENT_UNIT" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# Attempt to start/stop the eBPF system service via sudo.
# Non-fatal: eBPF is optional — agent-only mode still ships all metric streams.
ebpf_start() {
    if sudo -n systemctl start "$EBPF_UNIT" >/dev/null 2>&1; then
        _ok "eBPF daemon started ($EBPF_UNIT)"
        return 0
    elif sudo systemctl start "$EBPF_UNIT" >/dev/null 2>&1; then
        _ok "eBPF daemon started ($EBPF_UNIT)"
        return 0
    else
        _warn "eBPF daemon not started (no sudo/polkit or CAP_BPF unavailable)."
        _info "Scheduler and kernel metrics will be absent. Agent-only mode active."
        return 1
    fi
}

ebpf_stop() {
    sudo -n systemctl stop "$EBPF_UNIT" >/dev/null 2>&1 \
        || sudo systemctl stop "$EBPF_UNIT" >/dev/null 2>&1 \
        || true   # not fatal — may already be stopped or no sudo
}

# ── Agent binary resolution ────────────────────────────────────────────────────

# Look next to this script first — the user-mode installer puts rigsignal and
# rigsignal-agent in the same directory (~/.local/bin/). Gamescope / Gaming Mode
# may not have ~/.local/bin on PATH, so we can't rely on PATH alone.
resolve_agent_bin() {
    _script_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
    if [ -x "$_script_dir/rigsignal-agent" ]; then
        echo "$_script_dir/rigsignal-agent"
    elif command -v rigsignal-agent >/dev/null 2>&1; then
        command -v rigsignal-agent
    else
        echo ""
    fi
}

# ── Subcommand: assets install ────────────────────────────────────────────────

# This command intentionally has a narrower resolver than run/setup.  Assets
# are a release artifact and must never pair a user launcher with /usr's engine
# (or vice versa).
resolve_assets_installation() {
    _assets_script_dir=$(cd "$(dirname "$0")" 2>/dev/null && pwd -P) || return 1
    if [ "$_assets_script_dir" = "$HOME/.local/bin" ]; then
        ASSETS_AGENT="$HOME/.local/bin/rigsignal-agent"
        ASSETS_ENGINE="$HOME/.local/lib/rigsignal/engine"
    else
        ASSETS_AGENT="/usr/bin/rigsignal-agent"
        ASSETS_ENGINE="/usr/lib/rigsignal/engine"
    fi
    command -v python3 >/dev/null 2>&1 || { _err "python3 is required for rigsignal assets install."; return 1; }
    ASSETS_VERSION=$(python3 - "$ASSETS_AGENT" "$ASSETS_ENGINE" <<'PYEOF'
import json, os, re, stat, subprocess, sys
agent, engine = sys.argv[1:]
required = ("install_assets.py", "asset_adapters.py", "_version.py", "channel")
try:
    for path in (agent, *(os.path.join(engine, name) for name in required)):
        item = os.lstat(path)
        if not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode):
            raise ValueError("not a regular file")
    marker = open(os.path.join(engine, "channel"), "rb").read()
    if marker not in (b"rigsignal-release\n", b"rigsignal-git\n"):
        raise ValueError("invalid channel marker")
    result = subprocess.run([agent, "--build-info-json"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode != 0 or result.stderr:
        raise ValueError("build information unavailable")
    raw = result.stdout
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or b"\n" in raw:
        raise ValueError("extra build information output")
    def reject_duplicate_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    if (not isinstance(value, dict) or set(value) != {"name", "version", "commit"}
            or any(not isinstance(value[key], str) for key in value)
            or value["name"] != "rigsignal-agent"
            or re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", value["version"]) is None):
        raise ValueError("invalid build information")
    print(value["version"])
except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
PYEOF
) || { _err "engine_not_installed: matching launcher, agent, engine, and channel marker are required."; return 1; }
    ASSETS_CHANNEL=$(cat "$ASSETS_ENGINE/channel")
}

assets_sidecar_digest() {
    # Keep this deliberately standalone, matching install.sh's piped bootstrap
    # verifier.  The shared corpus under packaging/tests fences the two copies.
    python3 - "$1" "$2" <<'PYEOF'
import pathlib, re, sys
sidecar = pathlib.Path(sys.argv[1]).read_bytes()
name = sys.argv[2].encode("ascii")
match = re.fullmatch(rb"([0-9a-f]{64})(?:  | \*)" + re.escape(name) + rb"\n", sidecar)
if match is None:
    raise SystemExit(1)
print(match.group(1).decode("ascii"))
PYEOF
}

assets_restore_terminal() {
    if [ "${ASSETS_STTY_DISABLED:-0}" = "1" ]; then
        stty echo 2>/dev/null || true
        ASSETS_STTY_DISABLED=0
        printf '\n' >&2
    fi
}

assets_rollback_kibana_transaction() {
    [ "${ASSETS_KIBANA_TRANSACTION:-0}" = "1" ] || return 0
    _assets_rollback_ok=1
    if [ "${ASSETS_CONFIG_HAD:-0}" = "1" ]; then
        rm -f "$CONFIG_FILE" 2>/dev/null || true
        mv "${ASSETS_CONFIG_BACKUP:-}" "$CONFIG_FILE" 2>/dev/null || _assets_rollback_ok=0
    else
        rm -f "$CONFIG_FILE" 2>/dev/null || true
    fi
    [ "$_assets_rollback_ok" = "1" ] && ASSETS_KIBANA_TRANSACTION=0
    return $((1 - _assets_rollback_ok))
}

assets_restore_steamos_readonly() {
    [ "${STEAMOS_READONLY_DISABLED:-0}" = "1" ] || return 0
    sudo steamos-readonly enable >/dev/null 2>&1 || sudo steamos-readonly enable >/dev/null 2>&1 || return 1
    STEAMOS_READONLY_DISABLED=0
}

assets_cleanup() {
    _assets_cleanup_status=${1:-$?}
    # A signal received while cleanup is running must not tear down a second
    # time and strand the one-shot credential or leave terminal echo disabled.
    [ "${ASSETS_CLEANING:-0}" = "1" ] && return 0
    ASSETS_CLEANING=1
    assets_restore_terminal
    # During an S4 system transaction, only restore the user copy once its
    # root counterpart has been restored.  Retaining both new copies is safer
    # than creating a new root config next to an old user config.
    if [ "${SYSTEM_SCOPE_TRANSACTION_ACTIVE:-0}" = "1" ]; then
        rollback_system_transaction || true
        [ "${_system_ca_backup_ready:-1}" = "0" ] && [ "${_system_cfg_backup_ready:-1}" = "0" ] \
            && SYSTEM_SCOPE_RESTORED=1
        cleanup_system_transaction_temps
    fi
    if [ "${SYSTEM_SCOPE_RESTORED:-1}" = "1" ]; then
        assets_rollback_kibana_transaction
    fi
    # synchronize_ebpf_system_config uses this same flag for S4.  Retain that
    # restoration guarantee if an assets signal arrives during elevation.
    assets_restore_steamos_readonly || _warn "SteamOS left writable — run steamos-readonly enable"
    rm -f "${ASSETS_CREDENTIAL_FILE:-}" "${ASSETS_BUNDLE_SNAPSHOT:-}" "${ASSETS_SIDECAR_SNAPSHOT:-}" "${CA_SNAPSHOT:-}" "${_assets_new_config:-}" "${_sync_tmp:-}" 2>/dev/null || true
    [ "${ASSETS_KIBANA_TRANSACTION:-0}" = "1" ] || rm -f "${ASSETS_CONFIG_BACKUP:-}" 2>/dev/null || true
    [ -z "${ASSETS_TMP:-}" ] || rmdir "$ASSETS_TMP" 2>/dev/null || rm -rf "$ASSETS_TMP" 2>/dev/null || true
    ASSETS_CLEANING=0
    return "$_assets_cleanup_status"
}

assets_interrupted() {
    _assets_signal_status=$?
    _assets_signal=${1:-TERM}
    [ "${ASSETS_CLEANING:-0}" = "1" ] && return 0
    # This handler owns cancellation and reaping. In dash a trapped signal
    # interrupts wait without reaping the child; that first status is not the
    # engine status. Disable reentry before forwarding or waiting again.
    trap '' HUP INT TERM
    # The engine's lifetime begins at fork, not at the assignment on the next
    # line.  A signal delivered between `engine &` and `ASSETS_ENGINE_PID=$!`
    # finds the registration variable still empty, so every branch below would
    # take its no-engine path and cleanup would delete the one-shot credential
    # while a live engine still expects it.  $! is already the engine's pid in
    # that window, so resolve from it.  ASSETS_ENGINE_SPAWNED is what makes
    # that safe: $! keeps naming the engine after it has been reaped, and pid
    # numbers are recycled, so an ungated fallback could signal an unrelated
    # process.  Resolve before the watchdog below, which reassigns $!.
    if [ -z "${ASSETS_ENGINE_PID:-}" ] && [ "${ASSETS_ENGINE_SPAWNED:-0}" = "1" ]; then
        ASSETS_ENGINE_PID=$!
    fi
    # Preserve a completed ordinary wait before starting any background job:
    # dash can discard its cached status when the watchdog is spawned.
    if [ -n "${ASSETS_ENGINE_PID:-}" ] && ! kill -0 "$ASSETS_ENGINE_PID" 2>/dev/null; then
        if [ -z "${ASSETS_ENGINE_STATUS+x}" ]; then
            set +e
            wait "$ASSETS_ENGINE_PID"
            ASSETS_ENGINE_STATUS=$?
        fi
        ASSETS_ENGINE_PID=""
    fi
    if [ -n "${ASSETS_ENGINE_PID:-}" ]; then
        # Async children inherit ignored INT, so INT does not cancel the
        # background engine. Bound cancellation with a child-only watchdog.
        # Use one process (no sleep children) that the parent can reap.
        python3 - "$ASSETS_ENGINE_PID" <<'PYEOF' &
import os, signal, sys, time
pid = int(sys.argv[1])
for sig in (signal.SIGTERM, signal.SIGKILL):
    time.sleep(2)
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        break
PYEOF
        ASSETS_WATCHDOG_PID=$!
        kill -"$_assets_signal" "$ASSETS_ENGINE_PID" 2>/dev/null || true
        set +e
        wait "$ASSETS_ENGINE_PID"
        ASSETS_ENGINE_STATUS=$?
        # KILL also works before the watchdog interpreter initializes, with
        # the ignored signal dispositions inherited from this handler.
        kill -KILL "$ASSETS_WATCHDOG_PID" 2>/dev/null || true
        wait "$ASSETS_WATCHDOG_PID" 2>/dev/null
        ASSETS_WATCHDOG_PID=""
        ASSETS_ENGINE_PID=""
        set -e
    else
        [ -n "${ASSETS_ENGINE_STATUS+x}" ] || ASSETS_ENGINE_STATUS=$_assets_signal_status
    fi
    # Retire the EXIT trap BEFORE teardown, and handle cleanup's return
    # deliberately.  assets_cleanup returns the status it was given and resets
    # ASSETS_CLEANING on the way out, so with errexit enabled above a nonzero
    # engine status ended the shell on this very line -- before the trap was
    # removed -- and the still-installed EXIT trap ran cleanup a second time.
    # HUP/INT/TERM stay ignored (set at the top of this handler) across the
    # teardown, so a second signal during cleanup still cannot strand the
    # one-shot credential; they are retired only once teardown is complete.
    trap - EXIT
    assets_cleanup "${ASSETS_ENGINE_STATUS:-$_assets_signal_status}" || true
    trap - HUP INT TERM
    exit "${ASSETS_ENGINE_STATUS:-$_assets_signal_status}"
}

assets_snapshot_ca() {
    _assets_ca_source="$1"
    [ -n "$_assets_ca_source" ] || return 1
    snapshot_ca "$_assets_ca_source" "$ASSETS_CA_SHA256"
}

toml_get_section() {
    _toml_section="$1" _toml_key="$2" _toml_file="$3"
    awk -v section="$_toml_section" -v key="$_toml_key" '
        $0 ~ "^\\[" section "\\][ \\t]*(#.*)?$" { inside=1; next }
        /^\[[^]]+\]/ { inside=0 }
        inside && $0 ~ "^[ \\t]*" key "[ \\t]*=" { print; exit }
    ' "$_toml_file" 2>/dev/null | sed 's/^[^=]*=[[:space:]]*//' | sed 's/[[:space:]]*#.*$//' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr -d '"' | tr -d "'"
}

assets_load_persisted_inputs() {
    [ -f "$CONFIG_FILE" ] || { ASSETS_PERSISTED_ENDPOINT= ASSETS_PERSISTED_CA= ASSETS_PERSISTED_KIBANA=; return 0; }
    _assets_persisted=$(python3 - "$CONFIG_FILE" <<'PYEOF'
import sys, tomllib
try:
    with open(sys.argv[1], "rb") as handle: value = tomllib.load(handle)
    if not isinstance(value, dict): raise ValueError()
    elastic = value.get("elasticsearch", {})
    kibana = value.get("kibana", {})
    if not isinstance(elastic, dict) or not isinstance(kibana, dict): raise ValueError()
    values = (elastic.get("endpoint", ""), elastic.get("ca_cert", ""), kibana.get("endpoint", ""))
    if any(not isinstance(item, str) or "\t" in item or "\n" in item for item in values): raise ValueError()
    print("\t".join(values))
except (OSError, ValueError, tomllib.TOMLDecodeError):
    raise SystemExit(1)
PYEOF
) || return 1
    _assets_tab='	'
    IFS="$_assets_tab" read -r ASSETS_PERSISTED_ENDPOINT ASSETS_PERSISTED_CA ASSETS_PERSISTED_KIBANA <<EOF
$_assets_persisted
EOF
}

persist_kibana_endpoint() {
    _assets_kibana="$1"
    _assets_kibana_q=$(toml_quote "$_assets_kibana")
    mkdir -p "$CONFIG_DIR" || return 1
    chmod 700 "$CONFIG_DIR" || return 1
    _assets_new_config=$(mktemp "$CONFIG_DIR/.rigsignal.toml.assets.XXXXXX") || return 1
    chmod 600 "$_assets_new_config" || return 1
    _assets_config_input=$CONFIG_FILE
    [ -f "$_assets_config_input" ] || _assets_config_input=/dev/null
    awk -v endpoint="$_assets_kibana_q" '
        function flush() { if (inside && !seen) print "endpoint = \"" endpoint "\""; inside=0 }
        /^\[kibana\][ \t]*(#.*)?$/ { flush(); inside=1; seen=0; found=1; print; next }
        /^\[[^]]+\]/ { flush(); inside=0 }
        { if (inside && $0 ~ /^[ \t]*endpoint[ \t]*=/) { print "endpoint = \"" endpoint "\""; seen=1; next }; print }
        END { flush(); if (!found) { print ""; print "[kibana]"; print "endpoint = \"" endpoint "\"" } }
    ' "$_assets_config_input" 2>/dev/null > "$_assets_new_config" || { rm -f "$_assets_new_config"; return 1; }
    fsync_file_and_dir "$_assets_new_config" "$CONFIG_DIR" || { rm -f "$_assets_new_config"; return 1; }
    ASSETS_CONFIG_HAD=0
    if [ -e "$CONFIG_FILE" ]; then
        ASSETS_CONFIG_HAD=1
        ASSETS_CONFIG_BACKUP=$(mktemp "$CONFIG_DIR/.rigsignal.toml.assets.backup.XXXXXX") || return 1
        rm -f "$ASSETS_CONFIG_BACKUP" || return 1
        mv "$CONFIG_FILE" "$ASSETS_CONFIG_BACKUP" || return 1
    fi
    ASSETS_KIBANA_TRANSACTION=1
    mv "$_assets_new_config" "$CONFIG_FILE" || { assets_rollback_kibana_transaction; return 1; }
    fsync_file_and_dir "$CONFIG_FILE" "$CONFIG_DIR" || { assets_rollback_kibana_transaction; return 1; }
    return 0
}

assets_commit_kibana_transaction() {
    [ "${ASSETS_KIBANA_TRANSACTION:-0}" = "1" ] || return 0
    rm -f "${ASSETS_CONFIG_BACKUP:-}" 2>/dev/null || return 1
    ASSETS_KIBANA_TRANSACTION=0
}

materialize_admin_file() {
    ASSETS_CREDENTIAL_FILE=$(mktemp "$ASSETS_TMP/admin.XXXXXX") || return 1
    chmod 600 "$ASSETS_CREDENTIAL_FILE" || return 1
    if [ -n "$ASSETS_ADMIN_SOURCE" ]; then
        python3 - "$ASSETS_ADMIN_SOURCE" "$ASSETS_CREDENTIAL_FILE" <<'PYEOF'
import json, os, stat, sys, tomllib
source, destination = sys.argv[1:]
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(source, flags)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode): raise ValueError()
    with os.fdopen(fd, "rb") as handle: fd = None; value = tomllib.load(handle)
finally:
    if fd is not None: os.close(fd)
if (not isinstance(value, dict) or set(value) != {"elasticsearch"}
        or not isinstance(value["elasticsearch"], dict)
        or set(value["elasticsearch"]) != {"username", "password"}
        or any(not isinstance(value["elasticsearch"][k], str) for k in ("username", "password"))):
    raise SystemExit(1)
data = ("[elasticsearch]\nusername = " + json.dumps(value["elasticsearch"]["username"])
        + "\npassword = " + json.dumps(value["elasticsearch"]["password"]) + "\n").encode()
fd = os.open(destination, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600: raise ValueError()
    os.write(fd, data); os.fsync(fd)
finally: os.close(fd)
PYEOF
        return $?
    fi
    printf "Administrator username: " >&2
    IFS= read -r _assets_username || return 1
    printf "Administrator password (input hidden): " >&2
    # Set the intent first: a signal between stty and assignment must still
    # restore echo in the EXIT/signal cleanup path.
    ASSETS_STTY_DISABLED=1
    if stty -echo 2>/dev/null; then
        IFS= read -r _assets_password; _assets_read_status=$?
        assets_restore_terminal
        [ "$_assets_read_status" = 0 ] || return 1
    else
        ASSETS_STTY_DISABLED=0
        IFS= read -r _assets_password || return 1
    fi
    # The Python program is an argument, never stdin: stdin is reserved for
    # credentials only in this interactive path (the old heredoc/pipeline
    # combination consumed the program as stdin and produced an empty file).
    _assets_toml_program='import json, os, stat, sys, tomllib
destination = sys.argv[1]
username, password = os.fdopen(3, "r", encoding="utf-8").read().splitlines()
data = ("[elasticsearch]\nusername = " + json.dumps(username) + "\npassword = " + json.dumps(password) + "\n").encode()
if set(tomllib.loads(data.decode())) != {"elasticsearch"}: raise SystemExit(1)
fd = os.open(destination, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
try:
 st=os.fstat(fd)
 if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600: raise SystemExit(1)
 os.write(fd, data); os.fsync(fd)
finally: os.close(fd)'
    python3 -c "$_assets_toml_program" "$ASSETS_CREDENTIAL_FILE" 3<<EOF
$_assets_username
$_assets_password
EOF
}

cmd_assets_install() {
    # Never trace an administrator credential into the persistent debug log.
    set +x 2>/dev/null || true
    ASSETS_BUNDLE="" ASSETS_ENDPOINT="" ASSETS_CA_FILE="" ASSETS_CA_SHA256="" ASSETS_KIBANA=""
    ASSETS_ADMIN_SOURCE="" ASSETS_REPAIR=0 ASSETS_UPGRADE=0 ASSETS_ALLOW_DOWNGRADE=0 ASSETS_OWNERSHIP=default ASSETS_NONINTERACTIVE=0
    ASSETS_STTY_DISABLED=0 ASSETS_CLEANING=0 ASSETS_KIBANA_TRANSACTION=0 ASSETS_CONFIG_HAD=0
    # Assets setup/acquisition failures are local contract failures.  Keep
    # this scoped helper separate from the launcher's global _die() because
    # other subcommands retain their existing exit protocol.
    # The engine cannot classify a local acquisition failure it never gets to
    # see.  This narrow pre-engine check recognizes only a canonical,
    # protected active uncertainty record and emits the same redacted contract
    # token; it grants no overwrite authority to the shell.
    _assets_boundary_uncertain() {
        _assets_state_root=${XDG_STATE_HOME:-"$HOME/.local/state"}
        _assets_record="$_assets_state_root/rigsignal/assets/assets-marker.json"
        python3 - "$_assets_record" <<'PY'
import datetime, hashlib, ipaddress, json, os, re, stat, sys
from urllib.parse import urlsplit

path = sys.argv[1]
try:
    lst = os.lstat(path)
    if (not stat.S_ISREG(lst.st_mode) or lst.st_uid != os.geteuid()
            or stat.S_IMODE(lst.st_mode) != 0o600):
        raise ValueError()
    parent = os.lstat(os.path.dirname(path))
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700):
        raise ValueError()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (lst.st_dev, lst.st_ino):
            raise ValueError()
        raw = b"".join(iter(lambda: os.read(fd, 65536), b""))
    finally:
        os.close(fd)
    def pairs(items):
        value = dict(items)
        if len(value) != len(items):
            raise ValueError()
        return value
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    if json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                  allow_nan=False).encode("utf-8") != raw:
        raise ValueError()
    sha = re.compile(r"[0-9a-f]{64}\Z")
    commit = re.compile(r"[0-9a-f]{40}\Z")
    cluster = re.compile(r"[A-Za-z0-9_-]{22}\Z")
    transaction = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
    segment = re.compile(r"(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+\Z")
    timestamp = re.compile(r"[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,9})?Z\Z")
    common = {"asset_set_sha256", "bundle_sha256", "bundle_version", "cluster_uuid", "kibana_target",
              "ownership_profile", "schema_version", "source_commit", "state", "targets"}
    installing = common | {"caller_obligations", "created_at", "destination_map", "possible_mutation",
                           "predecessor", "progress", "transaction_id"}
    installed = common | {"caller_obligations", "completed_at", "completed_transaction_id", "destination_map",
                          "verified_target_set_sha256"}
    obligations = (["assets-66"], ["assets-66", "full-flow-step-11"])

    def target_key(key):
        if not isinstance(key, str): return False
        parts = key.split("/")
        return ((len(parts) == 3 and parts[0] == "es" and parts[1] in {
                    "component-template", "index-template", "ingest-pipeline", "security-role", "transform", "bundle-meta"}
                 and bool(segment.fullmatch(parts[2])))
                or (len(parts) == 4 and parts[0] == "kibana" and all(segment.fullmatch(part) for part in parts[1:])))

    def target_digest(items):
        return hashlib.sha256(json.dumps(items, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                                         allow_nan=False).encode("utf-8")).hexdigest()

    def valid_timestamp(item):
        if not isinstance(item, str) or not timestamp.fullmatch(item): return False
        try: datetime.datetime.fromisoformat(item.removesuffix("Z") + "+00:00")
        except ValueError: return False
        return True

    def canonical_origin(origin):
        if not isinstance(origin, str): return False
        try: parsed = urlsplit(origin); port = parsed.port
        except ValueError: return False
        if (parsed.scheme.lower() != "https" or not parsed.netloc or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in ("", "/")
                or parsed.hostname is None or "%" in parsed.hostname or (port is not None and not 1 <= port <= 65535)):
            return False
        try:
            address = ipaddress.ip_address(parsed.hostname)
            host = "[" + str(address) + "]" if address.version == 6 else str(address)
        except ValueError:
            try: host = parsed.hostname.encode("idna").decode("ascii").lower()
            except UnicodeError: return False
        return origin == "https://" + host + ("" if port in (None, 443) else ":" + str(port))

    def valid_targets(items):
        if not isinstance(items, list) or len(items) != 66: return False
        if any(not isinstance(item, dict) or set(item) != {"digest", "key"}
               or not target_key(item.get("key")) or not isinstance(item.get("digest"), str)
               or not sha.fullmatch(item["digest"]) for item in items): return False
        keys = [item["key"] for item in items]
        return len(set(keys)) == 66 and keys == sorted(keys, key=lambda key: key.encode("utf-8"))

    def valid_destination_map(mapping, items):
        if not isinstance(mapping, list): return False
        target_keys = {item["key"] for item in items}; submitted = set(); previous = None
        for item in mapping:
            if not isinstance(item, dict) or set(item) != {"destination_key", "submitted_key"}: return False
            source, destination = item.get("submitted_key"), item.get("destination_key")
            if (not isinstance(source, str) or not isinstance(destination, str) or source not in target_keys
                    or not source.startswith("kibana/") or not destination.startswith("kibana/")
                    or not target_key(source) or not target_key(destination) or source in submitted): return False
            source_parts, destination_parts = source.split("/"), destination.split("/")
            if source_parts[:3] != destination_parts[:3]: return False
            encoded = source.encode("utf-8")
            if previous is not None and encoded <= previous: return False
            previous = encoded; submitted.add(source)
        return True

    def valid_common(record):
        return (isinstance(record, dict) and record.get("schema_version") == 2
                and record.get("ownership_profile") == "default"
                and isinstance(record.get("bundle_version"), str) and bool(record["bundle_version"])
                and isinstance(record.get("source_commit"), str) and bool(commit.fullmatch(record["source_commit"]))
                and isinstance(record.get("bundle_sha256"), str) and bool(sha.fullmatch(record["bundle_sha256"]))
                and isinstance(record.get("asset_set_sha256"), str) and bool(sha.fullmatch(record["asset_set_sha256"]))
                and isinstance(record.get("cluster_uuid"), str) and bool(cluster.fullmatch(record["cluster_uuid"]))
                and isinstance(record.get("kibana_target"), dict) and set(record["kibana_target"]) == {"origin", "spaces"}
                and record["kibana_target"].get("spaces") == ["default", "rigsignal"]
                and canonical_origin(record["kibana_target"].get("origin")))

    def verified_digest(items, caller_obligations):
        physical = list(items)
        if caller_obligations == ["assets-66", "full-flow-step-11"]:
            physical.append({"key": "es/bundle-meta/rigsignal-bundle-meta",
                             "digest": target_digest("es/bundle-meta/rigsignal-bundle-meta")})
            physical.sort(key=lambda item: item["key"].encode("utf-8"))
        return target_digest(physical)

    def valid_installed(record, remote_binding=None):
        if not isinstance(record, dict) or set(record) != installed or record.get("state") != "installed": return False
        items = record.get("targets")
        if not valid_common(record) or not valid_targets(items) or record.get("asset_set_sha256") != target_digest(items): return False
        if remote_binding is not None and (record.get("cluster_uuid"), record.get("kibana_target")) != remote_binding: return False
        return (record.get("caller_obligations") in obligations and valid_timestamp(record.get("completed_at"))
                and isinstance(record.get("completed_transaction_id"), str) and bool(transaction.fullmatch(record["completed_transaction_id"]))
                and valid_destination_map(record.get("destination_map"), items)
                and isinstance(record.get("verified_target_set_sha256"), str) and bool(sha.fullmatch(record["verified_target_set_sha256"]))
                and record["verified_target_set_sha256"] == verified_digest(items, record["caller_obligations"]))

    if not isinstance(value, dict) or set(value) != installing or value.get("state") != "installing": raise ValueError()
    targets = value.get("targets")
    if (not valid_common(value) or not valid_targets(targets) or value.get("asset_set_sha256") != target_digest(targets)
            or value.get("caller_obligations") not in obligations or not valid_timestamp(value.get("created_at"))
            or not isinstance(value.get("possible_mutation"), bool)
            or not isinstance(value.get("transaction_id"), str) or not transaction.fullmatch(value["transaction_id"])
            or not valid_destination_map(value.get("destination_map"), targets)):
        raise ValueError()
    keys = [item["key"] for item in targets] + (["es/bundle-meta/rigsignal-bundle-meta"]
                                                   if value["caller_obligations"] == ["assets-66", "full-flow-step-11"] else [])
    if (not isinstance(value.get("progress"), dict) or set(value["progress"]) != set(keys)
            or any(status not in {"planned", "write-issued", "verified"} for status in value["progress"].values())): raise ValueError()
    predecessor = value.get("predecessor")
    if predecessor is not None and not valid_installed(predecessor, (value["cluster_uuid"], value["kibana_target"])): raise ValueError()
    if value["possible_mutation"] is not True: raise ValueError()
except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError, KeyError):
    raise SystemExit(1)
raise SystemExit(0)
PY
    }
    _assets_die() {
        if _assets_boundary_uncertain; then
            _err "RIGSIGNAL_RECOVERY_STATE partial-remote-possible transaction=<redacted>"
            exit 4
        fi
        _err "$*"; exit 2
    }
    _assets_refuse() { _err "$*"; exit 3; }
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --bundle|--endpoint|--ca-file|--ca-sha256|--kibana-endpoint|--admin-credentials-file|--ownership-profile)
                [ "$#" -ge 2 ] && [ -n "$2" ] || _assets_die "assets install: missing value for $1"
                case "$1" in
                    --bundle) [ -z "$ASSETS_BUNDLE" ] || _assets_die "assets install: duplicate --bundle"; ASSETS_BUNDLE=$2 ;;
                    --endpoint) [ -z "$ASSETS_ENDPOINT" ] || _assets_die "assets install: duplicate --endpoint"; ASSETS_ENDPOINT=$2 ;;
                    --ca-file) [ -z "$ASSETS_CA_FILE" ] || _assets_die "assets install: duplicate --ca-file"; ASSETS_CA_FILE=$2 ;;
                    --ca-sha256) [ -z "$ASSETS_CA_SHA256" ] || _assets_die "assets install: duplicate --ca-sha256"; ASSETS_CA_SHA256=$2 ;;
                    --kibana-endpoint) [ -z "$ASSETS_KIBANA" ] || _assets_die "assets install: duplicate --kibana-endpoint"; ASSETS_KIBANA=$2 ;;
                    --admin-credentials-file) [ -z "$ASSETS_ADMIN_SOURCE" ] || _assets_die "assets install: duplicate --admin-credentials-file"; ASSETS_ADMIN_SOURCE=$2 ;;
                    --ownership-profile) ASSETS_OWNERSHIP=$2 ;;
                esac; shift 2 ;;
            --repair) ASSETS_REPAIR=1; shift ;;
            --upgrade) ASSETS_UPGRADE=1; shift ;;
            --allow-downgrade) ASSETS_ALLOW_DOWNGRADE=1; shift ;;
            --non-interactive|--noninteractive) ASSETS_NONINTERACTIVE=1; shift ;;
            *) _assets_die "Usage: rigsignal assets install [--bundle PATH] [--endpoint URL] [--ca-file PATH --ca-sha256 HEX] [--kibana-endpoint URL] [--admin-credentials-file PATH] [--non-interactive]" ;;
        esac
    done
    [ -z "$ASSETS_CA_SHA256" ] || { case "$ASSETS_CA_SHA256" in *[!0123456789abcdefABCDEF]*|'') _assets_die "assets install: --ca-sha256 must be 64 hexadecimal characters";; esac; [ "${#ASSETS_CA_SHA256}" -eq 64 ] || _assets_die "assets install: --ca-sha256 must be 64 hexadecimal characters"; }
    [ -z "$ASSETS_CA_SHA256" ] || [ -n "$ASSETS_CA_FILE" ] || _assets_die "assets install: --ca-sha256 requires --ca-file"
    [ "$ASSETS_OWNERSHIP" != fleet-coexist ] || _assets_refuse "fleet_coexist_requires_full_flow: use the full packaged engine flow."
    [ "$ASSETS_OWNERSHIP" = default ] || _assets_die "assets install: invalid --ownership-profile"
    for _assets_env in RIGSIGNAL_CONFIG ES_URL ES_CA_CERT RIGSIGNAL_ENDPOINT RIGSIGNAL_CA_FILE RIGSIGNAL_KIBANA_ENDPOINT KIBANA_ENDPOINT; do
        _assets_env_value=$(printenv "$_assets_env" 2>/dev/null || true)
        [ -z "$_assets_env_value" ] || _assets_die "assets install: refusing ambiguous environment override $_assets_env"
    done
    resolve_assets_installation || _assets_die "assets install: matching engine installation is unavailable"
    ASSETS_TMP=$(mktemp -d "${TMPDIR:-/tmp}/rigsignal-assets.XXXXXX") || _assets_die "assets install: could not create private temporary directory"
    chmod 700 "$ASSETS_TMP" || _assets_die "assets install: could not secure temporary directory"
    ASSETS_ENGINE_PID="" ASSETS_ENGINE_SPAWNED=0
    trap assets_cleanup EXIT
    trap 'assets_interrupted HUP' HUP
    trap 'assets_interrupted INT' INT
    trap 'assets_interrupted TERM' TERM
    assets_load_persisted_inputs || _assets_die "assets install: persisted launcher configuration is invalid"
    [ -n "$ASSETS_ENDPOINT" ] || ASSETS_ENDPOINT=$ASSETS_PERSISTED_ENDPOINT
    [ -n "$ASSETS_KIBANA" ] || ASSETS_KIBANA=$ASSETS_PERSISTED_KIBANA
    [ -n "$ASSETS_CA_FILE" ] || ASSETS_CA_FILE=$ASSETS_PERSISTED_CA
    if [ "$ASSETS_NONINTERACTIVE" = 1 ] && { [ -z "$ASSETS_ENDPOINT" ] || [ -z "$ASSETS_CA_FILE" ] || [ -z "$ASSETS_KIBANA" ] || [ -z "$ASSETS_ADMIN_SOURCE" ]; }; then
        _assets_die "assets install: noninteractive input missing (endpoint, CA, Kibana endpoint, or administrator credentials)"
    fi
    if [ -z "$ASSETS_ENDPOINT" ]; then printf "Elasticsearch endpoint: " >&2; IFS= read -r ASSETS_ENDPOINT || _assets_die "assets install: endpoint is required"; fi
    validate_endpoint "$ASSETS_ENDPOINT" || _assets_die "assets install: Elasticsearch endpoint is invalid"
    if [ -z "$ASSETS_CA_FILE" ]; then printf "Elasticsearch CA file: " >&2; IFS= read -r ASSETS_CA_FILE || _assets_die "assets install: CA file is required"; fi
    assets_snapshot_ca "$ASSETS_CA_FILE" || _assets_die "assets install: CA file is required and must be valid"
    if [ -z "$ASSETS_KIBANA" ]; then printf "Kibana endpoint: " >&2; IFS= read -r ASSETS_KIBANA || _assets_die "assets install: Kibana endpoint is required"; fi
    if ! validate_url_origin "$ASSETS_KIBANA"; then
        _assets_die "assets install: Kibana endpoint must be an HTTPS origin with a valid host and optional port"
    fi
    case "$ASSETS_KIBANA" in
        https://*) ;;
        *) _assets_die "assets install: Kibana endpoint must be an HTTPS origin with a valid host and optional port" ;;
    esac
    persist_kibana_endpoint "$ASSETS_KIBANA" || _assets_die "assets install: could not atomically persist Kibana endpoint"
    _assets_ebpf=$(find_ebpf_bin)
    if [ -n "$_assets_ebpf" ] && ! synchronize_ebpf_system_config "$CA_SNAPSHOT"; then
        if [ "${SYSTEM_SCOPE_RESTORED:-0}" = "1" ]; then
            assets_rollback_kibana_transaction
        else
            _err "The eBPF system configuration could not be restored; retaining the matching user transaction."
        fi
        _assets_die "assets install: eBPF system config synchronization failed"
    fi
    assets_commit_kibana_transaction || _assets_die "assets install: could not finalize Kibana endpoint persistence"
    materialize_admin_file || _assets_die "assets install: administrator credentials must be exactly [elasticsearch] username/password TOML"
    if [ -n "$ASSETS_BUNDLE" ]; then
        [ -f "$ASSETS_BUNDLE" ] && [ -r "$ASSETS_BUNDLE" ] || _assets_die "assets install: bundle is not readable"
        _assets_name=$(basename "$ASSETS_BUNDLE")
        cp "$ASSETS_BUNDLE" "$ASSETS_TMP/$_assets_name" || _assets_die "assets install: could not snapshot bundle"
        cp "$ASSETS_BUNDLE.sha256" "$ASSETS_TMP/$_assets_name.sha256" || _assets_die "assets install: offline bundle requires $ASSETS_BUNDLE.sha256"
    else
        [ "$ASSETS_CHANNEL" != rigsignal-git ] || _assets_die "assets install: rigsignal-git requires --bundle; no release lookup was attempted"
        _assets_name="rigsignal-assets-${ASSETS_VERSION}.tar.gz"
        _assets_base="https://github.com/MathewRJ/RigSignal/releases/download/v${ASSETS_VERSION}"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$_assets_base/$_assets_name" -o "$ASSETS_TMP/$_assets_name" && curl -fsSL "$_assets_base/$_assets_name.sha256" -o "$ASSETS_TMP/$_assets_name.sha256" || _assets_die "assets install: matching release v${ASSETS_VERSION} is unavailable; use --bundle"
        elif command -v wget >/dev/null 2>&1; then
            wget -qO "$ASSETS_TMP/$_assets_name" "$_assets_base/$_assets_name" && wget -qO "$ASSETS_TMP/$_assets_name.sha256" "$_assets_base/$_assets_name.sha256" || _assets_die "assets install: matching release v${ASSETS_VERSION} is unavailable; use --bundle"
        else _assets_die "assets install: curl or wget is required to download the release bundle"; fi
    fi
    ASSETS_BUNDLE_SNAPSHOT="$ASSETS_TMP/$_assets_name" ASSETS_SIDECAR_SNAPSHOT="$ASSETS_TMP/$_assets_name.sha256"
    _assets_digest=$(assets_sidecar_digest "$ASSETS_SIDECAR_SNAPSHOT" "$_assets_name") || _assets_die "assets install: invalid bundle checksum sidecar"
    command -v sha256sum >/dev/null 2>&1 || _assets_die "assets install: sha256sum is required"
    _assets_actual=$(sha256sum "$ASSETS_BUNDLE_SNAPSHOT") || _assets_die "assets install: could not hash bundle snapshot"
    [ "${_assets_actual%% *}" = "$_assets_digest" ] || _assets_die "assets install: bundle checksum verification failed"
    # These values are shell variables, never reparsed input; invoke directly
    # so paths and the one-shot credential remain out of logs and argv secrets.
    if [ "$ASSETS_REPAIR" = 1 ]; then set -- --repair; else set --; fi
    [ "$ASSETS_UPGRADE" = 0 ] || set -- "$@" --upgrade
    [ "$ASSETS_ALLOW_DOWNGRADE" = 0 ] || set -- "$@" --allow-downgrade
    # On a signal the cancellation handler owns reaping and exits; this
    # ordinary wait path is only resumed when no cancellation was handled.
    set +e
    # Declare the spawn before the fork and retire it only once the engine has
    # been reaped: this flag is what licenses the handler to resolve the pid
    # from $! during the spawn/registration window, and what stops it doing so
    # once $! names a reaped pid whose number may have been recycled.
    ASSETS_ENGINE_SPAWNED=1
    python3 "$ASSETS_ENGINE/install_assets.py" --assets-only --profile user --ownership-profile default \
        --bundle "$ASSETS_BUNDLE_SNAPSHOT" --endpoint "$ASSETS_ENDPOINT" --ca-file "$CA_SNAPSHOT" \
        --kibana-endpoint "$ASSETS_KIBANA" --kibana-ca-file "$CA_SNAPSHOT" \
        --admin-credentials-file "$ASSETS_CREDENTIAL_FILE" --agent-binary "$ASSETS_AGENT" "$@" &
    ASSETS_ENGINE_PID=$!
    wait "$ASSETS_ENGINE_PID"
    ASSETS_ENGINE_STATUS=$?
    ASSETS_ENGINE_SPAWNED=0
    ASSETS_ENGINE_PID=""
    set -e
    return "$ASSETS_ENGINE_STATUS"
}

# ── Subcommand: setup ──────────────────────────────────────────────────────────

toml_quote() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

fsync_file_and_dir() {
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$1" "$2" >/dev/null 2>&1 <<'PYEOF'
import os
import sys
for path in sys.argv[1:]:
    fd = os.open(path, os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if os.path.isdir(path) else 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
PYEOF
        return $?
    fi
    # Setup can use curl when Python is unavailable.  A whole-filesystem sync
    # is a conservative durability fallback for this one-shot operation.
    command -v sync >/dev/null 2>&1 && sync
}

validate_ca_snapshot() {
    _ca_path="$1"
    # Setup validates only the strict PEM envelope: complete certificate blocks
    # with whitespace only outside them.  Elasticsearch's TLS handshake, then
    # the agent preflight, remain the authority for X.509 validity and trust.
    awk '
        BEGIN {
            # A sentinel record separator makes the entire file one record,
            # including CRLF and a missing final newline.
            RS = "\034"
            begin = "-----BEGIN CERTIFICATE-----"
            end = "-----END CERTIFICATE-----"
        }
        {
            remainder = $0
            gsub(/^[ \t\r\n]+/, "", remainder)
            gsub(/[ \t\r\n]+$/, "", remainder)
            if (remainder == "") exit 1

            while (remainder != "") {
                if (index(remainder, begin) != 1) exit 1
                certificate = substr(remainder, length(begin) + 1)
                end_at = index(certificate, end)
                if (end_at == 0) exit 1
                remainder = substr(certificate, end_at + length(end))
                gsub(/^[ \t\r\n]+/, "", remainder)
                gsub(/[ \t\r\n]+$/, "", remainder)
            }
            valid = 1
            exit
        }
        END { exit valid ? 0 : 1 }
    ' "$_ca_path"
}

verify_ca_pin() {
    _ca_path="$1"
    _expected_sha="$2"
    [ -n "$_expected_sha" ] || return 0
    command -v sha256sum >/dev/null 2>&1 || {
        _err "sha256sum is required to verify --ca-sha256."
        return 1
    }
    _actual_sha=$(sha256sum "$_ca_path" | awk '{print $1}')
    _expected_sha=$(printf '%s' "$_expected_sha" | tr 'A-F' 'a-f')
    if [ "$_actual_sha" != "$_expected_sha" ]; then
        _err "CA SHA-256 does not match --ca-sha256; refusing before contacting Elasticsearch."
        return 1
    fi
}

snapshot_ca() {
    _ca_source="$1"
    _expected_sha="$2"
    [ -n "$_ca_source" ] || return 0
    # Reuse an early explicit snapshot or persisted CA during reauthentication.
    # Otherwise copy once before hashing, structural validation, or TLS so later
    # consumers never reopen a caller-controlled or durable path.
    if [ -n "${CA_SNAPSHOT:-}" ] && [ "${CA_SNAPSHOT_SOURCE:-}" = "$_ca_source" ]; then
        return 0
    fi
    [ -z "${CA_SNAPSHOT:-}" ] || rm -f "$CA_SNAPSHOT"
    CA_SNAPSHOT=""
    CA_SNAPSHOT_SOURCE=""
    [ -f "$_ca_source" ] && [ -r "$_ca_source" ] || {
        _err "CA file is not readable: $_ca_source"
        return 1
    }
    mkdir -p "$CERT_DIR" || return 1
    chmod 700 "$CONFIG_DIR" "$CERT_DIR" || return 1
    CA_SNAPSHOT=$(mktemp "$CERT_DIR/.elasticsearch-ca.pem.XXXXXX") || return 1
    chmod 600 "$CA_SNAPSHOT" || return 1
    cp "$_ca_source" "$CA_SNAPSHOT" || return 1
    verify_ca_pin "$CA_SNAPSHOT" "$_expected_sha" || return 1
    if ! validate_ca_snapshot "$CA_SNAPSHOT"; then
        _err "CA file must be a non-empty PEM certificate bundle: $_ca_source"
        return 1
    fi
    CA_SNAPSHOT_SOURCE=$_ca_source
}

# Rewrite only the managed [elasticsearch] fields; all other bytes remain intact
# where TOML's line-oriented representation permits it.
mutate_elasticsearch_config() {
    _input="$1"
    _output="$2"
    _endpoint_q=$(toml_quote "$3")
    _api_key_q=$(toml_quote "$4")
    _ca_cert_q=$(toml_quote "$5")
    if [ ! -f "$_input" ]; then
        cat > "$_output" <<TOML
# RigSignal configuration — written by 'rigsignal setup'
# SECURITY: this file contains your API key. Permissions are set to 600.

[elasticsearch]
endpoint = "$_endpoint_q"
api_key = "$_api_key_q"
${_ca_cert_q:+ca_cert = "$_ca_cert_q"}

[collection]
# All collectors enabled by default.
ebpf = false

[session]
# Optional: set a fixed label for all sessions.
# label = ""
TOML
        return
    fi
    awk -v endpoint="$_endpoint_q" -v api_key="$_api_key_q" -v ca_cert="$_ca_cert_q" '
        function flush_missing() {
            if (in_es) {
                if (!seen_endpoint) print "endpoint = \"" endpoint "\""
                if (!seen_api_key) print "api_key = \"" api_key "\""
                if (!seen_ca_cert && ca_cert != "") print "ca_cert = \"" ca_cert "\""
            }
        }
        /^\[elasticsearch\][ \t]*(#.*)?$/ {
            flush_missing(); in_es=1; found=1
            seen_endpoint=seen_api_key=seen_ca_cert=0
            print; next
        }
        /^\[[^]]+\]/ {
            flush_missing(); in_es=0
        }
        {
            if (in_es && $0 ~ /^[ \t]*(endpoint|api_key|ca_cert)[ \t]*=/) {
                key=$0; sub(/^[ \t]*/, "", key); sub(/[ \t]*=.*/, "", key)
                match($0, /^[ \t]*/); indent=substr($0, RSTART, RLENGTH)
                comment=""; if (match($0, /[ \t]+#/)) comment=substr($0, RSTART)
                if (key == "endpoint") { print indent "endpoint = \"" endpoint "\"" comment; seen_endpoint=1; next }
                if (key == "api_key") { print indent "api_key = \"" api_key "\"" comment; seen_api_key=1; next }
                if (key == "ca_cert") { if (ca_cert != "") print indent "ca_cert = \"" ca_cert "\"" comment; seen_ca_cert=1; next }
            }
            print
        }
        END {
            flush_missing()
            if (!found) {
                print ""
                print "[elasticsearch]"
                print "endpoint = \"" endpoint "\""
                print "api_key = \"" api_key "\""
                if (ca_cert != "") print "ca_cert = \"" ca_cert "\""
            }
        }
    ' "$_input" > "$_output"
}

# The system copy is derived from the finished user TOML.  Its only textual
# difference is the root-readable CA location; endpoint, credentials, comments,
# and every other field remain byte-for-byte intact.
rewrite_system_ca_cert() {
    _input="$1"
    _output="$2"
    _ca_cert_q=$(toml_quote "$3")
    awk -v ca_cert="$_ca_cert_q" '
        function flush_missing() {
            if (in_es && !seen_ca_cert && ca_cert != "") print "ca_cert = \"" ca_cert "\""
        }
        /^\[elasticsearch\][ \t]*(#.*)?$/ {
            flush_missing(); in_es=1; found=1; seen_ca_cert=0
            print; next
        }
        /^\[[^]]+\]/ { flush_missing(); in_es=0 }
        {
            if (in_es && $0 ~ /^[ \t]*ca_cert[ \t]*=/) {
                match($0, /^[ \t]*/); indent=substr($0, RSTART, RLENGTH)
                comment=""; if (match($0, /[ \t]+#/)) comment=substr($0, RSTART)
                if (ca_cert != "") print indent "ca_cert = \"" ca_cert "\"" comment
                seen_ca_cert=1
                next
            }
            print
        }
        END {
            flush_missing()
            if (!found && ca_cert != "") {
                print ""
                print "[elasticsearch]"
                print "ca_cert = \"" ca_cert "\""
            }
        }
    ' "$_input" > "$_output"
}

find_ebpf_bin() {
    _ebpf_bin=$(command -v rigsignal-ebpf 2>/dev/null || true)
    if [ -z "$_ebpf_bin" ]; then
        for _ebpf_candidate in /usr/local/bin/rigsignal-ebpf /usr/bin/rigsignal-ebpf "$HOME/.local/bin/rigsignal-ebpf"; do
            if [ -x "$_ebpf_candidate" ]; then
                _ebpf_bin=$_ebpf_candidate
                break
            fi
        done
    fi
    printf '%s\n' "$_ebpf_bin"
}

rollback_system_transaction() {
    _rollback_ok=1
    # Do not remove an old target until its staged backup was proven to exist.
    # This keeps a failed backup move from destroying the original.
    if [ "$_system_ca_backup_ready" = "1" ]; then
        sudo rm -f "$_system_ca" >/dev/null 2>&1 || _rollback_ok=0
        if sudo mv "${_system_ca}.bak" "$_system_ca" >/dev/null 2>&1; then
            _system_ca_backup_ready=0
        else
            _rollback_ok=0
        fi
    elif [ "$_system_ca_had" = "0" ] && [ "$_system_ca_replaced" = "1" ]; then
        sudo rm -f "$_system_ca" >/dev/null 2>&1 || _rollback_ok=0
    fi
    if [ "$_system_cfg_backup_ready" = "1" ]; then
        sudo rm -f "$_system_cfg" >/dev/null 2>&1 || _rollback_ok=0
        if sudo mv "${_system_cfg}.bak" "$_system_cfg" >/dev/null 2>&1; then
            _system_cfg_backup_ready=0
        else
            _rollback_ok=0
        fi
    elif [ "$_system_cfg_had" = "0" ] && [ "$_system_cfg_replaced" = "1" ]; then
        sudo rm -f "$_system_cfg" >/dev/null 2>&1 || _rollback_ok=0
    fi
    [ "$_rollback_ok" = "1" ]
}

cleanup_system_transaction_temps() {
    # mktemp under /etc is privileged, so the ordinary assets EXIT cleanup
    # cannot remove these files directly.  This helper is shared by S4 and the
    # assets signal path, including interruption after a root replacement.
    if command -v sudo >/dev/null 2>&1; then
        sudo rm -f "${_system_ca_tmp:-}" "${_system_cfg_tmp:-}" >/dev/null 2>&1 || true
    fi
    rm -f "${_sync_tmp:-}" 2>/dev/null || true
    _system_ca_tmp="" _system_cfg_tmp=""
}

# This is the only setup path that owns /etc/rigsignal/rigsignal.toml and its
# CA copy.  It is deliberately reusable by S5 without adding another dispatcher.
synchronize_ebpf_system_config() {
    _sync_ca="$1"
    command -v sudo >/dev/null 2>&1 || return 1
    SYSTEM_SCOPE_RESTORED=0
    SYSTEM_SCOPE_TRANSACTION_ACTIVE=0
    _sync_tmp=$(mktemp "$CONFIG_DIR/.rigsignal-system.XXXXXX") || return 1
    chmod 600 "$_sync_tmp" || return 1
    rewrite_system_ca_cert "$CONFIG_FILE" "$_sync_tmp" \
        "${_sync_ca:+/etc/rigsignal/certs/elasticsearch-ca.pem}" || return 1

    _ebpf_was_active=0
    sudo systemctl is-active --quiet "$EBPF_UNIT" >/dev/null 2>&1 && _ebpf_was_active=1
    SETUP_EBPF_WAS_ACTIVE=$_ebpf_was_active
    if [ "$_ebpf_was_active" = "1" ] && ! sudo systemctl stop "$EBPF_UNIT"; then
        rm -f "$_sync_tmp"
        return 1
    fi

    # The EXIT trap restores this if setup is interrupted during elevation.
    _sync_ok=1
    if command -v steamos-readonly >/dev/null 2>&1; then
        sudo steamos-readonly disable >/dev/null 2>&1 || _sync_ok=0
        [ "$_sync_ok" = "1" ] && STEAMOS_READONLY_DISABLED=1
    fi
    if [ "$_sync_ok" = "1" ]; then
        sudo mkdir -p /etc/rigsignal/certs && sudo chmod 700 /etc/rigsignal /etc/rigsignal/certs || _sync_ok=0
    fi

    _system_ca=/etc/rigsignal/certs/elasticsearch-ca.pem
    _system_cfg=/etc/rigsignal/rigsignal.toml
    _system_ca_had=0
    _system_cfg_had=0
    _system_ca_backup_ready=0
    _system_cfg_backup_ready=0
    _system_ca_replaced=0
    _system_cfg_replaced=0
    _system_ca_tmp=""
    _system_cfg_tmp=""
    SYSTEM_SCOPE_TRANSACTION_ACTIVE=1
    [ "$_sync_ok" = "1" ] && sudo test -e "$_system_ca" && _system_ca_had=1
    [ "$_sync_ok" = "1" ] && sudo test -e "$_system_cfg" && _system_cfg_had=1
    if [ "$_sync_ok" = "1" ]; then
        sudo rm -f "${_system_ca}.bak" "${_system_cfg}.bak" >/dev/null 2>&1 || _sync_ok=0
        if [ "$_sync_ok" = "1" ] && [ "$_system_ca_had" = "1" ]; then
            sudo mv "$_system_ca" "${_system_ca}.bak" && sudo test -e "${_system_ca}.bak" \
                && _system_ca_backup_ready=1 || _sync_ok=0
        fi
        if [ "$_sync_ok" = "1" ] && [ "$_system_cfg_had" = "1" ]; then
            sudo mv "$_system_cfg" "${_system_cfg}.bak" && sudo test -e "${_system_cfg}.bak" \
                && _system_cfg_backup_ready=1 || _sync_ok=0
        fi
    fi
    if [ "$_sync_ok" = "1" ] && [ -n "$_sync_ca" ]; then
        _system_ca_tmp=$(sudo mktemp /etc/rigsignal/certs/.elasticsearch-ca.pem.XXXXXX) || _sync_ok=0
        [ "$_sync_ok" = "1" ] && sudo install -m 600 "$_sync_ca" "$_system_ca_tmp" \
            && sudo mv "$_system_ca_tmp" "$_system_ca" && _system_ca_replaced=1 || _sync_ok=0
    fi
    if [ "$_sync_ok" = "1" ]; then
        _system_cfg_tmp=$(sudo mktemp /etc/rigsignal/.rigsignal.toml.XXXXXX) || _sync_ok=0
        [ "$_sync_ok" = "1" ] && sudo install -m 600 "$_sync_tmp" "$_system_cfg_tmp" \
            && sudo mv "$_system_cfg_tmp" "$_system_cfg" && _system_cfg_replaced=1 || _sync_ok=0
    fi
    if [ "$_sync_ok" = "1" ]; then
        if [ -n "$_sync_ca" ]; then
            sudo python3 - "$_system_cfg" /etc/rigsignal "$_system_ca" /etc/rigsignal/certs <<'PYEOF' >/dev/null 2>&1 || _sync_ok=0
import os
import sys
for path in sys.argv[1:]:
    fd = os.open(path, os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if os.path.isdir(path) else 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
PYEOF
        else
            sudo python3 - "$_system_cfg" /etc/rigsignal <<'PYEOF' >/dev/null 2>&1 || _sync_ok=0
import os
import sys
for path in sys.argv[1:]:
    fd = os.open(path, os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if os.path.isdir(path) else 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
PYEOF
        fi
    fi
    if [ "$_sync_ok" = "1" ] && [ "$_ebpf_was_active" = "1" ]; then
        sudo systemctl start "$EBPF_UNIT" && sudo systemctl is-active --quiet "$EBPF_UNIT" || _sync_ok=0
    fi
    # Restore root scope while SteamOS is still writable.  If this fails, leave
    # the caller's matching user transaction intact rather than making it mixed.
    if [ "$_sync_ok" != "1" ]; then
        rollback_system_transaction || _sync_ok=0
        [ "$_system_ca_backup_ready" = "0" ] && [ "$_system_cfg_backup_ready" = "0" ] \
            && SYSTEM_SCOPE_RESTORED=1
    fi
    if [ "${STEAMOS_READONLY_DISABLED:-0}" = "1" ]; then
        # A read-only restore failure is also a transaction failure: restore
        # /etc before returning so the caller can safely roll back user scope.
        if sudo steamos-readonly enable >/dev/null 2>&1; then
            STEAMOS_READONLY_DISABLED=0
        else
            _sync_ok=0
        fi
    fi
    # A failed re-enable leaves SteamOS writable, so rollback can still occur.
    # This makes the root rollback and the caller's user rollback one failure
    # path, rather than returning a new root config beside an old user config.
    if [ "$_sync_ok" != "1" ]; then
        rollback_system_transaction || _sync_ok=0
        [ "$_system_ca_backup_ready" = "0" ] && [ "$_system_cfg_backup_ready" = "0" ] \
            && SYSTEM_SCOPE_RESTORED=1
    fi
    cleanup_system_transaction_temps
    if [ "$_sync_ok" = "1" ]; then
        sudo rm -f "${_system_ca}.bak" "${_system_cfg}.bak" >/dev/null 2>&1 || true
        SYSTEM_SCOPE_TRANSACTION_ACTIVE=0
    elif [ "${SYSTEM_SCOPE_RESTORED:-0}" = "1" ]; then
        SYSTEM_SCOPE_TRANSACTION_ACTIVE=0
    fi
    [ "$_sync_ok" = "1" ]
}

cleanup_setup() {
    _cleanup_status=$?
    _cleanup_failed=0
    if [ "${STEAMOS_READONLY_DISABLED:-0}" = "1" ]; then
        if sudo steamos-readonly enable >/dev/null 2>&1; then
            STEAMOS_READONLY_DISABLED=0
        else
            # One immediate retry covers transient SteamOS service failures.
            if sudo steamos-readonly enable >/dev/null 2>&1; then
                STEAMOS_READONLY_DISABLED=0
            else
                _err "SteamOS left writable — run steamos-readonly enable"
                _cleanup_failed=1
            fi
        fi
    fi
    rm -f "${CA_SNAPSHOT:-}" "${tmp_cfg:-}" 2>/dev/null || true
    rmdir "$CONFIG_DIR/.setup.lock" 2>/dev/null || true
    [ "$_cleanup_failed" = "0" ] || return 1
    return "$_cleanup_status"
}

rollback_user_transaction() {
    if [ "${USER_CONFIG_HAD:-0}" = "0" ]; then
        rm -f "$CONFIG_FILE" 2>/dev/null || true
    elif [ "${USER_CONFIG_BACKUP_READY:-0}" = "1" ]; then
        rm -f "$CONFIG_FILE" 2>/dev/null || true
        mv "${CONFIG_FILE}.bak" "$CONFIG_FILE" 2>/dev/null || true
    fi
    if [ "${USER_CA_CHANGED:-0}" = "1" ]; then
        if [ "${USER_CA_HAD:-0}" = "0" ]; then
            rm -f "$CERT_FILE" 2>/dev/null || true
        elif [ "${USER_CA_BACKUP_READY:-0}" = "1" ]; then
            rm -f "$CERT_FILE" 2>/dev/null || true
            mv "${CERT_FILE}.bak" "$CERT_FILE" 2>/dev/null || true
        fi
    fi
}

setup_interrupted() {
    trap - HUP INT TERM
    exit 128
}

recheck_elasticsearch_delivery() {
    es_request "$SETUP_ENDPOINT" "$SETUP_API_KEY" GET "/" "" "${CA_SNAPSHOT:-}"
    if ! is_2xx "$ES_STATUS"; then
        _err "Post-restart authenticated Elasticsearch recheck failed (HTTP status: ${ES_STATUS:-0})."
        _info "Verify the endpoint, API key, and CA, then rerun rigsignal setup before relying on telemetry delivery."
        return 1
    fi
    return 0
}

parse_setup_args() {
    SETUP_CA_FILE=""
    SETUP_CA_SHA256=""
    SETUP_ALLOW_UNKNOWN_VERSION=0
    SETUP_ARG_ERROR="usage"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --ca-file)
                [ -z "$SETUP_CA_FILE" ] && [ "$#" -ge 2 ] && [ -n "$2" ] || return 1
                SETUP_CA_FILE=$2; shift 2 ;;
            --ca-sha256)
                [ -z "$SETUP_CA_SHA256" ] && [ "$#" -ge 2 ] && [ -n "$2" ] || return 1
                SETUP_CA_SHA256=$2; shift 2 ;;
            --allow-unknown-version)
                SETUP_ALLOW_UNKNOWN_VERSION=1; shift ;;
            *) return 1 ;;
        esac
    done
    if [ -n "$SETUP_CA_SHA256" ]; then
        case "$SETUP_CA_SHA256" in *[!0123456789abcdefABCDEF]*) return 1 ;; esac
        [ "${#SETUP_CA_SHA256}" -eq 64 ] || return 1
    fi
    [ -z "$SETUP_CA_SHA256" ] || [ -n "$SETUP_CA_FILE" ] || {
        SETUP_ARG_ERROR="pin"
        _err "--ca-sha256 requires --ca-file; a pin alone cannot establish trust."
        return 1
    }
    return 0
}

cmd_setup() {
    # Debug tracing would expand the API key in command arguments. Disable it
    # for setup so credentials never reach the persistent launcher debug log.
    [ "${RIGSIGNAL_DEBUG:-0}" = "1" ] && set +x

    if ! parse_setup_args "$@"; then
        [ "$SETUP_ARG_ERROR" = "pin" ] || _err "Usage: rigsignal setup [--ca-file <path> [--ca-sha256 <64-hex>]] [--allow-unknown-version]"
        exit 1
    fi
    CA_SNAPSHOT=""
    CA_SNAPSHOT_SOURCE=""
    STEAMOS_READONLY_DISABLED=0
    trap cleanup_setup EXIT
    trap setup_interrupted HUP INT TERM
    if [ -n "$SETUP_CA_FILE" ]; then
        mkdir -p "$CONFIG_DIR" || _die "Could not create $CONFIG_DIR."
        chmod 700 "$CONFIG_DIR" || _die "Could not secure $CONFIG_DIR."
        snapshot_ca "$SETUP_CA_FILE" "$SETUP_CA_SHA256" || exit 1
    fi
    for _override in RIGSIGNAL_CONFIG ES_URL ES_API_KEY ES_CA_CERT; do
        eval "_override_value=\${$_override:-}"
        [ -z "$_override_value" ] || _die "Refusing setup while $_override is set: unset it so the selected Elasticsearch target is unambiguous."
    done

    mkdir -p "$CONFIG_DIR" || _die "Could not create $CONFIG_DIR."
    chmod 700 "$CONFIG_DIR" || _die "Could not secure $CONFIG_DIR."
    mkdir "$CONFIG_DIR/.setup.lock" 2>/dev/null || _die "Another RigSignal setup is in progress; retry when it finishes."

    # Check for existing valid config first.  An explicit CA is a requested
    # replacement, so it intentionally continues through the durable write path.
    if [ -f "$CONFIG_FILE" ]; then
        existing_endpoint=$(toml_get "endpoint" "$CONFIG_FILE")
        existing_key=$(toml_get "api_key" "$CONFIG_FILE")
        existing_ca=$(toml_get "ca_cert" "$CONFIG_FILE")

        if [ -n "$existing_endpoint" ] && [ -n "$existing_key" ]; then
            validate_endpoint "$existing_endpoint" || exit 1
            SETUP_ENDPOINT=$existing_endpoint
            SETUP_API_KEY=$existing_key
            _ca_source=$SETUP_CA_FILE
            [ -n "$_ca_source" ] || _ca_source=$existing_ca
            if [ -z "$_ca_source" ] && [ "${existing_endpoint#https://}" != "$existing_endpoint" ]; then
                printf "CA certificate file (leave empty to use system trust): "
                read -r _ca_source
            fi
            snapshot_ca "$_ca_source" "$SETUP_CA_SHA256" || exit 1
            printf "       Config found: %s\n" "$CONFIG_FILE"
            printf "       Endpoint:     %s\n" "$existing_endpoint"
            printf "       Verifying authentication and write privileges...\n"
            if validate_elasticsearch "$existing_endpoint" "$existing_key" "$CA_SNAPSHOT"; then
                if [ -z "$SETUP_CA_FILE" ] && [ -z "$CA_SNAPSHOT" ]; then
                    _ok "Already configured. Authentication and write privileges verified."
                    _ebpf_bin=$(find_ebpf_bin)
                    if [ -n "$_ebpf_bin" ]; then
                        synchronize_ebpf_system_config "" || _die "eBPF is installed but its system config could not be synchronized. Restore sudo access, then rerun rigsignal setup."
                        _ok "eBPF daemon config synchronized under /etc/rigsignal"
                        [ "${SETUP_EBPF_WAS_ACTIVE:-0}" = "0" ] || recheck_elasticsearch_delivery || exit 1
                    fi
                    return 0
                fi
                _ok "Authentication and write privileges verified. Updating the CA snapshot."
            else
                _warn "Already configured but connection failed."
                printf "       Endpoint: %s\n" "$existing_endpoint"
                printf "       Re-running setup to update credentials.\n\n"
                SETUP_ENDPOINT=""
                SETUP_API_KEY=""
            fi
        fi
    fi

    if [ -z "${SETUP_ENDPOINT:-}" ]; then
    # Print a brief explanation.
    printf '\n%sRigSignal Setup%s\n' "$_GRN" "$_NC"
    printf "===============\n"
    printf "RigSignal ships gaming metrics to Elasticsearch.\n"
    printf "You need an Elastic Cloud deployment (or self-hosted ES %s or newer).\n\n" "$ES_SUPPORTED_FLOOR_VERSION"
    printf "You will need:\n"
    printf "  - Your Elasticsearch endpoint URL\n"
    printf "  - An API key with write access to metrics-rigsignal.* indices\n\n"

    # Prompt for endpoint.
    printf "Elasticsearch endpoint\n"
    printf "  Example: https://my-deployment.es.us-central1.gcp.elastic.cloud\n"
    printf "  Endpoint: "
    read -r endpoint

    if [ -z "$endpoint" ]; then
        _die "Endpoint cannot be empty."
    fi

    # Strip trailing slash.
    endpoint="${endpoint%/}"
    validate_endpoint "$endpoint" || exit 1

    # Prompt for API key (stty -echo to prevent it appearing in terminal logs).
    printf "API key (input hidden): "
    # Use stty to suppress echo if available (POSIX but may not work in all contexts)
    if stty -echo 2>/dev/null; then
        read -r api_key
        stty echo 2>/dev/null
        printf "\n"
    else
        read -r api_key
    fi

    if [ -z "$api_key" ]; then
        _die "API key cannot be empty."
    fi
    validate_api_key_shape "$api_key" || exit 1

    _ca_source=$SETUP_CA_FILE
    [ -n "$_ca_source" ] || _ca_source=${existing_ca:-}
    if [ -z "$_ca_source" ] && [ "${endpoint#https://}" != "$endpoint" ]; then
        printf "CA certificate file (leave empty to use system trust): "
        read -r _ca_source
    fi
    snapshot_ca "$_ca_source" "$SETUP_CA_SHA256" || exit 1

    SETUP_ENDPOINT=$endpoint
    SETUP_API_KEY=$api_key
    fi

    if [ -z "${existing_endpoint:-}" ] || [ "$SETUP_ENDPOINT" != "$existing_endpoint" ] || [ -z "${existing_key:-}" ] || [ "$SETUP_API_KEY" != "$existing_key" ]; then
        printf "       Verifying authentication and write privileges for %s ...\n" "$SETUP_ENDPOINT"
        if ! validate_elasticsearch "$SETUP_ENDPOINT" "$SETUP_API_KEY" "$CA_SNAPSHOT"; then
            exit 1
        fi
        _ok "Authentication and write privileges verified."
    fi

    # Stop only services that were active before replacing either user file.  This
    # is deliberately independent of eBPF discovery: the user agent reads this
    # config even on installations without the optional daemon.
    SETUP_AGENT_WAS_ACTIVE=0
    systemctl --user is-active --quiet "$AGENT_UNIT" 2>/dev/null && SETUP_AGENT_WAS_ACTIVE=1
    if [ "$SETUP_AGENT_WAS_ACTIVE" = "1" ] && ! systemctl --user stop "$AGENT_UNIT"; then
        _die "Could not stop $AGENT_UNIT before replacing its configuration."
    fi

    # Install the exact validated bytes and TOML as one user-scope transaction.
    # Keep the old files as .bak until both replacements and durability checks
    # succeed so a later write failure cannot leave a mixed configuration.
    if [ -n "$CA_SNAPSHOT" ]; then
        SETUP_CA_CERT=$CERT_FILE
    else
        SETUP_CA_CERT=""
    fi
    tmp_cfg=$(mktemp "$CONFIG_DIR/.rigsignal.toml.XXXXXX") || _die "Could not create a config temporary file."
    chmod 600 "$tmp_cfg"
    mutate_elasticsearch_config "$CONFIG_FILE" "$tmp_cfg" "$SETUP_ENDPOINT" "$SETUP_API_KEY" "$SETUP_CA_CERT" \
        || _die "Could not update Elasticsearch settings."
    fsync_file_and_dir "$tmp_cfg" "$CONFIG_DIR" || _die "Could not fsync the new configuration."
    USER_CONFIG_HAD=0 USER_CA_HAD=0 USER_CA_CHANGED=0
    USER_CONFIG_BACKUP_READY=0 USER_CA_BACKUP_READY=0
    [ -e "$CONFIG_FILE" ] && USER_CONFIG_HAD=1
    [ -n "$CA_SNAPSHOT" ] && USER_CA_CHANGED=1
    [ "$USER_CA_CHANGED" = "0" ] || { [ -e "$CERT_FILE" ] && USER_CA_HAD=1; }
    if [ "$USER_CONFIG_HAD" = "1" ]; then
        rm -f "${CONFIG_FILE}.bak" || _die "Could not clear the previous configuration rollback staging file."
        mv "$CONFIG_FILE" "${CONFIG_FILE}.bak" && [ -e "${CONFIG_FILE}.bak" ] \
            && USER_CONFIG_BACKUP_READY=1 || _die "Could not stage the previous configuration for rollback."
    fi
    if [ "$USER_CA_CHANGED" = "1" ]; then
        if [ "$USER_CA_HAD" = "1" ]; then
            rm -f "${CERT_FILE}.bak" || { rollback_user_transaction; _die "Could not clear the previous CA rollback staging file."; }
            mv "$CERT_FILE" "${CERT_FILE}.bak" && [ -e "${CERT_FILE}.bak" ] \
                && USER_CA_BACKUP_READY=1 || { rollback_user_transaction; _die "Could not stage the previous CA for rollback."; }
        fi
        _user_ca_tmp=$(mktemp "$CERT_DIR/.elasticsearch-ca.install.XXXXXX") || { rollback_user_transaction; _die "Could not create a CA temporary file."; }
        chmod 600 "$_user_ca_tmp" && install -m 600 "$CA_SNAPSHOT" "$_user_ca_tmp" && mv "$_user_ca_tmp" "$CERT_FILE" || { rm -f "$_user_ca_tmp"; rollback_user_transaction; _die "Could not install the CA snapshot."; }
    fi
    mv "$tmp_cfg" "$CONFIG_FILE" || { rollback_user_transaction; _die "Could not atomically replace $CONFIG_FILE."; }
    _user_durable=1
    fsync_file_and_dir "$CONFIG_FILE" "$CONFIG_DIR" || _user_durable=0
    if [ "$USER_CA_CHANGED" = "1" ]; then
        fsync_file_and_dir "$CERT_FILE" "$CERT_DIR" || _user_durable=0
    fi
    if [ "$_user_durable" != "1" ]; then
        rollback_user_transaction
        _die "Could not durably install the user configuration."
    fi

    _ok "Config written to $CONFIG_FILE"

    _ebpf_bin=$(find_ebpf_bin)
    if [ -n "$_ebpf_bin" ]; then
        if ! synchronize_ebpf_system_config "$CA_SNAPSHOT"; then
            if [ "${SYSTEM_SCOPE_RESTORED:-0}" = "1" ]; then
                rollback_user_transaction
            else
                _err "The eBPF system configuration could not be restored; leaving the matching user transaction in place to avoid a mixed configuration."
            fi
            [ "$SETUP_AGENT_WAS_ACTIVE" = "0" ] || systemctl --user start "$AGENT_UNIT" >/dev/null 2>&1 || true
            _die "eBPF is installed but its system config could not be synchronized. Restore sudo access, then rerun rigsignal setup --ca-file <path>."
        fi
        _ok "eBPF daemon config and CA updated under /etc/rigsignal"
    fi
    rm -f "${CONFIG_FILE}.bak" "${CERT_FILE}.bak"

    if [ "$SETUP_AGENT_WAS_ACTIVE" = "1" ]; then
        systemctl --user start "$AGENT_UNIT" && wait_agent_active || _die "Could not restart $AGENT_UNIT after updating its configuration."
    fi
    if [ "$SETUP_AGENT_WAS_ACTIVE" = "1" ] || [ "${SETUP_EBPF_WAS_ACTIVE:-0}" = "1" ]; then
        recheck_elasticsearch_delivery || exit 1
    fi

    _info "Run 'rigsignal start' to begin collecting, or add 'rigsignal run %command%' as a Steam launch option."
}

# ── Subcommand: start ──────────────────────────────────────────────────────────

cmd_start() {
    # Clearing a failed state is new here, and it is the other half of widening
    # the start limiter window.  Before that change the limiter could never trip,
    # so the unit could not reach `failed` by crash-looping and this path was
    # unreachable; now it can.  A unit in that state refuses `systemctl start`
    # with a generic exit-code error, and the diagnostic below used to blame a
    # missing installation -- the wrong cause, for a user who has just fixed
    # their configuration and is trying again.  `cmd_run` has cleared it since
    # the previous instance of this bug class; the documented start path did not.
    systemctl --user reset-failed "$AGENT_UNIT" >/dev/null 2>&1 || true
    # Start the user agent service.
    if systemctl --user start "$AGENT_UNIT" 2>/dev/null; then
        if wait_agent_active; then
            _ok "Agent started ($AGENT_UNIT)"
        else
            _warn "Agent started but did not become active within 10 s — check journald:"
            _info "  journalctl --user -u $AGENT_UNIT -n 20"
        fi
    else
        _die "Failed to start $AGENT_UNIT. Is it installed, and does its configuration parse? Check: systemctl --user status $AGENT_UNIT"
    fi

    # Try the eBPF system service (optional — degrades gracefully).
    ebpf_start || true
}

# ── Subcommand: stop ───────────────────────────────────────────────────────────

cmd_stop() {
    systemctl --user stop "$AGENT_UNIT" >/dev/null 2>&1 && _ok "Agent stopped" || true
    ebpf_stop && _ok "eBPF daemon stopped" || true
}

# ── Subcommand: status ─────────────────────────────────────────────────────────

cmd_status() {
    # Agent service state — split capture from fallback so the fallback
    # echo doesn't double-up with systemctl's own stdout inside $().
    agent_state=$(systemctl --user is-active "$AGENT_UNIT" 2>/dev/null) || agent_state="inactive"
    ebpf_state=$(systemctl is-active "$EBPF_UNIT" 2>/dev/null) || ebpf_state="inactive"

    printf "\n  Agent  (%s): %s\n" "$AGENT_UNIT" "$agent_state"
    printf "  eBPF   (%s):  %s\n\n" "$EBPF_UNIT" "$ebpf_state"

    # Last session label from journald (if agent was ever run).
    last_label=$(journalctl --user -u "$AGENT_UNIT" -n 50 --no-pager 2>/dev/null \
        | grep -o 'label="[^"]*"' | tail -1 | sed 's/label="//;s/"//')
    last_game=$(journalctl --user -u "$AGENT_UNIT" -n 50 --no-pager 2>/dev/null \
        | grep "Game detected:" | tail -1 \
        | sed 's/.*Game detected: \([^(]*\).*/\1/' | sed 's/[[:space:]]*$//')

    if [ -n "$last_game" ]; then
        printf "  Last game:  %s\n" "$last_game"
    fi
    if [ -n "$last_label" ]; then
        printf "  Last label: %s\n" "$last_label"
    fi

    # Elasticsearch delivery health.  The agent no longer aborts on a failed
    # startup preflight, so an unreachable or misconfigured endpoint no longer
    # shows up as a crash-looping unit above.  This line is what replaces that
    # visibility for an operator who only runs `rigsignal status`.
    #
    # -b bounds it to the CURRENT BOOT and the journal timestamp is kept.  Both
    # matter: in the healthy steady state the agent says nothing at all, so two
    # hundred lines can reach back weeks, and an outage that ended days ago would
    # otherwise print here as if it were current state.  The two greps above are
    # labelled "Last game" and "Last label"; this one would read as now.
    #
    # The marker is anchored immediately after the tracing target so an ordinary
    # game name cannot drift into this line.  That is a narrowing, NOT a
    # guarantee: these messages are unescaped, so text a user controls can still
    # contain whatever it likes.  Closing that properly means escaping dynamic
    # text in the agent's own log output, which changes existing log lines and is
    # tracked separately.
    last_delivery=$(journalctl --user -u "$AGENT_UNIT" -b -n 200 -o short-iso --no-pager 2>/dev/null \
        | grep -E 'WARN rigsignal_agent: ES_DELIVERY ' | tail -1 \
        | sed -n 's/^\([^ ]*\) .*WARN rigsignal_agent: ES_DELIVERY \(.*\)$/\1  \2/p')
    if [ -n "$last_delivery" ]; then
        printf "  Delivery:   %s\n" "$last_delivery"
    fi

    printf "\n  Logs:   journalctl --user -u %s -f\n" "$AGENT_UNIT"
    printf "  Config: %s\n\n" "$CONFIG_FILE"
}

# ── Subcommand: run ────────────────────────────────────────────────────────────
# Steam launch option form: rigsignal run %command%
# Steam expands %command% to the full game executable + arguments.

cmd_run() {
    if [ $# -eq 0 ]; then
        _die "Usage: rigsignal run <command> [args...]"
    fi

    # Strip leading KEY=VALUE args and export them so users can write:
    #   rigsignal run RIGSIGNAL_LOG=debug %command%
    # rather than needing to place env vars before 'rigsignal' in the launch option.
    while [ $# -gt 0 ]; do
        case "$1" in
            [A-Za-z_]*=*)
                _varname="${1%%=*}"
                case "$_varname" in
                    *[!A-Za-z0-9_]*) break ;;
                    *)
                        _llog "cmd_run: exporting env: $_varname"
                        # shellcheck disable=SC2163  # $1 is NAME=VALUE by prior validation
                        export "$1"
                        shift
                        continue
                        ;;
                esac
                ;;
        esac
        break
    done

    if [ $# -eq 0 ]; then
        _die "No command remaining after env var extraction."
    fi

    _llog "cmd_run: command=$*"

    # Resolve the agent binary before starting anything.
    AGENT_BIN="$(resolve_agent_bin)"
    _llog "cmd_run: AGENT_BIN='$AGENT_BIN'"
    if [ -z "$AGENT_BIN" ]; then
        _warn "rigsignal-agent not found — launching game without telemetry."
        _info "Re-run the installer or add ~/.local/bin to PATH."
        _llog "cmd_run: agent not found — exec-ing game directly without telemetry"
        exec "$@"
    fi

    # Enable MangoHud frame timing collection via MANGOHUD=1.
    # We export MANGOHUD=1 rather than wrapping with the `mangohud` binary so
    # that the Steam Linux Runtime (pressure-vessel) uses its own bundled MangoHud
    # layer — the host binary cannot inject across the container boundary.
    # autostart_log=1 is written to ~/.config/MangoHud/MangoHud.conf by the
    # installer so it applies unconditionally; no_display=1 hides the overlay.
    # Set RIGSIGNAL_MANGOHUD=0 to opt out entirely.
    # Set RIGSIGNAL_MANGOHUD=display to show the overlay.
    if [ "${RIGSIGNAL_MANGOHUD:-auto}" != "0" ] && [ -z "${MANGOHUD:-}" ]; then
        MANGOHUD=1
        export MANGOHUD
        _llog "cmd_run: MANGOHUD=1 set (SLR bundled MangoHud, autostart_log via conf)"
        if [ "${RIGSIGNAL_MANGOHUD:-auto}" != "display" ]; then
            MANGOHUD_CONFIG="no_display=1"
            export MANGOHUD_CONFIG
            _llog "cmd_run: MANGOHUD_CONFIG=no_display=1 (overlay hidden)"
        else
            _llog "cmd_run: RIGSIGNAL_MANGOHUD=display — overlay visible"
        fi
    fi

    # Start the agent — systemd if reachable, direct binary otherwise.
    # Reset any prior FAILED state so the unit can always be started fresh.
    systemctl --user reset-failed "$AGENT_UNIT" 2>/dev/null || true
    _llog "cmd_run: reset-failed $AGENT_UNIT"

    # Capture the launcher PID before exec replaces this shell with the game.
    # In POSIX sh, $$ in a subshell still refers to the parent shell's PID,
    # so the watcher correctly monitors the game process after exec.
    _gp_pid=$$
    _llog "cmd_run: launcher PID=$_gp_pid (becomes game PID after exec)"

    if systemctl --user start "$AGENT_UNIT" >/dev/null 2>&1; then
        _llog "cmd_run: systemctl --user start $AGENT_UNIT succeeded (service mode)"
        # Double-fork the watcher: the outer subshell exits immediately, making
        # the inner watcher a child of init (PID 1) rather than of the exec'd
        # process. Without this, exec replaces this shell with steam-launch-wrapper
        # which becomes reaper — reaper then waits for the watcher (its child) and
        # the watcher waits for reaper to exit: deadlock, permanent black screen.
        # /proc/<pid> vanishes atomically on process exit — no PID-reuse race.
        (
          (
            while [ -d "/proc/$_gp_pid" ]; do sleep 1; done
            _llog "cmd_run: game PID $_gp_pid exited — stopping $AGENT_UNIT"
            systemctl --user stop "$AGENT_UNIT" --no-block 2>/dev/null || true
          ) &
        ) &
    else
        _llog "cmd_run: systemctl start failed (DBUS absent? unit missing?) — running agent directly"
        "$AGENT_BIN" &
        _agent_pid=$!
        _llog "cmd_run: direct agent started PID=$_agent_pid"
        (
          (
            while [ -d "/proc/$_gp_pid" ]; do sleep 1; done
            _llog "cmd_run: game PID $_gp_pid exited — kill -TERM agent $_agent_pid"
            kill -TERM "$_agent_pid" 2>/dev/null || true
          ) &
        ) &
    fi

    # exec replaces the launcher shell with the game process so Steam/Gamescope
    # tracks the correct PID for cgroup assignment, GPU priority, and display
    # management. Running the game as a subprocess (not exec) puts it in the
    # wrong place in the process tree and breaks Gaming Mode (Gamescope).
    _llog "cmd_run: exec-ing game (this shell becomes the game process): $*"
    exec "$@"
}

# ── Usage ──────────────────────────────────────────────────────────────────────

usage() {
    cat << 'EOF'
RigSignal launcher

Usage:
  rigsignal setup [--ca-file <path> [--ca-sha256 <hex>]] [--allow-unknown-version]
                              Configure Elasticsearch endpoint, API key, and CA
  rigsignal start              Start agent (+ eBPF if sudo available)
  rigsignal stop               Stop both services gracefully
  rigsignal status             Show service status and last session info
  rigsignal run <cmd> [args]   Start services, run command, stop on exit
  rigsignal assets install [options]
                              Install a verified release asset bundle as user

Steam integration — set in game Properties → Launch Options:
  rigsignal run %command%

Examples:
  rigsignal setup --ca-file ./http_ca.crt
  rigsignal start
  rigsignal status
  rigsignal run ./mygame --fullscreen
  rigsignal assets install --admin-credentials-file ./elastic-admin.toml
EOF
}

# ── Dispatch ───────────────────────────────────────────────────────────────────

subcmd="${1:-}"
_llog "launch: $0 $*"
shift 2>/dev/null || true

case "$subcmd" in
    setup)  cmd_setup "$@" ;;
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    status)
        # Reserve the durable handshake recheck surface without allowing malformed
        # status arguments to silently fall through into ordinary status output.
        case "$#" in
            0) cmd_status ;;
            2)
                if [ "$1" = "handshake" ] && [ "$2" = "recheck" ]; then
                    _err "handshake recheck is not yet available"
                else
                    _err "Invalid status arguments"
                fi
                exit 1
                ;;
            3)
                if [ "$1" = "handshake" ] && [ "$2" = "recheck" ] \
                    && [ "${#3}" -eq 64 ] && [ -n "$3" ] \
                    && case "$3" in *[!0123456789abcdef]*) false ;; *) true ;; esac
                then
                    _err "handshake recheck is not yet available"
                else
                    _err "Invalid status arguments"
                fi
                exit 1
                ;;
            *) _err "Invalid status arguments"; exit 1 ;;
        esac
        ;;
    run)    cmd_run "$@" ;;
    assets)
        [ "${1:-}" = install ] || { _err "Usage: rigsignal assets install [options]"; exit 2; }
        shift
        cmd_assets_install "$@"
        ;;
    "")     usage; exit 0 ;;
    *)      _err "Unknown subcommand: $subcmd"; echo; usage; exit 1 ;;
esac
