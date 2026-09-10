#!/usr/bin/env bash
# Clean-stack provisioning matrix.  The harness owns ES -> kibana_system ->
# Kibana bootstrap; the installer is invoked only after that sequence is ready.
set -euo pipefail
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=scripts/clean-stack/lib.sh
. "$SCRIPT_DIR/lib.sh"
CPU_INDEX=metrics-rigsignal.cpu-default
EVENTS_INDEX=logs-rigsignal.events-default
DIAGNOSIS_STREAM=logs-rigsignal.diagnosis-default
usage() { printf '%s\n' 'Usage: matrix.sh [--keep] [--dry-run] [--bundle PATH] fresh VERSION|idempotent-rerun VERSION|pre-w1-refusal VERSION|uuid-mismatch VERSION|bytes-live VERSION|upgrade VERSION|stackupgrade FROM TO' >&2; }
version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
assert_equal() { [[ "$3" == "$2" ]] || { printf 'ASSERT FAIL %s: expected=%q actual=%q\n' "$1" "$2" "$3" >&2; return 1; }; printf 'ASSERT PASS %s\n' "$1"; }
cleanup() { local status="$?"; cs_cleanup || true; [[ -z "$RUN_DIR" || "$keep" == 1 ]] || rm -rf "$RUN_DIR"; return "$status"; }
request() {
  local name="$1" file="$2" status; shift 2
  if ! status="$(cs_http_to_file "$file" --user "elastic:$ELASTIC_PASSWORD" "$@")"; then assert_equal "$name-reachable" success unreachable; return 1; fi
  if cs_status_is_success "$status"; then assert_equal "$name-http" success success; else assert_equal "$name-http" success "$status"; fi
}
kb_request() {
  local name="$1" file="$2" status; shift 2
  if ! status="$(cs_http_to_file "$file" --user "elastic:$ELASTIC_PASSWORD" --header 'kbn-xsrf: clean-stack-matrix' "$@")"; then assert_equal "$name-reachable" success unreachable; return 1; fi
  if cs_status_is_success "$status"; then assert_equal "$name-http" success success; else assert_equal "$name-http" success "$status"; fi
}
start_stack() {
  local v="$1" volumes="$2" ep='' kp=''
  [[ -v CLEAN_STACK_ES_PORT ]] && ep="$CLEAN_STACK_ES_PORT"; [[ -v CLEAN_STACK_KB_PORT ]] && kp="$CLEAN_STACK_KB_PORT"
  if [[ "$volumes" == 1 ]]; then cs_start_elasticsearch_with_volume "docker.elastic.co/elasticsearch/elasticsearch:$v" "$(cs_port_mapping "$ep" 9200)"; else cs_start_elasticsearch "docker.elastic.co/elasticsearch/elasticsearch:$v" "$(cs_port_mapping "$ep" 9200)"; fi
  CS_ES_URL="https://localhost:$(cs_published_port "$CS_ES_CONTAINER" 9200/tcp)"
  ES_URL="$CS_ES_URL"
  export CS_ES_URL
  cs_wait_for_elasticsearch "$ES_URL" elastic "$ELASTIC_PASSWORD" "$RUN_DIR/es-health.json" || { cs_timeout_with_logs Elasticsearch "$CS_ES_CONTAINER"; return 1; }
  local status
  status="$(cs_http_to_file "$RUN_DIR/kb-password.json" --user "elastic:$ELASTIC_PASSWORD" --header 'Content-Type: application/json' --request POST --data "{\"password\":\"$ELASTICSEARCH_PASSWORD\"}" "$ES_URL/_security/user/kibana_system/_password")"
  cs_status_is_success "$status" || return 1
  if [[ "$volumes" == 1 ]]; then cs_start_kibana_with_volume "docker.elastic.co/kibana/kibana:$v" "$(cs_port_mapping "$kp" 5601)"; else cs_start_kibana "docker.elastic.co/kibana/kibana:$v" "$(cs_port_mapping "$kp" 5601)"; fi
  CS_KIBANA_URL="https://localhost:$(cs_published_port "$CS_KB_CONTAINER" 5601/tcp)"
  KB_URL="$CS_KIBANA_URL"
  export CS_KIBANA_URL
  cs_wait_for_kibana "$KB_URL" elastic "$ELASTIC_PASSWORD" "$RUN_DIR/kb-health.json" || { cs_timeout_with_logs Kibana "$CS_ES_CONTAINER" "$CS_KB_CONTAINER"; return 1; }
}
build_bundle() {
  if [[ -n "$bundle_path" ]]; then BUNDLE="$bundle_path"; else BUNDLE="$RUN_DIR/assets.tar.gz"; python3 "$REPO_ROOT/tools/build_asset_bundle.py" --source-commit "$(git -C "$REPO_ROOT" rev-parse HEAD)" --output "$BUNDLE"; fi
  BUNDLE_VERSION="$(python3 - "$BUNDLE" <<'PY'
import json, sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as f: print(json.load(f.extractfile("manifest.json"))["bundle_version"])
PY
)"
}
install_current() {
  local root_args=()
  local installer="${CLEAN_STACK_INSTALL_COMMAND:-}"
  [[ -z "${RIGSIGNAL_ENROLLMENT_ROOT:-}" ]] || root_args=(--enrollment-root "$RIGSIGNAL_ENROLLMENT_ROOT")
  if [[ -z "$installer" && "${CLEAN_STACK_ALLOW_DEFAULT_INSTALLER:-0}" == 1 ]]; then
    installer="$SCRIPT_DIR/install-wrapper.sh"
  fi
  # A bare matrix invocation must still fail loudly: the default wrapper is an
  # explicit harness opt-in, never a substitute for a caller's installer.
  [[ -n "$installer" ]] || {
    printf 'ASSERT FAIL installer-precondition: CLEAN_STACK_INSTALL_COMMAND must provide the HTTPS/CA/admin inputs\n' >&2
    return 1
  }
  "$installer" --bundle "$BUNDLE" "${root_args[@]}"
}
install_previous() { RIGSIGNAL_ES_URL="$ES_URL" RIGSIGNAL_ES_AUTH="elastic:$ELASTIC_PASSWORD" "$SCRIPT_DIR/install-previous-state.sh"; }
owned_snapshot() {
  local output="$1" root="$2" item
  : >"$output"
  for item in \
    "/_component_template/logs-rigsignal.diagnosis-mappings" \
    "/_index_template/logs-rigsignal.diagnosis" \
    "/_security/role/rigsignal_shipper" \
    "/_data_stream/$DIAGNOSIS_STREAM" \
    "/_component_template/rigsignal-bundle-meta" \
    "/_security/api_key?owner=false"; do
    curl --silent --show-error --max-redirs 0 --user "elastic:$ELASTIC_PASSWORD" \
      --write-out '\nSTATUS:%{http_code}\n' "$ES_URL$item" >>"$output"
  done
  for item in state.json credentials.toml handshake.toml shipping-policy-v1.toml candidate/credentials.toml candidate/handshake.toml candidate/shipping-policy-v1.toml candidate/state.json; do
    if [[ -e "$root/$item" ]]; then stat -c "$item:%a:%u:%g:%s" "$root/$item" >>"$output"; sha256sum "$root/$item" >>"$output"; else printf '%s:ABSENT\n' "$item" >>"$output"; fi
  done
  sha256sum "$output" | awk '{print $1}'
}
assert_refusal() {
  local name root output before after
  name="$1"
  root="$2"
  output="$RUN_DIR/$name-installer.out"
  before="$(owned_snapshot "$RUN_DIR/$name-before.snapshot" "$root")"
  if install_current >"$output" 2>&1; then
    printf 'ASSERT FAIL %s-nonzero: installer unexpectedly succeeded\n' "$name" >&2
    return 1
  fi
  grep -Fx 'install refused: existing diagnosis stream is not W1; migration is required' "$output" >/dev/null || {
    printf 'ASSERT FAIL %s-refusal-message\n' "$name" >&2; return 1;
  }
  after="$(owned_snapshot "$RUN_DIR/$name-after.snapshot" "$root")"
  assert_equal "$name-owned-delta" "$before" "$after"
  for item in credentials.toml handshake.toml shipping-policy-v1.toml state.json; do
    [[ ! -e "$root/$item" ]] || { printf 'ASSERT FAIL %s-no-local-enrollment-%s\n' "$name" "$item" >&2; return 1; }
  done
  printf 'ASSERT PASS %s-refusal\n' "$name"
}
pre_w1_refusal() {
  local root="$RUN_DIR/pre-w1-enrollment"
  cs_create_network; start_stack "$one" 0; build_bundle
  request pre-w1-template "$RUN_DIR/pre-w1-template.json" --header 'Content-Type: application/json' --request PUT \
    --data-binary "@$SCRIPT_DIR/fixtures/pre-w1-logs-rigsignal.diagnosis.json" "$ES_URL/_index_template/logs-rigsignal.diagnosis"
  request pre-w1-stream "$RUN_DIR/pre-w1-stream.json" --request PUT "$ES_URL/_data_stream/$DIAGNOSIS_STREAM"
  RIGSIGNAL_ENROLLMENT_ROOT="$root" assert_refusal pre-w1 "$root"
}
uuid_mismatch() {
  local root="$RUN_DIR/uuid-enrollment" before after
  cs_create_network; start_stack "$one" 0; build_bundle
  # The first invocation must genuinely publish against A; do not manufacture
  # state.json for this cross-cluster proof.
  RIGSIGNAL_ENROLLMENT_ROOT="$root" install_current
  cs_docker_quiet stop "$CS_KB_CONTAINER"; cs_docker_quiet rm "$CS_KB_CONTAINER"; CS_KB_CREATED=0
  cs_docker_quiet stop "$CS_ES_CONTAINER"; cs_docker_quiet rm "$CS_ES_CONTAINER"; CS_ES_CREATED=0
  start_stack "$one" 0
  before="$(owned_snapshot "$RUN_DIR/uuid-before.snapshot" "$root")"
  if RIGSIGNAL_ENROLLMENT_ROOT="$root" install_current >"$RUN_DIR/uuid-installer.out" 2>&1; then
    printf 'ASSERT FAIL uuid-mismatch-nonzero: installer unexpectedly succeeded\n' >&2; return 1
  fi
  grep -Fx 'install refused: existing diagnosis stream is not W1; migration is required' "$RUN_DIR/uuid-installer.out" >/dev/null || {
    printf 'ASSERT FAIL uuid-mismatch-refusal-message\n' >&2; return 1;
  }
  after="$(owned_snapshot "$RUN_DIR/uuid-after.snapshot" "$root")"
  assert_equal uuid-mismatch-owned-delta "$before" "$after"
  printf 'ASSERT PASS uuid-mismatch-refusal\n'
}
bytes_live() {
  local agent="$REPO_ROOT/target/debug/rigsignal-agent" exact="$RUN_DIR/exact-cap.json" over="$RUN_DIR/one-over.out"
  [[ -x "$agent" ]] || { printf 'ASSERT FAIL bytes-live-agent: production fixture helper is absent\n' >&2; return 1; }
  cs_create_network; start_stack "$one" 0; build_bundle; install_current
  "$agent" fixture-event-bytes --input "$REPO_ROOT/fixtures/diagnosis_event/v1/positive/24-event-bytes-exact-cap.input.json" \
    --context "$REPO_ROOT/fixtures/diagnosis_event/v1/contexts/diagnosis-finding.json" >"$exact"
  assert_equal bytes-live-exact-cap-size 1048576 "$(wc -c <"$exact")"
  if "$agent" fixture-event-bytes --input "$REPO_ROOT/fixtures/diagnosis_event/v1/negative/24-event-bytes-one-over.input.json" \
      --context "$REPO_ROOT/fixtures/diagnosis_event/v1/contexts/diagnosis-finding.json" >"$RUN_DIR/one-over.json" 2>"$over"; then
    printf 'ASSERT FAIL bytes-live-one-over-local-rejection\n' >&2; return 1
  fi
  grep -Fx 'EventBytesLimitExceeded { limit: 1048576, actual_saturated: 1048577 }' "$over" >/dev/null || {
    printf 'ASSERT FAIL bytes-live-one-over-error\n' >&2; return 1;
  }
  request bytes-live-create "$RUN_DIR/bytes-live-create.json" --header 'Content-Type: application/json' --request POST \
    --data-binary "@$exact" "$ES_URL/$DIAGNOSIS_STREAM/_create/bytes-live-exact?refresh=wait_for"
  assert_equal bytes-live-no-ignored false "$(jq 'has("_ignored")' "$RUN_DIR/bytes-live-create.json")"
  assert_equal bytes-live-no-failure-store null "$(jq -r '.failure_store // "null"' "$RUN_DIR/bytes-live-create.json")"
  request bytes-live-round-trip "$RUN_DIR/bytes-live-round-trip.json" --request GET "$ES_URL/$DIAGNOSIS_STREAM/_search?q=event.id:01890f3e-7b64-7cc7-8a3d-5e6f708192a3"
  jq -cS '.hits.hits[0]._source' "$RUN_DIR/bytes-live-round-trip.json" >"$RUN_DIR/bytes-live-round-trip-source.json"
  # jq writes a presentation newline; the validator's production helper does
  # not, so remove only that transport newline before byte-for-byte comparison.
  head -c -1 "$RUN_DIR/bytes-live-round-trip-source.json" >"$RUN_DIR/bytes-live-round-trip-source-no-lf.json"
  mv "$RUN_DIR/bytes-live-round-trip-source-no-lf.json" "$RUN_DIR/bytes-live-round-trip-source.json"
  cmp -s "$exact" "$RUN_DIR/bytes-live-round-trip-source.json" || { printf 'ASSERT FAIL bytes-live-exact-round-trip\n' >&2; return 1; }
  request bytes-live-failure-store "$RUN_DIR/bytes-live-failures.json" --header 'Content-Type: application/json' --request POST \
    --data '{"query":{"term":{"event.id":"01890f3e-7b64-7cc7-8a3d-5e6f708192a3"}},"size":1}' "$ES_URL/$DIAGNOSIS_STREAM::failures/_search"
  assert_equal bytes-live-no-failure-document 0 "$(jq '.hits.hits|length' "$RUN_DIR/bytes-live-failures.json")"
}
ingest() {
  local now; now="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  jq --arg timestamp "$now" '. + {"@timestamp":$timestamp}' "$REPO_ROOT/fixtures/clean-stack/cpu-doc.json" >"$RUN_DIR/cpu.json"
  jq --arg timestamp "$now" '. + {"@timestamp":$timestamp}' "$REPO_ROOT/fixtures/clean-stack/events-doc.json" >"$RUN_DIR/events.json"
  # TSDS derives _id from dimensions+timestamp; a client-supplied _id is rejected (400).
  request cpu-ingest "$RUN_DIR/cpu-ingest.json" --header 'Content-Type: application/json' --request POST --data-binary "@$RUN_DIR/cpu.json" "$ES_URL/$CPU_INDEX/_doc?refresh=wait_for"
  request events-ingest "$RUN_DIR/events-ingest.json" --header 'Content-Type: application/json' --request POST --data-binary "@$RUN_DIR/events.json" "$ES_URL/$EVENTS_INDEX/_doc/rigsignal-matrix-events-sentinel?op_type=create&refresh=wait_for"
}
hash_source() { jq -cS '._source' "$1" | sha256sum | awk '{print $1}'; }
# TSDS sentinel has an auto-generated _id: locate it by its dimension marker instead.
cpu_sentinel_fetch() {
  # Called via command substitution: ASSERT PASS lines must not pollute the hash,
  # so all assert output is routed to stderr; only the hash reaches stdout.
  local name="$1" out="$2" hits
  request "$name" "$out" --header 'Content-Type: application/json' --request POST \
    --data '{"query":{"term":{"host.name":"fixture-host.example"}},"size":2}' \
    "$ES_URL/$CPU_INDEX/_search" 1>&2
  hits="$(jq -r '.hits.total.value' "$out")"
  assert_equal "$name-unique-sentinel" "1" "$hits" 1>&2
  jq -cS '.hits.hits[0]._source' "$out" | sha256sum | awk '{print $1}'
}
# GET _doc/<id> does not resolve through a data-stream name — search by _id instead.
events_sentinel_fetch() {
  local name="$1" out="$2" hits
  request "$name" "$out" --header 'Content-Type: application/json' --request POST \
    --data '{"query":{"ids":{"values":["rigsignal-matrix-events-sentinel"]}},"size":2}' \
    "$ES_URL/$EVENTS_INDEX/_search" 1>&2
  hits="$(jq -r '.hits.total.value' "$out")"
  assert_equal "$name-unique-sentinel" "1" "$hits" 1>&2
  jq -cS '.hits.hits[0]._source' "$out" | sha256sum | awk '{print $1}'
}
record() {
  CPU_HASH="$(cpu_sentinel_fetch cpu-before "$RUN_DIR/cpu-before.json")"
  EVENTS_HASH="$(events_sentinel_fetch events-before "$RUN_DIR/events-before.json")"
  request cpu-count-before "$RUN_DIR/cpu-count-before.json" --request GET "$ES_URL/$CPU_INDEX/_count"; CPU_COUNT="$(jq -r .count "$RUN_DIR/cpu-count-before.json")"
  request events-count-before "$RUN_DIR/events-count-before.json" --request GET "$ES_URL/$EVENTS_INDEX/_count"; EVENTS_COUNT="$(jq -r .count "$RUN_DIR/events-count-before.json")"
}
survival() {
  local actual
  actual="$(cpu_sentinel_fetch cpu-after "$RUN_DIR/cpu-after.json")"; assert_equal cpu-sentinel-source-hash "$CPU_HASH" "$actual"
  actual="$(events_sentinel_fetch events-after "$RUN_DIR/events-after.json")"; assert_equal events-sentinel-source-hash "$EVENTS_HASH" "$actual"
  request cpu-count-after "$RUN_DIR/cpu-count-after.json" --request GET "$ES_URL/$CPU_INDEX/_count"; actual="$(jq -r .count "$RUN_DIR/cpu-count-after.json")"; assert_equal cpu-sentinel-count "$CPU_COUNT" "$actual"
  request events-count-after "$RUN_DIR/events-count-after.json" --request GET "$ES_URL/$EVENTS_INDEX/_count"; actual="$(jq -r .count "$RUN_DIR/events-count-after.json")"; assert_equal events-sentinel-count "$EVENTS_COUNT" "$actual"
}
esql() {
  local name="$1" query="$2" expected="$3" actual
  jq -cn --arg query "$query" '{query:$query}' >"$RUN_DIR/$name-request.json"
  request "$name" "$RUN_DIR/$name-result.json" --header 'Content-Type: application/json' --request POST --data-binary "@$RUN_DIR/$name-request.json" "$ES_URL/_query"
  actual="$(jq -r 'if ((.values|length)==1 and (.values[0]|length)==1) then .values[0][0]|tostring else "__invalid__" end' "$RUN_DIR/$name-result.json")"; assert_equal "$name" "$expected" "$actual"
}
asserts() {
  local title actual component pipeline
  esql cpu-marker "FROM $CPU_INDEX | WHERE host.name == \"fixture-host.example\" | KEEP rigsignal.cpu.total_utilisation_pct" 42.25
  esql events-value "FROM $EVENTS_INDEX | WHERE host.name == \"fixture-host.example\" | KEEP rigsignal.stream.client.event" connected
  kb_request dashboard-find-rigsignal "$RUN_DIR/dashboards-rigsignal.json" --request GET "$KB_URL/s/rigsignal/api/saved_objects/_find?type=dashboard&per_page=1000"; actual="$(jq -r .total "$RUN_DIR/dashboards-rigsignal.json")"; assert_equal dashboard-rigsignal-total 6 "$actual"
  kb_request dashboard-find-default "$RUN_DIR/dashboards.json" --request GET "$KB_URL/api/saved_objects/_find?type=dashboard&per_page=1000"; actual="$(jq -r .total "$RUN_DIR/dashboards.json")"; assert_equal dashboard-default-total 1 "$actual"; jq -s '{saved_objects: (map(.saved_objects) | add)}' "$RUN_DIR/dashboards-rigsignal.json" "$RUN_DIR/dashboards.json" >"$RUN_DIR/dashboards-all.json"; mv "$RUN_DIR/dashboards-all.json" "$RUN_DIR/dashboards.json"
  for title in 'RigSignal: Engine & Diagnostics' 'RigSignal Flamegraph Profiles' 'RigSignal: Game Performance' 'RigSignal: Overview' 'RigSignal: Software Stack' 'RigSignal Streaming Lab' 'RigSignal: System Health'; do actual="$(jq -r --arg title "$title" '[.saved_objects[]|select(.attributes.title==$title)]|length' "$RUN_DIR/dashboards.json")"; assert_equal "dashboard-title-$title" 1 "$actual"; done
  request cpu-template-fetch "$RUN_DIR/template.json" --request GET "$ES_URL/_index_template/metrics-rigsignal.cpu"; actual="$(jq -r '(.index_templates|length==1)|tostring' "$RUN_DIR/template.json")"; assert_equal cpu-template-exists true "$actual"
  component="$(jq -r '[.index_templates[0].index_template.composed_of[]|select(endswith(".cpu@package"))][0]' "$RUN_DIR/template.json")"; assert_equal cpu-template-default-component metrics-rigsignal.cpu@package "$component"
  request cpu-component-fetch "$RUN_DIR/component.json" --request GET "$ES_URL/_component_template/$component"; pipeline="$(jq -r '.component_templates[0].component_template.template.settings.index.default_pipeline' "$RUN_DIR/component.json")"; assert_equal cpu-default-pipeline-name metrics-rigsignal.cpu-0.5.0 "$pipeline"
  request cpu-default-pipeline-fetch "$RUN_DIR/pipeline.json" --request GET "$ES_URL/_ingest/pipeline/$pipeline"; actual="$(jq -r 'has("metrics-rigsignal.cpu-0.5.0")|tostring' "$RUN_DIR/pipeline.json")"; assert_equal cpu-default-pipeline-exists true "$actual"
  request bundle-marker-fetch "$RUN_DIR/marker.json" --request GET "$ES_URL/_component_template/rigsignal-bundle-meta"; actual="$(jq -r '.component_templates[0].component_template._meta.bundle_version' "$RUN_DIR/marker.json")"; assert_equal bundle-marker-current-version "$BUNDLE_VERSION" "$actual"
  jq -cn --arg query "FROM $CPU_INDEX | STATS cpu_utilisation = AVG(rigsignal.cpu.total_utilisation_pct) BY Host = TO_LOWER(host.name) | SORT Host" '{query:$query}' >"$RUN_DIR/render.json"; request render-proof-cpu-panel "$RUN_DIR/render-result.json" --header 'Content-Type: application/json' --request POST --data-binary "@$RUN_DIR/render.json" "$ES_URL/_query"; actual="$(jq -r 'if (.values|length)>0 then "1" else "0" end' "$RUN_DIR/render-result.json")"; assert_equal render-proof-cpu-panel 1 "$actual"
}
dry_plan() {
  printf 'Dry run; generated resource suffix: %s\n' "$CS_SUFFIX"; cs_create_network
  if [[ "$mode" == stackupgrade ]]; then cs_create_named_volumes; cs_start_elasticsearch_with_volume "docker.elastic.co/elasticsearch/elasticsearch:$one" "$(cs_port_mapping '' 9200)"; cs_start_kibana_with_volume "docker.elastic.co/kibana/kibana:$one" "$(cs_port_mapping '' 5601)"; else cs_start_elasticsearch "docker.elastic.co/elasticsearch/elasticsearch:$one" "$(cs_port_mapping '' 9200)"; cs_start_kibana "docker.elastic.co/kibana/kibana:$one" "$(cs_port_mapping '' 5601)"; fi
  [[ "$mode" == upgrade ]] && printf '%s --dry-run\n' "$SCRIPT_DIR/install-previous-state.sh" || printf '%s --bundle <run-bundle> --endpoint <https-es> --ca-file <run-ca> --kibana-endpoint <https-kibana> --kibana-ca-file <run-ca> --profile user\n' "$SCRIPT_DIR/install-wrapper.sh"
  printf 'jq injects @timestamp; curl ingests fixtures and runs all named assertions\n'
  if [[ "$mode" == upgrade ]]; then printf 'python3 tools/build_asset_bundle.py; python3 tools/install_assets.py --bundle <run-bundle>; curl verifies sentinel hashes/counts and reruns all assertions\n'; fi
  if [[ "$mode" == stackupgrade ]]; then cs_docker_quiet stop "$CS_KB_CONTAINER"; cs_docker_quiet rm "$CS_KB_CONTAINER"; cs_docker_quiet stop "$CS_ES_CONTAINER"; cs_docker_quiet rm "$CS_ES_CONTAINER"; cs_start_elasticsearch_with_volume "docker.elastic.co/elasticsearch/elasticsearch:$two" "$(cs_port_mapping '' 9200)"; cs_start_kibana_with_volume "docker.elastic.co/kibana/kibana:$two" "$(cs_port_mapping '' 5601)"; printf 'curl reruns all assertions\n'; fi
  case "$mode" in
    idempotent-rerun) printf 'composite: fresh retained root, then same bundle installer rerun; record role/key/marker evidence\n' ;;
    pre-w1-refusal) printf 'self-contained: create non-W1 diagnosis stream, snapshot owned resources, assert installer refusal and zero delta\n' ;;
    uuid-mismatch) printf 'composite: provision A then invoke retained enrollment root against independent B; assert zero owned delta\n' ;;
    bytes-live) printf 'self-contained: canonical helper exact-cap 201/round-trip and one-over local rejection evidence\n' ;;
    stackupgrade) printf 'composite: rollover exact diagnosis stream after 9.4.4 restart, then scoped create proof before cleanup\n' ;;
  esac
}
keep=0; dry_run=0; bundle_path=''
while [[ $# -gt 0 && "$1" == -* ]]; do case "$1" in --keep) keep=1 ;; --dry-run) dry_run=1 ;; --bundle) shift; [[ $# -gt 0 ]] || { usage; exit 2; }; bundle_path="$1" ;; *) usage; exit 2 ;; esac; shift; done
[[ $# -gt 0 ]] || { usage; exit 2; }; mode="$1"; shift
case "$mode" in
  fresh|idempotent-rerun|pre-w1-refusal|uuid-mismatch|bytes-live|upgrade) if [[ $# != 1 ]] || ! version "$1"; then usage; exit 2; fi; one="$1"; two='' ;;
  stackupgrade) if [[ $# != 2 ]] || ! version "$1" || ! version "$2"; then usage; exit 2; fi; one="$1"; two="$2" ;;
  *) usage; exit 2 ;;
esac
export CS_KEEP="$keep" CS_DRY_RUN="$dry_run"; cs_init_names "$(cs_new_suffix)"; RUN_DIR=''; CS_RUN_DIR=''; ELASTIC_PASSWORD="rgs-$RANDOM$RANDOM-A1"; ELASTICSEARCH_PASSWORD="rgs-$RANDOM$RANDOM-B2"; export ELASTIC_PASSWORD ELASTICSEARCH_PASSWORD; trap cleanup EXIT
if [[ "$dry_run" == 1 ]]; then cs_set_tls_paths '/tmp/rigsignal-clean-stack-matrix-dry-run'; dry_plan; exit 0; fi
cs_require_tools bash curl docker jq openssl python3 sha256sum; RUN_DIR="$(mktemp -d /tmp/rigsignal-clean-stack-matrix.XXXXXX)"; chmod 700 "$RUN_DIR"; CS_RUN_DIR="$RUN_DIR"; export CS_RUN_DIR; cs_prepare_tls "$RUN_DIR"
case "$mode" in
  fresh) cs_create_network; start_stack "$one" 0; build_bundle; install_current; ingest; asserts ;;
  idempotent-rerun) cs_create_network; start_stack "$one" 0; build_bundle; install_current; install_current; ingest; asserts ;;
  pre-w1-refusal) pre_w1_refusal ;;
  uuid-mismatch) uuid_mismatch ;;
  bytes-live) bytes_live ;;
  upgrade) cs_create_network; start_stack "$one" 0; install_previous; ingest; record; build_bundle; install_current; survival; asserts ;;
  stackupgrade) cs_create_network; cs_create_named_volumes; start_stack "$one" 1; build_bundle; install_current; ingest; cs_docker_quiet stop "$CS_KB_CONTAINER"; cs_docker_quiet rm "$CS_KB_CONTAINER"; CS_KB_CREATED=0; cs_docker_quiet stop "$CS_ES_CONTAINER"; cs_docker_quiet rm "$CS_ES_CONTAINER"; CS_ES_CREATED=0; start_stack "$two" 1; asserts ;;
esac
