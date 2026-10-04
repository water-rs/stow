#!/usr/bin/env bash
# Drive the docs/MOCK.md recipe end-to-end on loopback:
#
#   1. build the four host binaries and generate a P-256 PKCS#8 key pair
#   2. start stow-mock-registry (28123), the edge under `wrangler dev`
#      (workerd, 8788; bundle built by `skyzen build`), and
#      `stow-build serve` (28124), running the scheduler schema migration
#      the deploy pipeline runs before the new build takes traffic
#   3. submit one small registry crate (itoa, latest 1.0.x, host target)
#      through `stow-admin` and wait for the scheduler to report
#      completion via the local CI's `workflow_run` webhook POST
#   4. export the signed artifact index from the registry's records
#      artifacts, publish it back, report each slice to the scheduler
#      gate and sync the folded records into the edge catalog
#      (`stow-admin index export` + `index publish` + `index report` +
#      `index sync`, as index-publish.yml runs them), then run the same
#      wave by hand through
#      `stow-admin preheat manual` on a crate with a real dependency
#      (walkdir → same-file) so layering and per-layer publish are
#      exercised
#   5. `stow index refresh` + `stow check` a throwaway consumer crate in
#      mock-key verify mode and assert the dependency was served from the
#      cache via local index resolution and a direct digest pull
#
# All state (keys, registry root, edge persist dir, stow cache, logs, the
# local-CI dispatch tree) lives under a single work dir so the run never
# touches the developer's real stow or cargo state. Every child process is
# killed on exit by PID — never by pattern.
#
# Tunables (env):
#   STOW_E2E_WORK_DIR        work dir instead of a fresh mktemp (CI log upload)
#   STOW_E2E_TOOLCHAIN       rustup toolchain for the run (default: stable)
#   STOW_E2E_READY_DEADLINE  seconds to wait for each service (default: 600)
#   STOW_E2E_TASK_DEADLINE   seconds to wait for the scheduler (default: 600)
set -euo pipefail
# Job control gives every background service its own process group, so the
# cleanup trap can kill whole trees — including grandchildren like
# wrangler/workerd that outlive a dead supervisor — by PGID, never by name.
set -m

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EDGE_PORT=8788
# Fixed ports sit below every OS's ephemeral range (Linux 32768-60999,
# macOS and Windows 49152-65535): inside it, any outbound socket on the
# runner can hold the port, and a loopback connect to a port nobody
# listens on can self-connect, so the in-use check below fired on a
# fresh runner.
REGISTRY_ADDR=127.0.0.1:28123
LOCAL_CI_ADDR=127.0.0.1:28124
EDGE_URL="http://127.0.0.1:${EDGE_PORT}"
SCHEDULER_URL="${EDGE_URL}/api/v1/scheduler"
# The trusted edge endpoints authenticate GitHub identity — no shared
# token exists. The operator's credential (GH_TOKEN/GITHUB_TOKEN, else
# `gh auth token`) is resolved once here because isolated_env swaps
# HOME/XDG_CONFIG_HOME, which would hide `gh`'s stored login.
EDGE_BEARER="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -z "$EDGE_BEARER" ]; then
    if command -v gh >/dev/null 2>&1; then
        EDGE_BEARER="$(gh auth token 2>/dev/null || true)"
    fi
fi
READY_DEADLINE="${STOW_E2E_READY_DEADLINE:-600}"
TASK_DEADLINE="${STOW_E2E_TASK_DEADLINE:-600}"
TASK_CRATE=itoa
TASK_FEATURES='["default"]'

# `stow-build` pins the task's rustc version via RUSTUP_TOOLCHAIN, so the
# whole run must use a toolchain whose `rustc --version` is itself a
# resolvable rustup toolchain name — a release, never a dated nightly.
export RUSTUP_TOOLCHAIN="${STOW_E2E_TOOLCHAIN:-stable}"

if [ -n "${STOW_E2E_WORK_DIR:-}" ]; then
    WORK_DIR="$STOW_E2E_WORK_DIR"
    if [ -e "$WORK_DIR" ] && [ -n "$(ls -A "$WORK_DIR" 2>/dev/null)" ]; then
        echo "[mock-e2e] STOW_E2E_WORK_DIR $WORK_DIR is not empty" >&2
        exit 1
    fi
    mkdir -p "$WORK_DIR"
else
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stow-mock-e2e.XXXXXX")"
fi
LOG_DIR="$WORK_DIR/logs"
mkdir -p "$LOG_DIR"

CHILD_PIDS=()
CHILD_NAMES=()

die() {
    echo "[mock-e2e] ERROR: $*" >&2
    exit 1
}

# All PIDs below $1, recursively. Printed one per line.
descendants() {
    local child
    for child in $(pgrep -P "$1" 2>/dev/null); do
        descendants "$child"
        echo "$child"
    done
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    local all_pids=() pid kids
    for pid in ${CHILD_PIDS[@]+"${CHILD_PIDS[@]}"}; do
        # Process-group kill reaches grandchildren reparented after their
        # supervisor died; the descendant walk below is the fallback.
        kill -- "-$pid" 2>/dev/null || true
        kids="$(descendants "$pid")"
        # shellcheck disable=SC2206 # PIDs are plain words; splitting is intended
        [ -n "$kids" ] && all_pids+=($kids)
        all_pids+=("$pid")
    done
    if [ ${#all_pids[@]} -gt 0 ]; then
        kill "${all_pids[@]}" 2>/dev/null || true
        local deadline=$((SECONDS + 10))
        while [ "$SECONDS" -lt "$deadline" ]; do
            local alive=0
            for pid in "${all_pids[@]}"; do
                kill -0 "$pid" 2>/dev/null && alive=$((alive + 1)) || true
            done
            [ "$alive" -eq 0 ] && break
            sleep 1
        done
        kill -9 "${all_pids[@]}" 2>/dev/null || true
    fi
    for pid in ${CHILD_PIDS[@]+"${CHILD_PIDS[@]}"}; do
        kill -9 -- "-$pid" 2>/dev/null || true
    done
    if [ "$status" -ne 0 ]; then
        # When the trap fires while a command's `>"$LOG_DIR/x.log" 2>&1`
        # redirect is still bound, stderr *is* one of the files below —
        # tailing it back into itself would grow without bound. Collect
        # into a file outside LOG_DIR first; a bare `cat` cannot loop.
        local dump="$WORK_DIR/cleanup-dump.txt" log
        echo "[mock-e2e] FAILED (exit $status) — log tails:" >"$dump"
        for log in "$LOG_DIR"/*.log; do
            [ -e "$log" ] || continue
            echo "===== $log =====" >>"$dump"
            tail -n 80 "$log" >>"$dump" 2>/dev/null || true
        done
        cat "$dump" >&2
    fi
    echo "[mock-e2e] logs: $LOG_DIR"
    exit "$status"
}
trap cleanup EXIT INT TERM

# PID of the most recently started service.
SERVICE_PID=""

start_service() {
    local name="$1" log="$2"
    shift 2
    "$@" >"$log" 2>&1 &
    SERVICE_PID=$!
    CHILD_PIDS+=("$SERVICE_PID")
    CHILD_NAMES+=("$name")
    echo "[mock-e2e] started $name (pid $SERVICE_PID), log: $log"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found on PATH: $1"
}

# Poll a readiness check with a wall-clock deadline. An optional owning PID
# as the third argument fails the wait early when that service has died.
wait_for() {
    local desc="$1" timeout="$2" owner_pid="$3"
    shift 3
    local deadline=$((SECONDS + timeout))
    while :; do
        check_children_alive
        if [ -n "$owner_pid" ] && ! kill -0 "$owner_pid" 2>/dev/null; then
            die "$desc: owning process $owner_pid exited before becoming ready"
        fi
        if "$@" >/dev/null 2>&1; then
            echo "[mock-e2e] $desc: ready"
            return 0
        fi
        [ "$SECONDS" -ge "$deadline" ] && die "timeout after ${timeout}s waiting for $desc"
        sleep 2
    done
}

# Any HTTP response proves the listener is up; used for endpoints whose
# routes are POST-only.
http_listening() {
    curl -s -o /dev/null --max-time 5 "$1"
}

check_children_alive() {
    local i
    for i in "${!CHILD_PIDS[@]}"; do
        kill -0 "${CHILD_PIDS[$i]}" 2>/dev/null || die "${CHILD_NAMES[$i]} exited unexpectedly"
    done
}

# Hermetic user-level state for consumer-side commands: a fresh HOME (which
# is what dirs::config_dir() derives from on macOS), XDG_CONFIG_HOME for
# Linux, and an empty CARGO_HOME so registry downloads stay in the work
# dir. RUSTUP_HOME points back at the real one — `stow-build` resolves
# `rustup_home()` from the real environment inside its sandbox, so the
# toolchain (and the version install above) must live there anyway.
# `ISOLATED_ENV` is set once `RUSTUP_HOME_REAL` is known, below.
isolated_env() {
    env "${ISOLATED_ENV[@]}" "$@"
}

# Every stow-cli call carries the full mock env — config, cache, verify
# mode, the run's edge URL, and the mock registry as the OCI base — so
# nothing falls back to the developer's real stow config.toml or to GHCR.
stow_cli() {
    isolated_env \
        STOW_EDGE_URL="$EDGE_URL" \
        STOW_REGISTRY_BASE_URL="http://${REGISTRY_ADDR}/v2/water-rs/stow-cache" \
        STOW_VERIFY_MODE="mock-key" \
        STOW_MOCK_PUBLIC_KEY_PATH="$WORK_DIR/keys/public.pem" \
        STOW_CACHE_DIR="$WORK_DIR/stow-cache" \
        "$BIN/stow-cli" "$@"
}

require_command cargo
require_command rustc
require_command rustup
require_command openssl
require_command curl
require_command jq
require_command sqlite3
require_command skyzen
require_command wrangler

[ -n "$EDGE_BEARER" ] || die \
    "no GitHub credential for the edge's trusted endpoints — set GH_TOKEN or run \`gh auth login\`"

RUSTC_VERSION="$(rustc --version | awk '{print $2}')"
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
RUSTUP_HOME_REAL="$(rustup show home)"
# The environment every stow process of this run gets: its own home,
# config and cargo home, with the real rustup toolchains.
ISOLATED_ENV=(
    HOME="$WORK_DIR/home"
    XDG_CONFIG_HOME="$WORK_DIR/config"
    CARGO_HOME="$WORK_DIR/cargo-home"
    RUSTUP_HOME="$RUSTUP_HOME_REAL"
)
[ -n "$RUSTC_VERSION" ] && [ -n "$HOST_TARGET" ] || die "could not detect rustc version/host"

# The build stage re-pins the task version as a rustup toolchain name
# (`RUSTUP_TOOLCHAIN=<semver>`), but a plain semver is only resolvable when
# a toolchain was installed under that version — `stable` alone leaves it
# unresolvable, and `rustup toolchain link` refuses channel-style names.
# Install the pinned release when missing. It lands in the real RUSTUP_HOME
# on purpose: `stow-build` resolves `rustup_home()` from the real
# environment inside the sandbox, so an isolated home would hide it.
if ! RUSTUP_TOOLCHAIN="$RUSTC_VERSION" rustc --version >/dev/null 2>&1; then
    echo "[mock-e2e] installing rustup toolchain '$RUSTC_VERSION' for the sandboxed build pin"
    rustup toolchain install --profile minimal "$RUSTC_VERSION" \
        || die "could not install rustup toolchain '$RUSTC_VERSION'"
fi
resolved="$(RUSTUP_TOOLCHAIN="$RUSTC_VERSION" rustc --version | awk '{print $2}')" \
    || die "rustup cannot resolve toolchain '$RUSTC_VERSION' (run under a release toolchain)"
[ "$resolved" = "$RUSTC_VERSION" ] \
    || die "RUSTUP_TOOLCHAIN=$RUSTC_VERSION resolved to rustc $resolved, expected $RUSTC_VERSION"

echo "[mock-e2e] work dir: $WORK_DIR"
echo "[mock-e2e] toolchain: $RUSTUP_TOOLCHAIN (rustc $RUSTC_VERSION, host $HOST_TARGET)"

# `skyzen dev` compiles the edge to wasm32 on the run's toolchain.
if ! rustup target list --installed --toolchain "$RUSTUP_TOOLCHAIN" \
    | grep -qx wasm32-unknown-unknown; then
    echo "[mock-e2e] installing wasm32-unknown-unknown for $RUSTUP_TOOLCHAIN"
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" wasm32-unknown-unknown
fi

cd "$REPO_ROOT"
echo "[mock-e2e] building stow-cli, stow-build, stow-mock-registry, stow-admin"
cargo build -p stow-cli --features mock-verify -p stow-build -p stow-mock-registry -p stow-admin \
    >"$LOG_DIR/cargo-build.log" 2>&1 \
    || die "cargo build failed — see $LOG_DIR/cargo-build.log"
cargo build -p stow-mock-registry --example demand_feed_fixture \
    >>"$LOG_DIR/cargo-build.log" 2>&1 \
    || die "cargo build (demand_feed_fixture example) failed — see $LOG_DIR/cargo-build.log"
BIN="$REPO_ROOT/target/debug"

# stow#523: typed demand-feed fixtures — the example writes the
# enqueue/queue document, per-hour provider documents, typed
# freeze bodies and the 512 KiB boundary pages the feed harness
# serves and posts below. `T05` starts hidden: the missing-fixture
# leg serves it back later.
"$BIN/examples/demand_feed_fixture" "$WORK_DIR/demand-fixtures" \
    || die "demand-feed fixture generation failed"
mv "$WORK_DIR/demand-fixtures/hours/2020-01-01T05.json" \
    "$WORK_DIR/demand-fixtures/2020-01-01T05.json"

# P-256 PKCS#8 key pair — the format sigstore accepts (docs/MOCK.md).
mkdir -p "$WORK_DIR/keys"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK_DIR/keys/private.pem"
openssl pkcs8 -topk8 -nocrypt -in "$WORK_DIR/keys/private.pem" -out "$WORK_DIR/keys/private.pkcs8.pem"
mv "$WORK_DIR/keys/private.pkcs8.pem" "$WORK_DIR/keys/private.pem"
openssl ec -in "$WORK_DIR/keys/private.pem" -pubout -out "$WORK_DIR/keys/public.pem"

mkdir -p "$WORK_DIR/mock-registry" "$WORK_DIR/edge-state" "$WORK_DIR/local-ci" "$WORK_DIR/stow-cache" \
    "$WORK_DIR/home" "$WORK_DIR/config" "$WORK_DIR/cargo-home"

# Nothing may already hold our ports: a stale listener would make every
# readiness probe pass against the wrong service.
for port in "$EDGE_PORT" "${REGISTRY_ADDR##*:}" "${LOCAL_CI_ADDR##*:}"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        die "port $port is already in use — refusing to probe a foreign service"
    fi
done

start_service mock-registry "$LOG_DIR/mock-registry.log" \
    "$BIN/stow-mock-registry" serve --registry-root "$WORK_DIR/mock-registry" --listen "$REGISTRY_ADDR" \
    --demand-fixtures "$WORK_DIR/demand-fixtures/hours"
# The version ping answers 401 + Bearer challenge, mirroring GHCR — that
# response is the readiness signal AND the auth handshake entry point.
mock_registry_ready() {
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${REGISTRY_ADDR}/v2/")" = "401" ]
}
wait_for "mock registry /v2/" 60 "$SERVICE_PID" mock_registry_ready

# Build the edge bundle once, then run `wrangler dev --local` (workerd)
# directly — the same command `skyzen dev` would supervise, minus its
# file watcher. The watcher is unusable here: on Linux inotify reports
# every open of the watched Cargo.toml/src files as a change, so each
# rebuild re-triggers itself and readiness never arrives; this lane
# never edits sources, so watching buys nothing.
(
    cd "$REPO_ROOT/edge"
    skyzen build --provider cloudflare --manifest Skyzen.mock.toml
) >"$LOG_DIR/edge-build.log" 2>&1 \
    || die "skyzen build failed — see $LOG_DIR/edge-build.log"
# The edge assumes its schema exists; migrations are deployment work, so the
# local D1 gets the same files the production pipeline applies, through the
# same `d1_migrations` bookkeeping: `ALTER TABLE … ADD COLUMN` and `DROP
# COLUMN` are not idempotent, so a reused edge-state dir (STOW_E2E_WORK_DIR)
# must apply only what it has not applied yet.
wrangler d1 migrations apply stow-mock --local \
    --config "$REPO_ROOT/edge/.skyzen/gen/wrangler.toml" \
    --persist-to "$WORK_DIR/edge-state" >>"$LOG_DIR/edge-migrate.log" 2>&1 \
    || die "edge migrations failed — see $LOG_DIR/edge-migrate.log"
(
    cd "$REPO_ROOT/edge"
    exec wrangler dev --local --config .skyzen/gen/wrangler.toml \
        --port "$EDGE_PORT" --persist-to "$WORK_DIR/edge-state"
) >"$LOG_DIR/edge.log" 2>&1 &
SERVICE_PID=$!
CHILD_PIDS+=("$SERVICE_PID")
CHILD_NAMES+=(edge)
echo "[mock-e2e] started edge (pid $SERVICE_PID), log: $LOG_DIR/edge.log"
# The scheduler Durable Object applies its schema through the operator
# migrate route — deployment work, never request work — so the mock
# plays the deploy pipeline: wait only for the listener, then run the
# same `stow-admin scheduler migrate` deploy-edge.yml runs, before any
# scheduler traffic. A status read before the migration is a 500; the
# listener probe takes the route's response code as its ready signal.
wait_for "edge listener" "$READY_DEADLINE" "$SERVICE_PID" \
    http_listening "$SCHEDULER_URL/status"
migrate_out="$(isolated_env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
    "$BIN/stow-admin" scheduler migrate 2>&1)" \
    || die "stow-admin scheduler migrate failed: $migrate_out"
echo "[mock-e2e] $migrate_out"
current_schema="$(sed -n 's/^const SCHEMA_VERSION: i64 = \([0-9]*\);/\1/p' \
    "$REPO_ROOT/edge/src/scheduler/queue.rs")"
[ -n "$current_schema" ] || die "could not read SCHEMA_VERSION from queue.rs"
[ "${migrate_out##* }" = "$current_schema" ] \
    || die "scheduler migrate reported '$migrate_out', expected schema $current_schema"
wait_for "edge scheduler status" "$READY_DEADLINE" "$SERVICE_PID" \
    curl -fsS "$SCHEDULER_URL/status"

# --- stow#523: hourly demand feed ------------------------------------
# The real admin -> authenticated workerd -> scheduler DO -> #522
# demand backend the hourly GitHub cron runs. The mock registry's
# --demand-fixtures dir answers every `analytics_engine/sql` demand
# query with the verbatim fixture file for the requested hour and
# appends one {"hour","served"} JSONL record to
# demand-queries.log, so the harness proves which hours were queried
# and that frozen hours are never re-queried. Corrupt/truncated byte
# streams live only in the mock provider files — the real edge
# endpoint is never faked. All expected identities and demand deltas
# come from the generator's expectations.json, never retyped here.
FEED_ROUTE="$EDGE_URL/api/v1/admin/scheduler/demand-feed"
DEMAND_ROUTE="$EDGE_URL/api/v1/admin/scheduler/demand"
FIXTURES="$WORK_DIR/demand-fixtures"
QUERY_LOG="$WORK_DIR/mock-registry/demand-queries.log"
EXPECT_TASKS="$(jq 'length' "$FIXTURES/expectations.json")"

feed_post() { # sub-route, body-file -> response body (fails on non-2xx)
    curl -fsS -H "Authorization: Bearer $EDGE_BEARER" \
        -H "Content-Type: application/json" \
        -X POST --data-binary "@$2" "$FEED_ROUTE/$1"
}
feed_post_code() { # sub-route, body-file -> HTTP status only
    curl -s -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $EDGE_BEARER" \
        -H "Content-Type: application/json" \
        -X POST --data-binary "@$2" "$FEED_ROUTE/$1"
}
demand_post() { # body-file -> demand report body
    curl -fsS -H "Authorization: Bearer $EDGE_BEARER" \
        -H "Content-Type: application/json" \
        -X POST --data-binary "@$1" "$DEMAND_ROUTE"
}
feed_freeze() { # hour: real begin -> patched-generation pages -> complete
    local hour="$1" gen page
    gen="$(feed_post begin <(jq -nc --arg h "$hour" '{hour:$h}') \
        | tee -a "$LOG_DIR/feed-begin-$hour.json" | jq -r '.generation')"
    [ -n "$gen" ] && [ "$gen" != "null" ] || die "feed begin $hour returned no generation"
    for page in "$FIXTURES/pages/$hour"-page-*.json; do
        jq --argjson g "$gen" '.generation = $g' "$page" >"$WORK_DIR/feed-page.json"
        feed_post page "$WORK_DIR/feed-page.json" >/dev/null \
            || die "feed freeze $hour: page $(basename "$page") rejected"
    done
    jq --argjson g "$gen" '.generation = $g' \
        "$FIXTURES/pages/$hour-complete.json" >"$WORK_DIR/feed-page.json"
    feed_post complete "$WORK_DIR/feed-page.json" >/dev/null \
        || die "feed freeze $hour: complete rejected"
    rm -f "$WORK_DIR/feed-page.json"
}
feed_deliver_until() { # hour: native deliver POSTs until delivered
    local hour="$1" reply
    for _ in 1 2 3 4 5 6 7 8; do
        reply="$(feed_post deliver <(jq -nc --arg h "$hour" '{hour:$h}'))" \
            || die "feed deliver $hour rejected"
        echo "$reply" >>"$LOG_DIR/feed-deliver-$hour.jsonl"
        [ "$(jq -rn --arg r "$reply" '$r|fromjson|.state' 2>/dev/null \
            || echo fail)" = "delivered" ] && return 0
    done
    die "feed deliver $hour never reached delivered"
}
feed_cleanup() { # hour: existing cleanup op drains staged payload pages
    local hour="$1" reply retired=0
    for _ in 1 2 3 4 5 6 7 8; do
        reply="$(feed_post cleanup <(jq -nc --arg h "$hour" '{hour:$h}'))" \
            || die "feed cleanup $hour rejected"
        echo "$reply" >>"$LOG_DIR/feed-cleanup-$hour.jsonl"
        retired=$((retired + $(jq -r '.retired' <<<"$reply")))
        [ "$(jq -r '.remaining' <<<"$reply")" = "false" ] && { echo "$retired"; return 0; }
    done
    die "feed cleanup $hour never reported remaining=false"
}
feed_cli() { # out_file [cli args...] -> prints captured output, CLI exit preserved
    local out_file="$1"; shift
    isolated_env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
        "$BIN/stow-admin" scheduler demand-feed --json "$@" \
        >"$out_file" 2>&1
    local status=$?
    cat "$out_file"
    return "$status"
}
feed_status() {
    curl -fsS -H "Authorization: Bearer $EDGE_BEARER" "$FEED_ROUTE/status"
}
feed_watermark() { feed_status | jq -r '.watermark // "null"'; }
feed_unfinished() { feed_status | jq -r '.unfinished.hour // "null"'; }
feed_unfinished_field() { feed_status | jq -r ".unfinished.$1 // \"null\""; }
query_count() { [ -f "$QUERY_LOG" ] && wc -l <"$QUERY_LOG" || echo 0; }
expect_watermark() {
    [ "$(feed_watermark)" = "$1" ] \
        || die "feed watermark is $(feed_watermark), expected $1"
}
expect_unfinished() { # hour state staged_pages
    local u_hour u_state u_pages
    u_hour="$(feed_unfinished)"; u_state="$(feed_unfinished_field state)"
    u_pages="$(feed_unfinished_field staged_pages)"
    [ "$u_hour" = "$1" ] && [ "$u_state" = "$2" ] \
        || die "unfinished is $u_hour/$u_state, expected $1/$2"
    [ -z "$3" ] || [ "$u_pages" = "$3" ] \
        || die "unfinished staged_pages is $u_pages, expected $3"
}
expect_query_delta() { # expected_new_queries hour
    local count
    count="$(query_count)"
    [ "$count" = "$1" ] || die "provider query count is $count, expected $1"
    [ "$(jq -r '.hour' "$QUERY_LOG" | tail -1)" = "$2" ] \
        || die "last provider query was not for $2"
}

# Every fixture queue row, paged through the typed task_ids selector
# in bounded chunks (the admin list ceiling is 500; sixty ids per
# call stays well under it and under URL length limits).
fixture_rows() { # out-file: one merged JSON array of QueueTask rows
    local out="$1" chunk query
    jq -r '.[].task_id' "$FIXTURES/expectations.json" >"$WORK_DIR/task-ids.txt"
    rm -f "$WORK_DIR"/ids-chunk-*; : >"$out"
    split -l 60 "$WORK_DIR/task-ids.txt" "$WORK_DIR/ids-chunk-"
    for chunk in "$WORK_DIR"/ids-chunk-*; do
        query="$(sed 's/^/task_ids=/' "$chunk" | paste -sd'&')"
        curl -fsS -H "Authorization: Bearer $EDGE_BEARER" \
            "$EDGE_URL/api/v1/admin/queue?$query" >"$WORK_DIR/queue-page.json" \
            || die "queue readback failed"
        jq -c '.[]' "$WORK_DIR/queue-page.json" >>"$out"
    done
}
# task_id -> value map for the fixture set.
fixture_values() { # out-file: {task_id: number}
    fixture_rows "$WORK_DIR/fixture-rows.jsonl"
    jq -s 'map({key: .task_id, value: (.value | tonumber)}) | from_entries' \
        "$WORK_DIR/fixture-rows.jsonl" >"$1"
}
# Assert the whole fixture set: every expected task present exactly
# once, every row non-dispatched.
assert_fixture_rows() {
    local rows uniq bad_status
    rows="$(jq -s 'length' "$WORK_DIR/fixture-rows.jsonl")"
    uniq="$(jq -s '[.[].task_id] | unique | length' "$WORK_DIR/fixture-rows.jsonl")"
    [ "$rows" = "$EXPECT_TASKS" ] && [ "$uniq" = "$EXPECT_TASKS" ] \
        || die "fixture queue rows: $rows rows / $uniq unique, expected $EXPECT_TASKS"
    bad_status="$(jq -s '[.[] | select(.status != "pending" and .status != "blocked")] | length' \
        "$WORK_DIR/fixture-rows.jsonl")"
    [ "$bad_status" = "0" ] \
        || die "fixture tasks must stay non-dispatched, got $bad_status rows outside pending/blocked"
}
# Exact per-task delta check against generated expectations:
# jq exits 0 only when EVERY row's (final - initial) equals the
# generated expected_delta — missing rows produce null and fail.
assert_all_deltas() { # init-map final-map
    jq -n --slurpfile init "$1" --slurpfile final "$2" \
        --slurpfile exp "$FIXTURES/expectations.json" '
        ($exp[0]) as $e |
        all($e[];
            (($final[0][.task_id] // null) != null) and
            (($init[0][.task_id] // null) != null) and
            (($final[0][.task_id] - $init[0][.task_id]) == .expected_delta))' \
        | grep -qx true \
        || die "fixture demand deltas mismatch — see $WORK_DIR/delta-diff.json"
}
delta_diff() { # init-map final-map -> writes mismatch report
    jq -n --slurpfile init "$1" --slurpfile final "$2" \
        --slurpfile exp "$FIXTURES/expectations.json" '
        ($exp[0]) | map(select(
            (($final[0][.task_id] // null) == null) or
            (($final[0][.task_id] - ($init[0][.task_id] // 0)) != .expected_delta)) |
            {task_id, crate_name, expected_delta,
             initial: $init[0][.task_id], final: $final[0][.task_id]})' \
        >"$WORK_DIR/delta-diff.json"
}
# Checkpoint the whole set right before a no-effect group.
values_checkpoint() { fixture_values "$WORK_DIR/values-prev.json"; }
# Whole-map equality for the "no demand effect" legs.
assert_values_unchanged() { # before-map
    fixture_values "$WORK_DIR/values-now.json"
    jq -n --slurpfile a "$1" --slurpfile b "$WORK_DIR/values-now.json" '$a[0] == $b[0]' \
        | grep -qx true || die "queue values changed across a no-effect leg"
}

# 1) Real queue tasks through the authenticated submit route: every
# distinct base dep the consumers reference — each parked on an
# absent `fixture-anchor-*` dep so deps_met stays 0 forever — plus
# 520 consumers sharing them as a real DAG. Nothing fixture-side can
# dispatch under the ordinary gate; no dispatch setting changes.
echo "[mock-e2e] demand feed: submitting fixture queue tasks"
submit_code="$(curl -s -o "$LOG_DIR/submit-fixture.json" -w '%{http_code}' \
    -H "Authorization: Bearer $EDGE_BEARER" -H "Content-Type: application/json" \
    -X POST --data-binary @"$FIXTURES/enqueue.json" \
    "$EDGE_URL/api/v1/scheduler/tasks/submit")"
[ "$submit_code" -ge 200 ] && [ "$submit_code" -lt 300 ] \
    || die "fixture submit failed ($submit_code): $(cat "$LOG_DIR/submit-fixture.json")"
fixture_rows "$WORK_DIR/fixture-rows.jsonl"
assert_fixture_rows
jq -s 'map({key: .task_id, value: (.value | tonumber)}) | from_entries' \
    "$WORK_DIR/fixture-rows.jsonl" >"$WORK_DIR/values-init.json"

# 5) Bootstrap gap scenario: freeze future T04 (3 pages) AND T00 with
# no watermark, deliver T00, then default CLI runs fill T01..T03 from
# the provider while T04's frozen bytes stay untouched; once T04 is
# canonical its original pages resume with no query.
echo "[mock-e2e] demand feed: freeze T00 + T04 (bootstrap, no watermark)"
feed_freeze 2020-01-01T00
feed_freeze 2020-01-01T04
feed_deliver_until 2020-01-01T00
expect_watermark 2020-01-01T00
expect_unfinished 2020-01-01T04 complete 3

echo "[mock-e2e] demand feed: canonical T01/T02/T03 fill under frozen T04"
q="$(query_count)"
feed_out="$LOG_DIR/demand-feed-01.json"
feed_cli "$feed_out" || die "demand-feed T01 failed -- see $feed_out"
[ "$(jq -r '.hour' "$feed_out")" = "2020-01-01T01" ] \
    && [ "$(jq -r '.state' "$feed_out")" = "delivered" ] \
    || die "demand-feed T01 unexpected report: $(cat "$feed_out")"
expect_watermark 2020-01-01T01
expect_unfinished 2020-01-01T04 complete 3
expect_query_delta $((q + 1)) 2020-01-01T01
feed_out="$LOG_DIR/demand-feed-02.json"
feed_cli "$feed_out" || die "demand-feed T02 failed -- see $feed_out"
expect_watermark 2020-01-01T02
expect_unfinished 2020-01-01T04 complete 3
expect_query_delta $((q + 2)) 2020-01-01T02

# Explicit leap past the canonical gap refuses before any query/write.
values_checkpoint
feed_out="$LOG_DIR/demand-feed-04-leap.json"
if feed_cli "$feed_out" --hour 2020-01-01T04; then
    die "demand-feed T04 should refuse while T03 is the canonical cursor"
fi
expect_query_delta $((q + 2)) 2020-01-01T02
expect_watermark 2020-01-01T02
assert_values_unchanged "$WORK_DIR/values-prev.json"

feed_out="$LOG_DIR/demand-feed-03.json"
feed_cli "$feed_out" || die "demand-feed T03 failed -- see $feed_out"
expect_watermark 2020-01-01T03
expect_query_delta $((q + 3)) 2020-01-01T03

q="$(query_count)"
feed_out="$LOG_DIR/demand-feed-04.json"
feed_cli "$feed_out" || die "demand-feed T04 resume failed -- see $feed_out"
[ "$(jq -r '.state' "$feed_out")" = "delivered" ] \
    || die "demand-feed T04: expected delivered, got $(cat "$feed_out")"
expect_watermark 2020-01-01T04
[ "$(query_count)" = "$q" ] \
    || die "frozen T04 resume must not re-query the provider"
expect_unfinished null null

# 2) Envelope bounds on the real DO stage route: a 1-entry page just
# under the 512KiB framing accepts; the same page just over refuses;
# a 257-entry page refuses on the entry bound alone. Rejections
# stage nothing — the durable status keeps only the accepted page.
echo "[mock-e2e] demand feed: T05 envelope + entry-count bounds"
values_checkpoint
gen="$(feed_post begin <(jq -nc '{hour:"2020-01-01T05"}') | jq -r '.generation')"
[ -n "$gen" ] && [ "$gen" != "null" ] || die "T05 begin returned no generation"
jq --argjson g "$gen" '.generation = $g' "$FIXTURES/boundary/under-page.json" \
    >"$WORK_DIR/feed-page.json"
under_code="$(feed_post_code page "$WORK_DIR/feed-page.json")"
[ "$under_code" -ge 200 ] && [ "$under_code" -lt 300 ] \
    || die "under-boundary page rejected ($under_code)"
jq --argjson g "$gen" '.generation = $g' "$FIXTURES/boundary/over-page.json" \
    >"$WORK_DIR/feed-page.json"
over_code="$(feed_post_code page "$WORK_DIR/feed-page.json")"
[ "$over_code" -ge 400 ] && [ "$over_code" -lt 500 ] \
    || die "oversize page must be refused 4xx, got $over_code"
jq --argjson g "$gen" '.generation = $g' "$FIXTURES/boundary/over-entries-page.json" \
    >"$WORK_DIR/feed-page.json"
entries_code="$(feed_post_code page "$WORK_DIR/feed-page.json")"
[ "$entries_code" -ge 400 ] && [ "$entries_code" -lt 500 ] \
    || die "257-entry page must be refused 4xx, got $entries_code"
expect_unfinished 2020-01-01T05 staging 1
assert_values_unchanged "$WORK_DIR/values-prev.json"

# 3) Provider HTTP error on the canonical hour: T05's fixture was
# hidden, so the resumed materialization rotates the staged boundary
# page, queries, and fails — demand values stay put.
q="$(query_count)"
feed_out="$LOG_DIR/demand-feed-05-missing.json"
if feed_cli "$feed_out"; then
    die "demand-feed T05 should fail while its fixture file is absent"
fi
expect_query_delta $((q + 1)) 2020-01-01T05
expect_watermark 2020-01-01T04
expect_unfinished 2020-01-01T05 staging
assert_values_unchanged "$WORK_DIR/values-prev.json"
mv "$FIXTURES/2020-01-01T05.json" "$FIXTURES/hours/2020-01-01T05.json"
feed_out="$LOG_DIR/demand-feed-05.json"
feed_cli "$feed_out" || die "demand-feed T05 retry failed -- see $feed_out"
expect_watermark 2020-01-01T05
expect_query_delta $((q + 2)) 2020-01-01T05

# Truncated stream, a late-invalid row (index 300, past the first
# page bound), then a declared-rows mismatch — the parser stages
# completed pages as it streams, so each failure leaves the hour
# staging with pages staged, the watermark unmoved, and zero demand
# effect. The cleanup report then drains the staged payload.
echo "[mock-e2e] demand feed: T06 failure classes"
valid06="$FIXTURES/hours/2020-01-01T06-valid.json"
values_checkpoint
size="$(wc -c <"$valid06")"
q="$(query_count)"
head -c $((size / 2)) "$valid06" >"$FIXTURES/hours/2020-01-01T06.json"
feed_out="$LOG_DIR/demand-feed-06-truncated.json"
if feed_cli "$feed_out"; then
    die "demand-feed T06 should fail on a truncated document"
fi
expect_query_delta $((q + 1)) 2020-01-01T06
expect_watermark 2020-01-01T05
expect_unfinished 2020-01-01T06 staging
assert_values_unchanged "$WORK_DIR/values-prev.json"

# 300 > 255, so page 0 already streamed to the DO: the failure leaves
# a genuine partial stage (exactly one page), never a freeze.
jq '.data[300].demand = "not-a-number"' "$valid06" >"$FIXTURES/hours/2020-01-01T06.json"
feed_out="$LOG_DIR/demand-feed-06-badrow.json"
if feed_cli "$feed_out"; then
    die "demand-feed T06 should fail on a late-invalid row"
fi
expect_query_delta $((q + 2)) 2020-01-01T06
expect_watermark 2020-01-01T05
expect_unfinished 2020-01-01T06 staging 1
assert_values_unchanged "$WORK_DIR/values-prev.json"

# `.rows` is checked at stream end, so all three pages of the 520-row
# document are already staged when the mismatch fails the run.
jq '.rows = 9999' "$valid06" >"$FIXTURES/hours/2020-01-01T06.json"
feed_out="$LOG_DIR/demand-feed-06-rowcount.json"
if feed_cli "$feed_out"; then
    die "demand-feed T06 should fail on a declared-rows mismatch"
fi
expect_query_delta $((q + 3)) 2020-01-01T06
expect_watermark 2020-01-01T05
expect_unfinished 2020-01-01T06 staging 3
assert_values_unchanged "$WORK_DIR/values-prev.json"

# Stale payload retirement is real work, not a claim: the existing
# cleanup report retires the staged pages before the retry rotates.
retired="$(feed_cleanup 2020-01-01T06)"
[ "$retired" -ge 1 ] \
    || die "cleanup must retire staged T06 pages after failures, retired=$retired"

cp "$valid06" "$FIXTURES/hours/2020-01-01T06.json"
feed_out="$LOG_DIR/demand-feed-06.json"
feed_cli "$feed_out" || die "demand-feed T06 retry failed -- see $feed_out"
expect_watermark 2020-01-01T06
expect_query_delta $((q + 4)) 2020-01-01T06
expect_unfinished null null

# Empty canonical hours walk begin -> complete -> delivered and move
# the watermark without touching the queue.
echo "[mock-e2e] demand feed: T07 + T08 empty hours"
values_checkpoint
q="$(query_count)"
feed_out="$LOG_DIR/demand-feed-07.json"
feed_cli "$feed_out" || die "demand-feed T07 failed -- see $feed_out"
expect_watermark 2020-01-01T07
expect_query_delta $((q + 1)) 2020-01-01T07
assert_values_unchanged "$WORK_DIR/values-prev.json"

# Leap refusal before any query, then the canonical fill.
feed_out="$LOG_DIR/demand-feed-09-leap.json"
if feed_cli "$feed_out" --hour 2020-01-01T09; then
    die "demand-feed T09 should refuse while T08 is canonical"
fi
expect_query_delta $((q + 1)) 2020-01-01T07
feed_out="$LOG_DIR/demand-feed-08.json"
feed_cli "$feed_out" || die "demand-feed T08 failed -- see $feed_out"
expect_watermark 2020-01-01T08
expect_query_delta $((q + 2)) 2020-01-01T08

# Schema-broken meta on the canonical hour, then the valid document.
values_checkpoint
cp "$FIXTURES/hours/2020-01-01T09.json" "$WORK_DIR/t09-valid.json"
jq '.meta = [{"bogus": true}]' "$WORK_DIR/t09-valid.json" \
    >"$FIXTURES/hours/2020-01-01T09.json"
feed_out="$LOG_DIR/demand-feed-09-broken.json"
if feed_cli "$feed_out"; then
    die "demand-feed T09 should refuse a schema-broken meta"
fi
expect_query_delta $((q + 3)) 2020-01-01T09
expect_watermark 2020-01-01T08
expect_unfinished 2020-01-01T09 staging
assert_values_unchanged "$WORK_DIR/values-prev.json"
mv "$WORK_DIR/t09-valid.json" "$FIXTURES/hours/2020-01-01T09.json"
feed_out="$LOG_DIR/demand-feed-09.json"
feed_cli "$feed_out" || die "demand-feed T09 retry failed -- see $feed_out"
expect_watermark 2020-01-01T09
expect_query_delta $((q + 4)) 2020-01-01T09
expect_unfinished null null

# 4) Lost-ACK resume: freeze T10's three pages via the typed routes,
# deliver exactly one page natively and keep the reply — the client
# died before seeing it. The provider file then turns corrupt; the
# real CLI resumes and delivers the two remaining frozen pages with
# zero new queries. Delivered-hour replays are terminal no-ops on
# both the feed route and the #522 demand route.
echo "[mock-e2e] demand feed: T10 freeze / lost-ACK resume"
feed_freeze 2020-01-01T10
reply="$(feed_post deliver <(jq -nc '{hour:"2020-01-01T10"}'))" \
    || die "T10 single-page deliver failed"
echo "$reply" >"$LOG_DIR/feed-deliver-10-first.json"
[ "$(jq -r '.delivered_page' <<<"$reply")" = "0" ] \
    && [ "$(jq -r '.applied' <<<"$reply")" = "true" ] \
    && [ "$(jq -r '.remaining_pages' <<<"$reply")" = "2" ] \
    && [ "$(jq -r '.touched_tasks' <<<"$reply")" -gt 0 ] \
    || die "T10 first deliver unexpected: $reply"
q="$(query_count)"
echo 'CORRUPTED upstream document' >"$FIXTURES/hours/2020-01-01T10.json"
feed_out="$LOG_DIR/demand-feed-10.json"
feed_cli "$feed_out" || die "demand-feed T10 resume failed -- see $feed_out"
[ "$(jq -r '.state' "$feed_out")" = "delivered" ] \
    && [ "$(jq -r '.staged_pages' "$feed_out")" = "0" ] \
    || die "demand-feed T10: expected delivered/0 staged, got $(cat "$feed_out")"
expect_watermark 2020-01-01T10
[ "$(query_count)" = "$q" ] \
    || die "frozen T10 resume must not query the (now corrupt) provider"
reply="$(feed_post deliver <(jq -nc '{hour:"2020-01-01T10"}'))" \
    || die "T10 delivered replay must be an accepted no-op"
echo "$reply" >>"$LOG_DIR/feed-deliver-10-first.json"
[ "$(jq -r '.state' <<<"$reply")" = "delivered" ] \
    && [ "$(jq -r '.delivered_page' <<<"$reply")" = "null" ] \
    && [ "$(jq -r '.applied' <<<"$reply")" = "false" ] \
    && [ "$(jq -r '.touched_tasks' <<<"$reply")" = "0" ] \
    && [ "$(jq -r '.remaining_pages' <<<"$reply")" = "0" ] \
    || die "T10 replay must be a delivered no-op, got $reply"
# The deterministic #522 batch id the first page already accepted:
# replaying it through the demand route writes nothing.
demand_reply="$(demand_post "$FIXTURES/pages/2020-01-01T10-demand-replay.json")" \
    || die "demand replay must be accepted"
echo "$demand_reply" >"$LOG_DIR/demand-replay-10.json"
[ "$(jq -r '.applied' <<<"$demand_reply")" = "false" ] \
    || die "demand replay must report applied=false, got $demand_reply"

# Exact whole-set demand deltas: every one of the 528 fixture tasks
# (all 520 consumers AND every shared base closure) must show exactly
# its generated expected_delta — no spot checks.
echo "[mock-e2e] demand feed: exact whole-set demand deltas"
fixture_values "$WORK_DIR/values-final.json"
delta_diff "$WORK_DIR/values-init.json" "$WORK_DIR/values-final.json"
assert_all_deltas "$WORK_DIR/values-init.json" "$WORK_DIR/values-final.json"
fixture_rows "$WORK_DIR/fixture-rows.jsonl"
assert_fixture_rows

# The provider log: exact per-hour query counts — T00/T04/T10 never
# appear (frozen bytes), T05 twice (missing then valid), T06 four
# times (three failures + retry), T09 twice (broken meta + valid).
echo "[mock-e2e] demand feed: provider query log"
feed_hours="$(jq -r '.hour' "$QUERY_LOG" | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
expected_hours=" 1 2020-01-01T01; 1 2020-01-01T02; 1 2020-01-01T03; 2 2020-01-01T05; 4 2020-01-01T06; 1 2020-01-01T07; 1 2020-01-01T08; 2 2020-01-01T09;"
[ "$feed_hours" = "$expected_hours" ] \
    || die "unexpected provider-query timeline: $feed_hours"

# Consent + sampling stay pinned to the checked-in SQL: weighted
# `sum(_sample_interval * double1)` under deterministic full ordering
# with LIMIT ALL (no engine-side truncation), and consent enforced at
# write time (STOW_NO_ANALYTICS) — the query can only ever see
# identities from consenting rows.
grep -q '_sample_interval \* double1' "$REPO_ROOT/edge/templates/demand_feed.sql" \
    || die "demand feed query lost the weighted sampling estimate"
grep -q 'LIMIT ALL' "$REPO_ROOT/edge/templates/demand_feed.sql" \
    || die "demand feed query lost LIMIT ALL truncation guard"
grep -q 'STOW_NO_ANALYTICS' "$REPO_ROOT/edge/templates/demand_feed.sql" \
    || die "demand feed query lost the consent contract"
# Observability limit, stated honestly: public surfaces expose queue
# values only — aborted/prepared input is proven here as zero value
# effect, and accepted-vs-consumed under real dispatch remains
# measured only by the existing stow#522 native budget drives.

# stow#336: production links every Linux unit against the Debian buster
# (glibc 2.28) sysroot build-crate.yml provisions — the dispatched builds
# link the same way through the same scripts, into a cache dir keyed by
# the deb manifest's hash so each box installs it once. The stow
# binaries themselves were built before this and keep the host glibc;
# the sysroot env is exported only inside the server below.
SYSROOT=""
if [ "$(uname -s)" = "Linux" ]; then
    SYSROOT="${XDG_CACHE_HOME:-$HOME/.cache}/stow/glibc-sysroot-$(sha256sum \
        "$REPO_ROOT/ci/glibc-sysroot-debs.txt" | cut -d' ' -f1)"
    if [ ! -d "$SYSROOT" ]; then
        "$REPO_ROOT/ci/glibc-sysroot/install.sh" "$SYSROOT" \
            || die "glibc sysroot install failed"
    fi
    "$REPO_ROOT/ci/glibc-sysroot/wrappers.sh" "$SYSROOT" \
        || die "glibc sysroot wrapper write failed"
fi

# The dispatch tree (.tmp/local-ci-dispatch) is written under the server's
# cwd; keep it inside the work dir.
(
    cd "$WORK_DIR/local-ci"
    # The builds this server runs consume the mock registry and an
    # isolated stow cache, never GHCR or the developer's ~/.stow.
    [ -z "$SYSROOT" ] || eval "$("$REPO_ROOT/ci/glibc-sysroot/env.sh" "$SYSROOT")"
    exec env "${ISOLATED_ENV[@]}" \
        STOW_REGISTRY_BASE_URL="http://${REGISTRY_ADDR}/v2/water-rs/stow-cache" \
        STOW_VERIFY_MODE="mock-key" \
        STOW_CACHE_DIR="$WORK_DIR/stow-cache" \
        SCHEDULER_URL="$SCHEDULER_URL" \
        STOW_EDGE_URL="$EDGE_URL" \
        STOW_GITHUB_WEBHOOK_SECRET="mock-github-webhook-secret" \
        STOW_MOCK_PUBLIC_KEY_PATH="$WORK_DIR/keys/public.pem" \
        STOW_MOCK_PRIVATE_KEY_PATH="$WORK_DIR/keys/private.pem" \
        STOW_MOCK_REGISTRY_ROOT="$WORK_DIR/mock-registry" \
        GH_TOKEN="$EDGE_BEARER" \
        "$BIN/stow-build" serve --listen "$LOCAL_CI_ADDR"
) >"$LOG_DIR/local-ci.log" 2>&1 &
SERVICE_PID=$!
CHILD_PIDS+=("$SERVICE_PID")
CHILD_NAMES+=(local-ci)
echo "[mock-e2e] started local-ci (pid $SERVICE_PID), log: $LOG_DIR/local-ci.log"
wait_for "local CI dispatch endpoint" 60 "$SERVICE_PID" \
    http_listening "http://${LOCAL_CI_ADDR}/dispatch"

# Latest non-yanked 1.0.x, read from the sparse index (one JSON line per
# release) rather than the rate-limited crates.io API.
TASK_VERSION="$(curl -fsS --max-time 30 -H 'User-Agent: stow-mock-e2e' \
    'https://index.crates.io/it/oa/itoa' \
    | jq -rs '[.[] | select(.yanked | not) | .vers | select(startswith("1.0."))]
              | sort_by(split(".") | map(tonumber)) | last // empty')"
[ -n "$TASK_VERSION" ] || die "no non-yanked itoa 1.0.x found on crates.io"
echo "[mock-e2e] submitting $TASK_CRATE $TASK_VERSION features=$TASK_FEATURES target=$HOST_TARGET rustc=$RUSTC_VERSION"

isolated_env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
    "$BIN/stow-admin" submit \
    --crate-name "$TASK_CRATE" \
    --version "$TASK_VERSION" \
    --features-json "$TASK_FEATURES" \
    --target "$HOST_TARGET" \
    --rustc-version "$RUSTC_VERSION" \
    --yes \
    >"$LOG_DIR/admin-submit.log" 2>&1 \
    || die "stow-admin submit failed — see $LOG_DIR/admin-submit.log"

# Poll the scheduler until the task completes, fails, or the deadline hits.
deadline=$((SECONDS + TASK_DEADLINE))
while :; do
    check_children_alive
    status_json="$(curl -fsS --max-time 10 "$SCHEDULER_URL/status" 2>/dev/null || true)"
    if [ -n "$status_json" ]; then
        completed="$(jq -r '.completed' <<<"$status_json")"
        failed="$(jq -r '.failed' <<<"$status_json")"
        echo "[mock-e2e] scheduler: $status_json"
        [ "$completed" -ge 1 ] && break
        [ "$failed" -ge 1 ] && die "scheduler reported the task failed: $status_json"
    fi
    [ "$SECONDS" -ge "$deadline" ] && die "scheduler did not complete the task within ${TASK_DEADLINE}s (last status: ${status_json:-none})"
    sleep 5
done

# The consumer resolves artifacts through the signed local index, so the
# slices the runs' records feed must exist in the mock registry before
# `stow check` runs: `index export --out-dir` reads and verifies the
# records artifacts (mock-key trust) in one pass, and `index publish`
# delegates each slice's signed push to `stow-mock-registry
# publish-index`, which writes the same layout the GHCR path produces.
isolated_env \
    STOW_REGISTRY_BASE_URL="http://${REGISTRY_ADDR}/v2/water-rs/stow-cache" \
    STOW_MOCK_PUBLIC_KEY_PATH="$WORK_DIR/keys/public.pem" \
    "$BIN/stow-admin" index export \
    --out-dir "$WORK_DIR/index-export" \
    --rustc-version "$RUSTC_VERSION" \
    >"$LOG_DIR/index-export.log" 2>&1 \
    || die "stow-admin index export failed — see $LOG_DIR/index-export.log"

pairs="$(python3 -c 'import json,sys
for s in json.load(open(sys.argv[1])):
    print(s["index_file"], s["folded_file"])' "$WORK_DIR/index-export/slices.json")" \
    || die "reading $WORK_DIR/index-export/slices.json failed"
echo "$pairs" | while read -r index_file folded_file; do
    [ -n "$index_file" ] || continue
    isolated_env \
        STOW_MOCK_PRIVATE_KEY_PATH="$WORK_DIR/keys/private.pem" \
        STOW_MOCK_REGISTRY_ROOT="$WORK_DIR/mock-registry" \
        "$BIN/stow-admin" index publish \
        --file "$WORK_DIR/index-export/$index_file" \
        --folded "$WORK_DIR/index-export/$folded_file" \
        >>"$LOG_DIR/index-publish.log" 2>&1 \
        || die "stow-admin index publish failed for $index_file — see $LOG_DIR/index-publish.log"
    isolated_env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
        "$BIN/stow-admin" index report \
        --file "$WORK_DIR/index-export/$index_file" \
        >>"$LOG_DIR/index-report.log" 2>&1 \
        || die "stow-admin index report failed for $index_file — see $LOG_DIR/index-report.log"
done

# D1's catalog is a read model of the records the export just folded:
# `index sync` replays `new-records.json` into it, as index-publish.yml
# does after its publish loop. The miss derivation reads it, so a
# covered graph mints no admission only once the sync has landed.
isolated_env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
    "$BIN/stow-admin" index sync \
    --file "$WORK_DIR/index-export/new-records.json" \
    >"$LOG_DIR/index-sync.log" 2>&1 \
    || die "stow-admin index sync failed — see $LOG_DIR/index-sync.log"

# Exercise the consumer-facing commands before `check`: refresh pulls and
# verifies the signed slice, status reports the cached row set the
# resolver will read.
stow_cli index refresh >"$LOG_DIR/index-refresh.log" 2>&1 \
    || die "stow index refresh failed — see $LOG_DIR/index-refresh.log"
stow_cli index status >"$LOG_DIR/index-status.log" 2>&1 \
    || die "stow index status failed — see $LOG_DIR/index-status.log"
cat "$LOG_DIR/index-status.log"
grep -q "target: $HOST_TARGET" "$LOG_DIR/index-status.log" \
    || die "index status lists no slice for $HOST_TARGET"
grep -q "rustc-version: $RUSTC_VERSION" "$LOG_DIR/index-status.log" \
    || die "index status lists no slice for rustc $RUSTC_VERSION"
index_rows="$(awk '/^rows: /{print $2}' "$LOG_DIR/index-status.log" | head -1)"
[ "${index_rows:-0}" -ge 1 ] \
    || die "cached index slice is empty (rows=$index_rows) — export/publish lost the task row"

# The same wave, driven by hand: `preheat manual` resolves the crate
# list in-process, layers it, dispatches straight to the local CI
# server, and publishes the index slice between layers — the edge only
# sees the runs' webhook completions. walkdir carries one unix dep
# (same-file), so the wave lands in two layers.
printf 'walkdir\n' >"$WORK_DIR/manual-crates.txt"
isolated_env \
    STOW_REGISTRY_BASE_URL="http://${REGISTRY_ADDR}/v2/water-rs/stow-cache" \
    STOW_MOCK_PUBLIC_KEY_PATH="$WORK_DIR/keys/public.pem" \
    STOW_MOCK_PRIVATE_KEY_PATH="$WORK_DIR/keys/private.pem" \
    STOW_MOCK_REGISTRY_ROOT="$WORK_DIR/mock-registry" \
    "$BIN/stow-admin" preheat manual \
    --crates "$WORK_DIR/manual-crates.txt" \
    --rustc-version "$RUSTC_VERSION" \
    --targets "$HOST_TARGET" \
    --dispatch-url "http://${LOCAL_CI_ADDR}" \
    --in-flight 4 \
    >"$LOG_DIR/preheat-manual.log" 2>&1 \
    || { cat "$LOG_DIR/preheat-manual.log"; die "stow-admin preheat manual failed — see $LOG_DIR/preheat-manual.log"; }

# The manual run's publish must have landed a slice serving walkdir —
# the driver's own wait loop already proved it, but assert the registry
# view directly so a driver-side wait bug cannot hide a lost publish.
# The mock registry, like GHCR, serves /v2 only to an anonymous bearer
# minted by its token endpoint.
registry_token="$(curl -fsS --max-time 10 \
    "http://${REGISTRY_ADDR}/token?service=${REGISTRY_ADDR}&scope=repository:water-rs/stow-cache:pull" \
    | jq -er .token)" \
    || die "mock registry token exchange failed"
curl -fsS --max-time 10 -H "Authorization: Bearer ${registry_token}" \
    "http://${REGISTRY_ADDR}/v2/water-rs/stow-cache/manifests/index.${HOST_TARGET}.${RUSTC_VERSION}" \
    -o /dev/null \
    || die "index slice index.${HOST_TARGET}.${RUSTC_VERSION} missing after the manual wave"

# Throwaway consumer pinned to the exact version the scheduler just built.
CONSUMER="$WORK_DIR/itoa-consumer"
isolated_env cargo new --lib --vcs none "$CONSUMER" >"$LOG_DIR/consumer-new.log" 2>&1 \
    || die "cargo new failed — see $LOG_DIR/consumer-new.log"
printf 'itoa = "=%s"\n' "$TASK_VERSION" >>"$CONSUMER/Cargo.toml"

# Warm the isolated CARGO_HOME the way any real consumer machine already
# is: stow's post-pin mirror analysis runs `cargo metadata --offline`,
# which needs the registry index and crate sources present locally. On a
# truly cold cache stow degrades to plain cargo by design (the
# no-slowdown floor), which would silently skip the very path this lane
# exists to exercise.
(
    cd "$CONSUMER"
    isolated_env cargo fetch
) >"$LOG_DIR/consumer-fetch.log" 2>&1 \
    || die "cargo fetch failed — see $LOG_DIR/consumer-fetch.log"

# `stow setup` first, the order a user follows: on Linux it provisions
# mold and writes the linker selection into the isolated CARGO_HOME's
# config.toml, and a build without that selection refuses to start.
# `stow status` reads the same file below.
(
    cd "$CONSUMER"
    stow_cli setup
) >"$LOG_DIR/stow-setup.log" 2>&1 \
    || die "stow setup failed — see $LOG_DIR/stow-setup.log"

[ -f "$WORK_DIR/cargo-home/config.toml" ] \
    || die "stow setup wrote no $WORK_DIR/cargo-home/config.toml"

(
    cd "$CONSUMER"
    stow_cli check
) >"$LOG_DIR/stow-check.log" 2>&1 \
    || die "stow check failed — see $LOG_DIR/stow-check.log"

(
    cd "$CONSUMER"
    stow_cli status
) >"$LOG_DIR/stow-status.log" 2>&1 \
    || die "stow status failed — see $LOG_DIR/stow-status.log"
cat "$LOG_DIR/stow-status.log"

STATE_DB="$WORK_DIR/stow-cache/state-v3.sqlite3"
[ -f "$STATE_DB" ] || die "stow state DB missing at $STATE_DB"
hits="$(sqlite3 "$STATE_DB" "SELECT COALESCE(SUM(hits),0) FROM crate_stats WHERE crate_name='$TASK_CRATE'")"
errors="$(sqlite3 "$STATE_DB" "SELECT COALESCE(SUM(errors),0) FROM crate_stats WHERE crate_name='$TASK_CRATE'")"
echo "[mock-e2e] $TASK_CRATE cache stats: hits=$hits errors=$errors"
[ "$hits" -ge 1 ] || die "$TASK_CRATE was not served from the cache (hits=$hits)"
[ "$errors" -eq 0 ] || die "$TASK_CRATE fetch recorded $errors errors"

# --- byte path: bundles served by digest, Workers Cache in front of GHCR ---
#
# `stow check` already fetched itoa's bundle through
# GET /api/v1/bundles/{digest}; the assertions below pin the route's
# contract directly. The index layer blob lives in the same registry
# repository but the CLI pulled it straight from the registry, so the
# edge has never served it. The route's whole caching contract is the
# immutable Cache-Control it emits — Workers Cache, enabled only on the
# deployed manifest, replays repeat reads without the worker running —
# so the e2e asserts the header rather than a hit/miss, which local dev
# has no platform cache to produce. A digest the registry does not hold
# is a 404, a malformed digest is a 400 before any fetch, and the
# retired /api/v1/artifacts/… path is gone.
INDEX_SLICE="$WORK_DIR/index-export/index.${HOST_TARGET}.${RUSTC_VERSION}"
[ -f "$INDEX_SLICE" ] || die "exported index slice missing: $INDEX_SLICE"
INDEX_DIGEST="sha256:$(sha256sum "$INDEX_SLICE" | awk '{print $1}')"
[ -f "$WORK_DIR/mock-registry/blobs/${INDEX_DIGEST/:/_}" ] \
    || die "index blob not in the mock registry: $INDEX_DIGEST"

headers="$(curl -fsS -D - -o "$WORK_DIR/bundle.bin" \
    "$EDGE_URL/api/v1/bundles/$INDEX_DIGEST")"
grep -qi '^cache-control: *public, max-age=31536000, immutable' <<<"$headers" \
    || die "digest fetch did not emit the immutable cache contract: $headers"
cmp -s "$WORK_DIR/bundle.bin" "$INDEX_SLICE" \
    || die "digest fetch served bytes other than the blob"
echo "[mock-e2e] digest fetch: bytes plus immutable cache contract (expected)"

code="$(curl -s -o /dev/null -w '%{http_code}' \
    "$EDGE_URL/api/v1/bundles/sha256:0000000000000000000000000000000000000000000000000000000000000000")"
[ "$code" = "404" ] || die "unknown bundle digest returned $code, expected 404"
code="$(curl -s -o /dev/null -w '%{http_code}' "$EDGE_URL/api/v1/bundles/sha256:nothex")"
[ "$code" = "400" ] || die "malformed bundle digest returned $code, expected 400"
code="$(curl -s -o /dev/null -w '%{http_code}' \
    "$EDGE_URL/api/v1/artifacts/$HOST_TARGET/$RUSTC_VERSION/0000000000000000")"
[ "$code" = "404" ] || die "retired artifacts route returned $code, expected 404"
echo "[mock-e2e] digest byte path: 404 miss, 400 malformed, old route gone (expected)"

# The hit already proved the new path end-to-end: local index resolution
# plus a direct signed bundle pull. What remains on the edge is
# POST /api/v1/admissions. A graph the catalog
# covers mints nothing; one it does not cover mints a stateless
# admission carrying a PoW challenge. itoa is covered — the scheduler
# just built it — so its expanded graph must return empty. `entries`
# carries the manifest's seed features (`["default"]`);
# `expanded_entries` carries the resolved feature set, which for
# itoa 1.0 is empty — its `default` feature declares nothing.
admissions="$(curl -fsS --max-time 30 -X POST "$EDGE_URL/api/v1/admissions" \
    -H 'content-type: application/json' \
    --data "$(jq -nc \
        --arg crate "$TASK_CRATE" \
        --arg version "$TASK_VERSION" \
        --arg target "$HOST_TARGET" \
        --arg rustc "$RUSTC_VERSION" \
        '{
            target: $target,
            rustc_version: $rustc,
            entries: [{crate_name: $crate, version: $version, features: ["default"]}],
            expanded_entries: [{
                crate_name: $crate,
                version: $version,
                features: [],
                dependencies: []
            }]
        }')")"
[ "$(jq -r 'length' <<<"$admissions")" = "0" ] \
    || die "covered graph minted admissions: $admissions"
echo "[mock-e2e] covered graph: 0 admissions (expected)"

# A real crate absent from the catalog must mint exactly one admission —
# proves the coverage check + dominator + HMAC mint path live.
admissions="$(curl -fsS --max-time 30 -X POST "$EDGE_URL/api/v1/admissions" \
    -H 'content-type: application/json' \
    --data "$(jq -nc \
        --arg target "$HOST_TARGET" \
        --arg rustc "$RUSTC_VERSION" \
        '{
            target: $target,
            rustc_version: $rustc,
            entries: [{crate_name: "libc", version: "0.2.177", features: ["default"]}],
            expanded_entries: [{
                crate_name: "libc",
                version: "0.2.177",
                features: ["default"],
                dependencies: []
            }]
        }')")"
[ "$(jq -r 'length' <<<"$admissions")" = "1" ] \
    || die "uncovered graph minted $(jq -r 'length' <<<"$admissions") admissions: $admissions"
jq -e '.[0].challenge | length > 0' <<<"$admissions" >/dev/null \
    || die "admission carries no PoW challenge: $admissions"
jq -e '.[0].request.crate_name == "libc"' <<<"$admissions" >/dev/null \
    || die "admission request does not echo the miss: $admissions"
echo "[mock-e2e] uncovered graph: 1 admission with PoW challenge (expected)"

echo "[mock-e2e] OK — $TASK_CRATE $TASK_VERSION served from the mock cache via the local index"\n
