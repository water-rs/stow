#!/usr/bin/env bash
# Traffic cost (stow#772): does launch user traffic fit the Cloudflare
# allowance without overloading the scheduler? One mock stack answers it
# end to end:
#
#   1. the scheduler budget pass at two fixture sizes (100k and 1M queue
#      rows, same shape) — every drive's statements, rowsRead and
#      rowsWritten against DO_BUDGETS, measured under workerd's billed
#      cursor counters; the 1M-row population pass is followed by a
#      restart of the edge over the persisted store and a status read
#      that wakes the scheduler, with V8's collections traced into the
#      edge log (`stow-admin traffic-cost restart`): the JavaScript heap
#      in use stays within 24 MiB of the empty scheduler's through the
#      population pass, its snapshot write and the wake, and the wake's
#      Wasm linear memory exceeds the graph storage it accounts for by
#      no more than 10 MiB;
#   2. Worker CPU per traffic lane, sampled by the isolate's V8 profiler
#      through workerd's DevTools inspector and divided by a fixed
#      reference workload profiled in the same isolate before and after
#      the lanes, so the runner's speed cancels, against
#      WORKER_CPU_BUDGETS (`stow-admin traffic-cost cpu`);
#   3. the peak-concurrency drive: every lane at the launch model's peak
#      rate for 30 minutes (`stow-admin traffic-cost peak`);
#   4. the budget pass again on the loaded fixture;
#   5. the verdict (`stow-admin traffic-cost verdict`): row budgets, rows
#      that grow with the stored bulk (more than 10% + 50 rows from the
#      small fixture to the large), and the peak serialized Durable
#      Object wall.
#
# The test fails on any of: a restart past the memory bounds above, a
# drive over its row budget, a drive that
# grows with stored rows, a lane over its CPU budget relative to the
# reference workload, an unusable reference, peak serialized DO
# wall above 0.5 s/s, any `overloaded` signal or 5xx under the peak
# drive, a lane error share over 1%, a response outside a lane's
# designed statuses, or a lane p99 over 10 s.
#
# The monthly projection against 80% of each product's allowance is not
# here: it adds the preheat waves and daily resubmits the Preheat cost
# job measures, so the release gate's `Monthly projection` job runs it
# (`stow-admin traffic-cost project`) over this run's budget-small.json,
# budget-after.json and worker-cpu.json in $WORK_DIR/reports and that
# job's preheat-cost-report.json.
#
# Every service is local: the mock GHCR (`stow-mock-registry`, the
# edge's GHCR_BASE_URL and the stats SQL endpoint), the edge under
# the native workerd test runtime, and `stow-build serve` under
# STOW_LOCAL_CI_STUB (the edge's STOW_LOCAL_CI_URL — the dispatch POST
# and the signed `workflow_run` callback are real, the cargo build
# behind them is not). Each pass's dispatches complete asynchronously
# through that stub, so the script waits until the stub reports no build
# run in progress — every callback answered — before the next step
# measures anything, and stops the services in reverse start order, so
# no callback ever meets a registry that is already gone.
#
# Tunables (env):
#   STOW_TRAFFIC_WORK_DIR       work dir instead of a fresh mktemp
#   STOW_E2E_TOOLCHAIN          rustup toolchain (default: stable)
#   STOW_E2E_READY_DEADLINE     seconds to wait for the edge (default 600)
#   STOW_TRAFFIC_SIZES          the two fixture sizes, small then large
#                               (default "100000 480000"); the CPU pass,
#                               the peak drive and the post-load pass run
#                               on the small one
#   STOW_TRAFFIC_DURATION_SECS  seconds of peak drive (default 1800)
#   STOW_TRAFFIC_SEGMENTS       drive segments; the edge restarts between
#                               them (default 4 — see the note above the
#                               edge lifecycle)
#   STOW_TRAFFIC_BUILD_CALLBACK_EPS  optional absolute build delivery rate
#   STOW_TRAFFIC_RATE_SCALE     multiplier over the model's peak rates
#                               (default 1.0)
#   STOW_TRAFFIC_MAX_JOBS       override both probe and mock dispatch caps
#   STOW_TRAFFIC_MAX_MACOS_JOBS override the mock macOS dispatch cap
#   STOW_TRAFFIC_RUSTC          rustc the lanes request and the index
#                               slice publishes under (default 1.85.0)
#   STOW_TRAFFIC_EDGE_PORT      port the test runtime binds (default 8788)
#   STOW_TRAFFIC_INSPECTOR_PORT port the workerd inspector binds (default 9230)
#   STOW_TRAFFIC_REGISTRY_PORT  port `stow-mock-registry serve` binds
#                               (default 28123)
#   STOW_TRAFFIC_LOCAL_CI_PORT  port `stow-build serve` binds (default 28124)
set -euo pipefail
set -m

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EDGE_PORT="${STOW_TRAFFIC_EDGE_PORT:-8788}"
INSPECTOR_PORT="${STOW_TRAFFIC_INSPECTOR_PORT:-9230}"
REGISTRY_ADDR="127.0.0.1:${STOW_TRAFFIC_REGISTRY_PORT:-28123}"
LOCAL_CI_ADDR="127.0.0.1:${STOW_TRAFFIC_LOCAL_CI_PORT:-28124}"
EDGE_URL="http://127.0.0.1:${EDGE_PORT}"
SCHEDULER_URL="${EDGE_URL}/api/v1/scheduler"
INSPECTOR_URL=
READY_DEADLINE="${STOW_E2E_READY_DEADLINE:-600}"
SIZES="${STOW_TRAFFIC_SIZES:-100000 480000}"
DURATION_SECS="${STOW_TRAFFIC_DURATION_SECS:-1800}"
SEGMENTS="${STOW_TRAFFIC_SEGMENTS:-4}"
RATE_SCALE="${STOW_TRAFFIC_RATE_SCALE:-1.0}"
PEAK_RATE_ARGS=()
if [ -n "${STOW_TRAFFIC_BUILD_CALLBACK_EPS:-}" ]; then
    PEAK_RATE_ARGS+=(--build-callback-eps "$STOW_TRAFFIC_BUILD_CALLBACK_EPS")
fi
RUSTC_VERSION="${STOW_TRAFFIC_RUSTC:-1.85.0}"
# A bundle the size of production's average fetch (stow#738: 1.4 MB
# per bundle) — the CPU pass streams it through the byte path.
BUNDLE_BYTES=1468006
# How long one pass's dispatch callbacks may take to drain.
DRAIN_DEADLINE=300

# One source for every value the mock deploy pins: the secrets the lanes
# sign and mint under, and the production dispatch cap the probe claims
# against (the mock deploy pins 3, below the fixture's 30 in-flight
# rows, which would price a pass that claims nothing).
manifest_var() {
    local value
    value="$(sed -n "s/^$2 *= *\"\([^\"]*\)\".*/\1/p" "$REPO_ROOT/edge/$1")"
    [ -n "$value" ] || { echo "[traffic] ERROR: $2 not found in edge/$1" >&2; exit 1; }
    echo "$value"
}
DISPATCH_LIMIT="${STOW_TRAFFIC_MAX_JOBS:-$(manifest_var Skyzen.toml STOW_MAX_CONCURRENT_JOBS)}"
MOCK_MAX_JOBS="${STOW_TRAFFIC_MAX_JOBS:-$(manifest_var Skyzen.mock.toml STOW_MAX_CONCURRENT_JOBS)}"
MOCK_CAP_ARGS=(--var "STOW_MAX_CONCURRENT_JOBS:$MOCK_MAX_JOBS")
if [ -n "${STOW_TRAFFIC_MAX_MACOS_JOBS:-}" ]; then
    MOCK_CAP_ARGS+=(--var "STOW_MAX_CONCURRENT_MACOS_JOBS:$STOW_TRAFFIC_MAX_MACOS_JOBS")
fi
WEBHOOK_SECRET="$(manifest_var Skyzen.mock.toml STOW_GITHUB_WEBHOOK_SECRET)"
APP_SLUG="$(manifest_var Skyzen.mock.toml GITHUB_APP_SLUG)"
POW_SECRET="$(manifest_var Skyzen.mock.toml STOW_POW_CHALLENGE_SECRET)"

export RUSTUP_TOOLCHAIN="${STOW_E2E_TOOLCHAIN:-stable}"

if [ -n "${STOW_TRAFFIC_WORK_DIR:-}" ]; then
    WORK_DIR="$STOW_TRAFFIC_WORK_DIR"
    mkdir -p "$WORK_DIR"
    # Later steps run from other directories; pin a relative value.
    WORK_DIR="$(cd "$WORK_DIR" && pwd)"
else
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stow-traffic.XXXXXX")"
fi
LOG_DIR="$WORK_DIR/logs"
REPORT_DIR="$WORK_DIR/reports"
mkdir -p "$LOG_DIR" "$REPORT_DIR" "$WORK_DIR/edge-state"

# Started services, in start order. Teardown walks them in reverse.
CHILD_PIDS=()
CHILD_NAMES=()

die() {
    echo "[traffic] ERROR: $*" >&2
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

# Stop one service and everything it started, then wait for it.
stop_tree() {
    local pid="$1" kids deadline
    kids="$(descendants "$pid")"
    kill -- "-$pid" 2>/dev/null || true
    # shellcheck disable=SC2086 # PIDs are plain words; splitting is intended
    kill "$pid" $kids 2>/dev/null || true
    deadline=$((SECONDS + 15))
    while [ "$SECONDS" -lt "$deadline" ] && kill -0 "$pid" 2>/dev/null; do
        sleep 1
    done
    # shellcheck disable=SC2086
    kill -9 -- "-$pid" "$pid" $kids 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    [ -n "${MOCK_MANIFEST:-}" ] && rm -f "$MOCK_MANIFEST"
    local i pid
    # The command `fg` is currently waiting on (or a substitution's
    # subshell) is a direct child too — stop it with the services so a
    # trap that fires mid-command tears down what it interrupted.
    for pid in $(pgrep -P $$ 2>/dev/null) ${FG_PID:-}; do
        stop_tree "$pid"
    done
    for ((i = ${#CHILD_PIDS[@]} - 1; i >= 0; i--)); do
        stop_tree "${CHILD_PIDS[$i]}"
    done
    # Keep population and Wasm-memory boundaries with successful reports too.
    # All writers have stopped, so the retained log includes the final sample.
    if [ -f "$LOG_DIR/edge.log" ]; then
        cp "$LOG_DIR/edge.log" "$REPORT_DIR/edge.log" || status=1
    fi
    if [ "$status" -ne 0 ]; then
        local dump="$WORK_DIR/cleanup-dump.txt" log
        echo "[traffic] FAILED (exit $status) — log tails:" >"$dump"
        for log in "$LOG_DIR"/*.log; do
            [ -e "$log" ] || continue
            echo "===== $log =====" >>"$dump"
            tail -n 80 "$log" >>"$dump" 2>/dev/null || true
        done
        cat "$dump" >&2
    fi
    echo "[traffic] logs: $LOG_DIR"
    echo "[traffic] reports: $REPORT_DIR"
    exit "$status"
}
trap cleanup EXIT INT TERM

# Process-group leader of the long command the script is waiting on.
# Bash defers a trapped signal until the current foreground child
# returns, so a TERM landing during a minutes-long build or the peak
# drive would never run the trap before the follow-up KILL. `fg` runs
# such commands as a background job and `wait`s on them — `wait` is
# interruptible, so the trap fires at once while the child is still
# alive for cleanup to kill (each `&` job is its own process group
# under `set -m`).
FG_PID=
fg() {
    "$@" &
    FG_PID=$!
    wait "$FG_PID"
}

# `fg` takes one command; a step that must run in another directory cds
# inside the job subshell first.
in_dir() {
    local dir="$1"
    shift
    ( cd "$dir" && "$@" )
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found on PATH: $1"
}

wait_for() {
    local desc="$1" timeout="$2" owner_pid="$3"
    shift 3
    local deadline=$((SECONDS + timeout))
    while :; do
        local i
        for i in "${!CHILD_PIDS[@]}"; do
            kill -0 "${CHILD_PIDS[$i]}" 2>/dev/null || die "${CHILD_NAMES[$i]} exited unexpectedly"
        done
        if [ -n "$owner_pid" ] && ! kill -0 "$owner_pid" 2>/dev/null; then
            die "$desc: owning process $owner_pid exited before becoming ready"
        fi
        if "$@" >/dev/null 2>&1; then
            echo "[traffic] $desc: ready"
            return 0
        fi
        [ "$SECONDS" -ge "$deadline" ] && die "timeout after ${timeout}s waiting for $desc"
        sleep 2
    done
}

http_listening() {
    curl -s -o /dev/null --max-time 5 "$1"
}

# True when the local CI stub reports no build run in progress: the stub
# marks a run completed only after the edge answered its `workflow_run`
# callback, so nothing a previous step dispatched is still landing.
builds_drained() {
    curl -sf --max-time 5 "http://${LOCAL_CI_ADDR}/tasks" | jq -e '
        [.tasks[] | select(.path == ".github/workflows/build-crate.yml")
                  | select(.status != "completed")] | length == 0' >/dev/null
}

drain_builds() {
    wait_for "dispatch callbacks drained ($1)" "$DRAIN_DEADLINE" "" builds_drained
}

# stow#955: every trusted call — reads, the budget probe, the lanes'
# queue mutations and submits — carries an operations.yml token signed
# by the mock issuer; one token serves a whole lane, so it outlives the
# longest (the 30-minute peak).
admin() {
    env STOW_EDGE_URL="$EDGE_URL" \
        GH_TOKEN="$("$BIN/stow-mock-registry" oidc-token --workflow operations.yml \
            --lifetime-secs 7200)" \
        "$BIN/stow-admin" "$@"
}

require_command cargo
require_command rustup
require_command curl
require_command jq
require_command openssl
require_command skyzen
require_command bun

read -r -a size_list <<<"$SIZES"
[ "${#size_list[@]}" -eq 2 ] || die "STOW_TRAFFIC_SIZES must name exactly two sizes"
SMALL="${size_list[0]}"
LARGE="${size_list[1]}"
[ "$SMALL" -lt "$LARGE" ] || die "STOW_TRAFFIC_SIZES must be ordered small then large"
SEG_SECS=$((DURATION_SECS / SEGMENTS))
[ "$SEG_SECS" -ge 60 ] || die "STOW_TRAFFIC_DURATION_SECS=$DURATION_SECS too small for $SEGMENTS segments"

echo "[traffic] work dir: $WORK_DIR"
echo "[traffic] dispatch caps: probe=$DISPATCH_LIMIT mock=$MOCK_MAX_JOBS macos=${STOW_TRAFFIC_MAX_MACOS_JOBS:-default}"

if ! rustup target list --installed --toolchain "$RUSTUP_TOOLCHAIN" \
    | grep -qx wasm32-unknown-unknown; then
    echo "[traffic] installing wasm32-unknown-unknown for $RUSTUP_TOOLCHAIN"
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" wasm32-unknown-unknown
fi

cd "$REPO_ROOT"
source "$REPO_ROOT/scripts/gate-tools.sh"
gate_tools production "$LOG_DIR/cargo-build.log" fg \
    || die "gate tools unavailable — see $LOG_DIR/cargo-build.log"

# P-256 PKCS#8 key pair — the format sigstore accepts (the same block
# scripts/mock-e2e.sh runs; docs/MOCK.md).
mkdir -p "$WORK_DIR/keys"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK_DIR/keys/private.pem"
openssl pkcs8 -topk8 -nocrypt -in "$WORK_DIR/keys/private.pem" -out "$WORK_DIR/keys/private.pkcs8.pem"
mv "$WORK_DIR/keys/private.pkcs8.pem" "$WORK_DIR/keys/private.pem"
openssl ec -in "$WORK_DIR/keys/private.pem" -pubout -out "$WORK_DIR/keys/public.pem"

for port in "$EDGE_PORT" "$INSPECTOR_PORT" "${REGISTRY_ADDR##*:}" "${LOCAL_CI_ADDR##*:}"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        die "port $port is already in use — refusing to measure a foreign service"
    fi
done

# The mock GHCR: bundles, index slices, records artifacts and the stats
# SQL endpoint all resolve here, so no lane leaves the machine for them.
mkdir -p "$WORK_DIR/mock-registry"
"$BIN/stow-mock-registry" serve --registry-root "$WORK_DIR/mock-registry" \
    --listen "$REGISTRY_ADDR" >"$LOG_DIR/mock-registry.log" 2>&1 &
CHILD_PIDS+=($!)
CHILD_NAMES+=(mock-registry)
echo "[traffic] started mock registry (pid $!), log: $LOG_DIR/mock-registry.log"
wait_for "mock registry listener" "$READY_DEADLINE" "$!" \
    http_listening "http://$REGISTRY_ADDR/v2/"

# The covered bundle the CPU pass streams, and one signed index slice at
# the (target, rustc) the index-pull lane requests that names it —
# without a slice the pointer GET 404s and the lane fires only the first
# of the two requests the launch model prices per pull.
BUNDLE_DIGEST="$("$BIN/stow-mock-registry" put-blob --size "$BUNDLE_BYTES" \
    --registry-root "$WORK_DIR/mock-registry" | jq -r .digest)"
jq --arg rustc "$RUSTC_VERSION" --arg digest "$BUNDLE_DIGEST" --argjson size "$BUNDLE_BYTES" '
    map(.rustc_version = $rustc
        | .oci_reference = "ghcr.io/water-rs/stow-cache-v2-\($rustc):serde.1.0.219-x86_64-unknown-linux-gnu"
        | .bundle_digest = $digest
        | .bundle_size = $size)
    | {artifacts: ., local_programs: []}
' "$REPO_ROOT/scripts/traffic-cost/index-records.json" >"$WORK_DIR/index-records.json"
"$BIN/stow-mock-registry" index-from-records \
    --records "$WORK_DIR/index-records.json" \
    --registry-root "$WORK_DIR/mock-registry" \
    --private-key "$WORK_DIR/keys/private.pem" \
    >>"$LOG_DIR/mock-registry-cli.log" 2>&1 \
    || die "index-from-records failed — see $LOG_DIR/mock-registry-cli.log"
echo "[traffic] published bundle $BUNDLE_DIGEST and its index slice (x86_64-unknown-linux-gnu / $RUSTC_VERSION)"

# The mock manifest's loopback URLs (the registry and the local-CI
# dispatcher) bake into the edge bundle at `skyzen build` time, so a
# shifted port set needs a manifest rendered for it: a copy of
# Skyzen.mock.toml with the two port strings rewritten, living only
# for the build.
MOCK_MANIFEST="$REPO_ROOT/edge/Skyzen.mock.traffic-$$.toml"
sed -e "s/127\.0\.0\.1:28123/127.0.0.1:${REGISTRY_ADDR##*:}/g" \
    -e "s/127\.0\.0\.1:28124/127.0.0.1:${LOCAL_CI_ADDR##*:}/g" \
    "$REPO_ROOT/edge/Skyzen.mock.toml" >"$MOCK_MANIFEST"
fg in_dir "$REPO_ROOT/edge" \
    skyzen build --release --provider cloudflare --manifest "$(basename "$MOCK_MANIFEST")" \
    >"$LOG_DIR/edge-build.log" 2>&1 \
    || die "skyzen build failed — see $LOG_DIR/edge-build.log"
rm -f "$MOCK_MANIFEST"
fg in_dir "$REPO_ROOT/edge/tests/idle" bun install --frozen-lockfile \
    >"$LOG_DIR/native-runtime-install.log" 2>&1 \
    || die "native runtime install failed — see $LOG_DIR/native-runtime-install.log"

# Run the built artifact and generated bindings through Wrangler's native
# Miniflare configuration adapter. The outbound service supplies pinned
# external responses and forwards only to the local CI/registry. Retain
# the existing segments and durable state across their restarts.
EDGE_IDX=-1
EDGE_PID=
INSPECTOR_URL_FILE="$WORK_DIR/edge-runtime-ready.json"

start_edge() {
    rm -f "$INSPECTOR_URL_FILE"
    (
        cd "$REPO_ROOT/edge"
        # workerd takes V8 flags from this variable: every collection
        # is traced into the edge log, where `traffic-cost restart`
        # reads the JavaScript heap in use before each one.
        exec env MINIFLARE_WORKERD_V8_FLAGS=--trace-gc \
            bun tests/idle/cpu-runtime.mjs --config .skyzen/gen/wrangler.toml \
            "${MOCK_CAP_ARGS[@]}" \
            --port "$EDGE_PORT" --inspector-port "$INSPECTOR_PORT" \
            --ready-file "$INSPECTOR_URL_FILE" \
            --persist-to "$WORK_DIR/edge-state"
    ) >>"$LOG_DIR/edge.log" 2>&1 &
    EDGE_PID=$!
    if [ "$EDGE_IDX" -lt 0 ]; then
        EDGE_IDX=${#CHILD_PIDS[@]}
        CHILD_PIDS+=("$EDGE_PID")
        CHILD_NAMES+=(edge)
    else
        CHILD_PIDS[EDGE_IDX]=$EDGE_PID
    fi
    echo "[traffic] started edge (pid $EDGE_PID), log: $LOG_DIR/edge.log"
    wait_for "edge listener" "$READY_DEADLINE" "$EDGE_PID" \
        http_listening "$SCHEDULER_URL/status"
    wait_for "edge inspector target" "$READY_DEADLINE" "$EDGE_PID" \
        test -s "$INSPECTOR_URL_FILE"
    INSPECTOR_URL="$(jq -er '.inspector' "$INSPECTOR_URL_FILE")"
}

# Resident set size of the edge process tree, logged at segment
# boundaries — the evidence the dev-runtime retainer stays bounded.
edge_rss_kb() {
    local pid rss total=0
    for pid in $(descendants "$EDGE_PID"); do
        rss="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')"
        [ -n "$rss" ] && total=$((total + rss))
    done
    echo "$total"
}

# Bytes the edge log holds now — the offsets `traffic-cost restart` cuts
# its windows at.
edge_log_bytes() {
    wc -c <"$LOG_DIR/edge.log" | tr -d ' '
}

start_edge

# The local dispatch endpoint the edge's STOW_LOCAL_CI_URL points at.
mkdir -p "$WORK_DIR/local-ci"
(
    cd "$WORK_DIR/local-ci"
    exec env \
        STOW_EDGE_URL="$EDGE_URL" \
        STOW_GITHUB_WEBHOOK_SECRET="$WEBHOOK_SECRET" \
        GITHUB_APP_SLUG="$APP_SLUG" \
        STOW_MOCK_PUBLIC_KEY_PATH="$WORK_DIR/keys/public.pem" \
        STOW_MOCK_PRIVATE_KEY_PATH="$WORK_DIR/keys/private.pem" \
        STOW_MOCK_REGISTRY_ROOT="$WORK_DIR/mock-registry" \
        STOW_LOCAL_CI_STUB=1 \
        "$BIN/stow-build" serve --listen "$LOCAL_CI_ADDR"
) >"$LOG_DIR/local-ci.log" 2>&1 &
CHILD_PIDS+=($!)
CHILD_NAMES+=(local-ci)
echo "[traffic] started local-ci stub (pid $!), log: $LOG_DIR/local-ci.log"
wait_for "local CI dispatch endpoint" 60 "$!" \
    http_listening "http://${LOCAL_CI_ADDR}/tasks"

# Same deploy order as deploy-edge.yml: the operator reset runs before
# the scheduler takes traffic.
fg admin scheduler reset --yes >"$WORK_DIR/scheduler-reset.log" 2>&1 \
    || die "stow-admin scheduler reset failed — see $WORK_DIR/scheduler-reset.log"
echo "[traffic] $(cat "$WORK_DIR/scheduler-reset.log")"
# Everything the edge logged up to here is the empty scheduler's: the
# baseline the population's JavaScript heap peak is judged against.
EMPTY_LOG_BYTES="$(edge_log_bytes)"

# One budget pass: $1 is the label, the rest the `scheduler budget`
# arguments. `--json` keeps the per-statement detail; the command exits
# non-zero when any drive is over its row budget.
budget_pass() {
    local label="$1"
    shift
    echo "[traffic] budget pass: $label"
    fg admin --json scheduler budget --dispatch-limit "$DISPATCH_LIMIT" "$@" \
        >"$REPORT_DIR/budget-$label.json" 2>"$LOG_DIR/budget-$label.log" \
        || { cat "$LOG_DIR/budget-$label.log" >&2; \
             die "budget pass $label over budget — see $REPORT_DIR/budget-$label.json"; }
    jq -r --arg label "$label" '
        "scheduler budget \($label) (queue rows \(.queue_rows)):",
        (.rows[] | "  \(.name | . + " " * (48 - length)) stmts=\(.statements)/\(.statement_budget) rows_read=\(.rows_read)/\(.read_budget) rows_written=\(.rows_written)/\(.write_budget) wall_ms=\(.wall_ms)\(if .over_budget then " OVER" else "" end)")
    ' "$REPORT_DIR/budget-$label.json"
    drain_builds "$label"
    # Observe retained memory before the next pass replaces this population.
    # These native counters do not establish transient peaks or billed memory.
    fg admin --json traffic-cost memory --inspector-url "$INSPECTOR_URL" \
        >"$REPORT_DIR/memory-$label.json" 2>"$LOG_DIR/memory-$label.log" \
        || die "memory observation $label failed — see $LOG_DIR/memory-$label.log"
}

# The large fixture first, so the CPU pass and the peak drive run on the
# small one the last reseed leaves.
# One million fixture rows start with 600k pending nodes, covering the
# 572,283 pending tasks observed in incident #1233. Keep both existing
# scale-comparison cases and their budgets unchanged.
budget_pass "population" --queue-rows 1000000

# Restart the edge over the persisted population and wake the scheduler
# with a status read: the wake logs the graph's occupancy and the Wasm
# linear memory. `traffic-cost restart` judges the traced JavaScript
# heap through the population pass, its snapshot write and the wake
# against the empty scheduler's, and the wake's linear memory against
# the graph storage it accounts for (stow#1380).
echo "[traffic] restart over the persisted population"
RESTART_LOG_BYTES="$(edge_log_bytes)"
stop_tree "$EDGE_PID"
start_edge
curl -sf --max-time "$READY_DEADLINE" "$SCHEDULER_URL/status" >/dev/null \
    || die "scheduler status read after the restart failed — see $LOG_DIR/edge.log"
fg admin --json traffic-cost restart --edge-log "$LOG_DIR/edge.log" \
    --empty-bytes "$EMPTY_LOG_BYTES" --restart-bytes "$RESTART_LOG_BYTES" \
    >"$REPORT_DIR/restart-memory.json" 2>"$LOG_DIR/restart-memory.log" \
    || { cat "$LOG_DIR/restart-memory.log" >&2; \
         die "restart memory over its bounds — see $REPORT_DIR/restart-memory.json"; }
jq -r '"restart memory: JS heap in use peak \(.run_heap_peak_mib) MiB (empty scheduler \(.empty_heap_peak_mib) MiB, bound +\(.heap_bound_mib) MiB); wasm linear \(.wake.wasm_linear_bytes) B vs accounted \(.wake.accounted_storage_bytes) B (bound +\(.linear_bound_bytes) B)"' \
    "$REPORT_DIR/restart-memory.json"

budget_pass "large" --queue-rows "$LARGE"
budget_pass "small" --queue-rows "$SMALL"

# The callback lane reports the fixture's in-flight tasks `completed`:
# each in-flight row is its own one-task run, bound to a `build-crate.yml`
# run this local CI never dispatched. In production the run's jobs page
# and the task's records artifact exist before the `completed` delivery
# does, and the alarm resolves the task from both — without them every
# completion would defer against a 404 jobs page until its ceiling. So
# the local CI records each bound run as a finished success and publishes
# the task's records artifact under the run's per-build tag
# `records-<rustc>-<hash>-<run id>-1`, at the task's own rustc.
# `traffic-cost fixture-runs` owns the shape math.
fg admin --json traffic-cost fixture-runs --queue-rows "$SMALL" \
    >"$WORK_DIR/fixture-runs.json" 2>"$LOG_DIR/fixture-runs.log" \
    || die "traffic-cost fixture-runs failed — see $LOG_DIR/fixture-runs.log"
curl -sf --max-time 60 -X POST -H 'Content-Type: application/json' \
    --data-binary @"$WORK_DIR/fixture-runs.json" \
    "http://${LOCAL_CI_ADDR}/seeded-runs" >>"$LOG_DIR/fixture-runs.log" \
    || die "local CI refused the fixture's runs — see $LOG_DIR/local-ci.log"
echo "[traffic] recorded $(jq '.runs | length' "$WORK_DIR/fixture-runs.json") in-flight fixture task runs and their records artifacts"

INDEX_PUBLISH_TOKEN_FILE="$WORK_DIR/index-publish-token"
(umask 077; "$BIN/stow-mock-registry" oidc-token --workflow index-publish.yml \
    --lifetime-secs 7200 > "$INDEX_PUBLISH_TOKEN_FILE")
RESOLVE_TOKEN_FILE="$WORK_DIR/resolve-token"
(umask 077; "$BIN/stow-mock-registry" oidc-token --workflow resolve-request.yml \
    --lifetime-secs 7200 > "$RESOLVE_TOKEN_FILE")

PREHEAT_CRON="$(bun -e 'console.log(Bun.TOML.parse(await Bun.file(process.argv[1]).text()).cloudflare.vars.STOW_PERIODIC_WORKFLOWS)' \
    "$REPO_ROOT/edge/Skyzen.mock.toml" | jq -er '
    to_entries | map(select(any(.value[]; . == "preheat-cron.yml")))
    | if length == 1 then .[0].key else error("expected one preheat cron") end')"
LANE_ARGS=(
    --newreleases-secret "$(manifest_var Skyzen.mock.toml STOW_NEWRELEASES_WEBHOOK_SECRET)"
    --preheat-cron "$PREHEAT_CRON"
    --resolve-token-file "$RESOLVE_TOKEN_FILE"
    --index-publish-token-file "$INDEX_PUBLISH_TOKEN_FILE"
    --index-publish-rustc "$(rustc --version | awk '{print $2}')"
    --model "$REPO_ROOT/launch-model.toml"
    --queue-rows "$SMALL"
    --rustc "$RUSTC_VERSION"
    --bundle-digest "$BUNDLE_DIGEST"
    --scheduler
    --webhook-secret "$WEBHOOK_SECRET"
    --pow-secret "$POW_SECRET"
)

echo "[traffic] Worker CPU per lane"
CPU_FAILED=0
fg admin --json traffic-cost cpu "${LANE_ARGS[@]}" \
    --inspector-url "$INSPECTOR_URL" \
    >"$REPORT_DIR/worker-cpu.json" 2>"$LOG_DIR/worker-cpu.log" \
    || {
        cat "$LOG_DIR/worker-cpu.log" >&2
        # A completed measurement can breach its budget without making
        # the independent peak and post-load measurements unusable.
        # Inspector, reference and transport errors produce no report.
        jq -e 'any(.rows[]; .over_budget)' "$REPORT_DIR/worker-cpu.json" >/dev/null \
            || die "Worker CPU measurement failed — see $LOG_DIR/worker-cpu.log"
        CPU_FAILED=1
        echo "[traffic] Worker CPU budget failed; collecting peak and post-load evidence before failing" >&2
    }
jq -r '"Worker CPU per event (idle window \(.idle_window_ms) ms collected \(.idle_cpu_ms) ms):",
       "  reference workload \(.reference.cpu_ms * 100 | round / 100) ms (before \(.reference.rounds_before | map(.sampled_cpu_ms / .invocations * 100 | round / 100)), after \(.reference.rounds_after | map(.sampled_cpu_ms / .invocations * 100 | round / 100)))",
       (.rows[] | "  \(.lane | . + " " * (20 - length)) \(.cpu_ms * 100 | round / 100) ms = \(.relative_cpu * 10000 | round / 10000) × reference (budget \(.budget_relative_cpu)) rounds \(.rounds_cpu_ms | map(. * 100 | round / 100))")' \
    "$REPORT_DIR/worker-cpu.json"
drain_builds "cpu"

echo "[traffic] peak drive: ${DURATION_SECS}s at rate scale $RATE_SCALE in $SEGMENTS segments"
for ((seg = 1; seg <= SEGMENTS; seg++)); do
    seg_secs=$SEG_SECS
    [ "$seg" -eq "$SEGMENTS" ] && seg_secs=$((DURATION_SECS - SEG_SECS * (SEGMENTS - 1)))
    if [ "$seg" -gt 1 ]; then
        echo "[traffic] edge tree rss before segment $seg restart: $(edge_rss_kb) KB"
        drain_builds "before edge restart $seg"
        stop_tree "$EDGE_PID"
        start_edge
    fi
    echo "[traffic] segment $seg/$SEGMENTS: ${seg_secs}s"
    fg admin --json traffic-cost peak "${LANE_ARGS[@]}" \
        --duration-secs "$seg_secs" \
        --inspector-url "$INSPECTOR_URL" \
        --cpu-out "$REPORT_DIR/peak-seg${seg}-cpu.json" \
        --rate-scale "$RATE_SCALE" "${PEAK_RATE_ARGS[@]}" \
        >"$REPORT_DIR/peak-seg${seg}.json" 2>"$LOG_DIR/peak-seg${seg}.log" \
        || { cat "$LOG_DIR/peak-seg${seg}.log" >&2; \
             die "peak drive segment $seg breached — see $REPORT_DIR/peak-seg${seg}.json"; }
    jq -r '.lanes | to_entries[] | "  \(.key | . + " " * (20 - length)) reqs=\(.value.requests) p50=\(.value.p50_ms | round)ms p99=\(.value.p99_ms | round)ms 5xx=\(.value.server_errors) overloaded=\(.value.overloaded)"' \
        "$REPORT_DIR/peak-seg${seg}.json"
done
echo "[traffic] edge tree rss after segment $SEGMENTS: $(edge_rss_kb) KB"
drain_builds "after the peak drive"

# The loaded fixture, measured again — no reseed.
budget_pass "after" --queue-rows "$SMALL"

fg admin traffic-cost verdict \
    --small "$REPORT_DIR/budget-small.json" \
    --large "$REPORT_DIR/budget-large.json" \
    --after "$REPORT_DIR/budget-after.json" \
    --model "$REPO_ROOT/launch-model.toml" \
    || die "traffic cost over its bounds — see the verdict above"

[ "$CPU_FAILED" -eq 0 ] \
    || die "Worker CPU budget failed — see $REPORT_DIR/worker-cpu.json; peak and post-load reports collected"

echo "[traffic] OK — within every budget and bound; reports for the projection: $REPORT_DIR"
