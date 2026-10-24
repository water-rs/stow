#!/usr/bin/env bash
# The stow#773 preheat cost test: drive a real preheat wave through the
# scheduler Durable Object on the mock stack and price it in the rows
# Cloudflare bills.
#
#   1. build stow-build (with the mock compiler), stow-mock-registry and
#      stow-admin; generate the mock cosign key pair
#   2. start stow-mock-registry (28123), the edge under `wrangler dev`
#      (workerd, 8790, budget-probe manifest at the production dispatch
#      caps and cost multiplier) and `stow-build serve` (28124); reset
#      the scheduler the way a deploy does
#   3. run the production preheat lanes against the mock edge, in the
#      order preheat-admin.yml runs them — `preheat top`, `preheat
#      top-binaries`, `preheat projects submit` over the reviewed
#      preheat/projects.toml — while the wave runs, as it does in
#      production: the scheduler dispatches what the lanes have already
#      submitted
#   4. drive the wave: every dispatch is a real `stow-build build` +
#      publish validation whose rustc invocations the mock compiler
#      answers with empty outputs, its records land in the mock registry
#      and its completion reaches the edge as a signed workflow_run
#      webhook; whenever nothing is in flight and new records exist, run
#      one publish round — index export → publish → report → sync, the
#      loop index-publish.yml drives — which releases the next layer.
#      The wave is over when the lanes are done and nothing is pending
#      or in flight
#   5. resubmit the same lists, as the daily preheat-cron does, and
#      drive whatever that releases
#   6. `stow-admin preheat cost report` reads the probe ledger snapshots
#      taken at every lane and round boundary, the local CI's runs and
#      the final published slices, writes
#      $WORK_DIR/preheat-cost-report.json and fails on any check: wave or
#      resubmit total over the preheat budget (types/src/do_budgets.rs),
#      per-event cost growing first → last layer past the stow#433
#      tolerance, a fixed-size event over its drive budget, a node
#      dispatched before its dependencies were published, a submitted
#      node never published, an `overloaded` answer, a failed submit, or
#      a resubmit that rebuilt anything
#
# The monthly projection (`stow-admin traffic-cost project`, the release
# gate's `Monthly projection` job) also needs the production wave's node
# count; `scripts/production-wave.sh` counts it in a job of its own.
#
# Why the compiler is the mocked seam: everything the scheduler's cost
# depends on — which tasks exist, their edges, when each completes, the
# records it publishes — comes from cargo's resolve and unit graph and
# the stages around rustc, which all run for real. Only the bytes rustc
# would produce are fake, and nothing in the scheduler reads them.
#
# All state lives under one work dir; every child is killed on exit by
# PID, never by pattern. The full-scale run (every lane at its
# production size, every CI target) is CI work: locally, reduce it with
# the tunables below.
#
# Tunables (env):
#   STOW_PREHEAT_COST_WORK_DIR     work dir instead of a fresh mktemp
#   STOW_PREHEAT_COST_LIMIT        --limit of `preheat top` and `preheat
#                                  top-binaries` (default 100 — the
#                                  production preheat-admin.yml value)
#   STOW_PREHEAT_COST_PROJECTS     submit only the first N repositories of
#                                  preheat/projects.toml (default: all)
#   STOW_PREHEAT_COST_TARGETS      comma-separated targets for every lane
#                                  (default: every CI_TARGET_TRIPLES entry)
#   STOW_PREHEAT_COST_MAX_JOBS     scheduler dispatch cap (default 45 —
#                                  edge/Skyzen.toml)
#   STOW_PREHEAT_COST_MAX_MACOS_JOBS
#                                  macOS-family dispatch cap (default 16 —
#                                  edge/Skyzen.toml)
#   STOW_PREHEAT_COST_DEADLINE     seconds each phase may take before the
#                                  run fails (default 21600)
#   STOW_PREHEAT_COST_EDGE_RSS_MB  restart the dev edge at an idle point
#                                  once its process tree passes this RSS
#                                  (default 1200; see launch-load.sh)
#   STOW_E2E_TOOLCHAIN             rustup toolchain for the run (default:
#                                  stable)
#   STOW_E2E_READY_DEADLINE        seconds to wait for each service
#                                  (default: 600)
set -euo pipefail
# Every background service in its own process group, so the cleanup trap
# can kill whole trees by PGID.
set -m

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EDGE_PORT=8790
# The mock manifest pins the registry and local CI to these ports
# (GHCR_BASE_URL, STOW_LOCAL_CI_URL).
REGISTRY_ADDR=127.0.0.1:28123
LOCAL_CI_ADDR=127.0.0.1:28124
EDGE_URL="http://127.0.0.1:${EDGE_PORT}"
SCHEDULER_URL="${EDGE_URL}/api/v1/scheduler"
LOCAL_CI_URL="http://${LOCAL_CI_ADDR}"
WEBHOOK_SECRET="mock-github-webhook-secret"
EDGE_BEARER="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -z "$EDGE_BEARER" ]; then
    if command -v gh >/dev/null 2>&1; then
        EDGE_BEARER="$(gh auth token 2>/dev/null || true)"
    fi
fi
READY_DEADLINE="${STOW_E2E_READY_DEADLINE:-600}"
LIMIT="${STOW_PREHEAT_COST_LIMIT:-100}"
PROJECTS="${STOW_PREHEAT_COST_PROJECTS:-}"
TARGETS="${STOW_PREHEAT_COST_TARGETS:-}"
MAX_JOBS="${STOW_PREHEAT_COST_MAX_JOBS:-45}"
MAX_MACOS_JOBS="${STOW_PREHEAT_COST_MAX_MACOS_JOBS:-16}"
PHASE_DEADLINE="${STOW_PREHEAT_COST_DEADLINE:-21600}"
EDGE_RSS_MB="${STOW_PREHEAT_COST_EDGE_RSS_MB:-1200}"
POLL_SECS=5

export RUSTUP_TOOLCHAIN="${STOW_E2E_TOOLCHAIN:-stable}"

if [ -n "${STOW_PREHEAT_COST_WORK_DIR:-}" ]; then
    WORK_DIR="$STOW_PREHEAT_COST_WORK_DIR"
    if [ -e "$WORK_DIR" ] && [ -n "$(ls -A "$WORK_DIR" 2>/dev/null)" ]; then
        echo "[preheat-cost] STOW_PREHEAT_COST_WORK_DIR $WORK_DIR is not empty" >&2
        exit 1
    fi
    mkdir -p "$WORK_DIR"
    # Later steps run from other directories; pin a relative value.
    WORK_DIR="$(cd "$WORK_DIR" && pwd)"
else
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stow-preheat-cost.XXXXXX")"
fi
LOG_DIR="$WORK_DIR/logs"
COST_DIR="$WORK_DIR/cost"
mkdir -p "$LOG_DIR" "$COST_DIR"

CHILD_PIDS=()
CHILD_NAMES=()

die() {
    echo "[preheat-cost] ERROR: $*" >&2
    exit 1
}

log() {
    echo "[preheat-cost] $*"
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
        # Collected outside LOG_DIR first: a redirect still bound to one
        # of the logs must not tail itself.
        local dump="$WORK_DIR/cleanup-dump.txt" logfile
        echo "[preheat-cost] FAILED (exit $status) — log tails:" >"$dump"
        for logfile in "$LOG_DIR"/*.log; do
            [ -e "$logfile" ] || continue
            echo "===== $logfile =====" >>"$dump"
            tail -n 40 "$logfile" >>"$dump" 2>&1 || true
        done
        cat "$dump" >&2
    fi
    log "logs: $LOG_DIR"
    exit "$status"
}
trap cleanup EXIT INT TERM

SERVICE_PID=""

start_service() {
    local name="$1" logfile="$2"
    shift 2
    "$@" >"$logfile" 2>&1 &
    SERVICE_PID=$!
    CHILD_PIDS+=("$SERVICE_PID")
    CHILD_NAMES+=("$name")
    log "started $name (pid $SERVICE_PID), log: $logfile"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found on PATH: $1"
}

check_children_alive() {
    local i
    for i in "${!CHILD_PIDS[@]}"; do
        # The lane runners are children too, and exit when their lanes do.
        case "${CHILD_NAMES[$i]}" in
            lanes) continue ;;
        esac
        kill -0 "${CHILD_PIDS[$i]}" 2>/dev/null || die "${CHILD_NAMES[$i]} exited unexpectedly"
    done
}

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
            log "$desc: ready"
            return 0
        fi
        [ "$SECONDS" -ge "$deadline" ] && die "timeout after ${timeout}s waiting for $desc"
        sleep 2
    done
}

http_listening() {
    curl -s -o /dev/null --max-time 5 "$1"
}

require_command cargo
require_command rustc
require_command rustup
require_command openssl
require_command curl
require_command jq
require_command skyzen
require_command wrangler

[ -n "$EDGE_BEARER" ] || die \
    "no GitHub credential for the edge's trusted endpoints — set GH_TOKEN or run \`gh auth login\`"

RUSTC_VERSION="$(rustc --version | awk '{print $2}')"
[ -n "$RUSTC_VERSION" ] || die "could not detect the rustc version"

# The build stage pins the task's rustc as a rustup toolchain name, so a
# toolchain under that exact version must exist (scripts/mock-e2e.sh has
# the reasoning).
if ! RUSTUP_TOOLCHAIN="$RUSTC_VERSION" rustc --version >/dev/null 2>&1; then
    log "installing rustup toolchain '$RUSTC_VERSION' for the sandboxed build pin"
    rustup toolchain install --profile minimal "$RUSTC_VERSION" \
        || die "could not install rustup toolchain '$RUSTC_VERSION'"
fi

# Every lane resolves for these targets, and every task builds for them:
# both need the std of each.
LANE_TARGET_ARGS=()
if [ -n "$TARGETS" ]; then
    LANE_TARGET_ARGS=(--targets "$TARGETS")
    IFS=',' read -r -a target_list <<<"$TARGETS"
    for target in "${target_list[@]}"; do
        if ! rustup target list --installed --toolchain "$RUSTC_VERSION" | grep -qx "$target"; then
            log "installing $target for $RUSTC_VERSION"
            rustup target add --toolchain "$RUSTC_VERSION" "$target" \
                || die "could not install $target for $RUSTC_VERSION"
        fi
    done
fi

log "work dir: $WORK_DIR"
log "rustc $RUSTC_VERSION; top/top-binaries limit $LIMIT; projects ${PROJECTS:-all}; targets ${TARGETS:-every CI target}"
log "dispatch caps: $MAX_JOBS ($MAX_MACOS_JOBS macOS)"

cd "$REPO_ROOT"
log "building stow-cli, stow-build (mock compiler), stow-mock-registry, stow-admin"
cargo build --release \
    -p stow-cli --features stow-cli/mock-verify \
    -p stow-build --features stow-build/mock-verify,stow-build/mock-compile \
    -p stow-mock-registry -p stow-admin \
    >"$LOG_DIR/cargo-build.log" 2>&1 \
    || die "cargo build failed — see $LOG_DIR/cargo-build.log"
BIN="$REPO_ROOT/target/release"

mkdir -p "$WORK_DIR/keys"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK_DIR/keys/private.pem"
openssl pkcs8 -topk8 -nocrypt -in "$WORK_DIR/keys/private.pem" -out "$WORK_DIR/keys/private.pkcs8.pem"
mv "$WORK_DIR/keys/private.pkcs8.pem" "$WORK_DIR/keys/private.pem"
openssl ec -in "$WORK_DIR/keys/private.pem" -pubout -out "$WORK_DIR/keys/public.pem"

mkdir -p "$WORK_DIR/mock-registry" "$WORK_DIR/edge-state" "$WORK_DIR/local-ci" \
    "$WORK_DIR/index-export"

for port in "$EDGE_PORT" "${REGISTRY_ADDR##*:}" "${LOCAL_CI_ADDR##*:}"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        die "port $port is already in use — refusing to probe a foreign service"
    fi
done

start_service mock-registry "$LOG_DIR/mock-registry.log" \
    "$BIN/stow-mock-registry" serve --registry-root "$WORK_DIR/mock-registry" --listen "$REGISTRY_ADDR"
mock_registry_ready() {
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${REGISTRY_ADDR}/v2/")" = "401" ]
}
wait_for "mock registry /v2/" 60 "$SERVICE_PID" mock_registry_ready

(
    cd "$REPO_ROOT/edge"
    skyzen build --provider cloudflare --manifest Skyzen.mock.toml
) >"$LOG_DIR/edge-build.log" 2>&1 \
    || die "skyzen build failed — see $LOG_DIR/edge-build.log"

# The edge runs under `wrangler dev`, whose dev-time service graph
# retains native memory per request (launch-load.sh has the details);
# the wave loop restarts it at an idle point once its tree passes
# EDGE_RSS_MB, with Durable-Object state persisted on disk. The
# production dispatch caps and cost multiplier replace the mock
# manifest's, so an alarm pass claims what production's claims and the
# in-edge daily cost breaker trips where production's would.
EDGE_IDX=-1
EDGE_PID=

start_edge() {
    (
        cd "$REPO_ROOT/edge"
        exec wrangler dev --local --config .skyzen/gen/wrangler.toml \
            --port "$EDGE_PORT" --persist-to "$WORK_DIR/edge-state" \
            --var "STOW_MAX_CONCURRENT_JOBS:$MAX_JOBS" \
            --var "STOW_MAX_CONCURRENT_MACOS_JOBS:$MAX_MACOS_JOBS" \
            --var "STOW_COST_BUDGET_MULTIPLIER:1.0"
    ) >>"$LOG_DIR/edge.log" 2>&1 &
    EDGE_PID=$!
    if [ "$EDGE_IDX" -lt 0 ]; then
        EDGE_IDX=${#CHILD_PIDS[@]}
        CHILD_PIDS+=("$EDGE_PID")
        CHILD_NAMES+=(edge)
    else
        CHILD_PIDS[EDGE_IDX]=$EDGE_PID
    fi
    log "started edge (pid $EDGE_PID), log: $LOG_DIR/edge.log"
    wait_for "edge listener" "$READY_DEADLINE" "$EDGE_PID" \
        http_listening "$SCHEDULER_URL/status"
}

stop_edge() {
    kill -- "-$EDGE_PID" 2>/dev/null || true
    kill "$EDGE_PID" 2>/dev/null || true
    local deadline=$((SECONDS + 30))
    while [ "$SECONDS" -lt "$deadline" ]; do
        http_listening "$SCHEDULER_URL/status" || break
        sleep 1
    done
    if http_listening "$SCHEDULER_URL/status"; then
        kill -9 -- "-$EDGE_PID" 2>/dev/null || true
    fi
    wait "$EDGE_PID" 2>/dev/null || true
}

edge_rss_kb() {
    local pid rss total=0
    for pid in $(descendants "$EDGE_PID"); do
        rss="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')"
        [ -n "$rss" ] && total=$((total + rss))
    done
    echo "$total"
}

admin() {
    env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
        STOW_REGISTRY_BASE_URL="http://${REGISTRY_ADDR}" \
        STOW_MOCK_PUBLIC_KEY_PATH="$WORK_DIR/keys/public.pem" \
        "$BIN/stow-admin" "$@"
}

start_edge
reset_out="$(admin scheduler reset --yes 2>&1)" \
    || die "stow-admin scheduler reset failed: $reset_out"
log "$reset_out"

# The local CI: every dispatch runs `stow-build build` and the publish
# stage's validation for real, with STOW_BUILD_MOCK_COMPILE answering
# rustc. The builder keeps its own cache dir.
(
    cd "$WORK_DIR/local-ci"
    exec env \
        SCHEDULER_URL="$SCHEDULER_URL" \
        STOW_EDGE_URL="$EDGE_URL" \
        STOW_GITHUB_WEBHOOK_SECRET="$WEBHOOK_SECRET" \
        STOW_REGISTRY_BASE_URL="http://${REGISTRY_ADDR}" \
        STOW_CACHE_DIR="$WORK_DIR/ci-cache" \
        STOW_VERIFY_MODE="mock-key" \
        STOW_MOCK_PUBLIC_KEY_PATH="$WORK_DIR/keys/public.pem" \
        STOW_MOCK_PRIVATE_KEY_PATH="$WORK_DIR/keys/private.pem" \
        STOW_MOCK_REGISTRY_ROOT="$WORK_DIR/mock-registry" \
        STOW_BUILD_MOCK_COMPILE=1 \
        GH_TOKEN="$EDGE_BEARER" \
        "$BIN/stow-build" serve --listen "$LOCAL_CI_ADDR"
) >"$LOG_DIR/local-ci.log" 2>&1 &
SERVICE_PID=$!
CHILD_PIDS+=("$SERVICE_PID")
CHILD_NAMES+=(local-ci)
log "started local-ci (pid $SERVICE_PID), log: $LOG_DIR/local-ci.log"
wait_for "local CI dispatch endpoint" 60 "$SERVICE_PID" \
    http_listening "${LOCAL_CI_URL}/dispatch"

# --- measurement helpers ----------------------------------------------------

snapshot() {
    admin preheat cost ledger --out "$1" >>"$LOG_DIR/ledger.log" 2>&1 \
        || die "ledger snapshot $1 failed — see $LOG_DIR/ledger.log"
}

# One lane, bracketed by ledger snapshots. A lane's failure is recorded
# (the report fails on it), never fatal here: the wave still runs what
# the other lanes submitted, as production's does.
run_lane() {
    local phase="$1" order="$2" lane="$3"
    shift 3
    local dir="$COST_DIR/$phase/lanes/$order-$lane" status=0
    mkdir -p "$dir"
    snapshot "$dir/before.json"
    admin --json preheat "$@" --yes >"$dir/plan.json" 2>"$dir/stderr.log" || status=$?
    echo "$status" >"$dir/exit"
    snapshot "$dir/after.json"
    [ "$status" -eq 0 ] || echo "[preheat-cost] lane $lane ($phase) exited $status — see $dir/stderr.log" >&2
}

PROJECT_ARGS=()
[ -n "$PROJECTS" ] && PROJECT_ARGS=(--limit "$PROJECTS")

run_lanes() {
    local phase="$1"
    run_lane "$phase" 01 top top \
        ${LANE_TARGET_ARGS[@]+"${LANE_TARGET_ARGS[@]}"} \
        --rustc-version "$RUSTC_VERSION" --limit "$LIMIT"
    run_lane "$phase" 02 top-binaries top-binaries \
        ${LANE_TARGET_ARGS[@]+"${LANE_TARGET_ARGS[@]}"} \
        --rustc-version "$RUSTC_VERSION" --limit "$LIMIT"
    run_lane "$phase" 03 projects projects submit \
        --file "$REPO_ROOT/preheat/projects.toml" \
        ${LANE_TARGET_ARGS[@]+"${LANE_TARGET_ARGS[@]}"} \
        --rustc-version "$RUSTC_VERSION" \
        ${PROJECT_ARGS[@]+"${PROJECT_ARGS[@]}"}
}

LANES_PID=""
LANES_IDX=-1

start_lanes() {
    local phase="$1"
    run_lanes "$phase" >>"$LOG_DIR/lanes-$phase.log" 2>&1 &
    LANES_PID=$!
    if [ "$LANES_IDX" -lt 0 ]; then
        LANES_IDX=${#CHILD_PIDS[@]}
        CHILD_PIDS+=("$LANES_PID")
        CHILD_NAMES+=(lanes)
    else
        CHILD_PIDS[LANES_IDX]=$LANES_PID
    fi
    log "started the $phase lanes (pid $LANES_PID), log: $LOG_DIR/lanes-$phase.log"
}

# The local CI's `build-crate.yml` runs, as four counts: runs still in
# flight, runs, tasks across them, and tasks that succeeded. One task is
# one run, so the run count is both the completions the scheduler paid
# and the builds; successes count per task, which is
# the task.
local_ci_counts() {
    curl -fsS --max-time 30 "${LOCAL_CI_URL}/tasks" | jq -r '
        [.tasks[] | select(.path == ".github/workflows/build-crate.yml")] as $tasks
        | "\([$tasks[] | select(.status != "completed")] | length) \($tasks | length) \([$tasks[] | select(.conclusion == "success")] | length)"'
}

ROUND=0

# One publish round — the loop index-publish.yml drives: export the
# records the registry gained, publish each changed slice, report each
# to the scheduler (which dispatches the dependents it releases), and
# sync the catalog. The ledger is read right before the first report
# (the earliest a released dependent may dispatch) and after the last.
publish_round() {
    local phase="$1"
    ROUND=$((ROUND + 1))
    local tag
    tag="$(printf '%03d' "$ROUND")"
    local dir="$COST_DIR/$phase/rounds/$tag"
    mkdir -p "$dir"
    admin index export --out-dir "$WORK_DIR/index-export" --rustc-version "$RUSTC_VERSION" \
        >"$LOG_DIR/index-export-$tag.log" 2>&1 \
        || die "index export failed — see $LOG_DIR/index-export-$tag.log"
    cp "$WORK_DIR/index-export/new-records.json" "$dir/new-records.json"
    local pairs
    pairs="$(jq -r '.[] | "\(.index_file) \(.folded_file)"' "$WORK_DIR/index-export/slices.json")" \
        || die "reading $WORK_DIR/index-export/slices.json failed"
    while read -r index_file folded_file; do
        [ -n "$index_file" ] || continue
        env STOW_MOCK_PRIVATE_KEY_PATH="$WORK_DIR/keys/private.pem" \
            STOW_MOCK_REGISTRY_ROOT="$WORK_DIR/mock-registry" \
            "$BIN/stow-admin" index publish \
            --file "$WORK_DIR/index-export/$index_file" \
            --folded "$WORK_DIR/index-export/$folded_file" \
            >>"$LOG_DIR/index-publish.log" 2>&1 \
            || die "index publish failed for $index_file — see $LOG_DIR/index-publish.log"
    done <<<"$pairs"
    snapshot "$dir/before-report.json"
    while read -r index_file _; do
        [ -n "$index_file" ] || continue
        admin index report --file "$WORK_DIR/index-export/$index_file" \
            >>"$LOG_DIR/index-report.log" 2>&1 \
            || die "index report failed for $index_file — see $LOG_DIR/index-report.log"
    done <<<"$pairs"
    snapshot "$dir/end.json"
    admin index sync --file "$WORK_DIR/index-export/new-records.json" \
        >>"$LOG_DIR/index-sync.log" 2>&1 \
        || die "index sync failed — see $LOG_DIR/index-sync.log"
    log "$phase round $tag: $(jq length "$dir/new-records.json") records, $(jq length "$WORK_DIR/index-export/slices.json") slices"
}

# Drive a phase until its lanes are done and nothing is pending or in
# flight. A publish round runs only at an idle point with new successes,
# so each round releases exactly the layer the last one's builds
# unlocked.
# Successful runs the last publish round covered — carried across
# phases, so the resubmit publishes only what it rebuilt.
PUBLISHED_SUCCESSES=0

drive_phase() {
    local phase="$1" deadline=$((SECONDS + PHASE_DEADLINE))
    local counts inflight tasks succeeded status
    local pending dispatched running failed lanes_done
    while :; do
        check_children_alive
        [ "$SECONDS" -lt "$deadline" ] || die "$phase phase passed its ${PHASE_DEADLINE}s deadline"
        lanes_done=0
        kill -0 "$LANES_PID" 2>/dev/null || lanes_done=1
        counts="$(local_ci_counts)" || die "local CI /tasks unreadable"
        read -r inflight tasks succeeded <<<"$counts"
        status="$(curl -fsS --max-time 30 "$SCHEDULER_URL/status")" || die "scheduler status unreadable"
        pending="$(jq -r .pending <<<"$status")"
        dispatched="$(jq -r .dispatched <<<"$status")"
        running="$(jq -r .running <<<"$status")"
        failed="$(jq -r .failed <<<"$status")"
        if [ "$inflight" -eq 0 ] && [ "$dispatched" -eq 0 ] && [ "$running" -eq 0 ]; then
            if [ "$succeeded" -gt "$PUBLISHED_SUCCESSES" ]; then
                # The only idle point with no submit in flight: the
                # lanes are done and no build is running.
                if [ "$lanes_done" -eq 1 ] && [ "$(($(edge_rss_kb) / 1024))" -gt "$EDGE_RSS_MB" ]; then
                    log "edge tree rss $(($(edge_rss_kb) / 1024)) MB — restarting before the round"
                    stop_edge
                    start_edge
                fi
                PUBLISHED_SUCCESSES="$succeeded"
                log "$phase: $tasks task runs so far"
                publish_round "$phase"
                continue
            fi
            if [ "$lanes_done" -eq 1 ]; then
                if [ "$pending" -ne 0 ]; then
                    echo "[preheat-cost] $phase stalled: $pending pending, $failed failed, nothing in flight and nothing new to publish" >&2
                fi
                log "$phase done: pending=$pending failed=$failed"
                return 0
            fi
        fi
        sleep "$POLL_SECS"
    done
}

# --- the wave ---------------------------------------------------------------

mkdir -p "$COST_DIR/wave" "$COST_DIR/resubmit"
snapshot "$COST_DIR/wave/start.json"
start_lanes wave
drive_phase wave
snapshot "$COST_DIR/wave/end.json"

# --- the daily resubmit -----------------------------------------------------

snapshot "$COST_DIR/resubmit/start.json"
start_lanes resubmit
drive_phase resubmit
snapshot "$COST_DIR/resubmit/end.json"

# --- the report -------------------------------------------------------------

scan=(--scan "$LOG_DIR/edge.log" --scan "$LOG_DIR/local-ci.log")
for stderr_log in "$COST_DIR"/*/lanes/*/stderr.log "$LOG_DIR"/index-report.log; do
    [ -e "$stderr_log" ] && scan+=(--scan "$stderr_log")
done
admin preheat cost report \
    --work-dir "$COST_DIR" \
    --rustc-version "$RUSTC_VERSION" \
    --local-ci-url "$LOCAL_CI_URL" \
    "${scan[@]}" \
    --out "$WORK_DIR/preheat-cost-report.json" \
    | tee "$LOG_DIR/report.log" \
    || die "preheat cost checks failed — see $WORK_DIR/preheat-cost-report.json"
log "report: $WORK_DIR/preheat-cost-report.json"