#!/usr/bin/env bash
# The stow#452 mock-stack load test: bring the edge up under
# `wrangler dev` on the 100k production-shaped fixture (the same
# machinery as scripts/scheduler-budget.sh), run the budget probe for a
# baseline report, drive `stow-admin launch-load` at the launch model's
# peak rates for the issue's thirty minutes, then run the probe again —
# the after report is what the launch-cost gate consumes, so a drive
# that degrades under load fails both gates.
#
# The stack is the whole mock: `stow-mock-registry` on 28123 (bundle and
# index slices — `index-from-records` publishes one slice up front so
# the index-pull lane fires both requests the model counts), the edge
# on 8789, and `stow-build serve` on 28124 under STOW_LOCAL_CI_STUB —
# the dispatch POST and the signed workflow_run webhook are real; the
# cargo build behind them is not (a real build per dispatch is orders
# of magnitude heavier than this lane can afford). The admissions and
# enqueue-redemption lanes mint tickets under the mock's
# STOW_POW_CHALLENGE_SECRET.
#
# Tunables (env):
#   STOW_LOAD_WORK_DIR        work dir instead of a fresh mktemp
#   STOW_E2E_TOOLCHAIN        rustup toolchain for the run (default: stable)
#   STOW_LOAD_DURATION_SECS   seconds of load (default 1800 — the issue's
#                           30 minutes)
#   STOW_LOAD_RATE_SCALE      multiplier over the model's peak rates
#                           (default 1.0)
#   STOW_LOAD_QUEUE_ROWS      seeded fixture size (default 100000)
#   STOW_LOAD_RUSTC           rustc the lanes request and the index
#                           slice publishes under (default 1.85.0)
#   STOW_LOAD_POW_SECRET      PoW challenge secret for the admissions
#                           and redemption lanes (default: the mock
#                           manifest's)
#   STOW_E2E_READY_DEADLINE   seconds to wait for the edge (default: 600)
set -euo pipefail
set -m

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EDGE_PORT=8789
REGISTRY_ADDR=127.0.0.1:28123
LOCAL_CI_ADDR=127.0.0.1:28124
EDGE_URL="http://127.0.0.1:${EDGE_PORT}"
SCHEDULER_URL="${EDGE_URL}/api/v1/scheduler"
EDGE_BEARER="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -z "$EDGE_BEARER" ]; then
    if command -v gh >/dev/null 2>&1; then
        EDGE_BEARER="$(gh auth token 2>/dev/null || true)"
    fi
fi
READY_DEADLINE="${STOW_E2E_READY_DEADLINE:-600}"
DURATION_SECS="${STOW_LOAD_DURATION_SECS:-1800}"
RATE_SCALE="${STOW_LOAD_RATE_SCALE:-1.0}"
QUEUE_ROWS="${STOW_LOAD_QUEUE_ROWS:-100000}"
RUSTC_VERSION="${STOW_LOAD_RUSTC:-1.85.0}"
# The mock manifest's STOW_GITHUB_WEBHOOK_SECRET — the value a mock
# delivery is signed under, not a production credential.
WEBHOOK_SECRET="${STOW_LOAD_WEBHOOK_SECRET:-mock-github-webhook-secret}"
# The mock manifest's STOW_POW_CHALLENGE_SECRET — the secret the
# admissions and enqueue-redemption lanes mint their tickets under.
POW_SECRET="${STOW_LOAD_POW_SECRET:-mock-pow-challenge-secret}"
# The production dispatch cap (`STOW_MAX_CONCURRENT_JOBS` in
# edge/Skyzen.toml): the mock deploy pins 3 — below the fixture's 30
# in-flight rows, which would leave every pass's claim walk zero slots
# — so the probe carries the real cap explicitly and the report echoes
# the limit it measured under.
DISPATCH_LIMIT="$(sed -n 's/^STOW_MAX_CONCURRENT_JOBS *= *"\([0-9]*\)".*/\1/p' \
    "$REPO_ROOT/edge/Skyzen.toml")"
[ -n "$DISPATCH_LIMIT" ] || {
    echo "[load] ERROR: STOW_MAX_CONCURRENT_JOBS not found in edge/Skyzen.toml" >&2
    exit 1
}

export RUSTUP_TOOLCHAIN="${STOW_E2E_TOOLCHAIN:-stable}"

if [ -n "${STOW_LOAD_WORK_DIR:-}" ]; then
    WORK_DIR="$STOW_LOAD_WORK_DIR"
    mkdir -p "$WORK_DIR"
else
    WORK_DIR="$(mktemp -d)"
fi
LOG_DIR="$WORK_DIR/logs"
mkdir -p "$LOG_DIR"

die() { echo "[load] ERROR: $*" >&2; exit 1; }

CHILD_PIDS=()
CHILD_NAMES=()

# All PIDs below $1, recursively. Printed one per line — the same
# descendant sweep scheduler-budget.sh's cleanup uses, so a mid-run
# failure cannot leak wrangler dev's workerd child or a stow-build
# serve still holding its port.
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
        local dump="$WORK_DIR/cleanup-dump.txt" log
        echo "[load] FAILED (exit $status) — log tails:" >"$dump"
        for log in "$LOG_DIR"/*.log; do
            [ -e "$log" ] || continue
            echo "===== $log =====" >>"$dump"
            tail -n 80 "$log" >>"$dump" 2>/dev/null || true
        done
        cat "$dump" >&2
    fi
    echo "[load] logs: $LOG_DIR"
    exit "$status"
}
trap cleanup EXIT INT TERM

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
            echo "[load] $desc: ready"
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
require_command rustup
require_command curl
require_command openssl
require_command skyzen
require_command wrangler

[ -n "$EDGE_BEARER" ] || die \
    "no GitHub credential for the edge's trusted endpoints — set GH_TOKEN or run \`gh auth login\`"

echo "[load] work dir: $WORK_DIR"

if ! rustup target list --installed --toolchain "$RUSTUP_TOOLCHAIN" \
    | grep -qx wasm32-unknown-unknown; then
    echo "[load] installing wasm32-unknown-unknown for $RUSTUP_TOOLCHAIN"
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" wasm32-unknown-unknown
fi

cd "$REPO_ROOT"
echo "[load] building stow-admin, stow-mock-registry and stow-build"
cargo build -p stow-admin -p stow-mock-registry -p stow-build >"$LOG_DIR/cargo-build.log" 2>&1 \
    || die "cargo build failed — see $LOG_DIR/cargo-build.log"
BIN="$REPO_ROOT/target/debug"

# P-256 PKCS#8 key pair — the format sigstore accepts (the same block
# scripts/mock-e2e.sh runs; docs/MOCK.md).
mkdir -p "$WORK_DIR/keys"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK_DIR/keys/private.pem"
openssl pkcs8 -topk8 -nocrypt -in "$WORK_DIR/keys/private.pem" -out "$WORK_DIR/keys/private.pkcs8.pem"
mv "$WORK_DIR/keys/private.pkcs8.pem" "$WORK_DIR/keys/private.pem"
openssl ec -in "$WORK_DIR/keys/private.pem" -pubout -out "$WORK_DIR/keys/public.pem"

for port in "$EDGE_PORT" "${REGISTRY_ADDR##*:}" "${LOCAL_CI_ADDR##*:}"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        die "port $port is already in use — refusing to load a foreign service"
    fi
done

# The bundle/index lanes miss through the Cache API into the mock GHCR
# — without it the edge's registry fetch is a transport error, not the
# designed 404.
mkdir -p "$WORK_DIR/mock-registry"
"$BIN/stow-mock-registry" serve --registry-root "$WORK_DIR/mock-registry" \
    --listen "$REGISTRY_ADDR" >"$LOG_DIR/mock-registry.log" 2>&1 &
SERVICE_PID=$!
CHILD_PIDS+=("$SERVICE_PID")
CHILD_NAMES+=(mock-registry)
echo "[load] started mock registry (pid $SERVICE_PID), log: $LOG_DIR/mock-registry.log"
wait_for "mock registry listener" "$READY_DEADLINE" "$SERVICE_PID" \
    http_listening "http://$REGISTRY_ADDR/v2/"

# One signed index slice at the (target, rustc) the index-pull lane
# requests — without a published slice the pointer GET 404s and the
# lane fires only the first of the two requests the launch model
# prices per pull. A single record with a bundle digest is enough for
# `index-from-records` to emit the slice.
cat >"$WORK_DIR/load-records.json" <<'RECORDS'
[{
  "compile_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "c_metadata": "a1b2c3d4",
  "extra_filename": "",
  "target": "x86_64-unknown-linux-gnu",
  "rustc_version": "__RUSTC__",
  "profile": {"opt_level": "3", "debuginfo": 0, "debug_assertions": false,
              "overflow_checks": false, "panic": "Unwind", "strip": "none"},
  "emit": ["link"],
  "crate_name": "serde",
  "version": "1.0.219",
  "features_json": "[]",
  "dependency_c_metadata_json": "[]",
  "oci_reference": "ghcr.io/water-rs/stow-cache:serde.1.0.219-x86_64-unknown-linux-gnu",
  "oci_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "has_native": false,
  "artifact_kind": "Rlib",
  "crate_types": ["rlib"],
  "artifact_size": 10,
  "bundle_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "bundle_size": 100,
  "compile_millis": 5
}]
RECORDS
sed -i "s/__RUSTC__/$RUSTC_VERSION/" "$WORK_DIR/load-records.json"
"$BIN/stow-mock-registry" index-from-records \
    --records "$WORK_DIR/load-records.json" \
    --registry-root "$WORK_DIR/mock-registry" \
    --private-key "$WORK_DIR/keys/private.pem" \
    || die "index-from-records failed"
echo "[load] published index slice for x86_64-unknown-linux-gnu / $RUSTC_VERSION"

(
    cd "$REPO_ROOT/edge"
    skyzen build --provider cloudflare --manifest Skyzen.mock.toml
) >"$LOG_DIR/edge-build.log" 2>&1 \
    || die "skyzen build failed — see $LOG_DIR/edge-build.log"
wrangler d1 migrations apply stow-mock --local \
    --config "$REPO_ROOT/edge/.skyzen/gen/wrangler.toml" \
    --persist-to "$WORK_DIR/edge-state" >>"$LOG_DIR/edge-migrate.log" 2>&1 \
    || die "edge D1 migrations failed — see $LOG_DIR/edge-migrate.log"
(
    cd "$REPO_ROOT/edge"
    exec wrangler dev --local --config .skyzen/gen/wrangler.toml \
        --port "$EDGE_PORT" --persist-to "$WORK_DIR/edge-state"
) >"$LOG_DIR/edge.log" 2>&1 &
SERVICE_PID=$!
CHILD_PIDS+=("$SERVICE_PID")
CHILD_NAMES+=(edge)
echo "[load] started edge (pid $SERVICE_PID), log: $LOG_DIR/edge.log"
wait_for "edge listener" "$READY_DEADLINE" "$SERVICE_PID" \
    http_listening "$SCHEDULER_URL/status"

# Same deploy order as deploy-edge.yml: the operator migration runs
# before the scheduler takes traffic.
migrate_out="$(env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
    "$BIN/stow-admin" scheduler migrate 2>&1)" \
    || die "stow-admin scheduler migrate failed: $migrate_out"
echo "[load] $migrate_out"

# The local dispatch endpoint the edge's STOW_LOCAL_CI_URL points at —
# STOW_LOCAL_CI_STUB short-circuits run_dispatched_task to the signed
# workflow_run webhook, so the per-claim fan-out hop (the dominant
# serialized term of a dispatch pass) is a real HTTP request without a
# real cargo build behind it.
mkdir -p "$WORK_DIR/local-ci"
(
    cd "$WORK_DIR/local-ci"
    exec env \
        STOW_EDGE_URL="$EDGE_URL" \
        STOW_GITHUB_WEBHOOK_SECRET="$WEBHOOK_SECRET" \
        STOW_MOCK_PUBLIC_KEY_PATH="$WORK_DIR/keys/public.pem" \
        STOW_MOCK_PRIVATE_KEY_PATH="$WORK_DIR/keys/private.pem" \
        STOW_MOCK_REGISTRY_ROOT="$WORK_DIR/mock-registry" \
        STOW_LOCAL_CI_STUB=1 \
        "$BIN/stow-build" serve --listen "$LOCAL_CI_ADDR"
) >"$LOG_DIR/local-ci.log" 2>&1 &
SERVICE_PID=$!
CHILD_PIDS+=("$SERVICE_PID")
CHILD_NAMES+=(local-ci)
echo "[load] started local-ci stub (pid $SERVICE_PID), log: $LOG_DIR/local-ci.log"
wait_for "local CI dispatch endpoint" 60 "$SERVICE_PID" \
    http_listening "http://${LOCAL_CI_ADDR}/dispatch"

# Baseline probe: seed the production shape and measure every drive —
# the "before" half of the issue's counted-rows check.
echo "[load] baseline: seeding $QUEUE_ROWS rows and running the budget probe"
env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
    "$BIN/stow-admin" --json scheduler budget --queue-rows "$QUEUE_ROWS" --reset \
    --dispatch-limit "$DISPATCH_LIMIT" \
    >"$WORK_DIR/budget-report-before.json" 2>"$LOG_DIR/budget-before-stderr.log" \
    || { cat "$LOG_DIR/budget-before-stderr.log" >&2; \
         die "baseline budget probe exceeded — see $WORK_DIR/budget-report-before.json"; }
echo "[load] baseline report: $WORK_DIR/budget-report-before.json"

# The load: every lane at the launch model's peak rate for the
# duration.
echo "[load] driving ${DURATION_SECS}s at rate scale $RATE_SCALE"
env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
    "$BIN/stow-admin" --json launch-load \
    --model "$REPO_ROOT/launch-model.toml" \
    --duration-secs "$DURATION_SECS" \
    --rate-scale "$RATE_SCALE" \
    --queue-rows "$QUEUE_ROWS" \
    --rustc "$RUSTC_VERSION" \
    --scheduler --webhook-secret "$WEBHOOK_SECRET" \
    --pow-secret "$POW_SECRET" \
    >"$WORK_DIR/launch-load-report.json" 2>"$LOG_DIR/launch-load-stderr.log" \
    || { cat "$LOG_DIR/launch-load-stderr.log" >&2; \
         die "launch-load breached — see $WORK_DIR/launch-load-report.json"; }
echo "[load] load report: $WORK_DIR/launch-load-report.json"

# The after probe: counted rows per route against the #433 budgets,
# measured after thirty minutes of launch-rate traffic — and the input
# the launch-cost gate then projects.
echo "[load] re-measuring the budget probe under the loaded fixture"
env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
    "$BIN/stow-admin" --json scheduler budget --queue-rows "$QUEUE_ROWS" \
    --dispatch-limit "$DISPATCH_LIMIT" \
    >"$WORK_DIR/budget-report-after.json" 2>"$LOG_DIR/budget-after-stderr.log" \
    || { cat "$LOG_DIR/budget-after-stderr.log" >&2; \
         die "post-load budget probe exceeded — see $WORK_DIR/budget-report-after.json"; }

echo "[load] launch-cost gate on the post-load report"
"$BIN/stow-admin" launch-gate \
    --report "$WORK_DIR/budget-report-after.json" \
    --model "$REPO_ROOT/launch-model.toml" \
    || die "launch-cost gate failed — see $WORK_DIR/budget-report-after.json"

echo "[load] OK — $DURATION_SECS at launch peak rate, both probes in budget"
