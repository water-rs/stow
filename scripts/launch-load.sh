#!/usr/bin/env bash
# The stow#452 mock-stack load test: bring the edge up under
# `wrangler dev` on the 100k production-shaped fixture (the same
# machinery as scripts/scheduler-budget.sh), run the budget probe for a
# baseline report, drive `stow-admin launch-load` at the launch model's
# peak rates for the issue's thirty minutes, then run the probe again —
# the after report is what the launch-cost gate consumes, so a drive
# that degrades under load fails both gates.
#
# Tunables (env):
#   STOW_LOAD_WORK_DIR        work dir instead of a fresh mktemp
#   STOW_E2E_TOOLCHAIN        rustup toolchain for the run (default: stable)
#   STOW_LOAD_DURATION_SECS   seconds of load (default 1800 — the issue's
#                           30 minutes)
#   STOW_LOAD_RATE_SCALE      multiplier over the model's peak rates
#                           (default 1.0)
#   STOW_LOAD_QUEUE_ROWS      seeded fixture size (default 100000)
#   STOW_E2E_READY_DEADLINE   seconds to wait for the edge (default: 600)
set -euo pipefail
set -m

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EDGE_PORT=8789
REGISTRY_ADDR=127.0.0.1:28123
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
# The mock manifest's STOW_GITHUB_WEBHOOK_SECRET — the value a mock
# delivery is signed under, not a production credential.
WEBHOOK_SECRET="${STOW_LOAD_WEBHOOK_SECRET:-mock-github-webhook-secret}"

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
cleanup() {
    local i
    for i in "${!CHILD_PIDS[@]}"; do
        kill "${CHILD_PIDS[$i]}" 2>/dev/null || true
    done
}
trap cleanup EXIT

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
require_command jq
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
echo "[load] building stow-admin and stow-mock-registry"
cargo build -p stow-admin -p stow-mock-registry >"$LOG_DIR/cargo-build.log" 2>&1 \
    || die "cargo build failed — see $LOG_DIR/cargo-build.log"
BIN="$REPO_ROOT/target/debug"

if (exec 3<>"/dev/tcp/127.0.0.1/$EDGE_PORT") 2>/dev/null; then
    die "port $EDGE_PORT is already in use — refusing to load a foreign service"
fi
if (exec 3<>"/dev/tcp/$REGISTRY_ADDR") 2>/dev/null; then
    die "port $REGISTRY_ADDR is already in use — refusing to treat a foreign registry as the mock"
fi

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

# Baseline probe: seed the production shape and measure every drive —
# the "before" half of the issue's counted-rows check.
echo "[load] baseline: seeding $QUEUE_ROWS rows and running the budget probe"
env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
    "$BIN/stow-admin" --json scheduler budget --queue-rows "$QUEUE_ROWS" --reset \
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
    --scheduler --webhook-secret "$WEBHOOK_SECRET" \
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
    >"$WORK_DIR/budget-report-after.json" 2>"$LOG_DIR/budget-after-stderr.log" \
    || { cat "$LOG_DIR/budget-after-stderr.log" >&2; \
         die "post-load budget probe exceeded — see $WORK_DIR/budget-report-after.json"; }

echo "[load] launch-cost gate on the post-load report"
"$BIN/stow-admin" launch-gate \
    --report "$WORK_DIR/budget-report-after.json" \
    --model "$REPO_ROOT/launch-model.toml" \
    || die "launch-cost gate failed — see $WORK_DIR/budget-report-after.json"

echo "[load] OK — $DURATION_SECS at launch peak rate, both probes in budget"
