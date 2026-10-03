#!/usr/bin/env bash
# The workerd cost gate (stow#433): bring the edge up under
# `wrangler dev` (workerd — the same SQLite storage and cursor
# accounting the Durable Object bills on), migrate the scheduler schema
# through the operator route like the deploy pipeline does, seed the
# production-shaped fixture through the object's probe route, and run
# the budget pass. The probe routes answer only when the deploy carries
# `STOW_SCHEDULER_BUDGET=1`, which `edge/Skyzen.mock.toml` sets and the
# production manifest never does.
#
#   stow-admin scheduler budget   prints the per-route table
#                                 (statements, rowsRead, rowsWritten
#                                 against the in-code budgets) and exits
#                                 non-zero on any over-budget route.
#
# The gate measures scale, not just a budget at one size: the same pass
# runs at two fixture sizes (100k and 1M queue rows, same shape) and a
# drive fails when its rowsRead or rowsWritten at the larger size
# exceeds its smaller-size value by more than 10% plus 50 rows. The
# absolute budgets remain the second check. Quantities a route may
# legitimately be bounded by — human-lane depth, in-flight count,
# completions in the last 24 h, blocked rows per page, the slice delta —
# are pinned by the fixture across sizes, so only the stored bulk grows.
#
# The dispatch pass drives the mock stack it would drive in
# production: `stow-mock-registry` on 28123 (the edge's GHCR_BASE_URL —
# the webhook's records check), `stow-build serve` on 28124 under
# STOW_LOCAL_CI_STUB (the edge's STOW_LOCAL_CI_URL — a real dispatch
# POST per claimed task, the pass's bounded-concurrent fan-out, then
# the signed workflow_run callback; only the cargo build is stubbed), and
# the production dispatch cap carried to the probe via
# `--dispatch-limit` — the mock deploy pins STOW_MAX_CONCURRENT_JOBS=3,
# below the fixture's 30 in-flight rows, which would price a pass that
# claims nothing.
#
# Tunables (env):
#   STOW_BUDGET_WORK_DIR       work dir instead of a fresh mktemp
#   STOW_E2E_TOOLCHAIN         rustup toolchain for the run (default: stable)
#   STOW_BUDGET_SIZES          fixture sizes for the scale check
#                            (default: "100000 1000000")
#   STOW_BUDGET_QUEUE_ROWS     run a single size instead (legacy dev
#                            path; disables the scale check)
#   STOW_E2E_READY_DEADLINE    seconds to wait for the edge (default: 600)
#   STOW_BUDGET_RESEED         `reset` to wipe and reseed an existing
#                            fixture, `no_seed` to measure as-is
#                            (single-size only)
set -euo pipefail
set -m

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EDGE_PORT=8788
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
QUEUE_ROWS="${STOW_BUDGET_QUEUE_ROWS:-}"
SIZES="${STOW_BUDGET_SIZES:-100000 1000000}"
RESEED="${STOW_BUDGET_RESEED:-}"
# The production dispatch cap (`STOW_MAX_CONCURRENT_JOBS` in
# edge/Skyzen.toml): the probe runs the claim walk under the real cap
# so the report's claimed_tasks/dispatch_limit reflect production, not
# the mock deploy's pinned-down value.
DISPATCH_LIMIT="$(sed -n 's/^STOW_MAX_CONCURRENT_JOBS *= *"\([0-9]*\)".*/\1/p' \
    "$REPO_ROOT/edge/Skyzen.toml")"
[ -n "$DISPATCH_LIMIT" ] || {
    echo "[budget] ERROR: STOW_MAX_CONCURRENT_JOBS not found in edge/Skyzen.toml" >&2
    exit 1
}

export RUSTUP_TOOLCHAIN="${STOW_E2E_TOOLCHAIN:-stable}"

if [ -n "${STOW_BUDGET_WORK_DIR:-}" ]; then
    WORK_DIR="$STOW_BUDGET_WORK_DIR"
    mkdir -p "$WORK_DIR"
else
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stow-budget.XXXXXX")"
fi
LOG_DIR="$WORK_DIR/logs"
mkdir -p "$LOG_DIR" "$WORK_DIR/edge-state"

CHILD_PIDS=()
CHILD_NAMES=()

die() {
    echo "[budget] ERROR: $*" >&2
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
        echo "[budget] FAILED (exit $status) — log tails:" >"$dump"
        for log in "$LOG_DIR"/*.log; do
            [ -e "$log" ] || continue
            echo "===== $log =====" >>"$dump"
            tail -n 80 "$log" >>"$dump" 2>/dev/null || true
        done
        cat "$dump" >&2
    fi
    echo "[budget] logs: $LOG_DIR"
    exit "$status"
}
trap cleanup EXIT INT TERM

SERVICE_PID=""

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
            echo "[budget] $desc: ready"
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
require_command openssl
require_command skyzen
require_command wrangler

[ -n "$EDGE_BEARER" ] || die \
    "no GitHub credential for the edge's trusted endpoints — set GH_TOKEN or run \`gh auth login\`"

echo "[budget] work dir: $WORK_DIR"

if ! rustup target list --installed --toolchain "$RUSTUP_TOOLCHAIN" \
    | grep -qx wasm32-unknown-unknown; then
    echo "[budget] installing wasm32-unknown-unknown for $RUSTUP_TOOLCHAIN"
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" wasm32-unknown-unknown
fi

cd "$REPO_ROOT"
echo "[budget] building stow-admin, stow-mock-registry and stow-build"
cargo build -p stow-admin -p stow-mock-registry -p stow-build \
    >"$LOG_DIR/cargo-build.log" 2>&1 \
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
        die "port $port is already in use — refusing to probe a foreign service"
    fi
done

# The mock GHCR the edge's GHCR_BASE_URL points at — the stub builds'
# signed workflow_run callbacks check the records artifact there.
mkdir -p "$WORK_DIR/mock-registry"
"$BIN/stow-mock-registry" serve --registry-root "$WORK_DIR/mock-registry" \
    --listen "$REGISTRY_ADDR" >"$LOG_DIR/mock-registry.log" 2>&1 &
SERVICE_PID=$!
CHILD_PIDS+=("$SERVICE_PID")
CHILD_NAMES+=(mock-registry)
echo "[budget] started mock registry (pid $SERVICE_PID), log: $LOG_DIR/mock-registry.log"
wait_for "mock registry listener" "$READY_DEADLINE" "$SERVICE_PID" \
    http_listening "http://$REGISTRY_ADDR/v2/"

(
    cd "$REPO_ROOT/edge"
    skyzen build --provider cloudflare --manifest Skyzen.mock.toml
) >"$LOG_DIR/edge-build.log" 2>&1 \
    || die "skyzen build failed — see $LOG_DIR/edge-build.log"
# Wrangler writes its own ISO-timestamped log to WRANGLER_LOG_PATH —
# pointing it inside the artifact logs dir keeps the native
# receipt-time channel (which the console output lacks) next to the
# report it timestamps.
mkdir -p "$LOG_DIR/wrangler"
export WRANGLER_LOG_PATH="$LOG_DIR/wrangler"
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
echo "[budget] started edge (pid $SERVICE_PID), log: $LOG_DIR/edge.log"
wait_for "edge listener" "$READY_DEADLINE" "$SERVICE_PID" \
    http_listening "$SCHEDULER_URL/status"

# The local dispatch endpoint the edge's STOW_LOCAL_CI_URL points at —
# STOW_LOCAL_CI_STUB short-circuits run_dispatched_task to the signed
# workflow_run webhook, so each claimed task's sequential
# trigger_build hop is a real HTTP round-trip in the pass's wall_ms
# without a cargo build behind it.
mkdir -p "$WORK_DIR/local-ci"
(
    cd "$WORK_DIR/local-ci"
    exec env \
        STOW_EDGE_URL="$EDGE_URL" \
        STOW_GITHUB_WEBHOOK_SECRET="mock-github-webhook-secret" \
        STOW_MOCK_PUBLIC_KEY_PATH="$WORK_DIR/keys/public.pem" \
        STOW_MOCK_PRIVATE_KEY_PATH="$WORK_DIR/keys/private.pem" \
        STOW_MOCK_REGISTRY_ROOT="$WORK_DIR/mock-registry" \
        STOW_LOCAL_CI_STUB=1 \
        "$BIN/stow-build" serve --listen "$LOCAL_CI_ADDR"
) >"$LOG_DIR/local-ci.log" 2>&1 &
SERVICE_PID=$!
CHILD_PIDS+=("$SERVICE_PID")
CHILD_NAMES+=(local-ci)
echo "[budget] started local-ci stub (pid $SERVICE_PID), log: $LOG_DIR/local-ci.log"
wait_for "local CI dispatch endpoint" 60 "$SERVICE_PID" \
    http_listening "http://${LOCAL_CI_ADDR}/dispatch"

# Same deploy order as deploy-edge.yml: the operator migration runs
# before the scheduler takes traffic.
migrate_out="$(env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
    "$BIN/stow-admin" scheduler migrate 2>&1)" \
    || die "stow-admin scheduler migrate failed: $migrate_out"
echo "[budget] $migrate_out"

print_table() {
    jq -r '
        "scheduler budget (queue rows \(.queue_rows), schema v\(.schema_version)):",
        (.rows[] | "  \(.name | . + " " * (34 - length)) stmts=\(.statements)/\(.statement_budget) rows_read=\(.rows_read)/\(.read_budget) rows_written=\(.rows_written)/\(.write_budget) wall_ms=\(.wall_ms)/\(.wall_budget)\(if .over_budget then " OVER" else "" end)")
    ' "$1"
}

# One budget pass: reset and reseed at $1 rows (the pass mutates the
# fixture — it cannot re-measure), then the gated run. `--json` keeps
# the per-statement detail for the report; the same run exits non-zero
# when any route is over budget.
run_pass() {
    local rows="$1" report="$2"
    echo "[budget] seeding $rows queue rows and running the budget pass"
    env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
        "$BIN/stow-admin" --json scheduler budget --queue-rows "$rows" --reset \
        --dispatch-limit "$DISPATCH_LIMIT" \
        >"$report" 2>"$LOG_DIR/budget-stderr-$rows.log" \
        || { cat "$LOG_DIR/budget-stderr-$rows.log" >&2; \
             die "scheduler budget exceeded — see $report"; }
    cat "$LOG_DIR/budget-stderr-$rows.log"
    print_table "$report"
    echo "[budget] report: $report"
}

if [ -n "$QUEUE_ROWS" ]; then
    # Legacy single-size dev path — no scale check.
    seed_args=(--queue-rows "$QUEUE_ROWS")
    case "$RESEED" in
        reset) seed_args+=(--reset) ;;
        no_seed) seed_args=(--no-seed) ;;
            "") ;;
        *) die "STOW_BUDGET_RESEED must be 'reset', 'no_seed', or empty" ;;
    esac
    env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
        "$BIN/stow-admin" --json scheduler budget "${seed_args[@]}" \
        --dispatch-limit "$DISPATCH_LIMIT" \
        >"$WORK_DIR/budget-report.json" 2>"$LOG_DIR/budget-stderr.log" \
        || { cat "$LOG_DIR/budget-stderr.log" >&2; die "scheduler budget exceeded — see $WORK_DIR/budget-report.json"; }
    cat "$LOG_DIR/budget-stderr.log"
    print_table "$WORK_DIR/budget-report.json"
    echo "[budget] report: $WORK_DIR/budget-report.json"
    echo "[budget] OK — every route within budget (single size, scale check skipped)"
    exit 0
fi
[ -z "$RESEED" ] || die "STOW_BUDGET_RESEED only applies to the single-size path (STOW_BUDGET_QUEUE_ROWS)"

# The scale gate: the same pass at each size, then the growth check.
# A route may legitimately be bounded by a held quantity — lane depth,
# the 24 h outcome window, in-flight count, the report's own size —
# and those comments in drives.rs name the quantity; everything else
# must be flat.
read -r -a size_list <<<"$SIZES"
[ "${#size_list[@]}" -eq 2 ] || die "STOW_BUDGET_SIZES must name exactly two sizes"
small="${size_list[0]}" large="${size_list[1]}"
[ "$small" -lt "$large" ] || die "STOW_BUDGET_SIZES must be ordered small then large"
run_pass "$small" "$WORK_DIR/budget-report-$small.json"
run_pass "$large" "$WORK_DIR/budget-report-$large.json"

# Fail on growth: more than 10% plus 50 rows over the small fixture on
# either counter flags a cost that tracks the stored bulk.
jq -r -n --slurpfile small "$WORK_DIR/budget-report-$small.json" \
         --slurpfile large "$WORK_DIR/budget-report-$large.json" '
    ($small[0].rows) as $s | ($large[0].rows) as $l |
    [ $s[] | . as $a | ($l[] | select(.name == $a.name)) as $b |
      { name: $a.name,
        read_small: $a.rows_read, read_large: $b.rows_read,
        wr_small: $a.rows_written, wr_large: $b.rows_written,
        grow: ($b.rows_read > ($a.rows_read * 1.1 + 50)
               or $b.rows_written > ($a.rows_written * 1.1 + 50)) } ] |
    . as $rows | ($rows | map(select(.grow))) as $bad |
    "scheduler scale check (\($small[0].queue_rows) → \($large[0].queue_rows) queue rows):",
    ($rows[] | "  \(.name | . + " " * (34 - length)) rows_read=\(.read_small)→\(.read_large) rows_written=\(.wr_small)→\(.wr_large)\(if .grow then " GROWS" else "" end)"),
    if ($bad | length) > 0
    then "\($bad | length) drive(s) grow with the fixture", error("scale check failed")
    else "scale check OK — every drive flat within 10% + 50 rows" end
' || die "scheduler scale check failed — see $WORK_DIR/budget-report-*.json"
echo "[budget] OK — every route within budget and flat across sizes"
