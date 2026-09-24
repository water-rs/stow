#!/usr/bin/env bash
# Drive the host-side-node pipeline end-to-end on loopback — the
# reproduction of the post-0.6.0 own-node failures (e.g. run
# 35995412018: snafu-derive's build compiling its host deps itself
# because no host-side node had published them):
#
#   1. build the four host binaries and generate a P-256 PKCS#8 key pair
#   2. start stow-mock-registry (40123), the edge under `wrangler dev`
#      (workerd, 8788; bundle built by `skyzen build`), and
#      `stow-build serve` (40124)
#   3. `stow-admin preheat plan` snafu-derive@0.9.2 for
#      wasm32-unknown-unknown — the failing production task — and POST
#      the expanded task batch to the scheduler. The plan mints
#      snafu-derive's whole proc-macro tree as host-side nodes on the
#      host triple (heck, proc-macro2, quote, syn, unicode-ident, the
#      root itself), each gated on its dependencies' published shapes.
#   4. build wave by wave: when every dispatched task has reported and
#      the remaining pending set is gated on the index, export → publish
#      → report the host slice so the gate opens the next wave — the
#      same loop the production index-publish workflow drives.
#   5. assert the catalog: heck rows live under the host triple with
#      unit_side=host at both linked shapes (native and explicit-target
#      invocations — cargo links host units in every phase, so check and
#      build merge to one row each), and nothing named heck under wasm32.
#   6. consumer: a crate with `snafu-derive` as a normal dependency —
#      the real consumer shape — runs `stow check` natively and under
#      `--target wasm32-unknown-unknown`; the stats DB must show hits
#      for every host-side dep on both invocations and zero errors.
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
#   STOW_E2E_TASK_DEADLINE   seconds to wait for the scheduler (default: 1200)
set -euo pipefail
# Job control gives every background service its own process group, so the
# cleanup trap can kill whole trees — including grandchildren like
# wrangler/workerd that outlive a dead supervisor — by PGID, never by name.
set -m

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EDGE_PORT=8788
REGISTRY_ADDR=127.0.0.1:40123
LOCAL_CI_ADDR=127.0.0.1:40124
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
TASK_DEADLINE="${STOW_E2E_TASK_DEADLINE:-1200}"
TASK_CRATE=snafu-derive
TASK_VERSION=0.9.2
CONSUMER_TARGET=wasm32-unknown-unknown

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
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stow-mock-e2e-host-deps.XXXXXX")"
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
            tail -n 80 "$log" >>"$dump" 2>&1 || true
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
isolated_env() {
    env \
        HOME="$WORK_DIR/home" \
        XDG_CONFIG_HOME="$WORK_DIR/config" \
        CARGO_HOME="$WORK_DIR/cargo-home" \
        RUSTUP_HOME="$RUSTUP_HOME_REAL" \
        "$@"
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

# `skyzen dev` compiles the edge to wasm32 on the run's toolchain, and the
# `--target wasm32` consumer check compiles the consumer crate for wasm32 —
# both need the std.
for toolchain in "$RUSTUP_TOOLCHAIN" "$RUSTC_VERSION"; do
    if ! rustup target list --installed --toolchain "$toolchain" \
        | grep -qx "$CONSUMER_TARGET"; then
        echo "[mock-e2e] installing $CONSUMER_TARGET for $toolchain"
        rustup target add --toolchain "$toolchain" "$CONSUMER_TARGET" \
            || die "could not install $CONSUMER_TARGET for $toolchain"
    fi
done

cd "$REPO_ROOT"
echo "[mock-e2e] building stow-cli, stow-build, stow-mock-registry, stow-admin"
cargo build -p stow-cli --features mock-verify -p stow-build -p stow-mock-registry -p stow-admin \
    >"$LOG_DIR/cargo-build.log" 2>&1 \
    || die "cargo build failed — see $LOG_DIR/cargo-build.log"
BIN="$REPO_ROOT/target/debug"

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
    "$BIN/stow-mock-registry" serve --registry-root "$WORK_DIR/mock-registry" --listen "$REGISTRY_ADDR"
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
wait_for "edge scheduler status" "$READY_DEADLINE" "$SERVICE_PID" \
    curl -fsS "$SCHEDULER_URL/status"

# The dispatch tree (.tmp/local-ci-dispatch) is written under the server's
# cwd; keep it inside the work dir.
(
    cd "$WORK_DIR/local-ci"
    exec env \
        SCHEDULER_URL="$SCHEDULER_URL" \
        STOW_EDGE_URL="$EDGE_URL" \
        STOW_REGISTRY_BASE_URL="http://${REGISTRY_ADDR}/v2/water-rs/stow-cache" \
        STOW_CACHE_DIR="$WORK_DIR/stow-cache" \
        STOW_VERIFY_MODE="mock-key" \
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

# --- submit the failing production task's graph ----------------------------

# `preheat plan` runs the edge's own resolver over the published tarball:
# a proc-macro crate lands on the runner-family host as a host-side node,
# and every crates.io dependency that is host-side in its unit graph
# becomes a host-side task the root's edges gate on. wasm32 is the
# production failure's target spelling.
isolated_env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
    "$BIN/stow-admin" --json preheat plan \
    "${TASK_CRATE}@${TASK_VERSION}" \
    --features-json '[]' \
    --target "$CONSUMER_TARGET" \
    --rustc-version "$RUSTC_VERSION" \
    >"$WORK_DIR/preheat-plan.json" 2>"$LOG_DIR/preheat-plan.log" \
    || die "stow-admin preheat plan failed — see $LOG_DIR/preheat-plan.log"

# The JSON plan carries the resolved task batch per target; host-side
# nodes mint under the runner-family host triple, so the wasm32 plan's
# tasks are the snafu-derive host tree at x86_64 host side.
plan_tasks="$(jq '[.targets[].tasks[]]' "$WORK_DIR/preheat-plan.json")"
task_count="$(jq 'length' <<<"$plan_tasks")"
[ "$task_count" -ge 2 ] || die "plan returned $task_count tasks — expected snafu-derive plus host deps"
echo "[mock-e2e] plan: $task_count tasks"
jq -r '.[] | "  \(.crate_name) \(.version) target=\(.target) host_side=\(.host_side) deps=\(.depends_on | length)"' \
    <<<"$plan_tasks"

# Every task in this plan must be host-side on the host triple: a
# proc-macro's whole unit graph is host units.
host_side_count="$(jq '[.[] | select(.host_side == true)] | length' <<<"$plan_tasks")"
[ "$host_side_count" -eq "$task_count" ] \
    || die "plan minted non-host-side tasks: $(jq -c '[.[] | select(.host_side != true)]' <<<"$plan_tasks")"
HECK_VERSION="$(jq -r '.[] | select(.crate_name == "heck") | .version' <<<"$plan_tasks" | head -1)"
[ -n "$HECK_VERSION" ] \
    || die "plan has no heck task — snafu-derive's host dep was not minted"
jq -e ".[] | select(.crate_name == \"$TASK_CRATE\")" <<<"$plan_tasks" >/dev/null \
    || die "plan has no $TASK_CRATE task"
echo "[mock-e2e] heck version resolved by the plan: $HECK_VERSION"

submit_json="$(curl -fsS --max-time 60 -X POST "$SCHEDULER_URL/tasks/submit" \
    -H "Authorization: Bearer $EDGE_BEARER" \
    -H 'content-type: application/json' \
    --data "$plan_tasks")"
echo "[mock-e2e] submit: $submit_json"

# --- build waves -----------------------------------------------------------
#
# The gate opens a dependent only when the published index serves every
# shape its edge requires — host-side deps of a host-side owner need all
# four (both invocations, both kinds). Publish waves release the queue
# depth-first: each round drains the unblocked tasks, then exports,
# publishes and reports the host slice so the next layer can go.
publish_slice() {
    local target="$1" out="$WORK_DIR/index-$1.bin" tag="$2"
    isolated_env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
        "$BIN/stow-admin" index export \
        --target "$target" \
        --rustc-version "$RUSTC_VERSION" \
        --out "$out" \
        >"$LOG_DIR/index-export-$tag.log" 2>&1 \
        || die "stow-admin index export ($target) failed — see $LOG_DIR/index-export-$tag.log"
    isolated_env \
        STOW_MOCK_PRIVATE_KEY_PATH="$WORK_DIR/keys/private.pem" \
        STOW_MOCK_REGISTRY_ROOT="$WORK_DIR/mock-registry" \
        "$BIN/stow-admin" index publish \
        --file "$out" \
        --target "$target" \
        --rustc-version "$RUSTC_VERSION" \
        >"$LOG_DIR/index-publish-$tag.log" 2>&1 \
        || die "stow-admin index publish ($target) failed — see $LOG_DIR/index-publish-$tag.log"
    isolated_env STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$EDGE_BEARER" \
        "$BIN/stow-admin" index report \
        --file "$out" \
        >"$LOG_DIR/index-report-$tag.log" 2>&1 \
        || die "stow-admin index report ($target) failed — see $LOG_DIR/index-report-$tag.log"
}

deadline=$((SECONDS + TASK_DEADLINE))
wave=0
last_completed=-1
last_publish=0
while :; do
    check_children_alive
    status_json="$(curl -fsS --max-time 10 "$SCHEDULER_URL/status" 2>/dev/null || true)"
    if [ -z "$status_json" ]; then
        sleep 5
        continue
    fi
    pending="$(jq -r '.pending' <<<"$status_json")"
    dispatched="$(jq -r '.dispatched' <<<"$status_json")"
    running="$(jq -r '.running' <<<"$status_json")"
    completed="$(jq -r '.completed' <<<"$status_json")"
    failed="$(jq -r '.failed' <<<"$status_json")"
    echo "[mock-e2e] scheduler: $status_json"
    [ "$failed" -ge 1 ] && die "scheduler reported a failed task: $status_json"
    if [ "$pending" -eq 0 ] && [ "$dispatched" -eq 0 ] && [ "$running" -eq 0 ]; then
        [ "$completed" -eq "$task_count" ] \
            || die "queue drained at $completed completed tasks, expected $task_count"
        break
    fi
    if [ "$pending" -gt 0 ] && [ "$dispatched" -eq 0 ] && [ "$running" -eq 0 ] \
        && { [ "$completed" -gt "$last_completed" ] || [ "$last_publish" -lt "$((SECONDS - 30))" ]; }; then
        # Every dispatched task reported; the pending set is gated on the
        # index — publish the host slice so the next wave releases. The
        # second arm republishes while the queue sits idle-but-pending —
        # the DO's gate re-evaluates per generation, so a publish that
        # landed between evaluations is cheap insurance against a missed
        # wake.
        wave=$((wave + 1))
        echo "[mock-e2e] publishing host slice (wave $wave)"
        publish_slice "$HOST_TARGET" "wave-$wave"
        last_completed="$completed"
        last_publish=$SECONDS
    fi
    [ "$SECONDS" -ge "$deadline" ] \
        && die "scheduler did not finish the graph within ${TASK_DEADLINE}s (last status: ${status_json})"
    sleep 5
done
echo "[mock-e2e] all $task_count tasks completed — the own-node check passed on every build"

# --- catalog assertions ----------------------------------------------------
#
# The catalog's artifacts table must register every host-side unit under
# the host triple with its stamped unit shape — side=host (1), both
# invocations (0=native, 1=target), both kinds (0=unlinked, 1=linked).
d1() {
    wrangler d1 execute stow-mock --local \
        --config "$REPO_ROOT/edge/.skyzen/gen/wrangler.toml" \
        --persist-to "$WORK_DIR/edge-state" \
        --command "$1" --json 2>/dev/null
}

heck_shapes="$(d1 "SELECT DISTINCT unit_invocation, unit_linked FROM artifacts \
    WHERE crate_name = 'heck' AND target = '$HOST_TARGET' AND unit_side = 1")"
echo "[mock-e2e] heck host-side shapes: $(jq -c '.[0].results' <<<"$heck_shapes")"
[ "$(jq '.[0].results | length' <<<"$heck_shapes")" = "2" ] \
    || die "heck host-side rows are not the two linked shapes: $(jq -c '.[0].results' <<<"$heck_shapes")"
for want in '{"unit_invocation":0,"unit_linked":1}' '{"unit_invocation":1,"unit_linked":1}'; do
    jq -e ".[0].results | map({unit_invocation, unit_linked}) | index($want) != null" \
        <<<"$heck_shapes" >/dev/null \
        || die "heck host-side rows miss shape $want"
done

# A host unit must never register under the task's *target* — the pre-#349
# bug shape that produced heck@wasm32 at the consumer's key.
heck_wasm="$(d1 "SELECT count(*) AS n FROM artifacts \
    WHERE crate_name = 'heck' AND target = '$CONSUMER_TARGET'")"
[ "$(jq -r '.[0].results[0].n' <<<"$heck_wasm")" = "0" ] \
    || die "heck registered under $CONSUMER_TARGET — the task-target registration bug is back"

# Every host dep lands under the host triple at host side.
for dep in snafu-derive proc-macro2 quote syn unicode-ident; do
    n="$(d1 "SELECT count(DISTINCT unit_invocation || '-' || unit_linked) AS n FROM artifacts \
        WHERE crate_name = '$dep' AND target = '$HOST_TARGET' AND unit_side = 1" \
        | jq -r '.[0].results[0].n')"
    [ "$n" = "2" ] || die "$dep covers $n host shapes under $HOST_TARGET, expected 2"
done
echo "[mock-e2e] catalog: all host deps register 2 linked shapes under $HOST_TARGET, none under $CONSUMER_TARGET"

# --- consumer repro --------------------------------------------------------
#
# A consumer whose build compiles snafu-derive's host units itself is
# exactly the failure shape. `stow check` serves each unit from the index
# slice of the platform its rustc invocation records — host units come
# from the host slice at the invocation spelling's own key.

# Both slices exist now; wasm32's is empty (no target-side node ever ran)
# but the wasm32 consumer's own units miss on purpose — the crate is not a
# node. Publish the wasm32 slice once so `stow index refresh --target`
# has a tag to pull.
publish_slice "$CONSUMER_TARGET" "final"
publish_slice "$HOST_TARGET" "final"

# The consumer's own `stow check` fetches its slices — the wasm32 check
# ensures the wasm32 AND the host slice it resolves host units from.
# Nothing refreshes the host slice by hand: this lane would mask a
# consumer that never fetches it (stow#367). `index status` asserts the
# fetch happened once the builds ran.
stow_cli index refresh --target "$CONSUMER_TARGET" >"$LOG_DIR/index-refresh-wasm.log" 2>&1 \
    || die "stow index refresh ($CONSUMER_TARGET) failed — see $LOG_DIR/index-refresh-wasm.log"

# A consumer pinned to the exact versions the scheduler just built —
# snafu-derive as an ordinary dependency makes cargo compile the whole
# proc-macro tree as host units of the consumer's build.
CONSUMER="$WORK_DIR/snafu-consumer"
isolated_env cargo new --lib --vcs none "$CONSUMER" >"$LOG_DIR/consumer-new.log" 2>&1 \
    || die "cargo new failed — see $LOG_DIR/consumer-new.log"
# snafu-derive as a normal dependency compiles as the consumer's
# proc-macro host unit; heck under [build-dependencies] compiles as the
# build script's host unit — the two consumer spellings a host-side node
# serves. A declared-but-unused dep still compiles.
printf 'snafu-derive = "=%s"\n\n[build-dependencies]\nheck = "=%s"\n' "$TASK_VERSION" "$HECK_VERSION" \
    >>"$CONSUMER/Cargo.toml"
printf 'fn main() {}\n' >"$CONSUMER/build.rs"

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
(
    cd "$CONSUMER"
    stow_cli setup
) >"$LOG_DIR/stow-setup.log" 2>&1 \
    || die "stow setup failed — see $LOG_DIR/stow-setup.log"

[ -f "$WORK_DIR/cargo-home/config.toml" ] \
    || die "stow setup wrote no $WORK_DIR/cargo-home/config.toml"

# Native consumer: host units at the native invocation spelling.
(
    cd "$CONSUMER"
    stow_cli check
) >"$LOG_DIR/stow-check-native.log" 2>&1 \
    || die "native stow check failed — see $LOG_DIR/stow-check-native.log"

STATE_DB="$WORK_DIR/stow-cache/state-v3.sqlite3"
[ -f "$STATE_DB" ] || die "stow state DB missing at $STATE_DB"
for dep in snafu-derive heck proc-macro2 quote syn unicode-ident; do
    # crate_stats keys the canonical rustc crate name (underscores).
    canonical="${dep//-/_}"
    hits="$(sqlite3 "$STATE_DB" "SELECT COALESCE(SUM(hits),0) FROM crate_stats WHERE crate_name='$canonical'")"
    errors="$(sqlite3 "$STATE_DB" "SELECT COALESCE(SUM(errors),0) FROM crate_stats WHERE crate_name='$canonical'")"
    echo "[mock-e2e] native $dep: hits=$hits errors=$errors"
    [ "$hits" -ge 1 ] || die "$dep was not served from the cache on the native build (hits=$hits)"
    [ "$errors" -eq 0 ] || die "$dep fetch recorded $errors errors on the native build"
done

# wasm32 consumer: the production spelling — host units at the --target
# invocation's own key. The served artifacts land in the same build's own
# target dir, so the second check re-serves them, not re-compiles.
(
    cd "$CONSUMER"
    stow_cli check --target "$CONSUMER_TARGET"
) >"$LOG_DIR/stow-check-wasm.log" 2>&1 \
    || die "wasm32 stow check failed — see $LOG_DIR/stow-check-wasm.log"

for dep in snafu-derive heck proc-macro2 quote syn unicode-ident; do
    canonical="${dep//-/_}"
    hits="$(sqlite3 "$STATE_DB" "SELECT COALESCE(SUM(hits),0) FROM crate_stats WHERE crate_name='$canonical'")"
    errors="$(sqlite3 "$STATE_DB" "SELECT COALESCE(SUM(errors),0) FROM crate_stats WHERE crate_name='$canonical'")"
    echo "[mock-e2e] wasm32 $dep: hits=$hits errors=$errors"
    [ "$hits" -ge 2 ] || die "$dep was not served on the wasm32 build too (total hits=$hits)"
    [ "$errors" -eq 0 ] || die "$dep fetch recorded $errors errors on the wasm32 build"
done

# The wasm32 check had to fetch the host slice itself — assert it landed.
stow_cli index status >"$LOG_DIR/index-status.log" 2>&1 \
    || die "stow index status failed — see $LOG_DIR/index-status.log"
cat "$LOG_DIR/index-status.log"
grep -q "target: $HOST_TARGET" "$LOG_DIR/index-status.log" \
    || die "index status lists no slice for $HOST_TARGET"
grep -q "target: $CONSUMER_TARGET" "$LOG_DIR/index-status.log" \
    || die "index status lists no slice for $CONSUMER_TARGET"

echo "[mock-e2e] OK — snafu-derive 0.9.2's host deps built as host-side nodes, gated on published shapes, and served a native and a wasm32 consumer with the own-node check passing on every task"
