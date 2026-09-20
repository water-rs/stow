#!/usr/bin/env bash
# Drive the docs/MOCK.md recipe end-to-end on loopback:
#
#   1. build the four host binaries and generate a P-256 PKCS#8 key pair
#   2. start stow-mock-registry (40123), the edge under `wrangler dev`
#      (workerd, 8788; bundle built by `skyzen build`), and
#      `stow-build serve` (40124)
#   3. submit one small registry crate (itoa, latest 1.0.x, host target)
#      through `stow-admin` and wait for the scheduler to report completion
#   4. `stow check` a throwaway consumer crate in mock-key verify mode and
#      assert the dependency was served from the cache
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
        echo "[mock-e2e] FAILED (exit $status) — log tails:" >&2
        local log
        for log in "$LOG_DIR"/*.log; do
            [ -e "$log" ] || continue
            echo "===== $log =====" >&2
            tail -n 80 "$log" >&2 || true
        done
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
# mode, and the run's edge URL — so nothing falls back to the developer's
# real stow config.toml.
stow_cli() {
    isolated_env \
        STOW_EDGE_URL="$EDGE_URL" \
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

# `skyzen dev` compiles the edge to wasm32 on the run's toolchain.
if ! rustup target list --installed --toolchain "$RUSTUP_TOOLCHAIN" \
    | grep -qx wasm32-unknown-unknown; then
    echo "[mock-e2e] installing wasm32-unknown-unknown for $RUSTUP_TOOLCHAIN"
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" wasm32-unknown-unknown
fi

cd "$REPO_ROOT"
echo "[mock-e2e] building stow-cli, stow-build, stow-mock-registry, stow-admin"
cargo build -p stow-cli --features mock-verify -p stow-build -p stow-mock-registry -p stow-admin \
    >"$LOG_DIR/cargo-build.log" 2>&1
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
wait_for "mock registry /v2/" 60 "$SERVICE_PID" curl -fsS "http://${REGISTRY_ADDR}/v2/"

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
# local D1 gets the same files the production pipeline applies. All files are
# idempotent, so re-running them against a persisted edge-state dir is safe.
for migration in "$REPO_ROOT/edge/migrations"/*.sql; do
    wrangler d1 execute stow-mock --local \
        --config "$REPO_ROOT/edge/.skyzen/gen/wrangler.toml" \
        --persist-to "$WORK_DIR/edge-state" \
        --file "$migration" >>"$LOG_DIR/edge-migrate.log" 2>&1 \
        || die "edge migration $migration failed — see $LOG_DIR/edge-migrate.log"
done
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

# Latest non-yanked 1.0.x on crates.io.
TASK_VERSION="$(curl -fsS --max-time 30 -H 'User-Agent: stow-mock-e2e' \
    'https://crates.io/api/v1/crates/itoa' \
    | jq -r '[.versions[] | select(.yanked | not) | .num | select(startswith("1.0."))]
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
    >"$LOG_DIR/admin-submit.log" 2>&1

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

# Throwaway consumer pinned to the exact version the scheduler just built.
CONSUMER="$WORK_DIR/itoa-consumer"
isolated_env cargo new --lib --vcs none "$CONSUMER" >"$LOG_DIR/consumer-new.log" 2>&1
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
) >"$LOG_DIR/consumer-fetch.log" 2>&1

(
    cd "$CONSUMER"
    stow_cli check
) >"$LOG_DIR/stow-check.log" 2>&1

# `stow status` needs the project's .cargo/config.toml to exist; `stow
# setup` writes it. Both run inside the throwaway dir under the work dir.
(
    cd "$CONSUMER"
    stow_cli setup
) >"$LOG_DIR/stow-setup.log" 2>&1
(
    cd "$CONSUMER"
    stow_cli status
) >"$LOG_DIR/stow-status.log" 2>&1
cat "$LOG_DIR/stow-status.log"

STATE_DB="$WORK_DIR/stow-cache/state-v3.sqlite3"
[ -f "$STATE_DB" ] || die "stow state DB missing at $STATE_DB"
hits="$(sqlite3 "$STATE_DB" "SELECT COALESCE(SUM(hits),0) FROM crate_stats WHERE crate_name='$TASK_CRATE'")"
errors="$(sqlite3 "$STATE_DB" "SELECT COALESCE(SUM(errors),0) FROM crate_stats WHERE crate_name='$TASK_CRATE'")"
echo "[mock-e2e] $TASK_CRATE cache stats: hits=$hits errors=$errors"
[ "$hits" -ge 1 ] || die "$TASK_CRATE was not served from the cache (hits=$hits)"
[ "$errors" -eq 0 ] || die "$TASK_CRATE fetch recorded $errors errors"

# The exact `c_metadata` fetch proved the hit; also prove the semantic
# path — the identity the consumer's graph analysis computes — resolves
# the same row. itoa declares no features, so the resolved feature set is
# `[]`; a features_json column drift would surface here as a 404.
semantic_status="$(curl -s -o "$WORK_DIR/semantic-response.bin" -w '%{http_code}' \
    --max-time 30 -X POST "$EDGE_URL/api/v1/artifacts/semantic" \
    -H 'content-type: application/json' \
    --data "$(jq -nc \
        --arg crate "$TASK_CRATE" \
        --arg version "$TASK_VERSION" \
        --arg target "$HOST_TARGET" \
        --arg rustc "$RUSTC_VERSION" \
        '{
            crate_name: $crate,
            version: $version,
            features_json: "[]",
            dependency_c_metadata_json: "[]",
            target: $target,
            rustc_version: $rustc,
            profile: {
                opt_level: "0",
                debuginfo: 1,
                debug_assertions: true,
                overflow_checks: true,
                panic: "Unwind"
            },
            emit: ["dep-info", "metadata"],
            kind: "Rlib",
            crate_types: ["lib"]
        }')")"
echo "[mock-e2e] semantic artifact lookup: HTTP $semantic_status"
[ "$semantic_status" = "200" ] \
    || die "semantic artifact lookup returned HTTP $semantic_status (expected 200)"

echo "[mock-e2e] OK — $TASK_CRATE $TASK_VERSION served from the mock cache"
