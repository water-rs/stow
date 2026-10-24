#!/usr/bin/env bash
# The production wave's size (stow#775): how many distinct nodes the
# production preheat lanes submit, which the monthly projection
# (`stow-admin traffic-cost project`, the release gate's `Monthly
# projection` job) scales the Preheat cost job's measured per-node costs
# to.
#
#   1. build stow-admin (release) and make sure the rustup toolchain the
#      resolver pins to the stable version is installed
#   2. read the `limit` and `targets` input defaults of
#      .github/workflows/preheat-admin.yml — the wave production runs
#   3. run the two lanes preheat-admin.yml runs — `preheat
#      top-binaries` and `preheat projects submit` over the
#      reviewed preheat/projects.toml — plan-only and concurrently (they
#      are independent): without `--yes` a lane resolves and prints the
#      tasks it would submit and never connects to an edge, so there is
#      no mock stack, no edge and no credential
#   4. `stow-admin preheat cost production` counts the distinct task
#      identities across the lanes and writes
#      $WORK_DIR/production-wave.json; it fails when a lane exited
#      non-zero or planned nothing, because either understates the wave
#
# Why its own job: the dump download plus the resolve takes minutes for
# the binaries lane and up to 100 for the projects lane in production,
# and beside the Preheat cost job's wave it competed for the runner's
# CPUs until that job's timeout. Here nothing else runs.
#
# Every child is bounded by a deadline and killed with its process
# group on exit; a lane that passes its deadline exits 124, which the
# count refuses.
#
# Tunables (env):
#   STOW_PRODUCTION_WAVE_WORK_DIR  work dir instead of a fresh mktemp
#                                  (must be empty)
#   STOW_PRODUCTION_WAVE_LIMIT     --limit of `preheat top-binaries`
#                                  (default: the `limit` input's default
#                                  in preheat-admin.yml)
#   STOW_PRODUCTION_WAVE_TARGETS   comma-separated --targets of every lane
#                                  (default: the `targets` input's
#                                  default in preheat-admin.yml)
#   STOW_PRODUCTION_WAVE_DEADLINE  seconds each lane may take before it
#                                  is killed (default 3300)
#   STOW_RESOLVE_CARGO_HOME        the root every lane's resolve
#                                  CARGO_HOMEs live under — lane <NN>-<name>
#                                  resolves against <root>/<NN>-<name>, so
#                                  the lanes stay parallel while a CI
#                                  cache restoring the root keeps the
#                                  index and .crate bodies warm across
#                                  runs (default: $WORK_DIR/resolve-cargo,
#                                  per-run scratch)
#   STOW_E2E_TOOLCHAIN             rustup toolchain for the run (default:
#                                  stable)
set -euo pipefail
# Every lane in its own process group, so the cleanup trap can kill
# whole trees by PGID.
set -m

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREHEAT_ADMIN_WORKFLOW="$REPO_ROOT/.github/workflows/preheat-admin.yml"
LANE_DEADLINE="${STOW_PRODUCTION_WAVE_DEADLINE:-3300}"

export RUSTUP_TOOLCHAIN="${STOW_E2E_TOOLCHAIN:-stable}"

if [ -n "${STOW_PRODUCTION_WAVE_WORK_DIR:-}" ]; then
    WORK_DIR="$STOW_PRODUCTION_WAVE_WORK_DIR"
    if [ -e "$WORK_DIR" ] && [ -n "$(ls -A "$WORK_DIR" 2>/dev/null)" ]; then
        echo "[production-wave] STOW_PRODUCTION_WAVE_WORK_DIR $WORK_DIR is not empty" >&2
        exit 1
    fi
    mkdir -p "$WORK_DIR"
else
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stow-production-wave.XXXXXX")"
fi
LOG_DIR="$WORK_DIR/logs"
LANES_DIR="$WORK_DIR/lanes"
# The resolve root sits beside the lane scratch, never inside it: the
# gate restores it from `actions/cache`, and a restored tree must not
# trip the empty-WORK_DIR check above. Each lane gets its own
# subdirectory — the lanes run concurrently and a worker's resolve holds
# cargo's exclusive package-cache lock, so lanes sharing one home would
# serialize against each other.
RESOLVE_ROOT="${STOW_RESOLVE_CARGO_HOME:-$WORK_DIR/resolve-cargo}"
mkdir -p "$LOG_DIR" "$LANES_DIR" "$RESOLVE_ROOT"

LANE_PIDS=()

die() {
    echo "[production-wave] ERROR: $*" >&2
    exit 1
}

log() {
    echo "[production-wave] $*"
}

# All PIDs below $1, recursively. Printed one per line.
descendants() {
    local child
    for child in $(pgrep -P "$1" 2>/dev/null); do
        descendants "$child"
        echo "$child"
    done
}

# `timeout` moves its command to a group of its own, so the lane's
# group alone would leave the resolve running: kill every descendant
# by PID as well.
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    local victims=() pid kid
    for pid in ${LANE_PIDS[@]+"${LANE_PIDS[@]}"}; do
        for kid in $(descendants "$pid"); do
            victims+=("$kid")
        done
        victims+=("$pid")
        kill -- "-$pid" 2>/dev/null || true
    done
    if [ ${#victims[@]} -gt 0 ]; then
        kill "${victims[@]}" 2>/dev/null || true
        kill -9 "${victims[@]}" 2>/dev/null || true
    fi
    log "logs: $LOG_DIR; lanes: $LANES_DIR"
    exit "$status"
}
trap cleanup EXIT INT TERM

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found on PATH: $1"
}

require_command cargo
require_command rustc
require_command rustup
require_command timeout
require_command yq

# The production wave is the one preheat-admin.yml runs, so its defaults
# come from that file rather than a copy here. preheat-cron.yml
# dispatches it with the projects lane on, so both lanes count.
workflow_default() {
    yq ".on.workflow_dispatch.inputs.$1.default" "$PREHEAT_ADMIN_WORKFLOW"
}
LIMIT="${STOW_PRODUCTION_WAVE_LIMIT:-$(workflow_default limit)}"
TARGETS="${STOW_PRODUCTION_WAVE_TARGETS:-$(workflow_default targets | tr ' ' ',')}"
for value in "$LIMIT" "$TARGETS"; do
    case "$value" in
        "" | null) die "could not read the limit and targets from $PREHEAT_ADMIN_WORKFLOW" ;;
    esac
done
RUSTC_VERSION="$(rustc --version | awk '{print $2}')"
[ -n "$RUSTC_VERSION" ] || die "could not detect the rustc version"

# The resolver pins its rustc to the rustup toolchain named by the
# version (`rustup which --toolchain`), so a toolchain under that exact
# version must exist (scripts/mock-e2e.sh has the reasoning).
if ! RUSTUP_TOOLCHAIN="$RUSTC_VERSION" rustc --version >/dev/null 2>&1; then
    log "installing rustup toolchain '$RUSTC_VERSION' for the resolver's pin"
    rustup toolchain install --profile minimal "$RUSTC_VERSION" \
        || die "could not install rustup toolchain '$RUSTC_VERSION'"
fi

log "work dir: $WORK_DIR"
log "resolve root: $RESOLVE_ROOT"
log "rustc $RUSTC_VERSION; limit $LIMIT; targets $TARGETS; lane deadline ${LANE_DEADLINE}s"

cd "$REPO_ROOT"
log "building stow-admin"
cargo build --release -p stow-admin >"$LOG_DIR/cargo-build.log" 2>&1 \
    || die "cargo build failed — see $LOG_DIR/cargo-build.log"
BIN="$REPO_ROOT/target/release"

# One lane, plan-only: preheat-admin.yml's invocation without `--yes`.
# A lane's failure is recorded in its `exit` file, never fatal here — the
# count refuses it, naming the lane.
plan_lane() {
    local order="$1" lane="$2" status=0
    shift 2
    local dir="$LANES_DIR/$order-$lane"
    mkdir -p "$dir"
    STOW_RESOLVE_CARGO_HOME="$RESOLVE_ROOT/$order-$lane" \
        timeout --kill-after=30 "$LANE_DEADLINE" \
        "$BIN/stow-admin" --json preheat "$@" >"$dir/plan.json" 2>"$dir/stderr.log" || status=$?
    echo "$status" >"$dir/exit"
    log "lane $lane exited $status"
    [ "$status" -eq 0 ] || echo "[production-wave] lane $lane exited $status — see $dir/stderr.log" >&2
}

LANE_NAMES=()

start_lane() {
    plan_lane "$@" &
    LANE_PIDS+=("$!")
    LANE_NAMES+=("$2")
    log "started lane $2 (pid $!)"
}

start_lane 01 top-binaries top-binaries \
    --targets "$TARGETS" --rustc-version "$RUSTC_VERSION" --limit "$LIMIT"
start_lane 02 projects projects submit \
    --file "$REPO_ROOT/preheat/projects.toml" \
    --targets "$TARGETS" --rustc-version "$RUSTC_VERSION"

for i in "${!LANE_PIDS[@]}"; do
    wait "${LANE_PIDS[$i]}" || die "lane runner ${LANE_NAMES[$i]} failed"
done

"$BIN/stow-admin" preheat cost production \
    --lanes-dir "$LANES_DIR" \
    --out "$WORK_DIR/production-wave.json" \
    | tee "$LOG_DIR/production-wave.log" \
    || die "the production wave count failed — see $LANES_DIR/*/stderr.log"
log "production wave: $WORK_DIR/production-wave.json"
