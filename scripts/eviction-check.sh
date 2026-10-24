#!/usr/bin/env bash
# Forced-eviction check for the in-memory scheduler graph (stow#878):
# kill the local workerd in the middle of a dispatch pass, restart it
# over the same persisted Durable Object storage and show that the
# woken scheduler lost no task and dispatched none twice.
#
#   1. start stow-mock-registry (28123), the edge under `wrangler dev`
#      (8788, bundle from `skyzen build --provider cloudflare --manifest
#      edge/Skyzen.mock.toml`) and the local-CI stub (28124)
#   2. seed the budget fixture, engage the dispatch freeze, then clear
#      it: the clear runs a dispatch pass that claims the free slots and
#      posts one `workflow_dispatch` per claim to the stub
#   3. the moment the stub has recorded its first dispatch, SIGKILL
#      workerd and wrangler (the pass dies between its claim row and its
#      last dispatch POST)
#   4. restart wrangler over the same persist dir and read the scheduler
#      back: the wake replays the snapshot and the log tail
#   5. assert the task total is unchanged, no task was dispatched twice
#      (the stub's run list holds each task id once, before and after the
#      restart settles), every dispatched task is claimed in the woken
#      graph, and in-flight stays within the dispatch cap
#
# The mock manifest caps dispatch at 3 for its end-to-end runs; the check
# runs at the production cap (edge/Skyzen.toml) so the fixture's 30 in-flight
# rows leave free slots.
#
# A claim whose dispatch POST never left is not lost: it sits dispatched
# without a run and the stale lease returns it to pending, so the check
# reports how many the kill cut off.
#
# All state lives under one work dir and every child is killed by PID on
# exit. Prerequisites: the host binaries (`cargo build -p stow-admin -p
# stow-build -p stow-mock-registry`), wrangler, jq and curl.
#
# Tunables (env):
#   STOW_EVICTION_WORK_DIR   work dir instead of a fresh mktemp
#   STOW_EVICTION_ROWS       fixture queue rows (default 10000: the smallest fixture whose pending set clears its dependency gates)
#   STOW_EVICTION_READY      seconds to wait for each service (default 240)
set -euo pipefail
set -m

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO_ROOT/target/debug"
EDGE_PORT=8788
INSPECTOR_PORT=9230
REGISTRY_ADDR=127.0.0.1:28123
LOCAL_CI=127.0.0.1:28124
EDGE_URL="http://127.0.0.1:$EDGE_PORT"
ROWS="${STOW_EVICTION_ROWS:-10000}"
READY="${STOW_EVICTION_READY:-240}"
export RUSTUP_TOOLCHAIN=stable

WORK="${STOW_EVICTION_WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/stow-eviction.XXXXXX")}"
mkdir -p "$WORK/logs" "$WORK/edge-state" "$WORK/keys" "$WORK/mock-registry" "$WORK/local-ci"
PIDS=()
die() { echo "eviction-check: $*" >&2; exit 1; }

cleanup() {
    for ((i = ${#PIDS[@]} - 1; i >= 0; i--)); do
        kill -- "-${PIDS[$i]}" 2>/dev/null || true
        kill "${PIDS[$i]}" 2>/dev/null || true
    done
    sleep 2
    for pid in "${PIDS[@]}"; do
        kill -9 -- "-$pid" 2>/dev/null || true
        kill -9 "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

manifest_var() { sed -n "s/^$2 *= *\"\([^\"]*\)\".*/\1/p" "$REPO_ROOT/edge/$1"; }
DISPATCH_LIMIT="$(manifest_var Skyzen.toml STOW_MAX_CONCURRENT_JOBS)"
WEBHOOK_SECRET="$(manifest_var Skyzen.mock.toml STOW_GITHUB_WEBHOOK_SECRET)"
BEARER="${GH_TOKEN:-$(gh auth token 2>/dev/null)}"
[ -n "$DISPATCH_LIMIT" ] && [ -n "$WEBHOOK_SECRET" ] || die "edge manifests carry no dispatch cap or webhook secret"
for tool in jq curl wrangler openssl; do
    command -v "$tool" >/dev/null || die "$tool is required"
done
for bin in stow-mock-registry stow-build stow-admin; do
    [ -x "$BIN/$bin" ] || die "$BIN/$bin is not built"
done

openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/keys/private.pem" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$WORK/keys/private.pem" -out "$WORK/keys/p8.pem" 2>/dev/null
mv "$WORK/keys/p8.pem" "$WORK/keys/private.pem"
openssl ec -in "$WORK/keys/private.pem" -pubout -out "$WORK/keys/public.pem" 2>/dev/null

export WRANGLER_LOG_PATH="$WORK/logs"

"$BIN/stow-mock-registry" serve --registry-root "$WORK/mock-registry" --listen "$REGISTRY_ADDR" \
    >"$WORK/logs/mock-registry.log" 2>&1 &
PIDS+=($!)
(cd "$WORK/local-ci" && exec env STOW_EDGE_URL="$EDGE_URL" STOW_GITHUB_WEBHOOK_SECRET="$WEBHOOK_SECRET" \
    STOW_MOCK_PUBLIC_KEY_PATH="$WORK/keys/public.pem" STOW_MOCK_PRIVATE_KEY_PATH="$WORK/keys/private.pem" \
    STOW_MOCK_REGISTRY_ROOT="$WORK/mock-registry" STOW_LOCAL_CI_STUB=1 \
    "$BIN/stow-build" serve --listen "$LOCAL_CI") >"$WORK/logs/local-ci.log" 2>&1 &
PIDS+=($!)

EDGE_PID=""
start_edge() {
    (cd "$REPO_ROOT/edge" && exec wrangler dev --local --config .skyzen/gen/wrangler.toml \
        --port "$EDGE_PORT" --inspector-port "$INSPECTOR_PORT" --persist-to "$WORK/edge-state" \
        --var "STOW_MAX_CONCURRENT_JOBS:$DISPATCH_LIMIT") \
        >>"$WORK/logs/edge.log" 2>&1 &
    EDGE_PID=$!
    PIDS+=("$EDGE_PID")
}
wait_edge() {
    local deadline=$((SECONDS + READY))
    until curl -s -o /dev/null --max-time 5 "$EDGE_URL/api/v1/scheduler/status"; do
        [ "$SECONDS" -ge "$deadline" ] && die "edge not ready: $(tail -20 "$WORK/logs/edge.log")"
        sleep 1
    done
}
api() { # method path [json]
    curl -sS --max-time 120 -X "$1" "$EDGE_URL$2" -H "authorization: Bearer $BEARER" \
        -H 'content-type: application/json' ${3:+-d "$3"}
}
# Every process below `pid`, depth first, so workerd (a grandchild of
# the wrangler shell) dies with it.
descendants() {
    local child
    for child in $(pgrep -P "$1" 2>/dev/null || true); do
        descendants "$child"
        echo "$child"
    done
}
stub_ids() { curl -s --max-time 5 "http://$LOCAL_CI/tasks" | jq -r '.tasks[].task_id' | sort; }
counts() { api GET /api/v1/scheduler/status; }

start_edge
wait_edge
STOW_EDGE_URL="$EDGE_URL" GH_TOKEN="$BEARER" "$BIN/stow-admin" scheduler reset --yes >/dev/null
# The first heavy request on a freshly started workerd can lose its
# connection; the seed wipes the store first, so repeating it is safe.
SEEDED=""
for attempt in 1 2 3; do
    if SEEDED="$(api POST /api/v1/admin/scheduler/budget/seed "{\"queue_rows\":$ROWS}")" \
        && jq -e '.nodes > 0' <<<"$SEEDED" >/dev/null 2>&1; then
        break
    fi
    echo "seed attempt $attempt failed: $SEEDED" >&2
    SEEDED=""
done
[ -n "$SEEDED" ] || die "the fixture seed failed three times"
api POST /api/v1/admin/dispatch-freeze '{"enabled":true,"reason":"eviction check"}' >/dev/null

BEFORE="$(counts)"
echo "before: $BEFORE"
[ "$(stub_ids | wc -l | tr -d ' ')" -eq 0 ] || die "the stub holds runs before the pass"

# Clearing the freeze runs the dispatch pass inline in this request.
(api POST /api/v1/admin/dispatch-freeze '{"enabled":false}' >"$WORK/logs/unfreeze.out" 2>&1 || true) &
UNFREEZE=$!
PIDS+=("$UNFREEZE")
deadline=$((SECONDS + 60))
until curl -s --max-time 2 "http://$LOCAL_CI/tasks" | grep -q '"task_id"'; do
    [ "$SECONDS" -ge "$deadline" ] && die "the pass dispatched nothing: $(cat "$WORK/logs/unfreeze.out")"
done
for pid in $(descendants "$EDGE_PID") "$EDGE_PID"; do
    kill -9 "$pid" 2>/dev/null || true
done
KILLED_AT="$(stub_ids | wc -l | tr -d ' ')"
echo "killed workerd with $KILLED_AT dispatch(es) recorded"
wait "$UNFREEZE" 2>/dev/null || true

start_edge
wait_edge
AFTER="$(counts)"
echo "after wake: $AFTER"
# The wake's first requests re-bind own runs from the CI listing and a
# second pass may claim: give the stub's webhooks time to settle, then
# read the final state.
sleep 5
FINAL="$(counts)"
echo "settled: $FINAL"

# Every task sits in exactly one of these; `human_pending` is a subset of
# `pending`.
sum() { jq '.pending + .dispatched + .running + .completed + .failed + .blocked' <<<"$1"; }
DISPATCHED=()
while IFS= read -r id; do DISPATCHED+=("$id"); done < <(stub_ids)
UNIQUE="$(printf '%s\n' "${DISPATCHED[@]}" | sort -u | wc -l | tr -d ' ')"
[ "${#DISPATCHED[@]}" -eq "$UNIQUE" ] || die "a task was dispatched twice: ${#DISPATCHED[@]} runs for $UNIQUE tasks"
[ "$(sum "$BEFORE")" -eq "$(sum "$AFTER")" ] || die "the wake changed the task total: $(sum "$BEFORE") -> $(sum "$AFTER")"
for id in "${DISPATCHED[@]}"; do
    status="$(api GET "/api/v1/admin/queue?task_ids=$id" | jq -r '.[0].status')"
    case "$status" in
        dispatched | running | completed | published) ;;
        *) die "dispatched task $id is $status in the woken graph" ;;
    esac
done
INFLIGHT="$(api GET /api/v1/admin/status | jq '.in_flight | length')"
[ "$INFLIGHT" -le "$DISPATCH_LIMIT" ] || die "in-flight $INFLIGHT exceeds the cap $DISPATCH_LIMIT"
echo "eviction-check: ok - ${#DISPATCHED[@]} dispatched once each, total $(sum "$AFTER") unchanged, in-flight $INFLIGHT <= $DISPATCH_LIMIT"
