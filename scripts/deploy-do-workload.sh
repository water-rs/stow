#!/usr/bin/env bash
# The deploy-edge Durable Object workload (stow#1022): the promoted
# verdict's DO sample, driven identically on both sides of a deploy —
# against the baseline before the candidate joins the deployment, and
# against the candidate right after promotion.
#
# It requests `GET /api/v1/scheduler/status` (unauthenticated, read-only,
# `no-store`; every call wakes the singleton Scheduler) on a fixed
# schedule of STOW_DO_WORKLOAD_RPS requests a second, each with a query
# string unique to the run, side and probe so no cache can answer it
# (stow#749). The measured window opens on the first whole minute at least
# 60 s after the first request and lasts STOW_DO_WORKLOAD_MINUTES whole
# minutes: the warm-up absorbs the request that hydrates an object the
# version change reset, so neither window holds a cold hydration, and the
# deployment change has propagated before the window opens. Whole minutes
# because the verdict's periodic dataset may bucket no finer.
#
# The window's end bound is written one second before the minute boundary
# — the verdict filters with `datetime_leq`, and a periodic row stamped
# on the boundary covers the minute after — and the schedule stops there.
#
#   scripts/deploy-do-workload.sh <baseline|candidate>
#
# Writes `do_window_from` and `do_window_to` (RFC 3339) to $GITHUB_OUTPUT.
# A probe answering anything but 200 fails the script.
set -euo pipefail

side=${1:?usage: deploy-do-workload.sh <baseline|candidate>}
case "$side" in
  baseline | candidate) ;;
  *)
    echo "::error::side must be baseline or candidate, got '$side'" >&2
    exit 1
    ;;
esac
: "${STOW_EDGE_URL:?STOW_EDGE_URL is required}"
: "${STOW_DO_WORKLOAD_RPS:?STOW_DO_WORKLOAD_RPS is required}"
: "${STOW_DO_WORKLOAD_MINUTES:?STOW_DO_WORKLOAD_MINUTES is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"

now_ms() { date -u +%s%3N; }
rfc3339() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }

interval_ms=$((1000 / STOW_DO_WORKLOAD_RPS))
start_ms=$(now_ms)
from_s=$(((start_ms / 1000 + 60 + 59) / 60 * 60))
to_s=$((from_s + STOW_DO_WORKLOAD_MINUTES * 60 - 1))
stop_ms=$((to_s * 1000))

echo "DO workload ($side): $STOW_DO_WORKLOAD_RPS req/s, window $(rfc3339 "$from_s") .. $(rfc3339 "$to_s")"

next_ms=$start_ms
probe=0
in_window=0
while :; do
  now=$(now_ms)
  if [ "$now" -ge "$stop_ms" ]; then
    break
  fi
  if [ "$now" -lt "$next_ms" ]; then
    wait_ms=$((next_ms - now))
    sleep "$((wait_ms / 1000)).$(printf '%03d' $((wait_ms % 1000)))"
    continue
  fi
  probe=$((probe + 1))
  next_ms=$((next_ms + interval_ms))
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 --retry 2 \
    "$STOW_EDGE_URL/api/v1/scheduler/status?deploy-do-workload=$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$side-$probe")
  if [ "$code" != 200 ]; then
    echo "::error::DO workload probe $probe answered $code" >&2
    exit 1
  fi
  if [ "$now" -ge $((from_s * 1000)) ]; then
    in_window=$((in_window + 1))
  fi
done

echo "DO workload ($side): $probe requests, $in_window inside the window"
{
  echo "do_window_from=$(rfc3339 "$from_s")"
  echo "do_window_to=$(rfc3339 "$to_s")"
} >> "$GITHUB_OUTPUT"
