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
# 60 s after the first request on `baseline` (already warm) and 330 s on
# `candidate` (past `durableObjectsPeriodicGroups`'s 5-minute periodic
# flush, so the cold `wake_graph` SQLite hydration after version reset
# flushes before `do_window_from`, stow#1669) and lasts
# STOW_DO_WORKLOAD_MINUTES whole minutes. Whole minutes because the
# verdict's periodic dataset may bucket no finer.
#
# The window's end bound is written one second before the minute boundary
# — the verdict filters with `datetime_leq`, and a periodic row stamped
# on the boundary covers the minute after — and the schedule stops there.
#
# On the candidate side the edge moves first and the Scheduler object
# follows minutes later, switching code between the two releases — each
# switch a fresh hydration — before it settles. Every probe reads the
# object's own `scheduler_release_tag`; one that is not
# STOW_DO_WORKLOAD_EXPECT_TAG restarts the warm-up, so the window opens
# only after a full warm-up of the object on the candidate's code, and
# the run fails once STOW_DO_WORKLOAD_SETTLE_MINUTES pass without one.
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

if [ "$side" = candidate ]; then
  : "${STOW_DO_WORKLOAD_EXPECT_TAG:?STOW_DO_WORKLOAD_EXPECT_TAG is required on the candidate side}"
  : "${STOW_DO_WORKLOAD_SETTLE_MINUTES:?STOW_DO_WORKLOAD_SETTLE_MINUTES is required on the candidate side}"
  warmup_s=330
else
  warmup_s=60
fi

interval_ms=$((1000 / STOW_DO_WORKLOAD_RPS))
start_ms=$(now_ms)
body=$(mktemp)

# Open the window on the first whole minute at least $warmup_s s after `$1` (ms).
open_window() {
  from_s=$((($1 / 1000 + warmup_s + 59) / 60 * 60))
  to_s=$((from_s + STOW_DO_WORKLOAD_MINUTES * 60 - 1))
  stop_ms=$((to_s * 1000))
}
open_window "$start_ms"
settle_deadline_ms=$((start_ms + ${STOW_DO_WORKLOAD_SETTLE_MINUTES:-0} * 60000))

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
  code=$(curl -sS -o "$body" -w '%{http_code}' --max-time 10 --retry 2 --retry-all-errors \
    "$STOW_EDGE_URL/api/v1/scheduler/status?deploy-do-workload=$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$side-$probe")
  if [ "$code" != 200 ]; then
    echo "::error::DO workload probe $probe answered $code" >&2
    exit 1
  fi
  if [ "$side" = candidate ]; then
    object_tag=$(jq -r '.scheduler_release_tag // "none"' "$body")
    if [ "$object_tag" != "$STOW_DO_WORKLOAD_EXPECT_TAG" ]; then
      if [ "$now" -ge "$settle_deadline_ms" ]; then
        echo "::error::the Scheduler object still runs $object_tag, not $STOW_DO_WORKLOAD_EXPECT_TAG, $STOW_DO_WORKLOAD_SETTLE_MINUTES minutes after the promotion" >&2
        exit 1
      fi
      previous_from=$from_s
      open_window "$now"
      in_window=0
      if [ "$from_s" != "$previous_from" ]; then
        echo "DO workload ($side): probe $probe reached the object on $object_tag; window moved to $(rfc3339 "$from_s") .. $(rfc3339 "$to_s")"
      fi
      continue
    fi
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
