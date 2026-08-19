#!/bin/bash
# One project at a time: prepare -> serve -> benchmark -> purge.
set -uo pipefail
B=/home/user/bench
while IFS="|" read -r n v u t; do
  [ -z "$n" ] && continue
  [ -f "$B/results/done-$n" ] && { echo "SKIP $n"; continue; }
  echo "=== $n ==="
  if ! "$B/prepare.sh" "$n" "$v" "$u" "$t"; then
    echo "$n PREPARE_FAILED"; rm -rf "$B/projects/$n" "$B/work/$n" /tmp/stow-workspaces/*; continue
  fi
  pkill -f edge_stub.py; sleep 1
  setsid nohup python3 "$B/edge_stub.py" "$B/registry" "$B/work/$n/records.json" 8787 > "$B/work/edge-$n.log" 2>&1 < /dev/null &
  sleep 3
  rm -rf "$B/work/cache"
  "$B/run_bench.sh" "$n" "$B/projects/$n" "$B/work/$n/records.json" 2>&1 | tail -1
  touch "$B/results/done-$n"
  # purge everything project-specific so disk stays flat
  rm -rf "$B/registry" "$B/work/cache" "$B/work/mock.db"* "$B/projects/$n" /tmp/stow-workspaces/*
  rm -f "$B/work/$n/upload-plan.json" "$B/work/$n/scan.json"
  df -h / | tail -1
done < "$B/projects.txt"
echo PIPELINE_DONE
