#!/bin/bash
# One project at a time: prepare -> serve -> benchmark -> purge.
set -uo pipefail
B=/home/user/bench
while IFS="|" read -r n v u t; do
  [ -z "$n" ] && continue
  [ -f "$B/results/done-$n" ] && { echo "SKIP $n"; continue; }
  echo "=== $n ==="
  # Stop the previous project's registry before capturing: a concurrent
  # serve keeps the prior project's blobs open while the next capture
  # competes for RAM with a 4-way-parallel cargo build.
  if [ -f "$B/work/registry.pid" ]; then
    kill "$(cat "$B/work/registry.pid")" 2>/dev/null; sleep 1
    rm -f "$B/work/registry.pid"
  fi
  if ! "$B/prepare.sh" "$n" "$v" "$u" "$t"; then
    echo "$n PREPARE_FAILED"; rm -rf "$B/projects/$n" "$B/work/$n" /tmp/stow-workspaces/*; continue
  fi
  # The consumer resolves through the signed local index: build the slice
  # from this project's records and publish it into the registry root,
  # then serve the root over the OCI protocol.
  /home/user/stow/target/release/stow-mock-registry index-from-records \
    --records "$B/work/$n/records.json" \
    --registry-root "$B/registry" \
    --private-key "$B/keys/mock.key" \
    > "$B/work/$n/index.log" 2>&1 || { echo "$n INDEX_FAILED"; continue; }
  nohup /home/user/stow/target/release/stow-mock-registry serve \
    --registry-root "$B/registry" > "$B/work/registry-$n.log" 2>&1 < /dev/null &
  echo $! > "$B/work/registry.pid"
  sleep 3
  rm -rf "$B/work/cache"
  "$B/run_bench.sh" "$n" "$B/projects/$n" "$B/work/$n/records.json" 2>&1 | tail -1
  touch "$B/results/done-$n"
  # purge everything project-specific so disk stays flat
  rm -rf "$B/registry" "$B/work/cache" "$B/projects/$n" /tmp/stow-workspaces/*
  rm -f "$B/work/$n/upload-plan.json" "$B/work/$n/scan.json"
  df -h / | tail -1
done < "$B/projects.txt"
echo PIPELINE_DONE
