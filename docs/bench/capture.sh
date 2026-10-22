#!/bin/bash
# Capture dependency artifacts for one project checkout via the trusted CI builder.
set -euo pipefail
PROJ_DIR="$1"; NAME="$2"; VER="$3"; OUT="$4"
BIN=/home/user/stow/target/release
# Honour a project's rust-toolchain pin: artifacts built with a different
# compiler can never match what the user's cargo will invoke.
RUSTC_VER=$(cd "$PROJ_DIR" && rustc --version | awk '{print $2}')
export STOW_BUILD_CARGO_SUBCOMMAND="${STOW_BUILD_CARGO_SUBCOMMAND:-build}"
# stow-build reads leg `--leg` of the dispatched batch from the
# `workflow_dispatch` event file ($GITHUB_EVENT_PATH, `.inputs.batch`),
# exactly as a build-batch.yml leg does. The batch and leg ids below are
# fixed well-formed values — the same kind the in-repo fixtures use —
# since the leg hash only binds a run's jobs page to legs, and a local
# capture produces no jobs page. BatchId/TaskHash reject anything but
# fixed-width lowercase hex.
BATCH='{"batch_id":"0123456789abcdef0123456789abcdef","rustc_version":"'"$RUSTC_VER"'","parallelism":1,"tasks":[{"i":0,"h":"0123456789abcdef","task_id":"t-'"$NAME"'","crate_name":"'"$NAME"'","version":"'"$VER"'","features_json":"[\"default\"]","target":"x86_64-unknown-linux-gnu","explicit_spelling":"keys-as-native","preserve_lockfile":true}],"nodes":[]}'
# The event file is the JSON-encoded batch nested in `inputs.batch` —
# python3 (already a bench-lane tool) does the string escaping.
EVENT=$(mktemp)
python3 -c 'import json, sys; json.dump({"inputs": {"batch": sys.argv[1]}}, open(sys.argv[2], "w"))' \
  "$BATCH" "$EVENT"
export GITHUB_EVENT_PATH="$EVENT"
# The build stage writes scan.json, upload-plan.json and blobs/ into $OUT.
exec "$BIN/stow-build" build --leg 0 --output-dir "$OUT"
