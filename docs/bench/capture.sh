#!/bin/bash
# Capture dependency artifacts for one project checkout via the trusted CI builder.
set -euo pipefail
PROJ_DIR="$1"; NAME="$2"; VER="$3"; OUT="$4"
BIN=/home/user/stow/target/release
# Honour a project's rust-toolchain pin: artifacts built with a different
# compiler can never match what the user's cargo will invoke.
RUSTC_VER=$(cd "$PROJ_DIR" && rustc --version | awk '{print $2}')
export STOW_BUILD_CARGO_SUBCOMMAND="${STOW_BUILD_CARGO_SUBCOMMAND:-build}"
# stow-build reads its task from the `workflow_dispatch` event file
# ($GITHUB_EVENT_PATH, `.inputs.task`), exactly as a build-crate.yml run
# does. The task id below is a fixed well-formed value — the same kind
# the in-repo fixtures use — a local capture produces no jobs page.
TASK='{"task_id":"t-'"$NAME"'","attempt":1,"crate_name":"'"$NAME"'","version":"'"$VER"'","features_json":"[\"default\"]","target":"x86_64-unknown-linux-gnu","rustc_version":"'"$RUSTC_VER"'","preserve_lockfile":true,"host_side":false,"explicit_spelling":"keys-as-native","dependency_subgraph":{"r":[],"n":[]}}'
# The event file is the JSON-encoded task nested in `inputs.task` —
# python3 (already a bench-lane tool) does the string escaping.
EVENT=$(mktemp)
python3 -c 'import json, sys; json.dump({"inputs": {"task": sys.argv[1]}}, open(sys.argv[2], "w"))' \
  "$TASK" "$EVENT"
export GITHUB_EVENT_PATH="$EVENT"
# The build stage writes scan.json, upload-plan.json and blobs/ into $OUT.
exec "$BIN/stow-build" build --output-dir "$OUT"
