#!/bin/bash
# Capture dependency artifacts for one project checkout via the trusted CI builder.
set -euo pipefail
PROJ_DIR="$1"; NAME="$2"; VER="$3"; OUT="$4"
BIN=/home/user/stow/target/release
mkdir -p "$OUT"
export STOW_BUILD_SOURCE_ROOT="$PROJ_DIR"
export STOW_BUILD_ONLY=1
# Honour a project's rust-toolchain pin: artifacts built with a different
# compiler can never match what the user's cargo will invoke.
RUSTC_VER=$(cd "$PROJ_DIR" && rustc --version | awk '{print $2}')
export STOW_BUILD_TASK_JSON='{"task_id":"t-'"$NAME"'","crate_name":"'"$NAME"'","version":"'"$VER"'","features_json":"[\"default\"]","target":"x86_64-unknown-linux-gnu","rustc_version":"'"$RUSTC_VER"'","preserve_lockfile":true}'
export STOW_SCAN_OUTPUT_PATH="$OUT/scan.json"
export STOW_UPLOAD_PLAN_PATH="$OUT/upload-plan.json"
export STOW_BUILD_CARGO_SUBCOMMAND="${STOW_BUILD_CARGO_SUBCOMMAND:-build}"
exec "$BIN/stow-build"
