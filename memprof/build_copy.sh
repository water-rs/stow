#!/bin/bash
# usage: build_copy.sh <stow worktree> <build name>
# Release-builds the edge worker (skyzen, Skyzen.mock.toml) and snapshots the
# bundle + generated wrangler config under $MEMPROF_DIR/<build name>.
set -euo pipefail
D=${MEMPROF_DIR:-$HOME/memprof}; mkdir -p "$D/out"
export PATH="$HOME/node/bin:$HOME/.cargo/bin:$PATH"
(cd "$1/edge" && skyzen build -m Skyzen.mock.toml -p cloudflare --release) > "$D/out/build-$2.log" 2>&1
rm -rf "$D/$2" && mkdir -p "$D/$2/.skyzen"
cp -r "$1"/edge/{stable-worker.js,stable-worker_bg.js,stable-worker_bg.wasm,migrations} "$D/$2/"
cp -r "$1"/edge/.skyzen/gen "$D/$2/.skyzen/"
