#!/bin/bash
# Clone + fetch + capture dependency artifacts for one project.
set -uo pipefail
NAME="$1"; VER="$2"; URL="$3"; TAG="$4"
B=/home/user/bench
D=$B/projects/$NAME
if [ ! -d "$D" ]; then
  git clone --depth 1 --branch "$TAG" "$URL" "$D" >/dev/null 2>&1 || { echo "$NAME CLONE_FAIL"; exit 1; }
fi
cd "$D" || exit 1
timeout 900 cargo fetch >/dev/null 2>&1 || { echo "$NAME FETCH_FAIL"; exit 1; }
mkdir -p "$B/work/$NAME"
if [ ! -s "$B/work/$NAME/upload-plan.json" ]; then
  timeout 3600 "$B/capture.sh" "$D" "$NAME" "$VER" "$B/work/$NAME" >"$B/work/$NAME/capture.log" 2>&1 \
    || { echo "$NAME CAPTURE_FAIL"; tail -5 "$B/work/$NAME/capture.log"; rm -rf /tmp/stow-workspaces/*; exit 1; }
fi
timeout 1800 /home/user/stow/target/release/stow-mock-registry populate \
  --upload-plan "$B/work/$NAME/upload-plan.json" \
  --registry-root "$B/registry" --sqlite "$B/work/mock.db" \
  --private-key "$B/keys/mock.key" --public-key "$B/keys/mock.pub" \
  --records-out "$B/work/$NAME/records.json" >"$B/work/$NAME/populate.log" 2>&1 \
  || { echo "$NAME POPULATE_FAIL"; tail -5 "$B/work/$NAME/populate.log"; exit 1; }
rm -rf /tmp/stow-workspaces/* "$D/target"
echo "$NAME OK $(python3 -c "import json;print(len(json.load(open('$B/work/$NAME/records.json'))))")"
