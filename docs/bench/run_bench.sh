#!/bin/bash
# Benchmark one project: plain cargo vs stow vs deps-prebuilt floor.
# usage: run_bench.sh <name> <project_dir> <records.json>
set -uo pipefail
NAME="$1"; DIR="$2"; RECORDS="$(readlink -f "$3")"
BIN=/home/user/stow/target/release
OUT=/home/user/bench/results
mkdir -p "$OUT"

export STOW_EDGE_URL=http://127.0.0.1:8787
export STOW_VERIFY_MODE=mock-key
export STOW_MOCK_PUBLIC_KEY_PATH=/home/user/bench/keys/mock.pub
export STOW_CACHE_DIR=/home/user/bench/work/cache
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost
export CARGO_INCREMENTAL=0

cd "$DIR" || exit 1

t() { # t <logfile> <cmd...>
  local log="$1"; shift
  local s=$(date +%s.%N)
  "$@" > "$log" 2>&1
  local rc=$?
  local e=$(date +%s.%N)
  echo "$(echo "$e - $s" | bc) $rc"
}

units() { grep -cE "^[[:space:]]+Compiling " "$1" 2>/dev/null | head -1 || true; }
hits() { curl -s --noproxy 127.0.0.1 http://127.0.0.1:8787/__stats; }

rm -rf target target-plain .cargo

# --- 1. plain cargo, cold ---
export CARGO_TARGET_DIR="$DIR/target-plain"
read PLAIN_T PLAIN_RC <<< "$(t $OUT/$NAME.plain.log cargo build)"
PLAIN_U=$(units $OUT/$NAME.plain.log)

# --- 2. floor: only workspace members recompiled, deps already built ---
MEMBERS=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | python3 -c "import json,sys;print(' '.join(p['name'] for p in json.load(sys.stdin)['packages']))")
for m in $MEMBERS; do cargo clean -p "$m" >/dev/null 2>&1; done
rm -rf "$CARGO_TARGET_DIR"/*/incremental "$CARGO_TARGET_DIR"/incremental 2>/dev/null
read FLOOR_T FLOOR_RC <<< "$(t $OUT/$NAME.floor.log cargo build)"
FLOOR_U=$(units $OUT/$NAME.floor.log)
rm -rf "$CARGO_TARGET_DIR"
unset CARGO_TARGET_DIR

# --- 3. stow, warm artifact cache (warm-up run then measured run) ---
"$BIN/stow-cli" build > /dev/null 2>&1
rm -rf target
read STOW_T STOW_RC <<< "$(t $OUT/$NAME.stow.log $BIN/stow-cli build)"
STOW_U=$(units $OUT/$NAME.stow.log)

# --- 4. stow with the resolver disabled ---
rm -rf target
read STOWNR_T STOWNR_RC <<< "$(t $OUT/$NAME.stow-nr.log $BIN/stow-cli build --no-stow-resolver)"
STOWNR_U=$(units $OUT/$NAME.stow-nr.log)

for rc in "$PLAIN_RC" "$FLOOR_RC" "$STOW_RC" "$STOWNR_RC"; do
  [ "$rc" = 0 ] || echo "!!! $NAME: a measured build FAILED (rc=$rc) — timings are meaningless"
done
rm -rf target target-plain

COVERAGE=$(grep -h "^stow: " "$OUT/$NAME.stow.log" | tail -1)
python3 - "$NAME" "$PLAIN_T" "$PLAIN_U" "$PLAIN_RC" "$FLOOR_T" "$FLOOR_U" "$FLOOR_RC" \
  "$STOW_T" "$STOW_U" "$STOW_RC" "$STOWNR_T" "$STOWNR_U" "$STOWNR_RC" "$RECORDS" "$COVERAGE" <<'PY'
import json, sys
k=sys.argv
rec=json.load(open(k[14]))
row=dict(project=k[1],
         plain_s=round(float(k[2]),2), plain_units=int(k[3]), plain_rc=int(k[4]),
         floor_s=round(float(k[5]),2), floor_units=int(k[6]), floor_rc=int(k[7]),
         stow_s=round(float(k[8]),2), stow_units=int(k[9]), stow_rc=int(k[10]),
         stow_nr_s=round(float(k[11]),2), stow_nr_units=int(k[12]), stow_nr_rc=int(k[13]),
         cached_artifacts=len(rec),
         coverage=(k[15] if len(k) > 15 else ""))
with open('/home/user/bench/results/summary.jsonl','a') as f:
    f.write(json.dumps(row)+"\n")
print(json.dumps(row))
PY
