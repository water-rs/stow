#!/bin/bash
# usage: suite.sh <build name> <suffix> [emit|dump]
#   emit: log a blake3 of each target's serialized (units, roots) (downloads=424242)
#   dump: additionally log the full JSON, extracted to dumps/<x>-<suffix>/<target>.json (424243)
H=$(cd "$(dirname "$0")" && pwd); D=${MEMPROF_DIR:-$HOME/memprof}
B=$1; S=$2; DL=0; [ "${3:-}" = emit ] && DL=424242; [ "${3:-}" = dump ] && DL=424243
T9='["aarch64-apple-darwin","aarch64-apple-ios","aarch64-apple-ios-sim","aarch64-linux-android","x86_64-unknown-linux-gnu","aarch64-unknown-linux-gnu","x86_64-pc-windows-msvc","aarch64-pc-windows-msvc","wasm32-unknown-unknown"]'
"$H/run_edge.sh" $B zed-$S project "{\"repo\":\"zed-industries/zed\",\"git_ref\":\"933d8d93819c749a607e561883855a9b95c79cea\",\"targets\":[\"x86_64-unknown-linux-gnu\"],\"rustc_version\":\"1.98.1\",\"downloads\":$DL}"
"$H/run_edge.sh" $B bat-$S crate "{\"crate_name\":\"bat\",\"version\":\"0.26.1\",\"targets\":$T9,\"rustc_version\":\"1.98.1\",\"downloads\":$DL}"
"$H/run_edge.sh" $B ra-$S project "{\"repo\":\"rust-lang/rust-analyzer\",\"git_ref\":\"1ad44dc58e65304b594063e70c144ecb58643671\",\"targets\":$T9,\"rustc_version\":\"1.98.1\",\"downloads\":$DL}"
cd "$D"
for x in zed bat ra; do
  R=runs/$x-$S; echo "== $x-$S"; cat $R-cpu.txt; tail -1 $R-v8-summary.json
  python3 "$H/summarize.py" $R-wrangler.log 2>/dev/null | grep "global peak"
  grep -oE "MEMPROF_UNITS [^ ]+ [0-9]+ [0-9a-f]+" $R-wrangler.log
  if [ "${3:-}" = dump ]; then
    mkdir -p dumps/$x-$S
    python3 - $R-wrangler.log dumps/$x-$S <<'PY'
import sys
for line in open(sys.argv[1], errors="replace"):
    i = line.find("MEMPROF_UNITSJSON ")
    if i < 0: continue
    t, j = line[i + len("MEMPROF_UNITSJSON "):].rstrip("\n").split(" ", 1)
    j = j[: j.rfind("]]") + 2]
    open(f"{sys.argv[2]}/{t}.json", "w").write(j)
PY
    ls dumps/$x-$S | wc -l
  fi
done
