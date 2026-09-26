#!/bin/bash
# usage: dump_bat.sh <build> <tag>
cd ~/memprof
T9='["aarch64-apple-darwin","aarch64-apple-ios","aarch64-apple-ios-sim","aarch64-linux-android","x86_64-unknown-linux-gnu","aarch64-unknown-linux-gnu","x86_64-pc-windows-msvc","aarch64-pc-windows-msvc","wasm32-unknown-unknown"]'
./run_edge2.sh $1 $2 crate "{\"crate_name\":\"bat\",\"version\":\"0.26.1\",\"targets\":$T9,\"rustc_version\":\"1.98.1\",\"downloads\":424243}" >/dev/null 2>&1
mkdir -p dumps/$2
python3 - "$2" <<'PY'
import sys,re
tag=sys.argv[1]
for line in open(f"runs/{tag}-wrangler.log",errors="replace"):
    i=line.find("MEMPROF_UNITSJSON ")
    if i<0: continue
    rest=line[i+len("MEMPROF_UNITSJSON "):].rstrip("\n")
    t,j=rest.split(" ",1)
    # strip trailing ansi / log suffix after the JSON
    end=j.rfind("]]")
    j=j[:end+2] if end>0 else j
    open(f"dumps/{tag}/{t}.json","w").write(j)
PY
ls dumps/$2 | wc -l
