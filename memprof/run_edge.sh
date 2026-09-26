#!/bin/bash
# usage: run_edge.sh <build name> <run tag> <project|crate> <request body json>
# Fresh `wrangler dev --local` isolate per request; samples V8 heap usage
# (inspector, 250 ms), workerd RSS and workerd CPU around one POST to the
# unauthenticated debug route.
set -u
H=$(cd "$(dirname "$0")" && pwd); D=${MEMPROF_DIR:-$HOME/memprof}
export PATH="$HOME/node/bin:$HOME/.cargo/bin:$PATH"
B=$1; T=$2; ROUTE=$3; BODY=$4; cd "$D"; mkdir -p runs; R=runs/$T
pkill -f "wrangler --config"; pkill workerd; sleep 2
wrangler --config "$D/$B/.skyzen/gen/wrangler.toml" dev --local --port 8788 --inspector-port 9229 \
  --persist-to "$HOME/.local/share/stow-edge-wrangler-state" --show-interactive-dev-session=false > $R-wrangler.log 2>&1 &
for i in $(seq 1 120); do curl -sf -o /dev/null http://127.0.0.1:8788/api/v1/scheduler/status && break; sleep 1; done
rm -f $R-v8.jsonl $R-v8.jsonl.done $R-rss.txt
node "$H/v8sample.mjs" $R-v8.jsonl 900000 > $R-v8-summary.json 2>&1 &
SP=$!
( while [ ! -f $R-v8.jsonl.done ]; do ps -C workerd -o rss= | awk '{s+=$1} END{print s}' >> $R-rss.txt; sleep 0.5; done ) &
sleep 2
cpu() { for p in $(pgrep -x workerd); do awk '{print $14+$15}' /proc/$p/stat; done | awk '{s+=$1} END{print s}'; }
C0=$(cpu); S0=$(date +%s.%N)
curl -s -o $R-resp.json -w "%{http_code}\n" -X POST http://127.0.0.1:8788/api/v1/debug/resolve/$ROUTE -H 'content-type: application/json' -d "$BODY" > $R-http.txt
C1=$(cpu); S1=$(date +%s.%N)
TICK=$(getconf CLK_TCK)
echo "http $(cat $R-http.txt) wall_s $(echo "$S1-$S0" | bc) workerd_cpu_ms $(( (C1-C0)*1000/TICK ))" > $R-cpu.txt
sleep 2; touch $R-v8.jsonl.done; wait $SP
python3 - $R <<'PY'
import json,sys
R=sys.argv[1]; M=1<<20
rows=[json.loads(l) for l in open(R+'-v8.jsonl') if l.strip()]
print(json.dumps({'used_peak':max(r['usedSize'] for r in rows)/M,'total_peak':max(r['totalSize'] for r in rows)/M,
 'backing_peak':max(r.get('backingStorageSize',0) for r in rows)/M,
 'used_plus_backing_peak':max(r['usedSize']+r.get('backingStorageSize',0) for r in rows)/M,
 'total_plus_backing_peak':max(r['totalSize']+r.get('backingStorageSize',0) for r in rows)/M,'samples':len(rows)}))
PY
