#!/bin/bash
# usage: multi.sh <build> <tag> — one isolate, zed/bat/ra x2 sequentially
set -u
export PATH="$HOME/node/bin:$HOME/.cargo/bin:$PATH"
B=$1; T=$2; cd ~/memprof; mkdir -p runs; R=runs/$T
pkill -f "wrangler --config" ; pkill workerd; sleep 2
wrangler --config "$HOME/memprof/$B/.skyzen/gen/wrangler.toml" dev --local --port 8788 --inspector-port 9229 \
  --persist-to "$HOME/.local/share/stow-edge-wrangler-state" --show-interactive-dev-session=false > $R-wrangler.log 2>&1 &
for i in $(seq 1 120); do curl -sf -o /dev/null http://127.0.0.1:8788/api/v1/scheduler/status && break; sleep 1; done
rm -f $R-v8.jsonl $R-v8.jsonl.done
node v8sample.mjs $R-v8.jsonl 1800000 > $R-v8-summary.json 2>&1 &
SP=$!
sleep 2
T9='["aarch64-apple-darwin","aarch64-apple-ios","aarch64-apple-ios-sim","aarch64-linux-android","x86_64-unknown-linux-gnu","aarch64-unknown-linux-gnu","x86_64-pc-windows-msvc","aarch64-pc-windows-msvc","wasm32-unknown-unknown"]'
ZED='{"repo":"zed-industries/zed","git_ref":"933d8d93819c749a607e561883855a9b95c79cea","targets":["x86_64-unknown-linux-gnu"],"rustc_version":"1.98.1","downloads":0}'
BAT="{\"crate_name\":\"bat\",\"version\":\"0.26.1\",\"targets\":$T9,\"rustc_version\":\"1.98.1\",\"downloads\":0}"
RA="{\"repo\":\"rust-lang/rust-analyzer\",\"git_ref\":\"1ad44dc58e65304b594063e70c144ecb58643671\",\"targets\":$T9,\"rustc_version\":\"1.98.1\",\"downloads\":0}"
: > $R-seq.txt
for n in 1 2; do for x in zed bat ra; do
  case $x in zed) RT=project; BD=$ZED;; bat) RT=crate; BD=$BAT;; ra) RT=project; BD=$RA;; esac
  echo "$x$n start $(date +%s.%N)" >> $R-seq.txt
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:8788/api/v1/debug/resolve/$RT -H 'content-type: application/json' -d "$BD")
  echo "$x$n end $(date +%s.%N) http $code" >> $R-seq.txt
  sleep 3
done; done
touch $R-v8.jsonl.done; wait $SP
python3 - $R <<'PY'
import json,sys
R=sys.argv[1]; M=1<<20
reqs=[]; cur=None
for line in open(R+'-wrangler.log',errors='replace'):
    i=line.find('MEMPROF {')
    if i<0: continue
    j=line[i+8:]; d,_=json.JSONDecoder().raw_decode(j)
    if d['label']=='request_start': cur=[]; reqs.append(cur)
    if cur is not None: cur.append(d)
seq=[l.split() for l in open(R+'-seq.txt')]
names=[s[0] for s in seq if s[1]=='start']
print(f"{'req':6} {'start_live':>10} {'peak':>7} {'end_live':>9} {'mem_size':>8}  top tags live at start")
for n,r in zip(names,reqs):
    s,e=r[0],r[-1]
    tags=sorted(((k,v['live']) for k,v in s['tags'].items()),key=lambda kv:-kv[1])[:5]
    print(f"{n:6} {s['live']/M:10.1f} {e['peak']/M:7.1f} {e['live']/M:9.1f} {e['memory_size']/M:8.1f}  "+' '.join(f"{k}={v/M:.1f}" for k,v in tags))
rows=[json.loads(l) for l in open(R+'-v8.jsonl') if l.strip()]
print("v8 used+backing peak %.1f MiB, used peak %.1f"%(max(r['usedSize']+r.get('backingStorageSize',0) for r in rows)/M, max(r['usedSize'] for r in rows)/M))
PY
cat $R-seq.txt | awk '{print $1,$2,$4,$5}'
