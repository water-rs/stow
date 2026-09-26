#!/bin/bash
set -u
export PATH="$HOME/node/bin:$HOME/.cargo/bin:$PATH"
B=$1; T=$2; cd ~/memprof; R=runs/$T
pkill -f "wrangler --config" ; pkill workerd; sleep 2
wrangler --config "$HOME/memprof/$B/.skyzen/gen/wrangler.toml" dev --local --port 8788 --inspector-port 9229 \
  --persist-to "$HOME/.local/share/stow-edge-wrangler-state" --show-interactive-dev-session=false > $R-wrangler.log 2>&1 &
for i in $(seq 1 120); do curl -sf -o /dev/null http://127.0.0.1:8788/api/v1/scheduler/status && break; sleep 1; done
sleep 2
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8788/api/v1/debug/resolve/project -H 'content-type: application/json' -d '{"repo":"zed-industries/zed","git_ref":"933d8d93819c749a607e561883855a9b95c79cea","targets":["x86_64-unknown-linux-gnu"],"rustc_version":"1.98.1","downloads":0}'
node heapsnap.mjs $R.heapsnapshot
python3 snap_ab.py $R.heapsnapshot
