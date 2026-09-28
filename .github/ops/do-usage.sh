#!/usr/bin/env bash
set -euo pipefail
api() { curl -sS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' "$@"; }
base="https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/workers"
echo "== custom domains before"
api "$base/domains?service=stow-edge" | jq -c '.errors // [.result[] | {id, hostname, service, zone_name}]'
for id in $(api "$base/domains?service=stow-edge" | jq -r '.result[]? | select(.hostname=="stow.waterui.dev") | .id'); do
  echo "== detach $id"
  api -X DELETE "$base/domains/$id" | jq -c '{success, errors}'
done
echo "== workers.dev subdomain"
api -X POST "$base/scripts/stow-edge/subdomain" --data '{"enabled":false}' | jq -c '{success, errors, result}'
echo "== custom domains after"
api "$base/domains?service=stow-edge" | jq -c '.errors // [.result[] | {id, hostname}]'
echo "== probe"
sleep 20
curl -sS -m 15 -o /dev/null -w 'stow.waterui.dev http=%{http_code}\n' https://stow.waterui.dev/api/v1/stats || echo "stow.waterui.dev unreachable (expected)"
