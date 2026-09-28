#!/usr/bin/env bash
set -euo pipefail
api() { curl -sS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' "$@"; }
echo "== email"
body=$(jq -n '{to:"me@lexo.cool", from:"alerts@stow.waterui.dev", subject:"stow alert channel test", text:"Test of stow alert delivery through Cloudflare Email Sending with the repository CLOUDFLARE_API_TOKEN. No action needed.", html:"<p>Test of stow alert delivery through Cloudflare Email Sending with the repository <code>CLOUDFLARE_API_TOKEN</code>. No action needed.</p>"}')
api -X POST "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/email/sending/send" --data "$body" | jq -c '{success, errors, result}'
echo "== zone"
zone=$(api "https://api.cloudflare.com/client/v4/zones?name=waterui.dev" | jq -r '.result[0].id // empty')
echo "zone_found=$([ -n "$zone" ] && echo yes || echo no)"
echo "== waf custom phase entrypoint"
api "https://api.cloudflare.com/client/v4/zones/$zone/rulesets/phases/http_request_firewall_custom/entrypoint" | jq -c '{success, errors, rules: [.result.rules[]? | {description, enabled, action}]}'
