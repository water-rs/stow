#!/usr/bin/env bash
set -euo pipefail
body=$(jq -n '{to:"me@lexo.cool", from:"alerts@stow.waterui.dev", subject:"stow alert channel test", text:"This is a test of stow alert delivery through Cloudflare Email Sending, sent from GitHub Actions with the repository CLOUDFLARE_API_TOKEN. No action needed.", html:"<p>This is a test of stow alert delivery through Cloudflare Email Sending, sent from GitHub Actions with the repository <code>CLOUDFLARE_API_TOKEN</code>. No action needed.</p>"}')
curl -sS -X POST "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/email/sending/send" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' --data "$body" | jq -c '{success, errors, result}'
