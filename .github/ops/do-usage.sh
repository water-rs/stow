#!/usr/bin/env bash
set -euo pipefail
since=$(date -u -d '-6 hours' +%Y-%m-%dT%H:00:00Z)
until=$(date -u +%Y-%m-%dT%H:%M:00Z)
query=$(cat <<'Q'
query($acct: String!, $since: Time!, $until: Time!) {
  viewer { accounts(filter: {accountTag: $acct}) {
    do: durableObjectsPeriodicGroups(limit: 50, filter: {datetimeHour_geq: $since, datetimeHour_leq: $until}, orderBy: [datetimeHour_ASC]) {
      dimensions { datetimeHour } sum { rowsRead rowsWritten activeTime subrequests }
    }
    doreq: durableObjectsInvocationsAdaptiveGroups(limit: 50, filter: {datetimeHour_geq: $since, datetimeHour_leq: $until}, orderBy: [datetimeHour_ASC]) {
      dimensions { datetimeHour } sum { requests }
    }
    workers: workersInvocationsAdaptive(limit: 50, filter: {datetimeHour_geq: $since, datetimeHour_leq: $until}, orderBy: [datetimeHour_ASC]) {
      dimensions { datetimeHour scriptName } sum { requests }
    }
    d1: d1AnalyticsAdaptiveGroups(limit: 50, filter: {datetimeHour_geq: $since, datetimeHour_leq: $until}, orderBy: [datetimeHour_ASC]) {
      dimensions { datetimeHour databaseId } sum { rowsRead rowsWritten readQueries writeQueries }
    }
  } }
}
Q
)
jq -n --arg q "$query" --arg acct "$CLOUDFLARE_ACCOUNT_ID" --arg since "$since" --arg until "$until" \
  '{query: $q, variables: {acct: $acct, since: $since, until: $until}}' \
| curl -sS -H "Authorization: Bearer $CF_ANALYTICS_TOKEN" -H 'Content-Type: application/json' \
    https://api.cloudflare.com/client/v4/graphql --data @- \
| jq -c '.errors // empty, (.data.viewer.accounts[0] | to_entries[] | {k: .key, rows: [.value[] | [.dimensions.datetimeHour, (.dimensions.scriptName // .dimensions.databaseId // ""), .sum]]})'
echo "== d1 databases"
curl -sS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/d1/database?per_page=50" | jq -c '[.result[] | {uuid, name}]'
