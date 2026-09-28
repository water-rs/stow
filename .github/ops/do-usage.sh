#!/usr/bin/env bash
set -euo pipefail
gql() {
  jq -n --arg q "$1" --argjson v "${2:-{\}}" '{query:$q, variables:$v}' |
    curl -sS https://api.cloudflare.com/client/v4/graphql \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' --data @-
}
echo "== dimensions"
gql '{ __type(name: "AccountDurableObjectsPeriodicGroupsDimensions") { fields { name } } }' | jq -c '[.data.__type.fields[]?.name]'
since=$(date -u -d '8 hours ago' +%Y-%m-%dT%H:%M:%SZ); until=$(date -u +%Y-%m-%dT%H:%M:%SZ)
vars=$(jq -n --arg a "$CLOUDFLARE_ACCOUNT_ID" --arg s "$since" --arg u "$until" '{a:$a,s:$s,u:$u}')
echo "== DO periodic by 15 min ($since..$until)"
gql 'query($a:String!,$s:Time!,$u:Time!){viewer{accounts(filter:{accountTag:$a}){durableObjectsPeriodicGroups(limit:1000,filter:{datetime_geq:$s,datetime_leq:$u},orderBy:[datetimeFifteenMinutes_ASC]){dimensions{datetimeFifteenMinutes} sum{cpuTime rowsRead rowsWritten}}}}}' "$vars" | jq -r '.errors // (.data.viewer.accounts[0].durableObjectsPeriodicGroups[] | "\(.dimensions.datetimeFifteenMinutes) read=\(.sum.rowsRead) written=\(.sum.rowsWritten) cpu_ms=\(.sum.cpuTime/1000|floor)")'
echo "== DO requests by 15 min"
gql 'query($a:String!,$s:Time!,$u:Time!){viewer{accounts(filter:{accountTag:$a}){durableObjectsInvocationsAdaptiveGroups(limit:1000,filter:{datetime_geq:$s,datetime_leq:$u},orderBy:[datetimeFifteenMinutes_ASC]){dimensions{datetimeFifteenMinutes} sum{requests}}}}}' "$vars" | jq -r '.errors // (.data.viewer.accounts[0].durableObjectsInvocationsAdaptiveGroups[] | "\(.dimensions.datetimeFifteenMinutes) requests=\(.sum.requests)")'
