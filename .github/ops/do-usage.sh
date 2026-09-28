#!/usr/bin/env bash
set -euo pipefail
gql() {
  jq -n --arg q "$1" --argjson v "${2:-{\}}" '{query:$q, variables:$v}' |
    curl -sS https://api.cloudflare.com/client/v4/graphql \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' --data @-
}
for t in DurableObjectsPeriodicGroupsSum DurableObjectsInvocationsAdaptiveGroupsSum DurableObjectsStorageGroupsMax WorkersInvocationsAdaptiveSum; do
  echo "== fields $t"
  gql "{ __type(name: \"AccountDurableObjects${t#DurableObjects}\") { fields { name } } }" | jq -c '[.data.__type.fields[]?.name]' || true
  gql "{ __type(name: \"Account${t}\") { fields { name } } }" | jq -c '[.data.__type.fields[]?.name]' || true
done
since=$(date -u -d '30 days ago' +%Y-%m-%d); until=$(date -u +%Y-%m-%d)
vars=$(jq -n --arg a "$CLOUDFLARE_ACCOUNT_ID" --arg s "$since" --arg u "$until" '{a:$a,s:$s,u:$u}')
echo "== DO periodic by day ($since..$until)"
gql 'query($a:String!,$s:Date!,$u:Date!){viewer{accounts(filter:{accountTag:$a}){durableObjectsPeriodicGroups(limit:1000,filter:{date_geq:$s,date_leq:$u},orderBy:[date_ASC]){dimensions{date} sum{activeTime cpuTime storageReadUnits storageWriteUnits rowsRead rowsWritten inboundWebsocketMsgCount exceededCpuErrors exceededMemoryErrors}}}}}' "$vars" | jq -c '.errors // .data.viewer.accounts[0].durableObjectsPeriodicGroups[] | [.dimensions.date, .sum]'
echo "== DO periodic (without row fields)"
gql 'query($a:String!,$s:Date!,$u:Date!){viewer{accounts(filter:{accountTag:$a}){durableObjectsPeriodicGroups(limit:1000,filter:{date_geq:$s,date_leq:$u},orderBy:[date_ASC]){dimensions{date} sum{activeTime cpuTime storageReadUnits storageWriteUnits}}}}}' "$vars" | jq -c '.errors // .data.viewer.accounts[0].durableObjectsPeriodicGroups[] | [.dimensions.date, .sum]'
echo "== DO invocations by day"
gql 'query($a:String!,$s:Date!,$u:Date!){viewer{accounts(filter:{accountTag:$a}){durableObjectsInvocationsAdaptiveGroups(limit:1000,filter:{date_geq:$s,date_leq:$u},orderBy:[date_ASC]){dimensions{date} sum{requests wallTime}}}}}' "$vars" | jq -c '.errors // .data.viewer.accounts[0].durableObjectsInvocationsAdaptiveGroups[] | [.dimensions.date, .sum]'
echo "== Worker invocations by day"
gql 'query($a:String!,$s:Date!,$u:Date!){viewer{accounts(filter:{accountTag:$a}){workersInvocationsAdaptive(limit:1000,filter:{date_geq:$s,date_leq:$u,scriptName:"stow-edge"},orderBy:[date_ASC]){dimensions{date} sum{requests errors subrequests} quantiles{cpuTimeP50 cpuTimeP99}}}}}' "$vars" | jq -c '.errors // .data.viewer.accounts[0].workersInvocationsAdaptive[] | [.dimensions.date, .sum, .quantiles]'
echo "== billing paygo usage"
curl -sS "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/paygo-usage?from=$since&to=$until" -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" | jq -c '.errors // .result' | head -c 6000; echo
curl -sS "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/billing/usage/paygo?from=$since&to=$until" -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" | jq -c '.errors // .result' | head -c 6000; echo
