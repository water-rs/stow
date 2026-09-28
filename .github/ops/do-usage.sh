#!/usr/bin/env bash
set -euo pipefail
gql() {
  jq -n --arg q "$1" '{query:$q}' |
    curl -sS https://api.cloudflare.com/client/v4/graphql \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' --data @-
}
for t in AccountWorkersInvocationsAdaptiveDimensions AccountWorkersInvocationsAdaptiveQuantiles AccountDurableObjectsInvocationsAdaptiveGroupsDimensions AccountDurableObjectsInvocationsAdaptiveGroupsSum AccountDurableObjectsPeriodicGroupsDimensions AccountDurableObjectsPeriodicGroupsSum AccountD1AnalyticsAdaptiveGroupsSum AccountD1AnalyticsAdaptiveGroupsDimensions; do
  echo "== $t"
  gql "{ __type(name: \"$t\") { fields { name } } }" | jq -c '[.data.__type.fields[]?.name]'
done
