#!/usr/bin/env bash
set -euo pipefail
for t in WorkersInvocationsAdaptiveSum DurableObjectsInvocationsAdaptiveGroupsSum DurableObjectsPeriodicGroupsSum D1AnalyticsAdaptiveGroupsSum WorkersInvocationsAdaptiveDimensions; do
  q=$(jq -n --arg t "$t" '{query: ("{ __type(name: \"" + $t + "\") { name fields { name } } }")}')
  curl -sS -H "Authorization: Bearer $CF_ANALYTICS_TOKEN" -H 'Content-Type: application/json' https://api.cloudflare.com/client/v4/graphql --data "$q" \
    | jq -c '{t: .data.__type.name, f: [.data.__type.fields[]?.name], e: .errors}'
done
