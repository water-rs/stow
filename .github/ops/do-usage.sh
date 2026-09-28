#!/usr/bin/env bash
set -euo pipefail
gql() { jq -n --arg q "$1" '{query: $q}' | curl -sS -H "Authorization: Bearer $CF_ANALYTICS_TOKEN" -H 'Content-Type: application/json' https://api.cloudflare.com/client/v4/graphql --data @-; }
acct=$(gql '{ __type(name: "account") { fields { name type { name ofType { name ofType { name ofType { name } } } } } } }')
for f in workersInvocationsAdaptive durableObjectsInvocationsAdaptiveGroups durableObjectsPeriodicGroups d1AnalyticsAdaptiveGroups; do
  t=$(echo "$acct" | jq -r --arg f "$f" '.data.__type.fields[] | select(.name == $f) | [.type.name, .type.ofType.name, .type.ofType.ofType.name, .type.ofType.ofType.ofType.name] | map(select(. != null)) | last')
  sumt=$(gql "{ __type(name: \"$t\") { fields { name type { name ofType { name } } } } }" | jq -r '.data.__type.fields[] | select(.name == "sum") | (.type.name // .type.ofType.name)')
  gql "{ __type(name: \"$sumt\") { fields { name } } }" | jq -c --arg f "$f" '{f: $f, sum: [.data.__type.fields[].name]}'
done
