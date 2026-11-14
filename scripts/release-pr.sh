#!/usr/bin/env bash
# Opens release-plz's release PR from a certified commit and records the
# certification on that commit.
#
# usage: scripts/release-pr.sh <certified-sha>
#
# Run from a clone whose `origin` carries the certified commit.
# release-plz branches the release PR at the checked-out HEAD and takes its
# base from the checked-out branch's name, so the certified commit is checked
# out as `main` tracking `origin/main`; the PR's head commit is then the
# certified commit plus the version bump and nothing else.
#
# Environment:
#   GITHUB_REPOSITORY  owner/name of the repository
#   GITHUB_TOKEN       token release-plz opens the branch and the PR with
#   STATUS_TOKEN       token the `Certified` commit status is written with; the
#                      release job accepts the status only from the workflow's
#                      own `github-actions[bot]`
#   RUN_URL            the certifying run, the status's target
#   GITHUB_API_URL     the REST API root, as Actions sets it
#   RELEASE_PLZ_ARGS   extra release-plz arguments, split on whitespace; the
#                      mock release flow names its forge here
set -euo pipefail

sha="${1:?usage: release-pr.sh <certified-sha>}"
: "${GITHUB_REPOSITORY:?}" "${GITHUB_TOKEN:?}" "${STATUS_TOKEN:?}" "${RUN_URL:?}" "${GITHUB_API_URL:?}"
read -r -a release_plz_args <<<"${RELEASE_PLZ_ARGS:-}"

git checkout -B main "$sha"
git branch --set-upstream-to=origin/main

release-plz release-pr --git-token "$GITHUB_TOKEN" "${release_plz_args[@]}"

# Recorded after the PR exists: a commit is never marked certified for a
# release that failed to open.
curl -fsS -o /dev/null --request POST \
  --header "Authorization: Bearer $STATUS_TOKEN" \
  --header "Accept: application/vnd.github+json" \
  --header "Content-Type: application/json" \
  "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/statuses/$sha" \
  --data "$(jq -n --arg url "$RUN_URL" \
    '{state: "success", context: "Certified", description: "Passed the release gate", target_url: $url}')"
echo "certified $sha"
