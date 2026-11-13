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
set -euo pipefail

sha="${1:?usage: release-pr.sh <certified-sha>}"
: "${GITHUB_REPOSITORY:?}" "${GITHUB_TOKEN:?}" "${STATUS_TOKEN:?}" "${RUN_URL:?}"

git checkout -B main "$sha"
git branch --set-upstream-to=origin/main

release-plz release-pr --git-token "$GITHUB_TOKEN"

# Recorded after the PR exists: a commit is never marked certified for a
# release that failed to open.
GH_TOKEN="$STATUS_TOKEN" gh api --method POST \
  "repos/$GITHUB_REPOSITORY/statuses/$sha" \
  -f state=success \
  -f context=Certified \
  -f description="Passed the release gate" \
  -f target_url="$RUN_URL" > /dev/null
echo "certified $sha"
