#!/usr/bin/env bash
# Resolves the commit a push to main releases, or none.
#
# usage: scripts/release-resolve.sh <pushed-sha>
#
# A push to main releases only the merge of a release PR: a pull request from
# a `release-plz-*` branch opened by the release PR App. Its head commit H is
# what ships, and only when H is exactly one commit, the certified commit X,
# plus the version bump, with X carrying the `Certified` status the release
# gate's own `github-actions[bot]` wrote. Anything else that looks like a
# release but is not that fails; a push that is not a release PR's merge
# releases nothing.
#
# Writes `head=<H>` to $GITHUB_OUTPUT (empty when there is nothing to release).
#
# Environment:
#   GITHUB_REPOSITORY  owner/name of the repository
#   GH_TOKEN           token with contents, pull-requests and statuses read
#   RELEASE_PR_AUTHOR  login of the App that opens release PRs, `<slug>[bot]`
#   GITHUB_OUTPUT      step output file
set -euo pipefail

pushed="${1:?usage: release-resolve.sh <pushed-sha>}"
: "${GITHUB_REPOSITORY:?}" "${GH_TOKEN:?}" "${RELEASE_PR_AUTHOR:?}" "${GITHUB_OUTPUT:?}"

prs="$(gh api "repos/$GITHUB_REPOSITORY/commits/$pushed/pulls" \
  | jq -c --arg author "$RELEASE_PR_AUTHOR" '
      [.[] | select(.head.ref | startswith("release-plz-"))
           | select(.user.login == $author)
           | select(.base.ref == "main" and .merged_at != null)]')"
count="$(jq 'length' <<<"$prs")"
if [ "$count" -eq 0 ]; then
  echo "$pushed is not the merge of a release PR; nothing to release"
  echo "head=" >> "$GITHUB_OUTPUT"
  exit 0
fi
if [ "$count" -ne 1 ]; then
  echo "::error::$count release PRs are associated with $pushed" >&2
  exit 1
fi
head="$(jq -r '.[0].head.sha' <<<"$prs")"

# main takes merge commits only, so the second parent of the pushed commit is
# the PR's head: nothing was added to or dropped from the PR in the merge.
second="$(gh api "repos/$GITHUB_REPOSITORY/commits/$pushed" --jq '.parents[1].sha // empty')"
if [ "$second" != "$head" ]; then
  echo "::error::$pushed does not merge the release PR head $head (second parent: ${second:-none})" >&2
  exit 1
fi

parents="$(gh api "repos/$GITHUB_REPOSITORY/commits/$head" --jq '[.parents[].sha]')"
if [ "$(jq 'length' <<<"$parents")" -ne 1 ]; then
  echo "::error::release PR head $head must have exactly one parent (the certified commit); parents: $parents" >&2
  exit 1
fi
certified="$(jq -r '.[0]' <<<"$parents")"

ok="$(gh api --paginate "repos/$GITHUB_REPOSITORY/commits/$certified/statuses" \
  | jq -s '[.[][] | select(.context == "Certified" and .state == "success"
                           and .creator.login == "github-actions[bot]")] | length')"
if [ "$ok" -eq 0 ]; then
  echo "::error::$certified, the parent of release PR head $head, has no Certified success status from github-actions[bot]" >&2
  exit 1
fi

echo "releasing $head (certified parent $certified)"
echo "head=$head" >> "$GITHUB_OUTPUT"
