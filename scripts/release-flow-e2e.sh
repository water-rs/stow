#!/usr/bin/env bash
# The release flow end to end on loopback (stow#1514): a certified commit
# gets its release PR, the PR's merge releases the PR's head commit, and a
# release PR that is not exactly one commit on a certified parent releases
# nothing.
#
# `stow-build serve` stands in for GitHub (docs/MOCK.md): the endpoints
# release-plz and the two release scripts call, over a bare repository per
# `owner/repo`. The scripts the workflows run run here unchanged, against a
# throwaway crate:
#
#   1. scripts/release-pr.sh <X> opens release-plz's release PR from the
#      certified commit X and sets the `Certified` status on it. The PR
#      branch's head H is one commit on X, the base is `main`, the PR is the
#      App's, and X carries `Certified` from the workflow's own bot.
#   2. `main` moves on (a commit lands after the certification) and the PR
#      merges as a merge commit, the only method `main` allows.
#   3. scripts/release-resolve.sh <merge> names H, not the merge commit;
#      `release-plz release` (git_only, as release-plz.yml runs it) checked
#      out at H tags `v<bumped>` at H, whose parent is X: the commit that
#      landed after the certification is in no release.
#   4. A second release PR gets an extra commit on its branch before it
#      merges: its head's parent is not certified, so the resolve step fails
#      and nothing would be released.
#
# Tunables (env):
#   STOW_RELEASE_FLOW_WORK_DIR  work dir instead of a fresh mktemp (log upload)
#   STOW_GATE_BIN_DIR           directory holding a built `stow-build`; unset
#                               builds the production gate tools
#   STOW_E2E_FORGE_PORT         port `stow-build serve` binds (default: 28125)
#
# Needs `release-plz`, `git` (2.38 or newer), `curl` and `jq` on PATH. Every
# child process is killed on exit by PID.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORGE_ADDR="127.0.0.1:${STOW_E2E_FORGE_PORT:-28125}"
API_URL="http://$FORGE_ADDR/api/v3"
OWNER=stow-flow
REPO=demo
SLUG="$OWNER/$REPO"
REPO_URL="http://$FORGE_ADDR/$SLUG"
APP_LOGIN='release-app[bot]'
ACTIONS_LOGIN='github-actions[bot]'
# The mock authenticates `mock-token:<login>` and acts as that login.
APP_TOKEN="mock-token:$APP_LOGIN"
ACTIONS_TOKEN="mock-token:$ACTIONS_LOGIN"
MAINTAINER_TOKEN="mock-token:maintainer"
# release-plz addresses a host that is not github.com as GitHub Enterprise
# unless told the forge; the release scripts take it from here.
export RELEASE_PLZ_ARGS="--forge github --repo-url $REPO_URL"

die() {
    echo "[release-flow] ERROR: $*" >&2
    exit 1
}

for tool in release-plz git curl jq; do
    command -v "$tool" >/dev/null 2>&1 || die "required command not found on PATH: $tool"
done

if [ -n "${STOW_RELEASE_FLOW_WORK_DIR:-}" ]; then
    mkdir -p "$STOW_RELEASE_FLOW_WORK_DIR"
    WORK_DIR="$(cd "$STOW_RELEASE_FLOW_WORK_DIR" && pwd)"
    [ -z "$(ls -A "$WORK_DIR")" ] || die "STOW_RELEASE_FLOW_WORK_DIR $WORK_DIR is not empty"
else
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stow-release-flow.XXXXXX")"
    OWN_WORK_DIR=1
fi
LOG_DIR="$WORK_DIR/logs"
mkdir -p "$LOG_DIR"

SERVER_PID=""
OWN_WORK_DIR="${OWN_WORK_DIR:-}"
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    if [ "$status" -ne 0 ]; then
        echo "[release-flow] FAILED (exit $status); log tails:" >&2
        for log in "$LOG_DIR"/*.log; do
            [ -e "$log" ] || continue
            echo "===== $log =====" >&2
            tail -n 40 "$log" >&2 || true
        done
    fi
    if [ "$status" -eq 0 ] && [ -n "$OWN_WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    else
        echo "[release-flow] work dir: $WORK_DIR"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

# The commits are the test's own: no signing, no hooks and no identity from
# the machine's git configuration.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=maintainer GIT_AUTHOR_EMAIL=maintainer@users.noreply.github.localhost
export GIT_COMMITTER_NAME=maintainer GIT_COMMITTER_EMAIL=maintainer@users.noreply.github.localhost

if [ -n "${STOW_GATE_BIN_DIR:-}" ]; then
    BIN="$(cd "$STOW_GATE_BIN_DIR" && pwd)"
else
    # shellcheck source=scripts/gate-tools.sh
    source "$REPO_ROOT/scripts/gate-tools.sh"
    gate_tools production "$LOG_DIR/gate-tools.log" || die "building the gate tools failed"
fi
[ -x "$BIN/stow-build" ] || die "no stow-build in $BIN"

# --- the mock GitHub and the repository behind it -------------------------

GIT_ROOT="$WORK_DIR/git"
ORIGIN="$GIT_ROOT/$SLUG.git"
mkdir -p "$GIT_ROOT/$OWNER"
git init -q --bare --initial-branch=main "$ORIGIN"

# `serve` is the dispatch server too and asks for its settings; this flow
# dispatches nothing, so they only have to be present.
(
    cd "$WORK_DIR"
    STOW_MOCK_GIT_ROOT="$GIT_ROOT" \
        STOW_EDGE_URL="http://127.0.0.1:9" \
        STOW_GITHUB_WEBHOOK_SECRET="release-flow" \
        STOW_MOCK_PRIVATE_KEY_PATH="$WORK_DIR/unused-key.pem" \
        STOW_MOCK_REGISTRY_ROOT="$WORK_DIR/unused-registry" \
        GITHUB_APP_SLUG="${APP_LOGIN%\[bot\]}" \
        exec "$BIN/stow-build" serve --listen "$FORGE_ADDR"
) >"$LOG_DIR/forge.log" 2>&1 &
SERVER_PID=$!
# The first request is the readiness check: retry while the listener binds.
curl -s -o /dev/null --retry 30 --retry-delay 1 --retry-connrefused "http://$FORGE_ADDR/tasks" \
    || die "the mock GitHub did not come up on $FORGE_ADDR"

# GET/POST/PUT the mock as <token>; prints the body, fails on a non-2xx.
api() {
    local token="$1" method="$2" path="$3"
    shift 3
    curl -fsS --request "$method" \
        --header "Authorization: Bearer $token" \
        --header "Accept: application/vnd.github+json" \
        "$@" "$API_URL/repos/$SLUG/$path"
}

# --- the throwaway crate: v0.1.0 released, one feature since --------------

SEED="$WORK_DIR/seed"
git init -q --initial-branch=main "$SEED"
mkdir -p "$SEED/src"
cat >"$SEED/Cargo.toml" <<'EOF'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"
publish = false
EOF
echo 'pub fn hello() {}' >"$SEED/src/lib.rs"
cat >"$SEED/release-plz.toml" <<'EOF'
[workspace]
# The tags are the record of what was released, as in release-plz.yml's
# repository; nothing is published to a registry here.
git_only = true
git_release_enable = false
changelog_update = true

[[package]]
name = "demo"
git_tag_name = "v{{ version }}"
EOF
(cd "$SEED" && cargo generate-lockfile --offline >/dev/null 2>&1) \
    || die "could not write the throwaway crate's lockfile"
git -C "$SEED" add -A
git -C "$SEED" commit -q -m "chore: initial commit"
git -C "$SEED" tag v0.1.0
echo 'pub fn greet() {}' >>"$SEED/src/lib.rs"
git -C "$SEED" commit -q -am "feat: add greet"
git -C "$SEED" remote add origin "$ORIGIN"
git -C "$SEED" push -q origin main v0.1.0

# A clone of the origin at <commit>, as the workflow's checkout.
clone_at() {
    local dir="$1" commit="$2"
    git clone -q "$ORIGIN" "$dir"
    git -C "$dir" checkout -q --detach "$commit"
}

origin_head() {
    git -C "$ORIGIN" rev-parse refs/heads/main
}

# Certifies <commit>: the release-pr step, with the workflow's inputs.
release_pr() {
    local commit="$1" dir="$2"
    clone_at "$dir" "$commit"
    (
        cd "$dir"
        GITHUB_REPOSITORY="$SLUG" GITHUB_API_URL="$API_URL" \
            GITHUB_TOKEN="$APP_TOKEN" STATUS_TOKEN="$ACTIONS_TOKEN" \
            RUN_URL="http://$FORGE_ADDR/$SLUG/actions/runs/1" \
            "$REPO_ROOT/scripts/release-pr.sh" "$commit"
    )
}

# The release job's resolve step for the commit a push to main created;
# prints the script's output file.
release_resolve() {
    local pushed="$1" output="$2"
    : >"$output"
    GITHUB_REPOSITORY="$SLUG" GITHUB_API_URL="$API_URL" GH_TOKEN="$ACTIONS_TOKEN" \
        RELEASE_PR_AUTHOR="$APP_LOGIN" GITHUB_OUTPUT="$output" \
        "$REPO_ROOT/scripts/release-resolve.sh" "$pushed"
}

# Lands a commit on the origin's main, as a merge after the certification.
land_on_main() {
    local dir="$1" message="$2"
    git clone -q "$ORIGIN" "$dir"
    echo "$message" >>"$dir/notes.txt"
    git -C "$dir" add notes.txt
    git -C "$dir" commit -q -m "$message"
    git -C "$dir" push -q origin main
}

merge_pull() {
    api "$MAINTAINER_TOKEN" PUT "pulls/$1/merge" \
        --header "Content-Type: application/json" --data '{"merge_method":"merge"}' | jq -r '.sha'
}

# --- 1. certification opens the release PR --------------------------------

CERTIFIED="$(origin_head)"
echo "[release-flow] certifying $CERTIFIED"
release_pr "$CERTIFIED" "$WORK_DIR/pr-clone" >"$LOG_DIR/release-pr.log" 2>&1 \
    || die "release-pr.sh failed"

PRS="$(api "$MAINTAINER_TOKEN" GET "pulls?state=open")"
[ "$(jq 'length' <<<"$PRS")" -eq 1 ] || die "expected one open release PR: $PRS"
PR_NUMBER="$(jq -r '.[0].number' <<<"$PRS")"
PR_BRANCH="$(jq -r '.[0].head.ref' <<<"$PRS")"
HEAD="$(jq -r '.[0].head.sha' <<<"$PRS")"
[[ "$PR_BRANCH" == release-plz-* ]] || die "release PR branch is $PR_BRANCH"
[ "$(jq -r '.[0].base.ref' <<<"$PRS")" = main ] || die "release PR base is not main"
[ "$(jq -r '.[0].user.login' <<<"$PRS")" = "$APP_LOGIN" ] || die "release PR is not the App's"
[ "$(git -C "$ORIGIN" rev-parse "$HEAD^")" = "$CERTIFIED" ] \
    || die "the release PR head's parent is not the certified commit"
[ "$(git -C "$ORIGIN" rev-list --count "$CERTIFIED..$HEAD")" -eq 1 ] \
    || die "the release PR is not exactly one commit on the certified commit"
STATUSES="$(api "$MAINTAINER_TOKEN" GET "commits/$CERTIFIED/statuses")"
jq -e --arg actor "$ACTIONS_LOGIN" \
    'any(.[]; .context == "Certified" and .state == "success" and .creator.login == $actor)' \
    <<<"$STATUSES" >/dev/null || die "the certified commit has no Certified status: $STATUSES"
VERSION="$(git -C "$ORIGIN" show "$HEAD:Cargo.toml" | sed -n 's/^version = "\(.*\)"$/\1/p')"
[ "$VERSION" != 0.1.0 ] || die "the release PR did not bump the version"
echo "[release-flow] release PR #$PR_NUMBER: $PR_BRANCH at $HEAD bumps demo to $VERSION"

# --- 2. main moves on; the PR merges --------------------------------------

land_on_main "$WORK_DIR/later-clone" "chore: work merged after the certification"
LATER="$(origin_head)"
MERGE="$(merge_pull "$PR_NUMBER")"
[ "$(origin_head)" = "$MERGE" ] || die "the merge is not main's head"
[ "$(git -C "$ORIGIN" rev-parse "$MERGE^2")" = "$HEAD" ] || die "the merge does not merge the PR head"
[ "$(git -C "$ORIGIN" rev-parse "$MERGE^1")" = "$LATER" ] || die "the merge is not on the later commit"

# --- 3. the merge releases H, not itself -----------------------------------

RESOLVED="$WORK_DIR/resolve-1.out"
release_resolve "$MERGE" "$RESOLVED" >"$LOG_DIR/resolve-1.log" 2>&1 || die "release-resolve.sh failed"
[ "$(sed -n 's/^head=//p' "$RESOLVED")" = "$HEAD" ] \
    || die "the resolve step named $(cat "$RESOLVED"), not $HEAD"

RELEASE_CLONE="$WORK_DIR/release-clone"
git clone -q "$ORIGIN" "$RELEASE_CLONE"
git -C "$RELEASE_CLONE" checkout -q --detach "$HEAD"
(
    cd "$RELEASE_CLONE"
    # shellcheck disable=SC2086 # the forge arguments are split on purpose
    release-plz release --git-token "$APP_TOKEN" $RELEASE_PLZ_ARGS
) >"$LOG_DIR/release.log" 2>&1 || die "release-plz release failed"
TAG="v$VERSION"
[ "$(git -C "$ORIGIN" rev-parse "refs/tags/$TAG^{commit}")" = "$HEAD" ] \
    || die "tag $TAG is not at the release PR head $HEAD"
[ "$(git -C "$ORIGIN" rev-parse "refs/tags/$TAG^{commit}^")" = "$CERTIFIED" ] \
    || die "tag $TAG is not one commit on the certified commit"
git -C "$ORIGIN" merge-base --is-ancestor "$LATER" "refs/tags/$TAG^{commit}" \
    && die "the commit merged after the certification is in the release"
echo "[release-flow] $TAG at $HEAD, one commit on certified $CERTIFIED"

# --- 4. an extra commit on the release branch releases nothing -------------

CERTIFIED_2="$(origin_head)"
release_pr "$CERTIFIED_2" "$WORK_DIR/pr-clone-2" >"$LOG_DIR/release-pr-2.log" 2>&1 \
    || die "the second release-pr.sh failed"
PRS_2="$(api "$MAINTAINER_TOKEN" GET "pulls?state=open")"
[ "$(jq 'length' <<<"$PRS_2")" -eq 1 ] || die "expected one open release PR: $PRS_2"
PR_NUMBER_2="$(jq -r '.[0].number' <<<"$PRS_2")"
BRANCH_2="$(jq -r '.[0].head.ref' <<<"$PRS_2")"
HEAD_2="$(jq -r '.[0].head.sha' <<<"$PRS_2")"
[ "$(git -C "$ORIGIN" rev-parse "$HEAD_2^")" = "$CERTIFIED_2" ] \
    || die "the second release PR head's parent is not the certified commit"

TAMPER="$WORK_DIR/tamper-clone"
git clone -q --branch "$BRANCH_2" "$ORIGIN" "$TAMPER"
echo "uncertified" >"$TAMPER/extra.txt"
git -C "$TAMPER" add extra.txt
git -C "$TAMPER" commit -q -m "chore: a commit nobody certified"
git -C "$TAMPER" push -q origin "$BRANCH_2"
MERGE_2="$(merge_pull "$PR_NUMBER_2")"
if release_resolve "$MERGE_2" "$WORK_DIR/resolve-2.out" >"$LOG_DIR/resolve-2.log" 2>&1; then
    die "the resolve step accepted a release PR with an extra commit"
fi
grep -q "no Certified success status" "$LOG_DIR/resolve-2.log" \
    || die "the resolve step failed for another reason: $(cat "$LOG_DIR/resolve-2.log")"
[ ! -s "$WORK_DIR/resolve-2.out" ] || die "the failed resolve step still named a commit"
echo "[release-flow] a release PR with an extra commit releases nothing"
echo "[release-flow] ok"
