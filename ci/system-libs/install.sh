#!/usr/bin/env bash
# Provision a Linux build leg's system-library root from
# ci/system-libs/lock.txt (stow#850): for each deb of the target's
# library sets, download it into <debs-dir> only if absent, verify
# every one against the lock's sha256, extract into a staging copy of
# <root>, relocate, and land it with an atomic mv — the same shape
# ci/glibc-sysroot/install.sh has. The debs never enter dpkg's
# database, so the Multi-Arch: same coupling that broke the leg
# whenever the runner image rolled newer than ports cannot occur.
#
# Usage: ci/system-libs/install.sh <target-triple> <debs-dir> <root>
#
# <target-triple> picks the sets: the aarch64 leg extracts libs-amd64
# (its host side — every Linux leg then presents the same host world)
# and libs-arm64; the x86_64 leg gets libs-amd64 once B2 switches it
# over. The toolchain sets stay out for now — the cross GCC and mold
# still come through apt until B1 (stow#862).
#
# Integrity is the git commit's: <debs-dir> is an actions/cache entry
# keyed on the lock hash, and a poisoned or truncated deb fails
# `sha256sum -c` before anything extracts. Needs curl, sha256sum and
# dpkg-deb.
set -euo pipefail

target="${1:?usage: install.sh <target-triple> <debs-dir> <root>}"
debs="${2:?usage: install.sh <target-triple> <debs-dir> <root>}"
root="${3:?usage: install.sh <target-triple> <debs-dir> <root>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="$here/lock.txt"

fail() { echo "install.sh: $*" >&2; exit 1; }

case "$target" in
    x86_64-unknown-linux-gnu)   libsets="libs-amd64";;
    aarch64-unknown-linux-gnu)  libsets="libs-amd64 libs-arm64";;
    *) fail "$target is not a Linux target the builders provision";;
esac
[ -f "$lock" ] \
    || fail "$lock is missing — generate it (the system-libs-lock workflow) and commit it"

# The lock's suite must be the runner's: its debs assume the image's
# base system at that release, and a mismatch fails here with a clear
# message rather than in a probe later.
suite="$(sed -n 's/^# suite: //p' "$lock" | head -1)"
[ -n "$suite" ] || fail "$lock carries no '# suite: <codename>' header"
# shellcheck source=/dev/null
codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
[ "$codename" = "$suite" ] \
    || fail "the lock is built for $suite but this runner is $codename — regenerate it (ci/system-libs/lock.sh <T>)"

# Fetch what the lock names for the target's sets — only when absent
# (the cache restored it already), then verify every deb regardless.
mkdir -p "$debs"
manifest="$debs.lock.sha256"
: > "$manifest"
files=()
while read -r sname sha file url; do
    case " $libsets " in *" $sname "*) ;; *) continue;; esac
    files+=("$file")
    [ -f "$debs/$file" ] || curl -fsSL --retry 3 -o "$debs/$file" "$url" \
        || fail "downloading $url failed"
    printf '%s  %s\n' "$sha" "$file" >> "$manifest"
done < <(grep -Ev '^[[:space:]]*(#|$)' "$lock")
[ "${#files[@]}" -gt 0 ] || fail "no lock lines matched sets: $libsets"
(cd "$debs" && sha256sum -c --quiet "$manifest") \
    || fail "a deb in $debs does not match the lock's sha256"
rm -f "$manifest"

# Extract into a sibling staging dir and land with mv — the tree is
# only ever complete or absent. Repointed symlinks and rewritten .pc
# prefixes name the final <root>, never the staging dir.
staging="$root.tmp.$$"
trap '[ -n "$staging" ] && rm -rf "$staging" || true' EXIT
mkdir -p "$staging"
for f in "${files[@]}"; do
    dpkg-deb -x "$debs/$f" "$staging"
done
"$here/relocate.sh" "$staging" "$root"
[ -e "$root" ] && rm -rf "$root"
mv "$staging" "$root"
staging=
