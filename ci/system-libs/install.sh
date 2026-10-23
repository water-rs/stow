#!/usr/bin/env bash
# Provision a Linux build leg from ci/system-libs/lock.txt
# (stow#850, stow#862): for each deb of the target's sets, download
# it into <debs-dir> only if absent, verify every one against the
# lock's sha256, extract the library sets into a staging copy of
# <root>, relocate, and land it with an atomic mv — the same shape
# ci/glibc-sysroot/install.sh has — and extract the toolchain set
# into / with `tar -x -k`, at the same paths apt used. No deb enters
# dpkg's database, so the Multi-Arch: same coupling that broke the
# leg whenever the runner image rolled newer than ports cannot
# occur.
#
# Usage: ci/system-libs/install.sh <target-triple> <debs-dir> <root>
#
# <target-triple> picks the sets: the aarch64 leg gets libs-amd64
# (its host side — every Linux leg presents the same host world),
# libs-arm64 and the aarch64 cross toolchain + mold; the x86_64 leg
# gets libs-amd64 and mold. The toolchain debs collide with nothing
# on the image — `tar -k` fails the leg if that stops being true —
# and their base runtime libraries are the image's, which the smoke
# test at the end proves (one empty TU through the cross driver and
# ar, plus `mold --version`).
#
# Integrity is the git commit's: <debs-dir> is an actions/cache entry
# keyed on the lock hash, and a poisoned or truncated deb fails
# `sha256sum -c` before anything extracts. Needs curl, sha256sum,
# dpkg-deb and sudo for the / extraction.
set -euo pipefail

target="${1:?usage: install.sh <target-triple> <debs-dir> <root>}"
debs="${2:?usage: install.sh <target-triple> <debs-dir> <root>}"
root="${3:?usage: install.sh <target-triple> <debs-dir> <root>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="$here/lock.txt"

fail() { echo "install.sh: $*" >&2; exit 1; }

case "$target" in
    x86_64-unknown-linux-gnu)
        libsets="libs-amd64"
        tcsets="toolchain-x86_64-unknown-linux-gnu";;
    aarch64-unknown-linux-gnu)
        libsets="libs-amd64 libs-arm64"
        tcsets="toolchain-aarch64-unknown-linux-gnu";;
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
libfiles=()
tcfiles=()
while read -r sname sha file url; do
    case " $libsets " in
        *" $sname "*) libfiles+=("$file");;
        *) case " $tcsets " in
               *" $sname "*) tcfiles+=("$file");;
               *) continue;;
           esac;;
    esac
    [ -f "$debs/$file" ] || curl -fsSL --retry 3 -o "$debs/$file" "$url" \
        || fail "downloading $url failed"
    printf '%s  %s\n' "$sha" "$file" >> "$manifest"
done < <(grep -Ev '^[[:space:]]*(#|$)' "$lock")
[ "${#libfiles[@]}" -gt 0 ] || fail "no lock lines matched sets: $libsets"
[ "${#tcfiles[@]}" -gt 0 ] || fail "no lock lines matched sets: $tcsets"
(cd "$debs" && sha256sum -c --quiet "$manifest") \
    || fail "a deb in $debs does not match the lock's sha256"
rm -f "$manifest"

# Extract the libraries into a sibling staging dir and land with mv —
# the tree is only ever complete or absent. Repointed symlinks and
# rewritten .pc prefixes name the final <root>, never the staging dir.
staging="$root.tmp.$$"
trap '[ -n "$staging" ] && rm -rf "$staging" || true' EXIT
mkdir -p "$staging"
for f in "${libfiles[@]}"; do
    dpkg-deb -x "$debs/$f" "$staging"
done
"$here/relocate.sh" "$staging" "$root"
[ -e "$root" ] && rm -rf "$root"
mv "$staging" "$root"
staging=

# Register the root's amd64 half with the loader (stow#862): host
# executables — build scripts, proc-macros, tests that dlopen —
# resolve the root's sonames after the image's own. `zz-` sorts last
# in ld.so.conf.d, so a library the image ships (`libssl.so.3`)
# still resolves from the image; only the root-only ones
# (`libva.so.2`, …) bind to it.
if [ -d "$root/usr/lib/x86_64-linux-gnu" ]; then
    echo "$root/usr/lib/x86_64-linux-gnu" \
        | sudo tee /etc/ld.so.conf.d/zz-stow-system-libs.conf > /dev/null
    sudo ldconfig
fi

# The toolchain debs land in / at the same paths apt used — -k makes
# any collision with an image file a hard failure rather than a
# silent overwrite behind dpkg's back.
for f in "${tcfiles[@]}"; do
    dpkg-deb --fsys-tarfile "$debs/$f" | sudo tar -x -k -C / \
        || fail "extracting $f into / failed — a file collided with the image"
done

# `-fuse-ld=mold` asks collect2 for ld.mold on the cross toolchain's
# own search path, which /usr/bin does not reach.
if [ "$target" = aarch64-unknown-linux-gnu ]; then
    sudo ln -sf /usr/bin/ld.mold /usr/aarch64-linux-gnu/bin/ld.mold
fi

# Smoke test: the toolchain's base runtime libraries are the image's
# — prove the image still provides them before the leg builds.
smoke="$(mktemp -d)"; trap 'rm -rf "$smoke"' EXIT
: > "$smoke/empty.c"
mold --version > /dev/null || fail "mold does not run after extraction"
if [ "$target" = aarch64-unknown-linux-gnu ]; then
    aarch64-linux-gnu-gcc-12 -c "$smoke/empty.c" -o "$smoke/empty.o" \
        || fail "aarch64-linux-gnu-gcc-12 does not run after extraction"
    aarch64-linux-gnu-ar rcs "$smoke/empty.a" "$smoke/empty.o" \
        || fail "aarch64-linux-gnu-ar does not run after extraction"
fi
rm -rf "$smoke"; trap - EXIT
