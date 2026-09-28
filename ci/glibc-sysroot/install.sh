#!/usr/bin/env bash
# Install the glibc-2.28 sysroot into <sysroot-dir>/<arch>.
#
# Usage: ci/glibc-sysroot/install.sh <sysroot-dir>
#
# stow#336: rustc dlopen's proc-macros and linked dylibs on the
# *user's* machine, so every ELF the cache serves must load on the
# glibc floor stow promises — 2.28, the manylinux_2_28 / RHEL 8
# baseline. A manylinux container would re-provision rustup, mold
# and the runner toolchain on every run; the cheaper setup keeps
# ubuntu-latest and aims compile *and* link at a Debian buster
# (glibc 2.28) sysroot: fourteen version-pinned, sha256-verified
# debs — libc6/libc6-dev, linux-libc-dev (buster's libc headers
# include <linux/*.h>), the gcc-8 runtime libs and headers,
# amd64 and arm64 — extracted under <sysroot-dir>/<arch>.
# Headers must come from the sysroot too: ≥2.38 headers redirect
# sscanf/strtol to `__isoc23_*` symbols 2.28 cannot serve.
#
# The deb manifest is ci/glibc-sysroot-debs.txt, read relative
# to this script's repository; debs come from archive.debian.org,
# buster's canonical mirror, and the extracted tree caches keyed
# by the manifest hash so each runner image downloads it once.
#
# The install is atomic: debs extract into a sibling temp dir and
# `mv` lands the tree only once every arch is extracted and every
# symlink repointed, so a caller's `[ -d "$sysroot" ]` cache check
# can never pick up a half-written tree. Repointed symlinks name
# the final <sysroot-dir>, never the temp one.
set -euo pipefail

sysroot="${1:?usage: install.sh <sysroot-dir>}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="$repo_root/ci/glibc-sysroot-debs.txt"

debs="$(mktemp -d)"
staging="${sysroot}.tmp.$$"
trap 'rm -rf "$debs" "$staging"' EXIT

mkdir -p "$staging"
cd "$debs"
# sha256, local filename, URL — one line per deb.
while read -r sha file url; do
    case "$sha" in ''|\#*) continue;; esac
    curl -fsSL --retry 3 -o "$file" "$url"
    echo "$sha  $file" | sha256sum -c --quiet
done < "$manifest"
for arch in x86_64 aarch64; do
    case "$arch" in
        x86_64) pkg=amd64;;
        aarch64) pkg=arm64;;
    esac
    staging_root="$staging/$arch"
    for deb in *_${pkg}.deb; do
        dpkg-deb -x "$deb" "$staging_root"
    done
    # Absolute symlinks (arm64's libm.so, libgcc_s.so, the
    # dynamic loader) resolve at the filesystem level — repoint
    # them into the final sysroot path. Sanitizer runtime libs
    # aren't in the deb set, so a few links stay dangling; nothing
    # links them. The GNU ld scripts keep their absolute paths:
    # under --sysroot the linker maps them inside the sysroot
    # itself, and a rewritten path would double-prefix there.
    find "$staging_root" -type l -lname '/*' | while IFS= read -r link; do
        ln -sfn "$sysroot/$arch$(readlink "$link")" "$link"
    done
done

mv "$staging" "$sysroot"
staging=
