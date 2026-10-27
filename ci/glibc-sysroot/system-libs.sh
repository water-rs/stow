#!/usr/bin/env bash
# Install the runner's development packages for the system
# libraries crate build scripts link, for one Linux target.
#
# Usage: ci/glibc-sysroot/system-libs.sh <target-triple>
#
# stow#729: a -sys crate that links a system library —
# openssl-sys, alsa-sys, cros-libva — asks pkg-config for it and
# compiles against its headers. The glibc-2.28 sysroot carries
# glibc and the gcc-8 runtime and nothing else, so those
# libraries are the runner image's: the shims search its
# multiarch include and library directories after the
# sysroot's (wrappers.sh says why in that order). The packages
# are ci/system-libs/libs.txt, one list for both legs.
#
# Only the x86_64 leg still installs this way: the aarch64 leg
# provisions both architectures' builds of the same list from
# ci/system-libs/lock.txt through ci/system-libs/install.sh
# instead (stow#850) — extracted, never dpkg-installed, so the
# ports/multiarch coupling with the image is gone for it. The
# x86_64 leg follows in B2 (stow#862).
set -euo pipefail

target="${1:?usage: system-libs.sh <target-triple>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mapfile -t packages < <(grep -Ev '^[[:space:]]*(#|$)' "$here/../system-libs/libs.txt")

case "$target" in
    x86_64-unknown-linux-gnu)
        sudo apt-get update -qq
        sudo apt-get install -y --no-install-recommends "${packages[@]}"
        ;;
    *)
        echo "system-libs.sh: $target is not a Linux target the builders provision" >&2
        exit 1
        ;;
esac
