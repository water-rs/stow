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
# The aarch64 leg cross-compiles on an x86_64 runner, so it
# installs the arm64 builds of the same packages beside the
# native ones through dpkg multiarch. The image's Ubuntu archive
# serves amd64 alone — left as it is, `apt-get update` asks it
# for arm64 indexes it does not have — so its sources are pinned
# to amd64, and arm64 comes from ports.ubuntu.com, where Ubuntu
# publishes its other architectures, at the image's own release.
# The arm64 build of pkgconf is the leg's cross pkg-config: it
# ships aarch64-linux-gnu-pkg-config, which searches the arm64
# .pc files, and build-crate.yml names it per target so a build
# script compiling for the host keeps the native pkg-config.
set -euo pipefail

target="${1:?usage: system-libs.sh <target-triple>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mapfile -t packages < <(grep -Ev '^[[:space:]]*(#|$)' "$here/../system-libs/libs.txt")

case "$target" in
    x86_64-unknown-linux-gnu)
        sudo apt-get update -qq
        sudo apt-get install -y --no-install-recommends "${packages[@]}"
        ;;
    aarch64-unknown-linux-gnu)
        sources=/etc/apt/sources.list.d/ubuntu.sources
        [ -f "$sources" ] || {
            echo "system-libs.sh: $sources does not exist — the runner image no longer configures its Ubuntu archive there" >&2
            exit 1
        }
        # shellcheck source=/dev/null
        codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
        sudo dpkg --add-architecture arm64
        sudo sed -i -e '/^Architectures:/d' -e '/^Types:/a Architectures: amd64' "$sources"
        sed -e "s|@CODENAME@|$codename|g" "$here/ports.sources.in" \
            | sudo tee /etc/apt/sources.list.d/ubuntu-ports.sources > /dev/null
        sudo apt-get update -qq
        sudo apt-get install -y --no-install-recommends \
            pkgconf:arm64 "${packages[@]/%/:arm64}"
        ;;
    *)
        echo "system-libs.sh: $target is not a Linux target the builders provision" >&2
        exit 1
        ;;
esac
