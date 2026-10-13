#!/usr/bin/env bash
# Write the glibc-2.28 sysroot compiler wrappers into <sysroot-dir>/bin.
#
# Usage: ci/glibc-sysroot/wrappers.sh <sysroot-dir>
#
# PATH shims named after the canonical drivers — rustc's `cc`
# link driver, cc-rs's `cc`/`c++`/`gcc`/`g++` fallbacks, the
# aarch64 leg's `aarch64-linux-gnu-*` toolchain (the published
# compile key carries `linker=aarch64-linux-gnu-gcc` verbatim,
# so PATH must deliver it — a renamed linker would re-key every
# aarch64 unit). Each shim execs the real driver with the
# sysroot's dirs first (-B wins over Debian's host multiarch
# spec dirs, which -L and LIBRARY_PATH lose to) and its headers
# in scope (--sysroot): ≥2.38 headers redirect sscanf/strtol
# to `__isoc23_*` symbols 2.28 cannot serve.
#
# Two header paths the flag alone leaves open. A TU naming
# /usr/include literally (`-I` or `-isystem`, either argv
# form — real crates do this) parses host glibc headers and
# mixes them into sysroot code, so the shim retargets that
# exact path inside the sysroot and keeps `-idirafter
# /usr/include` as the last resort for headers the sysroot
# lacks (non-glibc dev libs the runner still owns). And gcc
# finds libstdc++ headers through its install prefix, not
# --sysroot — the runner's libstdc++ declares
# pthread_cond_clockwait (glibc 2.30+) that the buster
# pthread.h has no decl for — so C++ mode pins the era
# libstdc++ headers the debs ship via -nostdinc++ + explicit
# -I order (baked on for the C++ drivers; a C driver adds it
# only when a C++ TU shows up in argv, since -nostdinc++
# warns on every .c compile). The era headers pin the driver
# too: GCC 13 made `__remove_cv` a built-in trait name, and
# it is an ordinary identifier in libstdc++ 8 — under the
# runner's default every TU including <memory> fails to
# parse (stow#693), so each shim execs the GCC 12 driver of
# its kind. The link had the mirror defect: the driver
# resolves -lstdc++ from its own install dir ahead of the
# sysroot, and the runner's libstdc++.so needs glibc
# 2.33/2.34 symbols 2.28 cannot serve — so each arch gets a
# cxx-link/ directory holding only a libstdc++.so symlink at
# the sysroot's libstdc++.so.6, put first on the link path
# of every shim (a C driver links C++ objects too: rustc
# links through `cc`). That buys an object that needs nothing
# newer than GCC 8's runtime where it is finally linked — a
# C++ object archived into an rlib meets the consumer's own
# libstdc++ — at the cost of the C++20 library libstdc++ 8
# never shipped: a crate needing <format> fails to build and
# stays a cache miss.
#
# And --sysroot does not move every directory the driver
# searches by itself. A cross driver has a tool include
# directory — /usr/aarch64-linux-gnu/include, the runner's own
# cross glibc headers — that it searches before the sysroot's:
# readable, it puts those newer headers in front of the 2.28
# ones; unreadable, as in the build sandbox, gcc stops with
# "stdc-predef.h: Permission denied" and every C compile on
# the aarch64 leg failed (stow#691). So the shim drops the
# driver's whole default list (-nostdinc) and names what
# belongs on it: the compiler's own headers, asked of the
# driver when the shim is written, then the sysroot's.
#
# Deterministic — written every run so a cache-restored
# sysroot and a fresh extract wire the same way. The native
# GCC 12 pair is required — a missing driver used to mean no
# shim, and a build then compiled against the host outside
# the sysroot — while the aarch64 pair stays optional (the
# x86_64 leg has no cross toolchain to ask) but lands both
# or neither.
set -euo pipefail

sysroot="${1:?usage: wrappers.sh <sysroot-dir>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$sysroot/bin"

# A driver the shim execs must exist: an absent one used to
# mean no shim, and a build then compiled against the
# runner's own toolchain outside the sysroot.
require_driver() {
    [ -x "$1" ] || {
        echo "wrappers.sh: $1 is not executable — install the $2 package" >&2
        exit 1
    }
}

# <arch>/cxx-link holds one symlink — libstdc++.so at the
# sysroot's runtime — so the shims' -L resolves -lstdc++
# there ahead of the driver's own install dir. Rewritten
# every run like the shims.
cxx_link() {
    local arch="$1" triple="$2" target
    target="$sysroot/$arch/usr/lib/$triple/libstdc++.so.6"
    [ -e "$target" ] || {
        echo "wrappers.sh: $target does not exist — the sysroot is missing libstdc++6" >&2
        exit 1
    }
    rm -rf "$sysroot/$arch/cxx-link"
    mkdir -p "$sysroot/$arch/cxx-link"
    ln -s "$target" "$sysroot/$arch/cxx-link/libstdc++.so"
}

write_wrapper() {
    local shim="$1" real="$2" arch="$3" triple="$4" cxx="$5"
    rm -f "$sysroot/bin/$shim"
    local own_include
    own_include="$("$real" -print-file-name=include)"
    sed -e "s|@SYSROOT@|$sysroot|g" \
        -e "s|@OWN_INCLUDE@|$own_include|g" \
        -e "s|@ARCH@|$arch|g" \
        -e "s|@TRIPLE@|$triple|g" \
        -e "s|@CXX@|$cxx|g" \
        -e "s|@REAL@|$real|g" \
        "$here/wrapper.sh.in" > "$sysroot/bin/$shim"
    chmod +x "$sysroot/bin/$shim"
}

require_driver /usr/bin/gcc-12 gcc-12
require_driver /usr/bin/g++-12 g++-12
cxx_link x86_64 x86_64-linux-gnu
write_wrapper cc  /usr/bin/gcc-12 x86_64 x86_64-linux-gnu 0
write_wrapper c++ /usr/bin/g++-12 x86_64 x86_64-linux-gnu 1
write_wrapper gcc /usr/bin/gcc-12 x86_64 x86_64-linux-gnu 0
write_wrapper g++ /usr/bin/g++-12 x86_64 x86_64-linux-gnu 1

cross_cc=/usr/bin/aarch64-linux-gnu-gcc-12
cross_cxx=/usr/bin/aarch64-linux-gnu-g++-12
if [ -x "$cross_cc" ] || [ -x "$cross_cxx" ]; then
    # Both or neither — a half-installed cross toolchain is a
    # broken sysroot, not a thinner one.
    require_driver "$cross_cc" gcc-12-aarch64-linux-gnu
    require_driver "$cross_cxx" g++-12-aarch64-linux-gnu
    cxx_link aarch64 aarch64-linux-gnu
    write_wrapper aarch64-linux-gnu-gcc "$cross_cc" aarch64 aarch64-linux-gnu 0
    write_wrapper aarch64-linux-gnu-g++ "$cross_cxx" aarch64 aarch64-linux-gnu 1
else
    rm -f "$sysroot/bin/aarch64-linux-gnu-gcc" "$sysroot/bin/aarch64-linux-gnu-g++"
fi
