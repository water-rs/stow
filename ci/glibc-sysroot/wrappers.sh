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
# warns on every .c compile).
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
# sysroot and a fresh extract wire the same way. A driver
# that is not installed gets no shim: the x86_64 leg has no
# cross toolchain to ask.
set -euo pipefail

sysroot="${1:?usage: wrappers.sh <sysroot-dir>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$sysroot/bin"
write_wrapper() {
    local shim="$1" real="$2" arch="$3" triple="$4" cxx="$5"
    rm -f "$sysroot/bin/$shim"
    [ -x "$real" ] || return 0
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
write_wrapper cc  /usr/bin/cc  x86_64 x86_64-linux-gnu 0
write_wrapper c++ /usr/bin/c++ x86_64 x86_64-linux-gnu 1
write_wrapper gcc /usr/bin/gcc x86_64 x86_64-linux-gnu 0
write_wrapper g++ /usr/bin/g++ x86_64 x86_64-linux-gnu 1
write_wrapper aarch64-linux-gnu-gcc /usr/bin/aarch64-linux-gnu-gcc aarch64 aarch64-linux-gnu 0
write_wrapper aarch64-linux-gnu-g++ /usr/bin/aarch64-linux-gnu-g++ aarch64 aarch64-linux-gnu 1
