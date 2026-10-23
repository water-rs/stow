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
# Everything else a build compiles against is the runner's: a
# -sys crate links a system library through pkg-config
# (openssl-sys, alsa-sys), and the sysroot ships glibc and the
# gcc-8 runtime alone. So after the sysroot's directories the
# shim searches the runner's in the same order — the multiarch
# include directory, then /usr/include, since Ubuntu keeps
# openssl/opensslconf.h apart from the rest of the OpenSSL
# headers (stow#729) — and puts /usr/lib/<triple> last on the
# link path. The sysroot's library directories are named with
# -L ahead of argv as well: a -L in argv — that fallback, or
# the one rustc forwards from a build script's pkg-config
# probe — is searched before the -B directories, and the link
# then took the runner's libc and its GLIBC_2.34 symbols. The
# runner's libraries need the runner's glibc in turn, which an
# executable link — a build script, a test — checks against
# the sysroot's 2.28 and refuses; the shim leaves those
# symbols to the loader (--allow-shlib-undefined, which a
# shared-object link does already), and that loader is the
# runner's, where they resolve. The cost of building against
# the runner's libraries is that a row carries their version:
# openssl-sys turns the OpenSSL release into cfg flags
# (ossl300, …) that are part of the compile key, so its rows
# serve only consumers whose library yields the same flags —
# the others miss and compile locally — and a linked output
# names the runner's sonames in NEEDED, as a local build
# against the same library would.
#
# Deterministic — written every run so a cache-restored
# sysroot and a fresh extract wire the same way. The native
# GCC 12 pair is required — a missing driver used to mean no
# shim, and a build then compiled against the host outside
# the sysroot — while the aarch64 pair stays optional (the
# x86_64 leg has no cross toolchain to ask) but lands both
# or neither.
#
# <system-libs-root> is the lock-extracted tree install.sh
# lands (stow#850): for each shim whose <triple> the root
# carries, the runner's last-resort dirs gain the root's own
# ahead of them — the -L sits after argv (a vendored lib
# keeps winning) but before /usr/lib/<triple>, and the
# -idirafter pair before the runner's. When the root has an
# arm64 half the script also writes the cross pkg-config
# pkgconf:arm64 used to provide, aarch64-linux-gnu-pkg-config,
# execing the native pkg-config with the root's arm64 .pc
# dirs as PKG_CONFIG_LIBDIR (the image's /usr/share/pkgconfig
# stays, as the personality's did).
set -euo pipefail

sysroot="${1:?usage: wrappers.sh <sysroot-dir> [<system-libs-root>]}"
syslibs="${2:-}"
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
    # The root's dirs precede the runner's last resorts only when
    # the root carries this shim's architecture.
    local ldir="" idirs=""
    if [ -n "$syslibs" ] && [ -d "$syslibs/usr/lib/$triple" ]; then
        ldir="-L$syslibs/usr/lib/$triple"
        idirs="-idirafter $syslibs/usr/include/$triple -idirafter $syslibs/usr/include"
    fi
    sed -e "s|@SYSROOT@|$sysroot|g" \
        -e "s|@OWN_INCLUDE@|$own_include|g" \
        -e "s|@ARCH@|$arch|g" \
        -e "s|@TRIPLE@|$triple|g" \
        -e "s|@CXX@|$cxx|g" \
        -e "s|@REAL@|$real|g" \
        -e "s|@SYS_LIBS_LDIR@|$ldir|g" \
        -e "s|@SYS_LIBS_IDIRS@|$idirs|g" \
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

# The cross pkg-config the arm64 .pc files probe through —
# PKG_CONFIG_aarch64_unknown_linux_gnu names it in the job env —
# exists only when the root carries the arm64 half.
if [ -n "$syslibs" ] && [ -d "$syslibs/usr/lib/aarch64-linux-gnu" ]; then
    cat > "$sysroot/bin/aarch64-linux-gnu-pkg-config" <<EOF
#!/usr/bin/env bash
# Written by wrappers.sh (stow#850): what pkgconf:arm64's personality
# provided while the arm64 libraries were dpkg-installed — the arm64
# multiarch .pc dirs, now the lock root's, plus /usr/share/pkgconfig.
exec env PKG_CONFIG_LIBDIR="$syslibs/usr/lib/aarch64-linux-gnu/pkgconfig:$syslibs/usr/share/pkgconfig:/usr/share/pkgconfig" \
    pkg-config "\$@"
EOF
    chmod +x "$sysroot/bin/aarch64-linux-gnu-pkg-config"
else
    rm -f "$sysroot/bin/aarch64-linux-gnu-pkg-config"
fi