#!/usr/bin/env bash
# Prove a -sys crate's system library builds and links through
# the glibc-2.28 sysroot shims: the provisioned headers and
# libraries are found, and the sysroot's glibc still wins.
#
# Usage: ci/glibc-sysroot/check-system-libs.sh <sysroot-dir> [<system-libs-root>]
#
# stow#729: openssl-sys failed on both Linux legs because the
# shims never searched the runner's multiarch include directory,
# where Ubuntu keeps openssl/opensslconf.h. The TU here includes
# <openssl/ssl.h> with `-I/usr/include` the way openssl-sys's
# build script names the include directory pkg-config reports,
# and is linked as a shared object — the shape a proc-macro or
# cdylib links in — against -lssl -lcrypto twice: once with the
# arch's library directory in argv, the way rustc forwards a
# build script's link search, and once with nothing, where the
# shim's own fallback must find the library. It also calls
# pthread_create, whose default version is GLIBC_2.34 in the
# runner's libc and GLIBC_2.17 or older in the sysroot's: a link
# that took the runner's libc fails the 2.28 audit. And
# libssl must be in NEEDED, or the library was never linked.
# Last, the TU is linked into an executable, the way a build
# script or a test links: the runner's libssl needs glibc
# symbols newer than 2.28, which only the runner's loader
# serves, so the shim must leave them to it — the native
# executable is run to show they resolve there.
#
# stow#850: <system-libs-root> is the lock-extracted tree
# install.sh lands; when it is given, the check also covers what
# the lookups now reach through it — every .pc the root carries,
# probed through the exact env env.sh exports (the per-target
# PKG_CONFIG_PATH for the amd64 half, the sysroot-written
# aarch64-linux-gnu-pkg-config wrapper for the arm64 one), and a
# clang --target=<triple> -fsyntax-only of <openssl/ssl.h> with
# the BINDGEN_EXTRA_CLANG_ARGS_<target> bindgen would get. The
# aarch64 pair is checked only when wrappers.sh wrote it.
set -euo pipefail

sysroot="${1:?usage: check-system-libs.sh <sysroot-dir> [<system-libs-root>]}"
syslibs="${2:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/glibc-sysroot/elf-audit.sh
. "$here/elf-audit.sh"

# The exact env the untrusted-build step exports — PATH onto the
# shims and the arm64 pkg-config wrapper, and the per-target
# pkg-config / bindgen variables pointing at the root.
eval "$("$here/env.sh" "$sysroot" ${syslibs:+"$syslibs"})"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/tu.c" <<'C'
#include <openssl/ssl.h>
#include <pthread.h>
static void *pass(void *arg) { return arg; }
int stow_check(void) {
    pthread_t thread;
    if (pthread_create(&thread, 0, pass, 0) != 0) return 1;
    pthread_join(thread, 0);
    return OPENSSL_init_ssl(0, NULL) == 1 ? 0 : 1;
}
C
cat > "$tmp/main.c" <<'C'
int stow_check(void);
int main(void) { return stow_check(); }
C
cat > "$tmp/tu-clang.c" <<'C'
#include <openssl/ssl.h>
int stow_check_clang(void) { return OPENSSL_init_ssl(0, NULL) == 1 ? 0 : 1; }
C

fail() {
    echo "check-system-libs: $*" >&2
    exit 1
}

# Audit one linked output: refuse a GLIBC_ reference above
# 2.28, refuse a missing libssl NEEDED, and print what was seen.
audit() {
    local file="$1" arch="$2" step="$3"
    local glibc
    glibc="$(highest_version "$file" GLIBC_)"
    if [ -n "$glibc" ] && version_over "$glibc" GLIBC_2.28; then
        fail "$file ($step): requires $glibc, above the GLIBC_2.28 floor — the link took the runner's libc"
    fi
    readelf -d "$file" | grep -q 'NEEDED.*libssl\.so' \
        || fail "$file ($step): no libssl in NEEDED — the library was not linked"
    echo "check-system-libs: $arch $(basename "$file"): highest GLIBC ${glibc:-none}"
}

# The library directory the arch's pkg-config reports: the
# root's when it carries the half, else the runner's.
libdir() {
    if [ -n "$syslibs" ] && [ -d "$syslibs/usr/lib/$1" ]; then
        echo "$syslibs/usr/lib/$1"
    else
        echo "/usr/lib/$1"
    fi
}

# Link the TU through one architecture's C shim: as a shared
# object with and without the arch's library directory in
# argv, then as an executable.
check_arch() {
    local arch="$1" cc="$2" triple="$3"
    local searched="$tmp/$arch-searched.so" fallback="$tmp/$arch-fallback.so"
    local exe="$tmp/$arch-exe"
    local libdir
    libdir="$(libdir "$triple")"

    "$cc" -shared -fPIC -I/usr/include -o "$searched" "$tmp/tu.c" \
        -L"$libdir" -lssl -lcrypto -pthread -fuse-ld=mold \
        || fail "$cc ($arch): link with -L$libdir in argv failed"
    audit "$searched" "$arch" "$cc link, -L$libdir in argv"

    "$cc" -shared -fPIC -I/usr/include -o "$fallback" "$tmp/tu.c" \
        -lssl -lcrypto -pthread -fuse-ld=mold \
        || fail "$cc ($arch): link through the shim's own library fallback failed"
    audit "$fallback" "$arch" "$cc link, shim fallback"

    "$cc" -I/usr/include -o "$exe" "$tmp/tu.c" "$tmp/main.c" \
        -L"$libdir" -lssl -lcrypto -pthread -fuse-ld=mold \
        || fail "$cc ($arch): executable link failed"
    audit "$exe" "$arch" "$cc executable link"
}

check_arch x86_64 cc x86_64-linux-gnu
"$tmp/x86_64-exe" \
    || fail "$tmp/x86_64-exe (linked by cc) exited $?"
if [ -x "$sysroot/bin/aarch64-linux-gnu-gcc" ]; then
    check_arch aarch64 aarch64-linux-gnu-gcc aarch64-linux-gnu
fi

# The root halves' pkg-config probes and the bindgen-side clang
# syntax check, per architecture the root carries.
check_pc() {
    local triple="$1" arch_label="$2"
    local dir="$syslibs/usr/lib/$triple/pkgconfig" pc mod
    [ -d "$dir" ] || return 0
    for pc in "$dir"/*.pc "$syslibs/usr/share/pkgconfig"/*.pc; do
        [ -e "$pc" ] || continue
        mod="$(basename "$pc" .pc)"
        case "$arch_label" in
            amd64)
                # The per-target variable's value is what the
                # pkg-config crate feeds the probe.
                PKG_CONFIG_PATH="${PKG_CONFIG_PATH_x86_64_unknown_linux_gnu:-}" \
                    pkg-config --cflags --libs "$mod" > /dev/null \
                    || fail "amd64 pkg-config probe of $mod failed"
                ;;
            arm64)
                aarch64-linux-gnu-pkg-config --cflags --libs "$mod" > /dev/null \
                    || fail "arm64 pkg-config probe of $mod failed through the wrapper"
                ;;
        esac
        echo "check-system-libs: $arch_label $mod.pc probes clean"
    done
}

check_bindgen() {
    local triple="$1" clang_target="$2" utarget="$3" var args
    var="BINDGEN_EXTRA_CLANG_ARGS_$utarget"
    [ -d "$syslibs/usr/lib/$triple" ] || return 0
    [ -n "${!var:-}" ] || fail "$var unset though the root carries $triple — env.sh drifted"
    command -v clang > /dev/null || fail "clang missing — bindgen needs it on the image"
    read -ra args <<< "${!var}"
    clang --target="$clang_target" -fsyntax-only "${args[@]}" "$tmp/tu-clang.c" \
        || fail "clang --target=$clang_target -fsyntax-only of <openssl/ssl.h> failed with $var"
    echo "check-system-libs: clang --target=$clang_target parses <openssl/ssl.h>"
}

if [ -n "$syslibs" ] && [ -d "$syslibs" ]; then
    check_pc x86_64-linux-gnu amd64
    check_bindgen x86_64-linux-gnu x86_64-unknown-linux-gnu x86_64_unknown_linux_gnu
    check_pc aarch64-linux-gnu arm64
    check_bindgen aarch64-linux-gnu aarch64-unknown-linux-gnu aarch64_unknown_linux_gnu
fi