#!/usr/bin/env bash
# Prove a -sys crate's system library builds and links through
# the glibc-2.28 sysroot shims: the runner's headers and
# libraries are found, and the sysroot's glibc still wins.
#
# Usage: ci/glibc-sysroot/check-system-libs.sh <sysroot-dir>
#
# stow#729: openssl-sys failed on both Linux legs because the
# shims never searched the runner's multiarch include directory,
# where Ubuntu keeps openssl/opensslconf.h. The TU here includes
# <openssl/ssl.h> with `-I/usr/include` the way openssl-sys's
# build script names the include directory pkg-config reports,
# and is linked as a shared object — the shape a proc-macro or
# cdylib links in — against -lssl -lcrypto twice: once with the
# runner's library directory in argv, the way rustc forwards a
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
# executable is run to show they resolve there. The aarch64
# pair is checked only when wrappers.sh wrote it, and needs
# the arm64 packages system-libs.sh installs.
set -euo pipefail

sysroot="${1:?usage: check-system-libs.sh <sysroot-dir>}"
# shellcheck source=ci/glibc-sysroot/elf-audit.sh
. "$(dirname "${BASH_SOURCE[0]}")/elf-audit.sh"

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

export PATH="$sysroot/bin:$PATH"

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

# Link the TU through one architecture's C shim: as a shared
# object with and without the runner's library directory in
# argv, then as an executable.
check_arch() {
    local arch="$1" cc="$2" triple="$3"
    local searched="$tmp/$arch-searched.so" fallback="$tmp/$arch-fallback.so"
    local exe="$tmp/$arch-exe"

    "$cc" -shared -fPIC -I/usr/include -o "$searched" "$tmp/tu.c" \
        -L"/usr/lib/$triple" -lssl -lcrypto -pthread -fuse-ld=mold \
        || fail "$cc ($arch): link with -L/usr/lib/$triple failed — is the $arch build of libssl-dev installed (ci/glibc-sysroot/system-libs.sh)?"
    audit "$searched" "$arch" "$cc link, -L/usr/lib/$triple in argv"

    "$cc" -shared -fPIC -I/usr/include -o "$fallback" "$tmp/tu.c" \
        -lssl -lcrypto -pthread -fuse-ld=mold \
        || fail "$cc ($arch): link through the shim's own library fallback failed"
    audit "$fallback" "$arch" "$cc link, shim fallback"

    "$cc" -I/usr/include -o "$exe" "$tmp/tu.c" "$tmp/main.c" \
        -L"/usr/lib/$triple" -lssl -lcrypto -pthread -fuse-ld=mold \
        || fail "$cc ($arch): executable link failed — the runner's libssl needs glibc symbols the sysroot's libc does not define"
    audit "$exe" "$arch" "$cc executable link"
}

check_arch x86_64 cc x86_64-linux-gnu
"$tmp/x86_64-exe" \
    || fail "$tmp/x86_64-exe (linked by cc) exited $?"
if [ -x "$sysroot/bin/aarch64-linux-gnu-gcc" ]; then
    check_arch aarch64 aarch64-linux-gnu-gcc aarch64-linux-gnu
fi
