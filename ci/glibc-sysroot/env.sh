#!/usr/bin/env bash
# Print the glibc-2.28 sysroot build environment as eval-able
# `export` statements — the exact set the untrusted-build step
# of build-crate.yml exports inside its own step, and the same
# set the mock e2e scripts hand the local CI server so its
# dispatched builds link the way production builds.
#
# Usage: eval "$(ci/glibc-sysroot/env.sh <sysroot-dir> [<system-libs-root>])"
#
# <system-libs-root> is the lock-extracted tree install.sh lands
# (stow#850); each export below appears only for the part of the
# root that exists — an x86_64 leg has no arm64 half, so the arm64
# entries stay absent there. `STOW_SYSTEM_LIBS` grants the tree
# through the toolchain passthrough like the sysroot's; the
# pkg-config, bindgen and CMake variables point each lookup at the
# root — per-target spellings, so a host probe keeps the native
# pkg-config and the aarch64 one is the wrapper wrappers.sh wrote
# (PKG_CONFIG_aarch64_unknown_linux_gnu keeps its job-set value).
# The amd64 pkg-config path uses PKG_CONFIG_PATH (not LIBDIR): the
# listed libraries win while the image's unlisted .pc files stay
# visible.
# Scope: the caller's step/process only, never a shared env
# file. stow's own tooling links the host's glibc; the sysroot
# belongs to the task's crate build alone. PATH leads to
# the shims — inside the sandbox every `cc`/`gcc`/`aarch64-*`
# lookup lands on them — and STOW_GLIBC_SYSROOT grants the
# tree through stow-build's toolchain passthrough. Nothing
# enters rustc argv: the compile key stays
# [link-arg=-fuse-ld=mold].
#
# Rust links reach the sysroot through the `cc` PATH shim — env,
# not argv, so a linked unit's compile key stays exactly
# `[link-arg=-fuse-ld=mold]`, the mold pin the capture wrapper
# already appends. `CARGO_TARGET_*_LINKER` cannot carry this: the
# driver name lands in argv as `-C linker=`, a key term a machine
# path would poison (and the published rows predate any wrapper).
# C compiles reach it through `CC_<triple>`/`CXX_<triple>` wrappers
# that add `--sysroot`, so cc-rs and cmake objects compile against
# the 2.28 headers.
set -euo pipefail

sysroot="${1:?usage: env.sh <sysroot-dir> [<system-libs-root>]}"
root="${2:-}"

# shellcheck disable=SC2016 # the $PATH is the export's literal text
printf 'export PATH="%s/bin:$PATH"\n' "$sysroot"
printf 'export STOW_GLIBC_SYSROOT="%s"\n' "$sysroot"

[ -n "$root" ] && [ -d "$root" ] || exit 0
printf 'export STOW_SYSTEM_LIBS="%s"\n' "$root"
[ -d "$root/usr" ] || exit 0
printf 'export CMAKE_PREFIX_PATH="%s"\n' "$root/usr"
for pair in \
    "x86_64-linux-gnu x86_64_unknown_linux_gnu" \
    "aarch64-linux-gnu aarch64_unknown_linux_gnu"; do
    triple="${pair%% *}"
    utarget="${pair##* }"
    [ -d "$root/usr/lib/$triple" ] || continue
    if [ "$triple" = x86_64-linux-gnu ]; then
        printf 'export PKG_CONFIG_PATH_%s="%s"\n' "$utarget" \
            "$root/usr/lib/$triple/pkgconfig:$root/usr/share/pkgconfig"
    fi
    printf 'export BINDGEN_EXTRA_CLANG_ARGS_%s="-isystem %s -isystem %s"\n' \
        "$utarget" "$root/usr/include/$triple" "$root/usr/include"
done