#!/usr/bin/env bash
# Print the glibc-2.28 sysroot build environment as eval-able
# `export` statements — the exact set the untrusted-build step
# of build-crate.yml exports inside its own step, and the same
# set the mock e2e scripts hand the local CI server so its
# dispatched builds link the way production builds.
#
# Usage: eval "$(ci/glibc-sysroot/env.sh <sysroot-dir>)"
#
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

sysroot="${1:?usage: env.sh <sysroot-dir>}"

printf 'export PATH="%s/bin:$PATH"\n' "$sysroot"
printf 'export STOW_GLIBC_SYSROOT="%s"\n' "$sysroot"
