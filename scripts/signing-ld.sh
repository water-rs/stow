#!/usr/bin/env bash
# Linker for the `stow-admin` binary only, selected by admin/build.rs
# through clang's `--ld-path` when STOW_LOCAL_SIGNING_IDENTITY is set on
# a macOS build (docs/USAGE.md, "Local code signing"): runs the real
# `ld`, then re-signs its `-o` output with that identity so the keychain
# ACL's "Always Allow" survives rebuilds. A codesign failure — including
# an identity codesign cannot find — fails the link. Reaching this
# script with the variable unset is an error, not a skip: the build
# script only selects it when the variable was set.
set -euo pipefail

identity=${STOW_LOCAL_SIGNING_IDENTITY:-}
if [[ -z $identity ]]; then
    echo "signing-ld: STOW_LOCAL_SIGNING_IDENTITY is empty — admin/build.rs only selects this linker when it was set; restore it or rebuild without it" >&2
    exit 1
fi

# clang hands the whole ld command line through a response file when it
# is long — every stow-admin link is — so argv can hold only
# @<tmpdir>/response-N.txt. Expand @file arguments to find the -o
# output; ld itself gets the original argv unchanged (it expands the
# file on its own). Response-file tokens are whitespace-separated with
# shell-style quoting, the grammar xargs applies.
args=()
for arg in "$@"; do
    if [[ $arg == @* ]]; then
        rsp=${arg#@}
        if [[ ! -f $rsp ]]; then
            echo "signing-ld: response file $rsp not found" >&2
            exit 1
        fi
        while IFS= read -r tok; do
            args+=("$tok")
        done < <(xargs -n1 printf '%s\n' <"$rsp")
    else
        args+=("$arg")
    fi
done

out=
prev=
for arg in "${args[@]}"; do
    if [[ $prev == -o ]]; then
        out=$arg
        break
    fi
    prev=$arg
done
# This wrapper exists only for the stow-admin binary's link, which
# always names its output: an invocation with no -o is a defect, not a
# probe to skip.
if [[ -z $out ]]; then
    echo "signing-ld: no -o in the ld command line — cannot find the output to sign" >&2
    exit 1
fi

ld "$@"

# --timestamp=none: the default timestamp path can call a network
# authority, which has no business on the link path.
if ! codesign --sign "$identity" --force --timestamp=none "$out"; then
    echo "signing-ld: codesign --sign '$identity' failed on $out" >&2
    echo "signing-ld: create the identity with scripts/local-signing-identity.sh, or unset STOW_LOCAL_SIGNING_IDENTITY" >&2
    exit 1
fi
