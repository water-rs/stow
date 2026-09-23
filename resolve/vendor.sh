#!/usr/bin/env bash
# Vendors cargo's resolver pipeline into stow-resolve.
# Source: cargo tag 0.99.0, commit 797e8a9bca276c1c9f9f738d2a20f484fa4eea9d.
# Each vendored file gets a provenance header; boundary imports are rewritten.
set -euo pipefail
SRC=${1:-$HOME/repos/cargo-src}
DST=${2:-$HOME/repos/stow/resolve/src}

FILES="
core/dependency.rs
core/features.rs
core/manifest.rs
core/package.rs
core/package_id.rs
core/package_id_spec.rs
core/profiles.rs
core/registry.rs
core/source_id.rs
core/summary.rs
core/workspace.rs
core/compiler/compile_kind.rs
core/compiler/crate_type.rs
core/compiler/artifact.rs
core/compiler/build_context/target_info.rs
core/resolver/mod.rs
core/resolver/conflict_cache.rs
core/resolver/context.rs
core/resolver/dep_cache.rs
core/resolver/encode.rs
core/resolver/errors.rs
core/resolver/features.rs
core/resolver/resolve.rs
core/resolver/types.rs
core/resolver/version_prefs.rs
ops/cargo_output_metadata.rs
ops/lockfile.rs
ops/resolve.rs
ops/cargo_read_manifest.rs
ops/cargo_compile/packages.rs
sources/config.rs
sources/overlay.rs
sources/path.rs
sources/replaced.rs
sources/source.rs
sources/registry/mod.rs
sources/registry/index/mod.rs
sources/registry/index/cache.rs
util/cache_lock.rs
util/canonical_url.rs
util/counter.rs
util/dependency_queue.rs
util/edit_distance.rs
util/errors.rs
util/flock.rs
util/frontmatter.rs
util/graph.rs
util/hasher.rs
util/hex.rs
util/important_paths.rs
util/interning.rs
util/into_url.rs
util/into_url_with_base.rs
util/local_poll_adapter.rs
util/restricted_names.rs
util/rustc.rs
util/semver_eval_ext.rs
util/semver_ext.rs
util/time_span.rs
util/unhashed.rs
util/once.rs
util/workspace.rs
util/context/schema.rs
util/context/target.rs
util/context/path.rs
util/context/value.rs
util/context/key.rs
util/toml/mod.rs
util/toml/targets.rs
util/toml/embedded.rs
diagnostics/report.rs
"

for f in $FILES; do
    mkdir -p "$DST/$(dirname "$f")"
    cp "$SRC/src/cargo/$f" "$DST/$f"
done

# Mechanical import rewrites: boundary crates -> our shims.
find "$DST" -name '*.rs' | while read -r f; do
  sed -i \
    -e 's/cargo_util::paths/crate::util::paths/g' \
    -e 's/cargo_util::registry/crate::util::registry/g' \
    -e 's/cargo_util::Sha256/crate::util::sha256::Sha256/g' \
    -e 's/cargo_util::ProcessBuilder/crate::util::process::ProcessBuilder/g' \
    -e 's/cargo_util::ProcessError/crate::util::process::ProcessError/g' \
    -e 's/cargo_util::exit_status_to_string/crate::util::process::exit_status_to_string/g' \
    -e 's/cargo_util_terminal::report/crate::util::report/g' \
    -e 's/cargo_util_terminal::Verbosity/crate::util::report::Verbosity/g' \
    -e 's/cargo_util_terminal::AnstyleHyperlink/crate::util::report::AnstyleHyperlink/g' \
    -e 's/cargo_util_terminal::self_or_auto_style/crate::util::report::self_or_auto_style/g' \
    -e 's/\bcargo_util::{\([^}]*\)ProcessBuilder/crate::util::process::{ProcessBuilder}/g' \
    "$f"
done
echo "vendored $(echo "$FILES" | wc -w) files"
