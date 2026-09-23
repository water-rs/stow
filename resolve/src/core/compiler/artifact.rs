//! Artifact matching for `[dependencies] artifact = "..."`.
//!
//! Cargo's `artifact.rs` also carries `get_env` which binds a
//! `BuildRunner`'s unit graph — build-phase machinery that does not exist in
//! a resolver. Only the matching used by `cargo_output_metadata` is kept.

use crate::CargoResult;
use crate::core::dependency::ArtifactKind;
use crate::core::{Dependency, Target};
use std::collections::HashSet;

/// Given a dependency with an artifact `artifact_dep` and a set of available `targets`
/// of its package, find a target for each kind of artifacts that are to be built.
///
/// Failure to match any target results in an error mentioning the parent manifests
/// `parent_package` name.
pub(crate) fn match_artifacts_kind_with_targets<'t, 'd>(
    artifact_dep: &'d Dependency,
    targets: &'t [Target],
    parent_package: &str,
) -> CargoResult<HashSet<(&'d ArtifactKind, &'t Target)>> {
    let mut out = HashSet::new();
    let artifact_requirements = artifact_dep.artifact().expect("artifact present");
    for artifact_kind in artifact_requirements.kinds() {
        let mut extend = |kind, filter: &dyn Fn(&&Target) -> bool| {
            let mut iter = targets.iter().filter(filter).peekable();
            let found = iter.peek().is_some();
            out.extend(std::iter::repeat(kind).zip(iter));
            found
        };
        let found = match artifact_kind {
            ArtifactKind::Cdylib => extend(artifact_kind, &|t| t.is_cdylib()),
            ArtifactKind::Staticlib => extend(artifact_kind, &|t| t.is_staticlib()),
            ArtifactKind::AllBinaries => extend(artifact_kind, &|t| t.is_bin()),
            ArtifactKind::SelectedBinary(bin_name) => extend(artifact_kind, &|t| {
                t.is_bin() && t.name() == bin_name.as_str()
            }),
        };
        if !found {
            anyhow::bail!(
                "dependency `{}` in package `{}` requires a `{}` artifact to be present.",
                artifact_dep.name_in_toml(),
                parent_package,
                artifact_kind
            );
        }
    }
    Ok(out)
}
