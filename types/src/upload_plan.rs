//! Upload planning: the `PlannedArtifact` list CI produces after a build, and
//! the compile-key hash that binds a cached artifact to one exact rustc
//! invocation identity.

use std::collections::BTreeMap;
use std::path::PathBuf;

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::api::ArtifactRecord;
use crate::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use crate::bundle::ArtifactBundleFile;
use crate::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
    WireRustcVersion,
};
use crate::platform::Profile;

/// One artifact CI plans to upload after a build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedArtifact {
    /// Stable hash of the rustc invocation identity.
    pub compile_key: String,
    /// Crate name.
    pub crate_name: CrateName,
    /// Crate version.
    pub crate_version: CrateVersion,
    /// Cargo `-C metadata` value.
    pub c_metadata: CMetadata,
    /// Cargo `-C extra-filename` suffix.
    pub extra_filename: String,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Sorted dependency identities driving the cache key.
    pub dependency_c_metadata_json: DependencyCMetadataJson,
    /// JSON-encoded compile keys of dependencies.
    pub dependency_compile_keys_json: String,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Cargo profile.
    pub profile: Profile,
    /// Sorted, deduplicated emit modes.
    pub emit: Vec<String>,
    /// OCI reference where this artifact will be pushed.
    pub oci_reference: String,
    /// Artifact kind (rlib / dylib / proc-macro).
    pub kind: ArtifactKind,
    /// Declared crate types.
    pub crate_types: Vec<RustCrateType>,
    /// Size in bytes.
    pub artifact_size: u64,
    /// Wall-clock milliseconds the captured rustc invocation took.
    pub compile_millis: u64,
    /// Files that will be packaged into the bundle.
    pub outputs: Vec<PlannedArtifactOutput>,
    /// The unit shape the builder recorded for this artifact — which side
    /// of the host/target boundary it serves, the cargo invocation
    /// spelling that produced it, and whether it links.
    #[serde(default)]
    pub unit_shape: Option<crate::public_cache::UnitShape>,
    /// Optional native (C/C++) artifacts captured from the build script.
    pub native: Option<NativeArtifacts>,
    /// The packed `OUT_DIR` tree for `native`, pushed as an extra OCI layer
    /// after `outputs`.
    #[serde(default)]
    pub native_archive: Option<PlannedArtifactOutput>,
}

/// One output file from a planned artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedArtifactOutput {
    /// Filesystem path to the output.
    pub path: PathBuf,
    /// Bundle metadata for this file.
    pub bundle_file: ArtifactBundleFile,
}

/// Build `ArtifactRecord` rows for D1 registration from upload plans.
///
/// # Errors
/// Returns an error when a plan's `oci_reference` has no entry in
/// `digests_by_reference` — the OCI push produced no manifest digest for a
/// planned artifact.
/// A published artifact's registry coordinates: the OCI manifest digest of
/// the signed artifact and the digest and size of its `<tag>.bundle` layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedArtifact {
    /// OCI manifest digest (`sha256:…`) of the signed artifact.
    pub oci_digest: String,
    /// Digest (`sha256:…`) of the bundle tar layer.
    pub bundle_digest: String,
    /// Size in bytes of the bundle tar.
    pub bundle_size: u64,
}

/// Build the records the register endpoint stores, one per plan.
///
/// Coordinates come from each plan's published entry;
/// `min_glibc_by_reference` carries the floor the publish stage measured
/// on each plan's outputs — `None` for an artifact with no glibc
/// requirement.
///
/// # Errors
/// Returns an error when a plan's `oci_reference` has no published entry
/// or no measured floor — a record must never register as unmeasured.
pub fn build_artifact_records(
    plans: &[PlannedArtifact],
    published_by_reference: &BTreeMap<String, PublishedArtifact>,
    min_glibc_by_reference: &BTreeMap<String, Option<crate::glibc::GlibcVersion>>,
) -> crate::error::Result<Vec<ArtifactRecord>> {
    let mut records = Vec::with_capacity(plans.len());

    for plan in plans {
        let Some(published) = published_by_reference.get(&plan.oci_reference) else {
            return Err(crate::stow_error!(
                "missing published coordinates for reference {}",
                plan.oci_reference
            ));
        };
        let Some(min_glibc) = min_glibc_by_reference.get(&plan.oci_reference) else {
            return Err(crate::stow_error!(
                "missing measured glibc floor for reference {}",
                plan.oci_reference
            ));
        };

        records.push(ArtifactRecord {
            compile_key: plan.compile_key.clone(),
            c_metadata: plan.c_metadata.clone(),
            extra_filename: plan.extra_filename.clone(),
            target: plan.target.clone(),
            rustc_version: plan.rustc_version.clone(),
            profile: plan.profile.clone(),
            emit: plan.emit.clone(),
            crate_name: plan.crate_name.clone(),
            version: plan.crate_version.clone(),
            features_json: plan.features_json.clone(),
            dependency_c_metadata_json: plan.dependency_c_metadata_json.clone(),
            oci_reference: plan.oci_reference.clone(),
            oci_digest: published.oci_digest.clone(),
            has_native: plan.native.is_some(),
            artifact_kind: plan.kind.clone(),
            crate_types: plan.crate_types.clone(),
            artifact_size: plan.artifact_size,
            bundle_digest: published.bundle_digest.clone(),
            bundle_size: published.bundle_size,
            compile_millis: plan.compile_millis,
            unit_shape: plan.unit_shape,
            min_glibc: *min_glibc,
        });
    }

    Ok(records)
}

/// The identity inputs hashed into a compile key.
///
/// A compile key binds an artifact to one exact rustc invocation identity —
/// crate coordinates, toolchain, profile, emit set, and dependency
/// identities — so two invocations sharing a key produce interchangeable
/// artifacts.
#[derive(Debug)]
pub struct CompileKeyInputs<'a> {
    /// crates.io package name.
    pub crate_name: &'a str,
    /// Crate version string.
    pub crate_version: &'a str,
    /// Compilation target triple.
    pub target: &'a str,
    /// rustc version string.
    pub rustc_version: &'a str,
    /// Normalized compile profile.
    pub profile: &'a Profile,
    /// Declared crate types.
    pub crate_types: &'a [RustCrateType],
    /// Sorted, deduplicated `--emit` kinds.
    pub emit: &'a [String],
    /// Canonical JSON-encoded features list.
    pub features_json: &'a str,
    /// Canonical JSON-encoded dependency `c_metadata` identities.
    pub dependency_c_metadata_json: &'a str,
    /// Primary artifact kind.
    pub kind: &'a ArtifactKind,
    /// `-Z embed-metadata` value when the invocation carried the flag
    /// (nightly cargo emits it on every unit). `None` hashes to the same
    /// key invocations produced before the flag was modeled.
    pub embed_metadata: Option<bool>,
    /// Sorted, deduplicated `--cfg` values other than `feature="…"`
    /// (build-script `cargo:rustc-cfg` output). An empty list hashes to
    /// the same key invocations produced before cfgs were modeled.
    pub cfgs: &'a [String],
    /// Whether the object files carry LLVM bitcode (`-C embed-bitcode`
    /// absent or `yes`). `false` — the value cargo passes to every unit no
    /// LTO consumer needs bitcode from — hashes to the same key invocations
    /// produced before the flag was modeled.
    pub embed_bitcode: bool,
    /// Sorted link-steering `-C` options that reach a link step for this
    /// unit. Empty for every rlib, because rustc never runs a linker to
    /// produce one, and empty for a linked unit that chose no link options
    /// — so an empty list hashes to the same key invocations produced
    /// before the linker was modeled.
    pub link_options: &'a [String],
}

/// Compute the BLAKE3 compile key over an invocation's identity inputs.
///
/// # Errors
/// Returns an error when `profile`, `crate_types`, or `emit` fail to
/// serialize for hashing.
pub fn compute_compile_key(inputs: &CompileKeyInputs<'_>) -> crate::error::Result<String> {
    let mut hasher = Hasher::new();
    hasher.update(b"stow-compile-key-v1");
    update_str(&mut hasher, inputs.crate_name);
    update_str(&mut hasher, inputs.crate_version);
    update_str(&mut hasher, inputs.target);
    update_str(&mut hasher, inputs.rustc_version);
    update_str(&mut hasher, inputs.features_json);
    update_str(&mut hasher, inputs.dependency_c_metadata_json);
    update_str(&mut hasher, inputs.kind.as_str());
    update_str(
        &mut hasher,
        &serde_json::to_string(inputs.profile).map_err(|error| {
            crate::stow_error!(
                "serialize compile profile for {} {}: {error}",
                inputs.crate_name,
                inputs.crate_version
            )
        })?,
    );
    update_str(
        &mut hasher,
        &serde_json::to_string(inputs.crate_types).map_err(|error| {
            crate::stow_error!(
                "serialize crate types for {} {}: {error}",
                inputs.crate_name,
                inputs.crate_version
            )
        })?,
    );
    update_str(
        &mut hasher,
        &serde_json::to_string(inputs.emit).map_err(|error| {
            crate::stow_error!(
                "serialize emit kinds for {} {}: {error}",
                inputs.crate_name,
                inputs.crate_version
            )
        })?,
    );
    if let Some(embed_metadata) = inputs.embed_metadata {
        update_str(&mut hasher, if embed_metadata { "yes" } else { "no" });
    }
    if !inputs.link_options.is_empty() {
        update_str(&mut hasher, "link-options");
        update_str(
            &mut hasher,
            &serde_json::to_string(inputs.link_options).map_err(|error| {
                crate::stow_error!(
                    "serialize link options for {} {}: {error}",
                    inputs.crate_name,
                    inputs.crate_version
                )
            })?,
        );
    }
    if !inputs.cfgs.is_empty() {
        update_str(&mut hasher, "cfgs");
        update_str(
            &mut hasher,
            &serde_json::to_string(inputs.cfgs).map_err(|error| {
                crate::stow_error!(
                    "serialize cfgs for {} {}: {error}",
                    inputs.crate_name,
                    inputs.crate_version
                )
            })?,
        );
    }
    if inputs.embed_bitcode {
        update_str(&mut hasher, "embed-bitcode=yes");
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn update_str(hasher: &mut Hasher, value: &str) {
    let len = u32::try_from(value.len()).expect("hash input string length exceeds u32 range");
    hasher.update(&len.to_le_bytes());
    hasher.update(value.as_bytes());
}
