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
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, DependencyIdentity, FeaturesJson,
    TargetTriple, WireRustcVersion,
};
use crate::platform::Profile;
use crate::rustc::ParsedRustcArgs;

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
    /// The task node's direct child task ids — the sorted, deduplicated
    /// preimage [`Self::dependency_identity`] hashes (stow#919).
    pub dependency_task_ids: Vec<String>,
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
    pub unit_shape: crate::public_cache::UnitShape,
    /// Optional native (C/C++) artifacts captured from the build script.
    pub native: Option<NativeArtifacts>,
    /// The packed `OUT_DIR` tree for `native`, pushed as an extra OCI layer
    /// after `outputs`.
    #[serde(default)]
    pub native_archive: Option<PlannedArtifactOutput>,
}

impl PlannedArtifact {
    /// The build-stage claim of the task's resolved dependency context —
    /// the Merkle digest of the carried child task ids, derived so the
    /// plan can never hold a digest disagreeing with its edges (stow#919).
    ///
    /// # Errors
    /// Mirrors [`DependencyIdentity::from_task_ids`].
    pub fn dependency_identity(&self) -> crate::error::Result<DependencyIdentity> {
        DependencyIdentity::from_task_ids(self.dependency_task_ids.iter().map(String::as_str))
    }
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

/// Build the records a task's signed records artifact carries, one per plan.
///
/// Coordinates come from each plan's published entry;
/// `min_glibc_by_reference` carries the floor the publish stage measured
/// on each plan's outputs — `None` for an artifact with no glibc
/// requirement.
///
/// # Errors
/// Returns an error when a plan's `oci_reference` has no published entry
/// or no measured floor — a record must never be published unmeasured.
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
            dependency_task_ids: plan.dependency_task_ids.clone(),
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
    /// The git source the unit's identity keys under, for a unit whose
    /// input lives in a cargo `git/checkouts/` slot. `None` for a crates.io
    /// unit — hashed only when present, so every published crates.io key
    /// is byte-identical to what it was before git sources were modeled.
    pub git_source: Option<GitSourceInputs<'a>>,
    /// The sorted, normalized `-C`/`-Z` options the registry identity does
    /// not model. Empty for a stock invocation — hashed only when
    /// non-empty, so every published crates.io key is byte-identical.
    pub extra_codegen: &'a [String],
}

/// The git-source identity inputs hashed into a compile key under the
/// `git-source` tag.
#[derive(Debug)]
pub struct GitSourceInputs<'a> {
    /// The full commit id the checkout is reset to.
    pub commit: &'a str,
    /// The manifest directory's path inside the repository.
    pub manifest_path_in_repo: &'a str,
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
    // rustc's check defaults (debug assertions on only at opt-level 0) were
    // once mislabeled as cargo's debug values, so a profile that differs
    // from the dev profile is tagged: a local entry keyed before the
    // correction can never answer a request keyed after it. The dev
    // profile, which every published node has, hashes exactly as before.
    if inputs.profile.opt_level != "0" || !inputs.profile.debug_assertions {
        update_str(&mut hasher, "rustc-check-defaults");
    }
    if let Some(git_source) = &inputs.git_source {
        update_str(&mut hasher, "git-source");
        update_str(&mut hasher, git_source.commit);
        update_str(&mut hasher, git_source.manifest_path_in_repo);
    }
    if !inputs.extra_codegen.is_empty() {
        update_str(&mut hasher, "extra-codegen");
        update_str(
            &mut hasher,
            &serde_json::to_string(inputs.extra_codegen).map_err(|error| {
                crate::stow_error!(
                    "serialize extra codegen options for {} {}: {error}",
                    inputs.crate_name,
                    inputs.crate_version
                )
            })?,
        );
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// The compile inputs one build script's output contributes to an
/// invocation: the `--cfg` and link arguments cargo adds from its
/// `cargo:rustc-cfg` and `cargo:rustc-link-arg` directives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildScriptInputs {
    /// Non-feature `--cfg` values, in directive order.
    pub cfgs: Vec<String>,
    /// Link arguments, in `link-arg=…` spelling and directive order.
    pub link_args: Vec<String>,
}

impl BuildScriptInputs {
    /// Read the inputs from a build script's captured `cargo:` lines.
    /// `cfg` values go through the argv parser's own reading, so a cfg is
    /// sorted into feature or other exactly as it is on a command line.
    #[must_use]
    pub fn from_directives(directives: &[String]) -> Self {
        let mut inputs = Self::default();
        for directive in directives {
            let Some(body) = directive
                .strip_prefix("cargo::")
                .or_else(|| directive.strip_prefix("cargo:"))
            else {
                continue;
            };
            match body.split_once('=') {
                Some(("rustc-cfg", cfg)) if crate::rustc::parse_feature_cfg(cfg).is_none() => {
                    inputs.cfgs.push(cfg.to_owned());
                }
                Some(("rustc-link-arg", arg)) => inputs.link_args.push(format!("link-arg={arg}")),
                _ => {}
            }
        }
        inputs
    }

    /// The inputs of the build script that owns `out_dir`, read from the
    /// `output` file beside it; none for a crate without a build script.
    ///
    /// # Errors
    /// Fails when `out_dir` is set and its build script output cannot be
    /// read (see [`crate::native_capture::read_build_script_directives`]).
    pub fn of_out_dir(
        crate_name: &str,
        out_dir: Option<&std::path::Path>,
    ) -> crate::error::Result<Self> {
        let Some(out_dir) = out_dir else {
            return Ok(Self::default());
        };
        Ok(Self::from_directives(
            &crate::native_capture::read_build_script_directives(crate_name, out_dir)?,
        ))
    }

    /// The inputs of a published artifact's captured build-script output;
    /// none for a crate without a build script.
    #[must_use]
    pub fn of(native: Option<&NativeArtifacts>) -> Self {
        native.map_or_else(Self::default, |native| {
            Self::from_directives(&native.cargo_directives)
        })
    }
}

/// The compile inputs a consumer's own invocation carries, apart from its
/// build script's output (stow#1047).
///
/// Published nodes are built in the dev profile with no extra flags, so
/// none of these are ever part of one. A semantic match stands a published
/// artifact in for a request and must prove it was compiled with the same
/// ones: [`candidate_compile_key`] recomputes the candidate's key under
/// these inputs and the match holds only when it is the key the candidate
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerInputs {
    /// `-Z embed-metadata`, when the invocation carried the flag.
    pub embed_metadata: Option<bool>,
    /// Whether the object files carry LLVM bitcode.
    pub embed_bitcode: bool,
    /// The `-C`/`-Z` options the registry identity does not model, in
    /// argv order.
    pub extra_codegen: Vec<String>,
    /// Non-feature `--cfg` values in argv order, build-script output
    /// removed.
    pub cfgs: Vec<String>,
    /// Link-steering `-C` options in argv order, build-script output
    /// removed.
    pub link_options: Vec<String>,
}

impl ConsumerInputs {
    /// The consumer's inputs: the invocation's, minus what `own` — the
    /// output of the invocation's own build script — contributed.
    ///
    /// Cargo emits one argument per directive, so the subtraction counts:
    /// a cfg set by both `RUSTFLAGS` and the build script appears twice
    /// on argv and once after removing the build script's.
    #[must_use]
    pub fn of(parsed: &ParsedRustcArgs, own: &BuildScriptInputs) -> Self {
        Self {
            embed_metadata: parsed.embed_metadata,
            embed_bitcode: parsed.embed_bitcode,
            extra_codegen: parsed.extra_codegen.clone(),
            cfgs: without_each(&parsed.cfg_args, &own.cfgs),
            link_options: without_each(&parsed.link_options, &own.link_args),
        }
    }

    /// The inputs of a stock invocation: nothing of the consumer's own
    /// beyond the bitcode every default compile embeds.
    #[must_use]
    pub const fn stock() -> Self {
        Self {
            embed_metadata: None,
            embed_bitcode: true,
            extra_codegen: Vec::new(),
            cfgs: Vec::new(),
            link_options: Vec::new(),
        }
    }

    /// Whether the inputs have a shape a published node can have: no cfg
    /// of the consumer's own, no extra codegen, no `embed-metadata` flag.
    /// A request that does not can only be answered by a local build.
    #[must_use]
    pub const fn is_publishable_shape(&self) -> bool {
        self.cfgs.is_empty() && self.extra_codegen.is_empty() && self.embed_metadata.is_none()
    }
}

/// `all` with one occurrence of each of `removed` taken out.
fn without_each(all: &[String], removed: &[String]) -> Vec<String> {
    let mut remaining = all.to_vec();
    for value in removed {
        if let Some(position) = remaining.iter().position(|candidate| candidate == value) {
            remaining.remove(position);
        }
    }
    remaining
}

/// The recorded identity of an artifact a semantic match proposes to
/// serve.
#[derive(Debug)]
pub struct CandidateIdentity<'a> {
    /// crates.io package name.
    pub crate_name: &'a str,
    /// Crate version string.
    pub crate_version: &'a str,
    /// Compilation target triple.
    pub target: &'a str,
    /// rustc version string.
    pub rustc_version: &'a str,
    /// Canonical JSON-encoded features list the key hashed.
    pub features_json: &'a str,
    /// Canonical JSON-encoded dependency `c_metadata` identities.
    pub dependency_c_metadata_json: &'a str,
    /// Primary artifact kind.
    pub kind: &'a ArtifactKind,
    /// Normalized compile profile.
    pub profile: &'a Profile,
    /// Declared crate types.
    pub crate_types: &'a [RustCrateType],
    /// Sorted, deduplicated `--emit` kinds.
    pub emit: &'a [String],
}

/// The compile key `candidate` would carry had it been compiled with the
/// consumer's inputs and `build_script`'s output.
///
/// Every input the key hashes is either the candidate's own recorded
/// identity or one of the two arguments, so equality with the key the
/// candidate carries proves the candidate was compiled with exactly them.
/// Cfgs are the consumer's and the build script's together; link options
/// count only for a crate type that reaches the linker.
///
/// # Errors
/// Returns an error when the identity fails to serialize for hashing.
pub fn candidate_compile_key(
    candidate: &CandidateIdentity<'_>,
    consumer: &ConsumerInputs,
    build_script: &BuildScriptInputs,
) -> crate::error::Result<String> {
    let mut cfgs = consumer.cfgs.clone();
    cfgs.extend(build_script.cfgs.iter().cloned());
    cfgs.sort();
    cfgs.dedup();
    let links = candidate.crate_types.iter().any(|crate_type| {
        matches!(
            crate_type,
            RustCrateType::ProcMacro | RustCrateType::Dylib | RustCrateType::Cdylib
        )
    });
    let link_options = if links {
        let mut raw = consumer.link_options.clone();
        raw.extend(build_script.link_args.iter().cloned());
        crate::rustc::canonical_link_options(&raw)
    } else {
        Vec::new()
    };
    compute_compile_key(&CompileKeyInputs {
        crate_name: candidate.crate_name,
        crate_version: candidate.crate_version,
        target: candidate.target,
        rustc_version: candidate.rustc_version,
        profile: candidate.profile,
        crate_types: candidate.crate_types,
        emit: candidate.emit,
        features_json: candidate.features_json,
        dependency_c_metadata_json: candidate.dependency_c_metadata_json,
        kind: candidate.kind,
        embed_metadata: consumer.embed_metadata,
        cfgs: &cfgs,
        embed_bitcode: consumer.embed_bitcode,
        link_options: &link_options,
        git_source: None,
        extra_codegen: &consumer.extra_codegen,
    })
}

fn update_str(hasher: &mut Hasher, value: &str) {
    let len = u32::try_from(value.len()).expect("hash input string length exceeds u32 range");
    hasher.update(&len.to_le_bytes());
    hasher.update(value.as_bytes());
}
