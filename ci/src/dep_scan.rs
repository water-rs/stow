use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use async_process::Command;
use cargo_metadata::{Metadata, Package, PackageId, Target, TargetKind};
use sha2::Digest as _;
use stow_types::api::BuildTaskPayload;
use stow_types::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use stow_types::platform::Profile;

use crate::task::{BuildWorkspace, BuiltWorkspace, CargoFeatureArgs, WorkspaceKind};
use stow_types::capture::{
    CapturedDependencyIdentity, CapturedRustcArtifact, CapturedRustcOutput, CapturedRustcOutputKind,
};

/// The scan output plus the completeness invariant the build stage records:
/// how many restorable records the collector delivered and the artifacts
/// planned from them. The two counts are written to `scan.json` so a lost
/// record can never masquerade as a complete scan.
#[derive(Debug, serde::Serialize)]
pub struct ScanReport {
    /// Restorable rustc-unit records the host collector delivered.
    pub restorable_captures: usize,
    /// One planned artifact per restorable record — enforced, not assumed.
    pub artifacts: Vec<ScannedArtifact>,
    /// Verified published artifacts the capture wrapper served instead of
    /// compiling — nothing is planned from them, but dependents resolved
    /// their `--extern` edges against their recorded outputs, and the
    /// publish stage requires the signed index to vouch for every claim
    /// before it counts toward closure coverage.
    pub consumed: Vec<ConsumedArtifact>,
}

/// A verified published artifact the build served instead of compiling the
/// crate: produced by no rustc invocation here, so nothing is planned from
/// it. The record exists so dependents resolve `--extern` edges against
/// the injected outputs and the publish stage can check the claim against
/// the signed index — an artifact naming a crate outside the task's
/// resolved closure is still refused.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsumedArtifact {
    /// Canonical package name the capture attributed to.
    pub crate_name: String,
    /// The published artifact's crate version.
    pub crate_version: String,
    /// Blake3 compile key — the store lookup key the wrapper used.
    pub compile_key: String,
    /// The artifact's stable `-C metadata` value.
    pub c_metadata: String,
    /// The compilation target triple the artifact serves.
    pub target: String,
    /// The stable rustc version the index slice keys on.
    pub rustc_version: String,
    /// The served unit's emit set — a `link` emit is what covers the
    /// closure's library-package coverage rule exactly like a planned
    /// build-phase artifact.
    pub emit: Vec<String>,
}

/// A [`ConsumedArtifact`] plus every record that claimed it — one per
/// phase the unit was served in, all describing the same verified bundle.
/// Internal scan state, kept separate so the serialized claim carries only
/// the identity the publish stage verifies.
struct ConsumedCapture {
    artifact: ConsumedArtifact,
    records: Vec<CapturedRustcArtifact>,
}

/// Which kind of record owns an `--extern` output path: the artifact a
/// compiled capture planned, or the verified artifact a unit was served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputOwner {
    Compiled(usize),
    Consumed(usize),
}

pub async fn scan_artifacts(
    built: &BuiltWorkspace,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<ScanReport> {
    let metadata = cargo_metadata(built.workspace(), task).await?;
    let rustc_version = task.rustc_version.as_str().to_owned();
    let package_index = package_index(&metadata, task);
    // The records the host collector received over IPC — the only capture
    // source the scan trusts. Nothing the sandbox wrote to disk qualifies.
    let captured_artifacts = built.captures();
    let restorable_captures = captured_artifacts
        .iter()
        .filter(|captured| captured.restorable)
        .count();

    let selected = select_captured_artifacts(&package_index, captured_artifacts)?;
    let plan_eligible_captures = restorable_captures - selected.absorbed_duplicates;
    let selected = selected.artifacts;
    let consumed_captures =
        collect_consumed_captures(&package_index, captured_artifacts, &rustc_version)?;
    // Every output about to be planned — and every output a served artifact
    // claims — must still be the bytes the wrapper hashed the moment rustc
    // exited or the verified bundle was injected. A build script that ran
    // later in the same phase could have rewritten an earlier unit's
    // output — or its snapshot — inside the shared target/capture dirs, so
    // anything that no longer matches its recorded digest is fatal, not
    // droppable.
    verify_output_digests(
        selected.iter().map(|artifact| &artifact.captured).chain(
            consumed_captures
                .iter()
                .flat_map(|capture| capture.records.iter()),
        ),
    )
    .await?;
    let output_owners = output_owner_index(&selected, &consumed_captures)?;
    let mut resolved = BTreeMap::<usize, ResolvedArtifact>::new();
    let mut visiting = BTreeSet::<usize>::new();
    let mut cx = ResolveCx {
        selected: &selected,
        consumed: &consumed_captures,
        output_owners: &output_owners,
        resolved: &mut resolved,
        visiting: &mut visiting,
    };

    let mut artifacts = Vec::with_capacity(selected.len());
    for index in 0..selected.len() {
        artifacts.push(build_scanned_artifact(task, &rustc_version, &mut cx, index).await?);
    }
    // One artifact per restorable record is the completeness invariant the
    // whole scan exists to keep: every path that could drop one is an error
    // above, so reaching a different count is a bug in this file, not data.
    // The one deliberate exclusion is the proven-identical same-unit
    // captures a unit leaves in several phases.
    if artifacts.len() != plan_eligible_captures {
        return Err(stow_types::stow_error!(
            "dep_scan received {plan_eligible_captures} restorable capture records but planned {} artifacts",
            artifacts.len()
        ));
    }
    for artifact in &mut artifacts {
        artifact
            .outputs
            .sort_by(|left, right| left.path.cmp(&right.path));
        let crate_name = artifact.crate_name.clone();
        let out_dir = artifact.build_script_out_dir.clone();
        artifact.native = smol::unblock(move || {
            stow_types::native_capture::capture_native_artifacts(&crate_name, out_dir.as_deref())
        })
        .await?;
    }
    artifacts.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.c_metadata.cmp(&right.c_metadata))
            .then(left.kind.as_str().cmp(right.kind.as_str()))
    });

    let consumed = consumed_captures
        .into_iter()
        .map(|capture| capture.artifact)
        .collect();

    Ok(ScanReport {
        restorable_captures,
        artifacts,
        consumed,
    })
}

/// The registry library packages of the task's resolved closure —
/// `(canonical crate name, version, resolved features)` — the candidates
/// the consumption prefetch may substitute a verified published artifact
/// for. Kept `pub(crate)` so `consume` resolves candidates against exactly
/// the same `cargo metadata` invocation the scan runs.
pub async fn consumable_packages(
    workspace: &BuildWorkspace,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<Vec<ConsumablePackage>> {
    let metadata = cargo_metadata(workspace, task).await?;
    Ok(package_index(&metadata, task)
        .into_values()
        .flat_map(BTreeMap::into_values)
        .filter(|package| package.registry)
        .map(|package| ConsumablePackage {
            crate_name: package.name.clone(),
            version: package.version.clone(),
            features: package.features,
        })
        .collect())
}

/// One registry library package of the task's resolved closure — a
/// consumption-prefetch candidate.
pub struct ConsumablePackage {
    /// Canonical package name.
    pub(crate) crate_name: String,
    /// Resolved package version.
    pub(crate) version: cargo_metadata::semver::Version,
    /// Features the task's resolution activates on it.
    pub(crate) features: BTreeSet<String>,
}

/// Re-hash every output of every selected capture — the snapshot when the
/// wrapper froze one, else the file itself — and require equality with the
/// `sha256` recorded at rustc exit. A mismatch means sandboxed code modified
/// the bytes after the record crossed to the host, so the scan aborts naming
/// the file and both digests.
async fn verify_output_digests<'a>(
    records: impl Iterator<Item = &'a CapturedRustcArtifact>,
) -> stow_types::error::Result<()> {
    for artifact in records {
        for output in &artifact.outputs {
            let source_path = output.snapshot_path.as_ref().unwrap_or(&output.path);
            let bytes = async_fs::read(source_path).await.map_err(|error| {
                stow_types::stow_error!(
                    "read captured output {} for digest verification: {error}",
                    source_path.display()
                )
            })?;
            let actual = hex::encode(sha2::Sha256::digest(&bytes));
            if actual != output.sha256 {
                return Err(stow_types::stow_error!(
                    "captured output {} for {} changed after rustc exited: recorded sha256 {}, actual sha256 {}",
                    source_path.display(),
                    artifact.crate_name,
                    output.sha256,
                    actual
                ));
            }
        }
    }
    Ok(())
}

/// Attribute every restorable record to a package and a kind, keyed for
/// selection. A restorable record the scan cannot plan is a missing output:
/// every unattributable path is fatal because anything less lets a lost or
/// tampered record shrink the plan.
///
/// Returns the selected artifacts plus the count of restorable records that
/// merged into an earlier one as proven-identical captures of the same unit
/// in another phase.
fn select_captured_artifacts(
    package_index: &PackageIndex,
    captured_artifacts: &[CapturedRustcArtifact],
) -> stow_types::error::Result<SelectedCaptures> {
    let mut selected =
        BTreeMap::<(String, String, String, String), SelectedCapturedArtifact>::new();
    let mut absorbed_duplicates = 0usize;
    for captured in captured_artifacts {
        // Observed units (build-script compiles, binaries, probes) exist so a
        // forged record collides with them; they carry no artifacts to plan.
        if !captured.restorable {
            continue;
        }
        let package = package_for_capture(package_index, captured).ok_or_else(|| {
            stow_types::stow_error!(
                "dep_scan could not attribute restorable capture {} {} (c_metadata {}) to any package in cargo metadata",
                captured.crate_name,
                captured.crate_version.as_deref().unwrap_or("<unknown>"),
                captured.c_metadata
            )
        })?;
        // A restorable record always produced an rlib or a dynamic library,
        // so an unrecognized crate-type list means the record is forged or
        // the parser lost the invocation's `--crate-type` — never a skip.
        let artifact_kind = artifact_kind_for_capture(captured).ok_or_else(|| {
            stow_types::stow_error!(
                "dep_scan could not classify restorable capture {} (c_metadata {}) with crate_types {:?}",
                captured.crate_name,
                captured.c_metadata,
                captured.crate_types
            )
        })?;
        let key = (
            package.name.clone(),
            captured.c_metadata.clone(),
            artifact_kind.as_str().to_owned(),
            serde_json::to_string(&captured.emit)
                .expect("captured emit serialization must succeed"),
        );
        let candidate = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind,
            captured: captured.clone(),
            dependency_aliases: Vec::new(),
        };
        if select_captured_artifact(&mut selected, key, candidate)? {
            absorbed_duplicates += 1;
        }
    }
    Ok(SelectedCaptures {
        artifacts: selected.into_values().collect(),
        absorbed_duplicates,
    })
}

/// The output of [`select_captured_artifacts`]: the artifacts the upload
/// plan may carry plus how many restorable records merged into an earlier
/// one as proven-identical captures of the same unit in another phase.
#[derive(Debug)]
struct SelectedCaptures {
    artifacts: Vec<SelectedCapturedArtifact>,
    absorbed_duplicates: usize,
}

/// Insert `candidate` under `key`, or absorb it into the record already
/// there when the two are provably captures of the same rustc unit.
/// Returns `true` when the candidate was merged rather than inserted.
fn select_captured_artifact(
    selected: &mut BTreeMap<(String, String, String, String), SelectedCapturedArtifact>,
    key: (String, String, String, String),
    candidate: SelectedCapturedArtifact,
) -> stow_types::error::Result<bool> {
    let Some(existing) = selected.get_mut(&key) else {
        selected.insert(key, candidate);
        return Ok(false);
    };
    // Two restorable records under one selection key are a duplicate: the key
    // already carries every identity dimension (crate, stable metadata, kind,
    // emit), so a second record claiming it is either the same rustc unit
    // seen twice — a unit that links in every cargo phase, like a build
    // dependency or a proc macro, is captured once per phase into that
    // phase's own `CARGO_TARGET_DIR`, and a split unit graph captures the
    // host and requested-target halves into sibling `deps` dirs — or a
    // forged replay. `same_captured_unit` is the proof of "same unit";
    // anything else is a collision and aborts the scan.
    if !same_captured_unit(&existing.captured, &candidate.captured) {
        return Err(stow_types::stow_error!(
            "dep_scan captured two different restorable artifacts for {} {} (c_metadata {}) emit {:?} — a duplicate identity means a forged or colliding record",
            candidate.captured.crate_name,
            candidate
                .captured
                .crate_version
                .as_deref()
                .unwrap_or("<unknown>"),
            candidate.captured.c_metadata,
            candidate.captured.emit
        ));
    }
    // The first capture survives: both records carry the same stable
    // identity a client resolves the crate by, and the same outputs modulo
    // directory, so either half is the artifact a lookup asks for. The
    // dropped half's output paths stay resolvable as aliases, so a
    // dependent whose `--extern` names the other phase's `deps` dir still
    // finds its owner.
    let dropped_output_paths = candidate
        .captured
        .outputs
        .iter()
        .map(|output| output.path.clone());
    existing.extend_dependency_aliases(
        candidate
            .dependency_aliases
            .iter()
            .cloned()
            .chain(dropped_output_paths),
    );
    Ok(true)
}

/// Whether two records are captures of the same rustc unit — the same
/// compilation driven into a different output directory — rather than two
/// different units colliding on one selection key.
///
/// A legitimate repeat is told from a forgery by what the record itself
/// carries: `out_dir`, `target_dir`, `build_script_out_dir`, the output
/// and dependency paths, and the snapshots are entitled to differ — they
/// are where the unit happened to be written this time. Everything that
/// identifies the unit — the full compile key, target, profile, crate
/// types, version, extra filename and dependency identities — must be
/// equal, and the outputs must be the same files modulo the directory
/// they were written to. Anything else is a collision.
///
/// No byte comparison is needed on top of that: the compile key already
/// blake3s the whole invocation, so records agreeing on it and the rest
/// of the identity are the same unit by construction, and
/// `verify_output_digests` re-hashes the surviving record's outputs
/// before anything is planned — integrity of what ships is covered
/// there, while the dropped half is discarded.
fn same_captured_unit(left: &CapturedRustcArtifact, right: &CapturedRustcArtifact) -> bool {
    left.crate_version == right.crate_version
        && left.crate_types == right.crate_types
        && left.target == right.target
        && left.compile_key == right.compile_key
        && left.extra_filename == right.extra_filename
        && left.profile == right.profile
        && same_dependency_identities(&left.dependencies, &right.dependencies)
        && captured_outputs_match(left, right)
}

/// Dependency identities equal modulo the directory each capture's
/// externs resolved through: same crate, compile key and stable metadata
/// per edge.
fn same_dependency_identities(
    left: &[CapturedDependencyIdentity],
    right: &[CapturedDependencyIdentity],
) -> bool {
    fn identities(dependencies: &[CapturedDependencyIdentity]) -> BTreeSet<(&str, &str, &str)> {
        dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.crate_name.as_str(),
                    dependency.compile_key.as_str(),
                    dependency.stable_c_metadata.as_str(),
                )
            })
            .collect()
    }
    identities(left) == identities(right)
}

/// Whether two records describe the same outputs written to different
/// directories: the same kind and file name per output. rlib and rmeta
/// carry nothing path-dependent, so their recorded digests must match
/// outright; a dynamic library is exempt because the linker writes the
/// path it was produced at into the file (the Mach-O install name, and
/// on MSVC the sibling .pdb path in the PE debug directory), so the same
/// module legitimately hashes differently per output directory.
/// Snapshot paths are excluded — they are per-capture temp names.
fn captured_outputs_match(left: &CapturedRustcArtifact, right: &CapturedRustcArtifact) -> bool {
    let mut left_outputs = left.outputs.iter().collect::<Vec<_>>();
    let mut right_outputs = right.outputs.iter().collect::<Vec<_>>();
    let by_kind_and_name = |a: &&CapturedRustcOutput, b: &&CapturedRustcOutput| {
        a.kind
            .cmp(&b.kind)
            .then(a.path.file_name().cmp(&b.path.file_name()))
    };
    left_outputs.sort_by(by_kind_and_name);
    right_outputs.sort_by(by_kind_and_name);
    if left_outputs.len() != right_outputs.len() {
        return false;
    }
    left_outputs
        .iter()
        .zip(&right_outputs)
        .all(|(output, peer)| {
            output.kind == peer.kind
                && output.path.file_name() == peer.path.file_name()
                && (output.kind == CapturedRustcOutputKind::DynamicLibrary
                    || output.sha256 == peer.sha256)
        })
}

/// Attribute every consumed record to a registry package of the resolved
/// closure and deduplicate by compile key — a served artifact hit in
/// several phases leaves one record per phase, all describing the same
/// verified bundle.
///
/// Every rule here is structural: an artifact staged under its compile key
/// by the verified prefetch still must attribute inside the task's
/// resolved closure, and two records naming different identities under one
/// compile key is a forged or colliding record, never a merge.
fn collect_consumed_captures(
    package_index: &PackageIndex,
    captured_artifacts: &[CapturedRustcArtifact],
    rustc_version: &str,
) -> stow_types::error::Result<Vec<ConsumedCapture>> {
    let mut captures = Vec::<ConsumedCapture>::new();
    let mut by_compile_key = BTreeMap::<String, usize>::new();
    for captured in captured_artifacts {
        if !captured.consumed {
            continue;
        }
        let package = package_for_capture(package_index, captured).ok_or_else(|| {
            stow_types::stow_error!(
                "dep_scan could not attribute consumed capture {} {} (compile_key {}) to any package in cargo metadata",
                captured.crate_name,
                captured.crate_version.as_deref().unwrap_or("<unknown>"),
                captured.compile_key
            )
        })?;
        // The prefetch only stages registry artifacts: a consumed record
        // naming a path member means the record, not the set, is wrong.
        if !package.registry {
            return Err(stow_types::stow_error!(
                "dep_scan consumed capture {} attributes to a non-registry package — only published registry artifacts may be served",
                captured.crate_name
            ));
        }
        let index = if let Some(index) = by_compile_key.get(&captured.compile_key) {
            let existing = &captures[*index].artifact;
            let package_name = &package.name;
            if existing.c_metadata != captured.c_metadata
                || existing.crate_name != *package_name
                || existing.crate_version != package.version.to_string()
            {
                return Err(stow_types::stow_error!(
                    "dep_scan consumed capture {} {} (compile_key {}, c_metadata {}) conflicts with an earlier consumed record — a duplicate identity means a forged or colliding record",
                    captured.crate_name,
                    captured.crate_version.as_deref().unwrap_or("<unknown>"),
                    captured.compile_key,
                    captured.c_metadata
                ));
            }
            *index
        } else {
            let index = captures.len();
            captures.push(ConsumedCapture {
                artifact: ConsumedArtifact {
                    crate_name: package.name.clone(),
                    crate_version: package.version.to_string(),
                    compile_key: captured.compile_key.clone(),
                    c_metadata: captured.c_metadata.clone(),
                    // Never the task's target as a stand-in: a host unit
                    // — a proc macro, a build dependency — is served from
                    // the host slice on a cross build, and labelling its
                    // claim with the task triple would send the publisher
                    // looking for a vouching row in a slice that cannot
                    // contain it. The wrapper resolves the real triple and
                    // records it; a record without one never came from the
                    // serve path.
                    target: captured.target.clone().ok_or_else(|| {
                        stow_types::stow_error!(
                            "consumed capture {} (compile_key {}) carries no target",
                            captured.crate_name,
                            captured.compile_key
                        )
                    })?,
                    rustc_version: rustc_version.to_owned(),
                    emit: captured.emit.clone(),
                },
                records: Vec::new(),
            });
            by_compile_key.insert(captured.compile_key.clone(), index);
            index
        };
        captures[index].records.push(captured.clone());
    }
    Ok(captures)
}

async fn build_scanned_artifact(
    task: &BuildTaskPayload,
    rustc_version: &str,
    cx: &mut ResolveCx<'_>,
    artifact_index: usize,
) -> stow_types::error::Result<ScannedArtifact> {
    let artifact = cx.selected.get(artifact_index).ok_or_else(|| {
        stow_types::stow_error!("selected artifact index {artifact_index} is out of bounds")
    })?;
    let resolved_artifact = resolve_artifact(cx, artifact_index)?;
    let dependencies = resolved_artifact.dependencies.clone();
    let mut outputs = Vec::with_capacity(artifact.captured.outputs.len());
    let mut artifact_size = 0u64;
    for output in &artifact.captured.outputs {
        let source_path = output
            .snapshot_path
            .clone()
            .unwrap_or_else(|| output.path.clone());
        let metadata = async_fs::metadata(&source_path).await?;
        artifact_size = artifact_size.saturating_add(metadata.len());
        outputs.push(ScannedArtifactOutput {
            kind: parsed_file_kind(output.kind),
            path: output.path.clone(),
            source_path,
        });
    }
    Ok(ScannedArtifact {
        crate_name: artifact.package.name.clone(),
        crate_version: artifact.package.version.to_string(),
        target: artifact
            .captured
            .target
            .clone()
            .unwrap_or_else(|| task.target.as_str().to_owned()),
        rustc_version: rustc_version.to_owned(),
        captured_compile_key: resolved_artifact.compile_key.clone(),
        c_metadata: resolved_artifact.stable_c_metadata.clone(),
        extra_filename: format!("-{}", resolved_artifact.stable_c_metadata),
        profile: artifact.captured.profile.clone(),
        emit: artifact.captured.emit.clone(),
        features_json: resolved_artifact.features_json.clone(),
        dependencies,
        artifact_size,
        compile_millis: artifact.captured.compile_millis,
        kind: artifact.artifact_kind.clone(),
        crate_types: artifact.package.crate_types.clone(),
        outputs,
        build_script_out_dir: artifact.captured.build_script_out_dir.clone(),
        native: None,
    })
}

/// The state resolution threads through [`resolve_artifact`] and
/// [`resolve_dependencies`]: the record sets they walk, the output-owner
/// index, and the memo maps accumulating across it.
struct ResolveCx<'a> {
    /// Selected compiled artifacts, by index.
    selected: &'a [SelectedCapturedArtifact],
    /// Consumed-capture groups, by index.
    consumed: &'a [ConsumedCapture],
    /// Output path → the record that produced it.
    output_owners: &'a BTreeMap<PathBuf, OutputOwner>,
    /// Resolved artifacts by selected index — the walk's memo.
    resolved: &'a mut BTreeMap<usize, ResolvedArtifact>,
    /// Selected indices on the current path — cycle detection.
    visiting: &'a mut BTreeSet<usize>,
}

fn resolve_artifact(
    cx: &mut ResolveCx<'_>,
    artifact_index: usize,
) -> stow_types::error::Result<ResolvedArtifact> {
    if let Some(existing) = cx.resolved.get(&artifact_index) {
        return Ok(existing.clone());
    }
    if !cx.visiting.insert(artifact_index) {
        return Err(stow_types::stow_error!(
            "dep_scan detected a cycle while resolving authoritative artifact index {artifact_index}"
        ));
    }

    let artifact = cx.selected.get(artifact_index).ok_or_else(|| {
        stow_types::stow_error!("selected artifact index {artifact_index} is out of bounds")
    })?;
    let dependencies = resolve_dependencies(cx, artifact_index)?;
    let features_json = serde_json::to_string(
        &artifact
            .package
            .features
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .expect("feature serialization must succeed");
    cx.visiting.remove(&artifact_index);

    let resolved_artifact = ResolvedArtifact {
        compile_key: artifact.captured.compile_key.clone(),
        stable_c_metadata: artifact.captured.c_metadata.clone(),
        features_json,
        dependencies,
    };
    cx.resolved
        .insert(artifact_index, resolved_artifact.clone());
    Ok(resolved_artifact)
}

fn resolve_dependencies(
    cx: &mut ResolveCx<'_>,
    artifact_index: usize,
) -> stow_types::error::Result<Vec<ScannedArtifactDependency>> {
    let artifact = cx.selected.get(artifact_index).ok_or_else(|| {
        stow_types::stow_error!("selected artifact index {artifact_index} is out of bounds")
    })?;
    let mut dependencies = Vec::with_capacity(artifact.captured.dependencies.len());
    for dependency in &artifact.captured.dependencies {
        match cx.output_owners.get(&dependency.path) {
            Some(OutputOwner::Compiled(dependency_index)) => {
                let resolved_dependency = resolve_artifact(cx, *dependency_index)?;
                // The claimed identity came from an `output-identities/*.json`
                // sidecar any sandboxed process could write; the resolved one
                // came from the dependency's own IPC record. A forged sidecar
                // must collide here instead of silently re-keying the
                // dependent under a false graph.
                if dependency.compile_key != resolved_dependency.compile_key
                    || dependency.stable_c_metadata != resolved_dependency.stable_c_metadata
                {
                    return Err(stow_types::stow_error!(
                        "dep_scan dependency identity {} claimed by {} at {} (compile_key {}, c_metadata {}) does not match the resolved artifact's identity (compile_key {}, c_metadata {})",
                        dependency.crate_name,
                        artifact.captured.crate_name,
                        dependency.path.display(),
                        dependency.compile_key,
                        dependency.stable_c_metadata,
                        resolved_dependency.compile_key,
                        resolved_dependency.stable_c_metadata
                    ));
                }
                dependencies.push(ScannedArtifactDependency {
                    crate_name: dependency.crate_name.clone(),
                    path: dependency.path.clone(),
                    compile_key: resolved_dependency.compile_key,
                    stable_c_metadata: resolved_dependency.stable_c_metadata,
                });
            }
            Some(OutputOwner::Consumed(consumed_index)) => {
                let served = cx.consumed.get(*consumed_index).ok_or_else(|| {
                    stow_types::stow_error!(
                        "consumed artifact index {consumed_index} is out of bounds"
                    )
                })?;
                // The served artifact has no compile step of its own — the
                // identity the signed index vouched for is what its record
                // carries, and a forged sidecar naming its output collides
                // against that exactly like a compiled dependency's.
                if dependency.compile_key != served.artifact.compile_key
                    || dependency.stable_c_metadata != served.artifact.c_metadata
                {
                    return Err(stow_types::stow_error!(
                        "dep_scan dependency identity {} claimed by {} at {} (compile_key {}, c_metadata {}) does not match the consumed artifact's identity (compile_key {}, c_metadata {})",
                        dependency.crate_name,
                        artifact.captured.crate_name,
                        dependency.path.display(),
                        dependency.compile_key,
                        dependency.stable_c_metadata,
                        served.artifact.compile_key,
                        served.artifact.c_metadata
                    ));
                }
                dependencies.push(ScannedArtifactDependency {
                    crate_name: dependency.crate_name.clone(),
                    path: dependency.path.clone(),
                    compile_key: served.artifact.compile_key.clone(),
                    stable_c_metadata: served.artifact.c_metadata.clone(),
                });
            }
            None => {
                return Err(stow_types::stow_error!(
                    "dep_scan could not resolve authoritative dependency owner for {} at {} while scanning {}",
                    dependency.crate_name,
                    dependency.path.display(),
                    artifact.captured.crate_name
                ));
            }
        }
    }
    dependencies.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.path.cmp(&right.path))
    });
    dependencies
        .dedup_by(|left, right| left.crate_name == right.crate_name && left.path == right.path);
    Ok(dependencies)
}

fn output_owner_index(
    selected: &[SelectedCapturedArtifact],
    consumed: &[ConsumedCapture],
) -> stow_types::error::Result<BTreeMap<PathBuf, OutputOwner>> {
    let mut owners = BTreeMap::new();
    for (index, artifact) in selected.iter().enumerate() {
        for output in &artifact.captured.outputs {
            insert_output_owner(
                &mut owners,
                selected,
                consumed,
                &output.path,
                OutputOwner::Compiled(index),
            )?;
        }
        for alias in &artifact.dependency_aliases {
            insert_output_owner(
                &mut owners,
                selected,
                consumed,
                alias,
                OutputOwner::Compiled(index),
            )?;
        }
    }
    for (index, capture) in consumed.iter().enumerate() {
        for record in &capture.records {
            for output in &record.outputs {
                insert_output_owner(
                    &mut owners,
                    selected,
                    consumed,
                    &output.path,
                    OutputOwner::Consumed(index),
                )?;
            }
        }
    }
    Ok(owners)
}

fn insert_output_owner(
    owners: &mut BTreeMap<PathBuf, OutputOwner>,
    selected: &[SelectedCapturedArtifact],
    consumed: &[ConsumedCapture],
    path: &Path,
    owner: OutputOwner,
) -> stow_types::error::Result<()> {
    if let Some(existing) = owners.insert(path.to_path_buf(), owner)
        && existing != owner
    {
        return Err(stow_types::stow_error!(
            "dep_scan found duplicate authoritative output path {} claimed by {} and {}",
            path.display(),
            owner_name(selected, consumed, existing),
            owner_name(selected, consumed, owner)
        ));
    }
    Ok(())
}

/// Name an owner for a collision error — the crate the record claims.
fn owner_name(
    selected: &[SelectedCapturedArtifact],
    consumed: &[ConsumedCapture],
    owner: OutputOwner,
) -> String {
    match owner {
        OutputOwner::Compiled(index) => selected.get(index).map_or_else(
            || format!("<index {index} out of bounds>"),
            |artifact| artifact.captured.crate_name.clone(),
        ),
        OutputOwner::Consumed(index) => consumed.get(index).map_or_else(
            || format!("<index {index} out of bounds>"),
            |capture| capture.artifact.crate_name.clone(),
        ),
    }
}

async fn cargo_metadata(
    workspace: &BuildWorkspace,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<Metadata> {
    let mut command = Command::new("cargo");
    command
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        // The build already ran and wrote a lockfile; this must report that
        // exact resolution, not a fresh one. Without --locked cargo is free to
        // re-resolve, and then the versions here disagree with the versions
        // rustc actually compiled: on eza, captures of cfg_if 1.0.0 and
        // ansi_width 0.1.0 found no package at those versions and 54 captures
        // were skipped, which cascaded into 48 dropped artifacts and left the
        // project with no usable cache at all.
        .arg("--locked")
        .arg("--manifest-path")
        .arg(workspace.manifest_path());
    // Task feature flags apply to the task crate's own manifest; a consumer
    // workspace already encoded them in its dependency declaration, and the
    // generated package declares no features for them to resolve.
    if workspace.kind() != WorkspaceKind::Consumer {
        CargoFeatureArgs::from_task(task).apply(&mut command);
    }
    let output = command.output().await?;

    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    serde_json::from_slice(&output.stdout).map_err(Into::into)
}

/// Indexed by library target name, then by version.
///
/// A dependency graph can legitimately contain two versions of one crate —
/// bitflags 1.3.2 alongside 2.5.0 — and they share a library target name.
/// Collapsing them into one entry per name meant every captured `bitflags`
/// unit was attributed to whichever version happened to land last, so one
/// version's compiled bytes were registered under the other's identity. The
/// client then injected bitflags 2.5.0 into a bitflags 1.3.2 unit and the
/// build failed with 126 conflicting-impl errors inside `nix`.
type PackageIndex = BTreeMap<String, BTreeMap<String, IndexedPackage>>;

fn package_index(metadata: &Metadata, task: &BuildTaskPayload) -> PackageIndex {
    let resolve_features = resolve_feature_map(metadata);
    let mut index = PackageIndex::new();
    for package in metadata
        .packages
        .iter()
        .filter_map(|package| indexed_package(package, resolve_features.get(&package.id), task))
    {
        // rustc's `--crate-name` is always underscored, but cargo reports a
        // library target's name verbatim — `cfg-if`, `ansi-width`. Indexing by
        // the raw name meant no capture of those crates ever matched, and on
        // eza that silently lost half the graph: 54 captures skipped, 48 more
        // artifacts dropped as their dependents lost an owner, and the project
        // ended up with no usable cache at all.
        index
            .entry(stow_types::public_cache::canonical_crate_name(
                &package.lib_target_name,
            ))
            .or_default()
            .insert(package.version.to_string(), package);
    }
    index
}

/// The package a capture belongs to, by library target name and the version
/// the capture wrapper read from the invocation's source path.
///
/// Falls back to the sole candidate when the capture predates version
/// recording, and refuses to guess when several versions are in play.
fn package_for_capture<'a>(
    index: &'a PackageIndex,
    captured: &CapturedRustcArtifact,
) -> Option<&'a IndexedPackage> {
    let by_version = index.get(captured.crate_name.as_str())?;
    match captured.crate_version.as_deref() {
        Some(version) => by_version.get(version),
        None if by_version.len() == 1 => by_version.values().next(),
        None => None,
    }
}

fn resolve_feature_map(metadata: &Metadata) -> BTreeMap<PackageId, BTreeSet<String>> {
    metadata
        .resolve
        .as_ref()
        .map(|resolve| {
            resolve
                .nodes
                .iter()
                .map(|node| {
                    (
                        node.id.clone(),
                        node.features
                            .iter()
                            .map(ToString::to_string)
                            .collect::<BTreeSet<_>>(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default()
}

/// The task feature set `indexed_package`/`package_has_library_target`
/// evaluate `required-features` against.
pub fn task_feature_set(task: &BuildTaskPayload) -> BTreeSet<String> {
    task.features_json.features().iter().cloned().collect()
}

/// The package's library target under the task's feature set, if it has one
/// the trusted pipeline would compile.
pub fn package_has_library_target(package: &Package, task_features: &BTreeSet<String>) -> bool {
    package
        .targets
        .iter()
        .find_map(|target| preferred_target(package, target, task_features))
        .or_else(|| package.targets.iter().find_map(candidate_target))
        .is_some()
}

fn indexed_package(
    package: &Package,
    features: Option<&BTreeSet<String>>,
    task: &BuildTaskPayload,
) -> Option<IndexedPackage> {
    let task_features = task_feature_set(task);
    let target = package
        .targets
        .iter()
        .find_map(|target| preferred_target(package, target, &task_features))
        .or_else(|| {
            package
                .targets
                .iter()
                .find_map(|target| candidate_target(target))
        });

    let (target, crate_types, _artifact_kind) = target?;

    let resolved_features = features.cloned().unwrap_or_default();
    let declared_features = package.features.keys().cloned().collect::<BTreeSet<_>>();
    let features = package_feature_set(
        package.name.as_str(),
        &resolved_features,
        &declared_features,
        &task_features,
        task,
    );

    Some(IndexedPackage {
        name: package.name.clone().into_inner(),
        version: package.version.clone(),
        lib_target_name: target.name.clone(),
        crate_types,
        features,
        registry: package
            .source
            .as_ref()
            .is_some_and(|source| source.to_string().starts_with("registry+")),
    })
}

fn package_feature_set(
    package_name: &str,
    resolved_features: &BTreeSet<String>,
    declared_features: &BTreeSet<String>,
    task_features: &BTreeSet<String>,
    task: &BuildTaskPayload,
) -> BTreeSet<String> {
    if !resolved_features.is_empty() {
        return resolved_features.clone();
    }
    if package_name == task.crate_name {
        // The task's requested features only count where the package
        // actually declares them — `default` included. A feature-less crate
        // registers `[]`, matching the resolved feature set the consumer's
        // semantic lookup computes, instead of a `["default"]` row that can
        // never be hit.
        return task_features
            .intersection(declared_features)
            .cloned()
            .collect();
    }
    BTreeSet::new()
}

fn preferred_target<'a>(
    package: &Package,
    target: &'a Target,
    task_features: &BTreeSet<String>,
) -> Option<(&'a Target, Vec<RustCrateType>, ArtifactKind)> {
    if package.name != target.name {
        return None;
    }
    if !target_required_features_match(target, task_features) {
        return None;
    }
    candidate_target(target)
}

fn candidate_target(target: &Target) -> Option<(&Target, Vec<RustCrateType>, ArtifactKind)> {
    let crate_types = target
        .kind
        .iter()
        .filter_map(rust_crate_type)
        .collect::<BTreeSet<_>>();
    let artifact_kind = artifact_kind(&crate_types)?;
    Some((
        target,
        crate_types.into_iter().collect::<Vec<_>>(),
        artifact_kind,
    ))
}

fn target_required_features_match(target: &Target, task_features: &BTreeSet<String>) -> bool {
    target.required_features.is_empty()
        || target
            .required_features
            .iter()
            .all(|feature| task_features.contains(feature))
}

const fn rust_crate_type(kind: &TargetKind) -> Option<RustCrateType> {
    match kind {
        TargetKind::Lib => Some(RustCrateType::Lib),
        TargetKind::RLib => Some(RustCrateType::Rlib),
        TargetKind::DyLib => Some(RustCrateType::Dylib),
        TargetKind::CDyLib => Some(RustCrateType::Cdylib),
        TargetKind::StaticLib => Some(RustCrateType::Staticlib),
        TargetKind::ProcMacro => Some(RustCrateType::ProcMacro),
        _ => None,
    }
}

fn artifact_kind(crate_types: &BTreeSet<RustCrateType>) -> Option<ArtifactKind> {
    if crate_types.contains(&RustCrateType::ProcMacro) {
        return Some(ArtifactKind::ProcMacro);
    }
    if crate_types.contains(&RustCrateType::Dylib) {
        return Some(ArtifactKind::Dylib);
    }
    if crate_types.contains(&RustCrateType::Lib) || crate_types.contains(&RustCrateType::Rlib) {
        return Some(ArtifactKind::Rlib);
    }
    None
}

fn artifact_kind_for_capture(captured: &CapturedRustcArtifact) -> Option<ArtifactKind> {
    if captured
        .crate_types
        .iter()
        .any(|crate_type| crate_type == "proc-macro")
    {
        return Some(ArtifactKind::ProcMacro);
    }
    if captured
        .crate_types
        .iter()
        .any(|crate_type| crate_type == "dylib")
    {
        return Some(ArtifactKind::Dylib);
    }
    if captured
        .crate_types
        .iter()
        .any(|crate_type| crate_type == "lib" || crate_type == "rlib")
    {
        return Some(ArtifactKind::Rlib);
    }
    None
}

const fn parsed_file_kind(kind: CapturedRustcOutputKind) -> ParsedFileKind {
    match kind {
        CapturedRustcOutputKind::Rlib => ParsedFileKind::Rlib,
        CapturedRustcOutputKind::Rmeta => ParsedFileKind::Rmeta,
        CapturedRustcOutputKind::DynamicLibrary => ParsedFileKind::DynamicLibrary,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScannedArtifact {
    pub crate_name: String,
    pub crate_version: String,
    pub target: String,
    pub rustc_version: String,
    pub captured_compile_key: String,
    pub c_metadata: String,
    pub extra_filename: String,
    pub profile: Profile,
    pub emit: Vec<String>,
    pub features_json: String,
    pub dependencies: Vec<ScannedArtifactDependency>,
    pub artifact_size: u64,
    /// Wall-clock milliseconds the captured rustc invocation took.
    pub compile_millis: u64,
    pub kind: ArtifactKind,
    pub crate_types: Vec<RustCrateType>,
    pub outputs: Vec<ScannedArtifactOutput>,
    /// Exact build-script `OUT_DIR` recorded at capture time, when the crate
    /// has a build script.
    pub build_script_out_dir: Option<PathBuf>,
    pub native: Option<NativeArtifacts>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScannedArtifactOutput {
    pub(crate) kind: ParsedFileKind,
    pub(crate) path: PathBuf,
    pub(crate) source_path: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScannedArtifactDependency {
    pub(crate) crate_name: String,
    pub(crate) path: PathBuf,
    pub(crate) compile_key: String,
    pub(crate) stable_c_metadata: String,
}

#[derive(Debug, Clone)]
struct IndexedPackage {
    name: String,
    version: cargo_metadata::semver::Version,
    lib_target_name: String,
    crate_types: Vec<RustCrateType>,
    features: BTreeSet<String>,
    /// Whether the package comes from a registry. Only a registry package
    /// has an identity the cache publishes under, so only a registry
    /// package can be served a published artifact instead of compiled.
    registry: bool,
}

#[derive(Debug)]
struct SelectedCapturedArtifact {
    package: IndexedPackage,
    artifact_kind: ArtifactKind,
    captured: CapturedRustcArtifact,
    dependency_aliases: Vec<PathBuf>,
}

impl SelectedCapturedArtifact {
    fn extend_dependency_aliases(&mut self, aliases: impl IntoIterator<Item = PathBuf>) {
        let existing_outputs = self
            .captured
            .outputs
            .iter()
            .map(|output| output.path.clone())
            .collect::<BTreeSet<_>>();
        let mut seen_aliases = self
            .dependency_aliases
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for alias in aliases {
            if existing_outputs.contains(&alias) {
                continue;
            }
            if seen_aliases.insert(alias.clone()) {
                self.dependency_aliases.push(alias);
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedArtifact {
    compile_key: String,
    stable_c_metadata: String,
    features_json: String,
    dependencies: Vec<ScannedArtifactDependency>,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum ParsedFileKind {
    Rlib,
    Rmeta,
    DynamicLibrary,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use sha2::Digest as _;

    use stow_types::api::BuildTaskPayload;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::platform::{PanicStrategy, Profile};

    use super::{
        IndexedPackage, ResolvedArtifact, SelectedCapturedArtifact, output_owner_index,
        package_feature_set, resolve_artifact, select_captured_artifact, select_captured_artifacts,
    };
    use stow_types::capture::{
        CapturedDependencyIdentity, CapturedRustcArtifact, CapturedRustcOutput,
        CapturedRustcOutputKind,
    };

    #[test]
    fn same_unit_rlib_captures_from_different_phase_dirs_merge() {
        // The legitimate same-key case: one build-dependency unit captured
        // once per cargo phase, into each phase's own target dir. The
        // output set is identical modulo directory — rlib and rmeta carry
        // nothing path-dependent, so their digests match — and the second
        // record merges its dependency aliases plus the paths of the
        // outputs it drops instead of colliding.
        let key = (
            "aho_corasick".to_owned(),
            "ef4a079a8dc04c32".to_owned(),
            ArtifactKind::Rlib.as_str().to_owned(),
            "[\"dep-info\",\"link\"]".to_owned(),
        );
        let mut selected = BTreeMap::new();
        let package = IndexedPackage {
            name: "aho_corasick".to_owned(),
            version: semver::Version::parse("1.1.4").expect("version"),
            lib_target_name: "aho_corasick".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
            features: BTreeSet::new(),
            registry: true,
        };
        let first = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind: ArtifactKind::Rlib,
            captured: captured(
                "aho_corasick",
                "ef4a079a8dc04c32",
                "/tmp/workspace/target-check/debug/deps",
            ),
            dependency_aliases: Vec::new(),
        };
        let mut duplicate = first.captured.clone();
        duplicate.out_dir = PathBuf::from("/tmp/workspace/target-build/debug/deps");
        duplicate.target_dir = PathBuf::from("/tmp/workspace/target-build");
        duplicate.outputs[0].path = PathBuf::from(
            "/tmp/workspace/target-build/debug/deps/libaho_corasick-ef4a079a8dc04c32.rmeta",
        );
        let second = SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured: duplicate,
            dependency_aliases: vec![PathBuf::from(
                "/tmp/workspace/target-check/debug/deps/libitoa-1234.rmeta",
            )],
        };

        select_captured_artifact(&mut selected, key.clone(), first).expect("select first");
        select_captured_artifact(&mut selected, key.clone(), second)
            .expect("the same unit in another phase dir merges");

        let stored = selected.get(&key).expect("selected capture");
        assert!(
            stored.dependency_aliases.contains(&PathBuf::from(
                "/tmp/workspace/target-check/debug/deps/libitoa-1234.rmeta"
            )),
            "declared aliases merge"
        );
        assert!(
            stored.dependency_aliases.contains(&PathBuf::from(
                "/tmp/workspace/target-build/debug/deps/libaho_corasick-ef4a079a8dc04c32.rmeta"
            )),
            "the dropped half's output paths stay resolvable"
        );
    }

    /// Two captures of one proc-macro unit, one per phase `CARGO_TARGET_DIR`:
    /// the only output is a dylib, whose bytes legitimately differ because
    /// the linker writes the output path (and on MSVC the .pdb path) into
    /// it — so the digests differ and the records still merge.
    #[test]
    fn same_unit_dylib_captures_from_different_phase_dirs_merge() {
        let key = (
            "equator_macro".to_owned(),
            "0c5856ca18b3a9e0".to_owned(),
            ArtifactKind::ProcMacro.as_str().to_owned(),
            "[\"dep-info\",\"link\"]".to_owned(),
        );
        let mut selected = BTreeMap::new();
        let package = IndexedPackage {
            name: "equator_macro".to_owned(),
            version: semver::Version::parse("0.4.2").expect("version"),
            lib_target_name: "equator_macro".to_owned(),
            crate_types: vec![RustCrateType::ProcMacro],
            features: BTreeSet::new(),
            registry: true,
        };
        let first = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind: ArtifactKind::ProcMacro,
            captured: dylib_capture(
                "/tmp/workspace/target-check/debug/deps/libequator_macro-0c5856ca18b3a9e0.dylib",
                "/tmp/workspace/target-check/debug/deps",
                &"cd".repeat(32),
            ),
            dependency_aliases: Vec::new(),
        };
        let second = SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::ProcMacro,
            captured: dylib_capture(
                "/tmp/workspace/target-build/debug/deps/libequator_macro-0c5856ca18b3a9e0.dylib",
                "/tmp/workspace/target-build/debug/deps",
                &"ef".repeat(32),
            ),
            dependency_aliases: Vec::new(),
        };

        select_captured_artifact(&mut selected, key.clone(), first).expect("select first");
        select_captured_artifact(&mut selected, key.clone(), second)
            .expect("the same unit in another phase dir merges");

        let stored = selected.get(&key).expect("selected capture");
        assert!(
            stored.dependency_aliases.contains(&PathBuf::from(
                "/tmp/workspace/target-build/debug/deps/libequator_macro-0c5856ca18b3a9e0.dylib"
            )),
            "the dropped half's dylib path stays resolvable"
        );
    }

    /// A proc-macro capture record: one `link` emit, one dylib output at
    /// `dylib_path` with the given recorded digest.
    fn dylib_capture(dylib_path: &str, out_dir: &str, sha256: &str) -> CapturedRustcArtifact {
        let out_dir = PathBuf::from(out_dir);
        CapturedRustcArtifact {
            crate_name: "equator_macro".to_owned(),
            crate_version: Some("0.4.2".to_owned()),
            crate_types: vec!["proc-macro".to_owned()],
            emit: vec!["dep-info".to_owned(), "link".to_owned()],
            target: Some("aarch64-apple-darwin".to_owned()),
            compile_key: "ab".repeat(32),
            c_metadata: "0c5856ca18b3a9e0".to_owned(),
            extra_filename: "-0c5856ca18b3a9e0".to_owned(),
            dependencies: Vec::new(),
            profile: debug_profile(),
            target_dir: out_dir
                .parent()
                .and_then(Path::parent)
                .map_or_else(|| out_dir.clone(), Path::to_path_buf),
            out_dir,
            build_script_out_dir: None,
            outputs: vec![CapturedRustcOutput {
                kind: CapturedRustcOutputKind::DynamicLibrary,
                path: PathBuf::from(dylib_path),
                snapshot_path: None,
                sha256: sha256.to_owned(),
            }],
            restorable: true,
            consumed: false,
            compile_millis: 0,
        }
    }

    #[test]
    fn same_key_records_with_different_outputs_are_a_fatal_duplicate() {
        let key = (
            "aho_corasick".to_owned(),
            "ef4a079a8dc04c32".to_owned(),
            ArtifactKind::Rlib.as_str().to_owned(),
            "[\"dep-info\",\"link\"]".to_owned(),
        );
        let mut selected = BTreeMap::new();
        let package = IndexedPackage {
            name: "aho_corasick".to_owned(),
            version: semver::Version::parse("1.1.4").expect("version"),
            lib_target_name: "aho_corasick".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
            features: BTreeSet::new(),
            registry: true,
        };
        let first = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind: ArtifactKind::Rlib,
            captured: captured(
                "aho_corasick",
                "ef4a079a8dc04c32",
                "/tmp/workspace/target/debug/deps",
            ),
            dependency_aliases: Vec::new(),
        };
        let mut different_outputs = first.captured.clone();
        different_outputs.outputs[0].sha256 = "ff".repeat(32);
        let second = SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured: different_outputs,
            dependency_aliases: Vec::new(),
        };

        select_captured_artifact(&mut selected, key.clone(), first).expect("select first");
        let error = select_captured_artifact(&mut selected, key, second)
            .expect_err("different outputs under one key must fail");
        assert!(error.to_string().contains("duplicate identity"), "{error}");
    }

    /// A second record under one key whose compile key differs is a
    /// genuinely different unit, not another capture of the same one.
    #[test]
    fn same_key_records_with_different_compile_keys_are_a_fatal_duplicate() {
        let key = (
            "aho_corasick".to_owned(),
            "ef4a079a8dc04c32".to_owned(),
            ArtifactKind::Rlib.as_str().to_owned(),
            "[\"dep-info\",\"link\"]".to_owned(),
        );
        let mut selected = BTreeMap::new();
        let package = IndexedPackage {
            name: "aho_corasick".to_owned(),
            version: semver::Version::parse("1.1.4").expect("version"),
            lib_target_name: "aho_corasick".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
            features: BTreeSet::new(),
            registry: true,
        };
        let mut first_capture = captured(
            "aho_corasick",
            "ef4a079a8dc04c32",
            "/tmp/workspace/target/debug/deps",
        );
        first_capture.compile_key = "aa".repeat(32);
        let first = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind: ArtifactKind::Rlib,
            captured: first_capture,
            dependency_aliases: Vec::new(),
        };
        let mut different_unit = first.captured.clone();
        different_unit.out_dir =
            PathBuf::from("/tmp/workspace/target/aarch64-apple-darwin/debug/deps");
        different_unit.compile_key = "bb".repeat(32);
        let second = SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured: different_unit,
            dependency_aliases: Vec::new(),
        };

        select_captured_artifact(&mut selected, key.clone(), first).expect("select first");
        let error = select_captured_artifact(&mut selected, key, second)
            .expect_err("a different compile key under one key must fail");
        assert!(error.to_string().contains("duplicate identity"), "{error}");
    }

    #[test]
    fn a_restorable_record_with_no_package_in_the_index_fails() {
        // The record claims `itoa` but no such package is in cargo's
        // metadata — nothing to attribute the outputs to, so the scan must
        // fail rather than shrink the plan.
        let index = super::PackageIndex::new();
        let mut captured = captured(
            "itoa",
            "ef4a079a8dc04c32",
            "/tmp/workspace/target/debug/deps",
        );
        captured.crate_version = Some("1.0.15".to_owned());

        let error = select_captured_artifacts(&index, &[captured])
            .expect_err("an unattributable restorable record must fail");
        assert!(error.to_string().contains("could not attribute"), "{error}");
    }

    #[test]
    fn a_restorable_record_with_no_artifact_kind_fails() {
        // `bin` produces nothing restorable, so a record claiming restorable
        // outputs with only a `bin` crate-type is forged — classify or fail.
        let mut index = super::PackageIndex::new();
        index
            .entry("itoa".to_owned())
            .or_default()
            .insert("1.0.15".to_owned(), indexed("itoa", "1.0.15"));
        let mut captured = captured(
            "itoa",
            "ef4a079a8dc04c32",
            "/tmp/workspace/target/debug/deps",
        );
        captured.crate_version = Some("1.0.15".to_owned());
        captured.crate_types = vec!["bin".to_owned()];

        let error = select_captured_artifacts(&index, &[captured])
            .expect_err("an unclassifiable restorable record must fail");
        assert!(error.to_string().contains("could not classify"), "{error}");
    }

    #[test]
    fn a_hyphenated_library_target_is_found_under_rustcs_crate_name() {
        // cargo reports cfg-if's library target as `cfg-if`; rustc calls it
        // `cfg_if`. Indexing by the raw name lost every such crate.
        let mut index = super::PackageIndex::new();
        index
            .entry(stow_types::public_cache::canonical_crate_name("cfg-if"))
            .or_default()
            .insert("1.0.0".to_owned(), indexed("cfg-if", "1.0.0"));

        let mut captured = captured_with_target(
            "cfg_if",
            "aaaaaaaaaaaaaaaa",
            "/tmp/workspace/target/debug/deps",
            None,
        );
        captured.crate_version = Some("1.0.0".to_owned());
        assert!(super::package_for_capture(&index, &captured).is_some());
    }

    #[test]
    fn two_versions_of_one_crate_stay_distinct_in_the_package_index() {
        // bitflags 1.3.2 and 2.5.0 coexist in plenty of real graphs and share
        // the library target name `bitflags`. Collapsing them registered one
        // version's bytes under the other's identity, and the client then
        // injected 2.5.0 into a 1.3.2 unit.
        let mut index = super::PackageIndex::new();
        for version in ["1.3.2", "2.5.0"] {
            index
                .entry("bitflags".to_owned())
                .or_default()
                .insert(version.to_owned(), indexed("bitflags", version));
        }

        let mut captured = captured_with_target(
            "bitflags",
            "aaaaaaaaaaaaaaaa",
            "/tmp/workspace/target/debug/deps",
            None,
        );
        captured.crate_version = Some("1.3.2".to_owned());
        assert_eq!(
            super::package_for_capture(&index, &captured)
                .expect("the 1.3.2 package")
                .version
                .to_string(),
            "1.3.2"
        );

        captured.crate_version = Some("2.5.0".to_owned());
        assert_eq!(
            super::package_for_capture(&index, &captured)
                .expect("the 2.5.0 package")
                .version
                .to_string(),
            "2.5.0"
        );

        // Refuse to guess rather than attribute bytes to the wrong version.
        captured.crate_version = None;
        assert!(super::package_for_capture(&index, &captured).is_none());

        // With only one version in the graph there is nothing to confuse.
        let mut single = super::PackageIndex::new();
        single
            .entry("bitflags".to_owned())
            .or_default()
            .insert("2.5.0".to_owned(), indexed("bitflags", "2.5.0"));
        assert!(super::package_for_capture(&single, &captured).is_some());
    }

    fn indexed(name: &str, version: &str) -> super::IndexedPackage {
        super::IndexedPackage {
            name: name.to_owned(),
            version: semver::Version::parse(version).expect("version"),
            // As cargo reports it: verbatim, hyphens and all.
            lib_target_name: name.to_owned(),
            crate_types: vec![RustCrateType::Lib],
            features: BTreeSet::new(),
            registry: true,
        }
    }

    /// A two-unit selection — the `itoa` leaf plus the `serde_json` unit
    /// that depends on it — and the `serde_json` task to resolve against.
    /// `claimed_*` is the identity the consumer's dependency sidecar
    /// attributes to the leaf, which the resolver must cross-check.
    fn leaf_and_consumer(
        claimed_compile_key: &str,
        claimed_stable_c_metadata: &str,
    ) -> (Vec<SelectedCapturedArtifact>, BuildTaskPayload) {
        let leaf_output = PathBuf::from(
            "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libitoa-raw.rmeta",
        );
        let leaf = leaf_selection(&leaf_output);
        let consumer =
            consumer_selection(&leaf_output, claimed_compile_key, claimed_stable_c_metadata);
        (vec![leaf, consumer], consumer_task())
    }

    /// The `itoa` leaf unit: one rmeta output and no dependencies.
    fn leaf_selection(leaf_output: &Path) -> SelectedCapturedArtifact {
        SelectedCapturedArtifact {
            package: indexed("itoa", "1.0.18"),
            artifact_kind: ArtifactKind::Rlib,
            captured: raw_lib_capture("itoa", "leaf-raw", Vec::new(), leaf_output.to_owned()),
            dependency_aliases: Vec::new(),
        }
    }

    /// The `serde_json` unit whose dependency sidecar claims `claimed_*`
    /// as the identity of the `itoa` leaf.
    fn consumer_selection(
        leaf_output: &Path,
        claimed_compile_key: &str,
        claimed_stable_c_metadata: &str,
    ) -> SelectedCapturedArtifact {
        let mut package = indexed("serde_json", "1.0.149");
        package.features = ["default".to_owned(), "std".to_owned()]
            .into_iter()
            .collect();
        SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured: raw_lib_capture(
                "serde_json",
                "consumer-raw",
                vec![CapturedDependencyIdentity {
                    crate_name: "itoa".to_owned(),
                    path: leaf_output.to_owned(),
                    compile_key: claimed_compile_key.to_owned(),
                    stable_c_metadata: claimed_stable_c_metadata.to_owned(),
                }],
                PathBuf::from(
                    "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libserde_json-raw.rmeta",
                ),
            ),
            dependency_aliases: Vec::new(),
        }
    }

    /// A metadata-phase capture of one lib unit in the shared dev-profile
    /// `out_dir`, with a single rmeta output at `output_path`.
    fn raw_lib_capture(
        crate_name: &str,
        c_metadata: &str,
        dependencies: Vec<CapturedDependencyIdentity>,
        output_path: PathBuf,
    ) -> CapturedRustcArtifact {
        CapturedRustcArtifact {
            crate_name: crate_name.to_owned(),
            crate_version: None,
            crate_types: vec!["lib".to_owned()],
            emit: vec!["dep-info".to_owned(), "metadata".to_owned()],
            target: Some("aarch64-apple-darwin".to_owned()),
            compile_key: String::new(),
            c_metadata: c_metadata.to_owned(),
            extra_filename: format!("-{c_metadata}"),
            dependencies,
            profile: debug_profile(),
            out_dir: PathBuf::from("/tmp/workspace/target/aarch64-apple-darwin/debug/deps"),
            target_dir: PathBuf::from("/tmp/workspace/target"),
            build_script_out_dir: None,
            outputs: vec![CapturedRustcOutput {
                kind: CapturedRustcOutputKind::Rmeta,
                path: output_path,
                snapshot_path: None,
                sha256: "00".repeat(32),
            }],
            restorable: true,
            consumed: false,
            compile_millis: 0,
        }
    }

    /// The `serde_json` task matching `consumer_selection`.
    fn consumer_task() -> BuildTaskPayload {
        BuildTaskPayload {
            task_id: "task".to_owned(),
            attempt: 1,
            crate_name: stow_types::identity::CrateName::parse("serde_json").unwrap(),
            version: stow_types::identity::CrateVersion::new(
                semver::Version::parse("1.0.149").unwrap(),
            ),
            features_json: stow_types::identity::FeaturesJson::canonicalize(vec![
                "default".to_owned(),
                "std".to_owned(),
            ])
            .unwrap(),
            target: stow_types::identity::TargetTriple::parse("aarch64-apple-darwin").unwrap(),
            rustc_version: stow_types::identity::WireRustcVersion::parse("1.91.1").unwrap(),
            preserve_lockfile: false,
        }
    }

    fn resolve_consumer(
        selected: &[SelectedCapturedArtifact],
    ) -> stow_types::error::Result<ResolvedArtifact> {
        let output_owners = output_owner_index(selected, &[]).expect("build output owner index");
        let mut resolved = BTreeMap::<usize, ResolvedArtifact>::new();
        let mut visiting = BTreeSet::<usize>::new();
        let mut cx = super::ResolveCx {
            selected,
            consumed: &[],
            output_owners: &output_owners,
            resolved: &mut resolved,
            visiting: &mut visiting,
        };
        resolve_artifact(&mut cx, 1)
    }

    #[test]
    fn a_forged_dependency_identity_sidecar_fails_resolution() {
        // The claimed identity came from an `output-identities/*.json` file
        // any sandboxed process could write; it must collide with the
        // dependency's own record, not silently re-key the dependent.
        let (selected, _task) =
            leaf_and_consumer("wrong-captured-compile-key", "wrong-captured-stable");
        let error = resolve_consumer(&selected).expect_err("a forged sidecar identity must fail");
        assert!(
            error
                .to_string()
                .contains("does not match the resolved artifact's identity"),
            "{error}"
        );
    }

    #[test]
    fn a_matching_dependency_identity_resolves() {
        // The leaf's own record carries compile_key "" and c_metadata
        // "leaf-raw"; a sidecar claiming exactly that is honest.
        let (selected, _task) = leaf_and_consumer("", "leaf-raw");
        let consumer = resolve_consumer(&selected).expect("resolve consumer");
        assert_eq!(consumer.dependencies.len(), 1);
        assert_eq!(consumer.dependencies[0].stable_c_metadata, "leaf-raw");
    }

    fn captured(crate_name: &str, c_metadata: &str, out_dir: &str) -> CapturedRustcArtifact {
        captured_with_target(
            crate_name,
            c_metadata,
            out_dir,
            Some("aarch64-apple-darwin"),
        )
    }

    /// The dev `Profile` every capture in this module is recorded under.
    fn debug_profile() -> Profile {
        Profile {
            opt_level: "0".to_owned(),
            debuginfo: 1,
            debug_assertions: true,
            overflow_checks: true,
            panic: PanicStrategy::Unwind,
            strip: stow_types::platform::StripLevel::None,
        }
    }

    fn captured_with_target(
        crate_name: &str,
        c_metadata: &str,
        out_dir: &str,
        target: Option<&str>,
    ) -> CapturedRustcArtifact {
        CapturedRustcArtifact {
            crate_name: crate_name.to_owned(),
            crate_version: None,
            crate_types: vec!["rlib".to_owned()],
            emit: vec!["dep-info".to_owned(), "link".to_owned()],
            target: target.map(ToOwned::to_owned),
            compile_key: String::new(),
            c_metadata: c_metadata.to_owned(),
            extra_filename: format!("-{c_metadata}"),
            dependencies: Vec::new(),
            profile: debug_profile(),
            out_dir: PathBuf::from(out_dir),
            target_dir: PathBuf::from("/tmp/workspace/target"),
            build_script_out_dir: None,
            outputs: vec![CapturedRustcOutput {
                kind: CapturedRustcOutputKind::Rmeta,
                path: PathBuf::from(out_dir).join(format!("lib{crate_name}-{c_metadata}.rmeta")),
                snapshot_path: None,
                sha256: "00".repeat(32),
            }],
            restorable: true,
            consumed: false,
            compile_millis: 0,
        }
    }

    #[test]
    fn dependency_without_resolved_features_does_not_inherit_root_task_features() {
        let task = BuildTaskPayload {
            task_id: "serde-1.0.228-task".to_owned(),
            attempt: 1,
            crate_name: stow_types::identity::CrateName::parse("serde").unwrap(),
            version: stow_types::identity::CrateVersion::new(
                semver::Version::parse("1.0.228").unwrap(),
            ),
            features_json: stow_types::identity::FeaturesJson::canonicalize(vec![
                "default".to_owned(),
                "derive".to_owned(),
                "serde_derive".to_owned(),
                "std".to_owned(),
            ])
            .unwrap(),
            target: stow_types::identity::TargetTriple::parse("aarch64-apple-darwin").unwrap(),
            rustc_version: stow_types::identity::WireRustcVersion::parse("1.91.1").unwrap(),
            preserve_lockfile: false,
        };
        let task_features = ["default", "derive", "serde_derive", "std"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();

        let serde_declared = [
            "alloc",
            "default",
            "derive",
            "rc",
            "serde_derive",
            "std",
            "unstable",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        assert_eq!(
            package_feature_set(
                "unicode-ident",
                &BTreeSet::new(),
                &BTreeSet::new(),
                &task_features,
                &task,
            ),
            BTreeSet::new()
        );
        assert_eq!(
            package_feature_set(
                "serde",
                &BTreeSet::new(),
                &serde_declared,
                &task_features,
                &task,
            ),
            task_features
        );
    }

    #[test]
    fn task_features_are_intersected_with_declared_features() {
        let task = BuildTaskPayload {
            task_id: "itoa-1.0.18-task".to_owned(),
            attempt: 1,
            crate_name: stow_types::identity::CrateName::parse("itoa").unwrap(),
            version: stow_types::identity::CrateVersion::new(
                semver::Version::parse("1.0.18").unwrap(),
            ),
            features_json: stow_types::identity::FeaturesJson::canonicalize(vec![
                "default".to_owned(),
            ])
            .unwrap(),
            target: stow_types::identity::TargetTriple::parse("aarch64-apple-darwin").unwrap(),
            rustc_version: stow_types::identity::WireRustcVersion::parse("1.91.1").unwrap(),
            preserve_lockfile: false,
        };
        let task_features = BTreeSet::from(["default".to_owned()]);

        // itoa declares no features at all: `["default"]` must collapse to
        // `[]` rather than registering a row the semantic lookup can never
        // match.
        assert_eq!(
            package_feature_set(
                "itoa",
                &BTreeSet::new(),
                &BTreeSet::new(),
                &task_features,
                &task,
            ),
            BTreeSet::new()
        );
        // A package that declares `default` plus other features keeps only
        // the declared subset of what the task requested.
        let declared = ["alloc", "default", "std"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            package_feature_set("itoa", &BTreeSet::new(), &declared, &task_features, &task,),
            BTreeSet::from(["default".to_owned()])
        );
    }

    fn selected_with_output(
        path: PathBuf,
        snapshot_path: Option<PathBuf>,
        sha256: String,
    ) -> SelectedCapturedArtifact {
        SelectedCapturedArtifact {
            package: IndexedPackage {
                name: "itoa".to_owned(),
                version: semver::Version::parse("1.0.18").expect("version"),
                lib_target_name: "itoa".to_owned(),
                crate_types: vec![RustCrateType::Lib],
                features: BTreeSet::new(),
                registry: true,
            },
            artifact_kind: ArtifactKind::Rlib,
            captured: CapturedRustcArtifact {
                crate_name: "itoa".to_owned(),
                crate_version: Some("1.0.18".to_owned()),
                crate_types: vec!["lib".to_owned()],
                emit: vec!["dep-info".to_owned(), "link".to_owned()],
                target: Some("aarch64-apple-darwin".to_owned()),
                compile_key: "deadbeef".to_owned(),
                c_metadata: "47d1962f861b84d6".to_owned(),
                extra_filename: "-47d1962f861b84d6".to_owned(),
                dependencies: Vec::new(),
                profile: debug_profile(),
                out_dir: path
                    .parent()
                    .map_or_else(|| path.clone(), Path::to_path_buf),
                target_dir: PathBuf::from("/tmp/workspace/target"),
                build_script_out_dir: None,
                outputs: vec![CapturedRustcOutput {
                    kind: CapturedRustcOutputKind::Rlib,
                    path,
                    snapshot_path,
                    sha256,
                }],
                restorable: true,
                consumed: false,
                compile_millis: 0,
            },
            dependency_aliases: Vec::new(),
        }
    }

    #[test]
    fn scan_verification_fails_on_a_digest_mismatch() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let output_path = tempdir.path().join("libitoa-47d1962f861b84d6.rlib");
            std::fs::write(&output_path, b"original bytes").expect("write output");
            let recorded = hex::encode(sha2::Sha256::digest(b"original bytes"));

            // Bytes rewritten after rustc exited — the recorded digest no
            // longer matches what is on disk.
            std::fs::write(&output_path, b"rewritten bytes").expect("rewrite output");

            let selected = [selected_with_output(
                output_path.clone(),
                None,
                recorded.clone(),
            )];
            let error = super::verify_output_digests(selected.iter().map(|s| &s.captured))
                .await
                .expect_err("modified output must fail verification");
            let message = error.to_string();
            assert!(
                message.contains(&recorded),
                "error names the recorded digest: {message}"
            );
            assert!(
                message.contains(&output_path.display().to_string()),
                "error names the file: {message}"
            );
        });
    }

    #[test]
    fn scan_verification_prefers_the_frozen_snapshot_bytes() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let output_path = tempdir.path().join("libitoa-47d1962f861b84d6.rlib");
            let snapshot_path = tempdir.path().join("snapshot.rlib");
            std::fs::write(&snapshot_path, b"rustc-exit bytes").expect("write snapshot");
            // The live output was clobbered after rustc exited; the snapshot
            // still holds the recorded bytes, so verification reads it.
            std::fs::write(&output_path, b"clobbered bytes").expect("write output");
            let recorded = hex::encode(sha2::Sha256::digest(b"rustc-exit bytes"));

            let selected = [selected_with_output(
                output_path,
                Some(snapshot_path),
                recorded,
            )];
            super::verify_output_digests(selected.iter().map(|s| &s.captured))
                .await
                .expect("snapshot bytes match the recorded digest");
        });
    }
}
