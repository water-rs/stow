use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use async_process::Command;
use cargo_metadata::{Metadata, Package, PackageId, Target, TargetKind};
use stow_types::api::BuildTaskPayload;
use stow_types::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use stow_types::platform::Profile;

use crate::native;
use crate::task::{BuiltWorkspace, CargoFeatureArgs};
use stow_types::capture::{CapturedRustcArtifact, CapturedRustcOutputKind};

pub async fn scan_artifacts(
    built: &BuiltWorkspace,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<Vec<ScannedArtifact>> {
    let metadata = cargo_metadata(built.workspace().manifest_path(), task).await?;
    let rustc_version = task.rustc_version.as_str().to_owned();
    let package_index = package_index(&metadata, task);
    // The records the host collector received over IPC — the only capture
    // source the scan trusts. Nothing the sandbox wrote to disk qualifies.
    let captured_artifacts = built.captures();
    let authoritative_target_dir = built.authoritative_target_dir().to_path_buf();
    // Mirrors the `--target` decision in `task::build`: a host build has one
    // unit graph, a cross-compile has two.
    let split_unit_graph = !crate::task::target_is_host(task.target.as_str()).await?;

    let mut selected =
        BTreeMap::<(String, String, String, String), SelectedCapturedArtifact>::new();
    let mut skipped_unindexed = BTreeSet::<String>::new();
    for captured in captured_artifacts {
        // Observed units (build-script compiles, binaries, probes) exist so a
        // forged record collides with them; they carry no artifacts to plan.
        if !captured.restorable {
            continue;
        }
        let Some(package) = package_for_capture(&package_index, captured) else {
            // Not debug: a capture dropped here takes every consumer of that
            // crate down with it, and the resulting "could not resolve
            // authoritative dependency owner" error names the consumer rather
            // than the crate that actually went missing.
            tracing::warn!(
                captured_crate = %captured.crate_name,
                c_metadata = %captured.c_metadata,
                captured_version = captured.crate_version.as_deref(),
                "dep_scan skipped capture: cargo metadata has no library target at that name and version"
            );
            skipped_unindexed.insert(captured.crate_name.clone());
            continue;
        };
        let Some(artifact_kind) = artifact_kind_for_capture(captured) else {
            tracing::debug!(
                captured_crate = %captured.crate_name,
                crate_types = ?captured.crate_types,
                "dep_scan skipped capture — unrecognized crate types"
            );
            continue;
        };
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
        select_captured_artifact(
            &mut selected,
            key,
            candidate,
            &authoritative_target_dir,
            task.target.as_str(),
            split_unit_graph,
        )?;
    }

    let selected = selected.into_values().collect::<Vec<_>>();
    let output_owners = output_owner_index(&selected)?;
    let mut resolved = BTreeMap::<usize, ResolvedArtifact>::new();
    let mut visiting = BTreeSet::<usize>::new();

    let mut artifacts = Vec::with_capacity(selected.len());
    let mut unresolved = 0_usize;
    for index in 0..selected.len() {
        match build_scanned_artifact(
            task,
            &rustc_version,
            &selected,
            &output_owners,
            &mut resolved,
            &mut visiting,
            index,
        )
        .await
        {
            Ok(artifact) => artifacts.push(artifact),
            // One unattributable unit used to abort the whole capture, so a
            // single crate cost every other artifact in the project: eza
            // 0.20.7 produced nothing at all because one `cfg_if` rmeta could
            // not be traced back to the invocation that wrote it.
            //
            // An artifact whose dependency identities cannot be resolved is
            // genuinely uncacheable - its compile key would be wrong - so drop
            // that one and keep going. Anything depending on it fails to
            // resolve in turn and drops with it, which is the correct closure.
            // Every drop is named, so this hides nothing.
            Err(error) => {
                unresolved = unresolved.saturating_add(1);
                let artifact = selected.get(index);
                tracing::warn!(
                    %error,
                    crate_name = artifact.map(|artifact| artifact.captured.crate_name.as_str()),
                    c_metadata = artifact.map(|artifact| artifact.captured.c_metadata.as_str()),
                    "dep_scan dropped an artifact whose dependency identities could not be resolved"
                );
                visiting.clear();
            }
        }
    }
    if unresolved > 0 {
        tracing::warn!(
            unresolved,
            scanned = artifacts.len(),
            skipped_unindexed = ?skipped_unindexed,
            "dep_scan could not resolve every captured artifact; the rest were scanned"
        );
    }
    if artifacts.is_empty() && !selected.is_empty() {
        return Err(stow_types::stow_error!(
            "dep_scan resolved none of the {} captured artifacts",
            selected.len()
        ));
    }
    for artifact in &mut artifacts {
        artifact
            .outputs
            .sort_by(|left, right| left.path.cmp(&right.path));
        artifact.native = native::capture_native_artifacts(
            &artifact.crate_name,
            artifact.build_script_out_dir.as_deref(),
        )
        .await?;
    }
    artifacts.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.c_metadata.cmp(&right.c_metadata))
            .then(left.kind.as_str().cmp(right.kind.as_str()))
    });

    Ok(artifacts)
}

fn select_captured_artifact(
    selected: &mut BTreeMap<(String, String, String, String), SelectedCapturedArtifact>,
    key: (String, String, String, String),
    mut candidate: SelectedCapturedArtifact,
    authoritative_target_dir: &Path,
    requested_target: &str,
    split_unit_graph: bool,
) -> stow_types::error::Result<()> {
    let candidate_authority = captured_authority(
        &candidate.captured,
        authoritative_target_dir,
        requested_target,
        split_unit_graph,
    );
    let Some(existing) = selected.get(&key) else {
        selected.insert(key, candidate);
        return Ok(());
    };
    let existing_authority = captured_authority(
        &existing.captured,
        authoritative_target_dir,
        requested_target,
        split_unit_graph,
    );

    match existing_authority.cmp(&candidate_authority) {
        std::cmp::Ordering::Less => {
            tracing::debug!(
                crate_name = %candidate.captured.crate_name,
                c_metadata = %candidate.captured.c_metadata,
                selected_authority = %candidate_authority.as_str(),
                replacing_out_dir = %candidate.captured.out_dir.display(),
                ignored_out_dir = %existing.captured.out_dir.display(),
                "dep_scan selected higher-authority cargo target outputs"
            );
            candidate.extend_dependency_aliases(existing.dependency_aliases.iter().cloned());
            candidate.extend_dependency_aliases(
                existing
                    .captured
                    .outputs
                    .iter()
                    .map(|output| output.path.clone()),
            );
            selected.insert(key, candidate);
            Ok(())
        }
        std::cmp::Ordering::Greater => {
            tracing::debug!(
                crate_name = %candidate.captured.crate_name,
                c_metadata = %candidate.captured.c_metadata,
                kept_authority = %existing_authority.as_str(),
                authoritative_out_dir = %existing.captured.out_dir.display(),
                ignored_out_dir = %candidate.captured.out_dir.display(),
                "dep_scan ignored lower-authority cargo target outputs"
            );
            let existing = selected.get_mut(&key).ok_or_else(|| {
                stow_types::stow_error!("selected artifact disappeared while merging aliases")
            })?;
            existing.extend_dependency_aliases(candidate.dependency_aliases);
            existing.extend_dependency_aliases(
                candidate
                    .captured
                    .outputs
                    .into_iter()
                    .map(|output| output.path),
            );
            Ok(())
        }
        std::cmp::Ordering::Equal => Err(stow_types::stow_error!(
            "captured duplicate artifact {} {} emit {:?} from {} and {} with ambiguous target authority",
            candidate.captured.crate_name,
            candidate.captured.c_metadata,
            candidate.captured.emit,
            existing.captured.out_dir.display(),
            candidate.captured.out_dir.display()
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CapturedAuthority {
    PrePhase,
    FinalHost,
    FinalRequestedTarget,
}

impl CapturedAuthority {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PrePhase => "pre-phase",
            Self::FinalHost => "final-host-target",
            Self::FinalRequestedTarget => "final-requested-target",
        }
    }
}

fn captured_authority(
    captured: &CapturedRustcArtifact,
    authoritative_target_dir: &Path,
    requested_target: &str,
    split_unit_graph: bool,
) -> CapturedAuthority {
    let Ok(relative_out_dir) = captured.out_dir.strip_prefix(authoritative_target_dir) else {
        return CapturedAuthority::PrePhase;
    };
    let Some(first_component) = relative_out_dir
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
    else {
        return CapturedAuthority::FinalHost;
    };
    if first_component == requested_target {
        return CapturedAuthority::FinalRequestedTarget;
    }
    // A host build passes no `--target`, so cargo writes every final unit
    // straight under `target/<profile>/` and there is no host/target split to
    // arbitrate — those units are all authoritative. Only a cross-compile puts
    // host units somewhere the requested triple is not.
    if split_unit_graph {
        CapturedAuthority::FinalHost
    } else {
        CapturedAuthority::FinalRequestedTarget
    }
}

async fn build_scanned_artifact(
    task: &BuildTaskPayload,
    rustc_version: &str,
    selected: &[SelectedCapturedArtifact],
    output_owners: &BTreeMap<PathBuf, usize>,
    resolved: &mut BTreeMap<usize, ResolvedArtifact>,
    visiting: &mut BTreeSet<usize>,
    artifact_index: usize,
) -> stow_types::error::Result<ScannedArtifact> {
    let artifact = selected.get(artifact_index).ok_or_else(|| {
        stow_types::stow_error!("selected artifact index {artifact_index} is out of bounds")
    })?;
    let resolved_artifact = resolve_artifact(
        selected,
        output_owners,
        resolved,
        visiting,
        task,
        rustc_version,
        artifact_index,
    )?;
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
        kind: artifact.artifact_kind.clone(),
        crate_types: artifact.package.crate_types.clone(),
        outputs,
        build_script_out_dir: artifact.captured.build_script_out_dir.clone(),
        native: None,
    })
}

fn resolve_artifact(
    selected: &[SelectedCapturedArtifact],
    output_owners: &BTreeMap<PathBuf, usize>,
    resolved: &mut BTreeMap<usize, ResolvedArtifact>,
    visiting: &mut BTreeSet<usize>,
    task: &BuildTaskPayload,
    rustc_version: &str,
    artifact_index: usize,
) -> stow_types::error::Result<ResolvedArtifact> {
    if let Some(existing) = resolved.get(&artifact_index) {
        return Ok(existing.clone());
    }
    if !visiting.insert(artifact_index) {
        return Err(stow_types::stow_error!(
            "dep_scan detected a cycle while resolving authoritative artifact index {artifact_index}"
        ));
    }

    let artifact = selected.get(artifact_index).ok_or_else(|| {
        stow_types::stow_error!("selected artifact index {artifact_index} is out of bounds")
    })?;
    let dependencies = resolve_dependencies(
        selected,
        output_owners,
        resolved,
        visiting,
        task,
        rustc_version,
        artifact_index,
    )?;
    let features_json = serde_json::to_string(
        &artifact
            .package
            .features
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .expect("feature serialization must succeed");
    visiting.remove(&artifact_index);

    let resolved_artifact = ResolvedArtifact {
        compile_key: artifact.captured.compile_key.clone(),
        stable_c_metadata: artifact.captured.c_metadata.clone(),
        features_json,
        dependencies,
    };
    resolved.insert(artifact_index, resolved_artifact.clone());
    Ok(resolved_artifact)
}

fn resolve_dependencies(
    selected: &[SelectedCapturedArtifact],
    output_owners: &BTreeMap<PathBuf, usize>,
    resolved: &mut BTreeMap<usize, ResolvedArtifact>,
    visiting: &mut BTreeSet<usize>,
    task: &BuildTaskPayload,
    rustc_version: &str,
    artifact_index: usize,
) -> stow_types::error::Result<Vec<ScannedArtifactDependency>> {
    let artifact = selected.get(artifact_index).ok_or_else(|| {
        stow_types::stow_error!("selected artifact index {artifact_index} is out of bounds")
    })?;
    let mut dependencies = Vec::with_capacity(artifact.captured.dependencies.len());
    for dependency in &artifact.captured.dependencies {
        let dependency_index = output_owners.get(&dependency.path).ok_or_else(|| {
            stow_types::stow_error!(
                "dep_scan could not resolve authoritative dependency owner for {} at {} while scanning {}",
                dependency.crate_name,
                dependency.path.display(),
                artifact.captured.crate_name
            )
        })?;
        let resolved_dependency = resolve_artifact(
            selected,
            output_owners,
            resolved,
            visiting,
            task,
            rustc_version,
            *dependency_index,
        )?;
        dependencies.push(ScannedArtifactDependency {
            crate_name: dependency.crate_name.clone(),
            path: dependency.path.clone(),
            compile_key: resolved_dependency.compile_key,
            stable_c_metadata: resolved_dependency.stable_c_metadata,
        });
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
) -> stow_types::error::Result<BTreeMap<PathBuf, usize>> {
    let mut owners = BTreeMap::new();
    for (index, artifact) in selected.iter().enumerate() {
        for output in &artifact.captured.outputs {
            insert_output_owner(&mut owners, selected, &output.path, index)?;
        }
        for alias in &artifact.dependency_aliases {
            insert_output_owner(&mut owners, selected, alias, index)?;
        }
    }
    Ok(owners)
}

fn insert_output_owner(
    owners: &mut BTreeMap<PathBuf, usize>,
    selected: &[SelectedCapturedArtifact],
    path: &Path,
    index: usize,
) -> stow_types::error::Result<()> {
    if let Some(existing) = owners.insert(path.to_path_buf(), index)
        && existing != index
    {
        let existing_artifact = selected.get(existing).ok_or_else(|| {
            stow_types::stow_error!("selected artifact index {existing} is out of bounds")
        })?;
        let artifact = selected.get(index).ok_or_else(|| {
            stow_types::stow_error!("selected artifact index {index} is out of bounds")
        })?;
        return Err(stow_types::stow_error!(
            "dep_scan found duplicate authoritative output path {} claimed by {} and {}",
            path.display(),
            existing_artifact.captured.crate_name,
            artifact.captured.crate_name
        ));
    }
    Ok(())
}

async fn cargo_metadata(
    manifest_path: &Path,
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
        .arg(manifest_path);
    CargoFeatureArgs::from_task(task).apply(&mut command);
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
                        node.features.iter().cloned().collect::<BTreeSet<_>>(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default()
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
    let features = package_feature_set(
        package.name.as_str(),
        &resolved_features,
        &task_features,
        task,
    );

    Some(IndexedPackage {
        name: package.name.clone(),
        version: package.version.clone(),
        lib_target_name: target.name.clone(),
        crate_types,
        features,
    })
}

fn package_feature_set(
    package_name: &str,
    resolved_features: &BTreeSet<String>,
    task_features: &BTreeSet<String>,
    task: &BuildTaskPayload,
) -> BTreeSet<String> {
    if !resolved_features.is_empty() {
        return resolved_features.clone();
    }
    if package_name == task.crate_name {
        return task_features.clone();
    }
    BTreeSet::new()
}

fn preferred_target<'a>(
    package: &Package,
    target: &'a Target,
    task_features: &BTreeSet<String>,
) -> Option<(&'a Target, Vec<RustCrateType>, ArtifactKind)> {
    if target.name != package.name {
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

fn task_feature_set(task: &BuildTaskPayload) -> BTreeSet<String> {
    task.features_json.features().iter().cloned().collect()
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
    use std::path::PathBuf;

    use stow_types::api::BuildTaskPayload;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::platform::{PanicStrategy, Profile};

    use super::{
        IndexedPackage, ResolvedArtifact, SelectedCapturedArtifact, output_owner_index,
        package_feature_set, resolve_artifact, select_captured_artifact,
    };
    use stow_types::capture::{
        CapturedDependencyIdentity, CapturedRustcArtifact, CapturedRustcOutput,
        CapturedRustcOutputKind,
    };

    #[test]
    fn authoritative_target_outputs_replace_prephase_outputs() {
        let key = (
            "slug".to_owned(),
            "abc123".to_owned(),
            ArtifactKind::Rlib.as_str().to_owned(),
            "[\"dep-info\",\"link\"]".to_owned(),
        );
        let mut selected = BTreeMap::new();
        let package = super::IndexedPackage {
            name: "slug".to_owned(),
            version: semver::Version::parse("0.1.6").expect("version"),
            lib_target_name: "slug".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
            features: Default::default(),
        };
        let fallback = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind: ArtifactKind::Rlib,
            captured: captured(
                "slug",
                "abc123",
                "/tmp/workspace/target-check/aarch64-apple-darwin/debug/deps",
            ),
            dependency_aliases: Vec::new(),
        };
        let authoritative = SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured: captured(
                "slug",
                "abc123",
                "/tmp/workspace/target/aarch64-apple-darwin/debug/deps",
            ),
            dependency_aliases: Vec::new(),
        };

        select_captured_artifact(
            &mut selected,
            key.clone(),
            fallback,
            &PathBuf::from("/tmp/workspace/target"),
            "aarch64-apple-darwin",
            true,
        )
        .expect("select fallback");
        select_captured_artifact(
            &mut selected,
            key.clone(),
            authoritative,
            &PathBuf::from("/tmp/workspace/target"),
            "aarch64-apple-darwin",
            true,
        )
        .expect("replace with authoritative");

        let stored = selected.get(&key).expect("selected capture");
        assert!(
            stored
                .captured
                .out_dir
                .starts_with("/tmp/workspace/target/aarch64-apple-darwin/debug/deps")
        );
        assert_eq!(stored.dependency_aliases.len(), 1);
        assert!(
            stored.dependency_aliases[0]
                .starts_with("/tmp/workspace/target-check/aarch64-apple-darwin/debug/deps")
        );
    }

    #[test]
    fn requested_target_outputs_replace_host_target_outputs() {
        let key = (
            "aho_corasick".to_owned(),
            "ef4a079a8dc04c32".to_owned(),
            ArtifactKind::Rlib.as_str().to_owned(),
            "[\"dep-info\",\"link\",\"metadata\"]".to_owned(),
        );
        let mut selected = BTreeMap::new();
        let package = super::IndexedPackage {
            name: "aho_corasick".to_owned(),
            version: semver::Version::parse("1.1.4").expect("version"),
            lib_target_name: "aho_corasick".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
            features: Default::default(),
        };
        let host_target = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind: ArtifactKind::Rlib,
            captured: captured_with_target(
                "aho_corasick",
                "ef4a079a8dc04c32",
                "/tmp/workspace/target/debug/deps",
                None,
            ),
            dependency_aliases: Vec::new(),
        };
        let requested_target = SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured: captured_with_target(
                "aho_corasick",
                "ef4a079a8dc04c32",
                "/tmp/workspace/target/aarch64-apple-darwin/debug/deps",
                Some("aarch64-apple-darwin"),
            ),
            dependency_aliases: Vec::new(),
        };

        select_captured_artifact(
            &mut selected,
            key.clone(),
            host_target,
            &PathBuf::from("/tmp/workspace/target"),
            "aarch64-apple-darwin",
            true,
        )
        .expect("select host target");
        select_captured_artifact(
            &mut selected,
            key.clone(),
            requested_target,
            &PathBuf::from("/tmp/workspace/target"),
            "aarch64-apple-darwin",
            true,
        )
        .expect("replace with requested target");

        let stored = selected.get(&key).expect("selected capture");
        assert!(
            stored
                .captured
                .out_dir
                .starts_with("/tmp/workspace/target/aarch64-apple-darwin/debug/deps")
        );
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
        }
    }

    #[test]
    fn a_host_build_treats_untriaged_profile_dirs_as_authoritative() {
        // A host build passes no `--target`, so cargo writes every final unit
        // under `target/debug/` with no triple component. Classifying those as
        // "host, therefore lower authority" left the whole proc-macro graph
        // keyed differently from a user's plain `cargo build`, and every crate
        // deriving through it missed the cache.
        let captured = captured_with_target(
            "aho_corasick",
            "ef4a079a8dc04c32",
            "/tmp/workspace/target/debug/deps",
            None,
        );
        assert_eq!(
            super::captured_authority(
                &captured,
                &PathBuf::from("/tmp/workspace/target"),
                "x86_64-unknown-linux-gnu",
                false,
            ),
            super::CapturedAuthority::FinalRequestedTarget
        );
        // The same path in a cross-compile really is the host half.
        assert_eq!(
            super::captured_authority(
                &captured,
                &PathBuf::from("/tmp/workspace/target"),
                "aarch64-apple-darwin",
                true,
            ),
            super::CapturedAuthority::FinalHost
        );
    }

    #[test]
    fn a_pre_phase_capture_is_recognised_under_either_unit_graph() {
        let captured = captured_with_target(
            "aho_corasick",
            "ef4a079a8dc04c32",
            "/tmp/workspace/target-check/debug/deps",
            None,
        );
        for split in [false, true] {
            assert_eq!(
                super::captured_authority(
                    &captured,
                    &PathBuf::from("/tmp/workspace/target"),
                    "x86_64-unknown-linux-gnu",
                    split,
                ),
                super::CapturedAuthority::PrePhase
            );
        }
    }

    #[test]
    fn authoritative_dependency_resolution_ignores_captured_stable_metadata_snapshot() {
        let leaf_output = PathBuf::from(
            "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libitoa-raw.rmeta",
        );
        let leaf = SelectedCapturedArtifact {
            package: IndexedPackage {
                name: "itoa".to_owned(),
                version: semver::Version::parse("1.0.18").expect("version"),
                lib_target_name: "itoa".to_owned(),
                crate_types: vec![RustCrateType::Lib],
                features: BTreeSet::new(),
            },
            artifact_kind: ArtifactKind::Rlib,
            captured: CapturedRustcArtifact {
                crate_name: "itoa".to_owned(),
                crate_version: None,
                crate_types: vec!["lib".to_owned()],
                emit: vec!["dep-info".to_owned(), "metadata".to_owned()],
                target: Some("aarch64-apple-darwin".to_owned()),
                compile_key: String::new(),
                c_metadata: "leaf-raw".to_owned(),
                extra_filename: "-leaf-raw".to_owned(),
                dependencies: Vec::new(),
                profile: Profile {
                    opt_level: "0".to_owned(),
                    debuginfo: 1,
                    debug_assertions: true,
                    overflow_checks: true,
                    panic: PanicStrategy::Unwind,
                },
                out_dir: PathBuf::from("/tmp/workspace/target/aarch64-apple-darwin/debug/deps"),
                target_dir: PathBuf::from("/tmp/workspace/target"),
                build_script_out_dir: None,
                outputs: vec![CapturedRustcOutput {
                    kind: CapturedRustcOutputKind::Rmeta,
                    path: leaf_output.clone(),
                    snapshot_path: None,
                    sha256: "00".repeat(32),
                }],
                restorable: true,
            },
            dependency_aliases: Vec::new(),
        };
        let consumer = SelectedCapturedArtifact {
            package: IndexedPackage {
                name: "serde_json".to_owned(),
                version: semver::Version::parse("1.0.149").expect("version"),
                lib_target_name: "serde_json".to_owned(),
                crate_types: vec![RustCrateType::Lib],
                features: ["default".to_owned(), "std".to_owned()]
                    .into_iter()
                    .collect(),
            },
            artifact_kind: ArtifactKind::Rlib,
            captured: CapturedRustcArtifact {
                crate_name: "serde_json".to_owned(),
                crate_version: None,
                crate_types: vec!["lib".to_owned()],
                emit: vec!["dep-info".to_owned(), "metadata".to_owned()],
                target: Some("aarch64-apple-darwin".to_owned()),
                compile_key: String::new(),
                c_metadata: "consumer-raw".to_owned(),
                extra_filename: "-consumer-raw".to_owned(),
                dependencies: vec![CapturedDependencyIdentity {
                    crate_name: "itoa".to_owned(),
                    path: leaf_output.clone(),
                    compile_key: "wrong-captured-compile-key".to_owned(),
                    stable_c_metadata: "wrong-captured-stable".to_owned(),
                }],
                profile: Profile {
                    opt_level: "0".to_owned(),
                    debuginfo: 1,
                    debug_assertions: true,
                    overflow_checks: true,
                    panic: PanicStrategy::Unwind,
                },
                out_dir: PathBuf::from("/tmp/workspace/target/aarch64-apple-darwin/debug/deps"),
                target_dir: PathBuf::from("/tmp/workspace/target"),
                build_script_out_dir: None,
                outputs: vec![CapturedRustcOutput {
                    kind: CapturedRustcOutputKind::Rmeta,
                    path: PathBuf::from(
                        "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libserde_json-raw.rmeta",
                    ),
                    snapshot_path: None,
                    sha256: "00".repeat(32),
                }],
                restorable: true,
            },
            dependency_aliases: Vec::new(),
        };
        let selected = vec![leaf, consumer];
        let output_owners = output_owner_index(&selected).expect("build output owner index");
        let task = BuildTaskPayload {
            task_id: "task".to_owned(),
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
        };
        let mut resolved = BTreeMap::<usize, ResolvedArtifact>::new();
        let mut visiting = BTreeSet::<usize>::new();

        let leaf_resolved = resolve_artifact(
            &selected,
            &output_owners,
            &mut resolved,
            &mut visiting,
            &task,
            "1.91.1",
            0,
        )
        .expect("resolve leaf artifact");
        let consumer_resolved = resolve_artifact(
            &selected,
            &output_owners,
            &mut resolved,
            &mut visiting,
            &task,
            "1.91.1",
            1,
        )
        .expect("resolve consumer artifact");

        assert_eq!(consumer_resolved.dependencies.len(), 1);
        assert_eq!(
            consumer_resolved.dependencies[0].stable_c_metadata,
            leaf_resolved.stable_c_metadata
        );
        assert_eq!(
            consumer_resolved.dependencies[0].compile_key,
            leaf_resolved.compile_key
        );
    }

    fn captured(crate_name: &str, c_metadata: &str, out_dir: &str) -> CapturedRustcArtifact {
        captured_with_target(
            crate_name,
            c_metadata,
            out_dir,
            Some("aarch64-apple-darwin"),
        )
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
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 1,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
            },
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
        }
    }

    #[test]
    fn dependency_without_resolved_features_does_not_inherit_root_task_features() {
        let task = BuildTaskPayload {
            task_id: "serde-1.0.228-task".to_owned(),
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

        assert_eq!(
            package_feature_set("unicode-ident", &BTreeSet::new(), &task_features, &task),
            BTreeSet::new()
        );
        assert_eq!(
            package_feature_set("serde", &BTreeSet::new(), &task_features, &task),
            task_features
        );
    }
}
