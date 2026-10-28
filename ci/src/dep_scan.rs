use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use async_process::Command;
use cargo_metadata::{Metadata, Package, Target, TargetKind};
use futures_util::StreamExt;
use sha2::Digest as _;
use stow_types::api::{BuildTaskPayload, ResolvedDependencyGraphEntry};
use stow_types::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use stow_types::platform::Profile;
use stow_types::unit_graph::{TaskUnitKind, TaskUnitSide};

use crate::task::{BuildWorkspace, BuiltWorkspace};
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
    let metadata = cargo_metadata(built.workspace()).await?;
    let rustc_version = task.rustc_version.as_str().to_owned();
    // The triple units compiled without a `--target` ran for: the
    // runner's host. `cargo` spells no `--target` for host units
    // (proc-macro and build-script subtrees) whatever the consumer's
    // spelling is, so a targetless capture's honest target is this —
    // never the task's.
    let host_target = crate::task::compile_host(task).await?;
    let package_index = package_index(&metadata, task);
    // The records the host collector received over IPC — the only capture
    // source the scan trusts. Nothing the sandbox wrote to disk qualifies.
    let captured_artifacts = built.captures();
    let restorable_captures = captured_artifacts
        .iter()
        .filter(|captured| captured.restorable)
        .count();

    let selected = select_captured_artifacts(&package_index, captured_artifacts)?;
    // Merges whose rlib digests differed are not settled yet: the
    // archives must agree on what rustc wrote before the merged halves
    // can be treated as one unit's captures.
    verify_rlib_pairs_agree(&selected.rlib_pairs).await?;
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
    let own_units = phase_own_units(task, built.unit_graphs(), built.run_dir())?;
    reject_foreign_compiled_units(
        task,
        &selected,
        &consumed_captures,
        &output_owners,
        &own_units,
    )?;
    reject_unflagged_proc_macro_extern(task, &selected, &consumed_captures, &output_owners)?;
    let phase_units = phase_feature_sets(task, built)?;
    let mut resolved = BTreeMap::<usize, ResolvedArtifact>::new();
    let mut visiting = BTreeSet::<usize>::new();
    let mut cx = ResolveCx {
        task,
        selected: &selected,
        consumed: &consumed_captures,
        output_owners: &output_owners,
        phase_units: &phase_units,
        resolved: &mut resolved,
        visiting: &mut visiting,
    };

    let mut artifacts = Vec::with_capacity(selected.len());
    for index in 0..selected.len() {
        artifacts.push(
            build_scanned_artifact(task, &rustc_version, &host_target, &mut cx, index).await?,
        );
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

/// The consumable set: every registry unit this build's own cargo unit
/// graph compiles, at the per-side feature set cargo activated for it —
/// the same identities a consumer's build computes, so a dep the build
/// can compile is always staged and one it cannot is never fetched
/// (stow#589). The task crate itself is excluded: a re-run after a
/// successful publish must never consume the artifact the task exists
/// to produce.
pub fn consumable_packages(
    task: &BuildTaskPayload,
    entries: &[ResolvedDependencyGraphEntry],
) -> Vec<ConsumablePackage> {
    entries
        .iter()
        // Only the task's own node is never consumable — it is the one
        // unit the task exists to produce. An outcome-3 host task
        // legitimately serves its crate's target-side twin: same name,
        // version and features, the other side (stow#723).
        .filter(|entry| {
            entry.crate_name.as_str() != task.crate_name.as_str()
                || &entry.version != task.version.as_semver()
                || entry.host_side != task.host_side
                || entry.features.iter().cloned().collect::<BTreeSet<_>>()
                    != task
                        .features_json
                        .features()
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>()
        })
        .map(|entry| ConsumablePackage {
            crate_name: entry.crate_name.as_str().to_owned(),
            version: entry.version.clone(),
            features: entry.features.iter().cloned().collect(),
            host_side: entry.host_side,
        })
        .collect()
}

/// One unit of the build workspace's own unit graph — a
/// consumption-prefetch candidate.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsumablePackage {
    /// Canonical package name.
    pub(crate) crate_name: String,
    /// Resolved package version.
    pub(crate) version: semver::Version,
    /// The feature set cargo activated for this unit — the identity the
    /// dep's own task published it under.
    pub(crate) features: BTreeSet<String>,
    /// Which half of the unit graph the unit compiles on: proc-macros,
    /// build dependencies and their subtree are host-side.
    pub(crate) host_side: bool,
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
            read_verified_output(source_path, &output.sha256, &artifact.crate_name).await?;
        }
    }
    Ok(())
}

/// Read one recorded output's file and require its sha256 to equal
/// `recorded`, the digest the wrapper froze at rustc exit — the check
/// [`verify_output_digests`] runs per output, lifted so
/// [`verify_rlib_pairs_agree`] applies the same rule to the merged-away
/// halves no record still owns. Returns the verified bytes.
async fn read_verified_output(
    source_path: &Path,
    recorded: &str,
    crate_name: &str,
) -> stow_types::error::Result<Vec<u8>> {
    let bytes = async_fs::read(source_path).await.map_err(|error| {
        stow_types::stow_error!(
            "read captured output {} for digest verification: {error}",
            source_path.display()
        )
    })?;
    let actual = hex::encode(sha2::Sha256::digest(&bytes));
    if actual != recorded {
        return Err(stow_types::stow_error!(
            "captured output {} for {} changed after rustc exited: recorded sha256 {}, actual sha256 {}",
            source_path.display(),
            crate_name,
            recorded,
            actual
        ));
    }
    Ok(bytes)
}

/// How many rlib pairs' files the member-agreement check reads at once.
/// A pair only exists when a merged capture's rlib digests differed —
/// rare beside the merges that prove identical at record level — and
/// each task is two file reads.
const RLIB_PAIR_CONCURRENCY: usize = 8;

/// Settle what selection deferred: every rlib pair whose recorded
/// digests differed between two captures merged as one unit. Each file
/// must still match its recorded digest — a rewritten file fails with
/// the same error [`verify_output_digests`] produces — and the archives
/// must agree on what rustc wrote (`lib.rmeta` and every `*.rcgu.o`, in
/// order) and on how many members the build script's native objects
/// contributed, whose names and bytes are free to differ because they
/// record where and when their own compiler ran (stow#719). A pair
/// that disagrees was never one unit: the merge fails as the duplicate
/// identity it is.
async fn verify_rlib_pairs_agree(pairs: &[RlibPair]) -> stow_types::error::Result<()> {
    let mut checks = futures_util::stream::iter(pairs)
        .map(verify_rlib_pair)
        .buffer_unordered(RLIB_PAIR_CONCURRENCY);
    while let Some(outcome) = checks.next().await {
        outcome?;
    }
    Ok(())
}

/// One pair: re-verify both files against their recorded digests, then
/// compare the archives member by member.
async fn verify_rlib_pair(pair: &RlibPair) -> stow_types::error::Result<()> {
    let (left, right) = futures_util::future::try_join(
        read_verified_output(&pair.left_path, &pair.left_sha256, &pair.crate_name),
        read_verified_output(&pair.right_path, &pair.right_sha256, &pair.crate_name),
    )
    .await?;
    crate::rlib_members::same_rustc_members(&left, &right).map_err(|disagreement| {
        stow_types::stow_error!(
            "dep_scan captured two different restorable artifacts for {} — rlib {} and rlib {} disagree: {} — a duplicate identity means a forged or colliding record",
            pair.crate_name,
            pair.left_path.display(),
            pair.right_path.display(),
            disagreement
        )
    })
}

/// Attribute every restorable record to a package and a kind, keyed for
/// selection. A restorable record the scan cannot plan is a missing output:
/// every unattributable path is fatal because anything less lets a lost or
/// tampered record shrink the plan.
///
/// Returns the selected artifacts, the count of restorable records that
/// merged into an earlier one as captures of the same unit in another
/// phase, and the rlib output pairs whose digests differed at those
/// merges — still owed to [`verify_rlib_pairs_agree`].
fn select_captured_artifacts(
    package_index: &PackageIndex,
    captured_artifacts: &[CapturedRustcArtifact],
) -> stow_types::error::Result<SelectedCaptures> {
    let mut selected = BTreeMap::<
        (
            String,
            String,
            String,
            String,
            Option<stow_types::public_cache::UnitInvocation>,
        ),
        SelectedCapturedArtifact,
    >::new();
    let mut absorbed_duplicates = 0usize;
    let mut rlib_pairs = Vec::new();
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
            captured.invocation,
        );
        let candidate = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind,
            captured: captured.clone(),
            dependency_aliases: Vec::new(),
        };
        match select_captured_artifact(&mut selected, key, candidate)? {
            Selection::Selected => {}
            Selection::Merged(pairs) => {
                absorbed_duplicates += 1;
                rlib_pairs.extend(pairs);
            }
        }
    }
    Ok(SelectedCaptures {
        artifacts: selected.into_values().collect(),
        absorbed_duplicates,
        rlib_pairs,
    })
}

/// The output of [`select_captured_artifacts`]: the artifacts the upload
/// plan may carry, how many restorable records merged into an earlier
/// one as captures of the same unit in another phase, and the rlib
/// pairs those merges left pending.
#[derive(Debug)]
struct SelectedCaptures {
    artifacts: Vec<SelectedCapturedArtifact>,
    absorbed_duplicates: usize,
    /// rlib output pairs whose recorded digests differed between two
    /// captures merged as one unit — a build script's native objects
    /// record where and when their compiler ran, so the digest cannot
    /// rule (stow#719); [`verify_rlib_pairs_agree`] compares what rustc
    /// itself wrote into the archives.
    rlib_pairs: Vec<RlibPair>,
}

/// One pair of rlib outputs — one file per capture — whose recorded
/// digests differed between two records merged as the same unit.
/// [`verify_rlib_pairs_agree`] settles the pair on what rustc itself
/// wrote into the archives.
#[derive(Debug)]
struct RlibPair {
    /// The crate both records claim, for errors.
    crate_name: String,
    /// The earlier record's file to read — the snapshot when the
    /// wrapper froze one, else the live output.
    left_path: PathBuf,
    /// The sha256 the earlier record recorded for that file.
    left_sha256: String,
    /// The merged record's file to read, by the same snapshot rule.
    right_path: PathBuf,
    /// The sha256 the merged record recorded for it.
    right_sha256: String,
}

/// What [`select_captured_artifact`] decided for one candidate.
#[derive(Debug)]
enum Selection {
    /// No record held the key — the candidate was selected as-is.
    Selected,
    /// The candidate is another capture of the unit already selected
    /// under the key; the carried rlib pairs' digests differed and the
    /// member-level check still has to prove them the same unit's.
    Merged(Vec<RlibPair>),
}

/// Insert `candidate` under `key`, or absorb it into the record already
/// there when the two are provably captures of the same rustc unit —
/// where "provably" reaches only as far as the records carry it: an rlib
/// whose digests differ defers to the member-level check the returned
/// [`Selection::Merged`] still owes.
fn select_captured_artifact(
    selected: &mut BTreeMap<
        (
            String,
            String,
            String,
            String,
            Option<stow_types::public_cache::UnitInvocation>,
        ),
        SelectedCapturedArtifact,
    >,
    key: (
        String,
        String,
        String,
        String,
        Option<stow_types::public_cache::UnitInvocation>,
    ),
    candidate: SelectedCapturedArtifact,
) -> stow_types::error::Result<Selection> {
    let Some(existing) = selected.get_mut(&key) else {
        selected.insert(key, candidate);
        return Ok(Selection::Selected);
    };
    // Two restorable records under one selection key are a duplicate: the
    // key already carries every identity dimension (crate, stable
    // metadata, kind, emit, invocation), so a second record claiming it
    // is either the same rustc unit seen twice — a unit that links in
    // every cargo phase, like a build dependency or a proc macro, is
    // captured once per phase into that phase's own `CARGO_TARGET_DIR`,
    // and a split unit graph captures the host and requested-target
    // halves into sibling `deps` dirs — or a forged replay.
    // `same_captured_unit` is the proof of "same unit";
    // anything else is a collision and aborts the scan, with both
    // records in the error so the field that tells them apart is on
    // the page.
    let Some(rlib_pairs) = same_captured_unit(&existing.captured, &candidate.captured) else {
        return Err(stow_types::stow_error!(
            "dep_scan captured two different restorable artifacts for {} {} (c_metadata {}) emit {:?} — a duplicate identity means a forged or colliding record:\n{}\n{}",
            candidate.captured.crate_name,
            candidate
                .captured
                .crate_version
                .as_deref()
                .unwrap_or("<unknown>"),
            candidate.captured.c_metadata,
            candidate.captured.emit,
            serde_json::to_string(&existing.captured)?,
            serde_json::to_string(&candidate.captured)?
        ));
    };
    // The first capture survives: both records carry the same stable
    // identity a client resolves the crate by, and outputs that are the
    // same modulo directory — modulo, for rlib pairs the check still
    // owes, the native members a build script's compile wrote
    // per-phase. The dropped half's output paths stay resolvable as
    // aliases, so a dependent whose `--extern` names the other phase's
    // `deps` dir still finds its owner.
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
    Ok(Selection::Merged(rlib_pairs))
}

/// Whether two records are captures of the same rustc unit — the same
/// compilation driven into a different output directory — rather than two
/// different units colliding on one selection key.
///
/// A legitimate repeat is told from a forgery by what the record itself
/// carries: `out_dir`, `target_dir`, `build_script_out_dir`, the output
/// and dependency paths, the snapshots and the alias's file name are
/// entitled to differ — they are where the unit happened to be written
/// this time, and under what invocation-specific hash cargo asked for
/// the output. Everything that identifies the unit — the full compile
/// key, target, profile, crate types, version, extra filename and
/// dependency identities — must be equal, and the outputs must be the
/// same files modulo the directory they were written to and, for the
/// alias, modulo the name cargo asked for. Anything else is a collision.
///
/// All of that is record-level; the one thing a record cannot vouch for
/// is an rlib's bytes. The archive bundles the build script's native
/// objects, and those record where and when their own compiler ran
/// (stow#719), so the same unit honestly produces different rlib
/// digests per phase — a digest mismatch defers rather than rules. What
/// proves the unit is the archives' agreement on what rustc itself
/// wrote, so the function hands back the pairs whose digests differed
/// for [`verify_rlib_pairs_agree`] to settle, while
/// `verify_output_digests` still re-hashes the surviving record's
/// outputs before anything is planned.
fn same_captured_unit(
    left: &CapturedRustcArtifact,
    right: &CapturedRustcArtifact,
) -> Option<Vec<RlibPair>> {
    let same_unit = left.crate_version == right.crate_version
        && left.crate_types == right.crate_types
        && left.target == right.target
        && left.compile_key == right.compile_key
        && left.extra_filename == right.extra_filename
        && left.profile == right.profile
        && same_dependency_identities(&left.dependencies, &right.dependencies);
    if !same_unit {
        return None;
    }
    captured_outputs_match(left, right)
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
/// directories: the same kind per output, and the same file name for the
/// stable-named outputs — the alias cargo originally asked for is
/// compared by kind and digest alone, since its name is cargo's
/// per-invocation unit hash rather than the unit's (stow#692). An rmeta's
/// recorded digest must match outright — metadata carries nothing
/// path-dependent — while a dynamic library is exempt entirely, because
/// the linker writes the path it was produced at into the file (the
/// Mach-O install name, and on MSVC the sibling .pdb path in the PE
/// debug directory), so the same module legitimately hashes differently
/// per output directory. An rlib sits between those poles: the archive
/// bundles the build script's native objects, and those record where
/// and when their own compiler ran (stow#719), so a differing rlib
/// digest is deferred, not ruled on — the pair is returned for the
/// member-level check to settle. Snapshot paths are excluded — they are
/// per-capture temp names.
///
/// Returns `None` when the records are different units by what they
/// carry, else one [`RlibPair`] per rlib output pair whose recorded
/// digests differ — empty when every digest matched.
fn captured_outputs_match(
    left: &CapturedRustcArtifact,
    right: &CapturedRustcArtifact,
) -> Option<Vec<RlibPair>> {
    fn by_kind_and_stable_name(record: &CapturedRustcArtifact) -> Vec<&CapturedRustcOutput> {
        let mut outputs = record.outputs.iter().collect::<Vec<_>>();
        outputs.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then(stable_output_name(record, a).cmp(&stable_output_name(record, b)))
        });
        outputs
    }
    let left_outputs = by_kind_and_stable_name(left);
    let right_outputs = by_kind_and_stable_name(right);
    if left_outputs.len() != right_outputs.len() {
        return None;
    }
    let mut rlib_pairs = Vec::new();
    for (output, peer) in left_outputs.iter().zip(&right_outputs) {
        if output.kind != peer.kind
            || stable_output_name(left, output) != stable_output_name(right, peer)
        {
            return None;
        }
        match output.kind {
            // The linker wrote the output path into the file; digest
            // equality is not the rule.
            CapturedRustcOutputKind::DynamicLibrary => {}
            // The digest can only differ through the native members a
            // build script archived — the member-level check decides.
            CapturedRustcOutputKind::Rlib if output.sha256 != peer.sha256 => {
                rlib_pairs.push(RlibPair {
                    crate_name: left.crate_name.clone(),
                    left_path: output
                        .snapshot_path
                        .clone()
                        .unwrap_or_else(|| output.path.clone()),
                    left_sha256: output.sha256.clone(),
                    right_path: peer
                        .snapshot_path
                        .clone()
                        .unwrap_or_else(|| peer.path.clone()),
                    right_sha256: peer.sha256.clone(),
                });
            }
            _ if output.sha256 != peer.sha256 => return None,
            _ => {}
        }
    }
    Some(rlib_pairs)
}

/// An output's file name when it is the unit's own stable name, `None`
/// for the alias cargo originally asked for. The alias's name identifies
/// nothing: it carries cargo's unit hash for this invocation, which
/// covers the profiles of the unit's whole dependency chain as that
/// invocation resolved them and so differs between two phases compiling
/// one and the same unit (stow#692).
fn stable_output_name<'a>(
    record: &CapturedRustcArtifact,
    output: &'a CapturedRustcOutput,
) -> Option<&'a OsStr> {
    if !record.extra_filename.is_empty()
        && output
            .path
            .file_stem()
            .is_some_and(|stem| stem.to_string_lossy().ends_with(&record.extra_filename))
    {
        output.path.file_name()
    } else {
        None
    }
}

/// One phase×invocation's view of the task's own unit: the crates.io
/// lib units of that phase's graph (for dep-owner attribution) and the
/// own unit's lib-dep keys — the unit the wrapper's own-crate edge
/// names on the task's side (stow#723).
#[derive(Debug)]
pub struct PhaseOwnUnit {
    pub units: Vec<stow_types::unit_graph::TaskUnit>,
    pub own_deps: BTreeSet<stow_types::unit_graph::TaskUnitKey>,
}

/// The `target_dir` → [`PhaseOwnUnit`] map for every phase×invocation.
///
/// The own unit is the one the generated wrapper's own-crate dep edge
/// names on the task's side. That edge leaves the wrapper unit
/// `wrapper_manifest` declares the task crate on: a target task is a
/// `[dependencies]` entry, so the edge leaves the wrapper's lib unit;
/// a host task is a `[build-dependencies]` entry, so the edge leaves
/// the wrapper's build-script *compile* unit — cargo never gives the
/// wrapper lib unit a build-dependency edge, in any phase or spelling.
/// Any other unit of the same package — the outcome-3 target twin the
/// wrapper also pins, on the lib unit's edges — is a dependency like
/// any other: served, never compiled (stow#723).
pub fn phase_own_units(
    task: &BuildTaskPayload,
    graphs: &[crate::task::PhaseUnitGraph],
    run_dir: &Path,
) -> stow_types::error::Result<BTreeMap<PathBuf, PhaseOwnUnit>> {
    use stow_types::unit_graph::{TaskUnitKind, TaskUnitSide};
    let host_triple = crate::task::runner_host_triple(task)?;
    let (own_side, declaring_kind) = if task.host_side {
        (TaskUnitSide::Host, TaskUnitKind::BuildScript)
    } else {
        (TaskUnitSide::Target, TaskUnitKind::Lib)
    };
    let mut phases = BTreeMap::new();
    for graph in graphs {
        let units = graph.task_units(host_triple).map_err(|error| {
            stow_types::stow_error!("{} unit graph does not convert: {error}", graph.label())
        })?;
        // The wrapper is the graph's only non-registry package, and it
        // has one unit of each kind.
        let mut declaring = units
            .iter()
            .filter(|unit| unit.key.kind == declaring_kind && !unit.is_crates_io);
        let wrapper = declaring.next().ok_or_else(|| {
            stow_types::stow_error!(
                "{} unit graph has no wrapper {declaring_kind:?} unit",
                graph.label()
            )
        })?;
        if let Some(other) = declaring.next() {
            return Err(stow_types::stow_error!(
                "{} unit graph has two non-registry {declaring_kind:?} units, {} and {}",
                graph.label(),
                wrapper.key.pkg,
                other.key.pkg,
            ));
        }
        let own = wrapper
            .deps
            .iter()
            .find(|dep| {
                dep.key.kind == TaskUnitKind::Lib
                    && dep.key.side == own_side
                    && dep.name == task.crate_name.as_str()
                    && dep.version == task.version.as_semver().to_string()
            })
            .and_then(|dep| units.iter().find(|unit| unit.key == dep.key))
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "{} unit graph's wrapper names no {}-side unit of the task crate {} {}",
                    graph.label(),
                    if task.host_side { "host" } else { "target" },
                    task.crate_name.as_str(),
                    task.version.as_semver(),
                )
            })?;
        let own_deps = own
            .deps
            .iter()
            .filter(|dep| dep.key.kind == TaskUnitKind::Lib)
            .map(|dep| dep.key.clone())
            .collect();
        phases.insert(graph.target_dir(run_dir), PhaseOwnUnit { units, own_deps });
    }
    Ok(phases)
}

/// Whether `artifact` is a capture of the task's own unit — the lib
/// unit the wrapper root's own-crate edge names in the phase×invocation
/// graph `artifact.target_dir` ran under. The answer is decided by
/// dependency sets: the own unit's externs resolve to its graph dep
/// units, and a same-package twin's resolve to different ones — a
/// compiled outcome-3 twin names a dep its host sibling never links
/// (stow#723).
///
/// A dep owner is attributed to a graph unit by package and version,
/// narrowed by the record's feature scan when two units of one package
/// share the graph — the only shape a kept-apart twin pair takes. An
/// owner that matches several units counts as matching whichever is in
/// the own unit's deps, so a shared dep's two identical twin units
/// never convict the own unit.
fn own_unit_record(
    task: &BuildTaskPayload,
    artifact: &SelectedCapturedArtifact,
    selected: &[SelectedCapturedArtifact],
    consumed: &[ConsumedCapture],
    output_owners: &BTreeMap<PathBuf, OutputOwner>,
    own_units: &BTreeMap<PathBuf, PhaseOwnUnit>,
) -> stow_types::error::Result<bool> {
    use stow_types::unit_graph::{TaskUnitKey, TaskUnitKind};
    let Some(phase) = own_units.get(&artifact.captured.target_dir) else {
        return Err(stow_types::stow_error!(
            "dep_scan capture of {} {} recorded target dir {}, which is no phase of this build",
            artifact.package.name,
            artifact.package.version,
            artifact.captured.target_dir.display(),
        ));
    };
    let mut possible = BTreeSet::<&TaskUnitKey>::new();
    for dependency in &artifact.captured.dependencies {
        let Some(owner) = output_owners.get(&dependency.path) else {
            return Ok(false);
        };
        let (name, version, features) = match owner {
            OutputOwner::Compiled(index) => {
                let dep = selected.get(*index).ok_or_else(|| {
                    stow_types::stow_error!("dep_scan owner index {index} is out of bounds")
                })?;
                (
                    dep.package.name.as_str(),
                    dep.package.version.to_string(),
                    &dep.captured.features,
                )
            }
            OutputOwner::Consumed(index) => {
                let capture = consumed.get(*index).ok_or_else(|| {
                    stow_types::stow_error!("dep_scan consumed index {index} is out of bounds")
                })?;
                let record = capture.records.first().ok_or_else(|| {
                    stow_types::stow_error!(
                        "dep_scan consumed capture {} carries no records",
                        capture.artifact.crate_name,
                    )
                })?;
                (
                    capture.artifact.crate_name.as_str(),
                    capture.artifact.crate_version.clone(),
                    &record.features,
                )
            }
        };
        // The task's package is never a dep of its own unit — a record
        // claiming one is not the own unit.
        if name == task.crate_name.as_str() && version == task.version.as_semver().to_string() {
            return Ok(false);
        }
        let mut candidates = phase
            .units
            .iter()
            .filter(|unit| {
                unit.key.kind == TaskUnitKind::Lib
                    && unit.is_crates_io
                    && unit.name == name
                    && unit.version == version
            })
            .map(|unit| &unit.key)
            .collect::<Vec<_>>();
        if candidates.len() > 1 {
            // Two units of one package in one graph are a kept-apart
            // twin pair; their feature sets differ.
            let matching: Vec<&TaskUnitKey> = phase
                .units
                .iter()
                .filter(|unit| {
                    candidates.contains(&&unit.key)
                        && unit.features.iter().cloned().collect::<BTreeSet<String>>() == *features
                })
                .map(|unit| &unit.key)
                .collect();
            if !matching.is_empty() {
                candidates = matching;
            }
        }
        if candidates.is_empty() || !candidates.iter().any(|key| phase.own_deps.contains(*key)) {
            return Ok(false);
        }
        possible.extend(candidates);
    }
    Ok(phase.own_deps.iter().all(|key| possible.contains(&key)))
}

/// The build's half of the graph contract: this task compiles its own
/// unit and is *served* every other node. A restorable record attributed
/// to any other package means cargo compiled a unit the consume store was
/// supposed to provide — the serve missed it, or the build order broke —
/// and registering its bytes would publish an artifact this task never
/// owned. Fail and name every such unit; none of it is salvage.
///
/// The task's own identity is a *unit*, not a package (stow#723): an
/// outcome-3 host task's unit graph carries the same package twice —
/// its own host unit and the target-side twin the self-twin edge pins,
/// which it is served like every other dependency. A record of the
/// task's package is the own unit only when its dependency owners are
/// the own unit's lib deps of the phase×invocation it compiled under
/// — the twin's dep set differs, so a compiled twin fails here instead
/// of registering under the task's rows.
///
/// Only restorable records reach this check — the selected set — so the
/// generated wrapper package, build-script compiles and binaries are out
/// by construction rather than filtered by name: they are never restorable
/// to begin with.
fn reject_foreign_compiled_units(
    task: &BuildTaskPayload,
    selected: &[SelectedCapturedArtifact],
    consumed: &[ConsumedCapture],
    output_owners: &BTreeMap<PathBuf, OutputOwner>,
    own_units: &BTreeMap<PathBuf, PhaseOwnUnit>,
) -> stow_types::error::Result<()> {
    let mut units = Vec::new();
    for artifact in selected {
        let package = &artifact.package;
        if package.name == task.crate_name.as_str()
            && package.version == *task.version.as_semver()
            && own_unit_record(task, artifact, selected, consumed, output_owners, own_units)?
        {
            continue;
        }
        let features = artifact
            .captured
            .features
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let target = artifact.captured.target.as_deref().unwrap_or("host");
        // A stable compile key is the identity the unit would have been
        // served under; `compile_key == c_metadata` marks the ephemeral
        // key a record carries when no stable identity exists.
        let served = if artifact.captured.compile_key == artifact.captured.c_metadata {
            String::new()
        } else {
            format!(
                " — would have been served under compile key {}",
                artifact.captured.compile_key
            )
        };
        units.push(format!(
            "{} {} features=[{features}] target={target}{served}",
            package.name, package.version,
        ));
    }
    if units.is_empty() {
        return Ok(());
    }
    Err(stow_types::stow_error!(
        "build compiled {} unit(s) that are not the task's own crate {} {} — a build compiles one crate and is served the rest:\n  {}",
        units.len(),
        task.crate_name.as_str(),
        task.version.as_semver(),
        units.join("\n  "),
    ))
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
    host_target: &str,
    cx: &mut ResolveCx<'_>,
    artifact_index: usize,
) -> stow_types::error::Result<ScannedArtifact> {
    let artifact = cx.selected.get(artifact_index).ok_or_else(|| {
        stow_types::stow_error!("selected artifact index {artifact_index} is out of bounds")
    })?;
    // `cargo` spells `--target` only for the task's own target: a unit
    // carrying a different one came from an invocation this build never
    // made, and registering it would write the catalog row under a
    // target that never compiled it.
    if let Some(target) = &artifact.captured.target
        && *target != task.target.as_str()
    {
        return Err(stow_types::stow_error!(
            "captured unit {} {} compiled for target {target} but the task targets {}",
            artifact.captured.crate_name,
            artifact
                .captured
                .crate_version
                .as_deref()
                .unwrap_or("<unknown>"),
            task.target
        ));
    }
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
        // The compile key already embeds the target the unit ran for,
        // so the row registers where the key points: a unit `cargo`
        // spelled no `--target` for ran for the runner's host — a host
        // unit, whatever the task's own target says.
        target: artifact
            .captured
            .target
            .clone()
            .unwrap_or_else(|| host_target.to_owned()),
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
        // The shape the edge's gate checks: the task's own side, the
        // invocation spelling the collector stamped on the capture, and
        // the emit set's link membership.
        unit_shape: stow_types::public_cache::UnitShape {
            // Every registered unit is the task's own crate's library
            // product — the own-node check bounds the registered set to
            // the crate the task owns, and `restorable` keeps
            // build-script compiles out — so the unit's side is the
            // node's side. `--target` presence cannot name it: under a
            // native invocation no unit carries one.
            side: if task.host_side {
                stow_types::public_cache::UnitSide::Host
            } else {
                stow_types::public_cache::UnitSide::Target
            },
            invocation: artifact.captured.invocation.ok_or_else(|| {
                stow_types::stow_error!(
                    "capture for {} {} carries no invocation stamp — the collector never saw it drain",
                    artifact.captured.crate_name,
                    artifact.captured.compile_key
                )
            })?,
            kind: stow_types::public_cache::UnitKind::from_emit(&artifact.captured.emit),
        },
        build_script_out_dir: artifact.captured.build_script_out_dir.clone(),
        native: None,
    })
}

/// The state resolution threads through [`resolve_artifact`] and
/// [`resolve_dependencies`]: the record sets they walk, the output-owner
/// index, the unit-graph feature sets labelling each row, and the memo
/// maps accumulating across it.
struct ResolveCx<'a> {
    /// The dispatched task — a selected artifact's side is always its.
    task: &'a BuildTaskPayload,
    /// Selected compiled artifacts, by index.
    selected: &'a [SelectedCapturedArtifact],
    /// Consumed-capture groups, by index.
    consumed: &'a [ConsumedCapture],
    /// Output path → the record that produced it.
    output_owners: &'a BTreeMap<PathBuf, OutputOwner>,
    /// Phase `CARGO_TARGET_DIR` → that phase×invocation's resolved lib-unit
    /// feature sets.
    phase_units: &'a BTreeMap<PathBuf, PhaseFeatureSets>,
    /// Resolved artifacts by selected index — the walk's memo.
    resolved: &'a mut BTreeMap<usize, ResolvedArtifact>,
    /// Selected indices on the current path — cycle detection.
    visiting: &'a mut BTreeSet<usize>,
}

/// One phase×invocation unit graph's resolved feature sets: every
/// crates.io lib unit's `(package, version, side)` → the feature set
/// cargo activated for it — the same set the task's dispatch and a
/// consumer's unit graph compute (stow#611).
struct PhaseFeatureSets {
    /// The phase and invocation spelling, for errors.
    label: String,
    lib_features: BTreeMap<(String, String, bool), BTreeSet<String>>,
}

/// Every phase×invocation's lib-unit feature sets, keyed by the phase's
/// `CARGO_TARGET_DIR` — the value a capture records as `target_dir`,
/// which is the only fact that says which graph a record compiled under.
fn phase_feature_sets(
    task: &BuildTaskPayload,
    built: &BuiltWorkspace,
) -> stow_types::error::Result<BTreeMap<PathBuf, PhaseFeatureSets>> {
    let host_triple = crate::task::runner_host_triple(task)?;
    let mut phases = BTreeMap::new();
    for graph in built.unit_graphs() {
        let units = graph.task_units(host_triple).map_err(|error| {
            stow_types::stow_error!("{} unit graph does not convert: {error}", graph.label())
        })?;
        let mut lib_features = BTreeMap::new();
        for unit in &units {
            if unit.key.kind != TaskUnitKind::Lib || !unit.is_crates_io {
                continue;
            }
            let key = (
                unit.name.clone(),
                unit.version.clone(),
                unit.key.side == TaskUnitSide::Host,
            );
            let features = unit.features.iter().cloned().collect::<BTreeSet<_>>();
            if let Some(existing) = lib_features.get(&key)
                && *existing != features
            {
                return Err(stow_types::stow_error!(
                    "{} unit graph holds two feature sets for the {} lib unit of {} {}",
                    graph.label(),
                    if unit.key.side == TaskUnitSide::Host {
                        "host"
                    } else {
                        "target"
                    },
                    unit.name,
                    unit.version,
                ));
            }
            lib_features.insert(key, features);
        }
        phases.insert(
            graph.target_dir(built.run_dir()),
            PhaseFeatureSets {
                label: graph.label(),
                lib_features,
            },
        );
    }
    Ok(phases)
}

/// The feature set the artifact's row is labelled with: the feature set
/// cargo's resolver computed for the package's lib unit in the unit graph
/// of the phase and invocation the capture belongs to — the directory the
/// record ran under names both (stow#611).
///
/// The capture's own `features` are *not* this set: they are the
/// `--cfg feature="…"` scan of the rustc argv, which also carries
/// whatever `cargo:rustc-cfg=feature="…"` lines the crate's build script
/// printed — cargo passes them to rustc exactly like resolved features
/// (`target-lexicon`'s `rust_1_40`, `winapi`'s implied set). Those cfgs
/// stay the invocation's truth for the compile key; the semantic label
/// is the resolver's answer alone.
///
/// No match is a hard error: the row has no honest label without the
/// unit that produced it, and falling back to the captured scan is the
/// mislabel this exists to remove.
fn unit_features_json(
    cx: &ResolveCx<'_>,
    artifact: &SelectedCapturedArtifact,
) -> stow_types::error::Result<String> {
    let Some(phase) = cx.phase_units.get(&artifact.captured.target_dir) else {
        return Err(stow_types::stow_error!(
            "dep_scan capture of {} {} recorded target dir {}, which is no phase of this build",
            artifact.package.name,
            artifact.package.version,
            artifact.captured.target_dir.display(),
        ));
    };
    let key = (
        artifact.package.name.clone(),
        artifact.package.version.to_string(),
        cx.task.host_side,
    );
    let Some(features) = phase.lib_features.get(&key) else {
        return Err(stow_types::stow_error!(
            "the {} unit graph holds no {}-side lib unit for {} {} — cannot label its row",
            phase.label,
            if cx.task.host_side { "host" } else { "target" },
            artifact.package.name,
            artifact.package.version,
        ));
    };
    stow_types::unit_graph::serialize_feature_set(features)
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
    let features_json = unit_features_json(cx, artifact)?;
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

/// stow#736: a target-side task at the runner's host triple handed
/// `KeysAsNative` must never carry a proc-macro in its own unit's
/// `--extern` set — one `--extern` to a proc-macro is exactly what makes
/// the explicit `--target <host>` spelling key differently, and
/// publishing the native-only shapes would serve the node at a key its
/// `--target` consumers never compute. The flag is resolved upstream, so
/// its presence here means the flag and the compiled graph disagree —
/// fail naming the dep rather than publish an incomplete node.
/// Transitive flagging is the resolver's; this guard covers the direct
/// edge the task's own capture records.
fn reject_unflagged_proc_macro_extern(
    task: &BuildTaskPayload,
    selected: &[SelectedCapturedArtifact],
    consumed: &[ConsumedCapture],
    output_owners: &BTreeMap<PathBuf, OutputOwner>,
) -> stow_types::error::Result<()> {
    let applies = !task.host_side
        && task.explicit_spelling == stow_types::public_cache::ExplicitSpelling::KeysAsNative
        && stow_types::api::runner_family(task.target.as_str())
            .is_some_and(|family| family.host_triple() == task.target.as_str());
    if !applies {
        return Ok(());
    }
    let is_proc_macro = |owner: OutputOwner| -> bool {
        match owner {
            OutputOwner::Compiled(index) => selected
                .get(index)
                .is_some_and(|artifact| artifact.artifact_kind == ArtifactKind::ProcMacro),
            OutputOwner::Consumed(index) => consumed
                .get(index)
                .and_then(|capture| capture.records.first())
                .is_some_and(|record| {
                    artifact_kind_for_capture(record) == Some(ArtifactKind::ProcMacro)
                }),
        }
    };
    for artifact in selected {
        for dependency in &artifact.captured.dependencies {
            let owner = output_owners.get(&dependency.path).copied();
            if owner.is_some_and(is_proc_macro) {
                return Err(stow_types::stow_error!(
                    "task {} ({} {} for {}) was dispatched KeysAsNative but its unit's --extern \
                     {} at {} is a proc-macro — the node's explicit-spelling flag is wrong \
                     (stow#736)",
                    task.task_id,
                    task.crate_name,
                    task.version,
                    task.target,
                    dependency.crate_name,
                    dependency.path.display(),
                ));
            }
        }
    }
    Ok(())
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

async fn cargo_metadata(workspace: &BuildWorkspace) -> stow_types::error::Result<Metadata> {
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
    // Task feature flags never reach the cargo command line: the wrapper
    // package's dependency declaration already encoded the selection, and
    // the generated package declares no features for them to resolve.
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
    let mut index = PackageIndex::new();
    for package in metadata
        .packages
        .iter()
        .filter_map(|package| indexed_package(package, task))
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

/// The task feature set `indexed_package` evaluates `required-features`
/// against.
fn task_feature_set(task: &BuildTaskPayload) -> BTreeSet<String> {
    task.features_json.features().iter().cloned().collect()
}

fn indexed_package(package: &Package, task: &BuildTaskPayload) -> Option<IndexedPackage> {
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

    Some(IndexedPackage {
        name: package.name.clone().into_inner(),
        version: package.version.clone(),
        lib_target_name: target.name.clone(),
        crate_types,
        registry: package
            .source
            .as_ref()
            .is_some_and(|source| source.to_string().starts_with("registry+")),
    })
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
    /// The unit shape the builder knows by construction — the task's own
    /// side, the invocation spelling the collector stamped, and the emit
    /// set's link membership.
    pub unit_shape: stow_types::public_cache::UnitShape,
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
    use stow_types::public_cache::UnitInvocation;
    use stow_types::unit_graph::{TaskUnitKind, TaskUnitSide};

    use super::{
        ConsumedCapture, IndexedPackage, ResolvedArtifact, RlibPair, SelectedCapturedArtifact,
        Selection, output_owner_index, reject_unflagged_proc_macro_extern, resolve_artifact,
        select_captured_artifact, select_captured_artifacts,
    };
    use stow_types::capture::{
        CapturedDependencyIdentity, CapturedRustcArtifact, CapturedRustcOutput,
        CapturedRustcOutputKind,
    };

    #[test]
    fn same_unit_rlib_captures_from_different_phase_dirs_merge() {
        // The legitimate same-key case: one build-dependency unit captured
        // once per cargo phase, into each phase's own target dir. The
        // output set is identical modulo directory — this fixture's
        // rmeta carries nothing path-dependent, so its digest matches —
        // and the second record merges its dependency aliases plus the
        // paths of the outputs it drops instead of colliding.
        let key = (
            "aho_corasick".to_owned(),
            "ef4a079a8dc04c32".to_owned(),
            ArtifactKind::Rlib.as_str().to_owned(),
            "[\"dep-info\",\"link\"]".to_owned(),
            Some(UnitInvocation::Target),
        );
        let mut selected = BTreeMap::new();
        let package = IndexedPackage {
            name: "aho_corasick".to_owned(),
            version: semver::Version::parse("1.1.4").expect("version"),
            lib_target_name: "aho_corasick".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
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
            Some(UnitInvocation::Target),
        );
        let mut selected = BTreeMap::new();
        let package = IndexedPackage {
            name: "equator_macro".to_owned(),
            version: semver::Version::parse("0.4.2").expect("version"),
            lib_target_name: "equator_macro".to_owned(),
            crate_types: vec![RustCrateType::ProcMacro],
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
            features: BTreeSet::new(),
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
            invocation: Some(stow_types::public_cache::UnitInvocation::Target),
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
            Some(UnitInvocation::Target),
        );
        let mut selected = BTreeMap::new();
        let package = IndexedPackage {
            name: "aho_corasick".to_owned(),
            version: semver::Version::parse("1.1.4").expect("version"),
            lib_target_name: "aho_corasick".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
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
        // Both records travel in the error: which field tells them apart
        // is the whole diagnosis (stow#692).
        let surviving_digest = &selected.values().next().expect("first").captured.outputs[0].sha256;
        assert!(error.to_string().contains(surviving_digest), "{error}");
        assert!(error.to_string().contains(&"ff".repeat(32)), "{error}");
    }

    /// An rlib digest difference under one selection key is not a
    /// verdict of its own: an rlib archiving a build script's native
    /// objects honestly differs between phases, because those objects
    /// record where and when their own compiler ran (stow#719). A
    /// build-dependency unit captured by `cargo check` and `cargo build`
    /// under the `--target` spelling — same invocation, same stable
    /// `c_metadata`, same `["dep-info","link","metadata"]` emit — merges
    /// with the differing pair pending the member-level check instead of
    /// failing at the record level.
    #[test]
    fn differing_rlib_bytes_under_one_key_defer_to_the_member_check() {
        let key = (
            "unicode_ident".to_owned(),
            "788c0f768456711f".to_owned(),
            ArtifactKind::Rlib.as_str().to_owned(),
            "[\"dep-info\",\"link\",\"metadata\"]".to_owned(),
            Some(UnitInvocation::Target),
        );
        let mut selected = BTreeMap::new();
        let package = IndexedPackage {
            name: "unicode_ident".to_owned(),
            version: semver::Version::parse("1.0.26").expect("version"),
            lib_target_name: "unicode_ident".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
            registry: true,
        };
        let mut check_capture = captured(
            "unicode_ident",
            "788c0f768456711f",
            "C:\\run\\target-check-target\\debug\\deps",
        );
        check_capture.target = Some("x86_64-pc-windows-msvc".to_owned());
        check_capture.emit = vec![
            "dep-info".to_owned(),
            "link".to_owned(),
            "metadata".to_owned(),
        ];
        check_capture.outputs.push(CapturedRustcOutput {
            kind: CapturedRustcOutputKind::Rlib,
            // A `/` before the file name — the shape `Path::join` gives
            // the sibling rmeta on this host — keeps the stable-name
            // pairing working where `\` is not a separator.
            path: PathBuf::from(
                "C:\\run\\target-check-target\\debug\\deps/libunicode_ident-788c0f768456711f.rlib",
            ),
            snapshot_path: None,
            sha256: "aa".repeat(32),
        });
        let mut build_capture = check_capture.clone();
        build_capture.out_dir = PathBuf::from("C:\\run\\target-build-target\\debug\\deps");
        build_capture.target_dir = PathBuf::from("C:\\run\\target-build-target");
        build_capture.outputs.iter_mut().for_each(|output| {
            output.path = PathBuf::from(
                output
                    .path
                    .to_string_lossy()
                    .replace("target-check-target", "target-build-target"),
            );
        });
        // The second phase's rlib hashes differently — its archived
        // native objects recorded that phase's own paths — while the
        // rmeta carries nothing path-dependent and keeps its digest.
        build_capture.outputs[1].sha256 = "bb".repeat(32);
        let first = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind: ArtifactKind::Rlib,
            captured: check_capture,
            dependency_aliases: Vec::new(),
        };
        let second = SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured: build_capture,
            dependency_aliases: Vec::new(),
        };

        select_captured_artifact(&mut selected, key.clone(), first).expect("select first");
        let outcome = select_captured_artifact(&mut selected, key, second)
            .expect("differing rlib digests defer to the member check");
        let Selection::Merged(pairs) = outcome else {
            panic!("the second capture merges: {outcome:?}");
        };
        assert_eq!(pairs.len(), 1, "exactly the differing rlib pair pends");
        let pair = &pairs[0];
        assert_eq!(pair.crate_name, "unicode_ident");
        assert_eq!(
            pair.left_path,
            PathBuf::from(
                "C:\\run\\target-check-target\\debug\\deps/libunicode_ident-788c0f768456711f.rlib"
            )
        );
        assert_eq!(pair.left_sha256, "aa".repeat(32));
        assert_eq!(
            pair.right_path,
            PathBuf::from(
                "C:\\run\\target-build-target\\debug\\deps/libunicode_ident-788c0f768456711f.rlib"
            )
        );
        assert_eq!(pair.right_sha256, "bb".repeat(32));
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
            Some(UnitInvocation::Target),
        );
        let mut selected = BTreeMap::new();
        let package = IndexedPackage {
            name: "aho_corasick".to_owned(),
            version: semver::Version::parse("1.1.4").expect("version"),
            lib_target_name: "aho_corasick".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
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

    /// stow#692: two captures of one host-side unit — the `psm 0.1.24`
    /// build dependency compiled by `cargo check` and `cargo build`
    /// under the native spelling — differ only in the name of the alias
    /// cargo originally asked for, which carries each invocation's own
    /// unit hash. The stable-named outputs pair by name, the aliases by
    /// kind and digest, and the records merge.
    #[test]
    fn captures_differing_only_in_the_alias_name_are_one_unit() {
        let key = psm_key();
        let mut selected = BTreeMap::new();
        let first = psm_selection(psm_capture(
            "/tmp/workspace/target-check-native",
            "8e5bdc87bc91e8f0",
        ));
        let second = psm_selection(psm_capture(
            "/tmp/workspace/target-build-native",
            "a40c71aa8d26bf90",
        ));

        select_captured_artifact(&mut selected, key.clone(), first).expect("select first");
        let merged = select_captured_artifact(&mut selected, key.clone(), second)
            .expect("captures differing only in the alias name are one unit");
        let Selection::Merged(pairs) = merged else {
            panic!("the second capture merges into the first");
        };
        assert!(pairs.is_empty(), "no rlib pair is left pending: {pairs:?}");

        let stored = selected.get(&key).expect("selected capture");
        assert!(
            stored.dependency_aliases.contains(&PathBuf::from(
                "/tmp/workspace/target-build-native/debug/deps/libpsm-a40c71aa8d26bf90.rlib"
            )),
            "the dropped half's alias paths stay resolvable"
        );
    }

    /// The alias is an rlib, so differing alias bytes are one more case
    /// the record level cannot rule on: the pair defers to the
    /// member-level check, where archives of different units collide on
    /// the rustc members they carry.
    #[test]
    fn an_alias_with_different_bytes_defers_to_the_member_check() {
        let key = psm_key();
        let mut selected = BTreeMap::new();
        let first = psm_selection(psm_capture(
            "/tmp/workspace/target-check-native",
            "8e5bdc87bc91e8f0",
        ));
        let mut build_capture =
            psm_capture("/tmp/workspace/target-build-native", "a40c71aa8d26bf90");
        build_capture.outputs[2].sha256 = "ff".repeat(32);
        let second = psm_selection(build_capture);

        select_captured_artifact(&mut selected, key.clone(), first).expect("select first");
        let outcome = select_captured_artifact(&mut selected, key, second)
            .expect("differing alias bytes defer to the member check");
        let Selection::Merged(pairs) = outcome else {
            panic!("the second capture merges: {outcome:?}");
        };
        assert_eq!(pairs.len(), 1, "exactly the differing alias pair pends");
        let pair = &pairs[0];
        assert_eq!(pair.crate_name, "psm");
        assert_eq!(
            pair.left_path,
            PathBuf::from(
                "/tmp/workspace/target-check-native/debug/deps/libpsm-8e5bdc87bc91e8f0.rlib"
            )
        );
        assert_eq!(pair.left_sha256, "aa".repeat(32));
        assert_eq!(
            pair.right_path,
            PathBuf::from(
                "/tmp/workspace/target-build-native/debug/deps/libpsm-a40c71aa8d26bf90.rlib"
            )
        );
        assert_eq!(pair.right_sha256, "ff".repeat(32));
    }

    /// Renaming a stable-named output does not turn it into an alias: a
    /// second record whose stable rlib carries a foreign hash falls out
    /// of the stable-name pairing and collides, because the stable name
    /// is the unit's identity.
    #[test]
    fn a_stable_output_under_another_name_is_still_a_collision() {
        let key = psm_key();
        let mut selected = BTreeMap::new();
        let first = psm_selection(psm_capture(
            "/tmp/workspace/target-check-native",
            "8e5bdc87bc91e8f0",
        ));
        let mut build_capture =
            psm_capture("/tmp/workspace/target-build-native", "a40c71aa8d26bf90");
        build_capture.outputs[0].path = PathBuf::from(
            "/tmp/workspace/target-build-native/debug/deps/libpsm-ffffffffffffffff.rlib",
        );
        let second = psm_selection(build_capture);

        select_captured_artifact(&mut selected, key.clone(), first).expect("select first");
        let error = select_captured_artifact(&mut selected, key, second)
            .expect_err("a stable output under another name must fail");
        assert!(error.to_string().contains("duplicate identity"), "{error}");
    }

    /// The selection key the `psm 0.1.24` host-side captures share.
    fn psm_key() -> (String, String, String, String, Option<UnitInvocation>) {
        (
            "psm".to_owned(),
            "cc065d16221ef4be".to_owned(),
            ArtifactKind::Rlib.as_str().to_owned(),
            "[\"dep-info\",\"link\"]".to_owned(),
            Some(UnitInvocation::Native),
        )
    }

    /// One `psm 0.1.24` capture as a selection candidate.
    fn psm_selection(captured: CapturedRustcArtifact) -> SelectedCapturedArtifact {
        SelectedCapturedArtifact {
            package: IndexedPackage {
                name: "psm".to_owned(),
                version: semver::Version::parse("0.1.24").expect("version"),
                lib_target_name: "psm".to_owned(),
                crate_types: vec![RustCrateType::Rlib],
                registry: true,
            },
            artifact_kind: ArtifactKind::Rlib,
            captured,
            dependency_aliases: Vec::new(),
        }
    }

    /// A capture of the `psm 0.1.24` host-side unit: the stable-named
    /// rlib and rmeta plus the same bytes under the alias cargo
    /// originally asked for, the alias named with this invocation's own
    /// unit hash (`alias_hash`) which differs between phases (stow#692).
    fn psm_capture(target_dir: &str, alias_hash: &str) -> CapturedRustcArtifact {
        let out_dir = format!("{target_dir}/debug/deps");
        let mut capture = captured("psm", "cc065d16221ef4be", &out_dir);
        capture.crate_version = Some("0.1.24".to_owned());
        capture.invocation = Some(UnitInvocation::Native);
        capture.target_dir = PathBuf::from(target_dir);
        let output =
            |kind: CapturedRustcOutputKind, name: String, sha256: &str| CapturedRustcOutput {
                kind,
                path: PathBuf::from(format!("{out_dir}/{name}")),
                snapshot_path: None,
                sha256: sha256.to_owned(),
            };
        capture.outputs = vec![
            output(
                CapturedRustcOutputKind::Rlib,
                "libpsm-cc065d16221ef4be.rlib".to_owned(),
                &"aa".repeat(32),
            ),
            output(
                CapturedRustcOutputKind::Rmeta,
                "libpsm-cc065d16221ef4be.rmeta".to_owned(),
                &"bb".repeat(32),
            ),
            output(
                CapturedRustcOutputKind::Rlib,
                format!("libpsm-{alias_hash}.rlib"),
                &"aa".repeat(32),
            ),
            output(
                CapturedRustcOutputKind::Rmeta,
                format!("libpsm-{alias_hash}.rmeta"),
                &"bb".repeat(32),
            ),
        ];
        capture
    }

    /// A host-side task runs every phase under both invocation spellings
    /// and each produces its own unit — same crate, same metadata, same
    /// emit, different compile key. Selection must keep both: collapsing
    /// them under one key aborted every host-side build as a duplicate
    /// identity (stow#431).
    #[test]
    fn native_and_target_spelling_of_one_unit_select_separately() {
        let mut index = super::PackageIndex::new();
        index
            .entry("aho_corasick".to_owned())
            .or_default()
            .insert("1.1.4".to_owned(), indexed("aho_corasick", "1.1.4"));

        let mut native = captured(
            "aho_corasick",
            "ef4a079a8dc04c32",
            "/tmp/workspace/target-native/debug/deps",
        );
        native.crate_version = Some("1.1.4".to_owned());
        native.compile_key = "aa".repeat(32);
        native.invocation = Some(stow_types::public_cache::UnitInvocation::Native);

        let mut explicit = captured(
            "aho_corasick",
            "ef4a079a8dc04c32",
            "/tmp/workspace/target-target/debug/deps",
        );
        explicit.crate_version = Some("1.1.4".to_owned());
        explicit.compile_key = "bb".repeat(32);
        explicit.invocation = Some(stow_types::public_cache::UnitInvocation::Target);

        let selected = select_captured_artifacts(&index, &[native, explicit])
            .expect("the two invocation spellings are two selected artifacts");
        assert_eq!(selected.artifacts.len(), 2);
        assert_eq!(selected.absorbed_duplicates, 0);
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

    /// A `link`-phase record attributed to `name`@`version` — the shape a
    /// compiled foreign unit arrives in.
    fn foreign_lib_unit(name: &str, version: &str, features: &[&str]) -> SelectedCapturedArtifact {
        let package = indexed(name, version);
        let mut captured = raw_lib_capture(
            name,
            "ef4a079a8dc04c32",
            Vec::new(),
            PathBuf::from(format!(
                "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/lib{}-ef4a.rlib",
                name.replace('-', "_")
            )),
        );
        captured.emit = vec!["dep-info".to_owned(), "link".to_owned()];
        captured.features = features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect();
        captured.compile_key = "ab".repeat(32);
        SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured,
            dependency_aliases: Vec::new(),
        }
    }

    /// The contract the scan enforces for the whole build: the task's own
    /// crate is the only thing it may compile — every other unit is served
    /// from the cache. A restorable record attributed to any other package
    /// is a defect the build fails on, and the error names the unit plus
    /// the identity it would have been served under.
    #[test]
    fn a_build_that_compiles_a_foreign_unit_fails_naming_it() {
        let task = consumer_task();
        let own = consumer_selection(
            &PathBuf::from(
                "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libitoa-raw.rmeta",
            ),
            "",
            "leaf-raw",
        );
        let foreign = foreign_lib_unit("itoa", "1.0.18", &["std"]);
        // The task's crate at any other version is another node's
        // identity — same rule.
        let wrong_version = foreign_lib_unit("serde_json", "9.9.9", &["std"]);
        // A host unit (a proc macro compiles for the build machine) whose
        // record carries an ephemeral key has no served identity to name.
        let mut foreign_proc_macro = foreign_lib_unit("serde_derive", "1.0.219", &[]);
        foreign_proc_macro.package.crate_types = vec![RustCrateType::ProcMacro];
        foreign_proc_macro.artifact_kind = ArtifactKind::ProcMacro;
        foreign_proc_macro.captured.crate_types = vec!["proc-macro".to_owned()];
        foreign_proc_macro.captured.target = None;
        foreign_proc_macro.captured.compile_key = foreign_proc_macro.captured.c_metadata.clone();

        let leaf_output = PathBuf::from(
            "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libitoa-raw.rmeta",
        );
        let consumed = vec![consumed_capture("itoa", "1.0.18", &[], &leaf_output)];
        let itoa = lib_unit("itoa", "1.0.18", TaskUnitSide::Target, &[]);
        let selected = vec![own, foreign, wrong_version, foreign_proc_macro];
        let (owners, own_units) = own_unit_context(
            &selected,
            &consumed,
            std::slice::from_ref(&itoa),
            std::slice::from_ref(&itoa),
        );
        let error =
            super::reject_foreign_compiled_units(&task, &selected, &consumed, &owners, &own_units)
                .expect_err("compiled foreign units fail the build");
        let message = error.to_string();
        assert!(message.contains("3 unit(s)"), "{message}");
        assert!(message.contains("itoa 1.0.18"), "{message}");
        assert!(message.contains("features=[std]"), "{message}");
        assert!(message.contains("target=aarch64-apple-darwin"), "{message}");
        assert!(
            message.contains(&format!("served under compile key {}", "ab".repeat(32))),
            "{message}"
        );
        assert!(message.contains("serde_json 9.9.9"), "{message}");
        assert!(message.contains("serde_derive 1.0.219"), "{message}");
        assert!(message.contains("target=host"), "{message}");
        assert_eq!(
            message.matches("served under compile key").count(),
            2,
            "a unit with no stable identity reports none: {message}"
        );
        assert!(
            !message.contains("serde_json 1.0.149 features"),
            "the task's own crate is not a defect: {message}"
        );
    }

    /// A build whose compiled units are all the task's own crate — its
    /// check-phase metadata unit and its build-phase link unit — is
    /// exactly the shape the cache exists for.
    #[test]
    fn a_build_that_compiles_only_its_own_crate_passes() {
        let task = consumer_task();
        let check_unit = consumer_selection(
            &PathBuf::from(
                "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libitoa-raw.rmeta",
            ),
            "",
            "leaf-raw",
        );
        let mut link_capture = check_unit.captured.clone();
        link_capture.c_metadata = "bd2c39b1e4a05d77".to_owned();
        link_capture.compile_key = "cd".repeat(32);
        link_capture.emit = vec!["dep-info".to_owned(), "link".to_owned()];
        link_capture.outputs = vec![CapturedRustcOutput {
            kind: CapturedRustcOutputKind::Rlib,
            path: PathBuf::from(
                "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libserde_json-bd2c.rlib",
            ),
            snapshot_path: None,
            sha256: "00".repeat(32),
        }];
        let link_unit = SelectedCapturedArtifact {
            package: check_unit.package.clone(),
            artifact_kind: ArtifactKind::Rlib,
            captured: link_capture,
            dependency_aliases: Vec::new(),
        };
        let leaf_output = PathBuf::from(
            "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libitoa-raw.rmeta",
        );
        let consumed = vec![consumed_capture("itoa", "1.0.18", &[], &leaf_output)];
        let itoa = lib_unit("itoa", "1.0.18", TaskUnitSide::Target, &[]);
        let selected = vec![check_unit, link_unit];
        let (owners, own_units) = own_unit_context(
            &selected,
            &consumed,
            std::slice::from_ref(&itoa),
            std::slice::from_ref(&itoa),
        );
        super::reject_foreign_compiled_units(&task, &selected, &consumed, &owners, &own_units)
            .expect("a build compiling only the task's own crate is legal");
        super::reject_foreign_compiled_units(&task, &[], &consumed, &owners, &own_units)
            .expect("an empty compiled set carries no foreign unit");
    }

    /// stow#723: the task's own identity is a unit, not a package — a
    /// host task's same-package target twin is a served dependency like
    /// any other. A compiled unit of the task's package whose dep set is
    /// the twin's fails as foreign; the own unit passes.
    #[test]
    fn a_compiled_same_package_twin_fails_as_foreign() {
        let mut task = consumer_task();
        task.host_side = true;
        let dep_path = PathBuf::from(
            "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libitoa-leaf.rmeta",
        );
        let twin_dep_path = PathBuf::from(
            "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libitoa-std.rmeta",
        );
        let make = |dep_path: &Path, output_name: &str| {
            let package = indexed("serde_json", "1.0.149");
            let mut captured = raw_lib_capture(
                "serde_json",
                "twin-raw",
                vec![CapturedDependencyIdentity {
                    crate_name: "itoa".to_owned(),
                    path: dep_path.to_owned(),
                    compile_key: "served".to_owned(),
                    stable_c_metadata: "served-meta".to_owned(),
                }],
                PathBuf::from(format!(
                    "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/{output_name}"
                )),
            );
            captured.features = ["default".to_owned(), "std".to_owned()]
                .into_iter()
                .collect();
            captured.target = None;
            SelectedCapturedArtifact {
                package,
                artifact_kind: ArtifactKind::Rlib,
                captured,
                dependency_aliases: Vec::new(),
            }
        };
        let mut twin = make(&twin_dep_path, "libserde_json-twin.rlib");
        twin.captured.c_metadata = "twin-meta".to_owned();
        twin.captured.compile_key = "ef".repeat(32);
        // The dep owners: two served `itoa` units, the own side's `[]`
        // leaf and the twin's `["std"]` one.
        let consumed = vec![
            consumed_capture("itoa", "1.0.18", &[], &dep_path),
            consumed_capture("itoa", "1.0.18", &["std"], &twin_dep_path),
        ];
        let itoa_host = lib_unit("itoa", "1.0.18", TaskUnitSide::Host, &[]);
        let itoa_target = lib_unit("itoa", "1.0.18", TaskUnitSide::Target, &["std"]);
        let (owners, own_units) = own_unit_context(
            &[make(&dep_path, "libserde_json-own.rlib"), twin],
            &consumed,
            &[itoa_host.clone(), itoa_target],
            &[itoa_host],
        );
        let error = super::reject_foreign_compiled_units(
            &task,
            &[
                make(&dep_path, "libserde_json-own.rlib"),
                make(&twin_dep_path, "libserde_json-twin.rlib"),
            ],
            &consumed,
            &owners,
            &own_units,
        )
        .expect_err("a compiled twin unit is foreign");
        assert!(error.to_string().contains("serde_json"), "{error}");
        super::reject_foreign_compiled_units(
            &task,
            &[make(&dep_path, "libserde_json-own.rlib")],
            &consumed,
            &owners,
            &own_units,
        )
        .expect("the own unit passes");
    }

    /// A lib `TaskUnit` for own-unit context fabrication.
    fn lib_unit(
        name: &str,
        version: &str,
        side: TaskUnitSide,
        features: &[&str],
    ) -> stow_types::unit_graph::TaskUnit {
        stow_types::unit_graph::TaskUnit {
            key: stow_types::unit_graph::TaskUnitKey {
                pkg: format!(
                    "registry+https://github.com/rust-lang/crates.io-index#{name}@{version}"
                ),
                platform: "aarch64-apple-darwin".to_owned(),
                side,
                kind: TaskUnitKind::Lib,
            },
            name: name.to_owned(),
            version: version.to_owned(),
            features: features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
            is_crates_io: true,
            deps: Vec::new(),
        }
    }

    /// A served dep's consumed capture: one record owning `path`.
    fn consumed_capture(
        name: &str,
        version: &str,
        features: &[&str],
        path: &Path,
    ) -> super::ConsumedCapture {
        let mut record = raw_lib_capture(name, "served-meta", Vec::new(), path.to_owned());
        record.features = features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect();
        record.consumed = true;
        super::ConsumedCapture {
            artifact: super::ConsumedArtifact {
                crate_name: name.to_owned(),
                crate_version: version.to_owned(),
                compile_key: "served".to_owned(),
                c_metadata: "served-meta".to_owned(),
                target: "aarch64-apple-darwin".to_owned(),
                rustc_version: "1.91.1".to_owned(),
                emit: vec!["dep-info".to_owned(), "link".to_owned()],
            },
            records: vec![record],
        }
    }

    /// The `(output_owners, own_units)` pair `reject_foreign_compiled_units`
    /// runs on, for records under `/tmp/workspace/target`: `units` is the
    /// phase graph's lib units, `own_deps` the own unit's dep units.
    fn own_unit_context(
        selected: &[SelectedCapturedArtifact],
        consumed: &[super::ConsumedCapture],
        units: &[stow_types::unit_graph::TaskUnit],
        own_deps: &[stow_types::unit_graph::TaskUnit],
    ) -> (
        BTreeMap<PathBuf, super::OutputOwner>,
        BTreeMap<PathBuf, super::PhaseOwnUnit>,
    ) {
        let owners = super::output_owner_index(selected, consumed).expect("output owner index");
        let own_units = BTreeMap::from([(
            PathBuf::from("/tmp/workspace/target"),
            super::PhaseOwnUnit {
                units: units.to_vec(),
                own_deps: own_deps.iter().map(|unit| unit.key.clone()).collect(),
            },
        )]);
        (owners, own_units)
    }

    fn indexed(name: &str, version: &str) -> super::IndexedPackage {
        super::IndexedPackage {
            name: name.to_owned(),
            version: semver::Version::parse(version).expect("version"),
            // As cargo reports it: verbatim, hyphens and all.
            lib_target_name: name.to_owned(),
            crate_types: vec![RustCrateType::Lib],
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
        let package = indexed("serde_json", "1.0.149");
        let mut captured = raw_lib_capture(
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
        );
        captured.features = ["default".to_owned(), "std".to_owned()]
            .into_iter()
            .collect();
        SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured,
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
            features: BTreeSet::new(),
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
            invocation: Some(stow_types::public_cache::UnitInvocation::Target),
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
            host_side: false,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            dependency_subgraph: stow_types::api::TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
        }
    }

    /// The label lookup's view of the phase graphs these tests run: one
    /// phase target dir holding `(package, version, host-side, resolved
    /// features)` lib units — the unit-graph answer the row label reads.
    fn phase_units(
        dir: &str,
        units: &[(&str, &str, bool, &[&str])],
    ) -> BTreeMap<PathBuf, super::PhaseFeatureSets> {
        let lib_features = units
            .iter()
            .map(|(name, version, host_side, features)| {
                (
                    ((*name).to_owned(), (*version).to_owned(), *host_side),
                    features
                        .iter()
                        .map(|feature| (*feature).to_owned())
                        .collect(),
                )
            })
            .collect();
        BTreeMap::from([(
            PathBuf::from(dir),
            super::PhaseFeatureSets {
                label: "check task-spelled".to_owned(),
                lib_features,
            },
        )])
    }

    fn resolve_consumer(
        selected: &[SelectedCapturedArtifact],
    ) -> stow_types::error::Result<ResolvedArtifact> {
        let task = consumer_task();
        let output_owners = output_owner_index(selected, &[]).expect("build output owner index");
        let phase_units = phase_units(
            "/tmp/workspace/target",
            &[
                ("itoa", "1.0.18", false, &[]),
                ("serde_json", "1.0.149", false, &["default", "std"]),
            ],
        );
        let mut resolved = BTreeMap::<usize, ResolvedArtifact>::new();
        let mut visiting = BTreeSet::<usize>::new();
        let mut cx = super::ResolveCx {
            task: &task,
            selected,
            consumed: &[],
            output_owners: &output_owners,
            phase_units: &phase_units,
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

    /// stow#611: the row's `features_json` is the feature set of the
    /// artifact's unit in the build's own cargo unit graph — the set
    /// cargo's resolver, stow-resolver and a consumer's unit graph all
    /// compute. For tokio on a non-Windows target the unit graph holds
    /// `{fs, net}` while `windows-sys` — the implicit feature of an
    /// optional dep only `cfg(windows)` compiles — stays out, because
    /// the graph is per target (stow#579).
    #[test]
    fn the_resolved_artifact_is_labelled_with_its_units_feature_set() {
        let task = consumer_task();
        let mut capture = captured("tokio", "1797fe20bc19a8bf", "/tmp/workspace/target/deps");
        capture.features = ["fs".to_owned(), "net".to_owned()].into_iter().collect();
        let selected = [SelectedCapturedArtifact {
            package: indexed("tokio", "1.53.2"),
            artifact_kind: ArtifactKind::Rlib,
            captured: capture,
            dependency_aliases: Vec::new(),
        }];
        let phase_units = phase_units(
            "/tmp/workspace/target",
            &[("tokio", "1.53.2", false, &["fs", "net"])],
        );
        let output_owners = output_owner_index(&selected, &[]).expect("owners");
        let mut resolved = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        let mut cx = super::ResolveCx {
            task: &task,
            selected: &selected,
            consumed: &[],
            output_owners: &output_owners,
            phase_units: &phase_units,
            resolved: &mut resolved,
            visiting: &mut visiting,
        };
        let artifact = resolve_artifact(&mut cx, 0).expect("resolve");
        assert_eq!(artifact.features_json, "[\"fs\",\"net\"]");
    }

    /// stow#611: a build script's `cargo:rustc-cfg=feature="…"` output
    /// reaches the invocation's `--cfg` set exactly like a resolved
    /// feature — `target-lexicon 0.13.5` compiles with
    /// `--cfg feature="rust_1_40"` — but the label is the unit's resolved
    /// set alone, `["default","std"]`, the only identity a consumer's
    /// unit graph computes.
    #[test]
    fn a_build_script_cfg_feature_never_reaches_the_label() {
        let task = consumer_task();
        let mut capture = captured(
            "target-lexicon",
            "1797fe20bc19a8bf",
            "/tmp/workspace/target/deps",
        );
        capture.features = [
            "default".to_owned(),
            "rust_1_40".to_owned(),
            "std".to_owned(),
        ]
        .into_iter()
        .collect();
        let selected = [SelectedCapturedArtifact {
            package: indexed("target-lexicon", "0.13.5"),
            artifact_kind: ArtifactKind::Rlib,
            captured: capture,
            dependency_aliases: Vec::new(),
        }];
        let phase_units = phase_units(
            "/tmp/workspace/target",
            &[("target-lexicon", "0.13.5", false, &["default", "std"])],
        );
        let output_owners = output_owner_index(&selected, &[]).expect("owners");
        let mut resolved = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        let mut cx = super::ResolveCx {
            task: &task,
            selected: &selected,
            consumed: &[],
            output_owners: &output_owners,
            phase_units: &phase_units,
            resolved: &mut resolved,
            visiting: &mut visiting,
        };
        let artifact = resolve_artifact(&mut cx, 0).expect("resolve");
        assert_eq!(artifact.features_json, "[\"default\",\"std\"]");
    }

    /// A selected artifact whose package has no lib unit on the task's
    /// side in its phase's graph cannot be labelled honestly — the
    /// capture claims a unit cargo never resolved, so the scan fails
    /// rather than fall back to the invocation's `--cfg` scan.
    #[test]
    fn an_artifact_with_no_matching_unit_is_an_error() {
        let task = consumer_task();
        let selected = [SelectedCapturedArtifact {
            package: indexed("unresolved", "4.2.0"),
            artifact_kind: ArtifactKind::Rlib,
            captured: captured(
                "unresolved",
                "1797fe20bc19a8bf",
                "/tmp/workspace/target/deps",
            ),
            dependency_aliases: Vec::new(),
        }];
        let phase_units = phase_units(
            "/tmp/workspace/target",
            &[("serde_json", "1.0.149", false, &["default", "std"])],
        );
        let output_owners = output_owner_index(&selected, &[]).expect("owners");
        let mut resolved = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        let mut cx = super::ResolveCx {
            task: &task,
            selected: &selected,
            consumed: &[],
            output_owners: &output_owners,
            phase_units: &phase_units,
            resolved: &mut resolved,
            visiting: &mut visiting,
        };
        let error = resolve_artifact(&mut cx, 0).expect_err("no unit, no label");
        let message = error.to_string();
        assert!(message.contains("unresolved 4.2.0"), "{message}");
        assert!(message.contains("target-side"), "{message}");
        assert!(message.contains("check task-spelled"), "{message}");
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
            features: BTreeSet::new(),
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
            invocation: Some(stow_types::public_cache::UnitInvocation::Target),
            compile_millis: 0,
        }
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
                registry: true,
            },
            artifact_kind: ArtifactKind::Rlib,
            captured: CapturedRustcArtifact {
                crate_name: "itoa".to_owned(),
                crate_version: Some("1.0.18".to_owned()),
                crate_types: vec!["lib".to_owned()],
                emit: vec!["dep-info".to_owned(), "link".to_owned()],
                features: BTreeSet::new(),
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
                invocation: Some(stow_types::public_cache::UnitInvocation::Target),
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

    /// An [`RlibPair`] over real files: each side's recorded sha256 is
    /// the digest of its bytes, as the wrapper recorded it.
    fn rlib_pair(
        crate_name: &str,
        left: &Path,
        left_bytes: &[u8],
        right: &Path,
        right_bytes: &[u8],
    ) -> RlibPair {
        RlibPair {
            crate_name: crate_name.to_owned(),
            left_path: left.to_path_buf(),
            left_sha256: hex::encode(sha2::Sha256::digest(left_bytes)),
            right_path: right.to_path_buf(),
            right_sha256: hex::encode(sha2::Sha256::digest(right_bytes)),
        }
    }

    /// stow#719: two captures of one unit's rlib whose archives differ
    /// only in the native member a build script bundled — different
    /// bytes and a different name, as a second phase's `OUT_DIR`
    /// produces — verify as the same unit.
    #[test]
    fn rlib_pairs_differing_only_in_native_members_verify() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let left = tempdir.path().join("libpsm-check.rlib");
            let right = tempdir.path().join("libpsm-build.rlib");
            let left_bytes = crate::object_arch::gnu_archive(&[
                ("lib.rmeta", b"metadata"),
                ("psm-cc065d16221ef4be.psm.0.rcgu.o", b"codegen object"),
                ("/tmp/one/out/psm.o", b"native object one"),
            ]);
            let right_bytes = crate::object_arch::gnu_archive(&[
                ("lib.rmeta", b"metadata"),
                ("psm-cc065d16221ef4be.psm.0.rcgu.o", b"codegen object"),
                ("/tmp/two/out/psm.o", b"native object two"),
            ]);
            std::fs::write(&left, &left_bytes).expect("write left rlib");
            std::fs::write(&right, &right_bytes).expect("write right rlib");

            super::verify_rlib_pairs_agree(&[rlib_pair(
                "psm",
                &left,
                &left_bytes,
                &right,
                &right_bytes,
            )])
            .await
            .expect("archives differing only in a native member agree");
        });
    }

    /// A pair whose `.rcgu.o` member differs is not one unit: the error
    /// names the crate and the rustc member that disagreed.
    #[test]
    fn rlib_pairs_with_different_rustc_members_fail() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let left = tempdir.path().join("libpsm-check.rlib");
            let right = tempdir.path().join("libpsm-build.rlib");
            let left_bytes = crate::object_arch::gnu_archive(&[
                ("lib.rmeta", b"metadata"),
                ("psm-cc065d16221ef4be.psm.0.rcgu.o", b"codegen left"),
            ]);
            let right_bytes = crate::object_arch::gnu_archive(&[
                ("lib.rmeta", b"metadata"),
                ("psm-cc065d16221ef4be.psm.0.rcgu.o", b"codegen right"),
            ]);
            std::fs::write(&left, &left_bytes).expect("write left rlib");
            std::fs::write(&right, &right_bytes).expect("write right rlib");

            let error = super::verify_rlib_pairs_agree(&[rlib_pair(
                "psm",
                &left,
                &left_bytes,
                &right,
                &right_bytes,
            )])
            .await
            .expect_err("a differing codegen member is a different unit");
            let message = error.to_string();
            assert!(message.contains("psm"), "names the crate: {message}");
            assert!(
                message.contains("psm-cc065d16221ef4be.psm.0.rcgu.o"),
                "names the member: {message}"
            );
        });
    }

    /// A pair member whose bytes no longer match its recorded digest
    /// fails the way `verify_output_digests` does — something rewrote
    /// the file after rustc exited.
    #[test]
    fn an_rlib_pair_member_changed_after_capture_fails() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let left = tempdir.path().join("libpsm-check.rlib");
            let right = tempdir.path().join("libpsm-build.rlib");
            let left_bytes = crate::object_arch::gnu_archive(&[("lib.rmeta", b"metadata")]);
            let right_bytes = crate::object_arch::gnu_archive(&[("lib.rmeta", b"metadata")]);
            std::fs::write(&left, &left_bytes).expect("write left rlib");
            std::fs::write(&right, b"rewritten after capture").expect("write right rlib");

            let error = super::verify_rlib_pairs_agree(&[rlib_pair(
                "psm",
                &left,
                &left_bytes,
                &right,
                &right_bytes,
            )])
            .await
            .expect_err("a file past its recorded digest must fail");
            assert!(
                error.to_string().contains("changed after rustc exited"),
                "{error}"
            );
        });
    }

    /// stow#589: the consumable set is the build workspace's own cargo
    /// unit graph — a build-script dep lands host-side and a transitive
    /// dep of a pinned crate lands target-side, each at the feature set
    /// cargo activated — while the task crate itself never becomes
    /// consumable. The fixture is the graph `cargo --unit-graph` emits
    /// for a native spelling of a target-side task whose manifest pins
    /// `direct-dep` and build-dep `host-dep`.
    #[test]
    fn consumable_packages_follow_the_builds_unit_graph() {
        // `path+` units' manifests are hashed at parse — the wrapper's
        // pkg id must name a real manifest, and a spaced directory
        // exercises the file-URL percent-encoding `path_pkg_root`
        // decodes.
        let tempdir = tempfile::tempdir().expect("tempdir");
        let project = tempdir.path().join("wrapper workspace");
        std::fs::create_dir(&project).expect("wrapper dir");
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"stow-ci-wrapper\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .expect("write wrapper manifest");
        let wrapper_url = url::Url::from_directory_path(&project).expect("dir url");
        let wrapper_pkg = format!("path+{wrapper_url}#stow-ci-wrapper@0.0.0");
        let mut graph_json: serde_json::Value =
            serde_json::from_str(UNIT_GRAPH_JSON).expect("fixture parses");
        for index in [0usize, 1] {
            graph_json["units"][index]["pkg_id"] = serde_json::Value::String(wrapper_pkg.clone());
        }
        let graph_json = serde_json::to_vec(&graph_json).expect("serialize fixture");
        let graph = stow_cli::expanded_dependency_graph(
            &graph_json,
            None,
            "x86_64-unknown-linux-gnu",
            &stow_types::identity::WireRustcVersion::parse("1.99.0").unwrap(),
        )
        .expect("unit graph parses");

        let task = BuildTaskPayload {
            task_id: "task-crate-1.2.3".to_owned(),
            attempt: 1,
            crate_name: stow_types::identity::CrateName::parse("task-crate").unwrap(),
            version: stow_types::identity::CrateVersion::new(semver::Version::new(1, 2, 3)),
            features_json: stow_types::identity::FeaturesJson::default(),
            target: stow_types::identity::TargetTriple::parse("aarch64-apple-darwin").unwrap(),
            rustc_version: stow_types::identity::WireRustcVersion::parse("1.99.0").unwrap(),
            preserve_lockfile: false,
            host_side: false,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            dependency_subgraph: stow_types::api::TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
        };
        let packages = super::consumable_packages(&task, &graph.entries);
        let found = packages
            .iter()
            .map(|package| {
                (
                    package.crate_name.as_str(),
                    package.version.to_string(),
                    package.features.iter().cloned().collect::<Vec<_>>(),
                    package.host_side,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            found,
            BTreeSet::from([
                (
                    "direct-dep",
                    "2.0.0".to_owned(),
                    vec!["compress".to_owned()],
                    false
                ),
                ("host-dep", "3.1.0".to_owned(), vec![], true),
                ("transitive-dep", "0.4.0".to_owned(), vec![], false),
                // stow#723: only the task's own *node* — name, version,
                // side and feature set — is never consumable. The
                // task's package at another feature set is a different
                // node and is served like any other.
                (
                    "task-crate",
                    "1.2.3".to_owned(),
                    vec!["std".to_owned()],
                    false
                ),
            ]),
            "the whole closure — build-script deps host-side, transitives target-side — is consumable at activated features"
        );
    }

    /// The `cargo --unit-graph` shape a native-spelling phase emits for a
    /// target-side task: the generated wrapper's lib unit (root) spells
    /// the task crate as a normal dep and hangs `[build-dependencies]`
    /// under its own custom-build unit. `@WRAPPER@` fills in the path pkg
    /// id, which must name a real manifest.
    const UNIT_GRAPH_JSON: &str = r#"{
        "version": 1,
        "units": [
            {
                "pkg_id": "@WRAPPER@",
                "target": {"kind": ["lib"]},
                "platform": "aarch64-apple-darwin",
                "mode": "build",
                "profile": {"opt_level": "0", "debuginfo": 2, "debug_assertions": true, "overflow_checks": true, "panic": "unwind", "strip": {"resolved": "None"}},
                "features": [],
                "dependencies": [
                    {"index": 1, "extern_crate_name": "stow_ci_wrapper"},
                    {"index": 2, "extern_crate_name": "task_crate"}
                ]
            },
            {
                "pkg_id": "@WRAPPER@",
                "target": {"kind": ["custom-build"]},
                "platform": "aarch64-apple-darwin",
                "mode": "build",
                "profile": {"opt_level": "0", "debuginfo": 0, "debug_assertions": true, "overflow_checks": true, "panic": "unwind", "strip": {"resolved": "None"}},
                "features": [],
                "dependencies": [
                    {"index": 4, "extern_crate_name": "host_dep"}
                ]
            },
            {
                "pkg_id": "registry+https://github.com/rust-lang/crates.io-index#task-crate@1.2.3",
                "target": {"kind": ["lib"]},
                "platform": "aarch64-apple-darwin",
                "mode": "build",
                "profile": {"opt_level": "0", "debuginfo": 2, "debug_assertions": true, "overflow_checks": true, "panic": "unwind", "strip": {"resolved": "None"}},
                "features": ["std"],
                "dependencies": [
                    {"index": 3, "extern_crate_name": "direct_dep"}
                ]
            },
            {
                "pkg_id": "registry+https://github.com/rust-lang/crates.io-index#direct-dep@2.0.0",
                "target": {"kind": ["lib"]},
                "platform": "aarch64-apple-darwin",
                "mode": "build",
                "profile": {"opt_level": "0", "debuginfo": 2, "debug_assertions": true, "overflow_checks": true, "panic": "unwind", "strip": {"resolved": "None"}},
                "features": ["compress"],
                "dependencies": [
                    {"index": 5, "extern_crate_name": "transitive_dep"}
                ]
            },
            {
                "pkg_id": "registry+https://github.com/rust-lang/crates.io-index#host-dep@3.1.0",
                "target": {"kind": ["lib"]},
                "platform": "aarch64-apple-darwin",
                "mode": "build",
                "profile": {"opt_level": "0", "debuginfo": 0, "debug_assertions": true, "overflow_checks": true, "panic": "unwind", "strip": {"resolved": "None"}},
                "features": [],
                "dependencies": []
            },
            {
                "pkg_id": "registry+https://github.com/rust-lang/crates.io-index#transitive-dep@0.4.0",
                "target": {"kind": ["lib"]},
                "platform": "aarch64-apple-darwin",
                "mode": "build",
                "profile": {"opt_level": "0", "debuginfo": 2, "debug_assertions": true, "overflow_checks": true, "panic": "unwind", "strip": {"resolved": "None"}},
                "features": [],
                "dependencies": []
            }
        ],
        "roots": [0]
    }"#;
    /// stow#736: a `KeysAsNative` contract is wrong when the task's own
    /// unit's `--extern` set holds a proc-macro — the flag the
    /// resolution handed down and the compiled graph disagree, and
    /// publishing the native-only shapes would leave `--target`
    /// consumers missing. The scan fails naming the dep before a byte
    /// is planned.
    #[test]
    fn an_unflagged_task_with_a_proc_macro_extern_is_rejected() {
        use stow_types::identity::{
            CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
        };
        let task = BuildTaskPayload {
            task_id: "task".to_owned(),
            attempt: 1,
            crate_name: CrateName::parse("demo").expect("name"),
            version: CrateVersion::new(semver::Version::new(1, 0, 0)),
            features_json: FeaturesJson::default(),
            target: TargetTriple::parse("x86_64-unknown-linux-gnu").expect("target"),
            rustc_version: WireRustcVersion::parse("1.91.1").expect("rustc"),
            preserve_lockfile: false,
            host_side: false,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            dependency_subgraph: stow_types::api::TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
        };
        // The proc-macro dep was served, not compiled: a consumed record
        // whose dylib output is the path the own unit's `--extern` names.
        let extern_path =
            PathBuf::from("/tmp/store/x86_64-unknown-linux-gnu/key/libderive-aa.dylib");
        let mut served = captured("derive", "aabbccddeeff0011", "/tmp/served/deps");
        served.crate_types = vec!["proc-macro".to_owned()];
        served.outputs = vec![CapturedRustcOutput {
            kind: CapturedRustcOutputKind::DynamicLibrary,
            path: extern_path.clone(),
            snapshot_path: None,
            sha256: "ab".repeat(32),
        }];
        let consumed = vec![ConsumedCapture {
            artifact: super::ConsumedArtifact {
                crate_name: "derive".to_owned(),
                crate_version: "1.0.0".to_owned(),
                compile_key: "f".repeat(64),
                c_metadata: "aabbccddeeff0011".to_owned(),
                target: "x86_64-unknown-linux-gnu".to_owned(),
                rustc_version: "1.91.1".to_owned(),
                emit: vec!["link".to_owned()],
            },
            records: vec![served],
        }];
        let mut own = captured(
            "demo",
            "1122334455667788",
            "/tmp/workspace/target/debug/deps",
        );
        own.dependencies = vec![CapturedDependencyIdentity {
            crate_name: "derive".to_owned(),
            path: extern_path,
            compile_key: "f".repeat(64),
            stable_c_metadata: "aabbccddeeff0011".to_owned(),
        }];
        let selected = vec![SelectedCapturedArtifact {
            package: indexed("demo", "1.0.0"),
            artifact_kind: ArtifactKind::Rlib,
            captured: own,
            dependency_aliases: Vec::new(),
        }];
        let owners = output_owner_index(&selected, &consumed).expect("owners");

        let error = reject_unflagged_proc_macro_extern(&task, &selected, &consumed, &owners)
            .expect_err("a proc-macro extern under KeysAsNative must fail");
        let message = error.to_string();
        assert!(
            message.contains("derive"),
            "names the proc-macro: {message}"
        );
        assert!(message.contains("736"), "names the issue: {message}");

        // The same capture under the flag the resolver should have
        // minted — or off the host triple — is legitimate.
        let mut flagged = task.clone();
        flagged.explicit_spelling = stow_types::public_cache::ExplicitSpelling::KeysApart;
        reject_unflagged_proc_macro_extern(&flagged, &selected, &consumed, &owners)
            .expect("a flagged task publishes both spellings");
        let mut cross = task;
        cross.target = TargetTriple::parse("aarch64-unknown-linux-gnu").expect("target");
        reject_unflagged_proc_macro_extern(&cross, &selected, &consumed, &owners)
            .expect("a cross target's one spelling is already explicit");
    }
}
