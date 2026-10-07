//! The build job's cache consumption (stow#299): fetch, verify and stage
//! the already-published artifacts this task's dependency closure needs,
//! so each sandboxed rustc unit can be served the same verified bundle a
//! user's CLI would inject instead of compiling the crate's whole
//! dependency closure from source.
//!
//! Everything on this side of the sandbox is ordinary host code — the
//! untrusted job already fetches the crate and its registry sources here.
//! The chain is the CLI's own: pull the signed index slice, digest-check
//! each bundle against the row's `bundle_digest`, cosign-verify it against
//! the pinned `build-crate.yml` identity, then stage it under a read-only
//! grant for the capture wrapper to inject. A bundle that fails any step
//! is skipped — the unit compiles — and a failed slice disables
//! consumption for the run: the same trust level as before this existed,
//! because nothing unverified is ever injected.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};

use stow_cli::build_consume::{self, ConsumeConfig, IndexSlice};
use stow_types::api::BuildTaskPayload;
use stow_types::index::ArtifactIndexRow;
use stow_types::public_cache::canonical_crate_name;

use crate::capture;
use crate::dep_scan;

/// What [`prefetch`] staged for the capture wrapper to serve: the read-only
/// store the sandbox grant covers and how many verified bundles it holds.
pub struct Consumption {
    /// Compile-key-addressed bundle store, ready to grant the phases.
    pub store_dir: PathBuf,
    /// Verified bundles staged under `store_dir`.
    pub artifacts: usize,
}

/// The signed index slices a task's dependency closure can legitimately
/// hit: the task target's, plus the host's when they differ — proc-macro
/// and build-dependency units key for the host triple, so their rows live
/// in the host slice, not the task target's. Both are signature-verified
/// inside [`build_consume::ensure_slice`] before a row is ever used.
pub async fn slices_for_task(
    config: &ConsumeConfig,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<Vec<IndexSlice>> {
    let task_slice =
        build_consume::ensure_slice(config, task.target.as_str(), task.rustc_version.as_str())
            .await?;
    let host_target = capture::detect_rustc_toolchain(&OsString::from("rustc"))
        .await?
        .host_target;
    if host_target == task.target.as_str() {
        return Ok(vec![task_slice]);
    }
    let host_slice =
        build_consume::ensure_slice(config, &host_target, task.rustc_version.as_str()).await?;
    Ok(vec![task_slice, host_slice])
}

/// Fetch and stage the published artifacts this task's dependencies can be
/// served from: every signed-index row matching a unit of the build
/// workspace's own cargo unit graph — name, version, activated feature
/// set and side — which the caller computed from the same cargo
/// invocations the build phases run (stow#586).
///
/// Rows whose dep-identity does not match this build's resolution are not
/// excluded here — the wrapper's compile-key lookup is what decides a hit;
/// prefetching a row it never matches only wastes a download.
///
/// # Errors
///
/// Returns an error when the config or the index slices cannot be
/// obtained — the caller treats that as "consumption disabled"
/// and builds exactly as before. A bundle that could not be *fetched* is
/// logged and skipped the same way: it removes one candidate, never the
/// task. A bundle that arrived and failed verification is neither, and
/// propagates — see [`build_consume::StageFailure`].
pub async fn prefetch(
    task: &BuildTaskPayload,
    packages: Vec<dep_scan::ConsumablePackage>,
    store_dir: &Path,
) -> Result<Consumption, build_consume::StageFailure> {
    let unavailable = build_consume::StageFailure::Unavailable;

    // Everything past here is the CLI's verified-download chain, and that
    // chain's HTTP client resolves DNS through a Tokio reactor. The build
    // stage runs on smol, where calling it panics outright. The network
    // phase therefore gets a Tokio runtime of its own on a blocking
    // thread, rather than the whole build stage being moved onto Tokio to
    // suit one step of it.
    let task = task.clone();
    let store_dir = store_dir.to_path_buf();
    on_a_tokio_runtime(move || async move { stage_candidates(&task, &packages, &store_dir).await })
        .await
        .map_err(unavailable)?
}

/// Run `work` on a Tokio runtime of its own, on a blocking thread.
///
/// The build stage's executor is smol, and the verified-download chain's
/// HTTP client resolves DNS through a Tokio reactor — without one it does
/// not return an error, it panics. One step needing Tokio is not a reason
/// to move the whole build stage onto it, so the step brings its own.
///
/// # Errors
///
/// Returns an error when the runtime cannot be built.
async fn on_a_tokio_runtime<Work, Fut, T>(work: Work) -> stow_types::error::Result<T>
where
    Work: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = T>,
    T: Send + 'static,
{
    smol::unblock(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| stow_types::stow_error!("build tokio runtime: {error}"))?;
        Ok(runtime.block_on(work()))
    })
    .await
}

/// The network half of [`prefetch`], on a Tokio runtime.
///
/// # Errors
///
/// [`build_consume::StageFailure::Unavailable`] when consumption could not
/// be set up at all, [`build_consume::StageFailure::Unverifiable`] when a
/// bundle the signed index vouches for did not verify.
async fn stage_candidates(
    task: &BuildTaskPayload,
    packages: &[dep_scan::ConsumablePackage],
    store_dir: &Path,
) -> Result<Consumption, build_consume::StageFailure> {
    // Setting consumption up is the part that may simply not be possible:
    // no config, no published slice yet. All of it reports as unavailable,
    // and the build runs exactly as it did before consumption existed.
    let unavailable = build_consume::StageFailure::Unavailable;
    let config = ConsumeConfig::load().map_err(unavailable)?;
    let slices = slices_for_task(&config, task).await.map_err(unavailable)?;
    let candidates = candidates(&slices, packages);

    // The prefetch pulls bundle blobs straight from GHCR by digest — the
    // offline-edge build never touches the byte path (stow#455). One
    // anonymous session mints one bearer for the whole batch.
    let registry =
        stow_oci::RegistryBase::parse(config.registry_base_url()).map_err(unavailable)?;
    let session = registry.session();

    let mut staged = 0usize;
    let mut seen_compile_keys = BTreeSet::new();
    for (slice, row) in candidates {
        if !seen_compile_keys.insert(row.compile_key.clone()) {
            continue;
        }
        match fetch_and_stage(&config, &session, slice, row, store_dir).await {
            Ok(()) => staged += 1,
            Err(build_consume::StageFailure::Unavailable(error)) => {
                tracing::warn!(
                    crate_name = %row.crate_name.as_str(),
                    version = %row.version,
                    compile_key = %row.compile_key,
                    %error,
                    "skipping cache-consumption bundle; the unit compiles instead"
                );
            }
            // The signed index vouched for this artifact and its bytes do
            // not back that up. Compiling past it would turn a broken or
            // tampered publication into a slow build and nothing else,
            // on the one machine whose output every user installs.
            Err(build_consume::StageFailure::Unverifiable(error)) => {
                return Err(build_consume::StageFailure::Unverifiable(
                    stow_types::stow_error!(
                        "the signed index vouches for `{}` {} (compile key {}) but its bundle did not verify: {error}",
                        row.crate_name.as_str(),
                        row.version,
                        row.compile_key
                    ),
                ));
            }
        }
    }

    tracing::info!(
        task_id = %task.task_id,
        staged,
        candidates = seen_compile_keys.len(),
        "cache-consumption prefetch staged verified bundles"
    );
    Ok(Consumption {
        store_dir: store_dir.to_path_buf(),
        artifacts: staged,
    })
}

/// The `(slice, row)` pairs a build may serve: rows matching a unit of
/// the build's own unit graph by canonical name, exact version,
/// activated feature set, and unit-graph side.
fn candidates<'a>(
    slices: &'a [IndexSlice],
    packages: &[dep_scan::ConsumablePackage],
) -> Vec<(&'a IndexSlice, &'a ArtifactIndexRow)> {
    let packages_by_name: BTreeMap<String, Vec<&dep_scan::ConsumablePackage>> = {
        let mut map: BTreeMap<String, Vec<&dep_scan::ConsumablePackage>> = BTreeMap::new();
        for package in packages {
            map.entry(canonical_crate_name(&package.crate_name))
                .or_default()
                .push(package);
        }
        map
    };
    let mut selected = Vec::new();
    for slice in slices {
        for row in &slice.index.rows {
            let crate_name = canonical_crate_name(row.crate_name.as_str());
            let Some(candidates) = packages_by_name.get(&crate_name) else {
                continue;
            };
            let features = row
                .features_json
                .features()
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let matches_package = candidates.iter().any(|package| {
                package.version.to_string() == row.version.to_string()
                    && package.features == features
                    && package_matches_side(package, row)
            });
            if !matches_package {
                continue;
            }
            selected.push((slice, row));
        }
    }
    selected
}

/// Whether the row's unit shape sits on the side the unit-graph entry
/// needs — a host entry is served only by a host-side row (the
/// proc-macro/build-dep shape), never by the same package's target-side
/// row. Rows published before `unit_shape` was recorded carry `None` and
/// stay eligible on either side: the compile-key lookup still decides
/// the hit, and a wrong-shape fetch only wastes a download.
fn package_matches_side(package: &dep_scan::ConsumablePackage, row: &ArtifactIndexRow) -> bool {
    row.unit_shape.as_ref().is_none_or(|shape| {
        (shape.side == stow_types::public_cache::UnitSide::Host) == package.host_side
    })
}

/// One row through the CLI's own verified-download chain: the bundle blob
/// pulled from GHCR by digest — not the edge byte path, which a fully
/// offline build cannot reach (stow#455) — hashed against `bundle_digest`,
/// manifest/config identity byte-compared against the signature-covered
/// `oci/config.json`, cosign signature verified against the pinned
/// `build-crate.yml` identity — then staged under the row's compile key
/// inside the slice's own target namespace for the read-only sandbox grant.
///
/// The namespace is the served-is-vouched invariant: the serve path looks
/// a compile key up only inside `store_dir/<the unit's effective target>`,
/// which is also the slice target the publish stage's vouch check
/// requires the row in. A catalog row whose compile key embeds a target
/// its slice's `target` column does not carry (registered before records
/// stored the honest target) sits in a directory no unit can be served
/// from — the unit compiles instead of serving a hit the index will not
/// vouch for.
async fn fetch_and_stage(
    config: &ConsumeConfig,
    session: &stow_oci::RegistrySession,
    slice: &IndexSlice,
    row: &ArtifactIndexRow,
    store_dir: &Path,
) -> Result<(), build_consume::StageFailure> {
    let entry_dir = store_dir
        .join(slice.index.header.target.as_str())
        .join(&row.compile_key);
    let bytes = session
        .pull_blob(&row.bundle_digest)
        .await
        .map_err(|error| {
            build_consume::StageFailure::Unavailable(stow_types::stow_error!(
                "pull bundle {} for `{}` {}: {error}",
                row.bundle_digest,
                row.crate_name.as_str(),
                row.version
            ))
        })?;
    stow_types::registry::verify_oci_digest(&bytes, &row.bundle_digest).map_err(|error| {
        build_consume::StageFailure::Unverifiable(stow_types::stow_error!(
            "bundle for `{}` {} did not hash to the index's bundle_digest: {error}",
            row.crate_name.as_str(),
            row.version
        ))
    })?;
    build_consume::stage_bundle_bytes(config, slice, row, &entry_dir, bytes).await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
        WireRustcVersion,
    };
    use stow_types::index::{ArtifactIndex, ArtifactIndexHeader, ArtifactIndexRow};
    use stow_types::platform::{PanicStrategy, Profile, StripLevel};
    use stow_types::public_cache::{UnitInvocation, UnitKind, UnitShape, UnitSide};

    use crate::dep_scan;

    /// The chain this module reuses resolves DNS through a Tokio reactor
    /// and panics — "there is no reactor running" — without one, while the
    /// build stage runs on smol. Whatever else changes, the network phase
    /// has to reach the wire from inside a Tokio runtime.
    #[test]
    fn the_network_phase_runs_inside_a_tokio_runtime() {
        let has_reactor = smol::block_on(async {
            assert!(
                tokio::runtime::Handle::try_current().is_err(),
                "the build stage's own executor must not already be Tokio, or this proves nothing"
            );
            super::on_a_tokio_runtime(|| async { tokio::runtime::Handle::try_current().is_ok() })
                .await
                .expect("runtime")
        });
        assert!(has_reactor, "the network phase ran without a Tokio reactor");
    }

    /// stow#586: a row is consumable only at the unit-graph identity —
    /// canonical name, exact version, the activated feature set AND the
    /// side. A host-side entry matches a host-shaped row and never the
    /// same package's target shape; a row published before `unit_shape`
    /// was recorded carries `None` and stays eligible on either side;
    /// and a row still labelled with cargo metadata's platform-agnostic
    /// resolve features (a feature this target never compiles, stow#579)
    /// does not match the graph's activated set.
    #[test]
    fn candidates_match_the_unit_graphs_side_and_features() {
        let packages = vec![
            dep_scan::ConsumablePackage {
                crate_name: "windows-link".to_owned(),
                version: semver::Version::new(0, 2, 1),
                features: BTreeSet::new(),
                host_side: true,
            },
            dep_scan::ConsumablePackage {
                crate_name: "tokio".to_owned(),
                version: semver::Version::new(1, 53, 2),
                features: BTreeSet::from(["fs".to_owned(), "net".to_owned()]),
                host_side: false,
            },
        ];

        let mut host_row = index_row("windows-link", "0.2.1", "aaaaaaaaaaaaaaaa", &[], None);
        host_row.unit_shape = Some(shape(UnitSide::Host));
        let mut target_row = index_row("windows-link", "0.2.1", "bbbbbbbbbbbbbbbb", &[], None);
        target_row.unit_shape = Some(shape(UnitSide::Target));
        let slice = stow_cli::build_consume::IndexSlice {
            manifest_digest: "sha256:".to_owned() + &"cd".repeat(32),
            index: ArtifactIndex {
                header: ArtifactIndexHeader {
                    format_version: stow_types::index::ARTIFACT_INDEX_FORMAT_VERSION,
                    target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
                    rustc_version: WireRustcVersion::parse("1.99.0").unwrap(),
                    generated_at: String::new(),
                    generation: 1,
                    row_count: 5,
                },
                rows: vec![
                    host_row,
                    target_row,
                    index_row("windows-link", "0.2.1", "cccccccccccccccc", &[], None),
                    index_row("tokio", "1.53.2", "dddddddddddddddd", &["fs", "net"], None),
                    index_row(
                        "tokio",
                        "1.53.2",
                        "eeeeeeeeeeeeeeee",
                        &["fs", "net", "windows-sys"],
                        None,
                    ),
                ],
            },
        };

        let slices = [slice];
        let hits = super::candidates(&slices, &packages);
        let staged = hits
            .iter()
            .map(|(_, row)| row.c_metadata.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            staged,
            BTreeSet::from(["aaaaaaaaaaaaaaaa", "cccccccccccccccc", "dddddddddddddddd"]),
            "host-shaped and shapeless windows-link rows and the exactly-labelled tokio row stage; the target shape and the metadata-labelled row do not"
        );
    }

    /// An index row fixture: `compile_key` hashes to `c_metadata`'s prefix
    /// (canonical rows are keyed so); `side` sets the row's `unit_shape`,
    /// `None` modelling a row published before shapes were recorded.
    fn index_row(
        name: &str,
        version: &str,
        c_metadata: &str,
        features: &[&str],
        side: Option<UnitSide>,
    ) -> ArtifactIndexRow {
        ArtifactIndexRow {
            crate_name: CrateName::parse(name).unwrap(),
            version: CrateVersion::new(semver::Version::parse(version).unwrap()),
            features_json: FeaturesJson::canonicalize(
                features.iter().map(|f| (*f).to_owned()).collect(),
            )
            .unwrap(),
            dependency_c_metadata_json: DependencyCMetadataJson::canonicalize(vec![]).unwrap(),
            c_metadata: CMetadata::parse(c_metadata).unwrap(),
            compile_key: format!("{c_metadata}{c_metadata}{c_metadata}"),
            bundle_digest: "sha256:".to_owned() + &"ab".repeat(32),
            bundle_size: 1,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 1,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
                strip: StripLevel::None,
            },
            emit: vec![],
            unit_shape: side.map(shape),
            min_glibc: None,
        }
    }

    fn shape(side: UnitSide) -> UnitShape {
        UnitShape {
            side,
            invocation: UnitInvocation::Native,
            kind: UnitKind::Linked,
        }
    }
}
