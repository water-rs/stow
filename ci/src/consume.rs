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
//! grant for the capture wrapper to inject. A bundle that never arrived
//! is skipped — the unit compiles — and nothing unverified is ever
//! injected. A slice that cannot be read fails the build: the scheduler
//! dispatched the task because its dependencies are published, so a build
//! that cannot see them would compile its whole closure instead of the
//! one crate it was dispatched for (stow#817).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Instant;

use futures_util::StreamExt;
use stow_cli::build_consume::{self, ConsumeConfig, IndexSlice};
use stow_types::api::BuildTaskPayload;
use stow_types::error::Context as _;
use stow_types::index::ArtifactIndexRow;
use stow_types::public_cache::canonical_crate_name;

use crate::dep_scan;

/// How many candidates are fetched, verified and staged at once.
///
/// Measured from a runner against the registry the builders pull from
/// (stow#717, run 38482237026; bundles average about 2 MB): one in
/// flight carried 400 bundles' worth at 73 ms each, eight at 10.9 ms,
/// sixteen at 5.2 ms, and thirty-two, sixty-four and a hundred and
/// twenty-eight stayed inside the noise of sixteen — the link is full
/// there, and more in flight only makes each request longer. The
/// registry refused nothing at any level.
const PREFETCH_CONCURRENCY: usize = 16;

/// What [`prefetch`] staged for the capture wrapper to serve: the read-only
/// store the sandbox grant covers and how many verified bundles it holds.
pub struct Consumption {
    /// Compile-key-addressed bundle store, ready to grant the phases.
    pub store_dir: PathBuf,
    /// Verified bundles staged under `store_dir`.
    pub artifacts: usize,
}

/// The signed index slices this task's dependency nodes were published
/// to: the task target's when a node sits on the target side, the host's
/// when one sits on the host side — proc-macro and build-dependency units
/// key for the host triple, so their rows live in the host slice, not the
/// task target's. The scheduler dispatched the task only once every node
/// was in its slice, so each slice named here exists, and one that cannot
/// be read is an error; a task with no dependency nodes names none. Each
/// is signature-verified inside [`build_consume::ensure_slice`] before a
/// row is ever used.
pub async fn slices_for_task(
    config: &ConsumeConfig,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<Vec<IndexSlice>> {
    slices_for_task_with(task, |target, rustc_version| {
        Box::pin(async move { build_consume::ensure_slice(config, &target, &rustc_version).await })
    })
    .await
}

/// [`slices_for_task`] with the slice fetch injected, so a test answers
/// from its own source instead of the process's config — the failure a
/// real fetch produces needs no environment to reach the error path.
pub async fn slices_for_task_with<'s>(
    task: &BuildTaskPayload,
    fetch: impl Fn(
        String,
        String,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = stow_types::error::Result<IndexSlice>> + Send + 's>,
    >,
) -> stow_types::error::Result<Vec<IndexSlice>> {
    let nodes = &task.dependency_subgraph.nodes;
    let mut targets = BTreeSet::new();
    if nodes.iter().any(|node| !node.host_side) {
        targets.insert(task.target.as_str().to_owned());
    }
    if nodes.iter().any(|node| node.host_side) {
        targets.insert(crate::task::compile_host(task).await?);
    }
    let rustc_version = task.rustc_version.as_str().to_owned();
    futures_util::future::try_join_all(targets.iter().map(|target| {
        futures_util::TryFutureExt::map_err(
            fetch(target.clone(), rustc_version.clone()),
            move |error| error.wrap_err(format!("index slice for {target}")),
        )
    }))
    .await
}

/// Fetch and stage the published artifacts this task's dependencies can be
/// served from: every signed-index row matching a unit of the build
/// workspace's own cargo unit graph — name, version, activated feature
/// set and side — which the caller computed from the same cargo
/// invocations the build phases run (stow#589).
///
/// Rows whose dep-identity does not match this build's resolution are not
/// excluded here — the wrapper's compile-key lookup is what decides a hit;
/// prefetching a row it never matches only wastes a download.
///
/// # Errors
///
/// Returns an error when the config, the index slices or the registry
/// session cannot be obtained, and when a bundle the signed index vouches
/// for arrived and failed verification — see
/// [`build_consume::StageFailure`]. A bundle that could not be *fetched*
/// is logged and skipped: it removes one candidate, never the task.
pub async fn prefetch(
    task: &BuildTaskPayload,
    packages: Vec<dep_scan::ConsumablePackage>,
    store_dir: &Path,
) -> stow_types::error::Result<Consumption> {
    // Everything past here is the CLI's verified-download chain, and that
    // chain's HTTP client resolves DNS through a Tokio reactor. The build
    // stage runs on smol, where calling it panics outright. The network
    // phase therefore gets a Tokio runtime of its own on a blocking
    // thread, rather than the whole build stage being moved onto Tokio to
    // suit one step of it.
    let task = task.clone();
    let store_dir = store_dir.to_path_buf();
    on_a_tokio_runtime(move || async move { stage_candidates(&task, &packages, &store_dir).await })
        .await?
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
/// Returns an error when consumption cannot be set up — no config, an
/// unreadable slice, no registry session — or when a bundle the signed
/// index vouches for did not verify.
async fn stage_candidates(
    task: &BuildTaskPayload,
    packages: &[dep_scan::ConsumablePackage],
    store_dir: &Path,
) -> stow_types::error::Result<Consumption> {
    // Every slice named here holds a dependency the scheduler saw
    // published before it dispatched the task, so failing to set
    // consumption up is not a cold cache: building on would compile what
    // the task was promised it would be served.
    let config = ConsumeConfig::load().wrap_err("load the cache-consumption config")?;
    let slices = slices_for_task(&config, task).await?;
    let candidates = candidates(&slices, packages);

    // The prefetch pulls bundle blobs straight from GHCR by digest — the
    // offline-edge build never touches the byte path (stow#455). One
    // anonymous session mints one bearer for the whole batch.
    let registry = stow_oci::RegistryBase::parse(config.registry_base_url())?;
    let http = config.registry_http().await?;
    let session = registry.session(
        &stow_types::registry::cache_repository(&task.rustc_version),
        &http,
    );

    let mut seen_compile_keys = BTreeSet::new();
    let mut distinct = Vec::new();
    for (slice, row) in candidates {
        if seen_compile_keys.insert(row.compile_key.clone()) {
            distinct.push((slice, row));
        }
    }
    let candidate_count = distinct.len();

    let started = Instant::now();
    let staged = stage_all(distinct, |slice, row| {
        fetch_and_stage(&config, &session, slice, row, store_dir)
    })
    .await?;

    tracing::info!(
        task_id = %task.task_id,
        staged,
        candidates = candidate_count,
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "cache-consumption prefetch staged verified bundles"
    );
    Ok(Consumption {
        store_dir: store_dir.to_path_buf(),
        artifacts: staged,
    })
}

/// Stage every candidate, `PREFETCH_CONCURRENCY` at a time, and count
/// the ones that landed.
///
/// The candidates are independent — one round trip to the registry
/// each, then checks on bytes already in hand — so serially the stage
/// cost the sum of them, about two minutes for a five-hundred-candidate
/// closure (stow#717). What a failure means is unchanged: a candidate
/// that could not be fetched is logged and skipped and its unit
/// compiles; one the signed index vouches for that did not verify fails
/// the stage, and the candidates still in flight are dropped with it.
async fn stage_all<'a, Stage, Staging>(
    candidates: Vec<(&'a IndexSlice, &'a ArtifactIndexRow)>,
    stage: Stage,
) -> stow_types::error::Result<usize>
where
    Stage: Fn(&'a IndexSlice, &'a ArtifactIndexRow) -> Staging + Send + Sync,
    Staging: Future<Output = Result<(), build_consume::StageFailure>> + Send,
{
    let mut staged = 0usize;
    let mut in_flight = futures_util::stream::iter(candidates)
        .map(|(slice, row)| {
            let staging = stage(slice, row);
            async move { (row, staging.await) }
        })
        .buffer_unordered(PREFETCH_CONCURRENCY);
    while let Some((row, outcome)) = in_flight.next().await {
        match outcome {
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
                // Returning drops the stream, which cancels the
                // candidates still in flight.
                return Err(stow_types::stow_error!(
                    "the signed index vouches for `{}` {} (compile key {}) but its bundle did not verify: {error}",
                    row.crate_name.as_str(),
                    row.version,
                    row.compile_key
                ));
            }
        }
    }
    Ok(staged)
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
/// row.
fn package_matches_side(package: &dep_scan::ConsumablePackage, row: &ArtifactIndexRow) -> bool {
    (row.unit_shape.side == stow_types::public_cache::UnitSide::Host) == package.host_side
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use stow_cli::build_consume::StageFailure;
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

    /// stow#589: a row is consumable only at the unit-graph identity —
    /// canonical name, exact version, the activated feature set AND the
    /// side. A host-side entry matches a host-shaped row and never the
    /// same package's target shape; and a row still labelled with cargo
    /// metadata's platform-agnostic resolve features (a feature this
    /// target never compiles, stow#579) does not match the graph's
    /// activated set.
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

        let slice = index_slice(vec![
            index_row(
                "windows-link",
                "0.2.1",
                "aaaaaaaaaaaaaaaa",
                &[],
                UnitSide::Host,
            ),
            index_row(
                "windows-link",
                "0.2.1",
                "bbbbbbbbbbbbbbbb",
                &[],
                UnitSide::Target,
            ),
            index_row(
                "windows-link",
                "0.2.1",
                "cccccccccccccccc",
                &[],
                UnitSide::Host,
            ),
            index_row(
                "tokio",
                "1.53.2",
                "dddddddddddddddd",
                &["fs", "net"],
                UnitSide::Target,
            ),
            index_row(
                "tokio",
                "1.53.2",
                "eeeeeeeeeeeeeeee",
                &["fs", "net", "windows-sys"],
                UnitSide::Target,
            ),
        ]);

        let slices = [slice];
        let hits = super::candidates(&slices, &packages);
        let staged = hits
            .iter()
            .map(|(_, row)| row.c_metadata.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            staged,
            BTreeSet::from(["aaaaaaaaaaaaaaaa", "cccccccccccccccc", "dddddddddddddddd"]),
            "the host-shaped windows-link rows and the exactly-labelled tokio row stage; the target shape and the metadata-labelled row do not"
        );
    }

    /// stow#717: the candidates are independent round trips, so they
    /// stage `PREFETCH_CONCURRENCY` at a time — the most ever in flight
    /// reaches the bound exactly, never above it.
    #[test]
    fn candidates_are_staged_concurrently_under_the_bound() {
        smol::block_on(async {
            const COUNT: usize = 3 * super::PREFETCH_CONCURRENCY;
            let slice = index_slice(
                (0..COUNT)
                    .map(|index| {
                        index_row(
                            &format!("crate-{index}"),
                            "1.0.0",
                            &format!("{index:016x}"),
                            &[],
                            UnitSide::Target,
                        )
                    })
                    .collect(),
            );
            let candidates = slice
                .index
                .rows
                .iter()
                .map(|row| (&slice, row))
                .collect::<Vec<_>>();

            let in_flight = AtomicUsize::new(0);
            let most_in_flight = AtomicUsize::new(0);
            let staged = super::stage_all(candidates, |_, _| {
                let in_flight = &in_flight;
                let most_in_flight = &most_in_flight;
                async move {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    most_in_flight.fetch_max(now, Ordering::SeqCst);
                    for _ in 0..3 {
                        futures_lite::future::yield_now().await;
                    }
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                }
            })
            .await
            .expect("every candidate stages");

            assert_eq!(staged, COUNT);
            assert_eq!(
                most_in_flight.load(Ordering::SeqCst),
                super::PREFETCH_CONCURRENCY
            );
        });
    }

    /// A candidate that could not be fetched is logged and skipped — its
    /// unit compiles — and the rest of the stage still lands.
    #[test]
    fn an_unfetchable_candidate_is_skipped_and_the_rest_are_staged() {
        smol::block_on(async {
            let slice = index_slice(vec![
                index_row("absent", "1.0.0", "0000000000000001", &[], UnitSide::Target),
                index_row(
                    "present-a",
                    "1.0.0",
                    "0000000000000002",
                    &[],
                    UnitSide::Target,
                ),
                index_row(
                    "present-b",
                    "1.0.0",
                    "0000000000000003",
                    &[],
                    UnitSide::Target,
                ),
            ]);
            let candidates = slice
                .index
                .rows
                .iter()
                .map(|row| (&slice, row))
                .collect::<Vec<_>>();

            let staged = super::stage_all(candidates, |_, row| async move {
                if row.crate_name.as_str() == "absent" {
                    Err(StageFailure::Unavailable(stow_types::stow_error!(
                        "no such blob"
                    )))
                } else {
                    Ok(())
                }
            })
            .await
            .expect("a missing bundle does not fail the stage");

            assert_eq!(staged, 2);
        });
    }

    /// A bundle the signed index vouched for that did not verify fails
    /// the whole stage — the row it names is in the error. The never-
    /// resolving sibling stands in for the candidates still in flight,
    /// which the return drops.
    #[test]
    fn an_unverifiable_candidate_fails_the_stage() {
        smol::block_on(async {
            let slice = index_slice(vec![
                index_row("forged", "2.3.4", "0000000000000004", &[], UnitSide::Target),
                index_row(
                    "genuine",
                    "1.0.0",
                    "0000000000000005",
                    &[],
                    UnitSide::Target,
                ),
            ]);
            let candidates = slice
                .index
                .rows
                .iter()
                .map(|row| (&slice, row))
                .collect::<Vec<_>>();

            let error = super::stage_all(candidates, |_, row| async move {
                if row.crate_name.as_str() == "forged" {
                    Err(StageFailure::Unverifiable(stow_types::stow_error!(
                        "signature did not check out"
                    )))
                } else {
                    futures_lite::future::pending::<()>().await;
                    Ok(())
                }
            })
            .await
            .expect_err("an unverifiable candidate fails the stage");

            let text = error.to_string();
            assert!(text.contains("forged"), "the row's crate name: {text}");
            assert!(text.contains("2.3.4"), "the row's version: {text}");
            assert!(text.contains("did not verify"), "the verdict: {text}");
        });
    }

    /// A one-slice fixture around `rows`: the target and rustc are the
    /// ones the `candidates` matching tests exercise.
    fn index_slice(rows: Vec<ArtifactIndexRow>) -> stow_cli::build_consume::IndexSlice {
        stow_cli::build_consume::IndexSlice {
            manifest_digest: "sha256:".to_owned() + &"cd".repeat(32),
            index: ArtifactIndex {
                header: ArtifactIndexHeader {
                    format_version: stow_types::index::ARTIFACT_INDEX_FORMAT_VERSION,
                    target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
                    rustc_version: WireRustcVersion::parse("1.99.0").unwrap(),
                    generated_at: String::new(),
                    generation: 1,
                    row_count: rows.len() as u64,
                },
                rows,
            },
        }
    }

    /// An index row fixture: `compile_key` hashes to `c_metadata`'s prefix
    /// (canonical rows are keyed so); `side` sets the row's `unit_shape`.
    fn index_row(
        name: &str,
        version: &str,
        c_metadata: &str,
        features: &[&str],
        side: UnitSide,
    ) -> ArtifactIndexRow {
        ArtifactIndexRow {
            dependency_task_ids: Vec::new(),
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
            unit_shape: shape(side),
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
