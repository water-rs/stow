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
use crate::task::BuildWorkspace;

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
/// served from: every signed-index row naming a registry library package
/// of the resolved closure at the same version and feature set — never the
/// task crate itself, which the task exists to compile.
///
/// Rows whose dep-identity does not match this build's resolution are not
/// excluded here — the wrapper's compile-key lookup is what decides a hit;
/// prefetching a row it never matches only wastes a download.
///
/// # Errors
///
/// Returns an error when the config, the index slices, or `cargo metadata`
/// cannot be obtained — the caller treats that as "consumption disabled"
/// and builds exactly as before. A bundle that could not be *fetched* is
/// logged and skipped the same way: it removes one candidate, never the
/// task. A bundle that arrived and failed verification is neither, and
/// propagates — see [`build_consume::StageFailure`].
pub async fn prefetch(
    task: &BuildTaskPayload,
    workspace: &BuildWorkspace,
    store_dir: &Path,
) -> Result<Consumption, build_consume::StageFailure> {
    let unavailable = build_consume::StageFailure::Unavailable;
    // The closure comes from `cargo metadata`, which this stage already
    // runs on its own executor.
    let packages = dep_scan::consumable_packages(workspace, task)
        .await
        .map_err(unavailable)?;

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
    let candidates = candidates(&slices, packages, task);

    let mut seen_compile_keys = BTreeSet::new();
    let candidates: Vec<_> = candidates
        .into_iter()
        .filter(|(_, row)| seen_compile_keys.insert(row.compile_key.clone()))
        .collect();
    // Verified bundles stage under per-compile-key dirs, so the fetches
    // are independent — a serial fetch puts one network round trip per
    // dep on the task's wall clock. Fan out and report in the same
    // order: skip the unavailable, fail the unverifiable.
    let config = std::sync::Arc::new(config);
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    let mut staged_fetches = tokio::task::JoinSet::new();
    for (slice, row) in candidates {
        let config = std::sync::Arc::clone(&config);
        let slice = slice.clone();
        let row = row.clone();
        let store_dir = store_dir.to_path_buf();
        let permit = std::sync::Arc::clone(&permits);
        staged_fetches.spawn(async move {
            let _permit = permit.acquire().await;
            let fetched = fetch_and_stage(&config, &slice, &row, &store_dir).await;
            (row, fetched)
        });
    }
    let mut staged = 0usize;
    while let Some(fetched) = staged_fetches.join_next().await {
        let (row, result) = fetched.expect("cache-consumption fetch panicked");
        match result {
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

/// The `(slice, row)` pairs a build may serve: rows matching a registry
/// library package of the closure by canonical name, exact version and
/// resolved feature set — with the task crate's own artifact excluded, so
/// a re-run after a successful publish can never consume the very artifact
/// the task must produce.
fn candidates<'a>(
    slices: &'a [IndexSlice],
    packages: &[dep_scan::ConsumablePackage],
    task: &BuildTaskPayload,
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
            });
            if !matches_package {
                continue;
            }
            let is_task_crate = crate_name == canonical_crate_name(task.crate_name.as_str())
                && row.version == task.version;
            if is_task_crate {
                continue;
            }
            selected.push((slice, row));
        }
    }
    selected
}

/// One row through the CLI's own verified-download chain: edge byte path
/// digest-checked against `bundle_digest`, manifest/config identity
/// byte-compared against the signature-covered `oci/config.json`, cosign
/// signature verified against the pinned `build-crate.yml` identity — then
/// staged under the row's compile key for the read-only sandbox grant.
async fn fetch_and_stage(
    config: &ConsumeConfig,
    slice: &IndexSlice,
    row: &ArtifactIndexRow,
    store_dir: &Path,
) -> Result<(), build_consume::StageFailure> {
    build_consume::stage_verified_bundle(config, slice, row, &store_dir.join(&row.compile_key))
        .await
}

#[cfg(test)]
mod tests {
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
}
