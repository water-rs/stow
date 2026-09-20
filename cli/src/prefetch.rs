use std::time::Instant;

use futures_util::{StreamExt, stream};

use crate::artifact_cache::{artifact_cache_key, filter_locally_cached_keys, prepare_local_cache};
use crate::budget::CacheBudget;
use crate::config::StowConfig;
use crate::fetch::{self, FetchRequest};
use crate::verify;

// Bundles pull straight from the OCI registry now — one blob GET per
// artifact, no batch envelope. Concurrency replaces the old batching as
// the throughput knob.
const PREFETCH_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrefetchArtifact {
    pub crate_name: String,
    pub c_metadata: String,
    /// `sha256:…` digest the bundle blob lives under in the registry.
    pub bundle_digest: String,
    pub target: String,
    pub rustc_version: String,
    pub depth: usize,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PrefetchSummary {
    pub already_local: usize,
    pub downloaded: usize,
    pub misses: usize,
    pub failed: usize,
    pub request_ms: u128,
    pub unpack_ms: u128,
    pub parse_ms: u128,
    pub verify_ms: u128,
    pub store_ms: u128,
}

impl PrefetchSummary {
    pub const fn total(self) -> usize {
        self.already_local + self.downloaded + self.misses + self.failed
    }
}

#[tracing::instrument(name = "stow.prefetch.warm_exact_artifacts", skip_all, fields(requests = requests.len()))]
pub async fn warm_exact_artifacts(
    config: &StowConfig,
    requests: &[PrefetchArtifact],
    budget: &CacheBudget,
) -> stow_types::error::Result<PrefetchSummary> {
    if requests.is_empty() {
        return Ok(PrefetchSummary::default());
    }

    config.ensure_dirs().await?;
    let (target, rustc_version) = validate_prefetch_requests(requests)?;
    let _version_cache_lease = prepare_local_cache(config, &rustc_version).await?;
    let started = Instant::now();
    let (already_local, missing_local) =
        partition_local_requests(config, requests, &rustc_version).await?;
    let mut summary = PrefetchSummary {
        already_local,
        ..PrefetchSummary::default()
    };
    merge_summary(
        &mut summary,
        drain_prefetch(config, &target, &rustc_version, &missing_local, budget).await?,
    );

    tracing::info!(
        target = %target,
        rustc_version = %rustc_version,
        total = summary.total(),
        already_local = summary.already_local,
        downloaded = summary.downloaded,
        misses = summary.misses,
        failed = summary.failed,
        request_ms = summary.request_ms,
        unpack_ms = summary.unpack_ms,
        parse_ms = summary.parse_ms,
        verify_ms = summary.verify_ms,
        store_ms = summary.store_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "prefetched exact stow artifacts for dependency graph"
    );

    Ok(summary)
}

/// Every request in one prefetch run must share a target triple and rustc
/// version — the artifacts are resolved and stored under exactly that pair.
/// Returns the shared `(target, rustc_version)`.
fn validate_prefetch_requests(
    requests: &[PrefetchArtifact],
) -> stow_types::error::Result<(String, String)> {
    let first = requests
        .first()
        .ok_or_else(|| stow_types::stow_error!("prefetch requests cannot be empty"))?;
    for request in requests {
        if request.target != first.target {
            return Err(stow_types::stow_error!(
                "prefetch target mismatch: expected {}, got {}",
                first.target,
                request.target
            ));
        }
        if request.rustc_version != first.rustc_version {
            return Err(stow_types::stow_error!(
                "prefetch rustc mismatch: expected {}, got {}",
                first.rustc_version,
                request.rustc_version
            ));
        }
    }
    Ok((first.target.clone(), first.rustc_version.clone()))
}

/// Split already-local artifacts from missing ones with a single indexed
/// query. The pre-pass only needs a yes/no per request — loading each bundle
/// to answer it (file lock + LRU write + five SELECTs, serially) dominated
/// the whole prefetch phase on a warm cache. Returns the count already
/// local and the parsed identities still to fetch.
async fn partition_local_requests<'a>(
    config: &StowConfig,
    requests: &'a [PrefetchArtifact],
    rustc_version: &str,
) -> stow_types::error::Result<(usize, Vec<&'a PrefetchArtifact>)> {
    let cache_keys = requests
        .iter()
        .map(|request| artifact_cache_key(&request.target, &request.c_metadata))
        .collect::<Vec<_>>();
    let locally_cached = filter_locally_cached_keys(config, rustc_version, &cache_keys).await?;

    let mut already_local = 0;
    let mut missing_local = Vec::new();
    for (request, cache_key) in requests.iter().zip(&cache_keys) {
        if locally_cached.contains(cache_key) {
            already_local += 1;
            continue;
        }
        missing_local.push(request);
    }
    Ok((already_local, missing_local))
}

/// Run the per-digest pulls under the shared pre-cargo budget's deadline.
/// Artifacts that miss the deadline are fetched on demand by the per-rustc
/// wrapper instead, where the latency overlaps cargo's own compilation
/// parallelism. The shared budget — not a private timer — is what keeps the
/// resolver, graph analysis, and prefetch from outlasting the build they
/// accelerate together.
async fn drain_prefetch(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
    missing_local: &[&PrefetchArtifact],
    budget: &CacheBudget,
) -> stow_types::error::Result<PrefetchSummary> {
    let base = fetch::registry_base(config)?;
    let mut results = stream::iter(missing_local.iter().map(|request| {
        process_prefetched_artifact(
            config.clone(),
            base.clone(),
            target.to_owned(),
            rustc_version.to_owned(),
            (*request).clone(),
        )
    }))
    .buffer_unordered(PREFETCH_CONCURRENCY);

    let mut summary = PrefetchSummary::default();
    let deadline = tokio::time::Instant::now() + budget.remaining();
    loop {
        // Explicit clock check in addition to `timeout_at`: under sustained
        // CPU saturation (dozens of verify/unpack tasks) the timer wheel can
        // fire late, but the wall clock cannot.
        if tokio::time::Instant::now() >= deadline {
            warn_deadline(&summary, missing_local.len(), budget);
            break;
        }
        match tokio::time::timeout_at(deadline, results.next()).await {
            Ok(Some(Ok(metrics))) => {
                tracing::debug!(
                    crate_name = %metrics.crate_name,
                    c_metadata = %metrics.c_metadata,
                    "prefetched stow artifact stored locally"
                );
                summary.parse_ms += metrics.parse_ms;
                summary.verify_ms += metrics.verify_ms;
                summary.store_ms += metrics.store_ms;
                summary.downloaded += 1;
            }
            Ok(Some(Err(error))) => {
                tracing::warn!(error = %error, "prefetched stow artifact processing failed");
                summary.failed += 1;
            }
            Ok(None) => break,
            Err(_elapsed) => {
                warn_deadline(&summary, missing_local.len(), budget);
                break;
            }
        }
    }
    Ok(summary)
}

/// Warn that the prefetch deadline cut the run short. `missing` is how many
/// artifacts were queued for download; the per-item outcomes already in
/// `summary` say how many of them actually ran, so the difference is what
/// the deadline skipped.
fn warn_deadline(summary: &PrefetchSummary, missing: usize, budget: &CacheBudget) {
    let skipped = missing.saturating_sub(summary.downloaded + summary.misses + summary.failed);
    tracing::warn!(
        skipped,
        deadline_ms = budget.total().as_millis(),
        "prefetch deadline reached; remaining artifacts will be fetched on demand"
    );
}

#[derive(Debug)]
struct PrefetchedArtifactMetrics {
    crate_name: String,
    c_metadata: String,
    parse_ms: u128,
    verify_ms: u128,
    store_ms: u128,
}

const fn merge_summary(summary: &mut PrefetchSummary, delta: PrefetchSummary) {
    summary.downloaded += delta.downloaded;
    summary.misses += delta.misses;
    summary.failed += delta.failed;
    summary.request_ms += delta.request_ms;
    summary.unpack_ms += delta.unpack_ms;
    summary.parse_ms += delta.parse_ms;
    summary.verify_ms += delta.verify_ms;
    summary.store_ms += delta.store_ms;
}

/// Pull one bundle blob by its index-provided digest, then run the same
/// parse → identity-validate → signature-verify → store pipeline the
/// per-invocation download path uses.
async fn process_prefetched_artifact(
    config: StowConfig,
    base: stow_oci::RegistryBase,
    target: String,
    rustc_version: String,
    request: PrefetchArtifact,
) -> stow_types::error::Result<PrefetchedArtifactMetrics> {
    let bytes = fetch::download_bundle_bytes(&base, &request.bundle_digest)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "pull prefetched bundle for {} {} ({}): {error}",
                request.crate_name,
                request.c_metadata,
                request.bundle_digest
            )
        })?;
    let parse_started = Instant::now();
    let bundle = fetch::parse_downloaded_bundle(bytes)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "parse prefetched bundle for {} {}: {error}",
                request.crate_name,
                request.c_metadata
            )
        })?;
    let parse_ms = parse_started.elapsed().as_millis();
    fetch::validate_bundle_identity(
        &bundle,
        &request.crate_name,
        &request.c_metadata,
        &target,
        &rustc_version,
    )
    .map_err(|error| {
        stow_types::stow_error!(
            "validate prefetched bundle for {} {}: {error}",
            request.crate_name,
            request.c_metadata
        )
    })?;
    let verify_started = Instant::now();
    verify::verify_bundle_signature(&config, &bundle)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "verify prefetched bundle for {} {}: {error}",
                request.crate_name,
                request.c_metadata
            )
        })?;
    let verify_ms = verify_started.elapsed().as_millis();
    let fetch_request = FetchRequest {
        target: &target,
        rustc_version: &rustc_version,
        c_metadata: &request.c_metadata,
    };
    let store_started = Instant::now();
    verify::store_downloaded_bundle_with_trust_marker(&config, &fetch_request, &bundle)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "store prefetched bundle for {} {}: {error}",
                request.crate_name,
                request.c_metadata
            )
        })?;
    let store_ms = store_started.elapsed().as_millis();
    Ok(PrefetchedArtifactMetrics {
        crate_name: request.crate_name,
        c_metadata: request.c_metadata,
        parse_ms,
        verify_ms,
        store_ms,
    })
}
