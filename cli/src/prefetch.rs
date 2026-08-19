use std::time::{Duration, Instant};

use futures_util::{StreamExt, stream};
use stow_types::api::BatchArtifactRequestEntry;
use tokio::task::JoinSet;

use crate::artifact_cache::{load_cached_bundle, prepare_local_cache, store_downloaded_bundle};
use crate::config::StowConfig;
use crate::fetch::{self, FetchRequest};
use crate::verify;

// Each batched artifact costs the edge several upstream subrequests when the
// CF cache is cold (manifest + config + signature + layers), and Workers cap
// subrequests per invocation (50 on the free plan). Keep batches small and
// recover throughput with client-side batch concurrency instead.
const PREFETCH_BATCH_SIZE: usize = 8;
const PREFETCH_BATCH_CONCURRENCY: usize = 4;
const STOW_PREFETCH_DEADLINE_SECS_ENV: &str = "STOW_PREFETCH_DEADLINE_SECS";

/// Time budget for the blocking prefetch phase: generous enough for a warm
/// CDN (hundreds of bundles at ~100ms), bounded so a degraded edge cannot
/// stall the build. Overridable per environment for benchmarking.
fn prefetch_deadline(missing: usize) -> Duration {
    if let Some(raw) = std::env::var_os(STOW_PREFETCH_DEADLINE_SECS_ENV)
        && let Some(secs) = raw.to_str().and_then(|value| value.parse::<u64>().ok())
    {
        return Duration::from_secs(secs);
    }
    let scaled_ms = (missing as u64).saturating_mul(250).clamp(10_000, 60_000);
    Duration::from_millis(scaled_ms)
}
const PREFETCH_MIN_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrefetchArtifact {
    pub crate_name: String,
    pub c_metadata: String,
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
) -> stow_types::error::Result<PrefetchSummary> {
    if requests.is_empty() {
        return Ok(PrefetchSummary::default());
    }

    config.ensure_dirs().await?;
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

    let _version_cache_lease = prepare_local_cache(config, &first.rustc_version).await?;
    let started = Instant::now();
    let mut summary = PrefetchSummary::default();
    let mut missing_local = Vec::<BatchArtifactRequestEntry>::new();
    for request in requests {
        let fetch_request = FetchRequest {
            target: &request.target,
            rustc_version: &request.rustc_version,
            c_metadata: &request.c_metadata,
            crate_name: &request.crate_name,
        };
        if let Some(bundle) = load_cached_bundle(config, &fetch_request).await? {
            drop(bundle);
            summary.already_local += 1;
        } else {
            let crate_name =
                stow_types::identity::CrateName::parse(request.crate_name.as_str()).map_err(
                    |error| stow_types::stow_error!(
                        "prefetch crate_name `{}`: {error}",
                        request.crate_name
                    ),
                )?;
            let c_metadata =
                stow_types::identity::CMetadata::parse(request.c_metadata.as_str()).map_err(
                    |error| stow_types::stow_error!(
                        "prefetch c_metadata `{}`: {error}",
                        request.c_metadata
                    ),
                )?;
            missing_local.push(BatchArtifactRequestEntry {
                crate_name,
                c_metadata,
            });
        }
    }

    let mut batch_config = config.clone();
    batch_config.request_timeout = batch_config
        .request_timeout
        .max(Duration::from_secs(PREFETCH_MIN_TIMEOUT_SECS));
    let target = first.target.clone();
    let rustc_version = first.rustc_version.clone();
    let mut batch_results = stream::iter(missing_local.chunks(PREFETCH_BATCH_SIZE).map(|batch| {
        process_prefetch_batch(
            config.clone(),
            batch_config.clone(),
            target.clone(),
            rustc_version.clone(),
            batch.to_vec(),
        )
    }))
    .buffer_unordered(PREFETCH_BATCH_CONCURRENCY);

    // No-slowdown floor: prefetch runs before cargo starts, so a slow or
    // degraded edge must never hold the build hostage. Artifacts that miss
    // the deadline are fetched on demand by the per-rustc wrapper instead,
    // where the latency overlaps cargo's own compilation parallelism.
    let deadline = tokio::time::Instant::now() + prefetch_deadline(missing_local.len());
    let mut deadline_skipped = 0_usize;
    loop {
        // Explicit clock check in addition to `timeout_at`: under sustained
        // CPU saturation (dozens of verify/unpack tasks) the timer wheel can
        // fire late, but the wall clock cannot.
        if tokio::time::Instant::now() >= deadline {
            deadline_skipped = summary
                .total()
                .saturating_sub(summary.already_local)
                .saturating_sub(summary.downloaded)
                .saturating_sub(summary.misses)
                .saturating_sub(summary.failed);
            tracing::warn!(
                skipped = deadline_skipped,
                deadline_ms = prefetch_deadline(missing_local.len()).as_millis(),
                "prefetch deadline reached; remaining artifacts will be fetched on demand"
            );
            break;
        }
        match tokio::time::timeout_at(deadline, batch_results.next()).await {
            Ok(Some(batch_result)) => {
                let batch_summary = batch_result?;
                merge_summary(&mut summary, batch_summary);
            }
            Ok(None) => break,
            Err(_elapsed) => {
                deadline_skipped = summary
                    .total()
                    .saturating_sub(summary.already_local)
                    .saturating_sub(summary.downloaded)
                    .saturating_sub(summary.misses)
                    .saturating_sub(summary.failed);
                tracing::warn!(
                    skipped = deadline_skipped,
                    deadline_ms = prefetch_deadline(missing_local.len()).as_millis(),
                    "prefetch deadline reached; remaining artifacts will be fetched on demand"
                );
                break;
            }
        }
    }

    tracing::info!(
        target = %first.target,
        rustc_version = %first.rustc_version,
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

async fn process_prefetch_batch(
    config: StowConfig,
    batch_config: StowConfig,
    target: String,
    rustc_version: String,
    batch: Vec<BatchArtifactRequestEntry>,
) -> stow_types::error::Result<PrefetchSummary> {
    let result = fetch::download_batch_bundles(&batch_config, &target, &rustc_version, &batch)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "download exact prefetch batch (size={}): {error}",
                batch.len()
            )
        })?;
    let mut batch_summary = PrefetchSummary {
        misses: result.missing.len(),
        request_ms: result.request_ms,
        unpack_ms: result.unpack_ms,
        ..PrefetchSummary::default()
    };

    let mut artifact_tasks = JoinSet::new();
    for downloaded in result.bundles {
        artifact_tasks.spawn(process_prefetched_artifact(
            config.clone(),
            batch_config.clone(),
            target.clone(),
            rustc_version.clone(),
            downloaded,
        ));
    }

    while let Some(artifact_result) = artifact_tasks.join_next().await {
        let metrics = match artifact_result {
            Ok(Ok(metrics)) => metrics,
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "prefetched stow artifact processing failed");
                batch_summary.failed += 1;
                continue;
            }
            Err(error) => {
                return Err(stow_types::stow_error!(
                    "prefetched stow artifact task join failed for target={target} rustc={rustc_version}: {error}"
                ));
            }
        };
        tracing::debug!(
            crate_name = %metrics.crate_name,
            c_metadata = %metrics.c_metadata,
            "prefetched stow artifact stored locally"
        );
        batch_summary.parse_ms += metrics.parse_ms;
        batch_summary.verify_ms += metrics.verify_ms;
        batch_summary.store_ms += metrics.store_ms;
        batch_summary.downloaded += 1;
    }

    Ok(batch_summary)
}

async fn process_prefetched_artifact(
    config: StowConfig,
    batch_config: StowConfig,
    target: String,
    rustc_version: String,
    downloaded: fetch::BatchDownloadedArtifact,
) -> stow_types::error::Result<PrefetchedArtifactMetrics> {
    let parse_started = Instant::now();
    let bundle = fetch::parse_downloaded_bundle(downloaded.bundle_bytes)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "parse prefetched bundle for {} {}: {error}",
                downloaded.crate_name,
                downloaded.c_metadata
            )
        })?;
    let parse_ms = parse_started.elapsed().as_millis();
    fetch::validate_bundle_identity(
        &bundle,
        &downloaded.crate_name,
        &downloaded.c_metadata,
        &target,
        &rustc_version,
    )
    .map_err(|error| {
        stow_types::stow_error!(
            "validate prefetched bundle for {} {}: {error}",
            downloaded.crate_name,
            downloaded.c_metadata
        )
    })?;
    let verify_started = Instant::now();
    verify::verify_bundle_signature(&batch_config, &bundle)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "verify prefetched bundle for {} {}: {error}",
                downloaded.crate_name,
                downloaded.c_metadata
            )
        })?;
    let verify_ms = verify_started.elapsed().as_millis();
    let fetch_request = FetchRequest {
        target: &target,
        rustc_version: &rustc_version,
        c_metadata: &downloaded.c_metadata,
        crate_name: &downloaded.crate_name,
    };
    let store_started = Instant::now();
    let cached_bundle = store_downloaded_bundle(&config, &fetch_request, &bundle)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "store prefetched bundle for {} {}: {error}",
                downloaded.crate_name,
                downloaded.c_metadata
            )
        })?;
    verify::persist_cached_bundle_trust_marker(&config, &cached_bundle)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "persist prefetched trust marker for {} {}: {error}",
                downloaded.crate_name,
                downloaded.c_metadata
            )
        })?;
    let store_ms = store_started.elapsed().as_millis();
    Ok(PrefetchedArtifactMetrics {
        crate_name: downloaded.crate_name,
        c_metadata: downloaded.c_metadata,
        parse_ms,
        verify_ms,
        store_ms,
    })
}
