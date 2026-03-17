use std::time::Duration;
use std::time::Instant;

use futures_util::stream::{self, StreamExt};
use stow_types::api::BatchArtifactRequestEntry;

use crate::artifact_cache::{load_cached_bundle, prepare_local_cache, store_downloaded_bundle};
use crate::config::StowConfig;
use crate::fetch::{self, FetchRequest};
use crate::verify;

const PREFETCH_BATCH_SIZE: usize = 32;
const PREFETCH_MIN_TIMEOUT_SECS: u64 = 12;

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
    pub fn total(self) -> usize {
        self.already_local + self.downloaded + self.misses + self.failed
    }
}

pub async fn warm_exact_artifacts(
    config: &StowConfig,
    requests: &[PrefetchArtifact],
) -> eyre::Result<PrefetchSummary> {
    if requests.is_empty() {
        return Ok(PrefetchSummary::default());
    }

    config.ensure_dirs().await?;
    let first = requests
        .first()
        .ok_or_else(|| eyre::eyre!("prefetch requests cannot be empty"))?;
    for request in requests {
        if request.target != first.target {
            return Err(eyre::eyre!(
                "prefetch target mismatch: expected {}, got {}",
                first.target,
                request.target
            ));
        }
        if request.rustc_version != first.rustc_version {
            return Err(eyre::eyre!(
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
        match load_cached_bundle(config, &fetch_request).await? {
            Some(bundle) => {
                drop(bundle);
                summary.already_local += 1;
            }
            None => missing_local.push(BatchArtifactRequestEntry {
                crate_name: request.crate_name.clone(),
                c_metadata: request.c_metadata.clone(),
            }),
        }
    }

    let mut batch_config = config.clone();
    batch_config.request_timeout = batch_config
        .request_timeout
        .max(Duration::from_secs(PREFETCH_MIN_TIMEOUT_SECS));
    let concurrency = prefetch_concurrency();

    for batch in missing_local.chunks(PREFETCH_BATCH_SIZE) {
        let result = fetch::download_batch_bundles(
            &batch_config,
            &first.target,
            &first.rustc_version,
            batch,
        )
        .await?;
        summary.misses += result.missing.len();
        summary.request_ms += result.request_ms;
        summary.unpack_ms += result.unpack_ms;
        let verified = stream::iter(result.bundles.into_iter())
            .map(|downloaded| {
                let batch_config = batch_config.clone();
                let config = config.clone();
                let target = first.target.clone();
                let rustc_version = first.rustc_version.clone();
                async move {
                    let parse_started = Instant::now();
                    let bundle = fetch::parse_downloaded_bundle(downloaded.bundle_bytes)
                        .await
                        .map_err(|error| {
                            eyre::eyre!(
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
                        eyre::eyre!(
                            "validate prefetched bundle for {} {}: {error}",
                            downloaded.crate_name,
                            downloaded.c_metadata
                        )
                    })?;
                    let verify_started = Instant::now();
                    verify::verify_bundle_signature(&batch_config, &bundle)
                        .await
                        .map_err(|error| {
                            eyre::eyre!(
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
                    store_downloaded_bundle(&config, &fetch_request, &bundle)
                        .await
                        .map_err(|error| {
                            eyre::eyre!(
                                "store prefetched bundle for {} {}: {error}",
                                downloaded.crate_name,
                                downloaded.c_metadata
                            )
                        })?;
                    let store_ms = store_started.elapsed().as_millis();
                    Ok::<_, eyre::Report>(PrefetchedArtifactMetrics {
                        crate_name: downloaded.crate_name,
                        c_metadata: downloaded.c_metadata,
                        parse_ms,
                        verify_ms,
                        store_ms,
                    })
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<_>>()
            .await;

        for verified_bundle in verified {
            let metrics = match verified_bundle {
                Ok(bundle) => bundle,
                Err(error) => {
                    tracing::warn!(error = %error, "prefetched stow artifact processing failed");
                    summary.failed += 1;
                    continue;
                }
            };
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

fn prefetch_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().saturating_mul(4))
        .unwrap_or(8)
        .clamp(8, 32)
}
