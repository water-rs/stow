use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

use futures_util::{StreamExt, stream};
use tokio::sync::watch;

use crate::artifact_cache::{artifact_cache_key, filter_locally_cached_keys, prepare_local_cache};
use crate::budget::CacheBudget;
use crate::config::StowConfig;
use crate::fetch::{self, BundleRef, FetchError};
use crate::verify;

// One edge byte-path GET per artifact, no batch envelope: the index already
// resolved every key, so concurrency is the throughput knob — and eight was
// turning it down. A 41-crate graph is 79 artifacts and 317MB; on a 1Gbps
// link, eight in flight fetched it in 6.6s and 7.1s, thirty-two in 2.5s and
// 3.1s. That is 42MB/s against 115MB/s: the link, not the server, is
// supposed to be the limit. Sixteen and forty-eight measured inside the
// noise of thirty-two, so the curve is flat above the point where the link
// saturates; this sits in the middle of that flat.
//
// The requests are multiplexed over one HTTP/2 or HTTP/3 connection to the
// edge, so the cost of another one in flight is a stream, not a socket.
const PREFETCH_CONCURRENCY: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrefetchArtifact {
    pub crate_name: String,
    pub c_metadata: String,
    /// `sha256:…` digest the signed index pins for the bundle bytes.
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

/// What one in-flight bundle fetch resolved to, broadcast to any wrapper
/// plan that found the same bundle while it was being fetched (stow#347).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefetchStatus {
    /// Still being fetched, verified or stored.
    Pending,
    /// Stored locally with its trust marker — a local lookup serves it.
    Stored,
    /// The edge answered 404 — the index row outlived its blob, so the
    /// call site treats this like a negative-cache entry.
    Absent,
    /// Download, verification or store failed — the caller retries its
    /// own fetch path.
    Failed,
}

/// The per-build ledger of which bundle fetches the prefetch pipeline
/// owns right now.
///
/// A rustc wrapper that reaches its remote-serve path for a covered key
/// subscribes here and waits for the outcome instead of opening a second
/// download. Receivers live in the map; each sender lives inside the
/// worker that owns the fetch, so a worker that never runs or is dropped
/// (deadline cut, task end) resolves its waiters as `Failed` rather than
/// leaving them waiting on a fetch that no longer exists.
pub struct PrefetchTracker {
    in_flight: Mutex<HashMap<String, watch::Receiver<PrefetchStatus>>>,
    wanted: std::sync::Arc<std::sync::Mutex<HashSet<String>>>,
}

impl PrefetchTracker {
    /// An empty ledger — subscriptions answer `None` until workers register.
    #[must_use]
    pub fn new() -> Self {
        Self {
            in_flight: Mutex::new(HashMap::new()),
            wanted: std::sync::Arc::new(std::sync::Mutex::new(HashSet::new())),
        }
    }

    /// Register `key` as in-flight; the returned sender belongs to the
    /// worker that settles it. Re-registering a key replaces the stale
    /// receiver — the freshest fetch is the answer a wrapper wants.
    pub fn track(&self, key: String) -> watch::Sender<PrefetchStatus> {
        let (sender, receiver) = watch::channel(PrefetchStatus::Pending);
        self.in_flight
            .lock()
            .expect("prefetch tracker lock")
            .insert(key, receiver);
        sender
    }

    /// Mark `key` as demanded by a live wrapper — the drain's feed picks
    /// wanted requests ahead of their queue position so an early unit
    /// waits on a fetch already running instead of one hundreds deep
    /// (stow#347). Harmless on keys the drain never registered: a wanted
    /// set is a hint, not a queue.
    pub fn want(&self, key: String) {
        if let Ok(mut wanted) = self.wanted.lock() {
            wanted.insert(key);
        }
    }

    /// The shared wanted set the drain's feed consults on every item it
    /// dequeues — a live priority hint rather than a snapshot.
    pub fn wanted_set(&self) -> std::sync::Arc<std::sync::Mutex<HashSet<String>>> {
        self.wanted.clone()
    }

    /// A receiver for the in-flight prefetch of `key`, if this build owns
    /// one. Subscribing also marks the key wanted: the caller is about to
    /// wait on it, so its fetch belongs at the front of whatever queue it
    /// sits in.
    pub fn subscribe(&self, key: &str) -> Option<watch::Receiver<PrefetchStatus>> {
        self.want(key.to_owned());
        self.in_flight
            .lock()
            .expect("prefetch tracker lock")
            .get(key)
            .cloned()
    }

    /// Forget every registered entry — called once the prefetch phase is
    /// over so the map does not outlive its meaning.
    pub fn finish(&self) {
        self.in_flight
            .lock()
            .expect("prefetch tracker lock")
            .clear();
    }
}

impl Default for PrefetchTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[tracing::instrument(name = "stow.prefetch.warm_exact_artifacts", skip_all, fields(requests = requests.len()))]
pub async fn warm_exact_artifacts(
    config: &StowConfig,
    requests: &[PrefetchArtifact],
    budget: &CacheBudget,
    tracker: Option<&PrefetchTracker>,
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
        drain_prefetch(
            config,
            &target,
            &rustc_version,
            &missing_local,
            budget,
            tracker,
        )
        .await?,
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

/// Run the per-artifact pulls under the shared pre-cargo budget's deadline.
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
    tracker: Option<&PrefetchTracker>,
) -> stow_types::error::Result<PrefetchSummary> {
    // Every request registers before the stream starts, so a wrapper whose
    // key is still queued already finds the ledger entry and waits on it
    // rather than racing the fetch with its own download (stow#347).
    let senders: HashMap<String, watch::Sender<PrefetchStatus>> =
        tracker.map_or_else(HashMap::new, |tracker| {
            missing_local
                .iter()
                .map(|request| {
                    let key = artifact_cache_key(target, &request.c_metadata);
                    (key.clone(), tracker.track(key))
                })
                .collect()
        });
    // Feed work out one at a time, preferring wanted keys over queue
    // position — a wrapper whose unit is demanded early bumps its fetch
    // to the front of whatever remains, which is what keeps the await
    // shorter than a compile (stow#347).
    let wanted = tracker.map(PrefetchTracker::wanted_set);
    let remaining = std::sync::Arc::new(std::sync::Mutex::new(
        missing_local
            .iter()
            .map(|request| {
                let key = artifact_cache_key(target, &request.c_metadata);
                ((*request).clone(), senders.get(&key).cloned())
            })
            .collect::<std::collections::VecDeque<_>>(),
    ));
    let feed = stream::unfold(remaining, move |remaining| {
        let wanted = wanted.clone();
        Box::pin(async move {
            let item = {
                let mut queue = remaining.lock().expect("prefetch feed lock");
                let wanted_position = wanted.as_ref().and_then(|wanted| {
                    let wanted = wanted.lock().expect("prefetch wanted lock");
                    queue.iter().position(|(request, _)| {
                        wanted.contains(&artifact_cache_key(&request.target, &request.c_metadata))
                    })
                });
                queue.remove(wanted_position.unwrap_or(0))
            }?;
            Some((item, remaining))
        })
    });
    let mut results = feed
        .map(|(request, sender)| {
            process_prefetched_artifact(
                config.clone(),
                target.to_owned(),
                rustc_version.to_owned(),
                request,
                sender,
            )
        })
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
            Ok(Some(Ok(PrefetchOutcome::Stored(metrics)))) => {
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
            Ok(Some(Ok(PrefetchOutcome::Absent))) => summary.misses += 1,
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

/// What one prefetched artifact came to: stored locally, or absent on the
/// edge (the index is ahead of a pruned catalog row — the wrapper's own
/// lookup will record the miss).
#[derive(Debug)]
enum PrefetchOutcome {
    Stored(PrefetchedArtifactMetrics),
    Absent,
}

/// Stream one bundle through the edge byte path, digest-checked against
/// the index, then run the same parse → identity-validate →
/// signature-verify → store pipeline the per-invocation download path
/// used to run. `sender` settles the tracker's entry for this key: a
/// wrapper that arrived while the fetch was in flight serves the stored
/// result or falls back to its own path (stow#347).
async fn process_prefetched_artifact(
    config: StowConfig,
    target: String,
    rustc_version: String,
    request: PrefetchArtifact,
    sender: Option<watch::Sender<PrefetchStatus>>,
) -> stow_types::error::Result<PrefetchOutcome> {
    let bundle_ref = BundleRef {
        target: &target,
        rustc_version: &rustc_version,
        crate_name: &request.crate_name,
        c_metadata: &request.c_metadata,
        bundle_digest: &request.bundle_digest,
    };
    let bytes = match fetch::download_bundle_bytes(&config, &bundle_ref).await {
        Ok(bytes) => bytes,
        Err(FetchError::NotFound) => {
            tracing::debug!(
                crate_name = %request.crate_name,
                c_metadata = %request.c_metadata,
                "prefetched stow artifact absent on the edge"
            );
            if let Some(sender) = sender {
                let _ = sender.send(PrefetchStatus::Absent);
            }
            return Ok(PrefetchOutcome::Absent);
        }
        Err(error) => {
            if let Some(sender) = sender {
                let _ = sender.send(PrefetchStatus::Failed);
            }
            return Err(stow_types::stow_error!(
                "fetch prefetched bundle for {} {} ({}): {error}",
                request.crate_name,
                request.c_metadata,
                request.bundle_digest
            ));
        }
    };
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
    let fetch_request = bundle_ref.fetch_request();
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
    if let Some(sender) = sender {
        let _ = sender.send(PrefetchStatus::Stored);
    }
    Ok(PrefetchOutcome::Stored(PrefetchedArtifactMetrics {
        crate_name: request.crate_name,
        c_metadata: request.c_metadata,
        parse_ms,
        verify_ms,
        store_ms,
    }))
}
