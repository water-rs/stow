//! Background redemption of enqueue admissions issued by the edge.
//!
//! A miss response no longer enqueues on the edge's fetch path — it carries
//! [`EnqueueAdmission`] tickets the CLI redeems by solving a blake3
//! proof-of-work and posting `{task_id, challenge, nonce, request}` to
//! `POST /api/v1/enqueue`. The `stow check`/`build` driver collects
//! admissions as its graph analyses arrive and hands them to a single
//! background worker, so solving overlaps the cargo build and never
//! perturbs the per-rustc wrapper hot path. Every failure is logged and
//! swallowed: admission is a best-effort preheat channel and must never
//! affect the build.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use stow_types::api::{EnqueueAdmission, EnqueueTicket};
use stow_types::pow::MAX_POW_DIFFICULTY;
use tokio::task::JoinHandle;
use zenwave::Client;

use crate::config::{DEFAULT_ADMISSION_DRAIN_TIMEOUT, StowConfig};

/// `stow predict`'s admission drain budget. Predicting exists to redeem
/// the admissions its analysis mints, so its deadline is sized to the
/// tickets' lifetime rather than the build-side courtesy window:
/// challenges are minute-scoped and die about two minutes after the edge
/// minted them, leaving roughly this much once analysis returns.
pub const PREDICT_ADMISSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(100);

/// Concurrent `POST /api/v1/enqueue` submissions during a drain. Each post
/// is a fresh TLS connection, so a sequential loop redeems only a handful
/// of tickets before the drain deadline; the edge is a Worker and absorbs
/// this fan-out trivially.
const SUBMIT_CONCURRENCY: usize = 64;

/// Hash attempts one driver run may spend redeeming admissions, across
/// every batch and every shard.
///
/// Difficulty is the edge's price for queue depth, and the honest client
/// response to a high price is to stop buying rather than to pay it: an
/// admission is a best-effort preheat request for work a deep queue
/// already holds thousands of, and its challenge dies about two minutes
/// after it is minted.
///
/// Without a budget the build paid that price in full. With the queue
/// 3 059 tasks deep the edge mints the 24-bit cap — `2^24` expected
/// hashes per admission — and a warm 108-crate build of `bat`, serving
/// every unit from cache, burned **342 CPU-seconds**, of which `perf` put
/// 78 % in `blake3_compress_in_place`. Plain `cargo build` compiles the
/// same project from scratch in 44.6 CPU-seconds. The cache was losing to
/// the compiler because it was mining.
///
/// `2^22` attempts is about a third of a core-second: it redeems a large
/// batch outright while the queue is shallow (12 bits: 4 096 expected
/// hashes each), and buys nothing once the queue is deep, which is the
/// answer a deep queue is asking for.
const SOLVE_ATTEMPT_BUDGET: u64 = 1 << 22;

/// Headroom over an admission's expected `2^difficulty` attempts before
/// the scan gives up on it. A nonce scan is geometric, so four times the
/// expectation finds one for about 98 % of admissions; the old `256×`
/// bound instead let a single unsolvable 24-bit admission consume `2^32`
/// hashes — seven core-minutes for one preheat request.
const ATTEMPT_HEADROOM_BITS: u32 = 2;

/// Collects miss admissions across the driver's graph analyses,
/// deduplicates them by task id, and redeems them from one background
/// worker while the build proceeds. Queued admissions are solved on
/// `available_parallelism` blocking shards and posted with bounded
/// concurrency — a large analysis never fans out into one task per
/// admission, but a single sequential worker could never finish a
/// multi-thousand-ticket batch inside the tickets' ~2-minute lifetime.
///
/// Never touched from the per-rustc wrapper — the wrapper runs its own
/// minimal runtime per cargo invocation and must stay free of proof-of-work
/// work. The multi-thread driver runtime owns the worker; when the driver
/// returns, unfinished redemptions are abandoned (a re-miss simply mints a
/// fresh admission next run).
#[derive(Debug)]
pub struct AdmissionCollector {
    seen: BTreeSet<String>,
    queued: Vec<EnqueueAdmission>,
    worker: Option<JoinHandle<()>>,
    config: Option<StowConfig>,
    /// Hash attempts left for this driver run, shared with every solver
    /// shard of every batch.
    budget: Arc<AtomicU64>,
}

impl Default for AdmissionCollector {
    fn default() -> Self {
        Self {
            seen: BTreeSet::new(),
            queued: Vec::new(),
            worker: None,
            config: None,
            budget: Arc::new(AtomicU64::new(SOLVE_ATTEMPT_BUDGET)),
        }
    }
}

impl AdmissionCollector {
    /// Queue freshly-seen admissions for background solving + posting.
    /// Repeat task ids (multiple analyses, mirror builds) are dropped so
    /// each task is solved and posted at most once per driver run, and
    /// admissions demanding more than [`MAX_POW_DIFFICULTY`] bits are
    /// refused — an expired challenge is worthless anyway.
    pub fn record(
        &mut self,
        config: &StowConfig,
        admissions: impl IntoIterator<Item = EnqueueAdmission>,
    ) {
        self.config = Some(config.clone());
        for admission in admissions {
            if !self.seen.insert(admission.task_id.clone()) {
                continue;
            }
            if admission.difficulty > MAX_POW_DIFFICULTY {
                tracing::warn!(
                    task_id = %admission.task_id,
                    difficulty = admission.difficulty,
                    max = MAX_POW_DIFFICULTY,
                    "skipping enqueue admission above maximum difficulty"
                );
                continue;
            }
            self.queued.push(admission);
        }
        self.spawn_worker(config);
    }

    /// Wait for the outstanding worker — including any batches queued
    /// while it ran — up to `admission_drain_timeout`. Called once the
    /// build finishes so the driver does not exit with redemptions in
    /// flight; whatever is left at the deadline is abandoned.
    pub async fn drain(&mut self) {
        let timeout = self
            .config
            .as_ref()
            .map_or(DEFAULT_ADMISSION_DRAIN_TIMEOUT, |config| {
                config.admission_drain_timeout
            });
        self.drain_for(timeout).await;
    }

    /// `drain` with an explicit deadline. `predict` uses this because its
    /// whole purpose is redeeming the admissions it minted — the
    /// build-side timeout would abandon nearly the whole batch.
    pub async fn drain_for(&mut self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.worker.is_none() {
                let Some(config) = self.config.clone() else {
                    return;
                };
                self.spawn_worker(&config);
            }
            let Some(mut worker) = self.worker.take() else {
                return;
            };
            match tokio::time::timeout_at(deadline, &mut worker).await {
                Ok(Err(error)) => {
                    tracing::warn!(%error, "enqueue admission worker failed");
                }
                Ok(Ok(())) => {}
                Err(_) => {
                    worker.abort();
                    tracing::debug!(
                        queued = self.queued.len(),
                        "abandoning unfinished enqueue admissions at drain deadline"
                    );
                    self.queued.clear();
                    return;
                }
            }
        }
    }

    /// Start the single background worker over the currently queued batch.
    /// Admissions recorded while a worker runs stay queued and are picked
    /// up by a follow-up worker inside `drain`, so at most one worker is
    /// ever live.
    fn spawn_worker(&mut self, config: &StowConfig) {
        if self.worker.is_some() || self.queued.is_empty() {
            return;
        }
        let batch = std::mem::take(&mut self.queued);
        let config = config.clone();
        let budget = Arc::clone(&self.budget);
        self.worker = Some(tokio::spawn(async move {
            redeem_batch(&config, batch, &budget).await;
        }));
    }
}

/// Solve `batch` across as many blocking shards as the host has cores,
/// then post the tickets with bounded concurrency. Both stages race the
/// tickets' minute-scoped challenge lifetime — doing either sequentially
/// redeems only a handful of a large batch before the deadline.
async fn redeem_batch(config: &StowConfig, batch: Vec<EnqueueAdmission>, budget: &Arc<AtomicU64>) {
    let mut batch = batch;
    let offset = solve_offset(batch.len());
    batch.rotate_left(offset);
    let tickets = solve_sharded(batch, budget).await;
    futures_util::stream::iter(tickets)
        .for_each_concurrent(SUBMIT_CONCURRENCY, |ticket| submit_ticket(config, ticket))
        .await;
}

/// Where in the batch this run starts solving.
///
/// The budget stops the solver partway through a batch larger than it can
/// pay for, and a batch is ordered by discovery, so starting at index zero
/// every time redeems the same early admissions on every run and never
/// attempts the tail at all — those artifacts stay uncovered and re-miss
/// identically for ever. At the production floor of 12 bits the budget
/// reaches about a thousand admissions, which a cold large workspace
/// exceeds. Starting at a rotating offset lets successive runs drain the
/// whole set instead.
fn solve_offset(len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    usize::try_from(nanos).unwrap_or(0) % len
}

/// Split `batch` into per-core shards and nonce-scan them on blocking
/// tasks. A single solver thread is fine for the build path's trickle of
/// tickets but cannot start a `predict`-sized batch within its lifetime.
async fn solve_sharded(
    batch: Vec<EnqueueAdmission>,
    budget: &Arc<AtomicU64>,
) -> Vec<EnqueueTicket> {
    if batch.is_empty() {
        return Vec::new();
    }
    let shards = std::thread::available_parallelism()
        .map_or(1, NonZeroUsize::get)
        .min(batch.len());
    let chunk_len = batch.len().div_ceil(shards);
    let mut handles = Vec::with_capacity(shards);
    for chunk in batch.chunks(chunk_len) {
        let chunk = chunk.to_vec();
        let budget = Arc::clone(budget);
        handles.push(tokio::task::spawn_blocking(move || {
            solve_all(&chunk, &budget)
        }));
    }
    let mut tickets = Vec::with_capacity(batch.len());
    for handle in handles {
        match handle.await {
            Ok(shard_tickets) => tickets.extend(shard_tickets),
            Err(error) => {
                tracing::warn!(%error, "enqueue admission solve shard failed");
            }
        }
    }
    tickets
}

/// Sequential nonce scan over the whole batch. Admissions that cannot be
/// solved within the attempt bound, or that the run's remaining budget
/// cannot pay for, are dropped — an expired challenge is worthless, so
/// giving up is the correct outcome.
fn solve_all(batch: &[EnqueueAdmission], budget: &AtomicU64) -> Vec<EnqueueTicket> {
    let mut tickets = Vec::with_capacity(batch.len());
    for admission in batch {
        let Some(nonce) = solve_nonce(admission, budget) else {
            tracing::warn!(
                task_id = %admission.task_id,
                difficulty = admission.difficulty,
                "enqueue admission unsolved within nonce bound; abandoning"
            );
            continue;
        };
        tickets.push(EnqueueTicket {
            task_id: admission.task_id.clone(),
            challenge: admission.challenge.clone(),
            nonce,
            request: admission.request.clone(),
        });
    }
    tickets
}

/// Scan nonces for the admission's required leading-zero bits, spending
/// at most `2^(difficulty + ATTEMPT_HEADROOM_BITS)` attempts and never
/// more than the run's remaining budget. Difficulty 0 short-circuits to
/// nonce 0 and costs nothing. Whatever the scan does not use is returned
/// to the budget, so an easy batch is not charged for the headroom it
/// never needed.
fn solve_nonce(admission: &EnqueueAdmission, budget: &AtomicU64) -> Option<u64> {
    if admission.difficulty == 0 {
        return Some(0);
    }
    let want = 1u64
        .checked_shl(admission.difficulty + ATTEMPT_HEADROOM_BITS)
        .unwrap_or(u64::MAX);
    let granted = take_attempts(budget, want);
    if granted == 0 {
        tracing::debug!(
            task_id = %admission.task_id,
            difficulty = admission.difficulty,
            "admission proof-of-work budget spent; leaving this preheat request unredeemed"
        );
        return None;
    }
    let (nonce, spent) = scan_nonces(admission, granted);
    budget.fetch_add(granted - spent, Ordering::Relaxed);
    nonce
}

/// Reserve up to `want` attempts from the shared budget, returning what
/// the budget could pay — zero when it is spent.
fn take_attempts(budget: &AtomicU64, want: u64) -> u64 {
    let mut remaining = budget.load(Ordering::Relaxed);
    loop {
        let granted = want.min(remaining);
        if granted == 0 {
            return 0;
        }
        match budget.compare_exchange_weak(
            remaining,
            remaining - granted,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return granted,
            Err(actual) => remaining = actual,
        }
    }
}

/// The first nonce meeting the admission's difficulty within `attempts`,
/// and how many attempts that took.
fn scan_nonces(admission: &EnqueueAdmission, attempts: u64) -> (Option<u64>, u64) {
    for nonce in 0..attempts {
        if stow_types::pow::enqueue_pow_zero_bits(&admission.task_id, &admission.challenge, nonce)
            >= admission.difficulty
        {
            return (Some(nonce), nonce + 1);
        }
    }
    (None, attempts)
}

async fn submit_ticket(config: &StowConfig, ticket: EnqueueTicket) {
    let url = format!("{}/api/v1/enqueue", config.edge_url.trim_end_matches('/'));
    let mut client = crate::edge_client::client(config);
    let result = client
        .post(&url)
        .and_then(|request| request.json_body(&ticket));
    match result {
        Ok(request) => match request.await {
            Ok(_) => {
                tracing::debug!(task_id = %ticket.task_id, "redeemed enqueue admission");
            }
            Err(error) => {
                tracing::warn!(
                    task_id = %ticket.task_id,
                    %error,
                    "enqueue admission post failed"
                );
            }
        },
        Err(error) => {
            tracing::warn!(
                task_id = %ticket.task_id,
                %error,
                "failed to build enqueue admission request"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use stow_types::api::{EnqueueAdmission, EnqueueRequest, EnqueueSource};

    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{AdmissionCollector, SOLVE_ATTEMPT_BUDGET, solve_nonce};
    use crate::config::{StowConfig, VerifyMode};

    fn test_request() -> EnqueueRequest {
        EnqueueRequest {
            crate_name: "serde".parse().expect("crate name"),
            version: "1.0.0".parse().expect("version"),
            features_json: stow_types::identity::FeaturesJson::canonicalize(Vec::new())
                .expect("features"),
            target: "x86_64-unknown-linux-gnu".parse().expect("target"),
            rustc_version: "1.92.0".parse().expect("rustc"),
            downloads: 0,
            source: EnqueueSource::CacheMiss,
            depends_on: Vec::new(),
            preserve_lockfile: false,
            project_source: None,
        }
    }

    fn test_admission(task_id: &str, difficulty: u32) -> EnqueueAdmission {
        EnqueueAdmission {
            task_id: task_id.to_owned(),
            challenge: "abcdef0123456789".to_owned(),
            difficulty,
            request: test_request(),
        }
    }

    fn full_budget() -> AtomicU64 {
        AtomicU64::new(SOLVE_ATTEMPT_BUDGET)
    }

    #[test]
    fn solver_finds_nonce_at_difficulty_eight() {
        let admission = test_admission("serde-1.0.0-deadbeef-x86_64_unknown_linux_gnu-1_92_0", 8);
        let budget = full_budget();
        let nonce = solve_nonce(&admission, &budget).expect("nonce found within bound");
        assert!(
            stow_types::pow::enqueue_pow_zero_bits(&admission.task_id, &admission.challenge, nonce,)
                >= 8
        );
    }

    #[test]
    fn solver_respects_the_attempt_bound() {
        // An empty attempt window can never produce a nonce — the scan
        // terminates with `None` rather than looping forever.
        let admission = test_admission("task-that-cannot-solve", 8);
        let budget = AtomicU64::new(0);
        assert!(solve_nonce(&admission, &budget).is_none());
    }

    /// A spent budget is the whole point: the build must not keep mining
    /// once it has paid what a run is worth, however many admissions are
    /// still queued.
    #[test]
    fn an_exhausted_budget_stops_the_solver() {
        let budget = AtomicU64::new(0);
        let batch: Vec<EnqueueAdmission> = (0..8)
            .map(|index| test_admission(&format!("task-{index}"), 8))
            .collect();
        assert!(super::solve_all(&batch, &budget).is_empty());
        assert_eq!(budget.load(Ordering::Relaxed), 0);
    }

    /// The headroom is reserved, not spent: a batch of easy admissions
    /// must not charge the budget for attempts no scan ever ran.
    #[test]
    fn unused_attempts_return_to_the_budget() {
        let budget = full_budget();
        let batch: Vec<EnqueueAdmission> = (0..16)
            .map(|index| test_admission(&format!("task-{index}"), 4))
            .collect();
        let tickets = super::solve_all(&batch, &budget);

        // Fifteen of the sixteen fixtures find a nonce inside the 4x
        // headroom; the sixteenth is the ~2 % tail a geometric scan leaves
        // at that bound, and abandoning it is the intended outcome for a
        // best-effort preheat request.
        assert_eq!(tickets.len(), 15);
        let spent = SOLVE_ATTEMPT_BUDGET - budget.load(Ordering::Relaxed);
        // Sixteen admissions at four bits cost about sixteen attempts
        // each; the reserved headroom is 64 per admission, so charging
        // the reservation would spend 1024.
        assert!(
            spent < 400,
            "spent {spent} attempts on sixteen 4-bit admissions"
        );
    }

    /// Difficulty 0 is the shallow-queue case and must stay free: it is
    /// what a healthy fleet mints, and it never touches the budget.
    /// The offset has to land inside the batch, and an empty batch has
    /// nowhere to start.
    #[test]
    fn the_solve_offset_stays_inside_the_batch() {
        assert_eq!(super::solve_offset(0), 0);
        for len in 1..64 {
            assert!(super::solve_offset(len) < len, "offset escaped len {len}");
        }
    }

    /// Rotating changes where solving starts, never which admissions are
    /// in the batch.
    #[test]
    fn rotating_the_batch_keeps_every_admission() {
        let mut batch: Vec<EnqueueAdmission> = (0..10)
            .map(|index| test_admission(&format!("task-{index}"), 0))
            .collect();
        let offset = super::solve_offset(batch.len());
        batch.rotate_left(offset);
        let mut ids: Vec<&str> = batch.iter().map(|a| a.task_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids.len(), 10);
        assert_eq!(ids[0], "task-0");
        assert_eq!(ids[9], "task-9");
    }

    #[test]
    fn a_free_admission_costs_no_budget() {
        let budget = full_budget();
        assert_eq!(solve_nonce(&test_admission("task", 0), &budget), Some(0));
        assert_eq!(budget.load(Ordering::Relaxed), SOLVE_ATTEMPT_BUDGET);
    }

    fn test_config() -> StowConfig {
        StowConfig {
            edge_url: "http://127.0.0.1:9".to_owned(),
            registry_base_url: "http://127.0.0.1:9/v2/water-rs/stow-cache".to_owned(),
            cache_dir: std::path::PathBuf::from("/tmp/stow-admission-test"),
            request_timeout: Duration::from_millis(50),
            negative_cache_ttl: Duration::from_secs(1),
            circuit_reset_after: Duration::from_secs(1),
            circuit_trip_threshold: 1,
            artifact_cache_max_bytes: 1,
            index_refresh_interval: Duration::from_secs(1),
            verify_mode: VerifyMode::GithubCi,
            admission_drain_timeout: Duration::from_secs(5),
            state_db_pool: StowConfig::default_state_db_pool(),
            trust_material: std::sync::Arc::default(),
        }
    }

    #[tokio::test]
    async fn collector_deduplicates_by_task_id() {
        let config = test_config();
        let mut collector = AdmissionCollector::default();

        collector.record(&config, [test_admission("task-1", 0)]);
        collector.record(&config, [test_admission("task-1", 0)]);
        collector.record(&config, [test_admission("task-2", 0)]);

        assert_eq!(collector.seen.len(), 2);
        // The spawned posts fail against the discard port — drain must still
        // finish and never surface the error.
        collector.drain().await;
    }

    #[tokio::test]
    async fn sharded_solve_covers_the_whole_batch() {
        let batch: Vec<EnqueueAdmission> = (0..257)
            .map(|index| test_admission(&format!("task-{index}"), 0))
            .collect();
        let budget = Arc::new(AtomicU64::new(SOLVE_ATTEMPT_BUDGET));
        let tickets = super::solve_sharded(batch, &budget).await;
        assert_eq!(tickets.len(), 257);
        assert!(tickets.iter().all(|ticket| ticket.nonce == 0));
    }

    #[tokio::test]
    async fn collector_skips_difficulty_above_the_cap() {
        let config = test_config();
        let mut collector = AdmissionCollector::default();

        collector.record(&config, [test_admission("task-hard", 25)]);

        assert_eq!(collector.queued.len(), 0);
        assert!(collector.worker.is_none());
        collector.drain().await;
    }
}
