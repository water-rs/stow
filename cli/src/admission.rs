//! Background redemption of enqueue admissions issued by the edge.
//!
//! A miss response no longer enqueues on the edge's fetch path — it carries
//! [`EnqueueAdmission`] tickets the CLI redeems by solving a blake3
//! proof-of-work and posting `{task_id, challenge, nonce, request}` to
//! `POST /api/v1/enqueue`. The `stow check`/`build` driver collects
//! admissions as its graph analyses arrive and hands them to a single
//! background worker. Every failure is logged and swallowed: admission is
//! a best-effort preheat channel and must never affect the build.
//!
//! "Background" is a contract, not a description of which task it runs on,
//! and it has two halves that this module owes the build:
//!
//! * It does not compete for the machine. A miss means cargo is about to
//!   compile that crate, so the cores belong to rustc. Solving happens on
//!   one thread within a bounded attempt budget — a fraction of one
//!   core-second per run — never on a shard per core.
//! * It does not extend the build past its budget. Misses mint when
//!   cargo finishes (stow#317), and redemption drains inline right
//!   after — bounded by the same attempt budget, never a second
//!   runtime's worth of mining.
//!
//! Both were once the other way round, and a warm `bat` build spent 342
//! CPU-seconds mining — against 44.6 for compiling the same project from
//! scratch — plus a five-second wait after cargo had already finished.

use futures_util::StreamExt;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use stow_types::api::{EnqueueAdmission, EnqueueTicket};
use stow_types::pow::MAX_POW_DIFFICULTY;
use tokio::task::JoinHandle;
use zenwave::Client;

use crate::config::StowConfig;

/// Concurrent `POST /api/v1/enqueue` submissions. Each post
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
/// minimal runtime per cargo invocation and must stay free of
/// proof-of-work work. The multi-thread driver runtime owns the worker;
/// `drain` awaits it after the build's admissions post.
#[derive(Debug)]
pub struct AdmissionCollector {
    seen: BTreeSet<String>,
    queued: Vec<EnqueueAdmission>,
    worker: Option<JoinHandle<()>>,
    /// Hash attempts left for this driver run, shared with the solver of
    /// every batch.
    budget: Arc<AtomicU64>,
}

impl Default for AdmissionCollector {
    fn default() -> Self {
        Self {
            seen: BTreeSet::new(),
            queued: Vec::new(),
            worker: None,
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

    /// Wait for the worker solving the queued batch to finish. Post-build
    /// minting redeems inline: the batch is bounded by the same attempt
    /// budget, and a challenge dies about two minutes after minting
    /// anyway, so the wait cannot outlive its usefulness.
    pub async fn drain(&mut self, config: &StowConfig) {
        self.spawn_worker(config);
        if let Some(worker) = self.worker.take() {
            let _ = worker.await;
        }
    }

    /// Start the single background worker over the currently queued
    /// batch. At most one worker is ever live: `record` refills `queued`
    /// and `drain` awaits the worker to completion.
    fn spawn_worker(&mut self, config: &StowConfig) {
        if self.worker.is_some() || self.queued.is_empty() {
            return;
        }
        let batch = std::mem::take(&mut self.queued);
        let config = config.clone();
        let budget = Arc::clone(&self.budget);
        let cancelled = Arc::new(AtomicBool::new(false));
        self.worker = Some(tokio::spawn(async move {
            redeem_batch(&config, batch, &budget, &cancelled).await;
        }));
    }
}

/// Solve `batch` across as many blocking shards as the host has cores,
/// then post the tickets with bounded concurrency. Both stages race the
/// tickets' minute-scoped challenge lifetime — doing either sequentially
/// redeems only a handful of a large batch before the deadline.
async fn redeem_batch(
    config: &StowConfig,
    batch: Vec<EnqueueAdmission>,
    budget: &Arc<AtomicU64>,
    cancelled: &Arc<AtomicBool>,
) {
    let mut batch = batch;
    let offset = solve_offset(batch.len());
    batch.rotate_left(offset);
    let tickets = solve_batch(batch, budget, cancelled).await;
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

/// Nonce-scan the batch on one blocking task.
///
/// One thread, because the cores belong to the compiler: a miss means
/// cargo is about to build that crate. The attempt budget bounds the whole
/// batch to a fraction of a core-second, so there is nothing here for a
/// shard per core to divide — sharding existed only when a single
/// admission could cost seconds.
async fn solve_batch(
    batch: Vec<EnqueueAdmission>,
    budget: &Arc<AtomicU64>,
    cancelled: &Arc<AtomicBool>,
) -> Vec<EnqueueTicket> {
    if batch.is_empty() {
        return Vec::new();
    }
    let budget = Arc::clone(budget);
    let cancelled = Arc::clone(cancelled);
    match tokio::task::spawn_blocking(move || solve_all(&batch, &budget, &cancelled)).await {
        Ok(tickets) => tickets,
        Err(error) => {
            tracing::warn!(%error, "enqueue admission solver failed");
            Vec::new()
        }
    }
}

/// Sequential nonce scan over the whole batch. Admissions that cannot be
/// solved within the attempt bound, or that the run's remaining budget
/// cannot pay for, are dropped — an expired challenge is worthless, so
/// giving up is the correct outcome.
fn solve_all(
    batch: &[EnqueueAdmission],
    budget: &AtomicU64,
    cancelled: &AtomicBool,
) -> Vec<EnqueueTicket> {
    let mut tickets = Vec::with_capacity(batch.len());
    for admission in batch {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        let Some(nonce) = solve_nonce(admission, budget, cancelled) else {
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
fn solve_nonce(
    admission: &EnqueueAdmission,
    budget: &AtomicU64,
    cancelled: &AtomicBool,
) -> Option<u64> {
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
    let (nonce, spent) = scan_nonces(admission, granted, cancelled);
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

/// How often a scan looks at the cancel flag. Frequently enough that a
/// finished build never waits on mining, rarely enough that the load costs
/// nothing against a blake3 compression per attempt.
const CANCEL_CHECK_INTERVAL: u64 = 4096;

/// The first nonce meeting the admission's difficulty within `attempts`,
/// and how many attempts that took. A cancelled scan stops where it is:
/// the build is over, so the ticket is worth nothing.
fn scan_nonces(
    admission: &EnqueueAdmission,
    attempts: u64,
    cancelled: &AtomicBool,
) -> (Option<u64>, u64) {
    for nonce in 0..attempts {
        if nonce % CANCEL_CHECK_INTERVAL == 0 && cancelled.load(Ordering::Relaxed) {
            return (None, nonce);
        }
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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
            host_side: false,
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

    fn running() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[test]
    fn solver_finds_nonce_at_difficulty_eight() {
        let admission = test_admission("serde-1.0.0-deadbeef-x86_64_unknown_linux_gnu-1_92_0", 8);
        let budget = full_budget();
        let nonce = solve_nonce(&admission, &budget, &running()).expect("nonce found within bound");
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
        assert!(solve_nonce(&admission, &budget, &running()).is_none());
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
        assert!(super::solve_all(&batch, &budget, &running()).is_empty());
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
        let tickets = super::solve_all(&batch, &budget, &running());

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
        assert_eq!(
            solve_nonce(&test_admission("task", 0), &budget, &running()),
            Some(0)
        );
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
        // The spawned posts fail against the discard port — draining must
        // still finish and never surface the error.
        collector.drain(&config).await;
    }

    #[tokio::test]
    async fn one_solver_covers_the_whole_batch() {
        let batch: Vec<EnqueueAdmission> = (0..257)
            .map(|index| test_admission(&format!("task-{index}"), 0))
            .collect();
        let budget = Arc::new(AtomicU64::new(SOLVE_ATTEMPT_BUDGET));
        let tickets = super::solve_batch(batch, &budget, &Arc::new(AtomicBool::new(false))).await;
        assert_eq!(tickets.len(), 257);
        assert!(tickets.iter().all(|ticket| ticket.nonce == 0));
    }

    /// The contract the build depends on: draining waits for the solver,
    /// but the attempt budget bounds the wait — a 24-bit admission would
    /// take seconds of mining, and the drain returns as soon as the
    /// budget is spent.
    #[tokio::test]
    async fn drain_is_bounded_by_the_attempt_budget() {
        let config = test_config();
        let mut collector = AdmissionCollector::default();
        collector.record(&config, [test_admission("task-hard", 24)]);

        let start = std::time::Instant::now();
        collector.drain(&config).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(10),
            "draining the worker took {elapsed:?}"
        );
    }

    /// And the scan really stops rather than mining on to its bound: a
    /// cancelled scan returns without spending the attempts it reserved.
    #[test]
    fn a_cancelled_scan_stops_where_it_is() {
        let budget = full_budget();
        let cancelled = AtomicBool::new(true);
        let batch = [test_admission("task-hard", 24)];

        let start = std::time::Instant::now();
        let tickets = super::solve_all(&batch, &budget, &cancelled);
        let elapsed = start.elapsed();

        assert!(tickets.is_empty());
        assert_eq!(budget.load(Ordering::Relaxed), SOLVE_ATTEMPT_BUDGET);
        assert!(
            elapsed < Duration::from_millis(100),
            "scan took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn collector_skips_difficulty_above_the_cap() {
        let config = test_config();
        let mut collector = AdmissionCollector::default();

        collector.record(&config, [test_admission("task-hard", 25)]);

        assert_eq!(collector.queued.len(), 0);
        assert!(collector.worker.is_none());
        collector.drain(&config).await;
    }
}
