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

use stow_types::api::{EnqueueAdmission, EnqueueTicket};
use stow_types::pow::MAX_POW_DIFFICULTY;
use tokio::task::JoinHandle;
use zenwave::Client;

use crate::config::{DEFAULT_ADMISSION_DRAIN_TIMEOUT, StowConfig};

/// Collects miss admissions across the driver's graph analyses,
/// deduplicates them by task id, and redeems them from one background
/// worker while the build proceeds. All queued admissions are solved
/// sequentially on a single `spawn_blocking` task and posted from the same
/// worker — a large analysis never fans out into one task per admission.
///
/// Never touched from the per-rustc wrapper — the wrapper runs its own
/// minimal runtime per cargo invocation and must stay free of proof-of-work
/// work. The multi-thread driver runtime owns the worker; when the driver
/// returns, unfinished redemptions are abandoned (a re-miss simply mints a
/// fresh admission next run).
#[derive(Debug, Default)]
pub struct AdmissionCollector {
    seen: BTreeSet<String>,
    queued: Vec<EnqueueAdmission>,
    worker: Option<JoinHandle<()>>,
    config: Option<StowConfig>,
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
        let deadline = tokio::time::Instant::now()
            + self
                .config
                .as_ref()
                .map_or(DEFAULT_ADMISSION_DRAIN_TIMEOUT, |config| {
                    config.admission_drain_timeout
                });
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
        self.worker = Some(tokio::spawn(
            async move { redeem_batch(&config, batch).await },
        ));
    }
}

/// Solve every admission in `batch` on one blocking task, then post each
/// resulting ticket sequentially from this same worker.
async fn redeem_batch(config: &StowConfig, batch: Vec<EnqueueAdmission>) {
    let tickets = match tokio::task::spawn_blocking(move || solve_all(&batch)).await {
        Ok(tickets) => tickets,
        Err(error) => {
            tracing::warn!(%error, "enqueue admission solve task failed");
            return;
        }
    };
    for ticket in tickets {
        submit_ticket(config, &ticket).await;
    }
}

/// Sequential nonce scan over the whole batch. Admissions that cannot be
/// solved within the attempt bound are dropped — an expired challenge is
/// worthless, so giving up is the correct outcome.
fn solve_all(batch: &[EnqueueAdmission]) -> Vec<EnqueueTicket> {
    let mut tickets = Vec::with_capacity(batch.len());
    for admission in batch {
        let Some(nonce) = solve_nonce(admission) else {
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

/// Scan nonces for the admission's required leading-zero bits, trying at
/// most `2^(difficulty + 8)` candidates — roughly 256× the expected work —
/// before giving up. Difficulty 0 short-circuits to nonce 0.
fn solve_nonce(admission: &EnqueueAdmission) -> Option<u64> {
    if admission.difficulty == 0 {
        return Some(0);
    }
    solve_nonce_with_limit(admission, 1u64 << (admission.difficulty + 8))
}

fn solve_nonce_with_limit(admission: &EnqueueAdmission, attempts: u64) -> Option<u64> {
    (0..attempts).find(|nonce| {
        stow_types::pow::enqueue_pow_zero_bits(&admission.task_id, &admission.challenge, *nonce)
            >= admission.difficulty
    })
}

async fn submit_ticket(config: &StowConfig, ticket: &EnqueueTicket) {
    let url = format!("{}/api/v1/enqueue", config.edge_url.trim_end_matches('/'));
    let mut client = zenwave::client().timeout(config.request_timeout);
    let result = client
        .post(&url)
        .and_then(|request| request.json_body(ticket));
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

    use super::{AdmissionCollector, solve_nonce, solve_nonce_with_limit};
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

    #[test]
    fn solver_finds_nonce_at_difficulty_eight() {
        let admission = test_admission("serde-1.0.0-deadbeef-x86_64_unknown_linux_gnu-1_92_0", 8);
        let nonce = solve_nonce(&admission).expect("nonce found within bound");
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
        assert!(solve_nonce_with_limit(&admission, 0).is_none());
    }

    fn test_config() -> StowConfig {
        StowConfig {
            edge_url: "http://127.0.0.1:9".to_owned(),
            cache_dir: std::path::PathBuf::from("/tmp/stow-admission-test"),
            request_timeout: Duration::from_millis(50),
            negative_cache_ttl: Duration::from_secs(1),
            graph_cache_ttl: Duration::from_secs(1),
            circuit_reset_after: Duration::from_secs(1),
            circuit_trip_threshold: 1,
            artifact_cache_max_bytes: 1,
            verify_mode: VerifyMode::GithubCi,
            mock_public_key_path: None,
            admission_drain_timeout: Duration::from_secs(5),
            state_db_pool: StowConfig::default_state_db_pool(),
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
    async fn collector_skips_difficulty_above_the_cap() {
        let config = test_config();
        let mut collector = AdmissionCollector::default();

        collector.record(&config, [test_admission("task-hard", 25)]);

        assert_eq!(collector.queued.len(), 0);
        assert!(collector.worker.is_none());
        collector.drain().await;
    }
}
