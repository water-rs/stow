//! Background redemption of enqueue admissions issued by the edge.
//!
//! A miss response no longer enqueues on the edge's fetch path — it carries
//! [`EnqueueAdmission`] tickets the CLI redeems by solving a blake3
//! proof-of-work and posting `{task_id, challenge, nonce}` to
//! `POST /api/v1/enqueue`. The `stow check`/`build` driver collects
//! admissions as its graph analyses arrive and hands them to spawned
//! background tasks, so solving overlaps the cargo build and never
//! perturbs the per-rustc wrapper hot path. Every failure is logged and
//! swallowed: admission is a best-effort preheat channel and must never
//! affect the build.

use std::collections::BTreeSet;

use stow_types::api::{EnqueueAdmission, EnqueueTicket};
use tokio::task::JoinSet;
use zenwave::Client;

use crate::config::StowConfig;

/// Collects miss admissions across the driver's graph analyses,
/// deduplicates them by task id, and redeems each on a spawned background
/// task while the build proceeds.
///
/// Never touched from the per-rustc wrapper — the wrapper runs its own
/// minimal runtime per cargo invocation and must stay free of proof-of-work
/// work. The multi-thread driver runtime owns every spawned task; when the
/// driver returns, unfinished redemptions are abandoned (a re-miss simply
/// mints a fresh admission next run).
#[derive(Debug, Default)]
pub struct AdmissionCollector {
    seen: BTreeSet<String>,
    pending: JoinSet<()>,
}

impl AdmissionCollector {
    /// Queue freshly-seen admissions for background solving + posting.
    /// Repeat task ids (multiple analyses, mirror builds) are dropped so
    /// each task is solved and posted at most once per driver run.
    pub fn record(
        &mut self,
        config: &StowConfig,
        admissions: impl IntoIterator<Item = EnqueueAdmission>,
    ) {
        for admission in admissions {
            if !self.seen.insert(admission.task_id.clone()) {
                continue;
            }
            let config = config.clone();
            self.pending
                .spawn(async move { solve_and_submit(&config, &admission).await });
        }
    }

    /// Wait for every outstanding solve+post task. Called once the build
    /// finishes so the driver does not exit with redemptions in flight.
    pub async fn drain(&mut self) {
        while self.pending.join_next().await.is_some() {}
    }
}

/// Solve one admission's proof-of-work and redeem it. Difficulty 0 means
/// the queue was shallow when the edge minted the ticket — the enqueue is
/// posted immediately without searching for a nonce.
async fn solve_and_submit(config: &StowConfig, admission: &EnqueueAdmission) {
    let nonce = if admission.difficulty == 0 {
        0
    } else {
        let task_id = admission.task_id.clone();
        let admission = admission.clone();
        match tokio::task::spawn_blocking(move || solve_nonce(&admission)).await {
            Ok(nonce) => nonce,
            Err(error) => {
                tracing::warn!(task_id = %task_id, %error, "enqueue admission solve task failed");
                return;
            }
        }
    };
    submit_ticket(config, admission, nonce).await;
}

/// Sequential nonce scan for the admission's required leading-zero bits —
/// deterministic, bounded in practice by the edge's 24-bit difficulty cap,
/// and identical to the digest the edge recomputes on redemption.
fn solve_nonce(admission: &EnqueueAdmission) -> u64 {
    let mut nonce = 0u64;
    loop {
        if stow_types::pow::enqueue_pow_zero_bits(&admission.task_id, &admission.challenge, nonce)
            >= admission.difficulty
        {
            return nonce;
        }
        nonce += 1;
    }
}

async fn submit_ticket(config: &StowConfig, admission: &EnqueueAdmission, nonce: u64) {
    let url = format!("{}/api/v1/enqueue", config.edge_url.trim_end_matches('/'));
    let ticket = EnqueueTicket {
        task_id: admission.task_id.clone(),
        challenge: admission.challenge.clone(),
        nonce,
    };
    let mut client = zenwave::client().timeout(config.request_timeout);
    let result = client
        .post(&url)
        .and_then(|request| request.json_body(&ticket));
    match result {
        Ok(request) => match request.await {
            Ok(_) => {
                tracing::debug!(task_id = %admission.task_id, "redeemed enqueue admission");
            }
            Err(error) => {
                tracing::warn!(
                    task_id = %admission.task_id,
                    %error,
                    "enqueue admission post failed"
                );
            }
        },
        Err(error) => {
            tracing::warn!(
                task_id = %admission.task_id,
                %error,
                "failed to build enqueue admission request"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use stow_types::api::EnqueueAdmission;

    use super::{AdmissionCollector, solve_nonce};
    use crate::config::{StowConfig, VerifyMode};

    #[test]
    fn solver_finds_nonce_at_difficulty_eight() {
        let admission = EnqueueAdmission {
            task_id: "serde-1.0.0-deadbeef-x86_64_unknown_linux_gnu-1_92_0".to_owned(),
            challenge: "abcdef0123456789".to_owned(),
            difficulty: 8,
        };
        let nonce = solve_nonce(&admission);
        assert!(
            stow_types::pow::enqueue_pow_zero_bits(&admission.task_id, &admission.challenge, nonce,)
                >= 8
        );
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
            state_db_pool: StowConfig::default_state_db_pool(),
        }
    }

    #[tokio::test]
    async fn collector_deduplicates_by_task_id() {
        let config = test_config();
        let mut collector = AdmissionCollector::default();
        let admission = EnqueueAdmission {
            task_id: "task-1".to_owned(),
            challenge: "00".to_owned(),
            difficulty: 0,
        };

        collector.record(&config, [admission.clone()]);
        collector.record(&config, [admission.clone()]);
        collector.record(
            &config,
            [EnqueueAdmission {
                task_id: "task-2".to_owned(),
                ..admission
            }],
        );

        assert_eq!(collector.seen.len(), 2);
        assert_eq!(collector.pending.len(), 2);
        // The spawned posts fail against the discard port — drain must still
        // finish and never surface the error.
        collector.drain().await;
    }
}
