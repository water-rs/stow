//! Bounded CI dispatch with a durable API recovery fence.

use futures_util::stream::{FuturesUnordered, StreamExt as _};
use skyzen_services::durable::DurableDb;
use stow_types::api::SchedulerEvent;
use stow_types::ci::{CiInterface, CiTransport, DispatchError};

use crate::errors::QueueError;
use crate::scheduler::{graph, queue, routes};

/// Persist the API recovery fence before any subsequent request may start.
///
/// # Errors
/// Returns the storage error if the recovery event cannot be appended.
pub async fn retain_ci_limit(
    graph: graph::LoadedGraph<'_>,
    db: &DurableDb,
    error: &DispatchError,
    now: i64,
) -> Result<bool, QueueError> {
    use stow_types::transient::RateLimit;
    let Some(limit) = error.rate_limit(now / 1_000) else {
        return Ok(false);
    };
    let wait = match limit {
        RateLimit::Wait { wait, .. } => wait,
        RateLimit::Unstated => {
            std::time::Duration::from_mins(u64::from(queue::dispatch_backoff_minutes(0)))
        }
    };
    let until = now.saturating_add(i64::try_from(wait.as_millis()).unwrap_or(i64::MAX));
    routes::commit(graph, db, &[SchedulerEvent::CiRateLimited { until }], now).await?;
    Ok(true)
}

struct ClaimOutcome {
    order: usize,
    claim: graph::Claimed,
    result: std::result::Result<stow_types::ci::DispatchedRun, DispatchError>,
}

/// Construct each payload only after admitting its outbound slot.
async fn submit_claim<T: CiTransport>(
    graph: graph::LoadedGraph<'_>,
    backend: &CiInterface<T>,
    order: usize,
    claim: graph::Claimed,
) -> Result<ClaimOutcome, QueueError> {
    let encoded = graph
        .with(|graph| graph.claimed_payload(&claim))?
        .encode_dispatch_task()
        .map_err(|error| DispatchError::Response(format!("encode task: {error}")));
    let outcome = match encoded {
        Ok(encoded) => backend.submit(&encoded).await,
        Err(error) => Err(error),
    };
    Ok(ClaimOutcome {
        order,
        claim,
        result: outcome,
    })
}

/// At most four requests are active. Observe each completion immediately so
/// a rate-limit refusal prevents any further admission, then drain the active
/// requests and apply their results in claim order.
///
/// # Errors
/// Returns a payload invariant or storage error; accepted unbound runs remain
/// recoverable through the persisted claims and normal run reconciliation.
pub async fn dispatch_claims<T: CiTransport>(
    graph: graph::LoadedGraph<'_>,
    db: &DurableDb,
    backend: &CiInterface<T>,
    claims: Vec<graph::Claimed>,
    now: impl Fn() -> i64,
) -> Result<(), QueueError> {
    let mut pending = claims.into_iter().enumerate();
    let mut active = FuturesUnordered::new();
    for (order, claim) in pending
        .by_ref()
        .take(crate::fetch_guard::MAX_OUTBOUND_INFLIGHT)
    {
        active.push(submit_claim(graph, backend, order, claim));
    }
    let mut outcomes = Vec::new();
    while let Some(result) = active.next().await {
        let outcome = result?;
        if let Err(error) = &outcome.result {
            retain_ci_limit(graph, db, error, now()).await?;
        }
        outcomes.push(outcome);
        if !graph.with(|graph| graph.ci_waiting(now()))
            && let Some((order, claim)) = pending.next()
        {
            active.push(submit_claim(graph, backend, order, claim));
        }
    }
    let mut refused: Vec<_> = pending.map(|(_, claim)| wire_claim(claim)).collect();
    outcomes.sort_unstable_by_key(|outcome| outcome.order);
    let mut bindings = Vec::new();
    let mut failures = Vec::new();
    for outcome in outcomes {
        let claim = outcome.claim;
        match outcome.result {
            Ok(run) => bindings.push(stow_types::api::DispatchBinding {
                task_id: claim.task_id,
                generation: claim.generation,
                run_id: run.workflow_run_id.to_string(),
            }),
            Err(error) if error.rate_limit(now() / 1_000).is_some() => {
                refused.push(wire_claim(claim));
            }
            Err(error) => {
                tracing::error!(task_id = %claim.task_id, %error, "failed to dispatch build");
                failures.push((claim.task_id, claim.generation, error.to_string()));
            }
        }
    }
    if !refused.is_empty() {
        routes::commit(
            graph,
            db,
            &[SchedulerEvent::ClaimsRefused { claims: refused }],
            now(),
        )
        .await?;
    }
    routes::settle_dispatch(graph, db, bindings, failures, now()).await
}

fn wire_claim(claim: graph::Claimed) -> stow_types::api::DispatchClaim {
    stow_types::api::DispatchClaim {
        task_id: claim.task_id,
        generation: claim.generation,
        attempt: claim.attempt,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use stow_types::ci::{CiRequest, CiResponse};

    use super::*;
    use crate::scheduler::{drives::HOST_NOW_MS, fixture, store, test_db};

    struct Limited {
        sent: AtomicUsize,
        answered: AtomicBool,
        primary: bool,
    }

    impl CiTransport for Limited {
        async fn send(&self, _request: CiRequest) -> Result<CiResponse, DispatchError> {
            let order = self.sent.fetch_add(1, Ordering::SeqCst);
            std::future::poll_fn(|cx| {
                cx.waker().wake_by_ref();
                if self.sent.load(Ordering::SeqCst) < 4
                    || (order != 0 && !self.answered.load(Ordering::SeqCst))
                {
                    return std::task::Poll::Pending;
                }
                if order == 0 {
                    self.answered.store(true, Ordering::SeqCst);
                }
                std::task::Poll::Ready(())
            })
            .await;
            match order {
                0 => {
                    let headers = if self.primary {
                        vec![
                            ("x-ratelimit-remaining".into(), "0".into()),
                            (
                                "x-ratelimit-reset".into(),
                                (HOST_NOW_MS / 1_000 + 60).to_string(),
                            ),
                        ]
                    } else {
                        vec![("retry-after".into(), "60".into())]
                    };
                    Ok(CiResponse {
                        status: 403,
                        headers,
                        body: b"{}".to_vec(),
                    })
                }
                1 | 3 => Ok(CiResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: serde_json::to_vec(&serde_json::json!({
                        "workflow_run_id": 900_000 + order,
                        "run_url": "https://api.github.com/run",
                        "html_url": "https://github.com/run",
                    }))
                    .expect("response"),
                }),
                2 => Err(DispatchError::Network("response lost".into())),
                _ => panic!("request admitted after rate-limit refusal"),
            }
        }
    }

    async fn verify_limit(primary: bool) {
        let db = test_db::memory_db().await.expect("db");
        let owner = graph::GraphCell::default();
        let settings = fixture::claim_settings(500, 50);
        fixture::seed(&db, &owner, fixture::GATE, &settings, HOST_NOW_MS)
            .await
            .expect("seed");
        let graph = owner.loaded().expect("loaded");
        let claims = routes::claim_pass(graph, &db, &settings, HOST_NOW_MS, 12)
            .await
            .expect("claims");
        assert_eq!(claims.len(), 12);
        let ids: Vec<_> = claims.iter().map(|claim| claim.task_id.clone()).collect();
        let backend = CiInterface::local_ci(
            "http://ci.test",
            Limited {
                sent: AtomicUsize::new(0),
                answered: AtomicBool::new(false),
                primary,
            },
        );
        dispatch_claims(graph, &db, &backend, claims, || HOST_NOW_MS)
            .await
            .expect("dispatch");
        let until = HOST_NOW_MS + if primary { 62_000 } else { 60_000 };
        assert!(graph.with(|graph| graph.ci_waiting(until - 1)));
        let recovered_owner = graph::GraphCell::default();
        let recovered = routes::wake_graph(&db, &recovered_owner, HOST_NOW_MS)
            .await
            .expect("replay");
        assert!(recovered.with(|graph| graph.ci_waiting(until - 1)));
        assert!(!recovered.with(|graph| graph.ci_waiting(until)));
        for held in [graph, recovered] {
            let rows = held
                .with(|graph| {
                    graph.list(
                        &stow_types::api::QueueSelector {
                            task_ids: ids.clone(),
                            ..Default::default()
                        },
                        HOST_NOW_MS,
                    )
                })
                .expect("rows");
            let bound = rows
                .iter()
                .filter(|row| row.github_run_id.is_some())
                .count();
            assert_eq!(bound, 2, "successful in-flight responses remain bound");
            assert!(
                held.with(|graph| graph.claim(&settings, until - 1, 12))
                    .expect("blocked claim")
                    .is_empty()
            );
            assert!(
                !held
                    .with(|graph| graph.claim(&settings, until, 12))
                    .expect("resumed claim")
                    .is_empty()
            );
        }
        let (mut loaded, events) = store::load(&db).await.expect("load");
        store::apply_events(&mut loaded, &events);
        assert!(loaded.ci_waiting(until - 1));
    }

    #[tokio::test]
    async fn primary_limit_stops_admission_and_survives_replay() {
        verify_limit(true).await;
    }

    #[tokio::test]
    async fn secondary_limit_stops_admission_and_survives_replay() {
        verify_limit(false).await;
    }
}
