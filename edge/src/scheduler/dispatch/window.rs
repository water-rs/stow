//! Bounded CI dispatch with a durable API recovery fence.

use futures_util::stream::{FuturesUnordered, StreamExt as _};
use skyzen_services::durable::DurableDb;
use std::mem::replace;

use stow_types::api::{DispatchFreezeTrigger, DispatchFreezeWorkflow, SchedulerEvent};
use stow_types::ci::{CiInterface, CiTransport, DispatchError};

use crate::errors::QueueError;
use crate::freeze::{self, AlertSink};
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
/// The first API refusal of the pass reads the dispatching workflow's `state`
/// once. When it is not `active` no further request is admitted, every
/// refused claim returns to pending through one `ClaimsRefused` row (as a
/// rate-limited one does), and after the claims settle the dispatch freeze
/// engages naming the workflow and its state. A refusal while the workflow is
/// `active` stays a failed POST: its claim re-queues under the dispatch
/// backoff. The freeze's transition sends the one alert and gates every later
/// pass until an operator lifts it.
///
/// # Errors
/// Returns a payload invariant or storage error; accepted unbound runs remain
/// recoverable through the persisted claims and normal run reconciliation.
pub async fn dispatch_claims<T: CiTransport, S: AlertSink + Sync>(
    graph: graph::LoadedGraph<'_>,
    db: &DurableDb,
    backend: &CiInterface<T>,
    sink: &S,
    claims: Vec<graph::Claimed>,
    now: impl Fn() -> i64,
    iso_now: impl Fn() -> String,
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
    let mut state_read = false;
    let mut inactive: Option<String> = None;
    while let Some(result) = active.next().await {
        let outcome = result?;
        if let Err(error) = &outcome.result {
            retain_ci_limit(graph, db, error, now()).await?;
            if matches!(error, DispatchError::Api { .. }) && !replace(&mut state_read, true) {
                match backend.build_workflow_state().await {
                    Ok(state) if state != WORKFLOW_ACTIVE => inactive = Some(state),
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(%error, "could not read the dispatching workflow's state");
                    }
                }
            }
        }
        outcomes.push(outcome);
        if inactive.is_none()
            && !graph.with(|graph| graph.ci_waiting(now()))
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
            Err(error)
                if error.rate_limit(now() / 1_000).is_some()
                    || (inactive.is_some() && matches!(error, DispatchError::Api { .. })) =>
            {
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
    routes::settle_dispatch(graph, db, bindings, failures, now()).await?;
    if let Some(state) = inactive {
        let store = graph::GraphFreezeStore::new(graph, iso_now(), now());
        let transition = freeze::apply_transition(
            &store,
            sink,
            freeze::FreezeAction::Freeze,
            DispatchFreezeTrigger::WorkflowDisabled(DispatchFreezeWorkflow {
                workflow: stow_types::trusted_builder::WORKFLOW_FILE.to_owned(),
                state,
            }),
            &iso_now(),
        )
        .await?;
        routes::persist_freeze(db, &store, None, now()).await?;
        if let freeze::FreezeTransition::Engaged(record) = transition {
            tracing::error!(
                trigger = %freeze::summarize_trigger(&record.trigger),
                notify = %freeze::summarize_notify(&record.notify),
                "dispatch freeze engaged: the dispatching workflow is not active"
            );
        }
    }
    Ok(())
}

/// The `state` GitHub reports for a workflow that dispatches.
const WORKFLOW_ACTIVE: &str = "active";

fn wire_claim(claim: graph::Claimed) -> stow_types::api::DispatchClaim {
    stow_types::api::DispatchClaim {
        task_id: claim.task_id,
        generation: claim.generation,
        attempt: claim.attempt,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use stow_types::ci::{CiRequest, CiResponse};

    use super::*;
    use crate::scheduler::{drives::HOST_NOW_MS, fixture, store, test_db};

    fn iso() -> String {
        "2026-10-28T12:00:00Z".to_owned()
    }

    /// Records every alert the freeze transitions send.
    #[derive(Default)]
    struct Mailbox(std::sync::Mutex<Vec<(&'static str, crate::freeze::AlertDraft)>>);

    impl AlertSink for Mailbox {
        fn opened(
            &self,
            draft: &crate::freeze::AlertDraft,
        ) -> impl std::future::Future<Output = stow_types::api::ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("mailbox")
                .push(("opened", draft.clone()));
            std::future::ready(stow_types::api::ChannelOutcome::Sent { message_id: None })
        }
        fn updated(
            &self,
            draft: &crate::freeze::AlertDraft,
        ) -> impl std::future::Future<Output = stow_types::api::ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("mailbox")
                .push(("updated", draft.clone()));
            std::future::ready(stow_types::api::ChannelOutcome::Sent { message_id: None })
        }
        fn resolved(
            &self,
            draft: &crate::freeze::AlertDraft,
        ) -> impl std::future::Future<Output = stow_types::api::ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("mailbox")
                .push(("resolved", draft.clone()));
            std::future::ready(stow_types::api::ChannelOutcome::Sent { message_id: None })
        }
    }

    /// Refuses every dispatch with a `422` and answers the workflow read
    /// with the configured `state`, counting both.
    struct Refusing {
        state: &'static str,
        posts: Arc<AtomicUsize>,
        reads: Arc<AtomicUsize>,
    }

    impl CiTransport for Refusing {
        fn send(
            &self,
            request: CiRequest,
        ) -> impl std::future::Future<Output = Result<CiResponse, DispatchError>> + Send {
            let response = if request.method == "POST" {
                self.posts.fetch_add(1, Ordering::SeqCst);
                CiResponse {
                    status: 422,
                    headers: Vec::new(),
                    body: br#"{"message":"Unprocessable"}"#.to_vec(),
                }
            } else {
                self.reads.fetch_add(1, Ordering::SeqCst);
                assert!(
                    request
                        .url
                        .ends_with("/repos/water-rs/stow/actions/workflows/build-crate.yml"),
                    "{}",
                    request.url
                );
                CiResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: format!(r#"{{"id":1,"state":"{}"}}"#, self.state).into_bytes(),
                }
            };
            std::future::ready(Ok(response))
        }
    }

    async fn refused_pass(
        state: &'static str,
    ) -> (
        DurableDb,
        graph::GraphCell,
        Vec<String>,
        Mailbox,
        (usize, usize),
    ) {
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
        let ids = claims.iter().map(|claim| claim.task_id.clone()).collect();
        let (posts, reads) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let backend = CiInterface::github(
            "water-rs/stow",
            "token",
            Refusing {
                state,
                posts: Arc::clone(&posts),
                reads: Arc::clone(&reads),
            },
        );
        let mailbox = Mailbox::default();
        dispatch_claims(graph, &db, &backend, &mailbox, claims, || HOST_NOW_MS, iso)
            .await
            .expect("dispatch");
        let counts = (posts.load(Ordering::SeqCst), reads.load(Ordering::SeqCst));
        (db, owner, ids, mailbox, counts)
    }

    async fn all_pending(held: graph::LoadedGraph<'_>, db: &DurableDb, ids: &[String]) -> bool {
        let rows = routes::list_tasks(
            held,
            db,
            &stow_types::api::QueueSelector {
                task_ids: ids.to_vec(),
                ..Default::default()
            },
            HOST_NOW_MS,
        )
        .await
        .expect("rows");
        rows.len() == ids.len()
            && rows.iter().all(|row| {
                row.status == stow_types::api::QueueTaskStatus::Pending
                    && row.github_run_id.is_none()
            })
    }

    /// A refusal that reads a non-active workflow releases every claim,
    /// stops admission after the first round, engages the freeze once
    /// with the workflow and its state, and holds across a replay; the
    /// freeze gates dispatch until it is lifted.
    #[tokio::test]
    async fn a_disabled_workflow_freezes_dispatch_and_releases_the_claims() {
        let (db, owner, ids, mailbox, (posts, reads)) = refused_pass("disabled_manually").await;
        assert_eq!(
            posts,
            crate::fetch_guard::MAX_OUTBOUND_INFLIGHT,
            "one round"
        );
        assert_eq!(reads, 1, "the state is read once");
        {
            let sent = mailbox.0.lock().expect("mailbox");
            assert_eq!(sent.len(), 1, "one alert, on the transition");
            assert_eq!(sent[0].0, "opened");
            assert_eq!(sent[0].1.key, crate::freeze::FREEZE_INCIDENT_KEY);
            assert!(
                sent[0]
                    .1
                    .subject
                    .contains("build-crate.yml is disabled_manually"),
                "{}",
                sent[0].1.subject
            );
        }
        let live = owner.loaded().expect("loaded");
        let recovered_owner = graph::GraphCell::default();
        let recovered = routes::wake_graph(&db, &recovered_owner, u64::MAX, HOST_NOW_MS)
            .await
            .expect("replay");
        let settings = fixture::claim_settings(500, 50);
        for held in [live, recovered] {
            let record = held.with(|graph| graph.freeze().cloned()).expect("frozen");
            assert_eq!(
                record.trigger,
                DispatchFreezeTrigger::WorkflowDisabled(DispatchFreezeWorkflow {
                    workflow: "build-crate.yml".to_owned(),
                    state: "disabled_manually".to_owned(),
                })
            );
            assert!(all_pending(held, &db, &ids).await);
            assert!(
                routes::claim_pass(held, &db, &settings, HOST_NOW_MS, 12)
                    .await
                    .expect("frozen pass")
                    .is_empty(),
                "nothing is claimed while frozen"
            );
        }
        let store = graph::GraphFreezeStore::new(live, iso(), HOST_NOW_MS);
        freeze::apply_transition(
            &store,
            &mailbox,
            freeze::FreezeAction::Clear,
            DispatchFreezeTrigger::Manual {
                actor: "operator".to_owned(),
            },
            &iso(),
        )
        .await
        .expect("clear");
        routes::persist_freeze(&db, &store, Some("operator"), HOST_NOW_MS)
            .await
            .expect("persist");
        assert!(
            !routes::claim_pass(live, &db, &settings, HOST_NOW_MS, 12)
                .await
                .expect("resumed pass")
                .is_empty(),
            "dispatch resumes once the freeze is lifted"
        );
    }

    /// A refusal while the workflow is active (a bad input, a revoked
    /// grant) is no reason to freeze and keeps the failed-POST path:
    /// every claim still posts, nothing alerts, each claim re-queues in
    /// memory under the dispatch backoff, and no `ClaimsRefused` row is
    /// written — a replay finds them dispatched, for the stale lease.
    #[tokio::test]
    async fn a_refusal_with_an_active_workflow_takes_the_backoff_without_freezing() {
        let (db, owner, ids, mailbox, (posts, reads)) = refused_pass("active").await;
        assert_eq!(posts, 12, "the pass is not stopped");
        assert_eq!(reads, 1, "the state is read once");
        assert!(mailbox.0.lock().expect("mailbox").is_empty());
        let live = owner.loaded().expect("loaded");
        assert!(live.with(|graph| graph.freeze().is_none()));
        assert!(all_pending(live, &db, &ids).await);
        let settings = fixture::claim_settings(500, 50);
        let reclaimed = routes::claim_pass(live, &db, &settings, HOST_NOW_MS, 12)
            .await
            .expect("same-instant pass");
        assert!(
            reclaimed.iter().all(|claim| !ids.contains(&claim.task_id)),
            "a backed-off claim is not reclaimed at once"
        );
        let recovered_owner = graph::GraphCell::default();
        let recovered = routes::wake_graph(&db, &recovered_owner, u64::MAX, HOST_NOW_MS)
            .await
            .expect("replay");
        assert!(
            !all_pending(recovered, &db, &ids).await,
            "the backoff is memory only: a replay finds the claims dispatched"
        );
    }

    struct Limited {
        sent: Arc<AtomicUsize>,
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
        let sent = Arc::new(AtomicUsize::new(0));
        let backend = CiInterface::local_ci(
            "http://ci.test",
            Limited {
                sent: Arc::clone(&sent),
                answered: AtomicBool::new(false),
                primary,
            },
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            dispatch_claims(
                graph,
                &db,
                &backend,
                &Mailbox::default(),
                claims,
                || HOST_NOW_MS,
                iso,
            ),
        )
        .await
        .expect("the first round must reach all four requests concurrently")
        .expect("dispatch");
        assert_eq!(
            sent.load(Ordering::SeqCst),
            4,
            "no admission after the refusal"
        );
        let until = HOST_NOW_MS + if primary { 62_000 } else { 60_000 };
        assert!(graph.with(|graph| graph.ci_waiting(until - 1)));
        let recovered_owner = graph::GraphCell::default();
        let recovered = routes::wake_graph(&db, &recovered_owner, u64::MAX, HOST_NOW_MS)
            .await
            .expect("replay");
        assert!(recovered.with(|graph| graph.ci_waiting(until - 1)));
        assert!(!recovered.with(|graph| graph.ci_waiting(until)));
        for held in [graph, recovered] {
            assert!(matches!(
                routes::require_ci_ready(held, until - 1),
                Err(QueueError::CiRateLimited)
            ));
            routes::require_ci_ready(held, until).expect("control dispatch resumes at deadline");
            let rows = routes::list_tasks(
                held,
                &db,
                &stow_types::api::QueueSelector {
                    task_ids: ids.clone(),
                    ..Default::default()
                },
                HOST_NOW_MS,
            )
            .await
            .expect("rows");
            let bound = rows
                .iter()
                .filter(|row| row.github_run_id.is_some())
                .count();
            assert_eq!(bound, 2, "successful in-flight responses remain bound");
            assert!(
                held.with(|graph| graph.claim_nodes(&settings, until - 1, 12))
                    .expect("blocked claim")
                    .is_empty()
            );
            assert!(
                !held
                    .with(|graph| graph.claim_nodes(&settings, until, 12))
                    .expect("resumed claim")
                    .is_empty()
            );
        }
        let (loaded, _) = store::restore(&db, u64::MAX).await.expect("load");
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
