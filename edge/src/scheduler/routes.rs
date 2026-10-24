//! The graph-and-store cores of the scheduler routes (stow#878).
//!
//! Every accepted event is appended to the log at the instant the
//! request accepted it, then applied to the in-memory graph — the same
//! `Graph::apply` a wake replays, so the live graph and a replayed one
//! agree event for event. The functions here are the platform-free
//! halves of the Durable Object handlers in `object.rs`: they take the
//! graph cell and a `DurableDb` and return typed results, so the
//! handlers add only extraction, error-to-status mapping and the alarm
//! arm, and the cost harness (`drives.rs`) prices exactly the code a
//! route runs — host and workerd alike.

use stow_types::api::{
    MutationKind, QueueSelector, SchedulerEvent, SubmissionTree, SubmitTaskIdEntry,
};

use super::graph::{Claimed, FinishOutcome, Graph, GraphCell, SnapshotCursor, StartOutcome};
use super::queue::{self, AlarmPlan, SchedulerSettings};
use super::store;
use crate::errors::QueueError;
use skyzen_services::durable::DurableDb;

/// Task ids per `Mutate` log event — a purge of a whole age band
/// splits so no row nears the platform's row bound.
const MUTATE_PART_IDS: usize = 4096;

/// Append `events` to the log at `now`, then apply each to the graph.
/// The append lands first: an event is acknowledged only once it is
/// durable, and a wake replays exactly what was acknowledged. `Submit`
/// parts go through [`commit_trees`] — their apply is the merge.
///
/// # Errors
/// `QueueError::Sql` when the append fails; nothing is applied then.
pub(super) async fn commit(
    graph: &GraphCell,
    db: &DurableDb,
    events: &[SchedulerEvent],
    now: i64,
) -> Result<(), QueueError> {
    append(graph, db, events, now).await?;
    graph.with(|graph| {
        for event in events {
            graph.apply(event, now);
        }
    });
    Ok(())
}

/// Append `events` to the log and count their bytes toward the next
/// snapshot's byte trigger.
async fn append(
    graph: &GraphCell,
    db: &DurableDb,
    events: &[SchedulerEvent],
    now: i64,
) -> Result<(), QueueError> {
    let appended = store::append_events(db, events, now).await?;
    graph.with(|graph| graph.log_appended(appended.bytes));
    Ok(())
}

/// Append the `BuildSample` events the graph's completions produced and
/// apply them: the sample window is graph state carried by the log and
/// the snapshot. The outbox is empty on every call that finished
/// nothing, so the common path appends nothing.
///
/// # Errors
/// `QueueError::Sql` when the append fails.
pub(super) async fn flush_samples(
    graph: &GraphCell,
    db: &DurableDb,
    now: i64,
) -> Result<(), QueueError> {
    let samples = graph.with(Graph::take_samples);
    if samples.is_empty() {
        return Ok(());
    }
    commit(graph, db, &samples, now).await
}

/// Append the `Submit` parts of every tree that changes the graph in
/// one turn, then merge each into it; returns the brand-new nodes. A
/// tree that would change nothing — a resubmission of nodes already
/// held at their downloads — appends nothing: replaying it would be a
/// no-op.
///
/// # Errors
/// `QueueError::Sql` on a failed append, `QueueError::Invariant` when
/// a tree is malformed.
pub(super) async fn commit_trees(
    graph: &GraphCell,
    db: &DurableDb,
    trees: &[SubmissionTree],
    now: i64,
) -> Result<u32, QueueError> {
    let changing = graph.with(|graph| {
        trees
            .iter()
            .map(|tree| graph.merge_changes(tree))
            .collect::<Result<Vec<_>, _>>()
    })?;
    let events: Vec<_> = trees
        .iter()
        .zip(&changing)
        .filter(|&(_, &changes)| changes)
        .flat_map(|(tree, _)| store::submission_events(tree))
        .collect();
    append(graph, db, &events, now).await?;
    graph.with(|graph| {
        trees.iter().try_fold(0u32, |inserted, tree| {
            graph
                .merge(tree, now)
                .map(|report| inserted.saturating_add(report.inserted))
        })
    })
}

/// `POST /tasks/submit[/trusted]`: the pending-depth cap gates
/// miss-lane trees (`enforce_pending_cap`), then every tree's parts
/// land in one turn before the merge — the single transaction the ack
/// follows.
///
/// # Errors
/// `QueueError::QueueFull` when the cap refuses the batch, otherwise
/// [`commit_trees`]'s.
pub(super) async fn submit(
    graph: &GraphCell,
    db: &DurableDb,
    settings: &SchedulerSettings,
    trees: &[SubmissionTree],
    enforce_pending_cap: bool,
    now: i64,
) -> Result<u32, QueueError> {
    if enforce_pending_cap {
        let incoming: u64 = trees
            .iter()
            .map(|tree| u64::try_from(tree.nodes.len()).unwrap_or(u64::MAX))
            .sum();
        let depth = graph.with(|graph| graph.pending_depth());
        if u64::from(depth).saturating_add(incoming) > u64::from(settings.max_queue_pending) {
            return Err(QueueError::QueueFull {
                pending: depth,
                cap: settings.max_queue_pending,
            });
        }
    }
    commit_trees(graph, db, trees, now).await
}

/// `POST /tasks/submit/ids`: the promote lane. The entries append as
/// one event; the apply raises the known nodes in place. Returns
/// `(promoted, unknown)`.
///
/// # Errors
/// `QueueError::Sql` on a failed append.
pub(super) async fn submit_ids(
    graph: &GraphCell,
    db: &DurableDb,
    entries: &[SubmitTaskIdEntry],
    now: i64,
) -> Result<(u32, Vec<String>), QueueError> {
    let event = SchedulerEvent::SubmitIds {
        entries: entries.to_vec(),
    };
    append(graph, db, std::slice::from_ref(&event), now).await?;
    Ok(graph.with(|graph| graph.submit_by_ids(entries)))
}

/// `POST /tasks/{verb}`: the selector resolves to ids against the
/// graph, the resolved ids are the logged events, and the apply is the
/// one replay runs. Returns the rows affected.
///
/// # Errors
/// `QueueError::EmptySelector`/`PurgeRequiresAge` for a selector the
/// verb refuses, `QueueError::Sql` on a failed append.
pub(super) async fn mutate(
    graph: &GraphCell,
    db: &DurableDb,
    op: MutationKind,
    selector: &QueueSelector,
    now: i64,
) -> Result<u32, QueueError> {
    let task_ids = graph.with(|graph| graph.select_ids(op, selector, now))?;
    let events: Vec<_> = task_ids
        .chunks(MUTATE_PART_IDS)
        .map(|ids| SchedulerEvent::Mutate {
            op,
            task_ids: ids.to_vec(),
        })
        .collect();
    append(graph, db, &events, now).await?;
    Ok(graph.with(|graph| {
        events.iter().fold(0u32, |affected, event| match event {
            SchedulerEvent::Mutate { op, task_ids } => {
                affected.saturating_add(graph.mutate(*op, task_ids, now))
            }
            _ => affected,
        })
    }))
}

/// `POST /demand`: the batch's report, its `Demand` event (absent on an
/// exact replay) and the wake plan the folded graph now has.
///
/// # Errors
/// The batch's own validation errors, `QueueError::Sql` on a failed
/// append.
pub(super) async fn demand(
    graph: &GraphCell,
    db: &DurableDb,
    request: &stow_types::api::SchedulerDemandRequest,
    settings: &SchedulerSettings,
    now: i64,
) -> Result<(stow_types::api::SchedulerDemandReport, AlarmPlan), QueueError> {
    let (report, event, plan) =
        graph.with(|graph| queue::demand_pass(graph, request, now, settings))?;
    if let Some(event) = event {
        commit(graph, db, &[event], now).await?;
    }
    Ok((report, plan))
}

/// `POST /index/published`: one `SliceReport` event; the apply flips
/// the matched dependency edges.
///
/// # Errors
/// `QueueError::Sql` on a failed append.
pub(super) async fn slice_report(
    graph: &GraphCell,
    db: &DurableDb,
    slice: &stow_types::api::PublishedSlice,
    now: i64,
) -> Result<(), QueueError> {
    let event = SchedulerEvent::SliceReport {
        target: slice.target.clone(),
        rustc_version: slice.rustc_version.clone(),
        base_generation: slice.base_generation,
        generation: slice.generation,
        added: slice.added.clone(),
        retired: slice.retired.clone(),
    };
    commit(graph, db, &[event], now).await
}

/// `POST /tasks/complete-run`: one `RunFinished` row per delivery,
/// appended before the ack; its apply lands on the same turn.
///
/// # Errors
/// `QueueError::Sql` on a failed append.
pub(super) async fn complete_run(
    graph: &GraphCell,
    db: &DurableDb,
    report: &stow_types::api::WorkflowRunComplete,
    now: i64,
) -> Result<FinishOutcome, QueueError> {
    let event = SchedulerEvent::RunFinished {
        run_id: report.github_run_id.clone().unwrap_or_default(),
        task_id: report.task_id.clone(),
        success: report.success,
        cancelled: report.cancelled,
        error: report.error.clone(),
    };
    append(graph, db, std::slice::from_ref(&event), now).await?;
    let run_id = report
        .github_run_id
        .as_deref()
        .and_then(|id| id.parse::<u64>().ok())
        .unwrap_or(0);
    let outcome = graph.with(|graph| {
        graph.run_finished(
            &report.task_id,
            run_id,
            report.success,
            report.cancelled,
            report.error.clone(),
            now,
        )
    });
    flush_samples(graph, db, now).await?;
    Ok(outcome)
}

/// `POST /tasks/run-update`: an own run's `in_progress` delivery
/// changes nothing persistent (the post-wake reconcile restores running
/// state); a run the scheduler did not dispatch appends its occupancy.
///
/// # Errors
/// `QueueError::Sql` on a failed append.
pub(super) async fn task_run_update(
    graph: &GraphCell,
    db: &DurableDb,
    update: &stow_types::api::TaskRunUpdate,
    now: i64,
) -> Result<StartOutcome, QueueError> {
    let run_id = update.github_run_id.parse::<u64>().unwrap_or(0);
    let family = stow_types::ci::family_of_task_id(&update.task_id)
        .unwrap_or(stow_types::api::RunnerFamily::Linux);
    let outcome = graph.with(|graph| graph.run_started(&update.task_id, run_id, family, now));
    if outcome == StartOutcome::External {
        let event = SchedulerEvent::ExternalRunStarted {
            run_id: update.github_run_id.clone(),
            family,
        };
        append(graph, db, std::slice::from_ref(&event), now).await?;
    }
    Ok(outcome)
}

/// The wake the graph plans — see [`Graph::wake_plan`].
pub(super) fn wake_plan(graph: &GraphCell, settings: &SchedulerSettings, now: i64) -> AlarmPlan {
    graph.with(|graph| graph.wake_plan(now, settings))
}

/// The flat log is bounded by snapshots: once the appended tail
/// crosses the threshold, write the chunked snapshot — covered prefix
/// dropped. Returns whether one was written.
///
/// The snapshot covers the whole log: every appended event was applied
/// before this turn, and the input gate admits no other request between
/// the chunk writes.
///
/// # Errors
/// `QueueError` on a failed chunk or watermark write.
pub(super) async fn snapshot_if_due(graph: &GraphCell, db: &DurableDb) -> Result<bool, QueueError> {
    if !graph.with(|graph| graph.snapshot_due()) {
        return Ok(false);
    }
    snapshot(graph, db).await?;
    Ok(true)
}

/// Write the snapshot now.
///
/// # Errors
/// `QueueError` on a failed chunk or watermark write.
pub(super) async fn snapshot(graph: &GraphCell, db: &DurableDb) -> Result<(), QueueError> {
    // Freed nodes leave the arena before the image is cut.
    graph.with(Graph::compact);
    let mut cursor = SnapshotCursor::default();
    store::write_snapshot_parts(db, || {
        graph.with(|graph| graph.next_snapshot_chunk(&mut cursor))
    })
    .await?;
    graph.with(|graph| {
        graph.log_since_snapshot = 0;
        graph.log_bytes_since_snapshot = 0;
    });
    Ok(())
}

/// A dispatch pass's claim half: free slots from the dispatch caps and
/// the external occupancy, then the graph's claim in rank order, with
/// ONE `Claims` event appended before any `workflow_dispatch` posts.
/// An empty claim set appends nothing.
///
/// # Errors
/// `QueueError::Invariant` when a claimed payload cannot rebuild,
/// `QueueError::Sql` on a failed append.
pub(super) async fn claim_pass(
    graph: &GraphCell,
    db: &DurableDb,
    settings: &SchedulerSettings,
    now: i64,
) -> Result<Vec<Claimed>, QueueError> {
    graph.with(|graph| graph.set_floor(settings.min_dispatch_value));
    let claims = graph.with(|graph| {
        let (total_free, macos_free) = graph.free_slots(settings);
        graph.claim(
            total_free,
            macos_free,
            now,
            i64::from(settings.stale_dispatch_minutes) * 60_000,
        )
    })?;
    if claims.is_empty() {
        return Ok(claims);
    }
    let event = SchedulerEvent::Claims {
        claims: claims
            .iter()
            .map(|claim| stow_types::api::DispatchClaim {
                task_id: claim.task_id.clone(),
                generation: claim.generation,
                attempt: claim.attempt,
            })
            .collect(),
    };
    append(graph, db, std::slice::from_ref(&event), now).await?;
    Ok(claims)
}

/// A dispatch pass's outcome half: ONE `Bindings` row for every
/// returned binding; POST failures re-queue their claim under backoff
/// in memory only — the failure is not a persistent event: a wake
/// replays the claim as dispatched-unbound, which the run-listing
/// reconcile binds or the stale lease returns.
///
/// # Errors
/// `QueueError::Sql` on a failed append.
pub(super) async fn settle_dispatch(
    graph: &GraphCell,
    db: &DurableDb,
    bindings: Vec<stow_types::api::DispatchBinding>,
    failures: Vec<(String, u64, String)>,
    now: i64,
) -> Result<(), QueueError> {
    if !bindings.is_empty() {
        commit(graph, db, &[SchedulerEvent::Bindings { bindings }], now).await?;
        // A binding can apply a completion that beat its dispatch
        // response.
        flush_samples(graph, db, now).await?;
    }
    graph.with(|graph| {
        for (task_id, generation, error) in failures {
            graph.mark_dispatch_failed(&task_id, generation, &error, now);
        }
    });
    Ok(())
}

/// `POST /requests/{id}/outcome`: merge the report's trees (their
/// `Submit` parts append first), then settle the record. `queued_before`
/// is probed on the pre-merge graph so a root's `was_queued` reads what
/// the report found.
///
/// # Errors
/// The record's own refusals (`UnknownRequest`,
/// `RequestAttemptSuperseded`), `QueueError::Sql` on a failed append.
pub(super) async fn request_outcome(
    graph: &GraphCell,
    db: &DurableDb,
    request_id: &str,
    report: &stow_types::api::RequestOutcomeReport,
    now: i64,
) -> Result<stow_types::api::CrateRequestStatus, QueueError> {
    let (queued_before, probe) =
        if let stow_types::api::RequestOutcome::Resolved { trees, roots } = &report.outcome {
            let queued_before: std::collections::BTreeSet<String> = roots
                .iter()
                .filter_map(|root| root.task_id.as_ref())
                .filter(|&task_id| graph.with(|graph| graph.has_task(task_id)))
                .cloned()
                .collect();
            commit_trees(graph, db, trees, now).await?;
            // The post-enqueue probe the per-target invariant reads.
            let ids: Vec<String> = roots
                .iter()
                .filter_map(|root| root.task_id.clone())
                .collect();
            (queued_before, graph.with(|graph| graph.probe_roots(&ids)))
        } else {
            Default::default()
        };
    let (status, event) = graph.with(|graph| {
        queue::apply_request_outcome(graph, request_id, report, &queued_before, &probe)
    })?;
    if let Some(event) = event {
        commit(graph, db, &[event], now).await?;
    }
    Ok(status)
}

/// `POST /requests/{id}/run-update`: the webhook's lifecycle event for
/// a resolve run.
///
/// # Errors
/// `UnknownRequest`/`RequestAttemptSuperseded` from the record fence,
/// `QueueError::Sql` on a failed append.
pub(super) async fn request_run_update(
    graph: &GraphCell,
    db: &DurableDb,
    request_id: &str,
    update: &stow_types::api::RequestRunUpdate,
    now: i64,
) -> Result<(), QueueError> {
    let event = graph.with(|graph| queue::record_request_run_update(graph, request_id, update))?;
    commit(graph, db, &[event], now).await
}

/// `POST /requests` admission, before the resolve run dispatches:
/// dedup on the request id and the daily-budget probe, then the
/// `Admitted` event — the durable write — appended and applied.
///
/// # Errors
/// `HumanDailyBudgetExhausted` when the day has no room,
/// `QueueError::Sql` on a failed append.
pub(super) async fn admit_request(
    graph: &GraphCell,
    db: &DurableDb,
    settings: &SchedulerSettings,
    admission: &stow_types::api::RequestAdmission,
    dispatched_at: i64,
    now: i64,
) -> Result<queue::RequestAdmissionStep, QueueError> {
    let (step, event) =
        graph.with(|graph| queue::admit_request(graph, admission, dispatched_at, settings))?;
    if let Some(event) = event {
        commit(graph, db, &[event], now).await?;
    }
    Ok(step)
}

/// A resolve dispatch that failed: flip the live attempt `failed`
/// naming the error, so a later re-request can retry.
///
/// # Errors
/// `QueueError::Sql` on a failed append.
pub(super) async fn fail_request_dispatch(
    graph: &GraphCell,
    db: &DurableDb,
    request_id: &str,
    attempt: u32,
    error: &str,
    now: i64,
) -> Result<(), QueueError> {
    if let Some(event) =
        graph.with(|graph| queue::fail_request_dispatch(graph, request_id, attempt, error))
    {
        commit(graph, db, &[event], now).await?;
    }
    Ok(())
}

/// `POST /demand-feed/begin`: open or rotate the hour's staging attempt;
/// the `Begin` event appends before the ack.
///
/// # Errors
/// The feed's contract refusals (`QueueError::Invariant`), `QueueError::Sql`
/// on a failed append.
pub(super) async fn feed_begin(
    graph: &GraphCell,
    db: &DurableDb,
    hour: &stow_types::api::DemandFeedHour,
    now_secs: i64,
) -> Result<stow_types::api::DemandFeedBeginReport, QueueError> {
    let (report, event) = graph.with(|graph| super::feed::feed_begin(graph, hour, now_secs))?;
    commit(graph, db, &[event], now_secs * 1_000).await?;
    Ok(report)
}

/// `POST /demand-feed/page`: stage one bounded page. A replayed page of
/// the same bytes appends nothing.
///
/// # Errors
/// The feed's contract refusals, `QueueError::Sql` on a failed append.
pub(super) async fn feed_page(
    graph: &GraphCell,
    db: &DurableDb,
    request: &stow_types::api::DemandFeedPageRequest,
    now_secs: i64,
) -> Result<(), QueueError> {
    if let Some(event) = graph.with(|graph| super::feed::feed_page(graph, request, now_secs))? {
        commit(graph, db, &[event], now_secs * 1_000).await?;
    }
    Ok(())
}

/// `POST /demand-feed/complete`: freeze the hour once its manifest
/// verifies.
///
/// # Errors
/// The feed's contract refusals, `QueueError::Sql` on a failed append.
pub(super) async fn feed_complete(
    graph: &GraphCell,
    db: &DurableDb,
    request: &stow_types::api::DemandFeedCompleteRequest,
    now_secs: i64,
) -> Result<(), QueueError> {
    let event = graph.with(|graph| super::feed::feed_complete(graph, request, now_secs))?;
    commit(graph, db, &[event], now_secs * 1_000).await
}

/// `POST /demand-feed/cleanup`: retire one bounded chunk of the hour's
/// dead pages.
///
/// # Errors
/// The feed's contract refusals, `QueueError::Sql` on a failed append.
pub(super) async fn feed_cleanup(
    graph: &GraphCell,
    db: &DurableDb,
    hour: &stow_types::api::DemandFeedHour,
    now_secs: i64,
) -> Result<stow_types::api::DemandFeedCleanupReport, QueueError> {
    let (report, event) = graph.with(|graph| super::feed::feed_cleanup(graph, hour, now_secs))?;
    if let Some(event) = event {
        commit(graph, db, &[event], now_secs * 1_000).await?;
    }
    Ok(report)
}

/// `POST /demand-feed/deliver`: replay the next undelivered page into
/// the demand fold; returns the report and the wake plan to arm.
///
/// # Errors
/// The feed's contract refusals, `QueueError::Sql` on a failed append.
pub(super) async fn feed_deliver(
    graph: &GraphCell,
    db: &DurableDb,
    hour: &stow_types::api::DemandFeedHour,
    settings: &SchedulerSettings,
    now_ms: i64,
) -> Result<(stow_types::api::DemandFeedDeliverReport, AlarmPlan), QueueError> {
    let (report, events, plan) =
        graph.with(|graph| super::feed::feed_deliver(graph, hour, now_ms, settings))?;
    commit(graph, db, &events, now_ms).await?;
    Ok((report, plan))
}

/// Forced-eviction invariants (stow#878): a Durable Object evicted at
/// any point of a dispatch pass wakes into the graph its store replays
/// to, and the next pass neither loses nor doubles a dispatch.
#[cfg(test)]
mod eviction_tests {
    use super::*;
    use crate::scheduler::drives::HOST_NOW_MS;
    use crate::scheduler::fixture::{self, FixtureShape};
    use crate::scheduler::test_db;

    const SHAPE: FixtureShape = fixture::GATE;

    /// The production dispatch cap: the fixture holds 30 in flight, so
    /// 15 slots are free.
    fn settings() -> SchedulerSettings {
        SchedulerSettings {
            dispatch: queue::Dispatch::Limited(std::num::NonZeroU32::new(45).expect("45")),
            ..SchedulerSettings::default()
        }
    }

    fn ids(claims: &[Claimed]) -> Vec<(String, u64)> {
        let mut ids: Vec<_> = claims
            .iter()
            .map(|claim| (claim.task_id.clone(), claim.generation))
            .collect();
        ids.sort();
        ids
    }

    /// What a woken Durable Object holds: the store replayed.
    async fn wake(db: &DurableDb) -> GraphCell {
        let (mut graph, tail) = store::load(db).await.expect("load");
        store::apply_events(&mut graph, &tail);
        let cell = GraphCell::default();
        cell.install(graph);
        cell
    }

    async fn seeded() -> (DurableDb, GraphCell) {
        let db = test_db::memory_db().await.expect("memory db");
        let cell = GraphCell::default();
        fixture::seed(&db, &cell, SHAPE, HOST_NOW_MS)
            .await
            .expect("seed");
        (db, cell)
    }

    /// Evicted after the `Claims` row landed and before any dispatch
    /// POST: the woken object holds those claims as dispatched, so its
    /// next pass takes only further tasks — no double dispatch.
    #[tokio::test]
    async fn an_eviction_after_the_claim_row_never_doubles_a_dispatch() {
        let (db, cell) = seeded().await;
        let settings = settings();
        let first = claim_pass(&cell, &db, &settings, HOST_NOW_MS)
            .await
            .expect("first pass");
        assert!(!first.is_empty(), "the fixture leaves free slots");
        let woken = wake(&db).await;
        let (before, after) = (
            cell.with(|graph| graph.inflight()),
            woken.with(|graph| graph.inflight()),
        );
        assert_eq!(before, after, "the replayed graph holds the same claims");
        let second = claim_pass(&woken, &db, &settings, HOST_NOW_MS)
            .await
            .expect("second pass");
        let taken = ids(&first);
        assert!(
            ids(&second).iter().all(|claim| !taken.contains(claim)),
            "a claimed task was claimed again after the wake"
        );
        let live = claim_pass(&cell, &db, &settings, HOST_NOW_MS)
            .await
            .expect("live second pass");
        assert_eq!(
            ids(&second),
            ids(&live),
            "the woken pass equals the pass of the object that never slept"
        );
    }

    /// Evicted before the `Claims` row landed (the claim only in
    /// memory): the store holds no trace, and the woken pass claims
    /// exactly what the lost pass had — nothing is lost.
    #[tokio::test]
    async fn an_eviction_before_the_claim_row_loses_nothing() {
        let (db, cell) = seeded().await;
        let settings = settings();
        let woken = wake(&db).await;
        let lost = claim_pass(&cell, &db, &settings, HOST_NOW_MS)
            .await
            .expect("pass");
        // Rewind the store to before the pass: drop the claim row.
        db.query("DELETE FROM event_log WHERE seq = (SELECT MAX(seq) FROM event_log)")
            .execute()
            .await
            .expect("drop the claim row");
        let again = claim_pass(&woken, &db, &settings, HOST_NOW_MS)
            .await
            .expect("woken pass");
        assert!(!lost.is_empty(), "the fixture leaves free slots");
        assert_eq!(ids(&lost), ids(&again));
    }
}

/// The snapshot trigger is events OR bytes, whichever comes first: a
/// wake replays at most the byte threshold of log, whatever the
/// submissions weigh (stow#878 §3.3).
#[cfg(test)]
mod snapshot_trigger_tests {
    use super::*;
    use crate::scheduler::fixture;
    use crate::scheduler::test_db;
    use stow_types::api::SubmissionSource;

    /// Fixture rows far outside the seeded range, so every node is new.
    const FIRST_ROW: u32 = 5_000_000;

    fn tree(first: u32, nodes: u32) -> SubmissionTree {
        SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: Vec::new(),
            nodes: (first..first + nodes)
                .map(|n| fixture::fixture_node(n, Vec::new()))
                .collect(),
        }
    }

    async fn tail_bytes(db: &DurableDb) -> u64 {
        let covered = store::watermark(db).await.expect("watermark");
        db.query("SELECT COALESCE(SUM(LENGTH(event)), 0) FROM event_log WHERE seq > ?")
            .bind(covered)
            .fetch_scalar::<i64>()
            .await
            .map(|bytes| u64::try_from(bytes).expect("non-negative"))
            .expect("tail size")
    }

    /// Submissions of any weight leave a tail of at most the byte
    /// threshold at the end of every turn, long before the event count
    /// is near its own.
    #[tokio::test]
    async fn the_tail_stays_under_the_byte_threshold_whatever_a_submission_weighs() {
        for nodes in [1_000, 4_096, 12_000] {
            let db = test_db::memory_db().await.expect("db");
            let cell = GraphCell::default();
            cell.install(Graph::default());
            let mut snapshots = 0u32;
            let mut widest = 0u64;
            for turn in 0..40u32 {
                let tree = tree(FIRST_ROW + turn * nodes, nodes);
                commit_trees(&cell, &db, std::slice::from_ref(&tree), 1)
                    .await
                    .expect("submit");
                if snapshot_if_due(&cell, &db).await.expect("snapshot") {
                    snapshots += 1;
                }
                let tail = tail_bytes(&db).await;
                widest = widest.max(tail);
                assert!(
                    tail <= store::SNAPSHOT_BYTE_THRESHOLD,
                    "{nodes}-node turns left {tail} bytes of tail after turn {turn}"
                );
                assert!(cell.with(|graph| graph.log_since_snapshot) <= 64);
            }
            assert!(snapshots >= 1, "{nodes}-node turns never snapshotted");
            // A wake of this store replays that tail into the same graph.
            let (mut woken, events) = store::load(&db).await.expect("load");
            eprintln!(
                "tail events {} bytes {}",
                events.len(),
                tail_bytes(&db).await
            );
            store::apply_events(&mut woken, &events);
            assert_eq!(woken.sizes(), cell.with(|graph| graph.sizes()));
            eprintln!("{nodes}-node submissions: widest tail {widest} B, {snapshots} snapshots");
        }
    }

    /// One submission of the full production wave (275,000 nodes, about
    /// 140 MB of log): the turn's snapshot drops it, so the wake replays
    /// no tail and holds the compact graph, inside 128 MiB.
    #[tokio::test]
    async fn a_wake_after_a_full_wave_submission_replays_no_wave() {
        const WAVE: u32 = 275_000;
        let db = test_db::memory_db().await.expect("db");
        let cell = GraphCell::default();
        cell.install(Graph::default());
        let wave = tree(FIRST_ROW, WAVE);
        commit_trees(&cell, &db, std::slice::from_ref(&wave), 1)
            .await
            .expect("submit the wave");
        assert!(
            cell.with(|graph| graph.log_bytes_since_snapshot) > 100 << 20,
            "the wave is over 100 MiB of log"
        );
        assert!(snapshot_if_due(&cell, &db).await.expect("snapshot"));
        assert_eq!(tail_bytes(&db).await, 0);
        drop(wave);
        let (woken, events) = store::load(&db).await.expect("load");
        assert!(events.is_empty());
        assert_eq!(woken.sizes().0, u64::from(WAVE));
        let heap = woken.heap_bytes();
        eprintln!("woken wave graph: {heap} B of arenas for {WAVE} nodes");
        assert!(heap < 128 << 20);
    }
}
