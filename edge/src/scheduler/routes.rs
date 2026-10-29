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

use super::graph::{Claimed, FinishOutcome, Graph, GraphCell, LoadedGraph, StartOutcome};
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
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    events: &[SchedulerEvent],
    now: i64,
) -> Result<(), QueueError> {
    commit_as(graph, db, None, events, now).await
}

/// [`commit`] for a request a GitHub Actions identity authenticated:
/// the first appended row carries that run's verified `actor`
/// (stow#955) — `None` on lanes no bearer credential reached (webhook
/// forwards, the anonymous submit, the alarm).
///
/// # Errors
/// `QueueError::Sql` when the append fails; nothing is applied then.
pub(super) async fn commit_as(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    actor: Option<&str>,
    events: &[SchedulerEvent],
    now: i64,
) -> Result<(), QueueError> {
    append(graph, db, actor, events, now).await?;
    graph.with(|graph| {
        for event in events {
            graph.apply(event, now);
        }
    });
    Ok(())
}

/// Append `events` to the log — the first row attributed to `actor`
/// when one authenticated the request — and count their bytes toward
/// the next snapshot's byte trigger.
async fn append(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    actor: Option<&str>,
    events: &[SchedulerEvent],
    now: i64,
) -> Result<(), QueueError> {
    let appended = store::append_events(db, actor, events, now).await?;
    graph.with(|graph| graph.log_appended(appended.bytes, appended.seq));
    Ok(())
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
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    trees: &[SubmissionTree],
    actor: Option<&str>,
    now: i64,
) -> Result<(u32, Vec<String>), QueueError> {
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
    append(graph, db, actor, &events, now).await?;
    graph.with(|graph| {
        trees
            .iter()
            .try_fold((0u32, Vec::new()), |(inserted, mut unpublished), tree| {
                graph.merge(tree, now).map(|report| {
                    unpublished.extend(report.unpublished);
                    (inserted.saturating_add(report.inserted), unpublished)
                })
            })
    })
}

/// `POST /tasks/submit[/trusted]`: the miss-lane pending-depth cap gates
/// miss-lane trees (`enforce_pending_cap`), then every tree's parts
/// land in one turn before the merge — the single transaction the ack
/// follows.
///
/// # Errors
/// `QueueError::QueueFull` when the cap refuses the batch, otherwise
/// [`commit_trees`]'s.
pub(super) async fn submit(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    settings: &SchedulerSettings,
    trees: &[SubmissionTree],
    enforce_pending_cap: bool,
    actor: Option<&str>,
    now: i64,
) -> Result<(u32, Vec<String>), QueueError> {
    if enforce_pending_cap {
        let incoming: u64 = trees
            .iter()
            .map(|tree| u64::try_from(tree.nodes.len()).unwrap_or(u64::MAX))
            .sum();
        let depth = graph.with(|graph| graph.miss_pending_depth());
        if u64::from(depth).saturating_add(incoming) > u64::from(settings.max_queue_pending) {
            return Err(QueueError::QueueFull {
                pending: depth,
                cap: settings.max_queue_pending,
            });
        }
    }
    commit_trees(graph, db, trees, actor, now).await
}

/// `POST /tasks/submit/ids`: the promote lane. The entries append as
/// one event; the apply raises the known nodes in place. Returns
/// `(promoted, unknown)`.
///
/// # Errors
/// `QueueError::Sql` on a failed append.
pub(super) async fn submit_ids(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    entries: &[SubmitTaskIdEntry],
    actor: Option<&str>,
    now: i64,
) -> Result<(u32, Vec<String>), QueueError> {
    let event = SchedulerEvent::SubmitIds {
        entries: entries.to_vec(),
    };
    append(graph, db, actor, std::slice::from_ref(&event), now).await?;
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
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    op: MutationKind,
    selector: &QueueSelector,
    actor: Option<&str>,
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
    append(graph, db, actor, &events, now).await?;
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
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    request: &stow_types::api::SchedulerDemandRequest,
    settings: &SchedulerSettings,
    actor: Option<&str>,
    now: i64,
) -> Result<(stow_types::api::SchedulerDemandReport, AlarmPlan), QueueError> {
    let (report, event, plan) =
        graph.with(|graph| queue::demand_pass(graph, request, now, settings))?;
    if let Some(event) = event {
        commit_as(graph, db, actor, &[event], now).await?;
    }
    Ok((report, plan))
}

/// `POST /index/published`: one `SliceReport` event per slice of the
/// publish run, committed in ONE append (stow#940); each apply flips
/// its matched dependency edges.
///
/// # Errors
/// `QueueError::Sql` on a failed append.
pub(super) async fn slice_reports(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    slices: &[stow_types::api::PublishedSlice],
    actor: Option<&str>,
    now: i64,
) -> Result<(), QueueError> {
    let events: Vec<SchedulerEvent> = slices
        .iter()
        .map(|slice| SchedulerEvent::SliceReport {
            target: slice.target.clone(),
            rustc_version: slice.rustc_version.clone(),
            base_generation: slice.base_generation,
            generation: slice.generation,
            added: slice.added.clone(),
            retired: slice.retired.clone(),
        })
        .collect();
    commit_as(graph, db, actor, &events, now).await
}

/// The `RunFinished` event a completion carries, with its parsed run
/// id. A malformed run id fails here — before any apply or append —
/// rather than persisting a row whose replay never applies.
///
/// # Errors
/// `QueueError::Invariant` on an unparseable run id.
fn run_finished_event(
    report: &stow_types::api::WorkflowRunComplete,
) -> Result<(SchedulerEvent, u64), QueueError> {
    let run_id = report.github_run_id.parse::<u64>().map_err(|error| {
        QueueError::Invariant(format!(
            "complete-run github_run_id {:?}: {error}",
            report.github_run_id
        ))
    })?;
    let event = SchedulerEvent::RunFinished {
        run_id: report.github_run_id.clone(),
        task_id: report.task_id.clone(),
        success: report.success,
        cancelled: report.cancelled,
        error: report.error.clone(),
    };
    Ok((event, run_id))
}

/// The completion's in-memory apply — split from the append so the
/// inline dispatch pass can fold the `RunFinished` row into its
/// `Claims` append: the finish frees the slot the claim then reads,
/// and both rows land in one append before any `workflow_dispatch`
/// POST and before the ack (stow#940).
fn apply_run_finished(
    graph: LoadedGraph<'_>,
    report: &stow_types::api::WorkflowRunComplete,
    run_id: u64,
    now: i64,
) -> FinishOutcome {
    graph.with(|graph| {
        graph.last_run_update_ms = Some(now);
        graph.run_finished(
            &report.task_id,
            run_id,
            report.success,
            report.cancelled,
            report.error.clone(),
            now,
        )
    })
}

/// `POST /tasks/complete-run`: one `RunFinished` row per delivery,
/// appended before the ack; its apply lands on the same turn.
///
/// # Errors
/// `QueueError::Sql` on a failed append.
pub(super) async fn complete_run(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    report: &stow_types::api::WorkflowRunComplete,
    now: i64,
) -> Result<FinishOutcome, QueueError> {
    let (event, run_id) = run_finished_event(report)?;
    append(graph, db, None, std::slice::from_ref(&event), now).await?;
    Ok(apply_run_finished(graph, report, run_id, now))
}

/// `POST /tasks/run-update`: the route serves external runs only —
/// the webhook forwards `in_progress` just for a run the scheduler did
/// not dispatch (stow#940), whose delivery appends its occupancy
/// (`ExternalRunStarted`) and stamps the health check's last-delivery
/// instant (stow#860). An own run's `in_progress` still lands through
/// the same path when one arrives — replayed events, or a run whose
/// actor a misnamed slug binding could not classify — `RunUpdate`
/// marks the acceptance so a wake replays it.
///
/// # Errors
/// `QueueError::Sql` on a failed append, `QueueError::Invariant` on a
/// malformed run id or a task id attributing to no runner family.
pub(super) async fn task_run_update(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    update: &stow_types::api::TaskRunUpdate,
    now: i64,
) -> Result<StartOutcome, QueueError> {
    let run_id = update.github_run_id.parse::<u64>().map_err(|error| {
        QueueError::Invariant(format!(
            "run-update github_run_id {:?}: {error}",
            update.github_run_id
        ))
    })?;
    let family = stow_types::ci::family_of_task_id(&update.task_id).ok_or_else(|| {
        QueueError::Invariant(format!(
            "run-update task {} attributes to no runner family",
            update.task_id
        ))
    })?;
    let outcome = graph.with(|graph| {
        graph.last_run_update_ms = Some(now);
        graph.run_started(&update.task_id, run_id, family, now)
    });
    let event = match outcome {
        StartOutcome::External => SchedulerEvent::ExternalRunStarted {
            run_id: update.github_run_id.clone(),
            family,
        },
        StartOutcome::Applied | StartOutcome::Stale => SchedulerEvent::RunUpdate,
    };
    append(graph, db, None, std::slice::from_ref(&event), now).await?;
    Ok(outcome)
}

/// The wake the graph plans — see [`Graph::wake_plan`].
pub(super) fn wake_plan(
    graph: LoadedGraph<'_>,
    settings: &SchedulerSettings,
    now: i64,
) -> AlarmPlan {
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
pub(super) async fn snapshot_if_due(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    now_ms: i64,
) -> Result<bool, QueueError> {
    if !graph.with(|graph| graph.snapshot_due()) {
        return Ok(false);
    }
    snapshot(graph, db, now_ms).await?;
    Ok(true)
}

/// Write the snapshot now. The meter checkpoint lands inside the same
/// storage-only turn, covering every append the snapshot serialized
/// plus the isolate's unsettled counts the cell still holds.
///
/// # Errors
/// `QueueError` on a failed chunk or watermark write.
pub(super) async fn snapshot(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    now_ms: i64,
) -> Result<(), QueueError> {
    // Freed nodes leave the arena before the image is cut.
    graph.with(Graph::compact);
    let plan = graph.with(|graph| graph.snapshot_plan())?;
    let meter = graph.with(|graph| graph.meter.clone());
    store::write_snapshot_parts(
        db,
        &plan,
        |span, encoder| {
            graph.with(|graph| {
                if encoder.is_none() {
                    *encoder = Some(graph.snapshot_encoder(span));
                }
                encoder.as_mut().expect("encoder").next_row(graph)
            })
        },
        &meter,
        graph.cell(),
        now_ms,
    )
    .await?;
    graph.with(|graph| {
        graph.snapshot_written();
        graph.log_since_snapshot = 0;
        graph.log_bytes_since_snapshot = 0;
    });
    Ok(())
}

/// The wake half of `object::ensure_graph`, platform-free so host
/// tests and the `wake` drive run the same sequence (stow#931):
/// [`store::wake`] loads the snapshot plus log tail, replays it and
/// writes the meter checkpoint — covering the wake's own reads and
/// every in-flight operation's unsettled counts — then `woken_at_ms`
/// stamps and the graph installs, all before any non-storage await.
/// `ensure_graph` adds the admission floor and the post-wake CI
/// reconcile on top.
///
/// # Errors
/// `QueueError` on a failed read or checkpoint write.
pub(super) async fn wake_graph<'a>(
    db: &DurableDb,
    cell: &'a GraphCell,
    now_ms: i64,
) -> Result<LoadedGraph<'a>, QueueError> {
    if let Some(loaded) = cell.loaded() {
        return Ok(loaded);
    }
    let mut graph = store::wake(db, cell, now_ms).await?;
    graph.woken_at_ms = now_ms;
    Ok(cell.install(graph))
}

/// Append the `Freeze` events a transition staged — the graph already
/// applied them, so only the log write remains. `db` is the
/// operation's metered handle: the append's rows must book like every
/// other statement so a later checkpoint covers the row's seq and a
/// wake replays it exactly once (stow#931). `actor` attributes a
/// manual transition's row to the run that requested it (stow#955);
/// the automatic trips pass `None`.
///
/// # Errors
/// `QueueError::Sql` on a failed append.
pub(super) async fn persist_freeze(
    db: &DurableDb,
    store: &super::graph::GraphFreezeStore<'_>,
    actor: Option<&str>,
    now: i64,
) -> Result<(), QueueError> {
    let appended = store::append_events(db, actor, &store.take_events(), now).await?;
    store
        .cell()
        .with(|graph| graph.log_appended(appended.bytes, appended.seq));
    Ok(())
}

/// A dispatch pass's claim half: free slots from the dispatch caps and
/// the external occupancy, then the graph's claim in rank order, with
/// ONE `Claims` event appended before any `workflow_dispatch` posts.
/// `bound` caps the claim count — a completion's inline pass claims at
/// most one concurrent POST round (`u32::MAX` claims every free slot).
/// An empty claim set appends nothing.
///
/// # Errors
/// `QueueError::Invariant` when a claimed payload cannot rebuild,
/// `QueueError::Sql` on a failed append.
pub(super) async fn claim_pass(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    settings: &SchedulerSettings,
    now: i64,
    bound: u32,
) -> Result<Vec<Claimed>, QueueError> {
    graph.with(|graph| graph.set_floor(settings.min_dispatch_value));
    let claims = graph.with(|graph| {
        let (total_free, macos_free) = graph.free_slots(settings);
        graph.claim(
            total_free.min(bound),
            macos_free.min(bound),
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
    append(graph, db, None, std::slice::from_ref(&event), now).await?;
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
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    bindings: Vec<stow_types::api::DispatchBinding>,
    failures: Vec<(String, u64, String)>,
    now: i64,
) -> Result<(), QueueError> {
    if !bindings.is_empty() {
        commit(graph, db, &[SchedulerEvent::Bindings { bindings }], now).await?;
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
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    request_id: &str,
    report: &stow_types::api::RequestOutcomeReport,
    actor: Option<&str>,
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
            commit_trees(graph, db, trees, actor, now).await?;
            // The post-enqueue probe the per-target invariant reads.
            let ids: Vec<String> = roots
                .iter()
                .filter_map(|root| root.task_id.clone())
                .collect();
            (
                queued_before,
                graph.with(|graph| graph.probe_roots(&ids, now)),
            )
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
    graph: LoadedGraph<'_>,
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
    graph: LoadedGraph<'_>,
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
    graph: LoadedGraph<'_>,
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
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    hour: &stow_types::api::DemandFeedHour,
    actor: &str,
    now_secs: i64,
) -> Result<stow_types::api::DemandFeedBeginReport, QueueError> {
    let (report, event) = graph.with(|graph| super::feed::feed_begin(graph, hour, now_secs))?;
    commit_as(graph, db, Some(actor), &[event], now_secs * 1_000).await?;
    Ok(report)
}

/// `POST /demand-feed/page`: stage one bounded page. A replayed page of
/// the same bytes appends nothing.
///
/// # Errors
/// The feed's contract refusals, `QueueError::Sql` on a failed append.
pub(super) async fn feed_page(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    request: &stow_types::api::DemandFeedPageRequest,
    actor: &str,
    now_secs: i64,
) -> Result<(), QueueError> {
    if let Some(event) = graph.with(|graph| super::feed::feed_page(graph, request, now_secs))? {
        commit_as(graph, db, Some(actor), &[event], now_secs * 1_000).await?;
    }
    Ok(())
}

/// `POST /demand-feed/complete`: freeze the hour once its manifest
/// verifies.
///
/// # Errors
/// The feed's contract refusals, `QueueError::Sql` on a failed append.
pub(super) async fn feed_complete(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    request: &stow_types::api::DemandFeedCompleteRequest,
    actor: &str,
    now_secs: i64,
) -> Result<(), QueueError> {
    let event = graph.with(|graph| super::feed::feed_complete(graph, request, now_secs))?;
    commit_as(graph, db, Some(actor), &[event], now_secs * 1_000).await
}

/// `POST /demand-feed/cleanup`: retire one bounded chunk of the hour's
/// dead pages.
///
/// # Errors
/// The feed's contract refusals, `QueueError::Sql` on a failed append.
pub(super) async fn feed_cleanup(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    hour: &stow_types::api::DemandFeedHour,
    actor: &str,
    now_secs: i64,
) -> Result<stow_types::api::DemandFeedCleanupReport, QueueError> {
    let (report, event) = graph.with(|graph| super::feed::feed_cleanup(graph, hour, now_secs))?;
    if let Some(event) = event {
        commit_as(graph, db, Some(actor), &[event], now_secs * 1_000).await?;
    }
    Ok(report)
}

/// `POST /demand-feed/deliver`: replay the next undelivered page into
/// the demand fold; returns the report and the wake plan to arm.
///
/// # Errors
/// The feed's contract refusals, `QueueError::Sql` on a failed append.
pub(super) async fn feed_deliver(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    hour: &stow_types::api::DemandFeedHour,
    settings: &SchedulerSettings,
    actor: &str,
    now_ms: i64,
) -> Result<(stow_types::api::DemandFeedDeliverReport, AlarmPlan), QueueError> {
    let (report, events, plan) =
        graph.with(|graph| super::feed::feed_deliver(graph, hour, now_ms, settings))?;
    commit_as(graph, db, Some(actor), &events, now_ms).await?;
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
    use crate::scheduler::graph::GraphCell;
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
        let (db, owner) = seeded().await;
        let cell = owner.loaded().expect("seeded");
        let settings = settings();
        let first = claim_pass(cell, &db, &settings, HOST_NOW_MS, u32::MAX)
            .await
            .expect("first pass");
        assert!(!first.is_empty(), "the fixture leaves free slots");
        let woken_owner = wake(&db).await;
        let woken = woken_owner.loaded().expect("woken");
        let (before, after) = (
            cell.with(|graph| graph.inflight()),
            woken.with(|graph| graph.inflight()),
        );
        assert_eq!(before, after, "the replayed graph holds the same claims");
        let second = claim_pass(woken, &db, &settings, HOST_NOW_MS, u32::MAX)
            .await
            .expect("second pass");
        let taken = ids(&first);
        assert!(
            ids(&second).iter().all(|claim| !taken.contains(claim)),
            "a claimed task was claimed again after the wake"
        );
        let live = claim_pass(cell, &db, &settings, HOST_NOW_MS, u32::MAX)
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
        let (db, owner) = seeded().await;
        let cell = owner.loaded().expect("seeded");
        let settings = settings();
        let woken_owner = wake(&db).await;
        let woken = woken_owner.loaded().expect("woken");
        let lost = claim_pass(cell, &db, &settings, HOST_NOW_MS, u32::MAX)
            .await
            .expect("pass");
        // Rewind the store to before the pass: drop the claim row.
        db.query("DELETE FROM event_log WHERE seq = (SELECT MAX(seq) FROM event_log)")
            .execute()
            .await
            .expect("drop the claim row");
        let again = claim_pass(woken, &db, &settings, HOST_NOW_MS, u32::MAX)
            .await
            .expect("woken pass");
        assert!(!lost.is_empty(), "the fixture leaves free slots");
        assert_eq!(ids(&lost), ids(&again));
    }
}

/// The stow#940 inline-dispatch contract: the request that frees a
/// slot or releases work runs the pass itself — a completion claims at
/// most one `MAX_OUTBOUND_INFLIGHT` round, `index/published` and the
/// request outcome claim every free slot — and the `RunFinished` row
/// folds into the `Claims` append. Anything claimable past the
/// completion's bound arms the alarm at `now`.
#[cfg(test)]
mod inline_dispatch_tests {
    use super::*;
    use crate::scheduler::drives::HOST_NOW_MS;
    use crate::scheduler::fixture::{self, FixtureShape};
    use crate::scheduler::graph::GraphCell;
    use crate::scheduler::test_db;
    use stow_types::api::WorkflowRunComplete;

    const SHAPE: FixtureShape = fixture::GATE;

    /// A completion's inline claim bound: one concurrent POST round.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "MAX_OUTBOUND_INFLIGHT is the small constant 4"
    )]
    const BOUND: u32 = crate::fetch_guard::MAX_OUTBOUND_INFLIGHT as u32;

    /// The production dispatch cap: the fixture holds 30 in flight, so
    /// 15 slots are free.
    fn settings() -> SchedulerSettings {
        SchedulerSettings {
            dispatch: queue::Dispatch::Limited(std::num::NonZeroU32::new(45).expect("45")),
            ..SchedulerSettings::default()
        }
    }

    async fn seeded() -> (DurableDb, GraphCell) {
        let db = test_db::memory_db().await.expect("memory db");
        let cell = GraphCell::default();
        fixture::seed(&db, &cell, SHAPE, HOST_NOW_MS)
            .await
            .expect("seed");
        (db, cell)
    }

    /// What a woken Durable Object holds: the store replayed.
    async fn wake(db: &DurableDb) -> GraphCell {
        let (mut graph, tail) = store::load(db).await.expect("load");
        store::apply_events(&mut graph, &tail);
        let cell = GraphCell::default();
        cell.install(graph);
        cell
    }

    async fn log_rows(db: &DurableDb) -> i64 {
        db.query("SELECT COUNT(*) FROM event_log")
            .fetch_scalar::<i64>()
            .await
            .expect("row count")
    }

    /// A completion for the fixture's `k`-th bound in-flight run.
    fn report(k: u32) -> WorkflowRunComplete {
        let run = SHAPE.in_flight_run(k);
        WorkflowRunComplete {
            task_id: run.task_id,
            success: true,
            error: None,
            cancelled: false,
            github_run_id: run.run_id.to_string(),
        }
    }

    /// A completion whose freed slot is all the pass can take: the cap
    /// leaves exactly the round's bound free, the claim takes them in
    /// the same turn the finish lands — `RunFinished` and `Claims` in
    /// ONE append — and nothing claimable remains, so the wake plan
    /// arms no immediate re-fire.
    #[tokio::test]
    async fn a_completion_claims_inline_and_arms_no_immediate_wake() {
        let (db, owner) = seeded().await;
        let cell = owner.loaded().expect("seeded");
        let settings = SchedulerSettings {
            dispatch: queue::Dispatch::Limited(std::num::NonZeroU32::new(33).expect("33")),
            ..settings()
        };
        // A finished reconcile marks `reconcile_attempted_at`, so only the
        // lease clocks arm the plan.
        cell.with(|graph| graph.reconcile_runs(&[], HOST_NOW_MS));
        let before = log_rows(&db).await;
        let report = report(0);
        assert_eq!(
            complete_run(cell, &db, &report, HOST_NOW_MS)
                .await
                .expect("completion"),
            FinishOutcome::Applied
        );
        let claims = claim_pass(cell, &db, &settings, HOST_NOW_MS, BOUND)
            .await
            .expect("inline pass");
        assert_eq!(
            claims.len(),
            usize::try_from(BOUND).expect("bound"),
            "the pass claims the freed slot plus the three left by the cap"
        );
        assert_eq!(
            log_rows(&db).await - before,
            2,
            "`RunFinished` lands before the pass, then `Claims`"
        );
        match wake_plan(cell, &settings, HOST_NOW_MS) {
            AlarmPlan::At(at) => assert!(
                at > HOST_NOW_MS,
                "nothing remains claimable, so no immediate re-fire"
            ),
            AlarmPlan::Delete => {}
        }
    }

    /// A completion with more claimable than one round: the pass
    /// dispatches the bound and the wake plan arms the alarm at `now`
    /// for the remainder.
    #[tokio::test]
    async fn a_completion_past_the_round_arms_the_alarm_at_now() {
        let (db, owner) = seeded().await;
        let cell = owner.loaded().expect("seeded");
        let settings = settings();
        let report = report(0);
        assert_eq!(
            complete_run(cell, &db, &report, HOST_NOW_MS)
                .await
                .expect("completion"),
            FinishOutcome::Applied
        );
        let claims = claim_pass(cell, &db, &settings, HOST_NOW_MS, BOUND)
            .await
            .expect("inline pass");
        assert_eq!(
            claims.len(),
            usize::try_from(BOUND).expect("bound"),
            "the bound holds at one concurrent round"
        );
        assert_eq!(
            wake_plan(cell, &settings, HOST_NOW_MS),
            AlarmPlan::At(HOST_NOW_MS),
            "the claimable remainder arms the alarm at now"
        );
    }

    /// A failed `workflow_dispatch` POST in an inline pass re-queues
    /// its claim under the dispatch backoff: the row returns to
    /// `pending`, no pass at the same instant reclaims it, and the
    /// wake plan arms at the `not_before`, not sooner.
    #[tokio::test]
    async fn a_failed_post_in_an_inline_pass_takes_the_backoff() {
        let (db, owner) = seeded().await;
        let cell = owner.loaded().expect("seeded");
        let settings = settings();
        cell.with(|graph| graph.reconcile_runs(&[], HOST_NOW_MS));
        let claims = claim_pass(cell, &db, &settings, HOST_NOW_MS, BOUND)
            .await
            .expect("inline pass");
        let failed_ids: std::collections::BTreeSet<&str> =
            claims.iter().map(|claim| claim.task_id.as_str()).collect();
        let failures = claims
            .iter()
            .map(|claim| (claim.task_id.clone(), claim.generation, "boom".to_owned()))
            .collect();
        settle_dispatch(cell, &db, Vec::new(), failures, HOST_NOW_MS)
            .await
            .expect("settle");
        let status = cell.with(|graph| {
            graph
                .list(
                    &stow_types::api::QueueSelector {
                        task_ids: vec![claims[0].task_id.clone()],
                        ..stow_types::api::QueueSelector::default()
                    },
                    HOST_NOW_MS,
                )
                .map(|tasks| tasks[0].status)
        });
        assert_eq!(
            status.expect("listed"),
            stow_types::api::QueueTaskStatus::Pending,
            "a failed claim re-queues to pending"
        );
        let second = claim_pass(cell, &db, &settings, HOST_NOW_MS, u32::MAX)
            .await
            .expect("same-instant pass");
        assert!(
            second
                .iter()
                .all(|claim| !failed_ids.contains(claim.task_id.as_str())),
            "a claim under its not_before is not reclaimed"
        );
        match wake_plan(cell, &settings, HOST_NOW_MS) {
            AlarmPlan::At(armed) => assert!(
                armed > HOST_NOW_MS,
                "the backoff arms the alarm at not_before"
            ),
            plan @ AlarmPlan::Delete => {
                panic!("a backed-off claim arms a wake: {plan:?}");
            }
        }
    }

    /// A frozen dispatch claims nothing inline — the folded
    /// `RunFinished` still lands, alone, in one append.
    #[tokio::test]
    async fn a_frozen_dispatch_claims_nothing_inline() {
        let (db, owner) = seeded().await;
        let cell = owner.loaded().expect("seeded");
        let settings = SchedulerSettings {
            dispatch: queue::Dispatch::Paused,
            ..settings()
        };
        let before = log_rows(&db).await;
        let report = report(0);
        assert_eq!(
            complete_run(cell, &db, &report, HOST_NOW_MS)
                .await
                .expect("completion"),
            FinishOutcome::Applied
        );
        let claims = claim_pass(cell, &db, &settings, HOST_NOW_MS, BOUND)
            .await
            .expect("frozen pass");
        assert!(claims.is_empty(), "a frozen dispatch claims nothing");
        assert_eq!(
            log_rows(&db).await - before,
            1,
            "the completion still lands its `RunFinished` row"
        );
    }

    /// The slice-report pass claims every free slot — the release
    /// route's bound is the dispatch cap, never the completion round.
    #[tokio::test]
    async fn a_slice_report_claims_every_free_slot() {
        let (db, owner) = seeded().await;
        let cell = owner.loaded().expect("seeded");
        let settings = settings();
        let free = cell.with(|graph| graph.free_slots(&settings)).0;
        let claims = claim_pass(cell, &db, &settings, HOST_NOW_MS, u32::MAX)
            .await
            .expect("slice-report pass");
        assert_eq!(
            claims.len(),
            usize::try_from(free).expect("free slots"),
            "every free slot claimed in one pass"
        );
        assert!(
            claims.len() > usize::try_from(BOUND).expect("bound"),
            "the pass is not held to the completion's round"
        );
    }

    /// A bounded claim is a prefix of the unbounded claim — the bound
    /// never reorders the rank.
    #[tokio::test]
    async fn a_bounded_claim_keeps_the_rank_order() {
        let (db_bound, owner_bound) = seeded().await;
        let bound_cell = owner_bound.loaded().expect("seeded");
        let (db_free, owner_free) = seeded().await;
        let free_cell = owner_free.loaded().expect("seeded");
        let settings = settings();
        let bounded = claim_pass(bound_cell, &db_bound, &settings, HOST_NOW_MS, BOUND)
            .await
            .expect("bounded pass");
        let unbounded = claim_pass(free_cell, &db_free, &settings, HOST_NOW_MS, u32::MAX)
            .await
            .expect("unbounded pass");
        let bounded_ids: Vec<&str> = bounded.iter().map(|c| c.task_id.as_str()).collect();
        let prefix: Vec<&str> = unbounded
            .iter()
            .take(bounded.len())
            .map(|c| c.task_id.as_str())
            .collect();
        assert_eq!(bounded_ids, prefix, "the bound truncates, never reorders");
    }

    /// Evicted after the completion's combined append and before the
    /// `Bindings` row: the woken graph replays the finish and the
    /// claims as dispatched-unbound — its next pass takes only fresh
    /// tasks, and the completion that arrives for one binds that
    /// replayed claim exactly once.
    #[tokio::test]
    async fn an_eviction_between_the_combined_append_and_bindings_builds_once() {
        let (db, owner) = seeded().await;
        let cell = owner.loaded().expect("seeded");
        let settings = settings();
        let report = report(0);
        assert_eq!(
            complete_run(cell, &db, &report, HOST_NOW_MS)
                .await
                .expect("completion"),
            FinishOutcome::Applied
        );
        let claims = claim_pass(cell, &db, &settings, HOST_NOW_MS, BOUND)
            .await
            .expect("inline pass");
        assert!(!claims.is_empty());
        let woken_owner = wake(&db).await;
        let woken = woken_owner.loaded().expect("woken");
        // The replayed claims stay claimed: the woken pass takes only
        // the tasks the first pass left.
        let second = claim_pass(woken, &db, &settings, HOST_NOW_MS, u32::MAX)
            .await
            .expect("woken pass");
        let taken: std::collections::BTreeSet<&str> =
            claims.iter().map(|claim| claim.task_id.as_str()).collect();
        assert!(
            second
                .iter()
                .all(|claim| !taken.contains(claim.task_id.as_str())),
            "a replayed claim was claimed again"
        );
        // The completion for one of the replayed claims binds and
        // finishes it — one build, once.
        let again = woken.with(|graph| {
            graph.run_finished(&claims[0].task_id, 9_999, true, false, None, HOST_NOW_MS)
        });
        assert!(
            matches!(again, FinishOutcome::Applied),
            "the replayed claim binds its completion once: {again:?}"
        );
    }

    /// The finish is durable before the pass can fail: `RunFinished`
    /// lands alone, so even a pass that never runs leaves a row a
    /// woken object replays into a finished node (stow#940).
    #[tokio::test]
    async fn a_completion_is_durable_before_any_pass() {
        let (db, owner) = seeded().await;
        let cell = owner.loaded().expect("seeded");
        let before = log_rows(&db).await;
        let report = report(0);
        assert_eq!(
            complete_run(cell, &db, &report, HOST_NOW_MS)
                .await
                .expect("completion"),
            FinishOutcome::Applied
        );
        assert_eq!(
            log_rows(&db).await - before,
            1,
            "the finish appends alone, before the pass"
        );
        let woken_owner = wake(&db).await;
        let woken = woken_owner.loaded().expect("woken");
        let status = woken.with(|graph| {
            graph
                .list(
                    &stow_types::api::QueueSelector {
                        task_ids: vec![report.task_id.clone()],
                        ..stow_types::api::QueueSelector::default()
                    },
                    HOST_NOW_MS,
                )
                .map(|tasks| tasks[0].status)
        });
        assert_eq!(
            status.expect("listed"),
            stow_types::api::QueueTaskStatus::Completed,
            "a wake replays the completion even without a pass"
        );
    }

    /// A completion's inline pass never reconciles: the run listing
    /// stays undone and `wake_plan` arms the alarm for it, so the
    /// webhook answers inside GitHub's delivery window (stow#940).
    #[tokio::test]
    async fn a_due_reconcile_arms_the_alarm_for_a_completion() {
        let (db, owner) = seeded().await;
        let cell = owner.loaded().expect("seeded");
        let settings = settings();
        let report = report(0);
        assert_eq!(
            complete_run(cell, &db, &report, HOST_NOW_MS)
                .await
                .expect("completion"),
            FinishOutcome::Applied
        );
        claim_pass(cell, &db, &settings, HOST_NOW_MS, BOUND)
            .await
            .expect("inline pass");
        // The seeded graph never reconciled, so the listing is due and
        // the completion's skipped reconcile arms the alarm at now.
        assert_eq!(
            wake_plan(cell, &settings, HOST_NOW_MS),
            AlarmPlan::At(HOST_NOW_MS),
            "a due reconcile arms the alarm, not the webhook"
        );
    }
}

/// stow#955: every mutation a workflow identity requested is
/// attributed in the log to that run's verified actor, and a manual
/// freeze's record names it — both surviving a wake.
#[cfg(test)]
mod attribution_tests {
    use super::*;
    use crate::scheduler::drives::HOST_NOW_MS;
    use crate::scheduler::fixture;
    use crate::scheduler::graph::{Graph, GraphCell, GraphFreezeStore};
    use crate::scheduler::test_db;
    use stow_types::api::{
        ChannelOutcome, DispatchFreezeTrigger, FreezeTransitionEvent, SubmissionSource,
    };

    #[derive(skyzen::FromRow)]
    struct Row {
        event: String,
    }

    /// Each log row's `actor`, in append order.
    async fn row_actors(db: &DurableDb) -> Vec<Option<String>> {
        db.query("SELECT event FROM event_log ORDER BY seq")
            .fetch_all::<Row>()
            .await
            .expect("rows")
            .iter()
            .map(|row| {
                serde_json::from_str::<serde_json::Value>(&row.event).expect("row json")["actor"]
                    .as_str()
                    .map(str::to_owned)
            })
            .collect()
    }

    async fn woken(db: &DurableDb) -> GraphCell {
        let (mut graph, tail) = store::load(db).await.expect("load");
        store::apply_events(&mut graph, &tail);
        let cell = GraphCell::default();
        cell.install(graph);
        cell
    }

    struct Sink;

    impl crate::freeze::AlertSink for Sink {
        fn opened(
            &self,
            _draft: &crate::freeze::AlertDraft,
        ) -> impl std::future::Future<Output = ChannelOutcome> + Send {
            core::future::ready(ChannelOutcome::Sent { message_id: None })
        }
        fn updated(
            &self,
            _draft: &crate::freeze::AlertDraft,
        ) -> impl std::future::Future<Output = ChannelOutcome> + Send {
            core::future::ready(ChannelOutcome::Sent { message_id: None })
        }
        fn resolved(
            &self,
            _draft: &crate::freeze::AlertDraft,
        ) -> impl std::future::Future<Output = ChannelOutcome> + Send {
            core::future::ready(ChannelOutcome::Sent { message_id: None })
        }
    }

    /// One manual transition as `write_dispatch_freeze` runs it.
    async fn manual(
        db: &DurableDb,
        cell: LoadedGraph<'_>,
        action: crate::freeze::FreezeAction,
        actor: &str,
    ) {
        let store = GraphFreezeStore::new(cell, "2026-10-28T12:00:00Z".to_owned(), HOST_NOW_MS);
        crate::freeze::apply_transition(
            &store,
            &Sink,
            action,
            DispatchFreezeTrigger::Manual {
                actor: actor.to_owned(),
            },
            "2026-10-28T12:00:00Z",
        )
        .await
        .expect("transition");
        persist_freeze(db, &store, Some(actor), HOST_NOW_MS)
            .await
            .expect("persist");
    }

    #[tokio::test]
    async fn a_manual_freeze_names_who_engaged_and_who_cleared_it() {
        let db = test_db::memory_db().await.expect("db");
        let owner = GraphCell::default();
        let cell = owner.install(Graph::default());
        manual(
            &db,
            cell,
            crate::freeze::FreezeAction::Freeze,
            "octo-engager",
        )
        .await;

        let engaged = woken(&db).await;
        let record = engaged
            .loaded()
            .expect("woken")
            .with(|graph| graph.freeze().cloned())
            .expect("frozen after the wake");
        assert_eq!(
            record.trigger,
            DispatchFreezeTrigger::Manual {
                actor: "octo-engager".to_owned()
            }
        );

        manual(
            &db,
            cell,
            crate::freeze::FreezeAction::Clear,
            "octo-clearer",
        )
        .await;
        assert_eq!(
            row_actors(&db).await,
            vec![
                Some("octo-engager".to_owned()),
                Some("octo-clearer".to_owned())
            ],
            "the engage and the clear rows each name their own run"
        );
        let cleared = woken(&db).await;
        let transitions = cleared
            .loaded()
            .expect("woken")
            .with(|graph| graph.freeze_transitions());
        let last = transitions.first().expect("newest first: the clear");
        assert_eq!(last.event, FreezeTransitionEvent::Cleared);
        assert_eq!(
            last.trigger,
            Some(DispatchFreezeTrigger::Manual {
                actor: "octo-engager".to_owned()
            }),
            "a cleared line still echoes the trigger it cleared"
        );
    }

    /// A trusted submit and a queue mutation attribute their first row;
    /// a no-op mutation appends nothing at all.
    #[tokio::test]
    async fn trusted_mutations_attribute_their_first_row() {
        let db = test_db::memory_db().await.expect("db");
        let owner = GraphCell::default();
        let cell = owner.install(Graph::default());
        let tree = SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![0],
            nodes: vec![fixture::fixture_node(9_000_000, Vec::new())],
        };
        let task_id = tree.nodes[0].task_id.clone();
        commit_trees(
            cell,
            &db,
            std::slice::from_ref(&tree),
            Some("octo-submitter"),
            1,
        )
        .await
        .expect("submit");
        let cancel = QueueSelector {
            task_ids: vec![task_id],
            ..QueueSelector::default()
        };
        let cancelled = mutate(
            cell,
            &db,
            MutationKind::Cancel,
            &cancel,
            Some("octo-operator"),
            HOST_NOW_MS,
        )
        .await
        .expect("cancel");
        assert_eq!(cancelled, 1);
        let unknown = QueueSelector {
            task_ids: vec!["no-such-task".to_owned()],
            ..QueueSelector::default()
        };
        mutate(
            cell,
            &db,
            MutationKind::Cancel,
            &unknown,
            Some("octo-operator"),
            HOST_NOW_MS,
        )
        .await
        .expect("no-op cancel");
        assert_eq!(
            row_actors(&db).await,
            vec![
                Some("octo-submitter".to_owned()),
                Some("octo-operator".to_owned())
            ]
        );
    }
}

/// The miss lane's pending cap bounds the miss lane alone (stow#1058).
#[cfg(test)]
mod miss_cap_tests {
    use super::*;
    use crate::scheduler::drives::HOST_NOW_MS;
    use crate::scheduler::fixture;
    use crate::scheduler::graph::GraphCell;
    use crate::scheduler::test_db;
    use stow_types::api::SubmissionSource;

    /// Fixture rows far outside the seeded range, so every node is new.
    const FIRST_ROW: u32 = 6_000_000;

    fn tree(source: SubmissionSource, first: u32, nodes: u32) -> SubmissionTree {
        SubmissionTree {
            source,
            roots: Vec::new(),
            nodes: (first..first + nodes)
                .map(|n| fixture::fixture_node(n, Vec::new()))
                .collect(),
        }
    }

    /// A preheat backlog far above the cap leaves a CLI miss admitted
    /// and pending; the cap still refuses a miss batch past its own
    /// lane's depth.
    #[tokio::test]
    async fn preheat_backlog_does_not_count_against_the_miss_cap() {
        let db = test_db::memory_db().await.expect("db");
        let owner = GraphCell::default();
        let cell = owner.install(Graph::default());
        let settings = SchedulerSettings {
            max_queue_pending: 3,
            ..SchedulerSettings::default()
        };
        let backlog = tree(SubmissionSource::Preheat, FIRST_ROW, 50);
        submit(cell, &db, &settings, &[backlog], false, None, HOST_NOW_MS)
            .await
            .expect("preheat backlog");
        assert!(cell.with(|graph| graph.status().pending) > settings.max_queue_pending);

        let miss = tree(SubmissionSource::CacheMiss, FIRST_ROW + 100, 3);
        let (inserted, _) = submit(cell, &db, &settings, &[miss], true, None, HOST_NOW_MS)
            .await
            .expect("a miss is admitted under a preheat backlog");
        assert_eq!(inserted, 3);
        assert_eq!(cell.with(|graph| graph.miss_pending_depth()), 3);

        let over = tree(SubmissionSource::CacheMiss, FIRST_ROW + 200, 1);
        let refused = submit(cell, &db, &settings, &[over], true, None, HOST_NOW_MS)
            .await
            .expect_err("the miss lane's own depth still hits the cap");
        assert!(matches!(
            refused,
            QueueError::QueueFull { pending: 3, cap: 3 }
        ));
    }
}

/// The snapshot trigger is events OR bytes, whichever comes first: a
/// wake replays at most the byte threshold of log, whatever the
/// submissions weigh (stow#878 §3.3).
#[cfg(test)]
mod snapshot_trigger_tests {
    use super::*;
    use crate::scheduler::drives::HOST_NOW_MS;
    use crate::scheduler::fixture;
    use crate::scheduler::graph::GraphCell;
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
            let owner = GraphCell::default();
            let cell = owner.install(Graph::default());
            let mut snapshots = 0u32;
            let mut widest = 0u64;
            for turn in 0..40u32 {
                let tree = tree(FIRST_ROW + turn * nodes, nodes);
                commit_trees(cell, &db, std::slice::from_ref(&tree), None, 1)
                    .await
                    .expect("submit");
                if snapshot_if_due(cell, &db, HOST_NOW_MS)
                    .await
                    .expect("snapshot")
                {
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
        let owner = GraphCell::default();
        let cell = owner.install(Graph::default());
        let wave = tree(FIRST_ROW, WAVE);
        commit_trees(cell, &db, std::slice::from_ref(&wave), None, 1)
            .await
            .expect("submit the wave");
        assert!(
            cell.with(|graph| graph.log_bytes_since_snapshot) > 100 << 20,
            "the wave is over 100 MiB of log"
        );
        assert!(
            snapshot_if_due(cell, &db, HOST_NOW_MS)
                .await
                .expect("snapshot")
        );
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
