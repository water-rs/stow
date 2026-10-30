use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use crate::scheduler::graph::RootProbe;
use skyzen_services::durable::Alarm;
use stow_types::identity::TargetTriple;

use crate::errors::QueueError;

// Dispatch ceiling defaults, used when neither a deploy binding nor an
// operator `dispatch-cap set` names one. Sized against the org's 60
// GitHub-hosted runners (15 of them macOS): 45 total leaves 15 runners
// for the repo's own CI, and the macOS cap keeps a full wave from
// queueing on the smallest pool while leaving 4 macOS runners free.
const DEFAULT_MAX_CONCURRENT_JOBS: NonZeroU32 = NonZeroU32::new(45).unwrap();
const DEFAULT_MAX_CONCURRENT_MACOS_JOBS: u32 = 11;
const DEFAULT_DISPATCH_MIN_AGE_MINUTES: u32 = 5;
// A single crate build on GitHub-hosted runners (toolchain install + compile
// + sign + push) can legitimately take tens of minutes and nothing updates
// the row while CI runs, so the stale-recovery cutoff must comfortably
// exceed the slowest expected build or long builds get double-dispatched.
const DEFAULT_STALE_DISPATCH_MINUTES: u32 = 60;
// A single `build-crate.yml` run claims one runner slot; the caps
// count in-flight tasks.
// Exponential dispatch-failure backoff cap.
const MAX_DISPATCH_BACKOFF_MINUTES: u32 = 60;

/// Failed-build retry cap: a failure reported while `attempt` is under
/// this re-queues the row under `not_before` backoff; a failure at the cap
/// parks it `failed` for an operator `retry`, which resets the cycle to 1.
pub const MAX_BUILD_ATTEMPTS: u32 = 4;

/// The priority operand a CLI cache miss carries, in centi-units —
/// the unit every other entry point's priority is a multiple of
/// (stow#879). A node's rank is `operand × time waited`, so `100` is
/// the `1` of the issue's table.
pub const MISS_PRIORITY: i64 = 100;
/// `stow.waterui.dev` — 30× the CLI's priority.
pub const REQUEST_PRIORITY: i64 = 3_000;
/// Preheat — a tenth of the CLI's priority.
pub const PREHEAT_PRIORITY: i64 = 10;
/// The inexact-hit report — a hundredth of the CLI's priority.
pub const INEXACT_PRIORITY: i64 = 1;

/// The scale a profile's weight is a share of: the dev profile ranks at
/// the whole scale, so a rank is `priority × weight × waited` with the
/// weight a whole number of hundredths (stow#1012).
pub const PRIORITY_SCALE: u32 = 100;
/// Default for the operator's `release-priority set`: release-profile
/// nodes rank at this percent of their entry point's priority, inside
/// the same aging rank as every other node. Provisional.
pub const DEFAULT_RELEASE_PRIORITY_PERCENT: u32 = 10;

/// A node's weight in the claim rank: its profile's share of
/// [`PRIORITY_SCALE`], `release_percent` being the operator's release
/// multiplier.
pub const fn profile_weight(
    profile: stow_types::node_profile::NodeProfile,
    release_percent: u32,
) -> u32 {
    use stow_types::node_profile::NodeProfile as P;
    match profile {
        P::Dev => PRIORITY_SCALE,
        P::Release => release_percent,
    }
}

/// The priority operand a submission tree's nodes enter the rank with
/// (stow#879): the source's class, or the caller's own value for
/// operations. The operand is what `rank = operand × waited` reads.
pub const fn source_priority(source: stow_types::api::SubmissionSource) -> i64 {
    use stow_types::api::SubmissionSource as S;
    match source {
        S::Operations { priority } => priority,
        S::CacheMiss => MISS_PRIORITY,
        S::HumanRequest => REQUEST_PRIORITY,
        S::Preheat => PREHEAT_PRIORITY,
        S::InexactHit => INEXACT_PRIORITY,
    }
}

/// Default for `STOW_MAX_QUEUE_PENDING` — miss-lane pending depth at which
/// miss-lane submits start being refused. The edge handler reads the same
/// binding for its pre-forward check, so this constant is the shared
/// default for both.
pub const DEFAULT_MAX_QUEUE_PENDING: u32 = 2_000;
/// Default for `STOW_HUMAN_DAILY_TASK_BUDGET` — human-lane tasks the
/// scheduler accepts per UTC day.
pub const DEFAULT_HUMAN_DAILY_TASK_BUDGET: u32 = 2_000;

/// Whether the scheduler dispatches at all, and the in-flight bound when
/// it does.
///
/// `Paused` is a real operating state — the deployment doc's deliberate
/// pause via `STOW_MAX_CONCURRENT_JOBS = "0"` — not a zero-sized limit:
/// submits keep queueing and nothing is claimed until a redeploy restores
/// a non-zero value. Carrying it in the type keeps "no dispatch" from
/// ever being expressed as a number, where a `0` reads as a cap the queue
/// arithmetic must somehow honor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// Submits keep queueing; nothing is claimed. The alarm still wakes
    /// at the earliest in-flight lease expiry so stale recovery runs.
    Paused,
    /// At most this many tasks in flight (`dispatched`/`running`) across
    /// all runner families.
    Limited(NonZeroU32),
}

impl Dispatch {
    /// The `STOW_MAX_CONCURRENT_JOBS` value: `0` pauses dispatch, any
    /// other value bounds the in-flight set.
    #[must_use]
    pub const fn from_max_concurrent_jobs(raw: u32) -> Self {
        match NonZeroU32::new(raw) {
            Some(limit) => Self::Limited(limit),
            None => Self::Paused,
        }
    }
}

/// Runtime-tunable scheduler knobs, read from Worker env bindings by the
/// Durable Object glue (`STOW_MAX_CONCURRENT_JOBS`,
/// `STOW_MAX_CONCURRENT_MACOS_JOBS`, `STOW_DISPATCH_MIN_AGE_MINUTES`,
/// `STOW_STALE_DISPATCH_MINUTES`, `STOW_MAX_QUEUE_PENDING`,
/// `STOW_HUMAN_DAILY_TASK_BUDGET`, `STOW_MIN_DISPATCH_VALUE`,
/// `STOW_MIN_DISPATCH_VALUE`).
///
/// Defaults match production; the local mock lowers `dispatch` via `vars`
/// because miniflare's workerd OOMs under parallel complete
/// bursts.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerSettings {
    /// The dispatch posture — see [`Dispatch`].
    pub dispatch: Dispatch,
    /// Cap on in-flight tasks whose target maps to the macOS runner
    /// family — the smallest pool in the org's fleet.
    pub max_concurrent_macos_jobs: u32,
    pub dispatch_min_age_minutes: u32,
    pub stale_dispatch_minutes: u32,
    /// Pending-queue depth at which [`enqueue`] refuses miss-lane
    /// submits. Human-lane tasks and [`enqueue_trusted`] callers are
    /// exempt.
    pub max_queue_pending: u32,
    /// Human-lane tasks accepted per UTC day, counted in the
    /// `human_daily_task_budget` table.
    pub human_daily_task_budget: u32,
    /// Admission floor on a node's rank operand (its priority,
    /// stow#879): a pending non-request node claims only while its
    /// operand reaches this bound — under-floor work stays queued and
    /// visible rather than being built. `0` admits everything. The
    /// human lane is exempt: a request someone asked for by name is
    /// never held by the floor. Parsed from `STOW_MIN_DISPATCH_VALUE`
    /// as a nonnegative i64 — the *operator input* the deploy binding
    /// stamps on each wake. A changed binding takes effect on the next
    /// [`crate::scheduler::graph::Graph::set_floor`] call.
    pub min_dispatch_value: i64,
}

impl Default for SchedulerSettings {
    fn default() -> Self {
        Self {
            dispatch: Dispatch::Limited(DEFAULT_MAX_CONCURRENT_JOBS),
            max_concurrent_macos_jobs: DEFAULT_MAX_CONCURRENT_MACOS_JOBS,
            dispatch_min_age_minutes: DEFAULT_DISPATCH_MIN_AGE_MINUTES,
            stale_dispatch_minutes: DEFAULT_STALE_DISPATCH_MINUTES,
            max_queue_pending: DEFAULT_MAX_QUEUE_PENDING,
            human_daily_task_budget: DEFAULT_HUMAN_DAILY_TASK_BUDGET,
            min_dispatch_value: DEFAULT_MIN_DISPATCH_VALUE,
        }
    }
}

impl SchedulerSettings {
    /// These binding settings under the operator's `dispatch-cap set`
    /// (stow#1039): its values replace the bindings' caps, and a
    /// `--macos`-less set leaves the macOS cap on its binding. The one
    /// place a stored setting enters the caps — the scheduler object
    /// applies it when it builds a request's or the alarm's settings,
    /// and everything downstream reads only the settings it is passed.
    #[must_use]
    pub const fn with_dispatch_cap(
        self,
        setting: Option<&stow_types::api::DispatchCapSetting>,
    ) -> Self {
        let Some(setting) = setting else {
            return self;
        };
        Self {
            dispatch: Dispatch::from_max_concurrent_jobs(setting.max_concurrent_jobs),
            max_concurrent_macos_jobs: match setting.max_concurrent_macos_jobs {
                Some(macos) => macos,
                None => self.max_concurrent_macos_jobs,
            },
            ..self
        }
    }
}

/// Seconds from `now_unix` to the next UTC midnight — the `Retry-After`
/// the edge attaches to a daily-budget refusal, matching the
/// `date('now')` rollover the `human_daily_task_budget` table keys on.
#[must_use]
pub const fn seconds_until_utc_midnight(now_unix: i64) -> u64 {
    // rem_euclid keeps the offset positive even for a pre-epoch input.
    #[expect(
        clippy::cast_sign_loss,
        reason = "86_400 - rem_euclid(86_400) is in 1..=86_400, always positive"
    )]
    let seconds = (86_400 - now_unix.rem_euclid(86_400)) as u64;
    seconds
}

/// What `submit_task_ids` reports: new queue rows inserted, plus the
/// submitted ids the node store does not hold — reported as unknown,
/// never re-minted (stow#588).
#[derive(Debug, Default)]
pub struct SubmitTaskIdsOutcome {
    pub inserted: u32,
    pub unknown: Vec<String>,
}

/// A request record's `state` holds a [`CrateRequestPhase`]'s
/// `snake_case` name and `outcome_json` the settled attempt's stored
/// roots — now `graph::RequestRecord`, replayed by `Request` events.
/// The per-target root `outcome_json` stores: the resolve job's
/// [`RequestRootOutcome`] plus whether the root's queue row already
/// existed when the outcome's enqueue ran — the fact a status read
/// needs to tell `queued` (the request's own work) from
/// `already_queued` (a row the request found).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RequestStoredRoot {
    /// The CI target this root serves.
    target: String,
    /// The lib-root task id — `None` for a crate with no library.
    task_id: Option<String>,
    /// The published slice already served the root at resolve time.
    cached: bool,
    /// The root's queue row existed before the outcome's enqueue.
    was_queued: bool,
}

/// The dedup decision `admit_request` hands back.
#[derive(Debug)]
pub enum RequestAdmissionStep {
    /// The record inserted (or a `failed` one re-attempted): dispatch the
    /// resolve run for this attempt.
    Dispatch {
        /// The record's live attempt — stamps the run name and payload.
        attempt: u32,
    },
    /// A live record already serves this request id — answer it as-is.
    Existing,
}

/// The `requests` table's `state` strings ↔ [`CrateRequestPhase`].
fn request_phase(state: &str) -> Result<stow_types::api::CrateRequestPhase, QueueError> {
    use stow_types::api::CrateRequestPhase as Phase;
    match state {
        "accepted" => Ok(Phase::Accepted),
        "resolving" => Ok(Phase::Resolving),
        "enqueued" => Ok(Phase::Enqueued),
        "failed" => Ok(Phase::Failed),
        other => Err(QueueError::Invariant(format!(
            "stored request state `{other}`"
        ))),
    }
}

/// Read one request record — the `requests` row's in-memory
/// equivalent, replayed through `Request` events (stow#878 stage 7).
fn load_request<'a>(
    graph: &'a crate::scheduler::graph::Graph,
    request_id: &str,
) -> Option<&'a crate::scheduler::graph::RequestRecord> {
    graph.requests.get(request_id)
}

/// `POST /requests` admission. A live record answers as found (the
/// request deduplicates on its deterministic id); a `failed` one
/// re-attempts — `attempt + 1` in the same conditional write, so the
/// run-name's `a{attempt}` leg keeps a stale run's webhook events off
/// the live attempt. Both spend a resolve run, so the insertion is
/// gated on today's human-lane budget having any room at all — the
/// enqueue's own charge still applies at outcome time; this probe only
/// refuses a dispatch whose tasks can never land.
pub fn admit_request(
    graph: &crate::scheduler::graph::Graph,
    admission: &stow_types::api::RequestAdmission,
    dispatched_at: i64,
    settings: &SchedulerSettings,
) -> Result<
    (
        RequestAdmissionStep,
        Option<stow_types::api::SchedulerEvent>,
    ),
    QueueError,
> {
    let record = load_request(graph, &admission.request_id);
    if let Some(record) = record
        && record.state != "failed"
    {
        return Ok((RequestAdmissionStep::Existing, None));
    }
    // The probe the SQL read over `human_daily_task_budget` — a fresh
    // day resets the spend, same as `date('now')` keyed the row.
    let spent = if graph.human_budget.0 == dispatched_at.div_euclid(86_400) {
        graph.human_budget.1
    } else {
        0
    };
    if spent >= i64::from(settings.human_daily_task_budget) {
        return Err(QueueError::HumanDailyBudgetExhausted {
            attempted: 1,
            budget: u64::from(settings.human_daily_task_budget),
        });
    }
    // A `failed` record re-attempts at `attempt + 1` — the same
    // conditional write `ON CONFLICT … WHERE state = 'failed'` gave.
    let attempt = record.map_or(1, |record| record.attempt + 1);
    let event = stow_types::api::SchedulerEvent::Request {
        request_id: admission.request_id.clone(),
        kind: stow_types::api::RequestEvent::Admitted {
            admission: Box::new(admission.clone()),
            attempt,
            dispatched_at,
        },
    };
    Ok((RequestAdmissionStep::Dispatch { attempt }, Some(event)))
}

/// The dispatch-failure write — flips the live attempt `failed` naming
/// the dispatch error, so a later re-request's re-attempt (which keys on
/// `failed`) can retry.
pub fn fail_request_dispatch(
    graph: &crate::scheduler::graph::Graph,
    request_id: &str,
    attempt: u32,
    error: &str,
) -> Option<stow_types::api::SchedulerEvent> {
    let record = load_request(graph, request_id)?;
    if record.attempt != attempt || record.state != "accepted" {
        return None;
    }
    Some(stow_types::api::SchedulerEvent::Request {
        request_id: request_id.to_owned(),
        kind: stow_types::api::RequestEvent::Outcome {
            attempt,
            state: "failed".to_owned(),
            outcome_json: None,
            error: Some(error.to_owned()),
        },
    })
}

/// The stored-root post-enqueue probe `request_record_status` takes —
/// task ids in, current statuses out (stow#878).
///
/// Filter the caller's graph-probed statuses to `ids` — the stored-root
/// re-validation's post-enqueue probe.
fn probe_by_id(probe: &RootProbe, ids: &[String]) -> RootProbe {
    RootProbe {
        statuses: ids
            .iter()
            .filter_map(|id| {
                probe
                    .statuses
                    .get(id)
                    .map(|status| (id.clone(), status.clone()))
            })
            .collect(),
        published: ids
            .iter()
            .filter(|id| probe.published.contains(*id))
            .cloned()
            .collect(),
    }
}

/// `POST /requests/{id}/outcome` — apply the resolve job's report.
///
/// A `Resolved` report enqueues its batch through the trusted lane
/// (verbatim — the resolver already pinned each identity, so the
/// canonicalization the admin submit route applies would only rewrite
/// the ids the report names), computes `was_queued` from a pre-enqueue
/// probe, stores the per-target roots, and flips the record `enqueued`
/// in one conditional write. A `Failed` report — or the trusted
/// enqueue's own refusal — flips it `failed` with the reason. Reports
/// naming a superseded attempt answer `RequestAttemptSuperseded`; a
/// report on an already-settled record is a no-op that re-answers the
/// stored state.
pub fn apply_request_outcome(
    graph: &crate::scheduler::graph::Graph,
    request_id: &str,
    report: &stow_types::api::RequestOutcomeReport,
    queued_before: &BTreeSet<String>,
    by_id: &RootProbe,
) -> Result<
    (
        stow_types::api::CrateRequestStatus,
        Option<stow_types::api::SchedulerEvent>,
    ),
    QueueError,
> {
    let record = load_request(graph, request_id)
        .ok_or_else(|| QueueError::UnknownRequest(request_id.to_owned()))?;
    if record.attempt != report.attempt {
        return Err(QueueError::RequestAttemptSuperseded {
            request_id: request_id.to_owned(),
            live: record.attempt,
            reported: report.attempt,
        });
    }
    if matches!(record.state.as_str(), "enqueued" | "failed") {
        return Ok((
            request_record_status(record, &move |ids: &[String]| probe_by_id(by_id, ids))?,
            None,
        ));
    }
    match &report.outcome {
        stow_types::api::RequestOutcome::Failed { error } => {
            let mut settled = record.clone();
            "failed".clone_into(&mut settled.state);
            settled.error = Some(error.clone());
            let event = stow_types::api::SchedulerEvent::Request {
                request_id: request_id.to_owned(),
                kind: stow_types::api::RequestEvent::Outcome {
                    attempt: report.attempt,
                    state: "failed".to_owned(),
                    outcome_json: None,
                    error: Some(error.clone()),
                },
            };
            Ok((
                request_record_status(&settled, &move |ids: &[String]| probe_by_id(by_id, ids))?,
                Some(event),
            ))
        }
        stow_types::api::RequestOutcome::Resolved { trees: _, roots } => {
            resolve_request_record(record, report.attempt, queued_before, by_id, roots)
        }
    }
}

/// The `Resolved` arm of [`apply_request_outcome`]: probe the roots for
/// `was_queued` before the enqueue, run the batch through the trusted
/// insert path, then settle the record `enqueued` with its stored roots
/// in one conditional write — the `state IN ('accepted', 'resolving')`
/// guard keeps a `completed` webhook racing the other way from erasing
/// the outcome.
fn resolve_request_record(
    record: &crate::scheduler::graph::RequestRecord,
    attempt: u32,
    queued_before: &BTreeSet<String>,
    by_id: &RootProbe,
    roots: &[stow_types::api::RequestRootOutcome],
) -> Result<
    (
        stow_types::api::CrateRequestStatus,
        Option<stow_types::api::SchedulerEvent>,
    ),
    QueueError,
> {
    // `was_queued` and `by_id` arrive graph-computed: the route probed
    // the in-memory graph before merging the report's trees (stow#878).
    let mut stored = Vec::with_capacity(roots.len());
    let mut targets = Vec::with_capacity(roots.len());
    for root in roots {
        let root_id = root.task_id.as_deref().unwrap_or_default();
        let outcome = crate::dependency_resolver::crate_request_target(
            &root.target,
            root_id,
            root.cached || by_id.published.contains(root_id),
            root.task_id.is_some(),
            queued_before.contains(root_id),
            by_id.statuses.get(root_id),
        )
        .map_err(|error| QueueError::Invariant(format!("request root {}: {error}", root.target)))?;
        targets.push(outcome);
        stored.push(RequestStoredRoot {
            target: root.target.as_str().to_owned(),
            task_id: root.task_id.clone(),
            cached: root.cached,
            was_queued: queued_before.contains(root_id),
        });
    }
    let outcome_json = serde_json::to_string(&stored)
        .map_err(|error| QueueError::Invariant(format!("encode request roots: {error}")))?;
    let event = stow_types::api::SchedulerEvent::Request {
        request_id: record.admission.request_id.clone(),
        kind: stow_types::api::RequestEvent::Outcome {
            attempt,
            state: "enqueued".to_owned(),
            outcome_json: Some(outcome_json),
            error: None,
        },
    };
    Ok((
        stow_types::api::CrateRequestStatus {
            request_id: record.admission.request_id.clone(),
            crate_name: record.admission.crate_name.clone(),
            version: record.admission.version.clone(),
            features_json: record.admission.features_json.clone(),
            rustc_version: record.admission.rustc_version.clone(),
            status: stow_types::api::CrateRequestPhase::Enqueued,
            targets,
            error: None,
            github_run_id: record.run_id.clone(),
            github_run_url: record.run_url.clone(),
        },
        Some(event),
    ))
}

/// `POST /requests/{id}/run-update` — the `workflow_run` webhook's
/// resolve-run lifecycle signal.
///
/// `in_progress` flips `accepted` → `resolving` and records the run id.
/// `completed` is the backstop: one conditional `UPDATE` flips a
/// still-live attempt to `failed`, so a record already `enqueued`
/// through its outcome route is never overwritten — a successful run's
/// outcome report lands before its `completed` event almost always, and
/// when it doesn't the record fails as "completed without an outcome".
/// `POST /requests/{id}/run-update` — the webhook's `workflow_run`
/// delivery for a resolve run: the `RunUpdated` event the route
/// appends — the same attempt fencing the SQL `UPDATE` guards wrote.
pub fn record_request_run_update(
    graph: &crate::scheduler::graph::Graph,
    request_id: &str,
    update: &stow_types::api::RequestRunUpdate,
) -> Result<stow_types::api::SchedulerEvent, QueueError> {
    let record = load_request(graph, request_id)
        .ok_or_else(|| QueueError::UnknownRequest(request_id.to_owned()))?;
    if record.attempt != update.attempt {
        return Err(QueueError::RequestAttemptSuperseded {
            request_id: request_id.to_owned(),
            live: record.attempt,
            reported: update.attempt,
        });
    }
    Ok(stow_types::api::SchedulerEvent::Request {
        request_id: request_id.to_owned(),
        kind: stow_types::api::RequestEvent::RunUpdated {
            update: Box::new(update.clone()),
        },
    })
}

/// `GET /requests/{id}` — the request record's live status, or `None`
/// when the id is unknown. An `enqueued` record's stored roots re-probe
/// the live queue on every read, so the per-target states keep moving
/// (`queued` → `building` → `cached`) after the outcome landed.
pub fn crate_request_status(
    graph: &crate::scheduler::graph::Graph,
    request_id: &str,
    now: i64,
) -> Result<Option<stow_types::api::CrateRequestStatus>, QueueError> {
    match load_request(graph, request_id) {
        Some(record) => Ok(Some(request_record_status(record, &|ids: &[String]| {
            graph.probe_roots(ids, now)
        })?)),
        None => Ok(None),
    }
}

/// Assemble the wire status for a record — re-probing stored roots
/// against the live queue when the record settled `enqueued`.
fn request_record_status(
    record: &crate::scheduler::graph::RequestRecord,
    status_of: &(impl Fn(&[String]) -> RootProbe + Send + Sync),
) -> Result<stow_types::api::CrateRequestStatus, QueueError> {
    let phase = request_phase(&record.state)?;
    let targets = if phase == stow_types::api::CrateRequestPhase::Enqueued {
        let roots: Vec<RequestStoredRoot> = serde_json::from_str(
            record.outcome_json.as_deref().unwrap_or("[]"),
        )
        .map_err(|error| QueueError::Invariant(format!("stored request outcome_json: {error}")))?;
        let ids: Vec<String> = roots
            .iter()
            .filter_map(|root| root.task_id.clone())
            .collect();
        let by_id = status_of(&ids);
        roots
            .iter()
            .map(|root| {
                let root_id = root.task_id.as_deref().unwrap_or_default();
                crate::dependency_resolver::crate_request_target(
                    &TargetTriple::parse(root.target.clone())?,
                    root_id,
                    root.cached || by_id.published.contains(root_id),
                    root.task_id.is_some(),
                    root.was_queued,
                    by_id.statuses.get(root_id),
                )
                .map_err(|error| {
                    QueueError::Invariant(format!("stored request root {}: {error}", root.target))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    Ok(stow_types::api::CrateRequestStatus {
        request_id: record.admission.request_id.clone(),
        crate_name: record.admission.crate_name.clone(),
        version: record.admission.version.clone(),
        features_json: record.admission.features_json.clone(),
        rustc_version: record.admission.rustc_version.clone(),
        status: phase,
        targets,
        error: record.error.clone(),
        github_run_id: record.run_id.clone(),
        github_run_url: record.run_url.clone(),
    })
}

/// Default for `STOW_MIN_DISPATCH_VALUE`: no admission floor — every
/// dispatchable row claims, as before the floor existed.
const DEFAULT_MIN_DISPATCH_VALUE: i64 = 0;

/// The largest `batch_id` a demand request may carry.
const MAX_DEMAND_BATCH_ID_BYTES: usize = 128;

/// The entry cap one demand batch may carry — each entry is one keyed
/// closure walk, so the cap also bounds a request's statement count.
const MAX_DEMAND_BATCH_ENTRIES: usize = 256;

/// `POST /demand` — a trusted demand batch (stow#522 I7). Every entry
/// names a host-side-free node identity (the Analytics Engine source
/// omits the side): the union of its unbuilt root rows — both compile
/// sides — and their unbuilt dependency closures over unmet edges is
/// its touched set. The entry's delta lands once per touched task —
/// the `UNION` walk dedups diamonds and cycles — while distinct
/// identities contribute their own deltas to a task they share.
///
/// The graph-side demand batch — dedup on `graph.demand_batches` and
/// hand back the `Demand` event for the route to append (stow#878
/// stage 7). A recorded `batch_id` carrying a different fingerprint
/// refuses before the event exists; an identical replay re-answers
/// the stored report.
pub fn apply_demand(
    graph: &crate::scheduler::graph::Graph,
    request: &stow_types::api::SchedulerDemandRequest,
) -> Result<
    (
        stow_types::api::SchedulerDemandReport,
        Option<stow_types::api::SchedulerEvent>,
    ),
    QueueError,
> {
    demand_batch_shape(request)?;
    let deltas = demand_deltas(&request.entries)?;
    let input_hash = demand_input_fingerprint(&deltas)?;
    if let Some((stored_hash, touched)) = graph.demand_batches.get(&request.batch_id) {
        if stored_hash != &input_hash {
            return Err(QueueError::Invariant(format!(
                "demand batch {} already delivered with a different payload",
                request.batch_id
            )));
        }
        return Ok((
            stow_types::api::SchedulerDemandReport {
                batch_id: request.batch_id.clone(),
                entries: u64::try_from(deltas.len()).unwrap_or(u64::MAX),
                touched_tasks: u64::try_from(*touched).unwrap_or(u64::MAX),
                applied: false,
            },
            None,
        ));
    }
    let contributions = graph.demand_contributions(&deltas)?;
    let entries: Vec<stow_types::api::DemandEntry> = contributions
        .into_iter()
        .map(|(task_id, delta)| stow_types::api::DemandEntry { task_id, delta })
        .collect();
    let touched = u64::try_from(entries.len()).unwrap_or(u64::MAX);
    let event = stow_types::api::SchedulerEvent::Demand {
        batch_id: request.batch_id.clone(),
        input_hash,
        entries,
    };
    Ok((
        stow_types::api::SchedulerDemandReport {
            batch_id: request.batch_id.clone(),
            entries: u64::try_from(deltas.len()).unwrap_or(u64::MAX),
            touched_tasks: touched,
            applied: true,
        },
        Some(event),
    ))
}

/// The `/demand` route's pass — the batch's `Demand` event plus the
/// wake the graph now plans (stow#878 stage 7).
pub fn demand_pass(
    graph: &crate::scheduler::graph::Graph,
    request: &stow_types::api::SchedulerDemandRequest,
    now_ms: i64,
    settings: &SchedulerSettings,
) -> Result<
    (
        stow_types::api::SchedulerDemandReport,
        Option<stow_types::api::SchedulerEvent>,
        AlarmPlan,
    ),
    QueueError,
> {
    let (report, event) = apply_demand(graph, request)?;
    let plan = graph.wake_plan(now_ms, settings);
    Ok((report, event, plan))
}

/// Perform the plan `next_alarm` decided on the real durable-object
/// alarm — shared by the wasm routes and the budget probe's demand
/// drive so the drive performs the same set/delete sequence the route
/// does. Alarm calls are platform operations, not SQL: they sit
/// outside the statement/rows meter by design (stow#522).
pub(super) async fn arm_alarm(alarm: &Alarm, plan: AlarmPlan) -> Result<(), QueueError> {
    match plan {
        AlarmPlan::Delete => alarm
            .delete_alarm()
            .await
            .map_err(|error| QueueError::Sql(format!("delete scheduler alarm: {error}"))),
        AlarmPlan::At(next_ms) => alarm
            .set_alarm(next_ms)
            .await
            .map_err(|error| QueueError::Sql(format!("set scheduler alarm {next_ms}: {error}"))),
    }
}

/// One canonical demand-batch input entry — the five identity fields
/// plus the summed delta, emitted in sorted order.
#[derive(serde::Serialize)]
struct CanonicalEntry {
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    delta: i64,
}

/// The request's shape bounds, checked before any read or write: a
/// bounded batch id and a bounded, non-empty entry list.
fn demand_batch_shape(request: &stow_types::api::SchedulerDemandRequest) -> Result<(), QueueError> {
    if request.batch_id.is_empty() || request.batch_id.len() > MAX_DEMAND_BATCH_ID_BYTES {
        return Err(QueueError::Invariant(format!(
            "demand batch_id must be 1..={MAX_DEMAND_BATCH_ID_BYTES} bytes"
        )));
    }
    if request.entries.is_empty() || request.entries.len() > MAX_DEMAND_BATCH_ENTRIES {
        return Err(QueueError::Invariant(format!(
            "demand batch must carry 1..={MAX_DEMAND_BATCH_ENTRIES} entries"
        )));
    }
    Ok(())
}

/// One batch's deduped per-identity deltas: an entry repeated under
/// the same identity is one demand report, and summing before the
/// walk keeps "once per task" true at identity granularity too. The
/// `BTreeMap`'s ordering is the canonicalization — the serialized
/// form below compares equal regardless of entry order or
/// duplication.
fn demand_deltas(
    entries: &[stow_types::api::SchedulerDemandEntry],
) -> Result<BTreeMap<[String; 5], i64>, QueueError> {
    let mut deltas: BTreeMap<[String; 5], i64> = BTreeMap::new();
    for entry in entries {
        let delta = u64_to_i64(entry.demand, "demand entry delta")?;
        let key = [
            entry.crate_name.as_str().to_owned(),
            entry.version.to_string(),
            entry.features_json.raw(),
            entry.target.as_str().to_owned(),
            entry.rustc_version.as_str().to_owned(),
        ];
        let total = deltas
            .get(&key)
            .copied()
            .unwrap_or(0)
            .checked_add(delta)
            .ok_or(QueueError::Overflow {
                field: "demand entry delta sum",
                value: u64::MAX,
            })?;
        deltas.insert(key, total);
    }
    Ok(deltas)
}

/// The batch id's payload fingerprint: blake3 of the sorted, summed
/// canonical entry serialization — the identity a redelivery of the
/// same observation must carry, and the cheap comparison a changed
/// payload fails (stow#522).
fn demand_input_fingerprint(deltas: &BTreeMap<[String; 5], i64>) -> Result<String, QueueError> {
    Ok(blake3::hash(canonical_demand_input(deltas)?.as_bytes())
        .to_hex()
        .to_string())
}

/// The batch id's accepted-payload fingerprint: the summed per-identity
/// deltas serialized in `BTreeMap` order, so two spellings of the same
/// observations — any entry order, any duplication — compare equal and
/// a changed payload compares different (stow#522).
fn canonical_demand_input(deltas: &BTreeMap<[String; 5], i64>) -> Result<String, QueueError> {
    serde_json::to_string(
        &deltas
            .iter()
            .map(|(identity, delta)| CanonicalEntry {
                crate_name: identity[0].clone(),
                version: identity[1].clone(),
                features_json: identity[2].clone(),
                target: identity[3].clone(),
                rustc_version: identity[4].clone(),
                delta: *delta,
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|error| QueueError::Invariant(format!("encode demand fingerprint input: {error}")))
}

/// The dispatch-failure backoff in minutes: `2^min(attempts, 6)` capped
/// at `MAX_DISPATCH_BACKOFF_MINUTES`, so a persistent failure (GitHub
/// outage, bad token) never spins the alarm in a zero-delay retry loop.
pub fn dispatch_backoff_minutes(attempts: u32) -> u32 {
    2u32.checked_pow(attempts.min(6))
        .unwrap_or(MAX_DISPATCH_BACKOFF_MINUTES)
        .min(MAX_DISPATCH_BACKOFF_MINUTES)
}

/// Write the freeze record — `record.notify` is whatever the alert send
/// already resolved to, so a failed send is persisted rather than
/// propagated: the freeze is the load-bearing action.
/// Lift the freeze by deleting the record row — the caller already
/// holds the record for the cleared-transition alert. The transition
/// log still records the cleared record's trigger so the watchdog's
/// issue can name what had been engaged.
/// Append one `dispatch_freeze_log` row — the transition log the #450
/// watchdog reads over `dispatch-freeze status` to write the
/// `GET /dispatch-freeze` (and so `stow-admin dispatch-freeze status`
/// and the watchdog) answers with it.
/// The evidence a failure-rate trip verdict becomes: the evaluated
/// window plus the dominant failure classes and the freshest failing
/// runs for the alert.
#[derive(Debug)]
pub struct FreezeTripDraft {
    /// The pure trip verdict over the window tallies.
    pub eval: crate::freeze::TripEval,
    /// Failure classes by descending count (`step: error-prefix`) — the
    /// lines the trip email leads with.
    pub classes: Vec<stow_types::api::DispatchFreezeClass>,
    /// `github_run_id`s of the most recent failures in the window.
    pub example_run_ids: Vec<String>,
}

/// Example run ids the trip email names — enough to click through, not
/// enough to bury the counts.
const TRIP_EXAMPLE_RUNS: i64 = 3;

/// Sum the in-window outcome buckets per target and run the pure trip
/// decision. The read is `attempt_outcome_buckets`, not the raw rows:
/// the window is at most `window_minutes / 5 + 1` buckets per target
/// (13 × 9 targets under the defaults) whatever the traffic, so the
/// cost of the check is constant in the number of completions it
/// covers. The sample is the outcome tally, not the queue rows: a
/// retried task flips back to `pending` and would otherwise erase its
/// earlier attempts from the window — exactly the retry-storm shape
/// this breaker exists to catch. Dispatch failures never land there
/// (no run was burned), so they are not the signal this watches.
pub fn evaluate_freeze_trip(
    graph: &crate::scheduler::graph::Graph,
    settings: &crate::freeze::FreezeSettings,
    now_ms: i64,
) -> Result<Option<FreezeTripDraft>, QueueError> {
    // The bucket table's `(target, bucket)` rollup is the ring's
    // read-time fold: only rows inside the window count, the same
    // bound the `bucket >= unixepoch - window` predicate gave.
    let cutoff = now_ms - i64::from(settings.window_minutes) * 60_000;
    let mut by_target: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for outcome in &graph.attempt_outcomes {
        if outcome.finished_at_ms < cutoff {
            continue;
        }
        let entry = by_target.entry(outcome.target.as_str()).or_default();
        entry.0 += 1;
        entry.1 += u64::from(outcome.failure_class.is_some());
    }
    let mut tallies = Vec::with_capacity(by_target.len());
    for (target, (outcomes, failures)) in by_target {
        tallies.push(crate::freeze::OutcomeTally {
            target: target.to_owned(),
            outcomes: u64_to_u32(outcomes, "window outcomes")?,
            failures: u64_to_u32(failures, "window failures")?,
        });
    }
    let Some(eval) = crate::freeze::evaluate(&tallies, settings) else {
        return Ok(None);
    };
    // The trip's evidence — failure classes by count, then the
    // freshest failing run ids the alert links.
    let mut classes_map: BTreeMap<String, u64> = BTreeMap::new();
    let mut run_ids: Vec<(i64, String)> = Vec::new();
    for outcome in &graph.attempt_outcomes {
        if outcome.finished_at_ms < cutoff {
            continue;
        }
        if let Some(class) = &outcome.failure_class {
            *classes_map.entry(class.clone()).or_default() += 1;
            run_ids.push((outcome.finished_at_ms, outcome.run_id.clone()));
        }
    }
    let mut classes: Vec<(String, u64)> = classes_map.into_iter().collect();
    classes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    run_ids.sort_by_key(|run| std::cmp::Reverse(run.0));
    run_ids.dedup_by(|a, b| a.1 == b.1);
    let example_run_ids = run_ids
        .into_iter()
        .take(usize::try_from(TRIP_EXAMPLE_RUNS).unwrap_or(usize::MAX))
        .map(|(_, id)| id)
        .collect();
    Ok(Some(FreezeTripDraft {
        eval,
        classes: classes
            .into_iter()
            .map(|(class, count)| stow_types::api::DispatchFreezeClass {
                class,
                count: u64_to_u32(count, "window failure class count").unwrap_or(u32::MAX),
            })
            .collect(),
        example_run_ids,
    }))
}

/// The graph-side freeze draft — `Some` when a trip window exists
/// and the freeze is not already engaged (stow#878 stage 7).
pub fn freeze_trip_draft(
    graph: &crate::scheduler::graph::Graph,
    settings: &crate::freeze::FreezeSettings,
    now_ms: i64,
) -> Result<Option<FreezeTripDraft>, QueueError> {
    if graph.freeze().is_some() {
        return Ok(None);
    }
    evaluate_freeze_trip(graph, settings, now_ms)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmPlan {
    /// Nothing can wake the queue: no unblocked pending rows and no active
    /// rows that could go stale.
    Delete,
    /// Wake at this epoch-millisecond timestamp.
    At(i64),
}

/// The invocation-spelling mask a dependent's edges carry: the cargo
/// invocations its own build compiles the dep's units under. A
/// host-side task runs every phase both natively and under `--target`
/// (its deps are host units under either spelling); so does a
/// `KeysApart` target-side task at the host triple, which compiles its
/// deps under both spellings too (stow#736); any other target-side
/// task runs the one spelling its target implies.
pub fn dep_invocation_mask(
    owner_target: &str,
    owner_host_side: bool,
    owner_explicit_spelling: stow_types::public_cache::ExplicitSpelling,
) -> i64 {
    let runs_both_spellings = owner_host_side
        || (owner_explicit_spelling == stow_types::public_cache::ExplicitSpelling::KeysApart
            && stow_types::api::runner_family(owner_target)
                .is_some_and(|family| family.host_triple() == owner_target));
    if runs_both_spellings {
        return 0b11;
    }
    match stow_types::api::runner_family(owner_target) {
        Some(family) if family.host_triple() == owner_target => 0b01,
        _ => 0b10,
    }
}

/// The `(invocation mask, required shape count)` one dependency edge
/// carries. The mask is the invocation spellings the dep's published
/// rows must cover; the count is the number of distinct
/// `(invocation, linked)` pairs the gate sums to. A host-side dep edge
/// needs the linked row under each spelling the owner compiles — host
/// units always link, so the check phase publishes the same shape the
/// build does. A target-side dep edge needs both kinds at the dep
/// node's own invocation spelling — except a `KeysApart` dep invoked
/// `Native`, which owes the four shapes of both spellings (stow#736).
pub fn dep_edge_requirements(
    owner_target: &str,
    owner_host_side: bool,
    owner_explicit_spelling: stow_types::public_cache::ExplicitSpelling,
    dep_target: &str,
    dep_host_side: bool,
    dep_explicit_spelling: stow_types::public_cache::ExplicitSpelling,
) -> (i64, i64) {
    if dep_host_side {
        let mask = dep_invocation_mask(owner_target, owner_host_side, owner_explicit_spelling);
        return (mask, i64::from(mask.count_ones()));
    }
    let mask = dep_invocation_mask(
        dep_target,
        false,
        stow_types::public_cache::ExplicitSpelling::KeysAsNative,
    );
    if mask == 0b01
        && dep_explicit_spelling == stow_types::public_cache::ExplicitSpelling::KeysApart
    {
        return (0b11, 4);
    }
    (mask, 2)
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64, QueueError> {
    i64::try_from(value).map_err(|_| QueueError::Overflow { field, value })
}

fn u64_to_u32(value: u64, field: &'static str) -> Result<u32, QueueError> {
    u32::try_from(value).map_err(|_| QueueError::Overflow { field, value })
}

#[cfg(test)]
mod tests {
    use super::seconds_until_utc_midnight;

    #[test]
    fn seconds_until_midnight_counts_to_day_end() {
        assert_eq!(seconds_until_utc_midnight(1_767_225_600), 86_400);
        assert_eq!(seconds_until_utc_midnight(1_767_225_600 + 3_600), 82_800);
        assert_eq!(seconds_until_utc_midnight(1_767_225_600 + 86_399), 1);
        assert_eq!(seconds_until_utc_midnight(0), 86_400);
    }
}
