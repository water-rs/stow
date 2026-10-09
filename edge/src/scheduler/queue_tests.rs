use std::collections::BTreeSet;
use std::future::Future;

use stow_types::api::{EnqueueRequest, EnqueueSource, task_id};
use stow_types::identity::FeaturesJson;

use super::{
    AlarmPlan, CoverageOracle, Dispatch, SchedulerSettings, SemanticTaskIdentity, next_alarm,
};
use crate::errors::QueueError;
use crate::scheduler::test_db::{
    StatementLog, counting_memory_db, counting_memory_db_raw, memory_db, memory_db_raw,
};
use skyzen_services::durable::DurableDb;
use stow_types::public_cache::{UnitInvocation, UnitKind, UnitShape, UnitSide};

const fn shape(side: UnitSide, invocation: UnitInvocation, kind: UnitKind) -> UnitShape {
    UnitShape {
        side,
        invocation,
        kind,
    }
}

/// Fixed column timestamp used for exact lease/eligibility assertions:
/// `2026-01-01 00:00:00` UTC in both the text form the `datetime()`
/// columns store and the epoch-ms form `now_ms`/`AlarmPlan::At` use.
const ROW_TS: &str = "2026-01-01 00:00:00";
const ROW_TS_MS: i64 = 1_767_225_600_000;
/// `2025-12-31 23:00:00` — strictly before `ROW_TS`, for an eligibility
/// that is already in the past.
const PAST_TS: &str = "2025-12-31 23:00:00";

const VERSION: &str = "1.0.0";
const FEATURES: &str = "[]";
const TARGET: &str = "x86_64-unknown-linux-gnu";
const MACOS_TARGET: &str = "aarch64-apple-darwin";
const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
const RUSTC: &str = "1.85.0";

/// The freeze window tests complete outcomes under — matches the
/// `STOW_FREEZE_WINDOW_MINUTES` default.
const TEST_WINDOW_MINUTES: u32 = 60;

const STALE_DISPATCH_MINUTES: u32 = 60;

async fn assert_parent_status(
    db: &DurableDb,
    expected: stow_types::api::QueueTaskStatus,
    deps: &[EnqueueRequest],
) {
    assert_eq!(
        super::task_status(db, &task_id_with("parent", TARGET, deps))
            .await
            .expect("read parent status")
            .expect("parent row")
            .status,
        expected
    );
}

fn stale_ms() -> i64 {
    i64::from(STALE_DISPATCH_MINUTES) * 60_000
}

const fn settings() -> SchedulerSettings {
    SchedulerSettings {
        dispatch: Dispatch::from_max_concurrent_jobs(10),
        max_concurrent_macos_jobs: 16,
        dispatch_min_age_minutes: 5,
        stale_dispatch_minutes: STALE_DISPATCH_MINUTES,
        max_queue_pending: 2_000,
        human_daily_task_budget: 2_000,
        min_dispatch_value: 0,
    }
}

const fn paused_settings() -> SchedulerSettings {
    SchedulerSettings {
        dispatch: Dispatch::Paused,
        ..settings()
    }
}

/// `super::enqueue` with the test settings, so existing call sites keep
/// their `(db, requests)` shape; cap tests call `super::enqueue` and
/// `super::enqueue_trusted` directly.
async fn enqueue(db: &DurableDb, requests: &[EnqueueRequest]) -> Result<u32, QueueError> {
    super::enqueue(db, requests, &settings()).await
}

#[derive(skyzen::FromRow)]
struct PairEdgeFlag {
    dep_crate_name: String,
    dep_met: i64,
}

async fn assert_pair_flags_after_publication(db: &DurableDb) {
    let pair_flags = db
        .query(
            "SELECT dep_crate_name, dep_met FROM queue_dependencies \
                 WHERE task_id = ? ORDER BY dep_crate_name",
        )
        .bind(task_id_on("pair", TARGET))
        .fetch_all::<PairEdgeFlag>()
        .await
        .expect("read pair edge flags after publication")
        .into_iter()
        .map(|edge| (edge.dep_crate_name, edge.dep_met))
        .collect::<Vec<_>>();
    assert_eq!(
        pair_flags,
        vec![("dep-fpub".to_owned(), 1), ("dep-short".to_owned(), 0)],
        "real publication initializes the fabricated pair edges"
    );
}

/// An artifact catalog that covers nothing: every claim goes to a
/// build, as before claim-time retirement existed.
struct NoCoverage;

impl CoverageOracle for NoCoverage {
    fn covered(
        &self,
        _identities: &[SemanticTaskIdentity],
    ) -> impl Future<Output = Result<BTreeSet<SemanticTaskIdentity>, QueueError>> + Send {
        std::future::ready(Ok(BTreeSet::new()))
    }
}

/// An artifact catalog that covers exactly the identities it was
/// built with, and records what it was asked about.
struct FixedCoverage {
    covered: BTreeSet<SemanticTaskIdentity>,
    asked: std::sync::Mutex<Vec<SemanticTaskIdentity>>,
}

impl CoverageOracle for FixedCoverage {
    fn covered(
        &self,
        identities: &[SemanticTaskIdentity],
    ) -> impl Future<Output = Result<BTreeSet<SemanticTaskIdentity>, QueueError>> + Send {
        self.asked
            .lock()
            .expect("oracle log")
            .extend_from_slice(identities);
        std::future::ready(Ok(identities
            .iter()
            .filter(|identity| self.covered.contains(identity))
            .cloned()
            .collect()))
    }
}

fn semantic_identity(crate_name: &str) -> SemanticTaskIdentity {
    SemanticTaskIdentity {
        crate_name: crate_name.to_owned(),
        version: VERSION.to_owned(),
        features_json: FEATURES.to_owned(),
        target: TARGET.to_owned(),
        rustc_version: RUSTC.to_owned(),
        host_side: false,
    }
}

/// Test subgraph carrying `deps` as the root's direct deps — each
/// given as its own request so the dep node embeds the dep's real
/// transitive subgraph and digests to the task id the dep's row
/// minted (stow#588). `dependency("x")` covers the leaf case; a
/// non-leaf dep is its own full `request(...)`.
fn subgraph_of(deps: &[EnqueueRequest]) -> stow_types::api::TaskSubgraph {
    let mut root_deps = Vec::with_capacity(deps.len());
    let mut nodes = Vec::new();
    for dep in deps {
        let base = u32::try_from(nodes.len()).expect("test node count");
        root_deps.push(base);
        // The dep's own wire nodes shift by `base + 1`: its node takes
        // slot `base`, its subgraph's nodes follow.
        let remap = |index: &u32| index + base + 1;
        nodes.push(stow_types::api::SubgraphNode {
            crate_name: dep.crate_name.clone(),
            version: dep.version.clone(),
            features_json: dep.features_json.clone(),
            host_side: dep.host_side,
            deps: dep
                .dependency_subgraph
                .root_deps
                .iter()
                .map(remap)
                .collect(),
        });
        nodes.extend(dep.dependency_subgraph.nodes.iter().map(|node| {
            stow_types::api::SubgraphNode {
                crate_name: node.crate_name.clone(),
                version: node.version.clone(),
                features_json: node.features_json.clone(),
                host_side: node.host_side,
                deps: node.deps.iter().map(remap).collect(),
            }
        }));
    }
    stow_types::api::TaskSubgraph { root_deps, nodes }
}

fn request(crate_name: &str, depends_on: &[EnqueueRequest]) -> EnqueueRequest {
    request_on(crate_name, TARGET, depends_on)
}

fn request_on(crate_name: &str, target: &str, deps: &[EnqueueRequest]) -> EnqueueRequest {
    EnqueueRequest {
        dependency_subgraph: subgraph_of(deps),
        crate_name: crate_name.parse().expect("valid crate name"),
        version: VERSION.parse().expect("valid semver"),
        features_json: FeaturesJson::default(),
        target: target.parse().expect("valid target triple"),
        rustc_version: RUSTC.parse().expect("valid rustc version"),
        downloads: 0,
        source: EnqueueSource::CacheMiss,
        preserve_lockfile: false,
        host_side: false,
    }
}

/// The task id a leaf-rooted request mints — what `enqueue` writes for
/// `request_on(crate_name, target, &[])` (stow#588: ids carry the
/// derived dependency-context digest).
fn task_id_on(crate_name: &str, target: &str) -> String {
    request_on(crate_name, target, &[])
        .task_id()
        .expect("derived test task id")
}

/// The task id `request_on(crate_name, target, deps)` mints — for
/// nodes enqueued with a non-empty dep set the leaf form does not
/// apply.
fn task_id_with(crate_name: &str, target: &str, deps: &[EnqueueRequest]) -> String {
    request_on(crate_name, target, deps)
        .task_id()
        .expect("derived test task id")
}

/// A leaf dep as its own request — `request(name, &[])` mints the
/// leaf-context id the dep's queue row carries.
fn dependency(crate_name: &str) -> EnqueueRequest {
    request(crate_name, &[])
}

/// The dependency-context identity a leaf dep's own subgraph resolves
/// to — what its `queue_dependencies` edge records and what a slice
/// row must carry for the gate to release on it (stow#588).
fn dep_identity(crate_name: &str) -> Option<stow_types::identity::DependencyIdentity> {
    dependency(crate_name).dependency_identity().ok()
}

/// A host-side leaf dep as its own request — minted at the consumer
/// family's host triple with `host_side`, the same identity its node
/// resolves to inside the consumer's subgraph (stow#588).
fn host_dependency_on(consumer_target: &str, crate_name: &str) -> EnqueueRequest {
    let mut dep = request_on(
        crate_name,
        stow_types::api::runner_family(consumer_target)
            .expect("consumer family")
            .host_triple(),
        &[],
    );
    dep.host_side = true;
    dep
}

/// Force a row into an in-flight status with a deterministic `updated_at`
/// — a state no public queue function produces (claim always stamps
/// `datetime('now')`), so one raw UPDATE is required.
async fn mark_active(db: &DurableDb, crate_name: &str, target: &str, status: &str) {
    db.query("UPDATE queue SET status = ?, updated_at = ?               WHERE crate_name = ? AND target = ?")
        .bind(status.to_owned())
        .bind(ROW_TS.to_owned())
        .bind(crate_name.to_owned())
        .bind(target)
        .execute()
        .await
        .expect("mark task active");
}

/// `enqueue` always stamps `first_requested_at = datetime('now')`; tests
/// that assert exact eligibility timestamps need a deterministic value.
async fn set_first_requested_at(db: &DurableDb, crate_name: &str, timestamp: &str) {
    set_first_requested_at_on(
        db,
        crate_name,
        TARGET,
        timestamp,
        settings().dispatch_min_age_minutes,
    )
    .await;
}

async fn set_first_requested_at_on(
    db: &DurableDb,
    crate_name: &str,
    target: &str,
    timestamp: &str,
    min_age_minutes: u32,
) {
    // `first_requested_at` is part of the persisted claim-order
    // tuple and of `wake_at`, so a direct column rewrite refreshes
    // both through the same row expressions production updates use.
    // Two statements: SET expressions read the pre-update row, so
    // the recomputes must run after the column write lands.
    db.query("UPDATE queue SET first_requested_at = ? WHERE task_id = ?")
        .bind(timestamp.to_owned())
        .bind(task_id_on(crate_name, target))
        .execute()
        .await
        .expect("set first_requested_at");
    db.query(&format!(
        "UPDATE queue SET wake_at = {} WHERE task_id = ?",
        super::wake_at_sql("lane", "first_requested_at", "not_before", min_age_minutes),
    ))
    .bind(task_id_on(crate_name, target))
    .execute()
    .await
    .expect("recompute wake_at");
    super::refresh_dispatch_keys(db, &[task_id_on(crate_name, target)])
        .await
        .expect("refresh dispatch_key");
}

#[tokio::test]
async fn active_only_wakes_at_lease_expiry() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("alpha", &[])])
        .await
        .expect("enqueue");
    mark_active(&db, "alpha", TARGET, "running").await;

    let plan = next_alarm(&db, ROW_TS_MS, &settings())
        .await
        .expect("next_alarm");
    // Lease = updated_at (2026-01-01 00:00:00) + stale_dispatch_minutes
    // (60) = 01:00:00. A `+`/`-` flip in the lease query's datetime
    // modifier moves this off the asserted value.
    assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + stale_ms()));
}

#[tokio::test]
async fn pending_blocked_by_active_dependency_wakes_at_lease_expiry() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    mark_active(&db, "dep", TARGET, "dispatched").await;

    let plan = next_alarm(&db, ROW_TS_MS, &settings())
        .await
        .expect("next_alarm");
    // The pending row must be filtered out by the dependency gate:
    // "dep" is dispatched, never published, so it is absent from the
    // slice the gate checks and the parent stays ineligible.
    assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + stale_ms()));
}

#[tokio::test]
async fn exhausted_capacity_with_eligible_pending_wakes_at_lease_expiry() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("busy", &[]), request("waiting", &[])])
        .await
        .expect("enqueue");
    mark_active(&db, "busy", TARGET, "dispatched").await;
    set_first_requested_at(&db, "waiting", PAST_TS).await;

    let settings = SchedulerSettings {
        dispatch: Dispatch::from_max_concurrent_jobs(1),
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let plan = next_alarm(&db, ROW_TS_MS, &settings)
        .await
        .expect("next_alarm");
    // The pending row is already eligible, but the only slot is taken:
    // waking at `now` would spin the object in a zero-delay alarm loop.
    assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + stale_ms()));
}

/// stow#444: a submit whose every row sits behind an unmet edge —
/// here a single task gated on a dep nobody has built — must leave
/// `schedule_alarm` with nothing to arm: `next_alarm` answers
/// `Delete`, so the request pays no wake for work it cannot run.
#[tokio::test]
async fn fully_gated_submit_arms_no_alarm() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("parent", &[dependency("dep-missing")])])
        .await
        .expect("enqueue gated submit");

    let plan = next_alarm(&db, ROW_TS_MS, &settings())
        .await
        .expect("next_alarm");
    assert_eq!(plan, AlarmPlan::Delete);
}

/// stow#444: a submit that does leave dispatchable work arms the
/// pass immediately — `next_alarm` answers `At(now)` for a row
/// already past its wake instant, exactly the wake `setAlarm(now)`
/// used to issue unconditionally.
#[tokio::test]
async fn dispatchable_submit_arms_at_now() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("ready", &[])])
        .await
        .expect("enqueue ready");
    set_first_requested_at(&db, "ready", PAST_TS).await;

    let plan = next_alarm(&db, ROW_TS_MS, &settings())
        .await
        .expect("next_alarm");
    assert_eq!(plan, AlarmPlan::At(ROW_TS_MS));
}

/// A paused scheduler keeps accepting submits but never plans a wake
/// for them: with nothing in flight the alarm is deleted, so the
/// queue waits out the pause instead of spinning on eligibility.
#[tokio::test]
async fn paused_with_nothing_in_flight_deletes_alarm() {
    let db = memory_db().await.expect("memory db");
    super::enqueue(&db, &[request("waiting", &[])], &paused_settings())
        .await
        .expect("enqueue");
    set_first_requested_at(&db, "waiting", PAST_TS).await;

    let plan = next_alarm(&db, ROW_TS_MS, &paused_settings())
        .await
        .expect("next_alarm");
    // The pending row is already eligible — under a live limit this
    // is `At(now)` — but paused means nothing to wake for.
    assert_eq!(plan, AlarmPlan::Delete);
}

/// With a build already in flight when dispatch pauses, the alarm
/// still wakes at its lease expiry so stale recovery can reclaim it.
#[tokio::test]
async fn paused_with_in_flight_row_wakes_at_lease_expiry() {
    let db = memory_db().await.expect("memory db");
    super::enqueue(
        &db,
        &[request("busy", &[]), request("waiting", &[])],
        &paused_settings(),
    )
    .await
    .expect("enqueue");
    mark_active(&db, "busy", TARGET, "dispatched").await;
    set_first_requested_at(&db, "waiting", PAST_TS).await;

    let plan = next_alarm(&db, ROW_TS_MS, &paused_settings())
        .await
        .expect("next_alarm");
    assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + stale_ms()));
}

/// Submits enqueue normally while paused, and the claim pass returns
/// nothing — the queue fills until the unpause deploy.
#[tokio::test]
async fn submit_while_paused_enqueues_but_claims_nothing() {
    let db = memory_db().await.expect("memory db");
    let inserted = super::enqueue(&db, &[request("waiting", &[])], &paused_settings())
        .await
        .expect("enqueue while paused");
    assert_eq!(inserted, 1);

    let claimed = super::claim_dispatchable_tasks(&db, &paused_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert!(claimed.is_empty());
    assert_eq!(super::status(&db).await.expect("status").pending, 1);
}

/// An in-flight row past its lease is still reclaimed to `pending`
/// while paused: the claim pass recovers stale work before the pause
/// check turns it away.
#[tokio::test]
async fn paused_claim_still_recovers_stale_in_flight_row() {
    let db = memory_db().await.expect("memory db");
    super::enqueue(&db, &[request("busy", &[])], &paused_settings())
        .await
        .expect("enqueue");
    mark_active(&db, "busy", TARGET, "dispatched").await;

    let claimed = super::claim_dispatchable_tasks(&db, &paused_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert!(claimed.is_empty());
    let status = db
        .query("SELECT status FROM queue WHERE task_id = ?")
        .bind(task_id_on("busy", TARGET))
        .fetch_scalar::<String>()
        .await
        .expect("status");
    assert_eq!(status, "pending");
}

#[tokio::test]
async fn eligible_pending_with_capacity_wakes_at_eligibility() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("ready", &[])])
        .await
        .expect("enqueue");
    set_first_requested_at_on(&db, "ready", TARGET, ROW_TS, 30).await;

    let settings = SchedulerSettings {
        dispatch_min_age_minutes: 30,
        ..settings()
    };
    let plan = next_alarm(&db, ROW_TS_MS, &settings)
        .await
        .expect("next_alarm");
    // Eligibility = first_requested_at + dispatch_min_age = 00:30:00.
    assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + 30 * 60_000));
}

#[tokio::test]
async fn overdue_pending_with_capacity_wakes_now() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("ready", &[])])
        .await
        .expect("enqueue");
    set_first_requested_at(&db, "ready", PAST_TS).await;

    let settings = SchedulerSettings {
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let plan = next_alarm(&db, ROW_TS_MS, &settings)
        .await
        .expect("next_alarm");
    assert_eq!(plan, AlarmPlan::At(ROW_TS_MS));
}

fn request_with_downloads(crate_name: &str, downloads: u64) -> EnqueueRequest {
    EnqueueRequest {
        downloads,
        ..request(crate_name, &[])
    }
}

const fn claim_settings() -> SchedulerSettings {
    SchedulerSettings {
        dispatch: Dispatch::from_max_concurrent_jobs(1),
        dispatch_min_age_minutes: 0,
        ..settings()
    }
}

/// Overwrite the cached token's `expires_at` with a `datetime()`
/// modifier evaluated by `SQLite` itself — the value under test is
/// stored in the RFC 3339 shape GitHub's API returns.
async fn set_cached_expiry(db: &DurableDb, modifier: &str) {
    db.query("UPDATE github_app_token SET expires_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) WHERE id = 1")
            .bind(modifier.to_owned())
            .execute()
            .await
            .expect("set cached token expiry");
}

fn token() -> crate::github_app::InstallationToken {
    crate::github_app::InstallationToken {
        token: "ghs_test".to_owned(),
        expires_at: "2099-01-01T00:00:00Z".to_owned(),
    }
}

#[tokio::test]
async fn repeated_requests_do_not_overtake_older_pending_tasks() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("old", &[])])
        .await
        .expect("enqueue old");
    enqueue(&db, &[request("spam", &[])])
        .await
        .expect("enqueue spam");
    set_first_requested_at(&db, "old", PAST_TS).await;
    // Hammer the newer task: under the removed request_count ordering it
    // would outrank the older row; under first-seen FIFO it cannot.
    for _ in 0..20 {
        enqueue(&db, &[request("spam", &[])])
            .await
            .expect("re-request spam");
    }

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "old");
}

/// stow#442 I6: `value` orders before FIFO, and the baseline value
/// carries the download/miss priority — a popular newer row now
/// outranks a less popular older one at equal lane and family.
#[tokio::test]
async fn higher_priority_value_claims_before_older_first_seen() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("old", &[])])
        .await
        .expect("enqueue old");
    enqueue(&db, &[request_with_downloads("popular", 10_000)])
        .await
        .expect("enqueue popular");
    set_first_requested_at(&db, "old", PAST_TS).await;

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "popular");
}

/// FIFO is the tie-breaker at equal value: two same-lane,
/// same-priority rows dispatch oldest-first (stow#442 I6).
#[tokio::test]
async fn equal_value_claims_in_first_seen_order() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("young", &[])])
        .await
        .expect("enqueue young");
    enqueue(&db, &[request("old", &[])])
        .await
        .expect("enqueue old");
    set_first_requested_at(&db, "old", PAST_TS).await;

    let settings = SchedulerSettings {
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 2);
    assert_eq!(claimed[0].crate_name, "old");
    assert_eq!(claimed[1].crate_name, "young");
}

/// The bands cover every lane/family combination: human rows always
/// outrank miss rows, and inside a lane a Windows row outranks a
/// non-Windows row — the same precedence today's CASE-encoded key
/// produced, arrived at regardless of request order or priority
/// (stow#442 I6).
#[tokio::test]
async fn value_bands_preserve_lane_then_family_precedence() {
    let db = memory_db().await.expect("memory db");
    // Worst case for the bands: the miss/Windows row is the oldest
    // and carries the largest admissible downloads; band order must
    // still dominate.
    let mut miss_win = request_on("miss-win", WINDOWS_TARGET, &[]);
    miss_win.downloads = i64::MAX as u64;
    enqueue(&db, &[miss_win]).await.expect("enqueue miss-win");
    enqueue(&db, &[request("miss-lin", &[])])
        .await
        .expect("enqueue miss-lin");
    enqueue(
        &db,
        &[
            EnqueueRequest {
                source: EnqueueSource::HumanRequest,
                ..request_on("human-lin", TARGET, &[])
            },
            EnqueueRequest {
                source: EnqueueSource::HumanRequest,
                ..request_on("human-win", WINDOWS_TARGET, &[])
            },
        ],
    )
    .await
    .expect("enqueue human");
    set_first_requested_at_on(
        &db,
        "miss-win",
        WINDOWS_TARGET,
        PAST_TS,
        settings().dispatch_min_age_minutes,
    )
    .await;

    let settings = SchedulerSettings {
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
        .await
        .expect("claim");
    let order = claimed
        .iter()
        .map(|task| task.crate_name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(order, ["human-win", "human-lin", "miss-win", "miss-lin"]);
}

/// The band arithmetic never overflows: a human Windows row at
/// `PRIORITY_MAX` takes the largest possible value,
/// `3 * VALUE_BAND + PRIORITY_MAX` — still inside `i64` — and
/// still dispatches first (stow#442 I6).
#[tokio::test]
async fn value_extremes_stay_within_i64_and_order() {
    #[derive(skyzen::FromRow)]
    struct ValueRow {
        value: String,
        key: String,
        first_requested_at: String,
        created_at: String,
    }
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            EnqueueRequest {
                source: EnqueueSource::HumanRequest,
                ..request_on("max", WINDOWS_TARGET, &[])
            },
            request("min", &[]),
        ],
    )
    .await
    .expect("enqueue");
    db.query("UPDATE queue SET priority = CAST(? AS INTEGER) WHERE task_id = ?")
        .bind(super::PRIORITY_MAX.to_string())
        .bind(task_id_on("max", WINDOWS_TARGET))
        .execute()
        .await
        .expect("set priority bound");
    super::refresh_dispatch_keys(&db, &[task_id_on("max", WINDOWS_TARGET)])
        .await
        .expect("refresh claim order");
    let row = db
        .query(
            "SELECT CAST(value AS TEXT) AS value, dispatch_key AS key, \
                        first_requested_at, created_at \
                 FROM queue WHERE task_id = ?",
        )
        .bind(task_id_on("max", WINDOWS_TARGET))
        .fetch_one::<ValueRow>()
        .await
        .expect("value row");
    assert_eq!(
        row.value.parse::<i64>().expect("integer value"),
        3 * super::VALUE_BAND + super::PRIORITY_MAX,
        "human + windows + PRIORITY_MAX is the largest legal value"
    );
    // The stored key is byte-exact the shared abstraction's output
    // for the same operands — human lane prefix first.
    assert_eq!(
        row.key,
        crate::scheduler::rank::dispatch_key(&crate::scheduler::rank::KeyOperands {
            lane: "human",
            family: "windows",
            priority: super::PRIORITY_MAX,
            demand: 0,
            cost_ms: crate::scheduler::rank::UNMEASURED_COST,
            first_requested_at: &row.first_requested_at,
            created_at: &row.created_at,
            task_id: &task_id_on("max", WINDOWS_TARGET),
        },)
    );
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed[0].crate_name, "max");
}

#[derive(skyzen::FromRow)]
struct KeyOrder {
    crate_name: String,
}

/// The claimed rows' crate names, sorted — floor tests compare
/// sets where the persisted order is separately covered.
async fn claimed_names(db: &DurableDb, settings: &SchedulerSettings) -> Vec<String> {
    let mut names: Vec<String> = super::claim_dispatchable_tasks(db, settings, &NoCoverage)
        .await
        .expect("claim")
        .iter()
        .map(|task| task.crate_name.as_str().to_owned())
        .collect();
    names.sort();
    names
}

/// Write the authoritative floor the writers' eligibility
/// expression reads — the `settings` row the operator migrate
/// stamps (stow#525 I10).
async fn set_floor(db: &DurableDb, floor: i64) {
    db.query(
        "INSERT INTO settings (key, value) VALUES ('min_dispatch_value', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(floor.to_string())
    .execute()
    .await
    .expect("set dispatch floor");
}

/// The persisted admission answer on one row.
async fn flag_of(db: &DurableDb, crate_name: &str) -> i64 {
    db.query("SELECT dispatch_eligible FROM queue WHERE crate_name = ?")
        .bind(crate_name.to_owned())
        .fetch_scalar::<i64>()
        .await
        .expect("dispatch_eligible")
}

/// The claim admits only rows whose persisted eligibility the floor
/// passed: at `floor = VALUE_BAND` a Windows miss (one band) claims
/// while a zero-value Linux miss stays under, and a floor one over
/// the band writes `dispatch_eligible = 0` onto every miss row
/// (stow#525 I10).
#[tokio::test]
async fn floor_admits_only_scored_rows() {
    let db = memory_db().await.expect("memory db");
    set_floor(&db, super::VALUE_BAND).await;
    enqueue(
        &db,
        &[request("lin", &[]), request_on("win", WINDOWS_TARGET, &[])],
    )
    .await
    .expect("enqueue");
    set_first_requested_at(&db, "lin", PAST_TS).await;
    set_first_requested_at_on(
        &db,
        "win",
        WINDOWS_TARGET,
        PAST_TS,
        settings().dispatch_min_age_minutes,
    )
    .await;
    assert_eq!(claimed_names(&db, &claim_settings()).await, ["win"]);
    assert_eq!(flag_of(&db, "lin").await, 0);
    // `win` is dispatched now; with only the value-0 `lin` left,
    // even a fresh claim page admits nothing.
    assert_eq!(
        claimed_names(&db, &claim_settings()).await,
        Vec::<String>::new()
    );

    // One band over the floor: a second queue floors every
    // miss-lane row, including the Windows band.
    let db = memory_db().await.expect("memory db");
    set_floor(&db, super::VALUE_BAND + 1).await;
    enqueue(
        &db,
        &[request("lin", &[]), request_on("win", WINDOWS_TARGET, &[])],
    )
    .await
    .expect("enqueue");
    set_first_requested_at(&db, "lin", PAST_TS).await;
    set_first_requested_at_on(
        &db,
        "win",
        WINDOWS_TARGET,
        PAST_TS,
        settings().dispatch_min_age_minutes,
    )
    .await;
    assert_eq!(flag_of(&db, "win").await, 0);
    assert_eq!(
        claimed_names(&db, &claim_settings()).await,
        Vec::<String>::new()
    );
}

/// A human-lane row is exempt from any floor — even `i64::MAX` —
/// because the flag's lane clause wins before the score compares,
/// while the miss lane is held entirely below it (stow#525 I10).
#[tokio::test]
async fn floor_never_blocks_the_human_lane() {
    let db = memory_db().await.expect("memory db");
    set_floor(&db, i64::MAX).await;
    enqueue(
        &db,
        &[
            EnqueueRequest {
                source: EnqueueSource::HumanRequest,
                ..request("human", &[])
            },
            request("miss", &[]),
        ],
    )
    .await
    .expect("enqueue");

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    let names = claimed
        .iter()
        .map(|task| task.crate_name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, ["human"], "only the exempt lane clears i64::MAX");
    assert_eq!(flag_of(&db, "miss").await, 0);
}

/// Equal scores tie on the persisted tuple exactly as before the
/// floor existed: admitted rows claim in stored `dispatch_key`
/// order, and an under-floor row does not stretch or reorder them
/// (stow#525 I10).
#[tokio::test]
async fn floor_preserves_the_tie_order() {
    let db = memory_db().await.expect("memory db");
    // Three Windows misses share one band — the three-way value
    // tie — beside one Linux miss the floor excludes.
    set_floor(&db, super::VALUE_BAND).await;
    enqueue(
        &db,
        &[
            request_on("cee", WINDOWS_TARGET, &[]),
            request_on("aye", WINDOWS_TARGET, &[]),
            request_on("bee", WINDOWS_TARGET, &[]),
            request("lin", &[]),
        ],
    )
    .await
    .expect("enqueue");
    for name in ["cee", "aye", "bee"] {
        set_first_requested_at_on(
            &db,
            name,
            WINDOWS_TARGET,
            PAST_TS,
            settings().dispatch_min_age_minutes,
        )
        .await;
    }

    let expected = db
        .query(
            "SELECT crate_name FROM queue WHERE status = 'pending' \
                 ORDER BY dispatch_key LIMIT 3",
        )
        .fetch_all::<KeyOrder>()
        .await
        .expect("stored key order")
        .into_iter()
        .map(|row| row.crate_name)
        .collect::<Vec<_>>();

    let page = SchedulerSettings {
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let claimed = super::claim_dispatchable_tasks(&db, &page, &NoCoverage)
        .await
        .expect("claim");
    let names = claimed
        .iter()
        .map(|task| task.crate_name.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(names, expected, "claims arrive in the stored key order");
    assert_eq!(names.len(), 3, "the Linux miss stays under the floor");
}

/// An under-floor row is no wake's reason to arm: the ready probe
/// and the deferred `MIN(wake_at)` probe both exclude it, so a
/// queue of only under-floor rows leaves the alarm disarmed instead
/// of spinning an empty dispatch loop (stow#525 I10).
#[tokio::test]
async fn under_floor_rows_never_arm_the_alarm() {
    // Without a floor the row is eligible now — the alarm arms at
    // `now`.
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("low", &[])]).await.expect("enqueue");
    set_first_requested_at(&db, "low", PAST_TS).await;
    let armed = next_alarm(&db, ROW_TS_MS, &claim_settings())
        .await
        .expect("next_alarm unfloored");
    assert_eq!(armed, AlarmPlan::At(ROW_TS_MS));

    // Under a floor the same row admits nothing and defers
    // nothing: both wake probes exclude it, and no stale lease or
    // requeue arm exists either.
    let db = memory_db().await.expect("memory db");
    set_floor(&db, 1).await;
    enqueue(&db, &[request("low", &[])]).await.expect("enqueue");
    set_first_requested_at(&db, "low", PAST_TS).await;
    let plan = next_alarm(&db, ROW_TS_MS, &claim_settings())
        .await
        .expect("next_alarm floored");
    assert_eq!(plan, AlarmPlan::Delete);
    assert!(
        super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")
            .is_empty()
    );
}

/// A bulk of under-floor rows — immediate and deferred wakes
/// alike — contributes no candidate to the claim page and arms no
/// alarm, and the one eligible row that lands among them still
/// claims: the equality predicate excludes the bulk inside the
/// index span, never as page entries the walk visits and rejects
/// (stow#525 I10).
#[tokio::test]
async fn under_floor_bulk_arms_no_wake_and_starves_no_page() {
    let db = memory_db().await.expect("memory db");
    set_floor(&db, 1).await;
    let bulk = (0..300)
        .map(|n| request(&format!("under{n}"), &[]))
        .collect::<Vec<_>>();
    enqueue(&db, &bulk).await.expect("enqueue under-floor bulk");
    // Half the bulk parks behind a future wake — immediate and
    // deferred under-floor rows alike must leave the probes' span.
    db.query(
        "UPDATE queue SET wake_at = datetime('now', '+30 minutes') \
             WHERE crate_name >= 'under2'",
    )
    .execute()
    .await
    .expect("defer part of the bulk");
    assert_eq!(
        next_alarm(&db, ROW_TS_MS, &claim_settings())
            .await
            .expect("next_alarm over the bulk"),
        AlarmPlan::Delete,
        "300 under-floor rows arm nothing"
    );
    assert_eq!(
        claimed_names(&db, &claim_settings()).await,
        Vec::<String>::new()
    );
    // The one row over the floor claims on the first page —
    // the floor is an index equality, not a scan the bulk can starve.
    enqueue(&db, &[request_on("win", WINDOWS_TARGET, &[])])
        .await
        .expect("enqueue the eligible row");
    set_first_requested_at_on(
        &db,
        "win",
        WINDOWS_TARGET,
        PAST_TS,
        settings().dispatch_min_age_minutes,
    )
    .await;
    assert_eq!(claimed_names(&db, &claim_settings()).await, ["win"]);
}

/// Demand that raises a row's score across the floor flips the
/// persisted flag with it: the batched update's `priority`
/// recomputation flows through the claim-order refresh, which
/// rewrites `value`, `dispatch_key` and `dispatch_eligible`
/// together (stow#525 I10).
#[tokio::test]
async fn demand_can_cross_the_floor() {
    let db = memory_db().await.expect("memory db");
    set_floor(&db, 1).await;
    enqueue(&db, &[request("rise", &[])])
        .await
        .expect("enqueue");
    set_first_requested_at(&db, "rise", PAST_TS).await;
    assert_eq!(flag_of(&db, "rise").await, 0);

    super::apply_batched_updates(
        &db,
        &settings(),
        &[super::BatchedUpdate {
            task_id: task_id_on("rise", TARGET),
            occurrences: 1,
            // `priority = downloads / 1000` reaches 1 — exactly the
            // floor, the boundary the flag must take.
            downloads: 1_000,
            redispatch: 0,
            human: 0,
        }],
    )
    .await
    .expect("demand update");
    assert_eq!(flag_of(&db, "rise").await, 1);
    assert_eq!(claimed_names(&db, &claim_settings()).await, ["rise"]);
}

/// A promoted row gains the human lane's exemption in the same
/// statement that moves its lane — an under-floor miss claims the
/// moment it is human (stow#525 I10).
#[tokio::test]
async fn promotion_grants_the_human_exemption() {
    let db = memory_db().await.expect("memory db");
    set_floor(&db, 1).await;
    enqueue(&db, &[request("prom", &[])])
        .await
        .expect("enqueue");
    assert_eq!(flag_of(&db, "prom").await, 0);

    let mutated = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Promote,
        &super::QueueSelector {
            task_ids: vec![task_id_on("prom", TARGET)],
            ..Default::default()
        },
    )
    .await
    .expect("promote");
    assert_eq!(mutated, 1);
    assert_eq!(flag_of(&db, "prom").await, 1);
    set_first_requested_at(&db, "prom", PAST_TS).await;
    assert_eq!(claimed_names(&db, &claim_settings()).await, ["prom"]);
}

/// A retried row keeps its persisted answer — retry rewrites
/// status, `not_before` and `wake_at`, never the flag (stow#525
/// I10).
#[tokio::test]
async fn retry_preserves_the_eligibility_flag() {
    let db = memory_db().await.expect("memory db");
    set_floor(&db, 1).await;
    enqueue(
        &db,
        &[request("low", &[]), request_on("win", WINDOWS_TARGET, &[])],
    )
    .await
    .expect("enqueue");
    for name in ["low", "win"] {
        db.query("UPDATE queue SET status = 'failed' WHERE crate_name = ?")
            .bind(name.to_owned())
            .execute()
            .await
            .expect("park the row failed");
    }
    let selector = super::QueueSelector {
        task_ids: vec![task_id_on("low", TARGET), task_id_on("win", WINDOWS_TARGET)],
        ..Default::default()
    };
    assert_eq!(
        super::apply_mutation(&db, &settings(), super::QueueMutation::Retry, &selector)
            .await
            .expect("retry"),
        2
    );
    assert_eq!(flag_of(&db, "low").await, 0);
    assert_eq!(flag_of(&db, "win").await, 1);
    set_first_requested_at_on(
        &db,
        "win",
        WINDOWS_TARGET,
        PAST_TS,
        settings().dispatch_min_age_minutes,
    )
    .await;
    assert_eq!(claimed_names(&db, &claim_settings()).await, ["win"]);
}

/// The operator floor move: `migrate` stamps the configured value
/// into `settings` and backfills `dispatch_eligible` — under-floor
/// rows lose the flag, the boundary and the exempt lane keep it,
/// and the stamped row is the value every writer reads from then
/// on (stow#525 I10).
#[tokio::test]
async fn operator_floor_change_backfills_eligibility() {
    let db = memory_db_raw().await.expect("raw memory db");
    super::migrate(&db, &settings()).await.expect("migrate");
    enqueue(
        &db,
        &[
            request("lin", &[]),
            request_on("win", WINDOWS_TARGET, &[]),
            EnqueueRequest {
                source: EnqueueSource::HumanRequest,
                ..request("human", &[])
            },
        ],
    )
    .await
    .expect("enqueue");
    assert_eq!(flag_of(&db, "lin").await, 1, "no floor admits all");

    let floor = |min_dispatch_value| SchedulerSettings {
        min_dispatch_value,
        ..settings()
    };
    // Raise the floor to one band: the Linux miss drops out, the
    // band row sits exactly at the floor, the human row is exempt.
    super::migrate_dispatch_eligible(&db, &floor(super::VALUE_BAND))
        .await
        .expect("apply floor");
    assert_eq!(flag_of(&db, "lin").await, 0);
    assert_eq!(flag_of(&db, "win").await, 1);
    assert_eq!(flag_of(&db, "human").await, 1);
    // A second pass with the same floor is a no-op — and a higher
    // floor floors the band too while the human stays.
    super::migrate_dispatch_eligible(&db, &floor(super::VALUE_BAND))
        .await
        .expect("idempotent pass");
    super::migrate_dispatch_eligible(&db, &floor(super::VALUE_BAND + 1))
        .await
        .expect("raise floor");
    assert_eq!(flag_of(&db, "win").await, 0);
    assert_eq!(flag_of(&db, "human").await, 1);
}

/// A caught mid-pass failure leaves no stamp, so a retried
/// operator migrate at the same floor still repairs: the backfill
/// must not have committed flags against a floor the settings row
/// was allowed to skip (stow#525 I10).
#[tokio::test]
async fn failed_backfill_retries_under_the_same_floor() {
    let db = memory_db_raw().await.expect("raw memory db");
    super::migrate(&db, &settings()).await.expect("migrate");
    enqueue(
        &db,
        &[request("lin", &[]), request_on("win", WINDOWS_TARGET, &[])],
    )
    .await
    .expect("enqueue");
    // Kill every queue UPDATE — the backfill's statement fails
    // before the stamp it was supposed to earn.
    db.query(
        "CREATE TRIGGER fail_backfill BEFORE UPDATE ON queue \
             BEGIN SELECT RAISE(ABORT, 'injected backfill failure'); END",
    )
    .execute()
    .await
    .expect("install failure trigger");
    let floored = SchedulerSettings {
        min_dispatch_value: 1,
        ..settings()
    };
    super::migrate_dispatch_eligible(&db, &floored)
        .await
        .expect_err("injected failure must abort the pass");
    // The pass recorded no stamp for the floor it was applying —
    // the last-applied floor ("0", from the schema-building
    // migrate) survives, so a retry still sees floor 1 as
    // unapplied rather than skipping the backfill over stale flags.
    let stamped: Option<String> = db
        .query("SELECT value FROM settings WHERE key = 'min_dispatch_value'")
        .fetch_scalar_optional::<String>()
        .await
        .expect("read stamped floor");
    assert_eq!(
        stamped.as_deref(),
        Some("0"),
        "a failed pass must not stamp"
    );
    db.query("DROP TRIGGER fail_backfill")
        .execute()
        .await
        .expect("remove failure trigger");
    // Same-floor retry converges: backfill repairs flags, then the
    // stamp lands.
    super::migrate_dispatch_eligible(&db, &floored)
        .await
        .expect("retried migrate");
    assert_eq!(flag_of(&db, "lin").await, 0);
    assert_eq!(flag_of(&db, "win").await, 1);
    let stamped: Option<String> = db
        .query("SELECT value FROM settings WHERE key = 'min_dispatch_value'")
        .fetch_scalar_optional::<String>()
        .await
        .expect("read stamped floor");
    assert_eq!(stamped.as_deref(), Some("1"));
}

/// A queue at the prior schema version — `dispatch_eligible`
/// missing and the floor-blind index names live — gains the
/// column, the eligible-aware indexes and the stamped floor in one
/// operator pass (stow#525 I10).
#[tokio::test]
async fn migrate_recovers_the_prior_schema() {
    let db = memory_db_raw().await.expect("raw memory db");
    super::migrate(&db, &settings()).await.expect("migrate");
    enqueue(
        &db,
        &[request("lin", &[]), request_on("win", WINDOWS_TARGET, &[])],
    )
    .await
    .expect("enqueue");
    // Roll the database back to the pre-12 shape: no column, the
    // old index names on their old column lists, the old stamp.
    for statement in [
        "DROP INDEX idx_queue_claim",
        "DROP INDEX idx_queue_wake",
        // The pre-13 trigger carried no eligibility write — drop
        // it rather than leave a definition that references the
        // column being removed.
        "DROP TRIGGER demand_fold",
        "ALTER TABLE queue DROP COLUMN dispatch_eligible",
        "CREATE INDEX idx_queue_dispatch ON queue \
             (status, deps_met, dispatch_key, dispatch_family, lane, first_requested_at, not_before)",
        "CREATE INDEX idx_queue_wake_eligible ON queue \
             (status, deps_met, dispatch_family, wake_at)",
        "UPDATE scheduler_schema_version SET version = 11",
    ] {
        db.query(statement)
            .execute()
            .await
            .expect("stage the prior schema");
    }
    let floored = SchedulerSettings {
        min_dispatch_value: 1,
        ..settings()
    };
    let report = super::migrate(&db, &floored).await.expect("migrate");
    assert_eq!((report.before, report.after), (11, super::SCHEMA_VERSION));
    assert_eq!(flag_of(&db, "lin").await, 0);
    assert_eq!(flag_of(&db, "win").await, 1);
    let names = db
        .query(
            "SELECT name FROM sqlite_master WHERE type = 'index' \
                 AND name LIKE 'idx_queue_%'",
        )
        .fetch_scalars::<String>()
        .await
        .expect("index names");
    assert!(names.iter().any(|name| name == "idx_queue_claim"));
    assert!(names.iter().any(|name| name == "idx_queue_wake"));
    assert!(!names.iter().any(|name| name == "idx_queue_dispatch"));
    assert!(!names.iter().any(|name| name == "idx_queue_wake_eligible"));
}

/// `QueueTask.value` is the column's exact decimal text — adjacent
/// scores above the JS-safe integer range round-trip through the
/// row projection and out over the JSON wire without rounding,
/// clamping, or a trailing `.0` (stow#525 I10).
#[tokio::test]
async fn list_tasks_reports_value_as_exact_decimal() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("wide-a", &[]), request("wide-b", &[])])
        .await
        .expect("enqueue");
    // Literals inside the statement text parse as i64 in SQLite —
    // the only wide-integer channel, since a bound parameter would
    // cross the lossy numeric transport.
    for (name, literal) in [
        ("wide-a", "36893574046765006"),
        ("wide-b", "36893574046765007"),
    ] {
        db.query(&format!(
            "UPDATE queue SET value = {literal} WHERE task_id = ?"
        ))
        .bind(task_id_on(name, TARGET))
        .execute()
        .await
        .expect("set wide value");
    }

    let tasks = super::list_tasks(&db, &super::QueueSelector::default())
        .await
        .expect("list tasks");
    let mut values = tasks
        .iter()
        .map(|task| (task.crate_name.as_str(), task.value.as_str()))
        .collect::<Vec<_>>();
    values.sort_unstable();
    assert_eq!(
        values,
        [
            ("wide-a", "36893574046765006"),
            ("wide-b", "36893574046765007")
        ],
        "adjacent >2^53 scores arrive digit-for-digit"
    );
    // The wire shape is a JSON string, not a number an f64 decoder
    // could truncate.
    let wide_b = tasks
        .iter()
        .find(|task| task.crate_name.as_str() == "wide-b")
        .expect("wide-b listed");
    let serialized = serde_json::to_string(wide_b).expect("serialize task");
    assert!(
        serialized.contains("\"value\":\"36893574046765007\""),
        "the score serializes as decimal text: {serialized}"
    );
}

/// A row migrated from a pre-`value` queue (the column still at its
/// ALTER default, the key in any older form) backfills to exactly
/// the formula a fresh insert writes — migrated and fresh rows
/// agree (stow#442 I6).
#[tokio::test]
async fn migrate_backfills_value_to_match_fresh_rows() {
    let db = memory_db_raw().await.expect("raw memory db");
    super::migrate(&db, &settings())
        .await
        .expect("first migrate");
    enqueue(
        &db,
        &[
            EnqueueRequest {
                source: EnqueueSource::HumanRequest,
                ..request("human", &[])
            },
            request_on("win", WINDOWS_TARGET, &[]),
            request("lin", &[]),
        ],
    )
    .await
    .expect("enqueue");
    // Simulate the ALTER's untouched state: `value` at its 0
    // default and the key in an obsolete form.
    db.query("UPDATE queue SET value = 0, dispatch_key = '0|0|1970|x|1970|0'")
        .execute()
        .await
        .expect("simulate migrated rows");

    super::migrate(&db, &settings()).await.expect("migrate");

    let drifted = db
        .query(super::RANK_SOURCE_SELECT)
        .fetch_all::<super::RankSourceRow>()
        .await
        .expect("load migrated rows")
        .iter()
        .map(|row| row.checked().expect("checked rank row"))
        .filter(|row| {
            let family = crate::scheduler::rank::dispatch_family(&row.target);
            family != row.dispatch_family
                || crate::scheduler::rank::raw_value(&row.lane, family, row.priority, row.demand)
                    != row.value
                || crate::scheduler::rank::dispatch_key(&crate::scheduler::rank::KeyOperands {
                    lane: &row.lane,
                    family,
                    priority: row.priority,
                    demand: row.demand,
                    cost_ms: row.cost_ms,
                    first_requested_at: &row.first_requested_at,
                    created_at: &row.created_at,
                    task_id: &row.task_id,
                }) != row.dispatch_key
        })
        .count();
    assert_eq!(
        drifted, 0,
        "every row carries the shared abstraction's pair"
    );
}

// stow#522 I7 — keyed demand application.

fn demand_entry_on(
    crate_name: &str,
    target: &str,
    delta: u64,
) -> stow_types::api::SchedulerDemandEntry {
    stow_types::api::SchedulerDemandEntry {
        crate_name: crate_name.parse().expect("demand crate"),
        version: VERSION.parse().expect("demand version"),
        features_json: FeaturesJson::default(),
        target: target.parse().expect("demand target"),
        rustc_version: RUSTC.parse().expect("demand rustc"),
        demand: delta,
    }
}

fn demand_entry(crate_name: &str, delta: u64) -> stow_types::api::SchedulerDemandEntry {
    demand_entry_on(crate_name, TARGET, delta)
}

fn demand_batch(
    batch_id: &str,
    entries: Vec<stow_types::api::SchedulerDemandEntry>,
) -> stow_types::api::SchedulerDemandRequest {
    stow_types::api::SchedulerDemandRequest {
        batch_id: batch_id.to_owned(),
        entries,
    }
}

async fn apply(
    db: &DurableDb,
    batch_id: &str,
    entries: Vec<stow_types::api::SchedulerDemandEntry>,
) -> Result<stow_types::api::SchedulerDemandReport, QueueError> {
    super::apply_demand(db, &demand_batch(batch_id, entries)).await
}

async fn demand_of(db: &DurableDb, crate_name: &str, target: &str) -> i64 {
    db.query("SELECT demand FROM queue WHERE crate_name = ? AND target = ?")
        .bind(crate_name.to_owned())
        .bind(target.to_owned())
        .fetch_scalar::<i64>()
        .await
        .expect("demand read")
}

async fn contribution_rows(db: &DurableDb, batch_id: &str) -> u64 {
    db.query("SELECT count(*) FROM demand_contributions WHERE batch_id = ?")
        .bind(batch_id.to_owned())
        .fetch_scalar::<u64>()
        .await
        .expect("contribution count")
}

/// Demand lands on the named node and walks its whole unbuilt
/// dependency closure; unrelated rows stay at zero (stow#522).
#[tokio::test]
async fn demand_walks_the_unbuilt_dependency_closure() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request("leaf", &[]),
            request("mid", &[dependency("leaf")]),
            request("root", &[request("mid", &[dependency("leaf")])]),
            request("other", &[]),
        ],
    )
    .await
    .expect("enqueue");

    let report = apply(&db, "h0", vec![demand_entry("root", 5)])
        .await
        .expect("demand");
    assert!(report.applied);
    assert_eq!(report.touched_tasks, 3);
    for name in ["root", "mid", "leaf"] {
        assert_eq!(demand_of(&db, name, TARGET).await, 5, "{name}");
    }
    assert_eq!(demand_of(&db, "other", TARGET).await, 0);
    // The closure's value rows carry the delta — the ordering
    // operand, not a side column.
    let value = db
        .query("SELECT value FROM queue WHERE task_id = ?")
        .bind(task_id_on("leaf", TARGET))
        .fetch_scalar::<i64>()
        .await
        .expect("value read");
    assert_eq!(value, 5, "miss row: bands and priority are 0");
}

/// A diamond — root reaches `c` through both `a` and `b` — applies
/// the delta once per task, and the walk dedup is visible in the
/// contribution rows too (stow#522).
#[tokio::test]
async fn demand_dedupes_diamond_paths() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request("c", &[]),
            request("a", &[dependency("c")]),
            request("b", &[dependency("c")]),
            request(
                "root",
                &[
                    request("a", &[dependency("c")]),
                    request("b", &[dependency("c")]),
                ],
            ),
        ],
    )
    .await
    .expect("enqueue");

    let report = apply(&db, "h0", vec![demand_entry("root", 7)])
        .await
        .expect("demand");
    assert_eq!(report.touched_tasks, 4);
    assert_eq!(demand_of(&db, "c", TARGET).await, 7);
    // Acceptance consumes the staged set in the same statement
    // (stow#523): an accepted batch's replay reads the header only.
    assert_eq!(contribution_rows(&db, "h0").await, 0);
}

/// One entry names a node identity without its side: both the
/// target-side and the host-side queue rows of that identity are
/// touched (stow#522).
#[tokio::test]
async fn demand_touches_both_compile_sides_of_one_identity() {
    let db = memory_db().await.expect("memory db");
    let host = EnqueueRequest {
        host_side: true,
        ..request("dual", &[])
    };
    enqueue(&db, &[request("dual", &[]), host])
        .await
        .expect("enqueue");

    let report = apply(&db, "h0", vec![demand_entry("dual", 3)])
        .await
        .expect("demand");
    assert_eq!(report.touched_tasks, 2);
    for host_side in [false, true] {
        let demand: i64 = db
            .query("SELECT demand FROM queue WHERE crate_name = 'dual' AND host_side = ?")
            .bind(i64::from(host_side))
            .fetch_scalar()
            .await
            .expect("host demand");
        assert_eq!(demand, 3, "host_side={host_side}");
    }
}

/// The walk stops at nodes that are done or in flight — completed
/// and running deps are not touched — and at edges whose slice
/// answer is already `dep_met = 1` (stow#522).
#[tokio::test]
async fn demand_stops_at_built_in_flight_and_met_edges() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request("done", &[]),
            request("live", &[]),
            request("leaf", &[]),
            request("met-dep", &[]),
            request(
                "root",
                &[
                    dependency("done"),
                    dependency("live"),
                    dependency("met-dep"),
                ],
            ),
        ],
    )
    .await
    .expect("enqueue");
    mark_active(&db, "done", TARGET, "completed").await;
    mark_active(&db, "live", TARGET, "running").await;
    // An edge whose dep the index already answered: met edges are
    // not part of the unbuilt closure even when the row behind
    // them is still pending.
    let root_id = task_id_with(
        "root",
        TARGET,
        &[
            dependency("done"),
            dependency("live"),
            dependency("met-dep"),
        ],
    );
    db.query(
        "UPDATE queue_dependencies SET dep_met = 1 \
                  WHERE task_id = ? AND dep_crate_name = 'met-dep'",
    )
    .bind(root_id.clone())
    .execute()
    .await
    .expect("met edge");
    // A failed dep is unbuilt — demand still flows to it.
    mark_active(&db, "leaf", TARGET, "failed").await;
    db.query("INSERT INTO queue_dependencies (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version, dep_host_side, dep_invocations, dep_shapes, dep_met, dep_side_known) \
                  VALUES (?, ?, 'leaf', ?, '[]', ?, ?, 0, 1, 2, 0, 1)")
            .bind(root_id.clone())
            .bind(task_id_on("leaf", TARGET))
            .bind(VERSION)
            .bind(TARGET)
            .bind(RUSTC)
            .execute()
            .await
            .expect("leaf edge");

    let report = apply(&db, "h0", vec![demand_entry("root", 4)])
        .await
        .expect("demand");
    assert_eq!(report.touched_tasks, 2, "root and the failed dep only");
    assert_eq!(demand_of(&db, "root", TARGET).await, 4);
    assert_eq!(demand_of(&db, "leaf", TARGET).await, 4);
    for name in ["done", "live", "met-dep"] {
        assert_eq!(demand_of(&db, name, TARGET).await, 0, "{name}");
    }
}

/// Distinct input identities contribute their own deltas to a
/// shared dependency — and a cycle terminates with each node
/// touched once (stow#522).
#[tokio::test]
async fn demand_sums_distinct_identities_and_survives_cycles() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request("shared", &[]),
            request("r1", &[dependency("shared")]),
            request("r2", &[dependency("shared")]),
        ],
    )
    .await
    .expect("enqueue shared");
    let report = apply(
        &db,
        "h0",
        vec![demand_entry("r1", 3), demand_entry("r2", 4)],
    )
    .await
    .expect("demand");
    assert_eq!(report.touched_tasks, 3);
    assert_eq!(demand_of(&db, "shared", TARGET).await, 7);

    // a ↔ b: the UNION dedup closes the cycle; each side gets the
    // delta once.
    // The resolver never emits a cycle, so the walk's UNION dedup is
    // exercised with hand-written edges on leaf rows instead.
    let cyc_a = request("cyc-a", &[]);
    let cyc_b = request("cyc-b", &[]);
    enqueue(&db, &[cyc_a.clone(), cyc_b.clone()])
        .await
        .expect("enqueue cycle");
    for (owner, dep) in [(&cyc_a, &cyc_b), (&cyc_b, &cyc_a)] {
        db.query(
            "INSERT INTO queue_dependencies (task_id, depends_on_task_id, dep_met)                  VALUES (?, ?, 0)",
        )
        .bind(owner.task_id().expect("owner id"))
        .bind(dep.task_id().expect("dep id"))
        .execute()
        .await
        .expect("cycle edge");
    }
    let report = apply(&db, "h1", vec![demand_entry("cyc-a", 2)])
        .await
        .expect("cycle demand");
    assert_eq!(report.touched_tasks, 2);
    for name in ["cyc-a", "cyc-b"] {
        assert_eq!(demand_of(&db, name, TARGET).await, 2, "{name}");
    }
}

/// The replay contract: re-delivering the same `batch_id` applies
/// nothing and reports `applied = false`; a distinct batch is a
/// distinct hour and adds on top (stow#522).
#[tokio::test]
async fn demand_replay_is_idempotent_and_batches_accumulate() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("root", &[])])
        .await
        .expect("enqueue");

    let first = apply(&db, "hour-1", vec![demand_entry("root", 5)])
        .await
        .expect("first");
    assert!(first.applied);
    let replay = apply(&db, "hour-1", vec![demand_entry("root", 5)])
        .await
        .expect("replay");
    assert!(!replay.applied);
    assert_eq!(demand_of(&db, "root", TARGET).await, 5);
    // The staged set retired at acceptance — the replay answered
    // from the header alone.
    assert_eq!(contribution_rows(&db, "hour-1").await, 0);

    // The shared pass still returns the planner's answer on an
    // exact replay — the route arms it, repairing a schedule a
    // previously lost response never set (stow#522).
    let (_report, plan) = super::demand_pass(
        &db,
        &demand_batch("hour-1", vec![demand_entry("root", 5)]),
        0,
        &settings(),
    )
    .await
    .expect("demand pass on replay");
    assert!(
        matches!(plan, super::AlarmPlan::At(_)),
        "a replay must still yield the alarm plan, got {plan:?}"
    );

    let next = apply(&db, "hour-2", vec![demand_entry("root", 5)])
        .await
        .expect("next hour");
    assert!(next.applied);
    assert_eq!(demand_of(&db, "root", TARGET).await, 10);
}

/// A delivery's cost is proportional to its own rows, not the
/// stored ledger: the same batch run against 3 vs 300 recorded
/// contribution batches issues identical statements with identical
/// counted rows, the batch predicate plans as an index search, and
/// a crashed earlier delivery converges by folding only its own
/// unmarked rows (stow#522).
#[tokio::test]
async fn demand_cost_stays_proportional_with_preexisting_history() {
    async fn seeded(history: u64) -> (DurableDb, StatementLog) {
        let (db, log) = counting_memory_db().await.expect("counting db");
        enqueue(&db, &[request("root", &[])])
            .await
            .expect("enqueue");
        // A long ledger built by real deliveries — every row
        // already folded through the same path under test.
        for hour in 0..history {
            apply(&db, &format!("old-{hour}"), vec![demand_entry("root", 2)])
                .await
                .expect("history batch");
        }
        (db, log)
    }

    async fn issued_new_batch(db: &DurableDb, log: &StatementLog) -> Vec<String> {
        let base = log.lock().expect("log").len();
        let report = apply(db, "new-hour", vec![demand_entry("root", 3)])
            .await
            .expect("new batch");
        assert!(report.applied);
        let issued = log.lock().expect("log")[base..].to_vec();
        // (sql, rows_read, rows_written) — the observable cost.
        issued
            .iter()
            .map(|s| format!("{}|{}|{}", s.sql, s.rows_read, s.rows_written))
            .collect()
    }

    let (small, small_log) = seeded(3).await;
    let (large, large_log) = seeded(300).await;
    let root = task_id_on("root", TARGET);
    assert_eq!(demand_of(&small, "root", TARGET).await, 6);
    assert_eq!(demand_of(&large, "root", TARGET).await, 600);

    let small_issued = issued_new_batch(&small, &small_log).await;
    let large_issued = issued_new_batch(&large, &large_log).await;
    assert_eq!(
        small_issued, large_issued,
        "history never enters the request"
    );
    assert_eq!(demand_of(&small, "root", TARGET).await, 9);
    assert_eq!(demand_of(&large, "root", TARGET).await, 603);

    // Every batch-keyed predicate is an index probe, not a ledger
    // scan — on reprepare's staging clear and on the acceptance
    // guard's staged count.
    for sql in [
        "DELETE FROM demand_contributions WHERE batch_id = ?",
        "SELECT count(*) FROM demand_contributions c WHERE c.batch_id = ?",
    ] {
        let details = db_plan(&small, sql, &["new-hour"]).await;
        assert!(
            details
                .iter()
                .any(|d| d.contains("SEARCH") && d.contains("demand_contributions")),
            "keyed predicate expected for `{sql}`: {details:?}"
        );
        assert!(
            !details
                .iter()
                .any(|d| d.contains("SCAN") && d.contains("demand_contributions")),
            "ledger scan on the demand path: {details:?}"
        );
    }

    // A delivery that failed after preparing — a `prepared` record
    // with staged rows — reserves nothing and folds nothing: the
    // same-input retry recomputes and accepts, and a different
    // batch never sees the draft's rows.
    let crashed = vec![demand_entry("root", 7)];
    db_insert_batch_record(
        &small,
        "crashed",
        &planted_input_hash(&crashed),
        1,
        "prepared",
    )
    .await;
    db_insert_contribution(&small, &root, "crashed", 7).await;
    let report = apply(&small, "crashed", crashed)
        .await
        .expect("re-deliver crashed batch");
    assert!(report.applied, "the reprepare accepts");
    assert_eq!(demand_of(&small, "root", TARGET).await, 16, "6 + 3 + 7");
    assert_eq!(batch_state(&small, "crashed").await, "accepted");
}

/// One staged row under a planted `prepared` draft — prepared the
/// same way the route prepares it, so the crashed delivery the
/// row models carried real post-fold fields when it died.
async fn db_insert_contribution(db: &DurableDb, task_id: &str, batch_id: &str, delta: i64) {
    let staged = super::prepare_demand_rows(db, &[(task_id.to_owned(), delta)], 0)
        .await
        .expect("prepare draft row")
        .remove(0);
    db.query(
        "INSERT INTO demand_contributions \
             (task_id, batch_id, delta, value, dispatch_key, dispatch_eligible) \
             VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(task_id.to_owned())
    .bind(batch_id.to_owned())
    .bind(delta)
    .bind(staged.value)
    .bind(staged.key)
    .bind(i64::from(staged.eligible))
    .execute()
    .await
    .expect("stage contribution");
}

/// One `demand_batches` row with an explicit state — how a test
/// plants the unaccepted `prepared` state a failed delivery leaves.
async fn db_insert_batch_record(
    db: &DurableDb,
    batch_id: &str,
    input_hash: &str,
    touched_count: i64,
    state: &str,
) {
    db.query(
        "INSERT INTO demand_batches (batch_id, input_hash, touched_count, state) \
             VALUES (?, ?, ?, ?)",
    )
    .bind(batch_id.to_owned())
    .bind(input_hash.to_owned())
    .bind(touched_count)
    .bind(state.to_owned())
    .execute()
    .await
    .expect("record batch");
}

/// The real canonical-input fingerprint for a batch id — how a
/// test's planted `prepared` record carries the input the retry
/// will compute, so the retry is a genuine same-input reprepare.
fn planted_input_hash(entries: &[stow_types::api::SchedulerDemandEntry]) -> String {
    super::demand_input_fingerprint(&super::demand_deltas(entries).expect("deltas"))
        .expect("fingerprint")
}

/// A batch record's current state string, for lifecycle assertions.
async fn batch_state(db: &DurableDb, batch_id: &str) -> String {
    db.query("SELECT state FROM demand_batches WHERE batch_id = ?")
        .bind(batch_id.to_owned())
        .fetch_scalar::<String>()
        .await
        .expect("batch state")
}

async fn batch_rows(db: &DurableDb, batch_id: &str) -> u64 {
    db.query("SELECT count(*) FROM demand_batches WHERE batch_id = ?")
        .bind(batch_id.to_owned())
        .fetch_scalar::<u64>()
        .await
        .expect("batch count")
}

async fn db_plan(db: &DurableDb, sql: &str, binds: &[&str]) -> Vec<String> {
    #[derive(skyzen::FromRow)]
    struct PlanRow {
        detail: String,
    }
    let explained = format!("EXPLAIN QUERY PLAN {sql}");
    let mut query = db.query(&explained);
    for bind in binds {
        query = query.bind((*bind).to_owned());
    }
    query
        .fetch_all::<PlanRow>()
        .await
        .expect("explain")
        .into_iter()
        .map(|row| row.detail)
        .collect()
}

/// Demand is a queue operand, not a side channel: an ordinary
/// re-request and a lane promotion recompute `value`/`dispatch_key`
/// through the same formula and keep the contribution (stow#522).
#[tokio::test]
async fn demand_survives_resubmit_and_promotion() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("root", &[])])
        .await
        .expect("enqueue");
    apply(&db, "h0", vec![demand_entry("root", 9)])
        .await
        .expect("demand");

    // Re-request: the enqueue path's key refresh recomputes value
    // with the demand operand.
    enqueue(&db, &[request("root", &[])])
        .await
        .expect("resubmit");
    assert_eq!(demand_of(&db, "root", TARGET).await, 9);
    let value = db
        .query("SELECT value FROM queue WHERE task_id = ?")
        .bind(task_id_on("root", TARGET))
        .fetch_scalar::<i64>()
        .await
        .expect("value read");
    assert_eq!(value, 9);

    // Promote recomputes lane/family bands and keeps demand.
    super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Promote,
        &filter_selector(stow_types::api::QueueSelector {
            crate_name: Some("root".parse().expect("crate name")),
            ..Default::default()
        }),
    )
    .await
    .expect("promote");
    assert_eq!(demand_of(&db, "root", TARGET).await, 9);
    let value = db
        .query("SELECT value FROM queue WHERE task_id = ?")
        .bind(task_id_on("root", TARGET))
        .fetch_scalar::<i64>()
        .await
        .expect("value read");
    assert_eq!(value, 2 * super::VALUE_BAND + 9, "human band + demand");
}

/// A delta that would push `priority + demand` past `PRIORITY_MAX`
/// is an error before any write — no clamp, no REAL promotion, and
/// the queue plus the contribution ledger are untouched
/// (stow#522).
#[tokio::test]
async fn demand_over_band_bound_fails_without_writes() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("root", &[])])
        .await
        .expect("enqueue");

    let over = (super::PRIORITY_MAX as u64) + 1;
    let error = apply(&db, "h0", vec![demand_entry("root", over)])
        .await
        .expect_err("over-bound demand must fail");
    assert!(error.to_string().contains("priority band"), "{error}");
    assert_eq!(demand_of(&db, "root", TARGET).await, 0);
    assert_eq!(contribution_rows(&db, "h0").await, 0);

    // Exactly at the bound is admissible.
    apply(
        &db,
        "h1",
        vec![demand_entry("root", super::PRIORITY_MAX as u64)],
    )
    .await
    .expect("at-bound demand");
    assert_eq!(demand_of(&db, "root", TARGET).await, super::PRIORITY_MAX);

    // A human-lane Windows root at the maximum wire delta: bands +
    // MAX(0,priority) + i64::MAX could not fit i64, so the typed
    // per-row bound must reject it *before* `raw_value` is
    // computed — never on the overflowed sum.
    let mut human = request_on("hwin", WINDOWS_TARGET, &[]);
    human.source = EnqueueSource::HumanRequest;
    enqueue(&db, &[human]).await.expect("enqueue human root");
    let error = apply(
        &db,
        "h2",
        vec![demand_entry_on(
            "hwin",
            WINDOWS_TARGET,
            u64::try_from(i64::MAX).expect("i64::MAX fits u64"),
        )],
    )
    .await
    .expect_err("i64::MAX delta must fail the band bound");
    assert!(error.to_string().contains("priority band"), "{error}");
    assert_eq!(demand_of(&db, "hwin", WINDOWS_TARGET).await, 0);
    assert_eq!(contribution_rows(&db, "h2").await, 0);
}

/// The stored batch record pins the accepted canonical input: a
/// redelivery naming the same id with ANY different payload — a
/// changed delta or a different identity set — fails before a
/// single write, so a mistaken retry can never reshape the frozen
/// contribution set (stow#522).
#[tokio::test]
async fn demand_conflicting_same_id_payload_fails_before_writes() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[request("root", &[dependency("mid")]), request("mid", &[])],
    )
    .await
    .expect("enqueue");
    apply(&db, "h0", vec![demand_entry("root", 5)])
        .await
        .expect("first delivery");

    // Same id, changed delta — refused.
    let error = apply(&db, "h0", vec![demand_entry("root", 7)])
        .await
        .expect_err("conflicting delta must fail");
    assert!(
        error.to_string().contains("different payload"),
        "conflict error: {error}"
    );
    // Same id, different identity — refused.
    apply(&db, "h0", vec![demand_entry("mid", 5)])
        .await
        .expect_err("conflicting identity must fail");

    // Nothing moved: demands and the batch record are exactly
    // what the first delivery established — the staged set stayed
    // retired.
    assert_eq!(demand_of(&db, "root", TARGET).await, 5);
    assert_eq!(demand_of(&db, "mid", TARGET).await, 5);
    assert_eq!(contribution_rows(&db, "h0").await, 0);
    assert_eq!(batch_rows(&db, "h0").await, 1);
}

/// An exact replay folds the frozen set, not the live closure:
/// after the graph moves on — the root completes, a new task and
/// edge arrive that a fresh walk would reach — the replay applies
/// nothing the first delivery did not record (stow#522).
#[tokio::test]
async fn demand_replay_uses_the_frozen_set_not_the_live_closure() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[request("leaf", &[]), request("root", &[dependency("leaf")])],
    )
    .await
    .expect("enqueue");
    let first = apply(&db, "h0", vec![demand_entry("root", 4)])
        .await
        .expect("first delivery");
    assert_eq!(first.touched_tasks, 2);

    // The graph moves on: the root completes (a fresh walk would
    // find no roots), and a new unbuilt task enters the closure —
    // `extra` is now a live `dep_met = 0` dep of `leaf`.
    mark_active(&db, "root", TARGET, "completed").await;
    enqueue(&db, &[request("extra", &[])])
        .await
        .expect("enqueue extra");
    db.query(
        "INSERT INTO queue_dependencies \
             (task_id, depends_on_task_id, dep_met) VALUES (?, ?, 0)",
    )
    .bind(task_id_on("leaf", TARGET))
    .bind(task_id_on("extra", TARGET))
    .execute()
    .await
    .expect("new edge");

    let replay = apply(&db, "h0", vec![demand_entry("root", 4)])
        .await
        .expect("replay");
    assert!(!replay.applied);
    assert_eq!(replay.touched_tasks, 2);
    assert_eq!(demand_of(&db, "extra", TARGET).await, 0);
    // Acceptance already retired the staged rows — the frozen
    // answer lives in the header, not staging.
    assert_eq!(contribution_rows(&db, "h0").await, 0);
}

/// An accepted batch that froze an empty contribution set keeps
/// its id claimed: replays still apply nothing, and a conflicting
/// payload on the same id is still a conflict — an unknown root at
/// first delivery does not make the id reusable (stow#522).
#[tokio::test]
async fn demand_empty_accepted_batch_stays_empty() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("other", &[])])
        .await
        .expect("enqueue");

    let first = apply(&db, "h0", vec![demand_entry("absent", 9)])
        .await
        .expect("first delivery");
    assert!(first.applied, "an empty accepted set still accepts");
    assert_eq!(first.touched_tasks, 0);
    assert_eq!(batch_rows(&db, "h0").await, 1);

    // The root becoming eligible later does not retro-apply: the
    // frozen empty set is what replays.
    enqueue(&db, &[request("absent", &[])])
        .await
        .expect("enqueue late root");
    let replay = apply(&db, "h0", vec![demand_entry("absent", 9)])
        .await
        .expect("replay");
    assert!(!replay.applied);
    assert_eq!(replay.touched_tasks, 0);
    assert_eq!(demand_of(&db, "absent", TARGET).await, 0);
    assert_eq!(contribution_rows(&db, "h0").await, 0);

    apply(&db, "h0", vec![demand_entry("absent", 8)])
        .await
        .expect_err("conflicting payload must fail");
}

/// An unaccepted draft is not a frozen set: a same-input retry on
/// a `prepared` record recomputes the CURRENT closure — staging
/// from the failed attempt is cleared, tasks the graph no longer
/// shows (a completed dep) contribute nothing, and a task that
/// entered the closure meanwhile joins the accepted set. The
/// draft's own staged rows never fold before acceptance and never
/// reserve band (stow#522).
#[tokio::test]
async fn demand_unaccepted_draft_retry_recomputes_the_live_closure() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[request("leaf", &[]), request("root", &[dependency("leaf")])],
    )
    .await
    .expect("enqueue");

    // A delivery that failed after preparing: the record and one
    // staged row exist, nothing accepted, nothing folded.
    let entries = vec![demand_entry("root", 9)];
    db_insert_batch_record(&db, "h0", &planted_input_hash(&entries), 2, "prepared").await;
    db_insert_contribution(
        &db,
        &task_id_with("root", TARGET, &[dependency("leaf")]),
        "h0",
        9,
    )
    .await;
    db_insert_contribution(&db, &task_id_on("leaf", TARGET), "h0", 9).await;
    assert_eq!(demand_of(&db, "root", TARGET).await, 0);
    assert_eq!(demand_of(&db, "leaf", TARGET).await, 0);

    // The graph moves before the retry: `leaf` completes (out of
    // the live closure) and `extra` joins it — while another
    // legitimate batch accepts against the same nodes, proof the
    // draft's staging reserved no demand.
    mark_active(&db, "leaf", TARGET, "completed").await;
    enqueue(&db, &[request("extra", &[])])
        .await
        .expect("enqueue extra");
    db.query(
        "INSERT INTO queue_dependencies \
             (task_id, depends_on_task_id, dep_met) VALUES (?, ?, 0)",
    )
    .bind(task_id_with("root", TARGET, &[dependency("leaf")]))
    .bind(task_id_on("extra", TARGET))
    .execute()
    .await
    .expect("new edge");
    apply(&db, "h1", vec![demand_entry("root", 3)])
        .await
        .expect("another batch");

    let retry = apply(&db, "h0", entries).await.expect("retry");
    assert!(retry.applied);
    assert_eq!(retry.touched_tasks, 2, "root + extra, not leaf");
    assert_eq!(demand_of(&db, "root", TARGET).await, 12, "9 + 3 from h1");
    assert_eq!(demand_of(&db, "extra", TARGET).await, 12);
    // `leaf` completed before either acceptance: h1's live closure
    // skipped it, and the draft's staged row for it was cleared —
    // its demand is 0, not the staged 9.
    assert_eq!(demand_of(&db, "leaf", TARGET).await, 0);
    // The recomputed set accepted — and consumed its staging in
    // the same statement.
    assert_eq!(contribution_rows(&db, "h0").await, 0, "staged set retired");
    assert_eq!(batch_state(&db, "h0").await, "accepted");
}

/// A failed staging statement leaves only unaccepted material: the
/// `prepared` record and its partial rows fold nothing and block
/// nothing — the same-input retry clears them and accepts the
/// recomputed set exactly once (stow#522).
#[tokio::test]
async fn demand_failed_staging_leaves_no_fold_and_retries_cleanly() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[request("leaf", &[]), request("root", &[dependency("leaf")])],
    )
    .await
    .expect("enqueue");

    // The stage INSERT failed mid-chunk: the record is prepared
    // and only part of the event's rows landed.
    let entries = vec![demand_entry("root", 5)];
    db_insert_batch_record(&db, "h0", &planted_input_hash(&entries), 2, "prepared").await;
    db_insert_contribution(
        &db,
        &task_id_with("root", TARGET, &[dependency("leaf")]),
        "h0",
        5,
    )
    .await;

    // No acceptance happened, so no queue row moved and no demand
    // was reserved — a whole different batch accepts freely.
    assert_eq!(demand_of(&db, "root", TARGET).await, 0);
    apply(&db, "h1", vec![demand_entry("root", 2)])
        .await
        .expect("independent batch");

    let retry = apply(&db, "h0", entries).await.expect("retry");
    assert!(retry.applied);
    assert_eq!(retry.touched_tasks, 2);
    assert_eq!(
        demand_of(&db, "root", TARGET).await,
        7,
        "5 recomputed + 2 from h1"
    );
    assert_eq!(demand_of(&db, "leaf", TARGET).await, 7);
    assert_eq!(contribution_rows(&db, "h0").await, 0, "staged set retired");
}

/// An accepted batch's replay is a pure header read: after the
/// response is lost and the graph changes — a completed root, a
/// new task and side — the redelivery reports the stored count and
/// issues zero writes (stow#522).
#[tokio::test]
async fn demand_accepted_replay_writes_nothing_after_graph_changes() {
    let (db, log) = counting_memory_db().await.expect("counting db");
    enqueue(
        &db,
        &[request("leaf", &[]), request("root", &[dependency("leaf")])],
    )
    .await
    .expect("enqueue");
    let first = apply(&db, "h0", vec![demand_entry("root", 4)])
        .await
        .expect("first delivery");
    assert_eq!(first.touched_tasks, 2);

    mark_active(&db, "root", TARGET, "completed").await;
    enqueue(&db, &[request("extra", &[])])
        .await
        .expect("enqueue extra");

    let base = log.lock().expect("log").len();
    let replay = apply(&db, "h0", vec![demand_entry("root", 4)])
        .await
        .expect("replay");
    assert!(!replay.applied);
    assert_eq!(replay.touched_tasks, 2, "the stored count answers");
    let issued = log.lock().expect("log")[base..].to_vec();
    assert!(
        issued.iter().all(|s| s.rows_written == 0),
        "an accepted replay must not write: {issued:?}"
    );
    assert_eq!(demand_of(&db, "extra", TARGET).await, 0);
    assert_eq!(demand_of(&db, "root", TARGET).await, 4);
}

/// The acceptance statement is statement-atomic: force the
/// trigger's staged-count verification to fail after the fold has
/// already written a queue row (the raw UPDATE bypasses the
/// caller's own count guard), and the abort rolls back the queue
/// fold, the staged rows, and the accepted transition alike —
/// the batch stays `prepared` and the queue untouched (stow#522).
#[tokio::test]
async fn demand_acceptance_trigger_failure_rolls_back_everything() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("root", &[])])
        .await
        .expect("enqueue");
    let root = task_id_on("root", TARGET);

    // Record says two staged rows; only one landed — the partial
    // prepared set the guard exists to refuse. A direct state
    // flip reaches the trigger: the fold writes root's demand,
    // then the count check aborts the whole statement.
    let entries = vec![demand_entry("root", 9)];
    db_insert_batch_record(&db, "h0", &planted_input_hash(&entries), 2, "prepared").await;
    db_insert_contribution(&db, &root, "h0", 9).await;
    let error = db
        .query("UPDATE demand_batches SET state = 'accepted' WHERE batch_id = ?")
        .bind("h0".to_owned())
        .execute()
        .await
        .expect_err("short staged set must abort acceptance");
    assert!(
        error.to_string().contains("staged set short"),
        "abort reason: {error}"
    );

    assert_eq!(batch_state(&db, "h0").await, "prepared");
    assert_eq!(
        demand_of(&db, "root", TARGET).await,
        0,
        "the fold rolled back"
    );
    assert_eq!(contribution_rows(&db, "h0").await, 1);

    // And the retry path still works on the rolled-back draft.
    let report = apply(&db, "h0", entries).await.expect("retry");
    assert!(report.applied);
    assert_eq!(demand_of(&db, "root", TARGET).await, 9);
}

/// A closure whose serialized set would exceed the workerd 2 MiB
/// bound lands whole: staging splits into chunks each under
/// `DEMAND_STAGE_CHUNK_BYTES`, every row survives, and acceptance
/// folds the complete set — no truncation, no giant bound string
/// or ledger row (stow#522).
#[tokio::test]
async fn demand_stages_large_closures_in_bounded_chunks() {
    // 60k rows of realistic 64-char task ids serialize to ~6 MiB —
    // far past the 2 MiB bound a single snapshot would hit.
    let rows: Vec<super::ContributionRow> = (0..60_000)
        .map(|i| super::ContributionRow {
            tid: format!("{i:064x}"),
            delta: 1,
            value: "0".to_owned(),
            key: format!("0{i:064x}|now|now|{i:064x}"),
            eligible: 1,
        })
        .collect();
    let chunks = super::contribution_chunks(&rows).expect("chunks");
    assert!(chunks.len() > 1, "the set must split");
    let mut seen = 0_usize;
    for chunk in &chunks {
        assert!(
            chunk.len() < super::DEMAND_STAGE_CHUNK_BYTES,
            "chunk over bound: {} bytes",
            chunk.len()
        );
        let parsed: Vec<super::ContributionRow> =
            serde_json::from_str(chunk).expect("chunk parses");
        seen += parsed.len();
    }
    assert_eq!(seen, rows.len(), "no row truncated or lost");
}

/// The end-to-end bound the serialized-snapshot path could never
/// cross: a real closure whose staged set exceeds the platform's
/// 2 MiB row/binding bound folds through multiple staging chunks
/// and still accepts atomically — full touched/ledger counts and
/// the last task's demand included. A delivery that dies after an
/// earlier staging chunk leaves only unaccepted draft material —
/// no header acceptance, no queue fold — and the same-input retry
/// recomputes, restages and converges exactly once (stow#522).
#[tokio::test]
async fn demand_multi_chunk_closure_is_atomic_end_to_end() {
    // 30k real queue tasks, one dependency chain — the closure
    // from the root touches all of them through the unmet-edge
    // walk, with the queue's own 64-hex task ids. The migration
    // permit stays open on this database: the failure-injection
    // trigger below is the same class of schema DDL the operator
    // migrate path issues — installing it is fixture preparation,
    // while every production statement the test drives is DML.
    const CHAIN: usize = 30_000;
    let (db, _log) = counting_memory_db_raw().await.expect("counting db");
    let mut requests: Vec<EnqueueRequest> = Vec::with_capacity(CHAIN);
    for i in 0..CHAIN {
        requests.push(request(&format!("chain-{i}"), &[]));
    }
    enqueue(&db, &requests).await.expect("enqueue chain");
    // The chain's edges are hand-written: each request carries its
    // real transitive subgraph on the wire, so 30k nested
    // `EnqueueRequest`s would square the fixture for no coverage —
    // the walk reads `queue_dependencies`, not the mint.
    for i in 0..CHAIN - 1 {
        db.query(
            "INSERT INTO queue_dependencies (task_id, depends_on_task_id, dep_met)                  VALUES (?, ?, 0)",
        )
        .bind(requests[i].task_id().expect("owner id"))
        .bind(requests[i + 1].task_id().expect("dep id"))
        .execute()
        .await
        .expect("chain edge");
    }

    // The staged set this event would produce: one serialized
    // snapshot of it measures past the 2 MiB bound the old
    // blob-column path bound as a single string, while the real
    // staging splits it into several bounded chunks.
    let contributions = super::demand_event_rows(
        &db,
        &super::demand_deltas(&[demand_entry("chain-0", 2)]).expect("deltas"),
    )
    .await
    .expect("closure rows");
    assert_eq!(contributions.len(), CHAIN, "the closure is the chain");
    let staged = super::prepare_demand_rows(&db, &contributions, 0)
        .await
        .expect("prepared rows");
    let snapshot = serde_json::to_string(&staged).expect("snapshot encodes");
    assert!(
        snapshot.len() > 2 * 1024 * 1024,
        "serialized staged set must cross the old 2 MiB bound: {} bytes",
        snapshot.len()
    );
    let chunks = super::contribution_chunks(&staged).expect("chunks");
    assert!(
        chunks.len() > 1,
        "the staged set must land as multiple chunks, got {}",
        chunks.len()
    );

    // The *old* minimal snapshot — `{tid, delta}` per row, the
    // shape the blob-column path staged — also crosses the 2 MiB
    // bound on its own: this fixture's proof doesn't depend on the
    // wider prepared payload.
    let minimal = serde_json::to_string(
        &contributions
            .iter()
            .map(|(task_id, delta)| serde_json::json!({"tid": task_id, "delta": delta}))
            .collect::<Vec<_>>(),
    )
    .expect("minimal snapshot encodes");
    assert!(
        minimal.len() > 2 * 1024 * 1024,
        "minimal tid/delta snapshot must cross the old 2 MiB bound: {} bytes",
        minimal.len()
    );

    sabotage_later_chunk_then_recover(&db, &chunks, CHAIN).await;
}

/// The failure half of
/// [`demand_multi_chunk_closure_is_atomic_end_to_end`]: installs a
/// `RAISE(ABORT)` trigger on one task id known to land in the last
/// staging chunk, runs the production `apply_demand` into it, and
/// asserts the landed prefix, the `prepared` header and the empty
/// queue fold — then drops the trigger and asserts the same-input
/// retry converges once and an exact replay writes nothing.
async fn sabotage_later_chunk_then_recover(db: &DurableDb, chunks: &[String], chain: usize) {
    let last_chunk: Vec<serde_json::Value> =
        serde_json::from_str(&chunks[chunks.len() - 1]).expect("last chunk decodes");
    let sabotage_tid = last_chunk[0]["tid"]
        .as_str()
        .expect("chunk row carries tid")
        .to_owned();
    db.query(&format!(
        "CREATE TRIGGER sabotage_demand_stage \
             AFTER INSERT ON demand_contributions \
             WHEN NEW.task_id = '{sabotage_tid}' \
             BEGIN SELECT RAISE(ABORT, 'injected staging failure'); END"
    ))
    .execute()
    .await
    .expect("install sabotage trigger");
    let entries = vec![demand_entry("chain-0", 2)];
    let failed = apply(db, "big", entries.clone())
        .await
        .expect_err("sabotaged staging must fail");
    let message = failed.to_string();
    assert!(
        message.contains("injected staging failure"),
        "the failure must be the injected abort, got: {message}"
    );
    let staged_so_far = contribution_rows(db, "big").await;
    assert!(
        staged_so_far > 0 && staged_so_far < chain as u64,
        "earlier chunks landed, the sabotaged one did not: {staged_so_far}"
    );
    assert_eq!(batch_state(db, "big").await, "prepared");
    assert_eq!(demand_of(db, "chain-0", TARGET).await, 0);
    assert_eq!(
        demand_of(db, &format!("chain-{}", chain - 1), TARGET).await,
        0,
        "no queue fold without acceptance"
    );

    // Remove the failure, then the same-input retry recomputes the
    // live closure, replaces the partial staging and accepts once —
    // every task touched, full ledger count, the last task's demand
    // folded.
    db.query("DROP TRIGGER sabotage_demand_stage")
        .execute()
        .await
        .expect("drop sabotage trigger");
    let report = apply(db, "big", entries).await.expect("retry converges");
    assert!(report.applied);
    assert_eq!(report.touched_tasks, chain as u64);
    // The accepted fold retired the whole staged set in the same
    // statement.
    assert_eq!(contribution_rows(db, "big").await, 0);
    assert_eq!(batch_state(db, "big").await, "accepted");
    assert_eq!(demand_of(db, "chain-0", TARGET).await, 2);
    assert_eq!(
        demand_of(db, &format!("chain-{}", chain - 1), TARGET).await,
        2
    );

    // And an exact replay of the accepted batch writes nothing:
    // the stored header answers, the demand stays folded once.
    let replay = apply(db, "big", vec![demand_entry("chain-0", 2)])
        .await
        .expect("accepted replay");
    assert!(!replay.applied);
    assert_eq!(replay.touched_tasks, chain as u64);
    assert_eq!(demand_of(db, "chain-0", TARGET).await, 2);
}

/// Persisted demand counts against the resubmit writer's band:
/// demand exactly at `PRIORITY_MAX` is legal while priority stays
/// 0, but a resubmit that would raise priority must be refused
/// before any write — queue, edges and demand untouched — while a
/// sibling below the bound still resubmits normally (stow#522).
#[tokio::test]
async fn demand_at_bound_then_rising_resubmit_is_refused() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("bound", &[]), request("fine", &[])])
        .await
        .expect("enqueue");
    apply(
        &db,
        "h0",
        vec![demand_entry("bound", super::PRIORITY_MAX as u64)],
    )
    .await
    .expect("at-bound demand");

    // downloads 1000 → new priority 1 > PRIORITY_MAX - demand = 0.
    let mut resubmit = request("bound", &[]);
    resubmit.downloads = 1000;
    let error = enqueue(&db, &[resubmit])
        .await
        .expect_err("resubmit past the band must fail");
    assert!(
        error.to_string().contains("priority band"),
        "band error: {error}"
    );

    // Nothing changed: demand, downloads and request count are the
    // pre-resubmit values.
    assert_eq!(demand_of(&db, "bound", TARGET).await, super::PRIORITY_MAX);
    let downloads: i64 = db
        .query("SELECT downloads FROM queue WHERE task_id = ?")
        .bind(task_id_on("bound", TARGET))
        .fetch_scalar::<i64>()
        .await
        .expect("downloads");
    let request_count: i64 = db
        .query("SELECT request_count FROM queue WHERE task_id = ?")
        .bind(task_id_on("bound", TARGET))
        .fetch_scalar::<i64>()
        .await
        .expect("request_count");
    assert_eq!((downloads, request_count), (0, 1));

    // Below the bound the same resubmit is ordinary: the sibling
    // takes downloads 5000 → priority 5, demand still folded.
    let mut ok = request("fine", &[]);
    ok.downloads = 5000;
    enqueue(&db, &[ok]).await.expect("below-bound resubmit");
    let priority: i64 = db
        .query("SELECT priority FROM queue WHERE task_id = ?")
        .bind(task_id_on("fine", TARGET))
        .fetch_scalar::<i64>()
        .await
        .expect("priority");
    assert_eq!(priority, 5);
}

/// The same refusal precedes the human-lane budget charge: a human
/// resubmit that would overflow the band is rejected before any
/// mutation, so `human_daily_task_budget` stays byte-identical —
/// on both the untrusted and the trusted entry path (stow#522).
#[tokio::test]
async fn demand_at_bound_human_resubmit_spends_no_budget() {
    async fn spent(db: &DurableDb) -> i64 {
        db.query(
            "SELECT task_count FROM human_daily_task_budget \
                 WHERE day = date('now')",
        )
        .fetch_scalar::<i64>()
        .await
        .expect("budget spend")
    }

    let db = memory_db().await.expect("memory db");
    let mut human = request("bound", &[]);
    human.source = EnqueueSource::HumanRequest;
    enqueue(&db, &[human.clone()]).await.expect("human enqueue");
    assert_eq!(spent(&db).await, 1, "the first submit charged once");
    apply(
        &db,
        "h0",
        vec![demand_entry("bound", super::PRIORITY_MAX as u64)],
    )
    .await
    .expect("at-bound demand");

    // downloads 1000 → new priority 1 > PRIORITY_MAX - demand = 0:
    // refused before the budget charge, through both entries.
    let mut resubmit = human;
    resubmit.downloads = 1000;
    enqueue(&db, &[resubmit.clone()])
        .await
        .expect_err("untrusted resubmit past the band must fail");
    assert_eq!(spent(&db).await, 1, "a refused resubmit spends nothing");
    super::enqueue_trusted(&db, &[resubmit], &settings())
        .await
        .expect_err("trusted resubmit past the band must fail");
    assert_eq!(spent(&db).await, 1, "trusted path spends nothing either");

    // Queue state is the pre-resubmit truth.
    assert_eq!(demand_of(&db, "bound", TARGET).await, super::PRIORITY_MAX);
    let downloads: i64 = db
        .query("SELECT downloads FROM queue WHERE task_id = ?")
        .bind(task_id_on("bound", TARGET))
        .fetch_scalar::<i64>()
        .await
        .expect("downloads");
    assert_eq!(downloads, 0);
    let edges: i64 = db
        .query("SELECT count(*) FROM queue_dependencies")
        .fetch_scalar::<i64>()
        .await
        .expect("edges");
    assert_eq!(edges, 0);
}

/// Demand magnitudes above the JS safe-integer bound stay exact:
/// the persisted `value` differs by exactly one for adjacent deltas
/// above 2^53 and the claim order follows it — the JSON-decimal
/// transport never became a float (stow#522).
#[tokio::test]
async fn demand_orders_exactly_above_the_js_safe_integer() {
    #[derive(skyzen::FromRow)]
    struct ValuePair {
        task_id: String,
        value: i64,
    }
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("less", &[]), request("more", &[])])
        .await
        .expect("enqueue");
    let js_safe = 9_007_199_254_740_992_u64; // 2^53
    assert!(js_safe + 2 <= super::PRIORITY_MAX as u64);
    apply(
        &db,
        "h0",
        vec![
            demand_entry("less", js_safe + 1),
            demand_entry("more", js_safe + 2),
        ],
    )
    .await
    .expect("demand");

    let values = db
        .query("SELECT task_id, value FROM queue ORDER BY task_id")
        .fetch_all::<ValuePair>()
        .await
        .expect("values");
    let less = values
        .iter()
        .find(|row| row.task_id == task_id_on("less", TARGET))
        .expect("less row")
        .value;
    let more = values
        .iter()
        .find(|row| row.task_id == task_id_on("more", TARGET))
        .expect("more row")
        .value;
    assert_eq!(more - less, 1, "adjacent deltas stay adjacent");
    assert!(less > js_safe.cast_signed(), "values are above 2^53");

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed[0].crate_name, "more");
}

/// An entry whose identity names no queue row is an accepted
/// zero-count batch — the id is claimed, the queue untouched
/// (stow#522).
#[tokio::test]
async fn demand_on_an_unknown_identity_is_a_noop() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("root", &[])])
        .await
        .expect("enqueue");
    let report = apply(&db, "h0", vec![demand_entry("absent", 5)])
        .await
        .expect("demand");
    assert!(report.applied, "an empty closure still accepts");
    assert_eq!(report.touched_tasks, 0);
    assert_eq!(contribution_rows(&db, "h0").await, 0);
    assert_eq!(batch_state(&db, "h0").await, "accepted");
    assert_eq!(demand_of(&db, "root", TARGET).await, 0);
}

/// Malformed batches fail at validation, before any queue read or
/// write: an empty or oversized `batch_id`, an empty entry list,
/// and a delta that cannot fit `i64` (stow#522).
#[tokio::test]
async fn demand_rejects_malformed_batches() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("root", &[])])
        .await
        .expect("enqueue");

    for bad in ["", &"x".repeat(129)] {
        apply(&db, bad, vec![demand_entry("root", 1)])
            .await
            .expect_err("bad batch_id must fail");
    }
    apply(&db, "h0", Vec::new())
        .await
        .expect_err("empty entries must fail");
    let entries = (0..=256)
        .map(|i| demand_entry(&format!("e{i}"), 1))
        .collect();
    apply(&db, "h0", entries)
        .await
        .expect_err("over-cap entries must fail");
    apply(&db, "h0", vec![demand_entry("root", u64::MAX)])
        .await
        .expect_err("u64 delta must fail");
    assert_eq!(demand_of(&db, "root", TARGET).await, 0);
}

/// With the macOS slot count spent mid-pass, the pass skips the
/// remaining macOS rows but still claims other families' work; the
/// skipped row stays pending for the next pass.
#[tokio::test]
async fn macos_cap_skips_macos_rows_but_claims_other_families() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request_on("mac-one", MACOS_TARGET, &[]),
            request_on("mac-two", MACOS_TARGET, &[]),
            request_on("lin", TARGET, &[]),
        ],
    )
    .await
    .expect("enqueue");

    let settings = SchedulerSettings {
        max_concurrent_macos_jobs: 1,
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
        .await
        .expect("claim");

    assert_eq!(claimed.len(), 2);
    assert_eq!(
        claimed
            .iter()
            .filter(|task| task.target == MACOS_TARGET)
            .count(),
        1,
        "the macOS cap admits exactly one macOS row"
    );
    assert!(
        claimed.iter().any(|task| task.crate_name == "lin"),
        "the Linux row is not held back by the macOS cap"
    );
    assert_eq!(super::status(&db).await.expect("status").pending, 1);
}

/// Within a lane, Windows-family rows claim before other targets even
/// when the other row was requested first — the Windows legs are the
/// slowest in a wave, so they start first.
#[tokio::test]
async fn windows_tasks_claim_before_linux_within_a_lane() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request_on("lin", TARGET, &[])])
        .await
        .expect("enqueue linux");
    enqueue(&db, &[request_on("win", WINDOWS_TARGET, &[])])
        .await
        .expect("enqueue windows");
    set_first_requested_at(&db, "lin", PAST_TS).await;

    let settings = SchedulerSettings {
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 2);
    assert_eq!(claimed[0].crate_name, "win");
    assert_eq!(claimed[1].crate_name, "lin");
}

/// With every macOS slot taken and only macOS rows pending, the alarm
/// must target the active row's lease expiry — never `now`, which
/// would spin the object in a zero-delay alarm loop.
#[tokio::test]
async fn saturated_macos_family_wakes_at_lease_expiry() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request_on("mac-busy", MACOS_TARGET, &[]),
            request_on("mac-waiting", MACOS_TARGET, &[]),
        ],
    )
    .await
    .expect("enqueue");
    mark_active(&db, "mac-busy", MACOS_TARGET, "dispatched").await;
    set_first_requested_at_on(
        &db,
        "mac-waiting",
        MACOS_TARGET,
        PAST_TS,
        settings().dispatch_min_age_minutes,
    )
    .await;

    let settings = SchedulerSettings {
        max_concurrent_macos_jobs: 1,
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let plan = next_alarm(&db, ROW_TS_MS, &settings)
        .await
        .expect("next_alarm");
    assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + stale_ms()));
}

/// The lane ordering still dominates the family ordering: a
/// human-lane Linux row claims ahead of a miss-lane Windows row.
#[tokio::test]
async fn human_lane_still_claims_first_regardless_of_family() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request_on("win", WINDOWS_TARGET, &[])])
        .await
        .expect("enqueue windows");
    enqueue(
        &db,
        &[EnqueueRequest {
            source: EnqueueSource::HumanRequest,
            ..request_on("lin", TARGET, &[])
        }],
    )
    .await
    .expect("enqueue human");

    let settings = SchedulerSettings {
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 2);
    assert_eq!(claimed[0].crate_name, "lin");
    assert_eq!(claimed[1].crate_name, "win");
}

#[tokio::test]
async fn a_target_no_runner_builds_never_enters_the_queue() {
    // `build-crate.yml` resolves an unknown target to an empty
    // `runs-on`, so such a row could only ever become a dispatch that
    // dies before any job starts — no job, no log, no completion
    // report, and the slot held until the stale sweep reclaims it.
    let db = memory_db().await.expect("memory db");
    let mut unrunnable = request("serde", &[]);
    unrunnable.target = "aarch64-unknown-linux-musl"
        .parse()
        .expect("valid target triple");

    let inserted = enqueue(&db, &[unrunnable]).await.expect("enqueue");

    assert_eq!(
        inserted, 0,
        "nothing is queued for a target CI cannot build"
    );
    assert_eq!(
        super::status(&db).await.expect("status").pending,
        0,
        "and the queue stays empty"
    );
}

#[tokio::test]
async fn a_ci_target_still_enters_the_queue() {
    let db = memory_db().await.expect("memory db");

    let inserted = enqueue(&db, &[request("serde", &[])])
        .await
        .expect("enqueue");

    assert_eq!(inserted, 1);
    assert_eq!(super::status(&db).await.expect("status").pending, 1);
}

/// `inserted` counts the records the submit landed — never the
/// backend's billed write rows, which include index maintenance:
/// a resync reports 0 and a mixed batch reports only its
/// newcomers.
#[tokio::test]
async fn a_submit_reports_only_the_records_it_inserted() {
    let db = memory_db().await.expect("memory db");

    let inserted = enqueue(&db, &[request("alpha", &[]), request("beta", &[])])
        .await
        .expect("enqueue pair");
    assert_eq!(inserted, 2);

    let resync = enqueue(&db, &[request("alpha", &[])])
        .await
        .expect("resync");
    assert_eq!(resync, 0, "a resync lands no new row");

    let mixed = enqueue(&db, &[request("beta", &[]), request("gamma", &[])])
        .await
        .expect("mixed submit");
    assert_eq!(mixed, 1, "only the newcomer counts");
}

/// The gate regression's slice membership: `dep-met` and
/// `dep-fpub` at both shapes a native target dep requires —
/// (Target, Native, Linked) and (…, Unlinked) — and `dep-short`
/// at only the linked one.
fn gate_pub_rows() -> Vec<stow_types::api::PublishedSliceRow> {
    let full = || {
        [
            shape(UnitSide::Target, UnitInvocation::Native, UnitKind::Linked),
            shape(UnitSide::Target, UnitInvocation::Native, UnitKind::Unlinked),
        ]
    };
    ["dep-met", "dep-fpub"]
        .iter()
        .flat_map(|name| full().iter().map(|s| (name, *s)).collect::<Vec<_>>())
        .map(|(name, s)| stow_types::api::PublishedSliceRow {
            dependency_identity: dep_identity(name),
            crate_name: name.parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            unit_shape: Some(s),
        })
        .chain(std::iter::once(stow_types::api::PublishedSliceRow {
            dependency_identity: dep_identity("dep-short"),
            crate_name: "dep-short".parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            unit_shape: Some(shape(
                UnitSide::Target,
                UnitInvocation::Native,
                UnitKind::Linked,
            )),
        }))
        .collect()
}

/// One submit derives every newcomer's `deps_met`/`blocked` from a
/// single readiness pass over the batch's edges: a row with no
/// edges lands met, a dep published at both of the shapes its
/// target requires releases its parent, a half-published dep only
/// waits, a dep retrying a transient failure waits unblocked,
/// and an unresolved-side edge blocks. Multi-dep owners fold per
/// edge: a met edge beside an unmet one still gates, and a blocker
/// flag on an already-published dep never blocks on its own.
#[tokio::test]
async fn a_submit_gates_each_new_task_on_its_published_deps() {
    let db = memory_db().await.expect("memory db");

    // A transient failure leaves the unpublished dependency pending
    // behind its retry backoff, so its parent waits unblocked.
    enqueue(&db, &[request("dep-failed", &[])])
        .await
        .expect("enqueue dep");
    fail_dependency_at_attempt(&db, "dep-failed", 1).await;
    enqueue(&db, &[request("dep-fpub", &[])])
        .await
        .expect("enqueue published dep");
    db.query("UPDATE queue SET status = 'failed' WHERE task_id = ?")
        .bind(task_id_on("dep-fpub", TARGET))
        .execute()
        .await
        .expect("fail published dep");
    // The migration's spelling for an edge whose required side it
    // could not derive — seeded directly so the owner below is
    // born carrying it (its empty `depends_on` means the resync
    // never deletes the row).
    db.query(
        "INSERT INTO queue_dependencies \
             (task_id, depends_on_task_id, dep_crate_name, dep_version, \
              dep_features_json, dep_target, dep_rustc_version, \
              dep_host_side, dep_invocations, dep_shapes, dep_side_known) \
             VALUES (?, 'unresolved', '', '', '', '', '', -1, 0, 0, 0)",
    )
    .bind(task_id_on("mystery", TARGET))
    .execute()
    .await
    .expect("seed unknown-side edge");
    // `pair` holds two stored edges, so the fold must sum across
    // them — and only an edge that is unmet *and* blocking may
    // raise `blocked`: dep-fpub publishes both shapes but its row
    // sits 'failed' (nothing in this submit names it, so no
    // requeue revives it), contributing unpub=0/blocker=1, while
    // dep-short is unmet but pending-free, unpub=1/blocker=0.
    let (invocations, shapes) = super::dep_edge_requirements(TARGET, false, TARGET, false);
    for (dep, side_known) in [("dep-fpub", 1), ("dep-short", 1)] {
        db.query(
            "INSERT INTO queue_dependencies \
                 (task_id, depends_on_task_id, dep_crate_name, dep_version, \
                  dep_features_json, dep_target, dep_rustc_version, \
                  dep_host_side, dep_dependency_identity, dep_invocations, dep_shapes, dep_side_known) \
                 VALUES (?, ?, ?, '1.0.0', '[]', ?, ?, 0, ?, ?, ?, ?)",
        )
        .bind(task_id_on("pair", TARGET))
        .bind(task_id_on(dep, TARGET))
        .bind(dep.to_owned())
        .bind(TARGET.to_owned())
        .bind(RUSTC.to_owned())
        .bind(
            dep_identity(dep)
                .expect("leaf dep identity")
                .to_string(),
        )
        .bind(invocations)
        .bind(shapes)
        .bind(side_known)
        .execute()
        .await
        .expect("seed known-side edge");
    }

    // One slice report serves `dep-met` and `dep-fpub` at both shapes
    // a native target dep requires, and `dep-short` at only the linked
    // shape. Publish it after the fabricated edges exist so the real
    // slice-delta path initializes the persisted `dep_met` flags.
    super::record_published_slice(&db, TARGET, RUSTC, None, None, &gate_pub_rows(), &[])
        .await
        .expect("record shared published slice");
    assert_pair_flags_after_publication(&db).await;

    let inserted = enqueue(
        &db,
        &[
            request("free", &[]),
            request("met", &[dependency("dep-met")]),
            request("short", &[dependency("dep-short")]),
            request("stalled", &[dependency("dep-failed")]),
            request("mystery", &[]),
            request("twin", &[dependency("dep-met"), dependency("dep-short")]),
            request("pair", &[]),
        ],
    )
    .await
    .expect("enqueue gate cases");
    assert_eq!(inserted, 7, "every newcomer landed");

    for (name, deps_met, blocked) in [
        ("free", 1, 0),
        ("met", 1, 0),
        ("short", 0, 0),
        ("stalled", 0, 0),
        ("mystery", 0, 1),
        // A met edge beside an unmet one: the fold still reports
        // the owner unmet, and a pending dep never blocks.
        ("twin", 0, 0),
        // A blocker flag on a met edge (published but failed dep)
        // cannot block, while the unmet edge still gates the owner.
        ("pair", 0, 0),
    ] {
        let deps: Vec<EnqueueRequest> = match name {
            "met" => vec![dependency("dep-met")],
            "short" => vec![dependency("dep-short")],
            "stalled" => vec![dependency("dep-failed")],
            "twin" => vec![dependency("dep-met"), dependency("dep-short")],
            _ => Vec::new(),
        };
        let id = task_id_with(name, TARGET, &deps);
        for (column, expected) in [("deps_met", deps_met), ("blocked", blocked)] {
            let stored = db
                .query(&format!("SELECT {column} FROM queue WHERE task_id = ?"))
                .bind(id.clone())
                .fetch_scalar::<i64>()
                .await
                .expect("stored gate flag");
            assert_eq!(stored, expected, "{name}: {column}");
        }
    }
}

/// A failed build under the attempt cap re-queues itself: the
/// failure report writes `pending` with the exponential
/// `not_before` backoff and the attempt bumped — the next dispatch
/// it earns is a retry of attempt 2, gated by the backoff.
#[tokio::test]
async fn failed_build_retries_behind_its_backoff() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("flaky", &[])])
        .await
        .expect("enqueue");
    set_first_requested_at(&db, "flaky", PAST_TS).await;

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    super::complete(
        &db,
        &claim_settings(),
        &super::BuildCompleteReport {
            task_id: claimed[0].task_id.clone(),
            generation_id: claimed[0].generation_id.clone(),
            attempt: claimed[0].attempt,
            success: false,
            error: Some("boom".to_owned()),
            finished_at: None,
            github_run_id: None,
        },
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete");

    assert_eq!(row_column(&db, "flaky", "status").await, "pending");
    assert_eq!(row_column(&db, "flaky", "CAST(attempt AS TEXT)").await, "2");
    // attempt 1 fails → 2^1 minutes of `not_before` backoff, and the
    // alarm's `wake_at` follows it.
    let gated = db
        .query(
            "SELECT CASE WHEN not_before > datetime('now') \
                 AND wake_at >= not_before THEN 1 ELSE 0 END AS gated \
                 FROM queue WHERE task_id = ?",
        )
        .bind(claimed[0].task_id.clone())
        .fetch_scalar::<i64>()
        .await
        .expect("read not_before gate");
    assert_eq!(gated, 1);

    // The backoff gates the retry — nothing claims it now — and a
    // re-request neither resurrects nor clears the gate.
    enqueue(&db, &[request("flaky", &[])])
        .await
        .expect("re-request");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert!(claimed.is_empty());
    assert_eq!(row_column(&db, "flaky", "status").await, "pending");
    assert_eq!(row_column(&db, "flaky", "CAST(attempt AS TEXT)").await, "2");
}

/// A failure at the attempt cap parks the row `failed` — no
/// resurrection, no backoff, no claim; only the operator's
/// `retry` returns it to `pending`.
#[tokio::test]
async fn failed_build_at_the_attempt_cap_parks_failed() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("flaky", &[])])
        .await
        .expect("enqueue");
    set_first_requested_at(&db, "flaky", PAST_TS).await;

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    db.query("UPDATE queue SET attempt = ? WHERE task_id = ?")
        .bind(i64::from(super::MAX_BUILD_ATTEMPTS))
        .bind(claimed[0].task_id.clone())
        .execute()
        .await
        .expect("set attempt to the cap");
    super::complete(
        &db,
        &claim_settings(),
        &report(
            &claimed[0].task_id,
            &claimed[0].generation_id,
            super::MAX_BUILD_ATTEMPTS,
            false,
        ),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete");
    assert_eq!(row_column(&db, "flaky", "status").await, "failed");
    assert_eq!(
        row_column(&db, "flaky", "CAST(attempt AS TEXT)").await,
        super::MAX_BUILD_ATTEMPTS.to_string()
    );

    // A re-request is a no-op: `failed` never resurrects.
    enqueue(&db, &[request("flaky", &[])])
        .await
        .expect("re-request");
    assert_eq!(row_column(&db, "flaky", "status").await, "failed");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert!(claimed.is_empty());
}

/// The lane an operator's rebuild submit takes: a completed
/// row ignores a miss-lane re-request (its artifacts sit in the
/// catalog), but the human lane — the lane an operator's re-request
/// rides — resurrects it. With the catalog's coverage oracle no
/// longer covering the over-floor row, the resurrected rebuild
/// claims rather than retiring.
#[tokio::test]
async fn human_rerequest_resurrects_completed_and_claims() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("stale-glibc", &[])])
        .await
        .expect("enqueue");
    set_first_requested_at(&db, "stale-glibc", PAST_TS).await;

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    super::complete(
        &db,
        &claim_settings(),
        &super::BuildCompleteReport {
            task_id: claimed[0].task_id.clone(),
            generation_id: claimed[0].generation_id.clone(),
            attempt: claimed[0].attempt,
            success: true,
            error: None,
            finished_at: None,
            github_run_id: None,
        },
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete");

    // A miss-lane re-request is a no-op against a completed row.
    enqueue(&db, &[request("stale-glibc", &[])])
        .await
        .expect("miss re-request");
    assert!(
        super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")
            .is_empty()
    );

    // The human lane resurrects it, and the oracle that no longer
    // covers the over-floor catalog row offers nothing to retire
    // against — the rebuild claims.
    let human = EnqueueRequest {
        source: EnqueueSource::HumanRequest,
        ..request("stale-glibc", &[])
    };
    super::enqueue_trusted(&db, &[human], &claim_settings())
        .await
        .expect("human re-request");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "stale-glibc");
}

#[tokio::test]
async fn github_app_token_cache_reuses_fresh_token() {
    let db = memory_db().await.expect("memory db");
    assert!(
        super::github_app_token(&db).await.expect("read").is_none(),
        "empty cache yields no token"
    );

    let stored = token();
    super::store_github_app_token(&db, &stored)
        .await
        .expect("store");
    let cached = super::github_app_token(&db)
        .await
        .expect("read")
        .expect("fresh token is cached");
    assert_eq!(cached.token, stored.token);
    assert_eq!(cached.expires_at, stored.expires_at);
}

#[tokio::test]
async fn github_app_token_cache_drops_token_inside_refresh_margin() {
    let db = memory_db().await.expect("memory db");
    super::store_github_app_token(&db, &token())
        .await
        .expect("store");
    // Four minutes out is inside the five-minute reuse floor: the
    // cached token must not be served.
    set_cached_expiry(&db, "+4 minutes").await;
    assert!(
        super::github_app_token(&db).await.expect("read").is_none(),
        "token inside the refresh margin must not be reused"
    );
}

#[tokio::test]
async fn github_app_token_cache_drops_expired_token() {
    let db = memory_db().await.expect("memory db");
    super::store_github_app_token(&db, &token())
        .await
        .expect("store");
    set_cached_expiry(&db, "-1 minutes").await;
    assert!(
        super::github_app_token(&db).await.expect("read").is_none(),
        "expired token must not be reused"
    );
}

#[tokio::test]
async fn github_app_token_store_overwrites_singleton_row() {
    let db = memory_db().await.expect("memory db");
    super::store_github_app_token(&db, &token())
        .await
        .expect("store first");
    let replacement = crate::github_app::InstallationToken {
        token: "ghs_replacement".to_owned(),
        expires_at: "2099-06-01T00:00:00Z".to_owned(),
    };
    super::store_github_app_token(&db, &replacement)
        .await
        .expect("store second");
    let cached = super::github_app_token(&db)
        .await
        .expect("read")
        .expect("token is cached");
    assert_eq!(cached.token, "ghs_replacement");
    assert_eq!(cached.expires_at, "2099-06-01T00:00:00Z");
}

fn human_request(crate_name: &str) -> EnqueueRequest {
    EnqueueRequest {
        source: EnqueueSource::HumanRequest,
        ..request(crate_name, &[])
    }
}

/// The unattended preheat wave re-submits the whole top-N list on
/// every tick. A completed row's artifacts are already in the
/// catalog, so a miss-lane re-request leaves it completed instead of
/// rebuilding the pool on a timer.
#[tokio::test]
async fn a_preheat_re_request_does_not_rebuild_a_completed_task() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("alpha", &[])])
        .await
        .expect("enqueue");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    let id = claimed[0].task_id.clone();
    super::complete(
        &db,
        &claim_settings(),
        &report(&id, &claimed[0].generation_id, 1, true),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete");

    enqueue(
        &db,
        &[EnqueueRequest {
            source: EnqueueSource::CrateUpdate,
            ..request("alpha", &[])
        }],
    )
    .await
    .expect("preheat re-request");

    let row = db
        .query("SELECT status, attempt FROM queue WHERE task_id = ?")
        .bind(id)
        .fetch_optional::<super::AttemptStatusRow>()
        .await
        .expect("row")
        .expect("row exists");
    assert_eq!(row.status, "completed");
    assert_eq!(row.attempt, 1);
    assert!(
        super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")
            .is_empty(),
        "a completed preheat task must not dispatch again"
    );
}

/// Convergence is the other half: an identity whose build failed
/// stays in the queue — the failure report re-queues it behind its
/// backoff — so the coverage the preheat lane asked for is
/// eventually reached without anyone dispatching by hand. The
/// wave's re-submit leaves the retry untouched.
#[tokio::test]
async fn a_preheat_re_request_retries_a_failed_task() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("alpha", &[])])
        .await
        .expect("enqueue");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    let id = claimed[0].task_id.clone();
    super::complete(
        &db,
        &claim_settings(),
        &report(&id, &claimed[0].generation_id, 1, false),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("fail the build");

    enqueue(
        &db,
        &[EnqueueRequest {
            source: EnqueueSource::CrateUpdate,
            ..request("alpha", &[])
        }],
    )
    .await
    .expect("preheat re-request");

    let row = db
        .query("SELECT status, attempt FROM queue WHERE task_id = ?")
        .bind(id)
        .fetch_optional::<super::AttemptStatusRow>()
        .await
        .expect("row")
        .expect("row exists");
    assert_eq!(row.status, "pending");
    assert_eq!(row.attempt, 2);
}

/// A task whose exact identity an artifact publish already covered is
/// retired at claim time — `completed`, never dispatched — and the
/// oracle is asked only about plain crates.io rows.
#[tokio::test]
async fn claim_retires_tasks_the_catalog_already_covers() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request("covered", &[]),
            request("uncovered", &[]),
            EnqueueRequest {
                preserve_lockfile: true,
                ..request("lockfile", &[])
            },
        ],
    )
    .await
    .expect("enqueue");
    let oracle = FixedCoverage {
        covered: BTreeSet::from([semantic_identity("covered")]),
        asked: std::sync::Mutex::new(Vec::new()),
    };
    let settings = SchedulerSettings {
        dispatch: Dispatch::from_max_concurrent_jobs(10),
        dispatch_min_age_minutes: 0,
        ..settings()
    };

    let claimed = super::claim_dispatchable_tasks(&db, &settings, &oracle)
        .await
        .expect("claim");
    let mut claimed_names = claimed
        .iter()
        .map(|task| task.crate_name.as_str())
        .collect::<Vec<_>>();
    claimed_names.sort_unstable();
    assert_eq!(claimed_names, ["lockfile", "uncovered"]);
    assert_eq!(
        oracle.asked.lock().expect("oracle log").as_slice(),
        [semantic_identity("covered"), semantic_identity("uncovered")]
    );
    let status = db
        .query("SELECT status FROM queue WHERE task_id = ?")
        .bind(crate_task_id("covered"))
        .fetch_scalar::<String>()
        .await
        .expect("status");
    assert_eq!(status, "completed");
}

fn crate_task_id(crate_name: &str) -> String {
    task_id_on(crate_name, TARGET)
}

/// Both rows are eligible to claim here: the miss row is aged past the
/// dispatch minimum, the human row is exempt from it — so the only
/// thing deciding order is the lane.
#[tokio::test]
async fn human_task_dispatches_before_older_miss_task() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("missed", &[])])
        .await
        .expect("enqueue miss");
    enqueue(&db, &[human_request("asked")])
        .await
        .expect("enqueue human");
    set_first_requested_at(&db, "missed", PAST_TS).await;

    let claimed = super::claim_dispatchable_tasks(&db, &settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 2);
    assert_eq!(claimed[0].crate_name, "asked");
    assert_eq!(claimed[1].crate_name, "missed");
}

/// A miss-lane task enqueued a second ago would sit out the whole
/// minimum-age window; the same-age human task must be claimable now.
#[tokio::test]
async fn human_task_bypasses_dispatch_min_age() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("missed", &[])])
        .await
        .expect("enqueue miss");
    enqueue(&db, &[human_request("asked")])
        .await
        .expect("enqueue human");

    let settings = SchedulerSettings {
        dispatch_min_age_minutes: 60,
        ..settings()
    };
    let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "asked");
}

#[tokio::test]
async fn human_rerequest_promotes_miss_task() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("asked", &[])])
        .await
        .expect("enqueue miss");
    let status = super::task_status(&db, &crate_task_id("asked"))
        .await
        .expect("task status")
        .expect("row exists");
    assert_eq!(status.lane, stow_types::api::TaskLane::Miss);

    enqueue(&db, &[human_request("asked")])
        .await
        .expect("re-request through human path");
    let status = super::task_status(&db, &crate_task_id("asked"))
        .await
        .expect("task status")
        .expect("row exists");
    assert_eq!(status.lane, stow_types::api::TaskLane::Human);
}

#[tokio::test]
async fn miss_rerequest_never_demotes_human_task() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[human_request("asked")])
        .await
        .expect("enqueue human");
    enqueue(&db, &[request("asked", &[])])
        .await
        .expect("re-request through miss path");

    let status = super::task_status(&db, &crate_task_id("asked"))
        .await
        .expect("task status")
        .expect("row exists");
    assert_eq!(status.lane, stow_types::api::TaskLane::Human);
}

/// A pending human task is eligible now, so with capacity free the
/// alarm must fire immediately instead of at `first_requested_at +
/// min_age` like a miss task would.
#[tokio::test]
async fn pending_human_task_makes_alarm_eligible_now() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[human_request("asked")])
        .await
        .expect("enqueue human");

    let settings = SchedulerSettings {
        dispatch_min_age_minutes: 60,
        ..settings()
    };
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_millis(),
    )
    .expect("epoch millis fits in i64");
    let plan = next_alarm(&db, now_ms, &settings)
        .await
        .expect("next_alarm");
    // Eligible-at-now resolves to `max(eligible, now)`; a miss task
    // this young would instead schedule ~an hour out. Allow a couple of
    // seconds of clock drift between the test capture and SQLite's
    // `datetime('now')`.
    match plan {
        AlarmPlan::At(ms) => {
            assert!(ms <= now_ms + 2_000, "alarm {ms} is not ~now ({now_ms})");
        }
        AlarmPlan::Delete => panic!("pending human task must wake the alarm now"),
    }
}

#[tokio::test]
async fn status_reports_human_pending_separately() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("missed", &[]), human_request("asked")])
        .await
        .expect("enqueue");

    let status = super::status(&db).await.expect("status");
    assert_eq!(status.pending, 2);
    assert_eq!(status.human_pending, 1);
}

/// Position is 1-based in human-lane dispatch order: the older human
/// task is first, the younger one second.
#[tokio::test]
async fn task_status_reports_human_lane_position() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[human_request("first"), human_request("second")])
        .await
        .expect("enqueue");
    set_first_requested_at(&db, "first", PAST_TS).await;

    let first = super::task_status(&db, &crate_task_id("first"))
        .await
        .expect("task status")
        .expect("row exists");
    let second = super::task_status(&db, &crate_task_id("second"))
        .await
        .expect("task status")
        .expect("row exists");
    assert_eq!(first.human_lane_position, Some(1));
    assert_eq!(second.human_lane_position, Some(2));
}

/// Two human tasks in one submit batch share `first_requested_at`,
/// `priority`, and `created_at`, so only the `task_id` tiebreaker can
/// order them — positions must follow ascending task id and match the
/// order `claim_dispatchable_tasks` dispatches in.
#[tokio::test]
async fn human_lane_position_ties_break_on_task_id() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[human_request("zed"), human_request("alpha")])
        .await
        .expect("enqueue");
    // `task_id("alpha") < task_id("zed")` on the crate-name segment —
    // pin every ordering column above it to identical values so
    // task_id is the only key that can decide.
    for name in ["alpha", "zed"] {
        set_first_requested_at(&db, name, PAST_TS).await;
    }
    db.query("UPDATE queue SET created_at = ?")
        .bind(ROW_TS.to_owned())
        .execute()
        .await
        .expect("pin created_at");

    let alpha = super::task_status(&db, &crate_task_id("alpha"))
        .await
        .expect("task status")
        .expect("row exists");
    let zed = super::task_status(&db, &crate_task_id("zed"))
        .await
        .expect("task status")
        .expect("row exists");
    assert_eq!(alpha.human_lane_position, Some(1));
    assert_eq!(zed.human_lane_position, Some(2));

    // The position must equal true dispatch order.
    let claimed = super::claim_dispatchable_tasks(&db, &settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 2);
    assert_eq!(claimed[0].crate_name, "alpha");
    assert_eq!(claimed[1].crate_name, "zed");
}

/// Positions order exactly when `value` sits above the workerd
/// cursor's JS-safe integer range: two human rows whose values
/// differ by 1 — far past 2^53, where a JS-number decode would
/// collapse them to one float — still rank correctly through the
/// persisted TEXT `dispatch_key` (stow#442 I6).
#[tokio::test]
async fn human_lane_position_orders_values_above_js_safe_integer() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[human_request("below"), human_request("above")])
        .await
        .expect("enqueue");
    for (name, priority) in [("below", 1_000_005_i64), ("above", 1_000_006_i64)] {
        db.query("UPDATE queue SET priority = ? WHERE task_id = ?")
            .bind(priority)
            .bind(crate_task_id(name))
            .execute()
            .await
            .expect("set priority");
    }
    super::refresh_dispatch_keys(&db, &[crate_task_id("below"), crate_task_id("above")])
        .await
        .expect("refresh claim order");
    // Guard the premise: the human band puts both rows' stored
    // values above 2^53, the range the JS cursor cannot represent.
    let stored = db
        .query("SELECT value FROM queue WHERE task_id = ?")
        .bind(crate_task_id("below"))
        .fetch_scalar::<i64>()
        .await
        .expect("stored value");
    assert!(stored > (1_i64 << 53));

    let below = super::task_status(&db, &crate_task_id("below"))
        .await
        .expect("task status")
        .expect("row exists");
    let above = super::task_status(&db, &crate_task_id("above"))
        .await
        .expect("task status")
        .expect("row exists");
    assert_eq!(above.human_lane_position, Some(1));
    assert_eq!(below.human_lane_position, Some(2));
}

#[tokio::test]
async fn task_status_omits_position_outside_pending_human_lane() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("missed", &[])])
        .await
        .expect("enqueue");

    let status = super::task_status(&db, &crate_task_id("missed"))
        .await
        .expect("task status")
        .expect("row exists");
    assert_eq!(status.lane, stow_types::api::TaskLane::Miss);
    assert_eq!(status.human_lane_position, None);
    assert!(
        super::task_status(&db, "no-such-task")
            .await
            .expect("task status")
            .is_none(),
        "unknown task id yields None"
    );
}

/// A report for a task the queue holds only applies while the row is
/// in flight under the reported attempt; the completion path can no
/// longer be exercised without a claim.
#[tokio::test]
async fn complete_marks_a_held_task_and_rejects_an_unknown_one() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("alpha", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("alpha", TARGET);
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempt, 1);

    super::complete(
        &db,
        &claim_settings(),
        &super::BuildCompleteReport {
            task_id: id.clone(),
            generation_id: claimed[0].generation_id.clone(),
            attempt: claimed[0].attempt,
            success: true,
            error: None,
            finished_at: None,
            github_run_id: None,
        },
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete a held task");
    let status = db
        .query("SELECT status FROM queue WHERE task_id = ?")
        .bind(id)
        .fetch_scalar::<String>()
        .await
        .expect("status");
    assert_eq!(status, "completed");

    // The DO maps this variant to 404: a report naming a task the
    // queue never held is a client error, not a server failure.
    let error = super::complete(
        &db,
        &claim_settings(),
        &super::BuildCompleteReport {
            task_id: "never-enqueued".to_owned(),
            generation_id: "unknown-generation".to_owned(),
            attempt: 1,
            success: true,
            error: None,
            finished_at: None,
            github_run_id: None,
        },
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect_err("an unknown task must be rejected");
    assert!(matches!(
        error,
        crate::errors::QueueError::UnknownTask(ref task_id)
            if task_id == "never-enqueued"
    ));
}

/// The regression this field exists for: attempt 1's report arriving
/// after the row was resurrected to attempt 2 must not overwrite the
/// new attempt's state — a report that matches no in-flight row is a
/// `StaleCompletion` (409 at the handler), never a silent success.
#[tokio::test]
async fn stale_report_for_a_superseded_attempt_leaves_the_live_row_untouched() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("alpha", &[])])
        .await
        .expect("enqueue");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    let id = claimed[0].task_id.clone();

    super::complete(
        &db,
        &claim_settings(),
        &report(&id, &claimed[0].generation_id, 1, true),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete attempt 1");
    // A human re-request resurrects the completed row as attempt 2,
    // and the resurrected row dispatches again.
    enqueue(&db, &[human_request("alpha")])
        .await
        .expect("re-request");
    let reclaimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("re-claim");
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].attempt, 2);

    let error = super::complete(
        &db,
        &claim_settings(),
        &report(&id, &claimed[0].generation_id, 1, true),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect_err("a report for attempt 1 must not apply to attempt 2");
    assert!(matches!(
        error,
        crate::errors::QueueError::StaleCompletion { .. }
    ));

    let row = db
        .query("SELECT status, attempt FROM queue WHERE task_id = ?")
        .bind(id.clone())
        .fetch_optional::<super::AttemptStatusRow>()
        .await
        .expect("row")
        .expect("row exists");
    assert_eq!(row.attempt, 2);
    assert_eq!(row.status, "dispatched");

    // And the report for the live attempt still completes normally.
    super::complete(
        &db,
        &claim_settings(),
        &report(&id, &reclaimed[0].generation_id, 2, true),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete attempt 2");
    let status = db
        .query("SELECT status FROM queue WHERE task_id = ?")
        .bind(id)
        .fetch_scalar::<String>()
        .await
        .expect("status");
    assert_eq!(status, "completed");
}

/// A second report for the attempt that already applied is a
/// duplicate, not a success: the row is already terminal, so the same
/// stale-completion rejection answers it.
#[tokio::test]
async fn duplicate_report_for_the_current_attempt_conflicts() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("alpha", &[])])
        .await
        .expect("enqueue");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    let id = claimed[0].task_id.clone();

    super::complete(
        &db,
        &claim_settings(),
        &report(&id, &claimed[0].generation_id, 1, true),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete");
    let error = super::complete(
        &db,
        &claim_settings(),
        &report(&id, &claimed[0].generation_id, 1, true),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect_err("a duplicate report must conflict");
    assert!(matches!(
        error,
        crate::errors::QueueError::StaleCompletion { .. }
    ));

    let status = db
        .query("SELECT status FROM queue WHERE task_id = ?")
        .bind(id)
        .fetch_scalar::<String>()
        .await
        .expect("status");
    assert_eq!(status, "completed");
}

/// Mark one crate's semantic identity served by the `(TARGET, RUSTC)`
/// slice — the state `stow-admin index report` produces through
/// `record_published_slice` after `index publish` lands. The rows
/// cover the shapes a native `(TARGET)` consumer's target-side dep
/// edge requires: its own invocation, both kinds.
async fn publish(db: &DurableDb, crate_name: &str) {
    let rows = [UnitKind::Linked, UnitKind::Unlinked]
        .iter()
        .map(|kind| stow_types::api::PublishedSliceRow {
            dependency_identity: dep_identity(crate_name),
            crate_name: crate_name.parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            unit_shape: Some(shape(UnitSide::Target, UnitInvocation::Native, *kind)),
        })
        .collect::<Vec<_>>();
    super::record_published_slice(db, TARGET, RUSTC, None, None, &rows, &[])
        .await
        .expect("record published slice");
}

/// The same, carrying the row's unit shape — what `index report`
/// sends once the publish path registers the builder-recorded shape
/// (`None` is the legacy shapeless row that covers nothing).
async fn publish_shapes(db: &DurableDb, crate_name: &str, target: &str, shapes: &[UnitShape]) {
    let rows = shapes
        .iter()
        .map(|shape| stow_types::api::PublishedSliceRow {
            dependency_identity: dep_identity(crate_name),
            crate_name: crate_name.parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            unit_shape: Some(*shape),
        })
        .collect::<Vec<_>>();
    super::record_published_slice(db, target, RUSTC, None, None, &rows, &[])
        .await
        .expect("record shaped published slice");
}

/// Completed is not servable: a dependency whose build landed but
/// whose slice has not been republished yet must not release its
/// dependent — the dependent's build resolves the dependency from
/// the signed index, and only a publish makes it appear there.
#[tokio::test]
async fn dependent_waits_for_a_completed_dependency_until_it_is_published() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim dep");
    assert_eq!(claimed.len(), 1);
    super::complete(
        &db,
        &claim_settings(),
        &report(
            &claimed[0].task_id,
            &claimed[0].generation_id,
            claimed[0].attempt,
            true,
        ),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete dep");

    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim parent");
    assert!(
        claimed.is_empty(),
        "a completed-but-unpublished dependency must not release its dependent"
    );
    assert_eq!(row_column(&db, "parent", "status").await, "pending");

    publish(&db, "dep").await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim parent after publish");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "parent");
}

/// A failed dependency on its retry backoff keeps its dependents
/// waiting: the failure report re-queues it `pending`, not
/// published, so the gate holds the parent until a build and a
/// publish land.
#[tokio::test]
async fn dependent_waits_while_a_failed_dependency_retries() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim dep");
    super::complete(
        &db,
        &claim_settings(),
        &report(
            &claimed[0].task_id,
            &claimed[0].generation_id,
            claimed[0].attempt,
            false,
        ),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("fail dep");

    // The dep is already `pending` behind its retry backoff —
    // retrying, not terminal — and the parent's submit is a no-op
    // against it.
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    assert_eq!(row_column(&db, "dep", "status").await, "pending");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert!(
        claimed.is_empty(),
        "neither the backoff-gated retry nor its unpublished dependent may claim"
    );
}

/// A dependency that fails for good leaves its dependents settled
/// behind it: reporting `blocked`, naming the failed dependency,
/// and never dispatched — no dispatching the dependent to compile
/// the dependency itself. Retrying the dependency returns the
/// dependent to `pending`, since the dependent's `blocked` is a
/// flag the dep's status flips maintain, not its own verdict.
#[tokio::test]
async fn dependent_settles_blocked_behind_a_terminally_failed_dependency() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim dep");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "dep");
    // The terminal failure: the last permitted attempt fails and
    // the row parks `failed`.
    db.query("UPDATE queue SET attempt = ? WHERE task_id = ?")
        .bind(i64::from(super::MAX_BUILD_ATTEMPTS))
        .bind(claimed[0].task_id.clone())
        .execute()
        .await
        .expect("set attempt to the cap");
    super::complete(
        &db,
        &claim_settings(),
        &report(
            &claimed[0].task_id,
            &claimed[0].generation_id,
            super::MAX_BUILD_ATTEMPTS,
            false,
        ),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("fail dep");
    assert_eq!(row_column(&db, "dep", "status").await, "failed");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim after terminal failure");
    assert!(
        claimed.is_empty(),
        "a terminally failed dependency must leave its dependent undispatched"
    );
    // Stored status stays `pending`; the read paths surface `blocked`
    // with the failed dependency's task id.
    assert_eq!(row_column(&db, "parent", "status").await, "pending");
    let parent = super::task_status(&db, &task_id_with("parent", TARGET, &[dependency("dep")]))
        .await
        .expect("read parent status")
        .expect("parent row");
    assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Blocked);
    assert_eq!(
        parent.blocked_by.as_deref(),
        Some(task_id_on("dep", TARGET).as_str()),
        "the blocked report must name the failed dependency's task id"
    );
    let listed = super::list_tasks(
        &db,
        &filter_selector(stow_types::api::QueueSelector {
            status: Some(stow_types::api::QueueTaskStatus::Blocked),
            ..Default::default()
        }),
    )
    .await
    .expect("list blocked tasks");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].crate_name, "parent");
    assert_eq!(
        listed[0].blocked_by.as_deref(),
        Some(task_id_on("dep", TARGET).as_str())
    );
    assert_eq!(super::status(&db).await.expect("status").blocked, 1);

    // Retrying the dependency returns the dependent to `pending`
    // — nothing to reconcile, the flag refresh just stops firing.
    let affected = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Retry,
        &filter_selector(stow_types::api::QueueSelector {
            status: Some(stow_types::api::QueueTaskStatus::Failed),
            ..Default::default()
        }),
    )
    .await
    .expect("retry dep");
    assert_eq!(affected, 1, "only the failed dep moves");
    assert_eq!(row_column(&db, "dep", "status").await, "pending");
    assert_eq!(row_column(&db, "dep", "CAST(attempt AS TEXT)").await, "1");
    let parent = super::task_status(&db, &task_id_with("parent", TARGET, &[dependency("dep")]))
        .await
        .expect("read parent status after retry")
        .expect("parent row");
    assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Pending);
    assert_eq!(parent.blocked_by, None);
}

/// The owner's persisted gate counters — `(unpublished_deps,
/// deps_met)` as stored, not the status derivation.
async fn gate_counters(db: &DurableDb, crate_name: &str) -> (i64, i64) {
    #[derive(skyzen::FromRow)]
    struct GateCounters {
        unpublished_deps: i64,
        deps_met: i64,
    }
    let counters = db
        .query("SELECT unpublished_deps, deps_met FROM queue                 WHERE crate_name = ? AND target = ?")
        .bind(crate_name.to_owned())
        .bind(TARGET)
        .fetch_one::<GateCounters>()
        .await
        .expect("read gate counters");
    (counters.unpublished_deps, counters.deps_met)
}

/// Each edge's stored `dep_met` flag, keyed by dep crate.
async fn edge_flags(db: &DurableDb) -> Vec<(String, i64)> {
    #[derive(skyzen::FromRow)]
    struct EdgeFlag {
        dep_crate_name: String,
        dep_met: i64,
    }
    let mut flags: Vec<(String, i64)> = db
        .query(
            "SELECT dep_crate_name, dep_met FROM queue_dependencies \
                 ORDER BY dep_crate_name",
        )
        .fetch_all::<EdgeFlag>()
        .await
        .expect("edge flags")
        .into_iter()
        .map(|edge| (edge.dep_crate_name, edge.dep_met))
        .collect();
    flags.sort();
    flags
}

/// The `PublishedSliceRow` set `publish` registers for a crate —
/// both kinds under the target side's native invocation — so a
/// delta report can add or retire exactly those rows.
fn dep_slice_rows(crate_name: &str) -> Vec<stow_types::api::PublishedSliceRow> {
    [UnitKind::Linked, UnitKind::Unlinked]
        .iter()
        .map(|kind| stow_types::api::PublishedSliceRow {
            dependency_identity: dep_identity(crate_name),
            crate_name: crate_name.parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            unit_shape: Some(shape(UnitSide::Target, UnitInvocation::Native, *kind)),
        })
        .collect()
}

/// A mixed dep set lands the slice answer per edge — the same
/// EXISTS the gate used to replay per evaluation, run once at
/// insert — and the owner counts its unmet edges, so `deps_met` is
/// the counter's zero (stow#521).
#[tokio::test]
async fn enqueue_writes_each_edge_s_answer_and_counts_unpublished_deps() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[request("served-dep", &[]), request("absent-dep", &[])],
    )
    .await
    .expect("enqueue deps");
    publish(&db, "served-dep").await;

    enqueue(
        &db,
        &[request(
            "parent",
            &[dependency("served-dep"), dependency("absent-dep")],
        )],
    )
    .await
    .expect("enqueue parent");

    assert_eq!(
        edge_flags(&db).await,
        vec![("absent-dep".to_owned(), 0), ("served-dep".to_owned(), 1),],
        "dep_met is the slice answer at edge-write time"
    );
    assert_eq!(gate_counters(&db, "parent").await, (1, 0));
    assert_eq!(gate_counters(&db, "absent-dep").await, (0, 1));
}

/// A publish delta flips exactly the edges its rows match — the
/// already-met edge does not move — and each owner's counter tracks
/// the flips, so reaching zero releases the pending row to claim.
#[tokio::test]
async fn a_slice_delta_flips_the_matched_edges_and_moves_the_counter() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[request("first-dep", &[]), request("second-dep", &[])],
    )
    .await
    .expect("enqueue deps");
    publish(&db, "first-dep").await;
    enqueue(
        &db,
        &[request(
            "parent",
            &[dependency("first-dep"), dependency("second-dep")],
        )],
    )
    .await
    .expect("enqueue parent");
    assert_eq!(gate_counters(&db, "parent").await, (1, 0));

    // A delta report on the live generation adds only second-dep's
    // rows: the first-dep edge is already met and must not flip.
    super::record_published_slice(
        &db,
        TARGET,
        RUSTC,
        Some(1),
        None,
        &dep_slice_rows("second-dep"),
        &[],
    )
    .await
    .expect("delta publish second-dep");

    assert_eq!(
        edge_flags(&db).await,
        vec![("first-dep".to_owned(), 1), ("second-dep".to_owned(), 1),]
    );
    assert_eq!(gate_counters(&db, "parent").await, (0, 1));
    let claimed = super::claim_dispatchable_tasks(
        &db,
        &SchedulerSettings {
            dispatch: Dispatch::from_max_concurrent_jobs(8),
            ..claim_settings()
        },
        &NoCoverage,
    )
    .await
    .expect("claim after delta");
    assert!(
        claimed.iter().any(|task| task.crate_name == "parent"),
        "an owner whose counter reaches 0 dispatches"
    );
}

/// Membership removal is a delta like any other: retiring a dep's
/// rows flips its matched edges back to unmet and the owner's
/// counter increments — the publish path stays symmetric.
#[tokio::test]
async fn a_slice_delta_retire_flips_the_edges_back_and_increments_the_counter() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    publish(&db, "dep").await;
    assert_eq!(gate_counters(&db, "parent").await, (0, 1));

    // applied_generation is 1 after the first publish; the retire
    // delta reports against it.
    super::record_published_slice(
        &db,
        TARGET,
        RUSTC,
        Some(1),
        None,
        &[],
        &dep_slice_rows("dep"),
    )
    .await
    .expect("delta retire dep");

    assert_eq!(
        edge_flags(&db).await,
        vec![("dep".to_owned(), 0)],
        "a retire flips the matched edge back to unmet"
    );
    assert_eq!(gate_counters(&db, "parent").await, (1, 0));
    let claimed = super::claim_dispatchable_tasks(
        &db,
        &SchedulerSettings {
            dispatch: Dispatch::from_max_concurrent_jobs(8),
            ..claim_settings()
        },
        &NoCoverage,
    )
    .await
    .expect("claim after retire");
    assert!(
        claimed.iter().all(|task| task.crate_name != "parent"),
        "an owner whose counter returns above 0 stops dispatching"
    );
}

async fn fail_dependency_at_attempt(db: &DurableDb, name: &str, attempt: u32) {
    let id = task_id_on(name, TARGET);
    mark_active(db, name, TARGET, "dispatched").await;
    let generation = db
        .query("UPDATE queue SET attempt = ? WHERE task_id = ? RETURNING generation_id")
        .bind(i64::from(attempt))
        .bind(id.clone())
        .fetch_scalar::<String>()
        .await
        .expect("seed dependency failure attempt");
    super::complete(
        db,
        &claim_settings(),
        &report(&id, &generation, attempt, false),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete dependency failure");
}

/// The three-dep parent shape `fatal_blocker`/`net_zero` enqueue.
fn parent_deps() -> Vec<EnqueueRequest> {
    vec![
        dependency("fatal-dep"),
        dependency("dep-a"),
        dependency("dep-b"),
    ]
}

#[tokio::test]
async fn net_zero_slice_flips_refresh_blocked_and_replays_preserve_counters() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[request("failed-dep", &[]), request("other-dep", &[])],
    )
    .await
    .expect("enqueue deps");
    publish(&db, "other-dep").await;
    enqueue(
        &db,
        &[request(
            "parent",
            &[dependency("failed-dep"), dependency("other-dep")],
        )],
    )
    .await
    .expect("enqueue parent");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim failed dependency");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "failed-dep");
    fail_dependency_at_attempt(&db, "failed-dep", super::MAX_BUILD_ATTEMPTS).await;
    assert_eq!(gate_counters(&db, "parent").await, (1, 0));
    assert_eq!(row_column(&db, "failed-dep", "status").await, "failed");
    assert_eq!(
        edge_flags(&db).await,
        vec![("failed-dep".to_owned(), 0), ("other-dep".to_owned(), 1),]
    );
    let parent = super::task_status(
        &db,
        &task_id_with(
            "parent",
            TARGET,
            &[dependency("failed-dep"), dependency("other-dep")],
        ),
    )
    .await
    .expect("read parent status")
    .expect("parent row");
    assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Blocked);
    assert_eq!(super::status(&db).await.expect("status").blocked, 1);

    // Several changed shapes match each edge, but each edge flips
    // only once. The owner's counter is unchanged while blocked
    // clears: the remaining unmet edge names a non-failed dep.
    for base in [1, 2] {
        super::record_published_slice(
            &db,
            TARGET,
            RUSTC,
            Some(base),
            None,
            &dep_slice_rows("failed-dep"),
            &dep_slice_rows("other-dep"),
        )
        .await
        .expect("swap or replay slice membership");
        assert_eq!(gate_counters(&db, "parent").await, (1, 0));
        assert_eq!(super::status(&db).await.expect("status").blocked, 0);
    }
    publish(&db, "other-dep").await;
    assert_eq!(gate_counters(&db, "parent").await, (1, 0));
    assert_eq!(super::status(&db).await.expect("status").blocked, 1);
}

#[tokio::test]
async fn fatal_blocker_clears_and_reappears_across_net_counter_flips() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request("fatal-dep", &[]),
            request("dep-a", &[]),
            request("dep-b", &[]),
        ],
    )
    .await
    .expect("enqueue dependencies");
    let mut initial_rows = dep_slice_rows("dep-a");
    initial_rows.extend(dep_slice_rows("dep-b"));
    super::record_published_slice(&db, TARGET, RUSTC, None, None, &initial_rows, &[])
        .await
        .expect("publish nonfatal dependencies");
    enqueue(
        &db,
        &[request(
            "parent",
            &[
                dependency("fatal-dep"),
                dependency("dep-a"),
                dependency("dep-b"),
            ],
        )],
    )
    .await
    .expect("enqueue parent");
    mark_active(&db, "dep-a", TARGET, "completed").await;
    mark_active(&db, "dep-b", TARGET, "completed").await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim fatal dependency");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "fatal-dep");
    fail_dependency_at_attempt(&db, "fatal-dep", super::MAX_BUILD_ATTEMPTS).await;
    assert_eq!(gate_counters(&db, "parent").await, (1, 0));
    assert_parent_status(
        &db,
        stow_types::api::QueueTaskStatus::Blocked,
        &parent_deps(),
    )
    .await;

    let mut retired = dep_slice_rows("dep-a");
    retired.extend(dep_slice_rows("dep-b"));
    super::record_published_slice(
        &db,
        TARGET,
        RUSTC,
        Some(1),
        None,
        &dep_slice_rows("fatal-dep"),
        &retired,
    )
    .await
    .expect("clear fatal and retire two nonfatal deps");
    assert_eq!(gate_counters(&db, "parent").await, (2, 0));
    assert_parent_status(
        &db,
        stow_types::api::QueueTaskStatus::Pending,
        &parent_deps(),
    )
    .await;

    super::record_published_slice(
        &db,
        TARGET,
        RUSTC,
        Some(2),
        None,
        &retired,
        &dep_slice_rows("fatal-dep"),
    )
    .await
    .expect("reintroduce fatal blocker and serve nonfatal deps");
    assert_eq!(gate_counters(&db, "parent").await, (1, 0));
    assert_parent_status(
        &db,
        stow_types::api::QueueTaskStatus::Blocked,
        &parent_deps(),
    )
    .await;

    super::record_published_slice(
        &db,
        TARGET,
        RUSTC,
        Some(3),
        None,
        &[],
        &dep_slice_rows("dep-a"),
    )
    .await
    .expect("retire a nonfatal dependency while fatal remains unmet");
    assert_eq!(gate_counters(&db, "parent").await, (2, 0));
    assert_parent_status(
        &db,
        stow_types::api::QueueTaskStatus::Blocked,
        &parent_deps(),
    )
    .await;
}

/// The counter stays live on non-pending rows: an edge flip against
/// a claimed owner still moves `unpublished_deps`, so the pending
/// transition's cheap re-derivation can never disagree with the
/// stored count.
#[tokio::test]
async fn the_counter_tracks_flips_on_a_claimed_owner_too() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    mark_active(&db, "parent", TARGET, "dispatched").await;
    assert_eq!(gate_counters(&db, "parent").await, (1, 0));

    publish(&db, "dep").await;

    assert_eq!(
        gate_counters(&db, "parent").await,
        (0, 1),
        "a dispatched owner's counter still moves with the delta"
    );
}

/// A failed dependency whose identity the published slice already
/// serves holds nothing back: the dependent still claims, so it
/// reports `pending`, never `blocked`. Only an unmet edge blocks.
#[tokio::test]
async fn dependent_is_not_blocked_by_a_failed_dependency_the_slice_already_serves() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    publish(&db, "dep").await;

    // The dependency's row is failed and republished — an operator
    // re-ran it after the slice went live and it failed again.
    mark_active(&db, "dep", TARGET, "failed").await;
    let parent = super::task_status(&db, &task_id_with("parent", TARGET, &[dependency("dep")]))
        .await
        .expect("read parent status")
        .expect("parent row");
    assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Pending);
    assert_eq!(parent.blocked_by, None);
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim parent");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "parent");
}

/// The gate releases when the dependency is later built and its
/// slice republished — a terminal failure is a settlement, not a
/// deadlock.
#[tokio::test]
async fn dependent_releases_when_the_dependency_later_succeeds_and_is_published() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim dep");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "dep");
    fail_dependency_at_attempt(&db, "dep", super::MAX_BUILD_ATTEMPTS).await;
    assert_eq!(gate_counters(&db, "parent").await, (1, 0));
    assert_eq!(super::status(&db).await.expect("status").blocked, 1);

    // An operator starts a fresh retry cycle; even after success,
    // the dependent still waits for the slice that serves it.
    super::apply_mutation(
        &db,
        &claim_settings(),
        super::QueueMutation::Retry,
        &stow_types::api::QueueSelector {
            task_ids: vec![claimed[0].task_id.clone()],
            ..Default::default()
        },
    )
    .await
    .expect("retry terminal dependency");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim dep retry");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "dep");
    super::complete(
        &db,
        &claim_settings(),
        &report(
            &claimed[0].task_id,
            &claimed[0].generation_id,
            claimed[0].attempt,
            true,
        ),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete dep retry");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim before publish");
    assert!(claimed.is_empty(), "completed is still not servable");

    publish(&db, "dep").await;
    assert_eq!(
        gate_counters(&db, "parent").await,
        (0, 1),
        "publishing the only unmet edge reaches the counter-zero fast path"
    );
    assert_eq!(super::status(&db).await.expect("status").blocked, 0);
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim parent after publish");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "parent");
}

/// A republished slice replaces membership wholesale: an identity
/// the new report no longer carries must not keep the gate open.
#[tokio::test]
async fn republishing_a_slice_replaces_its_membership() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    enqueue(&db, &[request("later", &[dependency("other")])])
        .await
        .expect("enqueue later");
    publish(&db, "dep").await;

    // A later report without "dep" shrinks the slice: the edge's
    // record must track the latest publish, never the union.
    publish(&db, "other").await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim after shrink");
    assert_eq!(claimed.len(), 1);
    assert_eq!(
        claimed[0].crate_name, "later",
        "an identity absent from the latest report must hold its dependents, \
             and one it still serves must release"
    );
}

/// A `--target` dependent's host-side dep edge is served by the
/// `--target` host shape alone: the slice's linked `debuginfo = 2`
/// row releases it, while a slice holding only the native shape
/// (`debuginfo = 1`) — what a host node's native-spelling run
/// publishes — does not (stow#349).
#[tokio::test]
async fn cross_dependent_releases_on_the_target_shape_of_a_host_dep() {
    let db = memory_db().await.expect("memory db");
    let host_dep = host_dependency_on("wasm32-unknown-unknown", "heck");
    enqueue(
        &db,
        &[request_on(
            "consumer",
            "wasm32-unknown-unknown",
            &[host_dep],
        )],
    )
    .await
    .expect("enqueue consumer");

    publish_shapes(
        &db,
        "heck",
        TARGET,
        &[
            shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Linked),
            shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Unlinked),
        ],
    )
    .await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim with only the native shape");
    assert!(
        claimed.is_empty(),
        "the native host shape alone must not serve a `--target` consumer's host dep"
    );

    publish_shapes(
        &db,
        "heck",
        TARGET,
        &[
            shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Linked),
            shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Unlinked),
        ],
    )
    .await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim with the target shape");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "consumer");
}

/// A native dependent's host-side dep edge needs the native host
/// shape (`debuginfo = 1`): the `--target` host shape it also
/// carries does not release it — the exact mis-service the snafu-
/// derive failure reported (stow#349).
#[tokio::test]
async fn native_dependent_needs_the_native_shape_of_a_host_dep() {
    let db = memory_db().await.expect("memory db");
    let host_dep = host_dependency_on(TARGET, "heck");
    enqueue(&db, &[request("consumer", &[host_dep])])
        .await
        .expect("enqueue consumer");

    publish_shapes(
        &db,
        "heck",
        TARGET,
        &[
            shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Linked),
            shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Unlinked),
        ],
    )
    .await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim with only the target shape");
    assert!(
        claimed.is_empty(),
        "the `--target` host shape must not serve a native consumer's host dep"
    );

    publish_shapes(
        &db,
        "heck",
        TARGET,
        &[
            shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Linked),
            shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Unlinked),
        ],
    )
    .await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim with the native shape");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "consumer");
}

/// A host-side dependent's own build runs both invocation spellings,
/// so its host-side dep edge needs both host shapes: a slice
/// missing either leaves the dependent held.
#[tokio::test]
async fn a_host_side_dependent_needs_both_shapes_of_a_host_dep() {
    let db = memory_db().await.expect("memory db");
    let host_dep = host_dependency_on(TARGET, "heck");
    let mut owner = request("proc-macro-crate", &[host_dep]);
    owner.host_side = true;
    enqueue(&db, &[owner])
        .await
        .expect("enqueue host-side owner");

    publish_shapes(
        &db,
        "heck",
        TARGET,
        &[
            shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Linked),
            shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Unlinked),
        ],
    )
    .await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim with one shape");
    assert!(
        claimed.is_empty(),
        "one host shape must not serve a dependent that builds under both invocations"
    );

    publish_shapes(
        &db,
        "heck",
        TARGET,
        &[
            shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Linked),
            shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Unlinked),
            shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Linked),
            shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Unlinked),
        ],
    )
    .await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim with both shapes");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "proc-macro-crate");
}

/// A real slice is every built node of a `(target, rustc)` pair —
/// production reports run into the thousands — so a large report
/// must record whole, partial tail included.
#[tokio::test]
async fn a_larger_slice_reports_whole() {
    const REPORT_ROWS: usize = 3_500;
    let db = memory_db().await.expect("memory db");
    let rows = (0..REPORT_ROWS)
        .flat_map(|index| {
            [UnitKind::Linked, UnitKind::Unlinked].map(|kind| stow_types::api::PublishedSliceRow {
                dependency_identity: dep_identity(&format!("crate-{index}")),
                crate_name: format!("crate-{index}").parse().expect("valid crate name"),
                version: VERSION.parse().expect("valid semver"),
                features_json: FeaturesJson::default(),
                unit_shape: Some(shape(UnitSide::Target, UnitInvocation::Native, kind)),
            })
        })
        .collect::<Vec<_>>();
    super::record_published_slice(&db, TARGET, RUSTC, None, None, &rows, &[])
        .await
        .expect("record wide slice");

    let last = format!("crate-{}", REPORT_ROWS - 1);
    enqueue(&db, &[request("parent", &[dependency(&last)])])
        .await
        .expect("enqueue parent");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim parent");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "parent");
}

/// A report that dies after inserting its rows but before flipping
/// `published_slices.generation` leaves orphans at a generation no
/// live pointer references. The next report must not inherit them:
/// `ON CONFLICT DO NOTHING` would otherwise keep the leftover rows
/// inside the generation it reuses, and the live set would silently
/// include a crate the report never named.
#[tokio::test]
async fn a_crashed_reports_orphans_cannot_leak_into_the_next_report() {
    let db = memory_db().await.expect("memory db");
    publish(&db, "dep").await;

    // Simulate a crashed second report: rows land at a generation
    // above the committed one, then the writer dies before the flip.
    db.query(
        "INSERT INTO published_slice_rows \
             (target, rustc_version, generation, crate_name, version, features_json) \
             VALUES (?, ?, 2, 'stale', '1.0.0', '[]')",
    )
    .bind(TARGET.to_owned())
    .bind(RUSTC.to_owned())
    .execute()
    .await
    .expect("orphan crashed-report rows");

    // The real report publishes only "dep" — the orphaned "stale"
    // row must not survive into the live set.
    publish(&db, "dep").await;
    let live = db
        .query(
            "SELECT count(*) AS count FROM published_slice_rows p \
                 JOIN published_slices s \
                   ON s.target = p.target AND s.rustc_version = p.rustc_version \
                  AND s.generation = p.generation \
                 WHERE p.target = ? AND p.rustc_version = ?",
        )
        .bind(TARGET.to_owned())
        .bind(RUSTC.to_owned())
        .fetch_scalar::<i64>()
        .await
        .expect("count live slice rows");
    assert_eq!(
        live, 2,
        "the live set is exactly the second report's rows, both shapes"
    );

    enqueue(&db, &[request("stale-dep", &[dependency("stale")])])
        .await
        .expect("enqueue stale dependent");
    enqueue(&db, &[request("fresh-dep", &[dependency("dep")])])
        .await
        .expect("enqueue fresh dependent");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim after republish");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "fresh-dep");
}

/// An edge the migration could not backfill keeps `''` for the
/// dependency's semantic identity — it can never resolve to a
/// published row, so the dependent is blocked rather than pending
/// forever, and the report says why.
#[tokio::test]
async fn an_unresolvable_dependency_edge_reports_blocked_with_unknown_identity() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    db.query("UPDATE queue_dependencies SET dep_crate_name = '' WHERE task_id = ?")
        .bind(task_id_with("parent", TARGET, &[dependency("dep")]))
        .execute()
        .await
        .expect("erase dep identity");
    // The persisted `blocked` flag answers at write time: the only
    // production writer of an unresolved identity is the dev-era
    // migration backfill, which recomputes the flag itself — replay
    // that owner refresh here.
    super::refresh_deps_met_tasks(&db, &[task_id_with("parent", TARGET, &[dependency("dep")])])
        .await
        .expect("recompute blocked after identity erase");

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim with unknown edge");
    assert!(claimed.is_empty());
    let parent = super::task_status(&db, &task_id_with("parent", TARGET, &[dependency("dep")]))
        .await
        .expect("read parent status")
        .expect("parent row");
    assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Blocked);
    assert_eq!(
        parent.blocked_by.as_deref(),
        Some("unknown dependency identity")
    );
    assert_eq!(super::status(&db).await.expect("status").blocked, 1);
}

fn report(
    task_id: &str,
    generation_id: &str,
    attempt: u32,
    success: bool,
) -> super::BuildCompleteReport {
    super::BuildCompleteReport {
        task_id: task_id.to_owned(),
        generation_id: generation_id.to_owned(),
        attempt,
        success,
        error: None,
        finished_at: None,
        github_run_id: None,
    }
}

fn report_with_run(
    task_id: &str,
    success: bool,
    github_run_id: &str,
) -> stow_types::api::WorkflowRunComplete {
    stow_types::api::WorkflowRunComplete {
        task_id: task_id.to_owned(),
        success,
        error: (!success).then(|| "build failed".to_owned()),
        github_run_id: Some(github_run_id.to_owned()),
    }
}

#[derive(skyzen::FromRow)]
struct AttemptEvidenceRow {
    generation_id: String,
    attempt: i64,
    github_run_id: Option<String>,
}

async fn seed_failed_retry_cycle(db: &DurableDb, id: &str, cycle: &str) {
    for attempt in 1..=4 {
        mark_active(db, "flaky", TARGET, "dispatched").await;
        db.query(
            "UPDATE queue SET attempt = ?, generation_id = lower(hex(randomblob(16))) \
                 WHERE task_id = ?",
        )
        .bind(i64::from(attempt))
        .bind(id.to_owned())
        .execute()
        .await
        .expect("seed retry-cycle attempt");
        super::complete(
            db,
            &settings(),
            &super::BuildCompleteReport {
                task_id: id.to_owned(),
                generation_id: db
                    .query("SELECT generation_id FROM queue WHERE task_id = ?")
                    .bind(id.to_owned())
                    .fetch_scalar::<String>()
                    .await
                    .expect("retry-cycle generation"),
                attempt,
                success: false,
                error: Some(format!("cycle-{cycle}-{attempt}")),
                github_run_id: Some(format!("run-{cycle}-{attempt}")),
                finished_at: None,
            },
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("record retry-cycle failure");
        if attempt == 1 {
            let short_backoff = db
                .query(
                    "SELECT CASE WHEN not_before <= datetime('now', '+3 minutes') \
                         THEN 1 ELSE 0 END FROM queue WHERE task_id = ?",
                )
                .bind(id.to_owned())
                .fetch_scalar::<i64>()
                .await
                .expect("read second-cycle backoff");
            assert_eq!(
                short_backoff, 1,
                "retry cycle backoff must restart at 2 minutes"
            );
        }
        db.query("UPDATE queue SET not_before = '1970-01-01 00:00:00', wake_at = '1970-01-01 00:00:00' WHERE task_id = ?")
                .bind(id.to_owned())
                .execute()
                .await
                .expect("open next retry-cycle attempt");
    }
}

#[tokio::test]
async fn two_retry_cycles_keep_distinct_failure_evidence() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("flaky", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("flaky", TARGET);

    seed_failed_retry_cycle(&db, &id, "a").await;

    super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Retry,
        &ids_selector(std::slice::from_ref(&id)),
    )
    .await
    .expect("operator retry");
    assert_eq!(
        row_column(&db, "flaky", "CAST(attempt AS TEXT)").await,
        "1",
        "operator retry resets the visible failure cycle to attempt 1"
    );
    seed_failed_retry_cycle(&db, &id, "b").await;

    let evidence = db
        .query(
            "SELECT generation_id, attempt, github_run_id FROM attempt_outcomes_v2 \
                 WHERE task_id = ? ORDER BY github_run_id",
        )
        .bind(id)
        .fetch_all::<AttemptEvidenceRow>()
        .await
        .expect("read failure evidence");
    assert_eq!(evidence.len(), 8);
    assert_eq!(evidence[0].attempt, 1);
    assert_eq!(evidence[3].attempt, 4);
    assert_eq!(evidence[4].attempt, 1);
    assert_eq!(evidence[7].attempt, 4);
    assert_eq!(evidence[0].github_run_id.as_deref(), Some("run-a-1"));
    assert_eq!(evidence[4].github_run_id.as_deref(), Some("run-b-1"));
    let mut generation_ids = evidence
        .iter()
        .map(|row| row.generation_id.clone())
        .collect::<Vec<_>>();
    generation_ids.sort();
    generation_ids.dedup();
    assert_eq!(
        generation_ids.len(),
        8,
        "each failure has a distinct generation"
    );
}

#[tokio::test]
async fn delayed_old_run_cannot_complete_new_bound_generation() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("flaky", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("flaky", TARGET);
    let first = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim A")[0]
        .clone();
    super::bind_dispatch_run(&db, &id, &first.generation_id, "run-a")
        .await
        .expect("bind A");
    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, false, "run-a"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete A");
    db.query("UPDATE queue SET not_before = '1970-01-01 00:00:00', wake_at = '1970-01-01 00:00:00' WHERE task_id = ?")
            .bind(id.clone())
            .execute()
            .await
            .expect("open retry");
    let second = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim B")[0]
        .clone();
    super::bind_dispatch_run(&db, &id, &second.generation_id, "run-b")
        .await
        .expect("bind B");
    let stale = super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, false, "run-a"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect_err("old A must conflict with B");
    assert!(matches!(stale, QueueError::StaleCompletion { .. }));
    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, true, "run-b"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete B");
    assert_eq!(row_column(&db, "flaky", "status").await, "completed");
}

#[tokio::test]
async fn early_completion_is_acknowledged_then_applied_after_exact_binding() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("early", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("early", TARGET);
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim")[0]
        .clone();
    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, false, "run-early"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("early report is durably acknowledged");
    assert_eq!(row_column(&db, "early", "status").await, "dispatched");
    assert_eq!(pending_completion_count(&db).await, 1);
    super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-early")
        .await
        .expect("bind exact run");
    super::reconcile_pending_completions(&db, &settings(), TEST_WINDOW_MINUTES)
        .await
        .expect("apply pending exact run");
    assert_eq!(row_column(&db, "early", "status").await, "pending");
    assert_eq!(pending_completion_count(&db).await, 0);
}

#[tokio::test]
async fn duplicate_early_delivery_is_idempotent_and_replay_conflicts_after_apply() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("replay", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("replay", TARGET);
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim")[0]
        .clone();
    let event = report_with_run(&id, true, "run-replay");
    super::complete_run(&db, &settings(), &event, TEST_WINDOW_MINUTES)
        .await
        .expect("first early delivery");
    super::complete_run(&db, &settings(), &event, TEST_WINDOW_MINUTES)
        .await
        .expect("duplicate early delivery");
    assert_eq!(pending_completion_count(&db).await, 1);
    super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-replay")
        .await
        .expect("bind replay run");
    super::reconcile_pending_completions(&db, &settings(), TEST_WINDOW_MINUTES)
        .await
        .expect("apply replay run");
    let replay = super::complete_run(&db, &settings(), &event, TEST_WINDOW_MINUTES)
        .await
        .expect_err("replayed applied delivery conflicts");
    assert!(matches!(replay, QueueError::StaleCompletion { .. }));
    assert_eq!(pending_completion_count(&db).await, 0);
}

#[tokio::test]
async fn response_loss_reclaim_drops_unbound_event_before_new_claim() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("lost", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("lost", TARGET);
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim")[0]
        .clone();
    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, false, "run-lost"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("store response-loss event");
    super::mark_dispatch_failed(
        &db,
        &settings(),
        &id,
        &claimed.generation_id,
        "response lost",
    )
    .await
    .expect("reclaim response-loss generation");
    assert_eq!(pending_completion_count(&db).await, 0);
    db.query("UPDATE queue SET not_before = '1970-01-01 00:00:00', wake_at = '1970-01-01 00:00:00' WHERE task_id = ?")
            .bind(id.clone())
            .execute()
            .await
            .expect("open replacement dispatch");
    let replacement = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim replacement")[0]
        .clone();
    assert_eq!(replacement.attempt, claimed.attempt);
    super::bind_dispatch_run(&db, &id, &replacement.generation_id, "run-new")
        .await
        .expect("bind replacement");
    let stale = super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, false, "run-lost"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect_err("orphaned response-loss run is stale");
    assert!(matches!(stale, QueueError::StaleCompletion { .. }));
}

#[tokio::test]
async fn late_dispatch_failure_cannot_overwrite_cancelled_or_retried_generation() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("fenced", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("fenced", TARGET);
    let first = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim A")[0]
        .clone();
    super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Cancel,
        &ids_selector(std::slice::from_ref(&id)),
    )
    .await
    .expect("cancel A");
    super::mark_dispatch_failed(
        &db,
        &settings(),
        &id,
        &first.generation_id,
        "late A failure",
    )
    .await
    .expect("fence late A failure after cancel");
    assert_eq!(row_column(&db, "fenced", "status").await, "failed");

    super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Retry,
        &ids_selector(std::slice::from_ref(&id)),
    )
    .await
    .expect("retry for B");
    let second = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim B")[0]
        .clone();
    assert_eq!(second.attempt, 1);
    assert_ne!(second.generation_id, first.generation_id);

    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, true, "run-b"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("persist early B completion");
    assert_eq!(pending_completion_count(&db).await, 1);
    super::bind_dispatch_run(&db, &id, &second.generation_id, "run-b")
        .await
        .expect("bind B");

    super::mark_dispatch_failed(
        &db,
        &settings(),
        &id,
        &first.generation_id,
        "late A failure",
    )
    .await
    .expect("fence late A failure after retry");
    assert_eq!(row_column(&db, "fenced", "status").await, "dispatched");
    assert_eq!(row_column(&db, "fenced", "github_run_id").await, "run-b");
    assert_eq!(pending_completion_count(&db).await, 1);

    super::reconcile_pending_completions(&db, &settings(), TEST_WINDOW_MINUTES)
        .await
        .expect("apply B completion");
    assert_eq!(row_column(&db, "fenced", "status").await, "completed");
    assert_eq!(pending_completion_count(&db).await, 0);
}

#[tokio::test]
async fn purge_recreate_keeps_failure_evidence_under_new_generation() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("purged", &[])])
        .await
        .expect("enqueue A");
    let id = task_id_on("purged", TARGET);
    let first = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim A")[0]
        .clone();
    db.query("UPDATE queue SET attempt = 4 WHERE task_id = ?")
        .bind(id.clone())
        .execute()
        .await
        .expect("seed terminal attempt");
    super::complete(
        &db,
        &settings(),
        &super::BuildCompleteReport {
            task_id: id.clone(),
            generation_id: first.generation_id.clone(),
            attempt: 4,
            success: false,
            error: Some("cycle A".to_owned()),
            finished_at: None,
            github_run_id: Some("run-a".to_owned()),
        },
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("record terminal A");

    super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Purge,
        &ids_selector(std::slice::from_ref(&id)),
    )
    .await
    .expect("purge A");
    enqueue(&db, &[request("purged", &[])])
        .await
        .expect("enqueue B");
    let second = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim B")[0]
        .clone();
    super::complete(
        &db,
        &settings(),
        &super::BuildCompleteReport {
            task_id: id.clone(),
            generation_id: second.generation_id.clone(),
            attempt: second.attempt,
            success: false,
            error: Some("cycle B".to_owned()),
            finished_at: None,
            github_run_id: Some("run-b".to_owned()),
        },
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("record B");

    let rows = db
        .query(
            "SELECT generation_id, attempt, github_run_id FROM attempt_outcomes_v2 \
                 WHERE task_id = ? ORDER BY finished_at, rowid",
        )
        .bind(id)
        .fetch_all::<AttemptEvidenceRow>()
        .await
        .expect("read preserved evidence");
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].generation_id, rows[1].generation_id);
    assert_eq!(rows[0].attempt, 4);
    assert_eq!(rows[1].attempt, 1);
}

#[tokio::test]
async fn late_failure_cannot_match_purged_recreated_generation() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("recreated", &[])])
        .await
        .expect("enqueue A");
    let id = task_id_on("recreated", TARGET);
    let first = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim A")[0]
        .clone();
    assert_eq!(
        row_column(&db, "recreated", "generation_id").await,
        first.generation_id
    );

    super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Cancel,
        &ids_selector(std::slice::from_ref(&id)),
    )
    .await
    .expect("cancel A");
    super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Purge,
        &ids_selector(std::slice::from_ref(&id)),
    )
    .await
    .expect("purge A");
    enqueue(&db, &[request("recreated", &[])])
        .await
        .expect("enqueue B");
    let second = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim B")[0]
        .clone();
    assert_ne!(first.generation_id, second.generation_id);
    assert_eq!(
        row_column(&db, "recreated", "generation_id").await,
        second.generation_id
    );

    super::mark_dispatch_failed(&db, &settings(), &id, &first.generation_id, "late A")
        .await
        .expect("fence old failure");
    assert_eq!(row_column(&db, "recreated", "status").await, "dispatched");
    assert_eq!(
        row_column(&db, "recreated", "generation_id").await,
        second.generation_id
    );
}

#[tokio::test]
async fn binding_clears_orphan_pending_run_before_normal_completion() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("orphan", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("orphan", TARGET);
    let first = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim A")[0]
        .clone();
    super::mark_dispatch_failed(&db, &settings(), &id, &first.generation_id, "response lost")
        .await
        .expect("reclaim A");
    db.query("UPDATE queue SET not_before = '1970-01-01 00:00:00', wake_at = '1970-01-01 00:00:00' WHERE task_id = ?")
            .bind(id.clone())
            .execute()
            .await
            .expect("open B");
    let second = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim B")[0]
        .clone();
    assert_eq!(second.attempt, first.attempt);
    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, false, "run-x"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("persist orphan X");
    assert_eq!(pending_completion_count(&db).await, 1);
    super::bind_dispatch_run(&db, &id, &second.generation_id, "run-y")
        .await
        .expect("bind Y");
    assert_eq!(pending_completion_count(&db).await, 0);
    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, true, "run-y"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete Y");
    assert_eq!(row_column(&db, "orphan", "status").await, "completed");
}

#[tokio::test]
async fn persisted_bound_pending_event_recovers_after_restart() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("restart", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("restart", TARGET);
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim")[0]
        .clone();
    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, false, "run-restart"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("persist pending event");
    super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-restart")
        .await
        .expect("persist binding");
    super::reconcile_pending_completions(&db, &settings(), TEST_WINDOW_MINUTES)
        .await
        .expect("restart recovery");
    assert_eq!(row_column(&db, "restart", "status").await, "pending");
    assert_eq!(pending_completion_count(&db).await, 0);
}

async fn pending_completion_count(db: &DurableDb) -> i64 {
    db.query("SELECT count(*) FROM pending_run_completions")
        .fetch_scalar::<i64>()
        .await
        .expect("pending completion count")
}

/// A `pending` count at or above `max_queue_pending` turns miss-lane
/// submits away; human-lane and trusted submits still get in.
#[tokio::test]
async fn full_queue_refuses_miss_lane_but_not_human_or_trusted() {
    let db = memory_db().await.expect("memory db");
    let cap_settings = SchedulerSettings {
        max_queue_pending: 2,
        ..settings()
    };
    super::enqueue(
        &db,
        &[request("one", &[]), request("two", &[])],
        &cap_settings,
    )
    .await
    .expect("enqueue up to the cap");

    let error = super::enqueue(&db, &[request("three", &[])], &cap_settings)
        .await
        .expect_err("a miss-lane submit over a full queue must be refused");
    assert!(matches!(
        error,
        QueueError::QueueFull { pending: 2, cap: 2 }
    ));

    // Human-lane work is exempt from the depth cap.
    super::enqueue(&db, &[human_request("asked")], &cap_settings)
        .await
        .expect("human-lane enqueue bypasses the pending cap");
    // And so is a trusted (repo-writer) submit of miss-lane work.
    super::enqueue_trusted(&db, &[request("four", &[])], &cap_settings)
        .await
        .expect("trusted submit bypasses the pending cap");
    assert_eq!(super::status(&db).await.expect("status").pending, 4);
}

#[tokio::test]
async fn human_daily_budget_refuses_the_submit_that_would_exceed_it() {
    let db = memory_db().await.expect("memory db");
    let budget_settings = SchedulerSettings {
        human_daily_task_budget: 3,
        ..settings()
    };
    super::enqueue(
        &db,
        &[human_request("one"), human_request("two")],
        &budget_settings,
    )
    .await
    .expect("first two human tasks fit the budget");

    // Two more would take the day to 4 > 3: refused, and the charge
    // is not recorded — a retry of a one-task submit still fits.
    let error = super::enqueue(
        &db,
        &[human_request("three"), human_request("four")],
        &budget_settings,
    )
    .await
    .expect_err("the submit crossing the budget must be refused");
    assert!(matches!(
        error,
        QueueError::HumanDailyBudgetExhausted {
            attempted: 2,
            budget: 3
        }
    ));
    super::enqueue(&db, &[human_request("three")], &budget_settings)
        .await
        .expect("a smaller submit still fits the remaining budget");

    // Miss-lane work never spends the human budget.
    super::enqueue(&db, &[request("missed", &[])], &budget_settings)
        .await
        .expect("miss-lane enqueue is not budget-gated");
    // …and a submit bigger than the whole budget fails without
    // touching the counter.
    let error = super::enqueue(
        &db,
        &[
            human_request("x"),
            human_request("y"),
            human_request("z"),
            human_request("w"),
        ],
        &budget_settings,
    )
    .await
    .expect_err("a submit over the whole budget can never fit");
    assert!(matches!(
        error,
        QueueError::HumanDailyBudgetExhausted { .. }
    ));
}

/// `tasks_status` must surface `preserve_lockfile`: it is the flag
/// that says whether the task's dependency closure is reproducible
/// from crates.io, and every status consumer reads it off this row.
#[tokio::test]
async fn tasks_status_surfaces_lockfile() {
    let db = memory_db().await.expect("memory db");
    let mut locked = request("locked", &[]);
    locked.preserve_lockfile = true;
    enqueue(&db, &[request("plain", &[]), locked])
        .await
        .expect("enqueue");

    let statuses = super::tasks_status(
        &db,
        &[task_id_on("plain", TARGET), task_id_on("locked", TARGET)],
    )
    .await
    .expect("tasks status");

    assert_eq!(statuses.len(), 2);
    let (plain, locked) = (&statuses[0], &statuses[1]);
    assert!(!plain.preserve_lockfile);
    assert!(!plain.preserve_lockfile);
    assert!(locked.preserve_lockfile);
    assert!(locked.preserve_lockfile);
}

// ===== Admin operations: list, mutation domains, status =====

/// A `QueueSelector` of explicit task ids.
fn ids_selector(ids: &[String]) -> stow_types::api::QueueSelector {
    stow_types::api::QueueSelector {
        task_ids: ids.to_vec(),
        ..Default::default()
    }
}

/// A `QueueSelector` of pure predicates, with no explicit ids.
fn filter_selector(selector: stow_types::api::QueueSelector) -> stow_types::api::QueueSelector {
    stow_types::api::QueueSelector {
        task_ids: Vec::new(),
        ..selector
    }
}

/// One column of one queue row, for post-mutation assertions.
async fn row_column(db: &DurableDb, crate_name: &str, column: &str) -> String {
    db.query(&format!(
        "SELECT {column} FROM queue WHERE crate_name = ? AND target = ?"
    ))
    .bind(crate_name.to_owned())
    .bind(TARGET)
    .fetch_scalar::<String>()
    .await
    .expect("row column")
}

/// Whether a queue row exists at all — purge assertions.
async fn row_exists(db: &DurableDb, crate_name: &str) -> bool {
    db.query("SELECT count(*) FROM queue WHERE crate_name = ? AND target = ?")
        .bind(crate_name.to_owned())
        .bind(TARGET)
        .fetch_scalar::<i64>()
        .await
        .expect("row count")
        > 0
}

#[tokio::test]
async fn list_tasks_filters_by_status_crate_and_ids() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("alpha", &[]), request("beta", &[])])
        .await
        .expect("enqueue");
    mark_active(&db, "beta", TARGET, "failed").await;

    let failed = super::list_tasks(
        &db,
        &filter_selector(stow_types::api::QueueSelector {
            status: Some(stow_types::api::QueueTaskStatus::Failed),
            ..Default::default()
        }),
    )
    .await
    .expect("list failed");
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].crate_name.as_str(), "beta");

    let named = super::list_tasks(
        &db,
        &filter_selector(stow_types::api::QueueSelector {
            crate_name: Some("alpha".parse().expect("crate name")),
            ..Default::default()
        }),
    )
    .await
    .expect("list by crate");
    assert_eq!(named.len(), 1);
    assert_eq!(named[0].task_id, task_id_on("alpha", TARGET));

    let by_id = super::list_tasks(&db, &ids_selector(&[task_id_on("beta", TARGET)]))
        .await
        .expect("list by id");
    assert_eq!(by_id.len(), 1);
    assert_eq!(by_id[0].status, stow_types::api::QueueTaskStatus::Failed);
}

#[tokio::test]
async fn retry_returns_failed_rows_to_pending() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("alpha", &[]), request("beta", &[])])
        .await
        .expect("enqueue");
    mark_active(&db, "alpha", TARGET, "failed").await;
    db.query("UPDATE queue SET error_msg = 'boom' WHERE task_id = ?")
        .bind(task_id_on("alpha", TARGET))
        .execute()
        .await
        .expect("set error");

    let affected = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Retry,
        &filter_selector(stow_types::api::QueueSelector {
            status: Some(stow_types::api::QueueTaskStatus::Failed),
            ..Default::default()
        }),
    )
    .await
    .expect("retry");
    assert_eq!(affected, 1);
    assert_eq!(row_column(&db, "alpha", "status").await, "pending");
    assert_eq!(row_column(&db, "alpha", "error_msg").await, "");
    // The pending sibling is untouched — retry's domain is failed rows.
    assert_eq!(row_column(&db, "beta", "status").await, "pending");
}

/// A retried row re-enters `pending` with a fresh retry budget while
/// its dispatch generation remains monotone for evidence fencing.
#[tokio::test]
async fn retry_returns_failed_rows_to_pending_with_a_fresh_attempt() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request("alpha", &[]),
            request("beta", &[]),
            request("gamma", &[]),
        ],
    )
    .await
    .expect("enqueue");
    mark_active(&db, "alpha", TARGET, "failed").await;
    mark_active(&db, "beta", TARGET, "failed").await;
    db.query(
        "UPDATE queue SET attempt = 4, error_msg = 'boom', \
                  not_before = '2999-01-01 00:00:00' WHERE task_id = ?",
    )
    .bind(task_id_on("alpha", TARGET))
    .execute()
    .await
    .expect("seed terminal state");

    let affected = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Retry,
        &ids_selector(&[task_id_on("alpha", TARGET), task_id_on("gamma", TARGET)]),
    )
    .await
    .expect("retry");
    // `gamma` is pending, not failed — outside retry's domain.
    assert_eq!(affected, 1);
    assert_eq!(row_column(&db, "alpha", "status").await, "pending");
    assert_eq!(row_column(&db, "alpha", "CAST(attempt AS TEXT)").await, "1");
    assert_eq!(row_column(&db, "alpha", "error_msg").await, "");
    assert_eq!(
        row_column(&db, "alpha", "not_before").await,
        "1970-01-01 00:00:00"
    );
    assert_eq!(row_column(&db, "beta", "status").await, "failed");
    assert_eq!(row_column(&db, "gamma", "status").await, "pending");
}

/// `retry` carries the same selector predicates as the other verbs:
/// `status` plus `rustc`/`target` scope the release to one build
/// line.
#[tokio::test]
async fn retry_selects_by_rustc_and_target() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("alpha", &[]), request("beta", &[])])
        .await
        .expect("enqueue");
    mark_active(&db, "alpha", TARGET, "failed").await;
    mark_active(&db, "beta", TARGET, "failed").await;
    // A failed row at a different rustc — the selector must not
    // reach it.
    let other = EnqueueRequest {
        rustc_version: "1.86.0".parse().expect("rustc"),
        ..request("other-rustc", &[])
    };
    let other_rustc = other.task_id().expect("other-rustc task id");
    enqueue(&db, &[other]).await.expect("enqueue other-rustc");
    db.query("UPDATE queue SET status = 'failed' WHERE task_id = ?")
        .bind(other_rustc.clone())
        .execute()
        .await
        .expect("fail other-rustc");

    let affected = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Retry,
        &filter_selector(stow_types::api::QueueSelector {
            status: Some(stow_types::api::QueueTaskStatus::Failed),
            rustc_version: Some(RUSTC.parse().expect("rustc")),
            target: Some(TARGET.parse().expect("target")),
            ..Default::default()
        }),
    )
    .await
    .expect("retry by rustc + target");
    assert_eq!(affected, 2);
    assert_eq!(row_column(&db, "alpha", "status").await, "pending");
    assert_eq!(row_column(&db, "beta", "status").await, "pending");
    assert_eq!(row_column(&db, "alpha", "CAST(attempt AS TEXT)").await, "1");
    let other_status = db
        .query("SELECT status FROM queue WHERE task_id = ?")
        .bind(other_rustc)
        .fetch_scalar::<String>()
        .await
        .expect("other-rustc status");
    assert_eq!(other_status, "failed");
}

#[tokio::test]
async fn cancel_fails_pending_and_dispatched_rows() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request("alpha", &[]),
            request("beta", &[]),
            request("gamma", &[]),
        ],
    )
    .await
    .expect("enqueue");
    mark_active(&db, "beta", TARGET, "dispatched").await;
    mark_active(&db, "gamma", TARGET, "completed").await;

    // A completed row is outside cancel's domain regardless of the
    // selector.
    let affected = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Cancel,
        &filter_selector(stow_types::api::QueueSelector {
            crate_name: Some("gamma".parse().expect("crate name")),
            ..Default::default()
        }),
    )
    .await
    .expect("cancel by crate");
    assert_eq!(affected, 0);
    assert_eq!(row_column(&db, "gamma", "status").await, "completed");

    let affected = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Cancel,
        &ids_selector(&[task_id_on("alpha", TARGET), task_id_on("beta", TARGET)]),
    )
    .await
    .expect("cancel");
    assert_eq!(affected, 2);
    assert_eq!(row_column(&db, "alpha", "status").await, "failed");
    assert_eq!(row_column(&db, "beta", "status").await, "failed");
    assert_eq!(
        row_column(&db, "alpha", "error_msg").await,
        "cancelled by operator"
    );
}

#[tokio::test]
async fn promote_moves_miss_lane_pending_to_human() {
    let db = memory_db().await.expect("memory db");
    let mut human = request("human", &[]);
    human.source = EnqueueSource::HumanRequest;
    enqueue(&db, &[request("alpha", &[]), request("beta", &[]), human])
        .await
        .expect("enqueue");
    mark_active(&db, "beta", TARGET, "dispatched").await;

    let affected = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Promote,
        &filter_selector(stow_types::api::QueueSelector {
            crate_name: Some("alpha".parse().expect("crate name")),
            ..Default::default()
        }),
    )
    .await
    .expect("promote");
    assert_eq!(affected, 1);
    assert_eq!(row_column(&db, "alpha", "lane").await, "human");
    // Dispatched and already-human rows are outside promote's domain.
    assert_eq!(row_column(&db, "beta", "lane").await, "miss");
    assert_eq!(row_column(&db, "human", "lane").await, "human");
}

#[tokio::test]
async fn purge_deletes_only_old_terminal_rows() {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request("old-done", &[]),
            request("old-failed", &[]),
            request("fresh-failed", &[]),
            request("live", &[]),
        ],
    )
    .await
    .expect("enqueue");
    mark_active(&db, "old-done", TARGET, "completed").await;
    mark_active(&db, "old-failed", TARGET, "failed").await;
    db.query("UPDATE queue SET status = 'failed' WHERE task_id = ?")
        .bind(task_id_on("fresh-failed", TARGET))
        .execute()
        .await
        .expect("fail fresh row");

    // An age-free filter selector cannot purge — the age floor is the
    // operator's contract that only settled rows are swept.
    let denied = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Purge,
        &filter_selector(stow_types::api::QueueSelector {
            status: Some(stow_types::api::QueueTaskStatus::Failed),
            ..Default::default()
        }),
    )
    .await;
    assert!(matches!(denied, Err(QueueError::PurgeRequiresAge)));

    let affected = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Purge,
        &filter_selector(stow_types::api::QueueSelector {
            older_than_secs: Some(3_600),
            ..Default::default()
        }),
    )
    .await
    .expect("purge");
    assert_eq!(affected, 2);
    assert!(!row_exists(&db, "old-done").await);
    assert!(!row_exists(&db, "old-failed").await);
    // Too young for the floor, and pending rows are never purgeable.
    assert!(row_exists(&db, "fresh-failed").await);
    assert!(row_exists(&db, "live").await);
}

#[tokio::test]
async fn mutations_reject_an_empty_selector() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("alpha", &[])])
        .await
        .expect("enqueue");
    let denied = super::apply_mutation(
        &db,
        &settings(),
        super::QueueMutation::Cancel,
        &stow_types::api::QueueSelector::default(),
    )
    .await;
    assert!(matches!(denied, Err(QueueError::EmptySelector)));
    assert_eq!(row_column(&db, "alpha", "status").await, "pending");
}

#[tokio::test]
async fn admin_status_reports_lanes_in_flight_and_targets() {
    let db = memory_db().await.expect("memory db");
    let mut human = request("human", &[]);
    human.source = EnqueueSource::HumanRequest;
    enqueue(
        &db,
        &[request("miss-a", &[]), request("miss-b", &[]), human],
    )
    .await
    .expect("enqueue");
    mark_active(&db, "miss-b", TARGET, "dispatched").await;
    db.query("UPDATE queue SET github_run_id = ? WHERE task_id = ?")
        .bind("777")
        .bind(task_id_on("miss-b", TARGET))
        .execute()
        .await
        .expect("stamp run id");
    // Terminal rows inside the 24 h window feed the per-target tally.
    db.query("UPDATE queue SET status = 'completed' WHERE task_id = ?")
        .bind(task_id_on("human", TARGET))
        .execute()
        .await
        .expect("complete human row");

    let status = super::admin_status(&db).await.expect("admin status");
    assert_eq!(status.pending_miss, 1);
    assert_eq!(status.pending_human, 0);
    assert!(status.oldest_pending_seconds.is_some());
    assert_eq!(status.in_flight.len(), 1);
    let in_flight = &status.in_flight[0];
    assert_eq!(in_flight.task_id, task_id_on("miss-b", TARGET));
    assert_eq!(in_flight.github_run_id.as_deref(), Some("777"));
    let target = status
        .targets
        .iter()
        .find(|entry| entry.target.as_str() == TARGET)
        .expect("target stats");
    assert_eq!(target.completed_24h, 1);
    assert_eq!(target.failed_24h, 0);
}

/// The dev-era DDL — `queue` without `host_side`/`shape_requeue`,
/// `queue_dependencies` carrying the dep_* identity columns but none
/// of the shape-gate columns — is what production ran before
/// host-side nodes.
const DEV_ERA_QUEUE: &str = "CREATE TABLE queue (
        task_id TEXT PRIMARY KEY,
        crate_name TEXT NOT NULL,
        version TEXT NOT NULL,
        features_json TEXT NOT NULL,
        target TEXT NOT NULL,
        rustc_version TEXT NOT NULL,
        downloads INTEGER NOT NULL DEFAULT 0,
        miss_count INTEGER NOT NULL DEFAULT 0,
        request_count INTEGER NOT NULL DEFAULT 1,
        priority INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        error_msg TEXT,
        preserve_lockfile INTEGER NOT NULL DEFAULT 0,
        lane TEXT NOT NULL DEFAULT 'miss' CHECK (lane IN ('miss', 'human')),
        dispatch_attempts INTEGER NOT NULL DEFAULT 0,
        attempt INTEGER NOT NULL DEFAULT 1,
        not_before TEXT NOT NULL DEFAULT '1970-01-01 00:00:00',
        first_requested_at TEXT NOT NULL DEFAULT (datetime('now')),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        github_run_id TEXT,
        UNIQUE(crate_name, version, features_json, target, rustc_version)
    )";
const DEV_ERA_DEPENDENCIES: &str = "CREATE TABLE queue_dependencies (
        task_id TEXT NOT NULL,
        depends_on_task_id TEXT NOT NULL,
        dep_crate_name TEXT NOT NULL DEFAULT '',
        dep_version TEXT NOT NULL DEFAULT '',
        dep_features_json TEXT NOT NULL DEFAULT '',
        dep_target TEXT NOT NULL DEFAULT '',
        dep_rustc_version TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (task_id, depends_on_task_id)
    )";

/// The objects a pre-`host_side` queue carried on top of
/// `DEV_ERA_QUEUE`: the counter triggers and the status index. On
/// `ALTER TABLE queue RENAME TO queue_migrated` `SQLite` moves them
/// with the table, so a rebuild that recreates the table and drops
/// the copy without re-running the include afterwards loses them
/// all — the regression `migrate_rebuilds_queue_triggers_and_indexes`
/// covers (stow#433).
const DEV_ERA_QUEUE_OBJECTS: &[&str] = &[
    "CREATE TABLE queue_status_counts (
            status TEXT NOT NULL,
            lane TEXT NOT NULL,
            n INTEGER NOT NULL,
            PRIMARY KEY (status, lane)
        )",
    "CREATE TRIGGER queue_counts_on_insert AFTER INSERT ON queue
         BEGIN
             INSERT INTO queue_status_counts (status, lane, n)
                 VALUES (NEW.status, NEW.lane, 1)
             ON CONFLICT (status, lane) DO UPDATE SET n = n + 1;
         END",
    "CREATE TRIGGER queue_counts_on_delete AFTER DELETE ON queue
         BEGIN
             INSERT INTO queue_status_counts (status, lane, n)
                 VALUES (OLD.status, OLD.lane, -1)
             ON CONFLICT (status, lane) DO UPDATE SET n = n - 1;
         END",
    "CREATE TRIGGER queue_counts_on_move
             AFTER UPDATE OF status, lane ON queue
             WHEN OLD.status != NEW.status OR OLD.lane != NEW.lane
         BEGIN
             INSERT INTO queue_status_counts (status, lane, n)
                 VALUES (OLD.status, OLD.lane, -1)
             ON CONFLICT (status, lane) DO UPDATE SET n = n - 1;
             INSERT INTO queue_status_counts (status, lane, n)
                 VALUES (NEW.status, NEW.lane, 1)
             ON CONFLICT (status, lane) DO UPDATE SET n = n + 1;
         END",
    "CREATE INDEX idx_queue_status_updated ON queue (status, updated_at)",
];

/// `migrate` must migrate a dev-era schema in any column order
/// and still backfill every pre-existing edge's mask: the backfill
/// joins `queue.host_side`, so it must run after the host-side
/// rebuild and must not depend on whether the ALTER columns it fills
/// were just added (stow#367).
#[derive(skyzen::FromRow)]
struct MigratedClaimRow {
    task_id: String,
    status: String,
    host_side: i64,
    shape_requeue: i64,
    attempt: i64,
    dispatch_attempts: i64,
    generation_id: String,
    github_run_id: Option<String>,
    not_before: String,
    wake_at: String,
}

async fn seed_legacy_inflight_claims(db: &DurableDb, owner: &str, dep: &str) {
    for statement in [DEV_ERA_QUEUE, DEV_ERA_DEPENDENCIES] {
        db.query(statement).execute().await.expect("dev-era ddl");
    }
    db.query(
        "CREATE TABLE attempt_outcomes (
                task_id TEXT NOT NULL,
                attempt INTEGER NOT NULL,
                target TEXT NOT NULL,
                failure_step TEXT,
                failure_class TEXT,
                github_run_id TEXT,
                finished_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (task_id, attempt)
            )",
    )
    .execute()
    .await
    .expect("legacy outcome ddl");
    db.query(
        "INSERT INTO attempt_outcomes \
             (task_id, attempt, target, failure_class, github_run_id) \
             VALUES ('legacy-before-migrate', 1, ?, 'legacy', 'run-legacy')",
    )
    .bind(TARGET)
    .execute()
    .await
    .expect("legacy outcome row");
    db.query(
        "INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version)
             VALUES (?, 'dep', '1.0.0', '[]', ?, '1.85.0'),
                    (?, 'parent', '1.0.0', '[]', ?, '1.85.0')",
    )
    .bind(dep.to_owned())
    .bind(TARGET)
    .bind(owner.to_owned())
    .bind(TARGET)
    .execute()
    .await
    .expect("dev-era queue rows");
    db.query(
            "INSERT INTO queue_dependencies
             (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version)
             VALUES (?, ?, 'dep', '1.0.0', '[]', ?, '1.85.0')",
        )
        .bind(owner.to_owned())
        .bind(dep.to_owned())
        .bind(TARGET)
        .execute()
        .await
        .expect("dev-era edge row");
    db.query("UPDATE queue SET dispatch_attempts = 2, attempt = 3")
        .execute()
        .await
        .expect("seed legacy attempt counters");
    db.query("UPDATE queue SET status = 'dispatched' WHERE task_id = ?")
        .bind(dep.to_owned())
        .execute()
        .await
        .expect("seed unbound legacy dispatch");
    db.query("UPDATE queue SET status = 'running', github_run_id = ? WHERE task_id = ?")
        .bind("legacy-run")
        .bind(owner.to_owned())
        .execute()
        .await
        .expect("seed bound legacy dispatch");
}

async fn assert_migrated_edge_masks(db: &DurableDb) {
    #[derive(skyzen::FromRow)]
    struct EdgeRow {
        side: i64,
        invocations: i64,
        shapes: i64,
    }
    let edge = db
        .query(
            "SELECT dep_host_side AS side, dep_invocations AS invocations, dep_shapes AS shapes \
                 FROM queue_dependencies",
        )
        .fetch_one::<EdgeRow>()
        .await
        .expect("edge row");
    // Owner and dep both mint on the family host triple, so the
    // dev-era edge's required side is ambiguous — the derivation
    // marks it -1 (unestablished) rather than trusting a target-side
    // 0 it cannot prove; `p.unit_side = -1` matches no published row
    // so the gate holds the dependent until a resync rewrites it.
    assert_eq!(edge.side, -1);
    // The mask is moot on a -1 edge — `p.unit_side = -1` matches no
    // published row — but it is written non-zero so the edge stays
    // out of the unbackfilled-0 marker class.
    assert_eq!(edge.invocations, 1);
    assert_eq!(edge.shapes, 2);
}

async fn assert_migrated_claims(
    db: &DurableDb,
    owner: &str,
    dep: &str,
    before_retry: MigratedClaimRow,
) {
    let rows = db
        .query(
            "SELECT task_id, status, host_side, shape_requeue, attempt, dispatch_attempts, \
                    generation_id, github_run_id, not_before, wake_at \
                 FROM queue",
        )
        .fetch_all::<MigratedClaimRow>()
        .await
        .expect("queue rows");
    assert_eq!(rows.len(), 2, "the rebuild keeps every queue row");
    assert!(
        rows.iter()
            .all(|row| row.host_side == 0 && row.shape_requeue == 0)
    );
    let abandoned = rows
        .iter()
        .find(|row| row.task_id == dep)
        .expect("abandoned row");
    assert_eq!(abandoned.status, "pending");
    assert_eq!(abandoned.attempt, 3);
    assert_eq!(abandoned.dispatch_attempts, 2);
    assert_ne!(abandoned.not_before, "1970-01-01 00:00:00");
    assert_ne!(abandoned.wake_at, "1970-01-01 00:00:00");
    assert_ne!(abandoned.generation_id, "");
    assert_eq!(abandoned.github_run_id, None);
    assert_eq!(
        (
            abandoned.status.clone(),
            abandoned.attempt,
            abandoned.dispatch_attempts,
            abandoned.generation_id.clone(),
            abandoned.not_before.clone(),
            abandoned.wake_at.clone(),
        ),
        (
            before_retry.status,
            before_retry.attempt,
            before_retry.dispatch_attempts,
            before_retry.generation_id,
            before_retry.not_before,
            before_retry.wake_at,
        ),
        "rerunning migration leaves the requeued claim unchanged"
    );
    let preserved = rows
        .iter()
        .find(|row| row.task_id == owner)
        .expect("bound row");
    assert_eq!(preserved.status, "running");
    assert_ne!(preserved.generation_id, "");
    assert_eq!(preserved.github_run_id.as_deref(), Some("legacy-run"));
}

async fn assert_migrated_outcome_history(db: &DurableDb) {
    assert_eq!(
        db.query(
            "SELECT count(*) FROM attempt_outcomes \
                 WHERE task_id = 'legacy-before-migrate'",
        )
        .fetch_scalar::<i64>()
        .await
        .expect("read preserved legacy outcome history"),
        1,
        "migration keeps legacy outcome evidence"
    );

    assert_eq!(
        super::stored_schema_version(db)
            .await
            .expect("schema version"),
        super::SCHEMA_VERSION,
        "a migrated queue is stamped at the current schema version"
    );
    db.query(
        "INSERT INTO attempt_outcomes \
             (task_id, attempt, target, failure_class, github_run_id) \
             VALUES ('legacy-after-migrate', 1, ?, 'legacy', 'run-legacy-2')",
    )
    .bind(TARGET)
    .execute()
    .await
    .expect("old writer remains compatible");
    let generation_columns = db
        .query("PRAGMA table_info(attempt_outcomes_v2)")
        .fetch_all::<super::QueueTableInfoRow>()
        .await
        .expect("generation outcome table");
    assert!(
        generation_columns
            .iter()
            .any(|column| column.name == "generation_id")
    );
}

#[tokio::test]
async fn migrate_migrates_a_dev_era_queue_and_backfills_edge_masks() {
    let db = memory_db_raw().await.expect("raw memory db");
    let owner = task_id_with("parent", TARGET, &[dependency("dep")]);
    let dep = task_id_on("dep", TARGET);
    seed_legacy_inflight_claims(&db, &owner, &dep).await;

    let report = super::migrate(&db, &settings()).await.expect("migrate");
    assert_eq!(
        (report.before, report.after),
        (0, super::SCHEMA_VERSION),
        "a pre-versioned queue reports 0 → SCHEMA_VERSION"
    );
    let before_retry = db
        .query(
            "SELECT task_id, status, host_side, shape_requeue, attempt, dispatch_attempts, \
                    generation_id, github_run_id, not_before, wake_at \
                 FROM queue WHERE task_id = ?",
        )
        .bind(dep.clone())
        .fetch_one::<MigratedClaimRow>()
        .await
        .expect("read requeued row before migration retry");
    let stale = super::complete_run(
        &db,
        &settings(),
        &report_with_run(&dep, false, "legacy-run"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect_err("legacy unbound completion cannot settle requeued work");
    assert!(matches!(stale, QueueError::StaleCompletion { .. }));

    // A second pass must be a no-op, not a failure — deploy retries.
    let retry = super::migrate(&db, &settings())
        .await
        .expect("migrate retry");
    assert_eq!(
        (retry.before, retry.after),
        (super::SCHEMA_VERSION, super::SCHEMA_VERSION)
    );

    assert_migrated_edge_masks(&db).await;

    assert_migrated_claims(&db, &owner, &dep, before_retry).await;
    let stale_bound = super::complete_run(
        &db,
        &settings(),
        &report_with_run(&owner, false, "older-run"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect_err("an old run cannot settle a preserved bound claim");
    assert!(matches!(stale_bound, QueueError::StaleCompletion { .. }));
    assert_migrated_outcome_history(&db).await;
}

/// A queue carrying the retired `rust_stable_channel` cache table
/// loses it in the same pass that stamps the version — `IF EXISTS`
/// makes the step idempotent, so the version bump's retry test is
/// also the cover for the table never having existed.
#[tokio::test]
async fn migration_drops_the_retired_channel_cache_table() {
    let db = memory_db_raw().await.expect("raw memory db");
    db.query(
        "CREATE TABLE rust_stable_channel (\
             id INTEGER PRIMARY KEY CHECK (id = 1),\
             version TEXT NOT NULL,\
             fetched_at TEXT NOT NULL DEFAULT (datetime('now')))",
    )
    .execute()
    .await
    .expect("create retired table");

    super::migrate(&db, &settings()).await.expect("migrate");

    let columns = db
        .query("PRAGMA table_info(rust_stable_channel)")
        .fetch_all::<super::QueueTableInfoRow>()
        .await
        .expect("table_info");
    assert!(columns.is_empty(), "the retired table is gone");
}

/// A fresh database runs the migration pass and ends stamped at
/// `SCHEMA_VERSION` — production's pre-versioned queues take the
/// same path exactly once, through the operator route.
#[tokio::test]
async fn a_fresh_database_migrates_and_is_stamped() {
    let db = memory_db_raw().await.expect("raw memory db");
    let report = super::migrate(&db, &settings()).await.expect("migrate");
    assert_eq!((report.before, report.after), (0, super::SCHEMA_VERSION));
    assert_eq!(
        super::stored_schema_version(&db)
            .await
            .expect("schema version"),
        super::SCHEMA_VERSION
    );
}

/// The ops rule's cost bound (stow#432): request code runs no
/// schema work at all — no version read, no `PRAGMA`, no DDL — so
/// the cheapest request path issues exactly its own statement. The
/// backend's migration permit already refuses anything else; this
/// names what the permit is for.
#[tokio::test]
async fn a_request_path_issues_no_schema_statements() {
    let (db, log) = counting_memory_db().await.expect("counting db");
    let base = log.lock().expect("log").len();
    super::pending_count(&db).await.expect("pending_count");
    let issued = log.lock().expect("log")[base..].to_vec();
    assert_eq!(
        issued.len(),
        1,
        "the pending-count read is one statement and nothing else: {issued:?}"
    );
    assert!(
        issued[0].sql.starts_with("SELECT"),
        "the one statement is the pending count: {}",
        issued[0].sql
    );
}

/// A queue stamped newer than this build's `SCHEMA_VERSION` was
/// migrated by newer code — `migrate` fails fast rather than letting
/// old code read a schema it does not understand.
#[tokio::test]
async fn migrate_refuses_a_newer_schema() {
    // The migrate path's fixture: `migrate` runs only behind the
    // operator route, where schema probes are permitted.
    let db = memory_db_raw().await.expect("raw memory db");
    super::migrate(&db, &settings())
        .await
        .expect("first migrate");
    db.query(&format!(
        "UPDATE scheduler_schema_version SET version = {}",
        super::SCHEMA_VERSION + 1
    ))
    .execute()
    .await
    .expect("stamp newer version");
    let error = super::migrate(&db, &settings())
        .await
        .expect_err("a newer schema version must fail fast");
    assert!(
        error.to_string().contains("newer"),
        "the error names the version skew, got: {error}"
    );
}

/// The host backend enforces both halves of the ops rule (stow#432):
/// a request-path database refuses every `PRAGMA` — including the
/// documented ones, since request code must never probe the schema —
/// and every DDL head, while the migrate path's fixture still applies
/// the Durable Object authorizer's pragma allowlist (`user_version`
/// refused, `table_info` allowed) on top of permitting the DDL.
#[tokio::test]
async fn the_test_backend_refuses_schema_work_outside_migrate() {
    let db = memory_db().await.expect("memory db");
    for sql in [
        "PRAGMA user_version",
        "PRAGMA table_info(queue)",
        "CREATE TABLE extra (id INTEGER)",
        "ALTER TABLE queue ADD COLUMN extra INTEGER",
        "DROP TABLE queue",
    ] {
        assert!(
            db.query(sql).execute().await.is_err(),
            "{sql} must fail on a request-path database"
        );
    }
    let db = memory_db_raw().await.expect("raw memory db");
    db.query("PRAGMA table_info(queue)")
        .fetch_all::<super::QueueTableInfoRow>()
        .await
        .expect("the documented pragma the migrations rely on");
    db.query("CREATE TABLE tmp_marker (id INTEGER)")
        .execute()
        .await
        .expect("DDL on the migrate path's database");
    let error = db
        .query("PRAGMA user_version")
        .execute()
        .await
        .expect_err("the DO authorizer refuses it even under migrate");
    assert!(
        error.to_string().contains("user_version"),
        "the rejection names the pragma, got: {error}"
    );
}

/// The side derivation each dev-era edge takes: a dep on the family
/// host triple under a cross owner is provably host, a dep on the
/// owner's own target off the host triple is provably target, and a
/// dep on the host triple under an owner on the same triple — or on
/// neither — stays unestablished (-1).
#[tokio::test]
async fn migrate_derives_dev_era_edge_sides_from_triples() {
    #[derive(skyzen::FromRow)]
    struct EdgeRow {
        side: i64,
    }
    const CROSS: &str = "aarch64-unknown-linux-gnu";
    const WASM: &str = "wasm32-unknown-unknown";
    let db = memory_db_raw().await.expect("raw memory db");
    for statement in [DEV_ERA_QUEUE, DEV_ERA_DEPENDENCIES] {
        db.query(statement).execute().await.expect("dev-era ddl");
    }
    // (owner target, dep target, expected side)
    let cases: [(&str, &str); 4] = [
        (CROSS, TARGET),
        (CROSS, CROSS),
        (TARGET, TARGET),
        (WASM, WASM),
    ];
    for (index, (owner_target, dep_target)) in cases.iter().enumerate() {
        let owner = format!("owner{index}");
        let dep = format!("dep{index}");
        let owner_id = task_id(&owner, VERSION, FEATURES, owner_target, RUSTC, false);
        let dep_id = task_id(&dep, VERSION, FEATURES, dep_target, RUSTC, false);
        db.query(
                "INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version) \
                 VALUES (?, ?, '1.0.0', '[]', ?, '1.85.0'), (?, ?, '1.0.0', '[]', ?, '1.85.0')",
            )
            .bind(owner_id.clone())
            .bind(owner)
            .bind(*owner_target)
            .bind(dep_id.clone())
            .bind(dep)
            .bind(*dep_target)
            .execute()
            .await
            .expect("dev-era queue rows");
        db.query(
                "INSERT INTO queue_dependencies \
                 (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version) \
                 VALUES (?, ?, ?, '1.0.0', '[]', ?, '1.85.0')",
            )
            .bind(owner_id)
            .bind(dep_id)
            .bind(format!("dep{index}"))
            .bind(*dep_target)
            .execute()
            .await
            .expect("dev-era edge row");
    }

    super::migrate(&db, &settings()).await.expect("migrate");
    super::migrate(&db, &settings())
        .await
        .expect("migrate retry is a no-op");

    let rows = db
        .query(
            "SELECT dep_host_side AS side FROM queue_dependencies \
                 ORDER BY task_id",
        )
        .fetch_all::<EdgeRow>()
        .await
        .expect("edge rows");
    assert_eq!(rows.len(), 4);
    // task_ids hash, so order is not the insert order — compare the
    // side multiset: one unestablished, two provably target, one
    // provably host.
    let mut sides: Vec<i64> = rows.iter().map(|row| row.side).collect();
    sides.sort_unstable();
    assert_eq!(sides, vec![-1, 0, 0, 1]);
}

/// The human-lane position count must drive from the covering
/// `(status, lane, dispatch_key)` index — a plain status scan would
/// walk every pending miss row to reach a human lane's prefix.
async fn assert_human_position_plan(db: &DurableDb) {
    #[derive(Debug, skyzen::FromRow)]
    struct PlanRow {
        detail: String,
    }
    let plan = db
        .query(
            "EXPLAIN QUERY PLAN \
                 SELECT count(*) FROM queue \
                 WHERE status = 'pending' AND lane = 'human' AND dispatch_key < ?",
        )
        .bind("9999999999999999999")
        .fetch_all::<PlanRow>()
        .await
        .expect("human position query plan");
    assert!(
        plan.iter().any(|row| row
            .detail
            .contains("USING COVERING INDEX idx_queue_human_position")),
        "human position must use the covering lane/key index: {plan:?}"
    );
}

/// The `host_side` rebuild renames `queue` aside, recreates it, copies
/// the rows and drops the copy — and `SQLite` moves the old table's
/// named indexes and triggers onto `queue_migrated` with the rename,
/// so the include that recreates them must run after the drop or the
/// rebuilt queue keeps neither. Start from a pre-`host_side` queue
/// carrying the era's counter triggers and one index, migrate, and
/// assert every `queue` index and trigger `schema.sql` declares
/// exists afterwards — and that the counters still track a write.
#[tokio::test]
async fn migrate_rebuilds_queue_triggers_and_indexes() {
    #[derive(skyzen::FromRow)]
    struct ObjectRow {
        name: String,
    }
    let db = memory_db_raw().await.expect("raw memory db");
    // The era's objects on the dev-era queue: counter triggers and
    // the status index. Without the post-drop include the rename
    // moves them to `queue_migrated` and the drop deletes them.
    for statement in [DEV_ERA_QUEUE, DEV_ERA_DEPENDENCIES]
        .into_iter()
        .chain(DEV_ERA_QUEUE_OBJECTS.iter().copied())
    {
        db.query(statement).execute().await.expect("dev-era ddl");
    }
    db.query(
        "INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version)
             VALUES (?, 'dep', '1.0.0', '[]', ?, '1.85.0')",
    )
    .bind(task_id_on("dep", TARGET))
    .bind(TARGET)
    .execute()
    .await
    .expect("dev-era queue row");

    super::migrate(&db, &settings()).await.expect("migrate");

    // Every index and trigger schema.sql declares on `queue` must
    // exist on the rebuilt table.
    let mut expected = Vec::new();
    for statement in include_str!("schema.sql").split(';') {
        let normalized = statement.replace('\n', " ");
        let is_queue_object = normalized.contains("ON queue ")
            && (normalized.contains("INDEX") || normalized.contains("TRIGGER"));
        if !is_queue_object {
            continue;
        }
        let name = normalized
            .split_whitespace()
            .skip_while(|token| *token != "EXISTS")
            .nth(1)
            .expect("object name after IF NOT EXISTS");
        expected.push(name.to_owned());
    }
    assert!(!expected.is_empty(), "schema.sql declares queue objects");
    let present: BTreeSet<String> = db
        .query(
            "SELECT name FROM sqlite_master \
                 WHERE tbl_name = 'queue' AND type IN ('index', 'trigger')",
        )
        .fetch_all::<ObjectRow>()
        .await
        .expect("sqlite_master")
        .into_iter()
        .map(|row| row.name)
        .collect();
    let missing: Vec<String> = expected
        .iter()
        .filter(|name| !present.contains(*name))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "the rebuild dropped queue objects: {missing:?}"
    );

    assert_human_position_plan(&db).await;

    // And the counters must track a write made after the migration —
    // the defect's other half is triggers that exist but never fire.
    let before: Option<i64> = db
        .query(
            "SELECT n FROM queue_status_counts \
                 WHERE status = 'pending' AND lane = 'miss'",
        )
        .fetch_scalar_optional::<i64>()
        .await
        .expect("counter row");
    db.query(
        "INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version)
             VALUES (?, 'post', '1.0.0', '[]', ?, '1.85.0')",
    )
    .bind(task_id_on("post", TARGET))
    .bind(TARGET)
    .execute()
    .await
    .expect("post-migration insert");
    let after: Option<i64> = db
        .query(
            "SELECT n FROM queue_status_counts \
                 WHERE status = 'pending' AND lane = 'miss'",
        )
        .fetch_scalar_optional::<i64>()
        .await
        .expect("counter row after insert");
    assert_eq!(
        after,
        Some(before.unwrap_or(0) + 1),
        "the counter trigger tracks a write made after the migration"
    );
}

/// The claim-frontier regression (stow#433): with every macOS slot
/// taken and more than `CLAIM_MAX_PAGES × CLAIM_PAGE_ROWS` eligible
/// macOS rows ordered ahead, a Rust-side skip spent the whole page
/// budget on rows it could not claim, so the claimable rows past the
/// frontier starved while `next_alarm` kept re-arming `At(now)` for
/// them. The saturated family's exclusion lives in the claim query's
/// WHERE now, so a pass must reach the Linux row.
#[tokio::test]
async fn a_saturated_macos_backlog_does_not_starve_other_families() {
    let db = memory_db().await.expect("memory db");
    // One more macOS row than the pass's page budget — enough to
    // fill every page if the exclusion were still Rust-side.
    let overflow = super::CLAIM_MAX_PAGES
        * usize::try_from(super::CLAIM_PAGE_ROWS).expect("claim page rows")
        + 1;
    let mut requests = Vec::with_capacity(overflow);
    for index in 0..overflow {
        requests.push(request_on(&format!("mac{index:05}"), MACOS_TARGET, &[]));
    }
    // The backlog exceeds `max_queue_pending` — the trusted route
    // skips the cap, which is also how production's backlog got
    // that deep.
    super::enqueue_trusted(&db, &requests, &settings())
        .await
        .expect("enqueue macos backlog");
    super::enqueue_trusted(&db, &[request_on("lin", TARGET, &[])], &settings())
        .await
        .expect("enqueue linux");
    // Order the macOS backlog strictly ahead of the Linux row in
    // claim order — persisted `dispatch_key` bakes the row's
    // `first_requested_at`, so recompute it in the same update.
    db.query("UPDATE queue SET first_requested_at = ? WHERE target = ?")
        .bind(PAST_TS)
        .bind(MACOS_TARGET)
        .execute()
        .await
        .expect("backdate macos backlog");
    let mac_ids = db
        .query("SELECT task_id FROM queue WHERE target = ?")
        .bind(MACOS_TARGET)
        .fetch_scalars::<String>()
        .await
        .expect("macos ids");
    super::refresh_dispatch_keys(&db, &mac_ids)
        .await
        .expect("recompute backdated keys");

    let settings = SchedulerSettings {
        max_concurrent_macos_jobs: 0,
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "lin");
    assert_eq!(claimed[0].target, TARGET);
}

/// The claim pass reads in proportion to the slots it fills
/// (stow#433): three open slots over a 2,000-row eligible frontier
/// must issue exactly one page read — `LIMIT min(CLAIM_PAGE_ROWS,
/// 2 × slots)` — and hand the coverage oracle a lookup sized to
/// that page, never to the frontier.
#[tokio::test]
async fn a_small_slot_pass_reads_one_page_not_the_frontier() {
    let (db, log) = counting_memory_db().await.expect("counting db");
    let requests: Vec<EnqueueRequest> = (0..2_000)
        .map(|i| request(&format!("frontier-{i:04}"), &[]))
        .collect();
    // The backlog sits at `max_queue_pending`; the trusted route
    // admits it regardless.
    super::enqueue_trusted(&db, &requests, &settings())
        .await
        .expect("enqueue frontier");

    let oracle = FixedCoverage {
        covered: BTreeSet::new(),
        asked: std::sync::Mutex::new(Vec::new()),
    };
    let settings = SchedulerSettings {
        dispatch: Dispatch::from_max_concurrent_jobs(3),
        dispatch_min_age_minutes: 0,
        ..settings()
    };
    let base = log.lock().expect("log").len();
    let claimed = super::claim_dispatchable_tasks(&db, &settings, &oracle)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 3);

    let page_reads = log
        .lock()
        .expect("log")
        .iter()
        .skip(base)
        .filter(|stmt| stmt.sql.starts_with("SELECT q.task_id, q.attempt"))
        .count();
    assert_eq!(
        page_reads, 1,
        "a 3-slot pass over a 2000-row frontier must read one page"
    );
    let asked = oracle.asked.lock().expect("oracle log").len();
    assert_eq!(
        asked, 6,
        "the coverage lookup is sized to the page (2 × slots), not the frontier"
    );
}

/// A dependent behind an unestablished edge (`dep_host_side = -1`)
/// stays held even when its dep publishes every shape it owns:
/// `p.unit_side = -1` matches no row, so nothing published can
/// satisfy it — only the resolver's resync rewrites the edge with a
/// real side, which is what a re-request carrying `depends_on` does.
#[tokio::test]
async fn dependent_behind_an_unestablished_edge_waits_for_resync() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    // The spelling the migration writes on an edge whose required
    // side it could not derive.
    db.query("UPDATE queue_dependencies SET dep_host_side = -1")
        .execute()
        .await
        .expect("stamp unestablished edge");

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim dep");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "dep");
    super::complete(
        &db,
        &claim_settings(),
        &report(
            &claimed[0].task_id,
            &claimed[0].generation_id,
            claimed[0].attempt,
            true,
        ),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete dep");
    publish(&db, "dep").await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim with unestablished edge");
    assert!(claimed.is_empty(), "a -1 edge satisfies no published row");

    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("re-request parent resyncs the edge");
    let side = db
        .query("SELECT dep_host_side FROM queue_dependencies")
        .fetch_scalar::<i64>()
        .await
        .expect("edge side");
    assert_eq!(side, 0);

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim after resync");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "parent");
}

/// A dependency reported `completed` whose published rows never
/// covered a dependent's required shapes is not done: the claim pass
/// re-queues it once — behind the existing backoff — so the rebuild
/// republishes real shapes (stow#367). The latch holds, so a still-
/// uncovered second completion does not loop the rebuild.
#[tokio::test]
async fn completed_dependency_with_uncovered_shapes_is_requeued_once() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    enqueue(&db, &[request("parent", &[dependency("dep")])])
        .await
        .expect("enqueue parent");
    mark_active(&db, "dep", TARGET, "completed").await;

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert!(
        claimed.is_empty(),
        "the requeued dep sits behind its backoff and the parent stays gated"
    );
    assert_eq!(row_column(&db, "dep", "status").await, "pending");
    let latch = db
        .query("SELECT shape_requeue FROM queue WHERE task_id = ?")
        .bind(task_id_on("dep", TARGET))
        .fetch_scalar::<i64>()
        .await
        .expect("shape_requeue");
    assert_eq!(latch, 1);

    db.query("UPDATE queue SET not_before = '1970-01-01 00:00:00' WHERE task_id = ?")
        .bind(task_id_on("dep", TARGET))
        .execute()
        .await
        .expect("clear dep backoff");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim requeued dep");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "dep");
    super::complete(
        &db,
        &claim_settings(),
        &report(
            &claimed[0].task_id,
            &claimed[0].generation_id,
            claimed[0].attempt,
            true,
        ),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete dep");

    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim after second completion");
    assert!(
        claimed.is_empty(),
        "the latch blocks a second re-queue; the parent waits for the publish"
    );
    assert_eq!(row_column(&db, "dep", "status").await, "completed");

    publish(&db, "dep").await;
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim parent");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].crate_name, "parent");
}

/// The columns the requeue-ordering tests assert on.
#[derive(Debug, skyzen::FromRow)]
struct QueueCounters {
    status: String,
    attempt: i64,
    request_count: i64,
}

async fn queue_counters(db: &DurableDb, crate_name: &str) -> QueueCounters {
    db.query("SELECT status, attempt, request_count FROM queue WHERE task_id = ?")
        .bind(task_id_on(crate_name, TARGET))
        .fetch_one::<QueueCounters>()
        .await
        .expect("read queue counters")
}

/// Seed a row as failed with known counters so the assertions about
/// what one chunk did to it are exact.
async fn seed_failed(db: &DurableDb, crate_name: &str, attempt: i64, request_count: i64) {
    enqueue(db, &[request(crate_name, &[])])
        .await
        .expect("seed enqueue");
    db.query(
        "UPDATE queue SET status = 'failed', attempt = ?, request_count = ?, \
             error_msg = 'boom' WHERE task_id = ?",
    )
    .bind(attempt)
    .bind(request_count)
    .bind(task_id_on(crate_name, TARGET))
    .execute()
    .await
    .expect("seed failed row");
}

/// Several parents in one chunk all name the same failed dep.
/// Requesting a task no longer revives a terminal row from any
/// lane: the dep's status, attempt and counters are untouched
/// however many parents name it, and every parent parks `blocked`
/// behind it.
#[tokio::test]
async fn a_chunk_never_revives_a_failed_dependency() {
    let db = memory_db().await.expect("memory db");
    seed_failed(&db, "dep", 7, 5).await;

    enqueue(
        &db,
        &[
            request("p1", &[dependency("dep")]),
            request("p2", &[dependency("dep")]),
            request("p3", &[dependency("dep")]),
        ],
    )
    .await
    .expect("enqueue parents");

    let row = queue_counters(&db, "dep").await;
    assert_eq!(
        (row.status.as_str(), row.attempt, row.request_count),
        ("failed", 7, 5),
        "a request never revives a terminal row"
    );
    for parent in ["p1", "p2", "p3"] {
        assert_eq!(row_column(&db, parent, "CAST(blocked AS TEXT)").await, "1");
    }
}

/// The dep's own request is no different from its dependents':
/// re-requesting a `failed` row counts the request —
/// `request_count` +1 — and changes nothing else. `blocked` rows
/// behave identically (`resurrects` names neither).
#[tokio::test]
async fn dep_request_never_revives_a_failed_dep_in_one_chunk() {
    let db = memory_db().await.expect("memory db");
    seed_failed(&db, "dep", 7, 5).await;

    enqueue(
        &db,
        &[request("dep", &[]), request("parent", &[dependency("dep")])],
    )
    .await
    .expect("enqueue dep then parent");

    let dep = queue_counters(&db, "dep").await;
    assert_eq!(
        (dep.status.as_str(), dep.attempt, dep.request_count),
        ("failed", 7, 6),
        "request counted, status untouched"
    );
    assert_eq!(
        row_column(&db, "parent", "CAST(blocked AS TEXT)").await,
        "1"
    );
}

/// Order inside the chunk is irrelevant — parent first lands the
/// same as dep first: the failed row counts one request and keeps
/// its terminal status.
#[tokio::test]
async fn parent_request_before_its_failed_dep_in_one_chunk() {
    let db = memory_db().await.expect("memory db");
    seed_failed(&db, "dep", 7, 5).await;

    enqueue(
        &db,
        &[request("parent", &[dependency("dep")]), request("dep", &[])],
    )
    .await
    .expect("enqueue parent then dep");

    let dep = queue_counters(&db, "dep").await;
    assert_eq!(
        (dep.status.as_str(), dep.attempt, dep.request_count),
        ("failed", 7, 6),
        "same outcome either order: no resurrection"
    );
}

/// Issue #418 regression guard: a submit chunk must not issue one
/// statement per request or per edge. A 1000-request chunk with
/// three deps each — 1000 fresh rows, 3000 edges, 4000 probe ids —
/// runs 6 statements on the host backend: the chunked existence
/// probes (2), the batched task insert (1), the edge-set delete (1),
/// and the batched edge inserts (2). The schema check that topped
/// them up is gone entirely (stow#432): request code runs none. A
/// return to per-row statements issues thousands.
#[tokio::test]
async fn a_submit_chunk_issues_a_constant_statement_count() {
    let (db, log) = counting_memory_db().await.expect("counting db");
    let requests: Vec<EnqueueRequest> = (0..1000)
        .map(|i| {
            request(
                &format!("req-{i}"),
                &(0..3)
                    .map(|k| dependency(&format!("dep-{i}-{k}")))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let base = log.lock().expect("log").len();

    super::enqueue_trusted(&db, &requests, &settings())
        .await
        .expect("enqueue chunk");

    let issued = log.lock().expect("log").len() - base;
    // Ten: node-store upsert (two bounded json_each batches over the
    // chunk's ~3000-node batch) + edge delete + edge insert +
    // edge-flag probe + task insert + task update + dep-requeue +
    // `deps_met` refresh + `dispatch_key` refresh, each a bounded
    // statement count over the whole chunk regardless of request
    // count.
    assert!(
        issued <= 10,
        "a 1000-request chunk must stay a constant statement count \
             (measured 10), got {issued}"
    );
}

// ===== Dispatch freeze (issue #279) =====

/// Claim capacity large enough to seed whole windows of outcomes in
/// one pass.
const fn wide_claim_settings() -> SchedulerSettings {
    SchedulerSettings {
        dispatch: Dispatch::from_max_concurrent_jobs(500),
        dispatch_min_age_minutes: 0,
        ..settings()
    }
}

/// Enqueue then claim `count` tasks on `target`, then complete each
/// one — `Some((error, run_id))` fails it, `None` succeeds —
/// leaving `count` outcomes counted in `attempt_outcome_buckets`
/// (and `count` raw rows in `attempt_outcomes` when all fail).
async fn seed_outcomes(
    db: &DurableDb,
    batch: u32,
    count: usize,
    target: &str,
    failure: Option<(&str, &str)>,
) {
    // Names carry the batch: a repeat name re-requests a task whose
    // own retry backoff already hides it from the claim this
    // seeding is about to run.
    let requests: Vec<EnqueueRequest> = (0..count)
        .map(|i| request_on(&format!("outcome-{batch}-{i}"), target, &[]))
        .collect();
    super::enqueue_trusted(db, &requests, &wide_claim_settings())
        .await
        .expect("seed enqueue");
    let claimed = super::claim_dispatchable_tasks(db, &wide_claim_settings(), &NoCoverage)
        .await
        .expect("seed claim");
    assert_eq!(claimed.len(), count);
    for task in claimed {
        let mut report = report(
            &task.task_id,
            &task.generation_id,
            task.attempt,
            failure.is_none(),
        );
        if let Some((error, run_id)) = failure {
            report.error = Some(error.to_owned());
            report.github_run_id = Some(run_id.to_owned());
        }
        super::complete(db, &wide_claim_settings(), &report, TEST_WINDOW_MINUTES)
            .await
            .expect("seed complete");
    }
}

fn freeze_record_fixture() -> stow_types::api::DispatchFreezeRecord {
    stow_types::api::DispatchFreezeRecord {
        frozen_at: "2026-09-22T03:51:00Z".to_owned(),
        trigger: stow_types::api::DispatchFreezeTrigger::Manual,
        notify: stow_types::api::ChannelOutcome::Disabled {
            reason: "test".to_owned(),
        },
    }
}

/// The record's presence is the flag: set reads back, enabled
/// reports true, delete clears both.
#[tokio::test]
async fn freeze_record_roundtrips_and_deletes() {
    let db = memory_db().await.expect("memory db");
    assert!(super::freeze_record(&db).await.expect("read").is_none());
    assert!(!super::freeze_enabled(&db).await.expect("enabled"));

    let record = freeze_record_fixture();
    super::set_freeze(&db, &record).await.expect("set");
    assert!(super::freeze_enabled(&db).await.expect("enabled"));
    let stored = super::freeze_record(&db)
        .await
        .expect("read")
        .expect("stored");
    assert_eq!(stored, record);

    super::delete_freeze(&db).await.expect("delete");
    assert!(!super::freeze_enabled(&db).await.expect("enabled"));
    assert!(super::freeze_record(&db).await.expect("read").is_none());
}

/// While frozen, claim returns nothing and enqueue keeps accepting —
/// and `next_alarm` plans `Delete` so no dispatch pass even wakes.
/// Clearing restores dispatch.
#[tokio::test]
async fn freeze_gates_dispatch_but_not_enqueue_and_clear_resumes() {
    let db = memory_db().await.expect("memory db");
    super::set_freeze(&db, &freeze_record_fixture())
        .await
        .expect("set freeze");

    // Enqueue is unaffected — misses keep arriving.
    enqueue(&db, &[request("frozen-miss", &[])])
        .await
        .expect("enqueue while frozen");
    // Dispatch is not: the claim gate answers empty no matter what
    // is pending.
    assert!(
        super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim while frozen")
            .is_empty()
    );
    let plan = super::next_alarm(&db, ROW_TS_MS, &settings())
        .await
        .expect("next alarm while frozen");
    assert_eq!(plan, AlarmPlan::Delete);

    super::delete_freeze(&db).await.expect("clear");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim after clear");
    assert_eq!(claimed.len(), 1, "the freeze-queued miss dispatches");
}

/// The trip decision reads `attempt_outcomes`, not live queue rows —
/// a retried task keeps every failed attempt inside the window.
#[tokio::test]
async fn evaluate_freeze_trip_reads_attempt_outcomes() {
    let db = memory_db().await.expect("memory db");
    let freeze = crate::freeze::FreezeSettings {
        window_minutes: 60,
        min_outcomes: 10,
        fail_percent: 50,
    };

    // Below the floor the ratio never trips, whatever it reads.
    seed_outcomes(&db, 0, 9, TARGET, Some(("build-crate 500", "run-1"))).await;
    assert!(
        super::evaluate_freeze_trip(&db, &freeze)
            .await
            .expect("evaluate")
            .is_none(),
        "9/9 failures under a floor of 10 must not trip"
    );

    // Crossing the floor *and* the ratio trips; the draft carries
    // the class tally and example run ids the alert prints.
    seed_outcomes(&db, 1, 1, TARGET, None).await;
    seed_outcomes(&db, 2, 1, TARGET, Some(("build-crate 500", "run-2"))).await;
    let draft = super::evaluate_freeze_trip(&db, &freeze)
        .await
        .expect("evaluate")
        .expect("10 failures of 11 outcomes trips (>= 10 sample, 91% >= 50%)");
    assert!(draft.eval.fleet_tripped);
    assert_eq!(draft.eval.outcomes, 11);
    assert_eq!(draft.eval.failures, 10);
    assert_eq!(
        draft.classes.first().map(|class| class.class.as_str()),
        Some("build-crate 500"),
        "the dominant class names the error's first line"
    );
    assert_eq!(draft.classes.first().map(|class| class.count), Some(10));
    assert_eq!(
        draft.example_run_ids,
        vec!["run-2".to_owned(), "run-1".to_owned()],
        "freshest failing run ids first"
    );
}

/// A failure wave concentrated on one target trips that target's
/// stream even when the fleet aggregate stays under the ratio.
#[tokio::test]
async fn evaluate_freeze_trip_trips_a_single_target_stream() {
    let db = memory_db().await.expect("memory db");
    let freeze = crate::freeze::FreezeSettings {
        window_minutes: 60,
        min_outcomes: 10,
        fail_percent: 50,
    };
    // 10/10 on the Windows leg, all green on Linux: fleet 10/30 =
    // 33% stays quiet; the target trips alone.
    seed_outcomes(&db, 0, 20, TARGET, None).await;
    seed_outcomes(
        &db,
        1,
        10,
        WINDOWS_TARGET,
        Some(("linker exploded", "run-9")),
    )
    .await;
    let draft = super::evaluate_freeze_trip(&db, &freeze)
        .await
        .expect("evaluate")
        .expect("the concentrated stream trips");
    assert!(!draft.eval.fleet_tripped);
    let tripped: Vec<&str> = draft
        .eval
        .targets
        .iter()
        .filter(|target| target.tripped)
        .map(|target| target.target.as_str())
        .collect();
    assert_eq!(tripped, [WINDOWS_TARGET]);
}

/// The exact boundary is inclusive: `failures*100 >=
/// outcomes*fail_percent` at the sample floor.
#[tokio::test]
async fn freeze_trip_boundary_is_inclusive() {
    let db = memory_db().await.expect("memory db");
    let freeze = crate::freeze::FreezeSettings {
        window_minutes: 60,
        min_outcomes: 10,
        fail_percent: 50,
    };
    seed_outcomes(&db, 0, 5, TARGET, None).await;
    seed_outcomes(&db, 1, 5, TARGET, Some(("boom", "run-1"))).await;
    assert!(
        super::evaluate_freeze_trip(&db, &freeze)
            .await
            .expect("evaluate")
            .is_some(),
        "5/10 failures at a 50% threshold trips"
    );
}

/// A completion's read set must stay constant as the outcome window
/// fills — a wave of N completions cannot cost N rows per
/// completion (the raw-row design read the whole in-window log:
/// a wave of N completions read about N²/2 rows). Seed the window
/// with 10, then 10,000 outcomes and measure the rows a failing
/// completion plus its trip evaluation read: identical at both
/// volumes.
#[tokio::test]
async fn a_completion_reads_a_constant_row_count_as_the_window_fills() {
    let freeze = crate::freeze::FreezeSettings {
        window_minutes: TEST_WINDOW_MINUTES,
        min_outcomes: 10,
        fail_percent: 50,
    };
    let mut reads = Vec::new();
    for volume in [10usize, 10_000] {
        let (db, log) = counting_memory_db().await.expect("counting db");
        // Fill the window the way a failure wave leaves it: twelve
        // in-window buckets totaling `volume` outcomes (all
        // failures), plus `volume` raw failure rows — the evidence
        // the trip alert reads.
        let per_bucket = i64::try_from(volume.div_ceil(12)).expect("fits");
        db.query(
                "WITH RECURSIVE seq(x) AS (                     SELECT 0 UNION ALL SELECT x + 1 FROM seq WHERE x < 11                 )                  INSERT INTO attempt_outcome_buckets (target, bucket, outcomes, failures)                  SELECT ?, (unixepoch('now') / 300) * 300 - x * 300, ?, ? FROM seq",
            )
            .bind(TARGET)
            .bind(per_bucket)
            .bind(per_bucket)
            .execute()
            .await
            .expect("seed buckets");
        db.query(
                "WITH RECURSIVE seq(x) AS (                     SELECT 1 UNION ALL SELECT x + 1 FROM seq WHERE x <= ?                 )                  INSERT INTO attempt_outcomes_v2                      (task_id, generation_id, attempt, target, failure_class,                       github_run_id, finished_at)                  SELECT 'seed-' || x, 'seed-generation-' || x, 1, ?, 'boom',                         'run-' || x, datetime('now', '-' || (x % 50) || ' minutes')                  FROM seq",
            )
            .bind(i64::try_from(volume).expect("fits"))
            .bind(TARGET)
            .execute()
            .await
            .expect("seed failure rows");

        // The measured completion: a live task reports a failure,
        // then the trip evaluation runs — the production handler's
        // exact read path.
        enqueue(&db, &[request("measured", &[])])
            .await
            .expect("enqueue");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        let base = log.lock().expect("log").len();
        super::complete(
            &db,
            &claim_settings(),
            &super::BuildCompleteReport {
                task_id: claimed[0].task_id.clone(),
                generation_id: claimed[0].generation_id.clone(),
                attempt: claimed[0].attempt,
                success: false,
                error: Some("boom".to_owned()),
                finished_at: None,
                github_run_id: Some("run-live".to_owned()),
            },
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete");
        super::evaluate_freeze_trip(&db, &freeze)
            .await
            .expect("evaluate");
        let read: u64 = log.lock().expect("log")[base..]
            .iter()
            .map(|entry| entry.rows_read)
            .sum();
        reads.push(read);
    }
    assert_eq!(
        reads[0], reads[1],
        "a completion over 10 stored outcomes read {} rows; over 10,000 \
             it read {} — the read set must be window-bounded, not volume-\
             bounded",
        reads[0], reads[1]
    );
}
/// `POST /requests` input for `crate_name` — mirrors the edge's
/// admission after version/rustc resolution.
fn admission(crate_name: &str) -> stow_types::api::RequestAdmission {
    stow_types::api::RequestAdmission {
        request_id: stow_types::api::request_id(crate_name, VERSION, FEATURES, RUSTC),
        crate_name: crate_name.parse().expect("request crate"),
        version: VERSION.parse().expect("request version"),
        features_json: FeaturesJson::default(),
        rustc_version: RUSTC.parse().expect("request rustc"),
        max_closure: 500,
    }
}

fn resolved_report(attempt: u32, crate_name: &str) -> stow_types::api::RequestOutcomeReport {
    use stow_types::api::{RequestOutcome, RequestOutcomeReport, RequestRootOutcome};
    let task = EnqueueRequest {
        source: EnqueueSource::HumanRequest,
        ..request(crate_name, &[dependency("dep")])
    };
    RequestOutcomeReport {
        attempt,
        outcome: RequestOutcome::Resolved {
            tasks: vec![task.clone()],
            roots: vec![RequestRootOutcome {
                target: TARGET.parse().expect("target"),
                task_id: Some(task.task_id().expect("resolved task id")),
                cached: false,
            }],
        },
    }
}

#[tokio::test]
async fn request_admission_dedups_and_re_attempts_a_failed_record() {
    let db = memory_db().await.expect("memory db");
    let admission = admission("req-crate");

    let step = super::admit_request(&db, &admission, 1_000, &settings())
        .await
        .expect("first admit");
    assert!(matches!(
        step,
        super::RequestAdmissionStep::Dispatch { attempt: 1 }
    ));
    let status = super::crate_request_status(&db, &admission.request_id)
        .await
        .expect("status")
        .expect("record");
    assert_eq!(status.status, stow_types::api::CrateRequestPhase::Accepted);

    // Same request id again — the live record answers, no re-dispatch.
    let step = super::admit_request(&db, &admission, 2_000, &settings())
        .await
        .expect("second admit");
    assert!(matches!(step, super::RequestAdmissionStep::Existing));

    // A `failed` record re-attempts at `attempt + 1` in one write.
    super::fail_request_dispatch(&db, &admission.request_id, 1, "dispatch refused")
        .await
        .expect("fail");
    let step = super::admit_request(&db, &admission, 3_000, &settings())
        .await
        .expect("re-attempt admit");
    assert!(matches!(
        step,
        super::RequestAdmissionStep::Dispatch { attempt: 2 }
    ));
    let status = super::crate_request_status(&db, &admission.request_id)
        .await
        .expect("status")
        .expect("record");
    assert_eq!(status.status, stow_types::api::CrateRequestPhase::Accepted);
    assert_eq!(status.error, None);
}

#[tokio::test]
async fn request_admission_refuses_when_the_day_is_spent() {
    let db = memory_db().await.expect("memory db");
    db.query(
        "INSERT INTO human_daily_task_budget (day, task_count) \
             VALUES (date('now'), ?)",
    )
    .bind(i64::from(settings().human_daily_task_budget))
    .execute()
    .await
    .expect("seed spent day");
    let error = super::admit_request(&db, &admission("req-crate"), 1_000, &settings())
        .await
        .expect_err("spent day refuses admission");
    assert!(matches!(
        error,
        QueueError::HumanDailyBudgetExhausted { .. }
    ));
}

#[tokio::test]
async fn request_run_updates_drive_the_lifecycle() {
    let db = memory_db().await.expect("memory db");
    let admission = admission("req-crate");
    super::admit_request(&db, &admission, 1_000, &settings())
        .await
        .expect("admit");

    super::record_request_run_update(
        &db,
        &admission.request_id,
        &stow_types::api::RequestRunUpdate {
            attempt: 1,
            action: stow_types::api::RequestRunAction::InProgress,
            conclusion: None,
            run_id: Some("9".to_owned()),
            run_url: Some("https://example/run/9".to_owned()),
        },
    )
    .await
    .expect("in_progress");
    let status = super::crate_request_status(&db, &admission.request_id)
        .await
        .expect("status")
        .expect("record");
    assert_eq!(status.status, stow_types::api::CrateRequestPhase::Resolving);
    assert_eq!(status.github_run_id.as_deref(), Some("9"));

    // A `completed` delivery on a live record is the failure
    // backstop: the resolve reported no outcome.
    super::record_request_run_update(
        &db,
        &admission.request_id,
        &stow_types::api::RequestRunUpdate {
            attempt: 1,
            action: stow_types::api::RequestRunAction::Completed,
            conclusion: Some("success".to_owned()),
            run_id: Some("9".to_owned()),
            run_url: Some("https://example/run/9".to_owned()),
        },
    )
    .await
    .expect("completed");
    let status = super::crate_request_status(&db, &admission.request_id)
        .await
        .expect("status")
        .expect("record");
    assert_eq!(status.status, stow_types::api::CrateRequestPhase::Failed);
    assert!(
        status
            .error
            .as_deref()
            .is_some_and(|error| error.contains("outcome report")),
        "the backstop names why the record failed: {:?}",
        status.error
    );
}

#[tokio::test]
async fn request_run_update_refuses_a_stale_attempt() {
    let db = memory_db().await.expect("memory db");
    let admission = admission("req-crate");
    super::admit_request(&db, &admission, 1_000, &settings())
        .await
        .expect("admit");
    let error = super::record_request_run_update(
        &db,
        &admission.request_id,
        &stow_types::api::RequestRunUpdate {
            attempt: 9,
            action: stow_types::api::RequestRunAction::InProgress,
            conclusion: None,
            run_id: None,
            run_url: None,
        },
    )
    .await
    .expect_err("attempt 9 is stale");
    assert!(matches!(error, QueueError::RequestAttemptSuperseded { .. }));
}

#[tokio::test]
async fn request_outcome_enqueues_and_settles_the_record() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("dep", &[])])
        .await
        .expect("enqueue dep");
    let admission = admission("req-crate");
    super::admit_request(&db, &admission, 1_000, &settings())
        .await
        .expect("admit");

    let status = super::apply_request_outcome(
        &db,
        &settings(),
        &admission.request_id,
        &resolved_report(1, "req-crate"),
    )
    .await
    .expect("outcome");
    assert_eq!(status.status, stow_types::api::CrateRequestPhase::Enqueued);
    assert_eq!(status.targets.len(), 1);
    assert_eq!(
        status.targets[0].state,
        stow_types::api::CrateRequestState::Queued
    );

    // The root task landed as a pending human-lane row.
    let lane: String = db
        .query("SELECT lane FROM queue WHERE task_id = ?")
        .bind(task_id_with("req-crate", TARGET, &[dependency("dep")]))
        .fetch_scalar::<String>()
        .await
        .expect("read task lane");
    let status_row: String = db
        .query("SELECT status FROM queue WHERE task_id = ?")
        .bind(task_id_with("req-crate", TARGET, &[dependency("dep")]))
        .fetch_scalar::<String>()
        .await
        .expect("read task status");
    assert_eq!((lane.as_str(), status_row.as_str()), ("human", "pending"));

    // A second identical report is a no-op read of the settled
    // record — not a re-enqueue.
    let again = super::apply_request_outcome(
        &db,
        &settings(),
        &admission.request_id,
        &resolved_report(1, "req-crate"),
    )
    .await
    .expect("replay");
    assert_eq!(again.status, stow_types::api::CrateRequestPhase::Enqueued);

    // And a `completed` webhook delivery afterward must not claw the
    // settled record back to `failed` — the conditional write's
    // whole point (stow#428 review).
    super::record_request_run_update(
        &db,
        &admission.request_id,
        &stow_types::api::RequestRunUpdate {
            attempt: 1,
            action: stow_types::api::RequestRunAction::Completed,
            conclusion: Some("failure".to_owned()),
            run_id: None,
            run_url: None,
        },
    )
    .await
    .expect("completed after settle");
    let status = super::crate_request_status(&db, &admission.request_id)
        .await
        .expect("status")
        .expect("record");
    assert_eq!(status.status, stow_types::api::CrateRequestPhase::Enqueued);
}

#[tokio::test]
async fn request_outcome_failed_marks_the_record() {
    let db = memory_db().await.expect("memory db");
    let admission = admission("req-crate");
    super::admit_request(&db, &admission, 1_000, &settings())
        .await
        .expect("admit");
    let status = super::apply_request_outcome(
        &db,
        &settings(),
        &admission.request_id,
        &stow_types::api::RequestOutcomeReport {
            attempt: 1,
            outcome: stow_types::api::RequestOutcome::Failed {
                error: "resolve: no semver-compatible version".to_owned(),
            },
        },
    )
    .await
    .expect("failed outcome");
    assert_eq!(status.status, stow_types::api::CrateRequestPhase::Failed);
    assert_eq!(
        status.error.as_deref(),
        Some("resolve: no semver-compatible version")
    );
}

#[tokio::test]
async fn request_outcome_refuses_a_stale_attempt() {
    let db = memory_db().await.expect("memory db");
    let admission = admission("req-crate");
    super::admit_request(&db, &admission, 1_000, &settings())
        .await
        .expect("admit");
    let error = super::apply_request_outcome(
        &db,
        &settings(),
        &admission.request_id,
        &resolved_report(2, "req-crate"),
    )
    .await
    .expect_err("attempt 2 is stale");
    assert!(matches!(error, QueueError::RequestAttemptSuperseded { .. }));
}

// ---- stow#524: expected build cost ----

/// Claim, pin the claim instant `minutes_ago` back, bind a run and
/// complete it successfully — one honest sample of the path a real
/// build takes. `claimed_at` is pinned by raw UPDATE for the same
/// reason `mark_active` writes `updated_at` directly: no public
/// function produces a past claim stamp, and the pin must be exact
/// for a deterministic duration assertion.
async fn complete_success_at_minutes(db: &DurableDb, task_id: &str, run: &str, minutes_ago: u32) {
    let claimed = super::claim_dispatchable_tasks(db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim")[0]
        .clone();
    db.query("UPDATE queue SET claimed_at = datetime('now', ?) WHERE task_id = ?")
        .bind(format!("-{minutes_ago} minutes"))
        .bind(task_id.to_owned())
        .execute()
        .await
        .expect("pin claim instant");
    super::bind_dispatch_run(db, task_id, &claimed.generation_id, run)
        .await
        .expect("bind run");
    super::complete_run(
        db,
        &settings(),
        &report_with_run(task_id, true, run),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete");
}

#[derive(skyzen::FromRow)]
struct BuildStatRow {
    builds: i64,
    median_ms: i64,
}

/// `EXPLAIN QUERY PLAN` detail rows — only the plan text matters.
#[derive(skyzen::FromRow)]
struct PlanRow {
    detail: String,
}

async fn build_stats(db: &DurableDb, crate_name: &str) -> Option<BuildStatRow> {
    db.query(
        "SELECT builds, median_ms FROM crate_build_stats \
             WHERE crate_name = ? AND target = ?",
    )
    .bind(crate_name.to_owned())
    .bind(TARGET)
    .fetch_optional::<BuildStatRow>()
    .await
    .expect("build stats")
}

async fn sample_count(db: &DurableDb, crate_name: &str) -> i64 {
    db.query("SELECT count(*) FROM crate_build_samples WHERE crate_name = ?")
        .bind(crate_name.to_owned())
        .fetch_scalar::<i64>()
        .await
        .expect("sample count")
}

/// The in-flight re-request writer rewrites `updated_at` even on an
/// active task — a resubmitted build's duration must still measure
/// from the claim's immutable `claimed_at`, not the mutable stamp.
#[tokio::test]
async fn build_duration_samples_the_immutable_claim_instant() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("durable", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("durable", TARGET);
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim")[0]
        .clone();
    super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-1")
        .await
        .expect("bind");
    // Pin the claim instant BEFORE the resubmission so a writer
    // that clobbered `claimed_at` would be caught rather than
    // masked: the pin must survive the in-flight writer verbatim.
    db.query("UPDATE queue SET claimed_at = datetime('now', '-1 hour') WHERE task_id = ?")
        .bind(id.clone())
        .execute()
        .await
        .expect("pin claim instant");
    let pinned = row_column(&db, "durable", "claimed_at").await;
    // The resubmission: `apply_batched_updates` rewrites
    // `updated_at` on the in-flight row.
    enqueue(&db, &[request("durable", &[])])
        .await
        .expect("in-flight resubmission");
    let claimed_at = row_column(&db, "durable", "claimed_at").await;
    let updated_at = row_column(&db, "durable", "updated_at").await;
    assert_eq!(claimed_at, pinned, "the resubmit rewrote claimed_at");
    assert_ne!(claimed_at, updated_at, "the resubmit moved updated_at");

    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, true, "run-1"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete");

    let duration = db
        .query("SELECT duration_ms FROM crate_build_samples WHERE crate_name = 'durable'")
        .fetch_scalar::<i64>()
        .await
        .expect("duration sample");
    assert!(
        (3_500_000..=3_700_000).contains(&duration),
        "claim-to-completion ~1h, not resubmit-to-completion ~0: {duration}"
    );
    let stats = build_stats(&db, "durable").await.expect("stats row exists");
    assert_eq!(stats.builds, 1);
    assert_eq!(stats.median_ms, duration);
}

/// A deferred completion — the webhook landed while the row's
/// `github_run_id` was still `NULL`, so it parked in
/// `pending_run_completions` — measures claim-to-`received_at`, the
/// instant the run actually finished, not the later binding moment.
#[tokio::test]
async fn deferred_completion_measures_duration_at_received_at() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("deferred", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("deferred", TARGET);
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim")[0]
        .clone();
    db.query("UPDATE queue SET claimed_at = datetime('now', '-1 hour') WHERE task_id = ?")
        .bind(id.clone())
        .execute()
        .await
        .expect("pin claim instant");
    // The report arrives with no run bound yet — it parks, stamping
    // `received_at` at arrival.
    assert!(
        super::persist_pending_completion(&db, &report_with_run(&id, true, "run-def"))
            .await
            .expect("park completion")
    );
    super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-def")
        .await
        .expect("bind run");
    super::apply_pending_completion_for_binding(
        &db,
        &settings(),
        &id,
        &claimed.generation_id,
        "run-def",
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("apply bound completion");

    let duration = db
        .query("SELECT duration_ms FROM crate_build_samples WHERE crate_name = 'deferred'")
        .fetch_scalar::<i64>()
        .await
        .expect("duration sample");
    assert!(
        (3_500_000..=3_700_000).contains(&duration),
        "claim-to-received_at ~1h: {duration}"
    );
}

/// A measured claim-to-completion span is nonnegative by
/// construction; a report whose finish precedes its claim (skewed
/// `finished_at`, a future `claimed_at`) must fail the sample
/// insert through the column's `CHECK (duration_ms >= 0)` — the
/// span is never clamped into a bogus zero. The failed statement
/// must leave no trace: no sample, no stats row, no median and no
/// key refresh off it. A legitimately zero-length span (sub-ms
/// build) still records and floors its median to the 1ms unit.
#[tokio::test]
async fn backward_completion_span_fails_without_polluting_stats() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("skewed", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("skewed", TARGET);
    let report = super::BuildCompleteReport {
        task_id: id,
        generation_id: "gen-skew".to_owned(),
        attempt: 1,
        success: true,
        error: None,
        github_run_id: Some("run-skew".to_owned()),
        finished_at: Some(ROW_TS.to_owned()),
    };
    // Claim stamped after the reported finish — a negative span.
    let error =
        super::record_build_sample(&db, &report, "skewed", TARGET, Some("2099-01-01 00:00:00"))
            .await
            .expect_err("negative measured span fails");
    assert!(
        error.to_string().contains("record build sample"),
        "statement error, not a silent write: {error}"
    );
    let count = db
        .query(
            "SELECT (SELECT count(*) FROM crate_build_samples) + \
                 (SELECT count(*) FROM crate_build_stats) AS n",
        )
        .fetch_scalar::<i64>()
        .await
        .expect("cost state count");
    assert_eq!(count, 0, "no sample/stats/window pollution");

    // The legitimate zero-length span records and floors to the
    // 1ms unit at the stats write.
    let same = super::BuildCompleteReport {
        finished_at: Some(ROW_TS.to_owned()),
        ..report
    };
    super::record_build_sample(&db, &same, "skewed", TARGET, Some(ROW_TS))
        .await
        .expect("zero-length span records");
    let median = db
        .query("SELECT median_ms FROM crate_build_stats WHERE crate_name = 'skewed'")
        .fetch_scalar::<i64>()
        .await
        .expect("median");
    assert_eq!(median, 1, "0ms span floors to the 1ms unit");
}

/// One task's stored key prefix — the 65-char lane+score field the
/// rank assertions compare.
async fn prefix_of(db: &DurableDb, name: &str) -> String {
    db.query("SELECT substr(dispatch_key, 1, 65) AS p FROM queue WHERE crate_name = ?")
        .bind(name.to_owned())
        .fetch_scalar::<String>()
        .await
        .expect("prefix")
}

async fn status_of(db: &DurableDb, name: &str) -> String {
    db.query("SELECT status FROM queue WHERE crate_name = ?")
        .bind(name.to_owned())
        .fetch_scalar::<String>()
        .await
        .expect("status")
}

/// The key prefix the same operands derive at the moved cost —
/// what every repriced row must carry.
fn repriced_prefix() -> String {
    crate::scheduler::rank::rank_prefix("miss", 100, std::num::NonZero::new(1000).unwrap())
}

/// The shared fixture: five fresh-keyed rows whose stored keys go
/// stale the moment a cost lands underneath them — each named for
/// the re-entry path it exercises, `waiter` the non-transitioned
/// control.
async fn reentry_fixture() -> (DurableDb, String) {
    let db = memory_db().await.expect("memory db");
    enqueue(
        &db,
        &[
            request("retried", &[]),
            request("failed-dispatch", &[]),
            request("stale", &[]),
            request("shaped", &[]),
            request("waiter", &[dependency("shaped")]),
        ],
    )
    .await
    .expect("enqueue");
    // Fresh keys at cost 1 (no stats yet); then the cost moves
    // underneath them — each row's stored key is now stale.
    for name in ["retried", "failed-dispatch", "stale", "shaped", "waiter"] {
        db.query(
            "INSERT INTO crate_build_stats \
                 (crate_name, target, builds, median_ms) \
                 VALUES (?, ?, 3, 1000)",
        )
        .bind(name.to_owned())
        .bind(TARGET)
        .execute()
        .await
        .expect("move cost");
        db.query("UPDATE queue SET priority = 100 WHERE crate_name = ?")
            .bind(name.to_owned())
            .execute()
            .await
            .expect("set priority");
    }
    let stale_prefix = prefix_of(&db, "retried").await;
    for name in ["failed-dispatch", "stale", "shaped", "waiter"] {
        assert_eq!(
            prefix_of(&db, name).await,
            stale_prefix,
            "{name} starts on the cost-1 key"
        );
    }
    (db, stale_prefix)
}

/// Every nonpending→pending re-entry reprices through the shared
/// refresh: a row whose key was written before a cost move must
/// leave the transition carrying the new cost's rank — on the
/// operator `Retry` and on `mark_dispatch_failed` here, on the
/// stale-lease recovery and the incomplete-shape requeue in the
/// sibling test — while rows that did not transition keep their
/// keys byte-for-byte.
#[tokio::test]
async fn retry_and_dispatch_failure_reprice_against_moved_cost() {
    let (db, _stale) = reentry_fixture().await;
    let priced = repriced_prefix;

    // Operator Retry: failed → pending.
    db.query("UPDATE queue SET status = 'failed' WHERE crate_name = 'retried'")
        .execute()
        .await
        .expect("park failed");
    let selector = super::QueueSelector {
        task_ids: vec![task_id_on("retried", TARGET)],
        ..Default::default()
    };
    super::apply_mutation(&db, &settings(), super::QueueMutation::Retry, &selector)
        .await
        .expect("retry");
    assert_eq!(status_of(&db, "retried").await, "pending");
    assert_eq!(prefix_of(&db, "retried").await, priced());

    // mark_dispatch_failed: dispatched (run unbound) → pending.
    db.query(
        "UPDATE queue SET status = 'dispatched', generation_id = 'gen-fd' \
             WHERE crate_name = 'failed-dispatch'",
    )
    .execute()
    .await
    .expect("mark dispatched");
    super::mark_dispatch_failed(
        &db,
        &settings(),
        &task_id_on("failed-dispatch", TARGET),
        "gen-fd",
        "workflow_dispatch failed",
    )
    .await
    .expect("dispatch failure");
    assert_eq!(status_of(&db, "failed-dispatch").await, "pending");
    assert_eq!(prefix_of(&db, "failed-dispatch").await, priced());
}

/// The other two nonpending→pending paths — see
/// [`retry_and_dispatch_failure_reprice_against_moved_cost`].
#[tokio::test]
async fn stale_recovery_and_shape_requeue_reprice_against_moved_cost() {
    let (db, stale_prefix) = reentry_fixture().await;
    let priced = repriced_prefix;

    // Stale-lease recovery: running, past the stale window → pending.
    db.query(
        "UPDATE queue SET status = 'running', updated_at = datetime('now', '-2 days') \
             WHERE crate_name = 'stale'",
    )
    .execute()
    .await
    .expect("mark stale");
    super::recover_stale_active_tasks(&db, &settings())
        .await
        .expect("recover stale");
    assert_eq!(status_of(&db, "stale").await, "pending");
    assert_eq!(prefix_of(&db, "stale").await, priced());

    // Incomplete-shape requeue: completed dep → pending once.
    db.query("UPDATE queue SET status = 'completed' WHERE crate_name = 'shaped'")
        .execute()
        .await
        .expect("mark completed");
    db.query(
        "UPDATE queue_dependencies SET dep_crate_name = 'shaped', \
                 dep_host_side = 0, dep_met = 0 \
             WHERE task_id = ? AND depends_on_task_id = ?",
    )
    .bind(task_id_on("waiter", TARGET))
    .bind(task_id_on("shaped", TARGET))
    .execute()
    .await
    .expect("resolve edge identity");
    super::requeue_incomplete_shape_deps(&db, &settings())
        .await
        .expect("shape requeue");
    assert_eq!(status_of(&db, "shaped").await, "pending");
    assert_eq!(prefix_of(&db, "shaped").await, priced());

    // The non-transitioned row keeps its stale key byte-for-byte:
    // only the refresh's own cost-move path may reprice it.
    assert_eq!(prefix_of(&db, "waiter").await, stale_prefix);
}

/// The statistic is the window's lower median — durations 1, 2,
/// and 100 minutes report 2 minutes, where a moving mean would
/// report ~34 — and the window never grows past
/// `BUILD_SAMPLE_WINDOW` however many samples land.
#[tokio::test]
async fn build_stats_median_is_a_real_median_over_a_bounded_window() {
    let db = memory_db().await.expect("memory db");
    let versions = ["1.0.0", "1.1.0", "1.2.0"];
    let minutes = [1, 2, 100];
    for (version, minutes_ago) in versions.iter().zip(minutes) {
        let mut request = request_on("median", TARGET, &[]);
        request.version = version.parse().expect("semver");
        let id = request.task_id().expect("request task id");
        enqueue(&db, &[request]).await.expect("enqueue");
        complete_success_at_minutes(&db, &id, &format!("run-{version}"), minutes_ago).await;
    }
    let stats = build_stats(&db, "median").await.expect("stats row");
    assert_eq!(stats.builds, 3);
    assert!(
        (110_000..=130_000).contains(&stats.median_ms),
        "lower median of 1/2/100 min is 2 min, not the ~34-min mean: {}",
        stats.median_ms
    );

    // The window caps at BUILD_SAMPLE_WINDOW: enough further
    // completions to overflow it leave exactly the bound.
    for round in 0..(super::BUILD_SAMPLE_WINDOW + 3) {
        let version = format!("2.0.{round}");
        let mut request = request_on("median", TARGET, &[]);
        request.version = version.parse().expect("semver");
        let id = request.task_id().expect("request task id");
        enqueue(&db, &[request]).await.expect("enqueue");
        complete_success_at_minutes(&db, &id, &format!("run-b{round}"), 3).await;
    }
    assert_eq!(
        sample_count(&db, "median").await,
        super::BUILD_SAMPLE_WINDOW
    );
    assert_eq!(
        build_stats(&db, "median").await.expect("stats row").builds,
        3 + super::BUILD_SAMPLE_WINDOW + 3
    );
}

/// The generation fence reaches the sample path: a replayed report
/// for a consumed generation and a report naming a generation that
/// was never live are both rejected before they can record a
/// duration, and a failure never samples at all.
#[tokio::test]
async fn stale_duplicate_and_failed_reports_never_sample() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("fenced", &[])])
        .await
        .expect("enqueue");
    let id = task_id_on("fenced", TARGET);
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim")[0]
        .clone();
    super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-f")
        .await
        .expect("bind");
    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, true, "run-f"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("complete");
    assert_eq!(sample_count(&db, "fenced").await, 1);

    let replay = super::complete_run(
        &db,
        &settings(),
        &report_with_run(&id, true, "run-f"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect_err("replayed completion conflicts");
    assert!(matches!(replay, QueueError::StaleCompletion { .. }));
    let ghost = super::complete(
        &db,
        &settings(),
        &report(&id, "never-live-generation", 1, true),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect_err("old-generation report conflicts");
    assert!(matches!(ghost, QueueError::StaleCompletion { .. }));
    assert_eq!(
        sample_count(&db, "fenced").await,
        1,
        "rejected reports added no samples"
    );

    enqueue(&db, &[request("failonly", &[])])
        .await
        .expect("enqueue");
    let fail_id = task_id_on("failonly", TARGET);
    let failed_claim = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim")[0]
        .clone();
    super::bind_dispatch_run(&db, &fail_id, &failed_claim.generation_id, "run-x")
        .await
        .expect("bind");
    super::complete_run(
        &db,
        &settings(),
        &report_with_run(&fail_id, false, "run-x"),
        TEST_WINDOW_MINUTES,
    )
    .await
    .expect("failure completes");
    assert_eq!(
        sample_count(&db, "failonly").await,
        0,
        "a truncated failure run prices no build"
    );
}

/// Cost divides the demand operand inside a band: at equal
/// priority the crate the stats call cheaper claims first, while
/// the bands stay absolute — an unmeasured cheap miss can never
/// outrank a measured expensive human task.
#[tokio::test]
async fn cheaper_expected_build_claims_first_inside_a_band() {
    let db = memory_db().await.expect("memory db");
    db.query(
        "INSERT INTO crate_build_stats (crate_name, target, builds, median_ms) \
             VALUES ('pricey', ?, 5, 3600000)",
    )
    .bind(TARGET)
    .execute()
    .await
    .expect("seed pricey stats");
    let expensive = stow_types::api::EnqueueRequest {
        downloads: 5_000_000,
        ..request("pricey", &[])
    };
    let cheap = stow_types::api::EnqueueRequest {
        downloads: 5_000_000,
        ..request("cheap", &[])
    };
    enqueue(&db, &[expensive, cheap]).await.expect("enqueue");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed[0].crate_name, "cheap", "cost-divided rank");

    // Bands still win: a pricey human-lane task claims ahead of an
    // unmeasured miss however cheap the miss looks.
    let db = memory_db().await.expect("memory db");
    db.query(
        "INSERT INTO crate_build_stats (crate_name, target, builds, median_ms) \
             VALUES ('hpricey', ?, 5, 3600000)",
    )
    .bind(TARGET)
    .execute()
    .await
    .expect("seed pricey stats");
    let human = stow_types::api::EnqueueRequest {
        downloads: 5_000_000,
        source: EnqueueSource::HumanRequest,
        ..request("hpricey", &[])
    };
    let miss = stow_types::api::EnqueueRequest {
        downloads: 5_000_000,
        ..request("mcheap", &[])
    };
    super::enqueue_trusted(&db, &[human, miss], &settings())
        .await
        .expect("enqueue");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(
        claimed[0].crate_name, "hpricey",
        "band precedence is undivided"
    );
}

/// Equal score operands keep `value`'s FIFO: same band, same
/// priority, same cost answer → `first_requested_at` decides.
#[tokio::test]
async fn equal_scores_keep_fifo_order() {
    let db = memory_db().await.expect("memory db");
    let first = stow_types::api::EnqueueRequest {
        downloads: 5_000_000,
        ..request("fifo-first", &[])
    };
    let second = stow_types::api::EnqueueRequest {
        downloads: 5_000_000,
        ..request("fifo-second", &[])
    };
    enqueue(&db, &[first, second]).await.expect("enqueue");
    db.query(
        "UPDATE queue SET first_requested_at = '2025-01-01 00:00:00' \
             WHERE crate_name = 'fifo-first'",
    )
    .execute()
    .await
    .expect("age the first request");
    // The instant is baked into the key — the same keyed refresh
    // every operand move takes rewrites it.
    super::refresh_dispatch_keys(&db, &[task_id_on("fifo-first", TARGET)])
        .await
        .expect("refresh aged key");
    let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
        .await
        .expect("claim");
    assert_eq!(claimed[0].crate_name, "fifo-first");
}

/// The stats probe correlates to the outer row on every recompute
/// path: two crates with different medians must each price by
/// their own (`crate_name`, `target`) row through a resubmit's key
/// refresh, a promote and a median move — not whatever stats row
/// the table yields first (stow#524 review: an unqualified probe
/// collapses to `s.crate_name = s.crate_name` and answers one
/// median for every row).
#[tokio::test]
async fn refreshed_scores_price_their_own_crate_target() {
    let db = memory_db().await.expect("memory db");
    // 'dear' lands in the table first, so a broken probe hands its
    // median to every row and makes 'cheap' indistinguishable.
    db.query(
        "INSERT INTO crate_build_stats (crate_name, target, builds, median_ms) \
             VALUES ('dear', ?, 5, 3600000), ('cheap', ?, 5, 36000), ('cheap', ?, 5, 999999)",
    )
    .bind(TARGET)
    .bind(TARGET)
    .bind(MACOS_TARGET)
    .execute()
    .await
    .expect("seed stats");
    let dear = stow_types::api::EnqueueRequest {
        downloads: 5_000_000,
        ..request("dear", &[])
    };
    let cheap = stow_types::api::EnqueueRequest {
        downloads: 5_000_000,
        ..request("cheap", &[])
    };
    let mac = stow_types::api::EnqueueRequest {
        downloads: 5_000_000,
        ..request_on("cheap", MACOS_TARGET, &[])
    };
    enqueue(&db, &[dear, cheap, mac]).await.expect("enqueue");

    let prefix = async |db: &DurableDb, name: &str, target: &str| -> String {
        db.query(
            "SELECT substr(dispatch_key, 1, 65) AS p FROM queue \
                 WHERE crate_name = ? AND target = ?",
        )
        .bind(name.to_owned())
        .bind(target.to_owned())
        .fetch_scalar::<String>()
        .await
        .expect("score prefix")
    };
    // A resubmit recomputes each touched row's key: a broken probe
    // leaves every row at 'dear''s cost and the prefixes tie.
    enqueue(&db, &[request("dear", &[]), request("cheap", &[])])
        .await
        .expect("resubmit");
    assert!(
        prefix(&db, "cheap", TARGET).await < prefix(&db, "dear", TARGET).await,
        "refreshed keys price each row's own cost"
    );
    // Target discriminates too: 'cheap' on macOS has its own
    // (crate, target) median, not the Linux row's.
    assert!(
        prefix(&db, "cheap", MACOS_TARGET).await > prefix(&db, "cheap", TARGET).await,
        "same crate on a pricier target scores lower"
    );

    // Promote recomputes the key under the 'human' operand: the
    // cost probe still has to bind to the outer row.
    for name in ["dear", "cheap"] {
        super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Promote,
            &filter_selector(stow_types::api::QueueSelector {
                crate_name: Some(name.parse().expect("crate name")),
                ..Default::default()
            }),
        )
        .await
        .expect("promote");
    }
    assert!(
        prefix(&db, "cheap", TARGET).await < prefix(&db, "dear", TARGET).await,
        "promoted keys price each row's own cost"
    );

    // A median move refreshes only that key's pending set: 'cheap'
    // reprices, 'dear' keeps its key byte-for-byte.
    let dear_key = prefix(&db, "dear", TARGET).await;
    super::record_build_sample(
        &db,
        &super::BuildCompleteReport {
            task_id: task_id_on("cheap", TARGET),
            generation_id: "gen-cost-move".to_owned(),
            attempt: 1,
            success: true,
            error: None,
            github_run_id: None,
            finished_at: None,
        },
        "cheap",
        TARGET,
        Some("2025-01-01 00:00:00"),
    )
    .await
    .expect("cost move sample");
    assert_ne!(
        prefix(&db, "cheap", TARGET).await,
        prefix(&db, "dear", TARGET).await,
        "median move repriced the moved key"
    );
    assert_eq!(
        prefix(&db, "dear", TARGET).await,
        dear_key,
        "an unrelated key is untouched"
    );
}

/// The keyed refresh's probe is served by its partial index, not
/// a crate-wide walk — it reads the same-(crate, target) pending
/// set, never the crate's terminal or other-target history.
#[tokio::test]
async fn cost_move_refresh_uses_the_pending_crate_target_index() {
    let db = memory_db().await.expect("memory db");
    let plan = db
        .query(
            "EXPLAIN QUERY PLAN \
                 SELECT q.task_id FROM queue q \
                 WHERE q.status = 'pending' AND q.crate_name = ? AND q.target = ?",
        )
        .bind("crate0".to_owned())
        .bind(TARGET.to_owned())
        .fetch_all::<PlanRow>()
        .await
        .expect("explain refresh");
    let detail = plan
        .iter()
        .map(|row| row.detail.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        detail.contains("idx_queue_pending_crate_target"),
        "refresh probe should seek the partial index: {detail}"
    );
}

/// The insert cost probe starts from the event's distinct
/// `(crate_name, target)` keys and seeks `crate_build_stats` by
/// its primary key — stored build history of any size stays out
/// of an enqueue's read set (stow#524 review).
#[tokio::test]
async fn insert_cost_probe_seeks_stats_by_pk_only() {
    let db = memory_db().await.expect("memory db");
    // Seed stored history far larger than the batch's distinct
    // keys — a stats-first probe would read all of it.
    db.query(
        "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 \
                                     FROM seq WHERE n < 10000) \
             INSERT INTO crate_build_stats (crate_name, target, builds, median_ms) \
             SELECT 'old' || n, 'x86_64-unknown-linux-gnu', n, n FROM seq",
    )
    .execute()
    .await
    .expect("seed stats history");
    let plan = db
        .query(&format!("EXPLAIN QUERY PLAN {}", super::INSERT_COST_PROBE))
        .bind(super::enqueue_json(&[request("probe", &[])]).expect("json"))
        .fetch_all::<PlanRow>()
        .await
        .expect("explain cost probe");
    let detail = plan
        .iter()
        .map(|row| row.detail.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        detail.contains("SEARCH s") && !detail.contains("SCAN s"),
        "cost probe should PK-seek stats per event key: {detail}"
    );
}

/// The refresh writer itself — not only the pure helper —
/// preserves exactness past `2^53`: adjacent priorities that
/// collapsed under REAL keep distinct exact keys, and an extreme
/// stored median prices through the same writer byte-for-byte as
/// the shared abstraction derives it (stow#524 review).
#[tokio::test]
async fn refresh_writer_preserves_exactness_beyond_f64() {
    let db = memory_db().await.expect("memory db");
    enqueue(&db, &[request("priced", &[]), request("plain", &[])])
        .await
        .expect("enqueue");
    let near = 9_007_199_254_740_992_i64;
    // Wide operands bind as TEXT with a CAST — an i64 bind would
    // itself cross the JSON number boundary and truncate.
    for (name, priority) in [("priced", near), ("plain", near + 1)] {
        db.query("UPDATE queue SET priority = CAST(? AS INTEGER) WHERE task_id = ?")
            .bind(priority.to_string())
            .bind(task_id_on(name, TARGET))
            .execute()
            .await
            .expect("set priority");
    }
    db.query(
        "INSERT INTO crate_build_stats \
             (crate_name, target, builds, median_ms) \
             VALUES ('priced', ?, 3, CAST(? AS INTEGER))",
    )
    .bind(TARGET)
    .bind(i64::MAX.to_string())
    .execute()
    .await
    .expect("seed extreme cost");

    super::refresh_dispatch_keys(
        &db,
        &[task_id_on("priced", TARGET), task_id_on("plain", TARGET)],
    )
    .await
    .expect("refresh keys");

    let prefix = async |db: &DurableDb, name: &str| -> String {
        db.query(
            "SELECT substr(dispatch_key, 1, 65) AS p FROM queue \
                 WHERE crate_name = ? AND target = ?",
        )
        .bind(name.to_owned())
        .bind(TARGET.to_owned())
        .fetch_scalar::<String>()
        .await
        .expect("prefix")
    };
    let priced = prefix(&db, "priced").await;
    let plain = prefix(&db, "plain").await;
    // 'priced' ranks near/(2^63-1) ≈ 1 against 'plain''s near+1 —
    // distinct keys, and each byte-exact the abstraction's output
    // for the row's own operands.
    assert_eq!(
        priced,
        crate::scheduler::rank::rank_prefix(
            "miss",
            near,
            std::num::NonZero::new(i64::MAX).unwrap()
        ),
        "extreme stored median prices exactly through the writer"
    );
    assert_eq!(
        plain,
        crate::scheduler::rank::rank_prefix(
            "miss",
            near + 1,
            crate::scheduler::rank::UNMEASURED_COST
        ),
        "adjacent >2^53 priority keeps its exact key"
    );
    assert!(plain < priced, "the larger exact ratio claims first");
}

/// The additive migration grows `claimed_at` and the build-cost
/// tables on a dev-era queue — the operator route's only schema
/// work — while rows migrated before the column carry no claim
/// stamp and sample nothing.
#[tokio::test]
async fn migration_adds_claim_stamp_and_cost_tables() {
    let db = memory_db_raw().await.expect("raw memory db");
    for statement in [DEV_ERA_QUEUE, DEV_ERA_DEPENDENCIES] {
        db.query(statement).execute().await.expect("dev-era schema");
    }
    super::migrate(&db, &settings()).await.expect("migrate");
    let queue_columns = db
        .query("PRAGMA table_info(queue)")
        .fetch_all::<super::QueueTableInfoRow>()
        .await
        .expect("queue columns")
        .into_iter()
        .map(|column| column.name)
        .collect::<Vec<_>>();
    assert!(queue_columns.iter().any(|name| name == "claimed_at"));
    for table in ["crate_build_samples", "crate_build_stats"] {
        let columns = db
            .query(&format!("PRAGMA table_info({table})"))
            .fetch_all::<super::QueueTableInfoRow>()
            .await
            .expect("cost table columns");
        assert!(!columns.is_empty(), "{table} exists");
    }
}
