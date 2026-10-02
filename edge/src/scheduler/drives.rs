//! The scheduler route list both cost gates drive. The host-side gate
//! (`cost_gate.rs`, `cargo test -p stow-edge`) runs this same list on a
//! small fixture against `counting_memory_db` as a fast pre-check; the
//! workerd harness (`budget.rs`, `scripts/scheduler-budget.sh`) runs it
//! on the 100k production fixture inside the Durable Object, where
//! `CfDurableDb` reports the real `rowsRead`/`rowsWritten` Cloudflare
//! bills. One drive list keeps the two harnesses honest: a route that
//! only existed in one of them would be an unmeasured request path.
//!
//! Every entry is a cold-start measure — the drives deliberately skip
//! `migrate`, which is operations work, never request code.

#[cfg(not(target_arch = "wasm32"))]
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use skyzen_services::durable::DurableDb;
use stow_types::api::{
    EnqueueDependency, EnqueueRequest, EnqueueSource, PublishedSliceRow, QueueSelector,
    QueueTaskStatus,
};
use stow_types::identity::FeaturesJson;
use stow_types::public_cache::{UnitInvocation, UnitKind, UnitShape, UnitSide};

use super::fixture::FixtureShape;
use super::queue::{self, QueueMutation, SchedulerSettings};
#[cfg(not(target_arch = "wasm32"))]
use super::queue::{CoverageOracle, SemanticTaskIdentity};

/// What a [`Drive`] runs: the route's queue-layer calls exactly once
/// against `db`. `FixtureShape` is copied — four bytes.
type DriveRun = for<'a> fn(
    &'a DurableDb,
    FixtureShape,
    &'a SchedulerSettings,
    &'a DriveContext,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// What a drive may reach besides the metered queue `DurableDb`.
///
/// The host gate's context is empty. The workerd probe's carries the
/// Worker env and the catalog D1 handle wrapped in the counted backend,
/// so the pass drive runs the real dispatch path — binding resolution,
/// the paged claim with its per-page coverage lookup, and the
/// `MAX_OUTBOUND_INFLIGHT`-bounded `trigger_build` fan-out — and the
/// report can price the coverage lookup's D1 rows against what the
/// pass claimed.
pub struct DriveContext {
    /// The Worker env — set only on the wasm32 probe.
    #[cfg(target_arch = "wasm32")]
    pub env: Option<skyzen::runtime::wasm::WasmEnv>,
    /// The catalog D1 handle on the counted backend — set only on the
    /// wasm32 probe.
    #[cfg(target_arch = "wasm32")]
    pub d1: Option<skyzen_services::Db>,
    /// Σ D1 `meta` rows the counted backend observed — read back into
    /// the report row after each drive.
    pub d1_rows: std::sync::Arc<std::sync::Mutex<(u64, u64)>>,
    /// Tasks the pass drives claimed. The launch gate's per-claim
    /// marginal price divides the hot-minus-idle delta by this count —
    /// never by a checked-in slots assumption — and refuses a report
    /// that claims nothing while build traffic is nonzero.
    pub claimed_tasks: std::sync::Arc<std::sync::Mutex<u64>>,
}

impl DriveContext {
    /// The host gate's context — no Worker env, no catalog. Only the
    /// host test harness calls it: on wasm the probe uses `worker`.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    #[must_use]
    pub fn host() -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            env: None,
            #[cfg(target_arch = "wasm32")]
            d1: None,
            d1_rows: std::sync::Arc::new(std::sync::Mutex::new((0, 0))),
            claimed_tasks: std::sync::Arc::new(std::sync::Mutex::new(0)),
        }
    }

    /// The workerd probe's context: the Worker env plus the catalog D1
    /// on the counted backend whose totals feed `d1_rows`.
    #[cfg(target_arch = "wasm32")]
    pub fn worker(env: &skyzen::runtime::wasm::WasmEnv) -> Result<Self, String> {
        let d1_rows = std::sync::Arc::new(std::sync::Mutex::new((0u64, 0u64)));
        let d1 = super::budget::counted_d1(env, std::sync::Arc::clone(&d1_rows))?;
        Ok(Self {
            env: Some(env.clone()),
            d1: Some(d1),
            d1_rows,
            claimed_tasks: std::sync::Arc::new(std::sync::Mutex::new(0)),
        })
    }

    /// Read the counted D1 totals so far.
    pub fn d1_counts(&self) -> (u64, u64) {
        *self.d1_rows.lock().expect("d1 counter")
    }

    /// Tasks claimed by the pass drives so far.
    pub fn claims(&self) -> u64 {
        *self.claimed_tasks.lock().expect("claim counter")
    }

    /// Record `n` claimed tasks.
    fn add_claims(&self, n: usize) {
        *self.claimed_tasks.lock().expect("claim counter") += u64::try_from(n).unwrap_or(u64::MAX);
    }
}

/// One route (or the alarm pass) driven against the seeded queue.
pub struct Drive {
    /// The route label — the budget table's row key.
    pub name: &'static str,
    /// Run the route's queue-layer calls exactly once against `db`.
    pub run: DriveRun,
}

/// The drives, in budget-table order. Read routes first, then the
/// state-changing ones: the submit/publish/alarm drives mutate the
/// fixture, and the ordering keeps those mutations from hiding behind
/// the read routes' measurements.
pub const DRIVES: &[Drive] = &[
    Drive {
        name: "GET /status",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::status(db)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        // Bounded by held quantities: the outcomes walk is the last
        // 24 h of completions (`FixtureShape::LAST_24H_ROWS`, an
        // `idx_queue_updated_at` range), and the in-flight section by
        // the dispatch cap (`FixtureShape::IN_FLIGHT_ROWS`) — neither
        // tracks the stored queue bulk.
        name: "GET /admin/status",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::admin_status(db)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "GET /tasks",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(db, &QueueSelector::default())
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "GET /tasks?status=failed",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        status: Some(QueueTaskStatus::Failed),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "GET /tasks?status=pending",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        status: Some(QueueTaskStatus::Pending),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "GET /tasks?status=blocked",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        status: Some(QueueTaskStatus::Blocked),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "GET /tasks?target=…",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        target: Some(
                            stow_types::api::CI_TARGET_TRIPLES[0]
                                .parse()
                                .map_err(|error| format!("target parse: {error}"))?,
                        ),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "GET /tasks?crate=…",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        crate_name: Some(
                            "crate123"
                                .parse()
                                .map_err(|error| format!("crate: {error}"))?,
                        ),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        // The age selector walks `idx_queue_updated_at` — the rows it
        // reads are bounded by the page limit, and the 24 h window it
        // lands in is held at `FixtureShape::LAST_24H_ROWS`.
        name: "GET /tasks?older_than=86400",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        older_than_secs: Some(86_400),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "GET /tasks?task_ids=…",
        run: |db, shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        task_ids: vec![
                            hex_id(u64::from(FixtureShape::pending_row(600))),
                            hex_id(u64::from(shape.failed_row(0))),
                        ],
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "POST /tasks/complete-run",
        run: |db, shape, _settings, _ctx| {
            Box::pin(async move {
                queue::complete_run(
                    db,
                    &stow_types::api::WorkflowRunComplete {
                        task_id: hex_id(u64::from(shape.running_row())),
                        success: true,
                        error: None,
                        github_run_id: Some("12345".to_owned()),
                    },
                    crate::freeze::DEFAULT_FREEZE_WINDOW_MINUTES,
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "POST /tasks/retry",
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                queue::apply_mutation(
                    db,
                    settings,
                    QueueMutation::Retry,
                    &QueueSelector {
                        task_ids: vec![
                            hex_id(u64::from(shape.failed_row(0))),
                            hex_id(u64::from(shape.failed_row(1))),
                        ],
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "POST /tasks/cancel",
        run: |db, _shape, settings, _ctx| {
            Box::pin(async move {
                queue::apply_mutation(
                    db,
                    settings,
                    QueueMutation::Cancel,
                    &QueueSelector {
                        task_ids: vec![
                            hex_id(u64::from(FixtureShape::pending_row(701))),
                            hex_id(u64::from(FixtureShape::pending_row(702))),
                        ],
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "POST /tasks/promote",
        run: |db, _shape, settings, _ctx| {
            Box::pin(async move {
                queue::apply_mutation(
                    db,
                    settings,
                    QueueMutation::Promote,
                    &QueueSelector {
                        task_ids: vec![hex_id(u64::from(FixtureShape::pending_row(703)))],
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "POST /tasks/purge",
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                queue::apply_mutation(
                    db,
                    settings,
                    QueueMutation::Purge,
                    &QueueSelector {
                        task_ids: vec![
                            hex_id(u64::from(shape.completed_row(0))),
                            hex_id(u64::from(shape.completed_row(1))),
                        ],
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        // A settled `enqueued` record: the row read, the stored-roots
        // parse and the live `tasks_status` re-probe — a pending human
        // root pays the lane-position walk, bounded by the held lane
        // depth.
        name: "GET /requests/{id}",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::crate_request_status(db, stow_types::fixture::REQUEST_FIXTURE_ENQUEUED)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        // The request lane's admission end to end — on wasm the real
        // `admit_request_pass`: the freeze and budget probes, the
        // deduping insert and the serialized `trigger_resolve` hop to
        // the local-CI dispatcher (the production GitHub arm's token
        // read is the same cached row the alarm pass pays). On host the
        // queue-layer calls only — dedup read, budget probe, insert.
        name: "POST /requests",
        run: |db, _shape, settings, ctx| {
            Box::pin(async move { admit_request_drive(db, settings, ctx).await })
        },
    },
    Drive {
        // `in_progress` on the record the admit drive just inserted:
        // the row read plus the conditional `accepted -> resolving`
        // update that stamps the run id.
        name: "POST /requests/{id}/run-update (in_progress)",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::record_request_run_update(
                    db,
                    DRIVE_REQUEST_ID,
                    &stow_types::api::RequestRunUpdate {
                        attempt: 1,
                        action: stow_types::api::RequestRunAction::InProgress,
                        conclusion: None,
                        run_id: Some("43".to_owned()),
                        run_url: Some(
                            "https://github.com/water-rs/stow/actions/runs/43".to_owned(),
                        ),
                    },
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        // A `Resolved` report on the live record: the pre/post
        // `tasks_status` probes, the trusted enqueue of its batch and
        // the conditional `enqueued` write — the same insert machinery
        // the submit drives price, at the request batch's size.
        name: "POST /requests/{id}/outcome",
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                queue::apply_request_outcome(db, settings, DRIVE_REQUEST_ID, &request_report(shape))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        // `completed` on the now-`enqueued` record — the single
        // conditional update keyed on the current state, which is the
        // overwrite the backstop must never perform (stow#428 review):
        // the real event costs the row read plus one no-op write.
        name: "POST /requests/{id}/run-update (completed)",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::record_request_run_update(
                    db,
                    DRIVE_REQUEST_ID,
                    &stow_types::api::RequestRunUpdate {
                        attempt: 1,
                        action: stow_types::api::RequestRunAction::Completed,
                        conclusion: Some("success".to_owned()),
                        run_id: Some("43".to_owned()),
                        run_url: Some(
                            "https://github.com/water-rs/stow/actions/runs/43".to_owned(),
                        ),
                    },
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        // The pending-depth check is a `queue_status_counts` row read;
        // the human-lane position walk is bounded by the lane's depth
        // (`FixtureShape::HUMAN_LANE_ROWS`, held across sizes), not by
        // the queue.
        name: "POST /enqueue (untrusted)",
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                // A zero cap turns any queue depth into a refusal, so
                // the drive measures the refuse path deterministically
                // rather than betting the fixture stays over the
                // deploy's cap. QueueFull is the pass; anything else
                // is a failure.
                let mut refused = *settings;
                refused.max_queue_pending = 0;
                match queue::enqueue(db, &submit_batch(shape), &refused).await {
                    Ok(_) | Err(crate::errors::QueueError::QueueFull { .. }) => Ok(()),
                    Err(error) => Err(error.to_string()),
                }
            })
        },
    },
    Drive {
        // The accept half of the untrusted route: the cap is lifted so
        // the probe measures the insert — pending-count read, the
        // human-lane budget charge and position walk, the edge sync.
        // The launch gate prices a miss-lane enqueue here: an accepted
        // redemption pays the insert, not the refusal, and pricing it
        // on the refusal row underreads the DO writes admissions cost.
        name: "POST /enqueue (untrusted accept)",
        run: |db, shape, settings, _ctx| {
            let mut lifted = *settings;
            lifted.max_queue_pending = u32::MAX;
            Box::pin(async move {
                queue::enqueue(db, &submit_accept_batch(shape), &lifted)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "POST /admin/enqueue (trusted)",
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                queue::enqueue_trusted(db, &submit_batch(shape), settings)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "POST /admin/enqueue (resubmit)",
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                queue::enqueue_trusted(db, &submit_batch(shape), settings)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "POST /index/published (full)",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                // A full report (`base_generation: None`) — the
                // first-publish and resync path — on a dedicated slice
                // whose size is held across fixtures. Its cost is
                // legitimately bounded by the report's own membership:
                // the report body carries every row it claims, and the
                // live-set fetch reads only that slice.
                queue::record_published_slice(
                    db,
                    stow_types::api::CI_TARGET_TRIPLES[8],
                    "9.9.9",
                    None,
                    None,
                    &full_slice_report(),
                    &[],
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        name: "POST /index/published (delta)",
        run: |db, shape, _settings, _ctx| {
            Box::pin(async move {
                // A routine per-wave report: `added`/`retired` carry only
                // what moved, `base_generation` is the live token, and
                // every read is bounded by the delta — the probe (1 row),
                // the retire's PK joins, and the dependent refresh.
                let target = stow_types::api::CI_TARGET_TRIPLES[0];
                let rustc = "1.85.0";
                let base = db
                    .query(
                        "SELECT applied_generation FROM published_slices \
                         WHERE target = ? AND rustc_version = ?",
                    )
                    .bind(target.to_owned())
                    .bind(rustc.to_owned())
                    .fetch_scalar_optional::<i64>()
                    .await
                    .map_err(|error| error.to_string())?;
                let (added, retired) = delta_slice_report(shape);
                queue::record_published_slice(db, target, rustc, base, None, &added, &retired)
                    .await
                    .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        // One dispatch pass end to end — on wasm the real
        // `dispatch_pass` (`object.rs`): binding resolution, the claim
        // paged at `2 × open slots` rows with its per-page catalog
        // coverage lookup, and the `MAX_OUTBOUND_INFLIGHT`-bounded
        // `trigger_build` fan-out — the HTTP wall the launch gate's
        // peak-wall bound exists to measure. On host the claim runs the
        // same queue code against the empty-catalog oracle — the host
        // gate checks statements and counters only.
        name: "alarm pass",
        run: |db, _shape, settings, ctx| {
            Box::pin(async move { dispatch_pass_drive(db, settings, ctx, false).await })
        },
    },
    Drive {
        // The same pass with dispatch paused: the claim returns early,
        // so this measures the per-invocation floor — stale-recovery
        // probes, the freeze and binding reads, and the wake-time
        // re-arm — every alarm wake pays regardless of what it claims.
        // The launch gate (stow#452) prices an invocation from this
        // row and the claims inside a pass as the marginal cost
        // between it and the hot pass above.
        name: "alarm pass (idle)",
        run: |db, _shape, settings, ctx| {
            Box::pin(async move { dispatch_pass_drive(db, settings, ctx, true).await })
        },
    },
];

/// One dispatch pass exactly as `run_alarm` runs it, minus the metering
/// tail. `idle` pauses dispatch inside the pass — the claim early-outs
/// after the stale-recovery and freeze probes every wake owes.
async fn dispatch_pass_drive(
    db: &DurableDb,
    settings: &SchedulerSettings,
    ctx: &DriveContext,
    idle: bool,
) -> Result<(), String> {
    let mut pass_settings = *settings;
    if idle {
        pass_settings.dispatch = queue::Dispatch::Paused;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let env = ctx
            .env
            .as_ref()
            .ok_or_else(|| "dispatch pass drive needs a Worker env".to_owned())?;
        let d1 = ctx
            .d1
            .as_ref()
            .ok_or_else(|| "dispatch pass drive needs the counted D1".to_owned())?;
        let coverage = super::object::CatalogCoverage { db: d1.clone() };
        let claimed = super::object::dispatch_pass(env, db, &pass_settings, &coverage)
            .await
            .map_err(|error| error.to_string())?;
        ctx.add_claims(claimed);
        if !idle {
            // Under `LocalCi` `dispatch_pass` resolves no credential,
            // but a production claiming pass pays
            // `github_app::installation_token` — the cached-token
            // storage read, with a mint only on expiry. The probe seeds
            // the cache row (`budget::run`), so this call returns on the
            // read and the drive prices the step the GitHub arm pays.
            let config = crate::github_app::AppConfig {
                app_id: "stow-budget-probe".to_owned(),
                installation_id: "0".to_owned(),
                private_key_pem: String::new(),
            };
            let _ = crate::github_app::installation_token(db, &config)
                .await
                .map_err(|error| error.to_string())?;
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let claimed = queue::claim_dispatchable_tasks(db, &pass_settings, &NoCoverage)
            .await
            .map_err(|error| error.to_string())?;
        ctx.add_claims(claimed.len());
    }
    queue::next_alarm(db, 0, &pass_settings)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Slice rows a delta report moves — retired from the live set plus the
/// same number added. The dependent refresh must stay proportional to
/// this, not to the slice.
const DELTA_ROWS: u32 = 30;

/// A coverage oracle that answers "not covered" for every row — the
/// catalog is empty under the fixture, which is the shape a cold cache
/// presents. Host-side only: the wasm pass drive uses the real
/// `CatalogCoverage` over the counted D1.
#[cfg(not(target_arch = "wasm32"))]
struct NoCoverage;

#[cfg(not(target_arch = "wasm32"))]
impl CoverageOracle for NoCoverage {
    fn covered(
        &self,
        _identities: &[SemanticTaskIdentity],
    ) -> impl Future<Output = Result<BTreeSet<SemanticTaskIdentity>, crate::errors::QueueError>> + Send
    {
        std::future::ready(Ok(BTreeSet::new()))
    }
}

use stow_types::fixture::task_hex_id as hex_id;

/// The crate identity a queue row carries — the same formulas the seed
/// SQL uses, kept in one place so a drive always names a real row. The
/// pair is injective in `n` at any fixture size.
fn crate_identity(n: u32) -> (String, String) {
    (
        format!("crate{}", n % 20000),
        format!("1.{}.{}", n / 20000, n % 500),
    )
}

/// A submit batch: a resync of fixture row 101's identity (its edge set
/// is rewritten — the delta edge sync), one fresh miss task, and one
/// human-lane request — the request mix the enqueue path sees in
/// production. Deps name completed fixture rows, so the edges resolve.
fn submit_batch(shape: FixtureShape) -> Vec<EnqueueRequest> {
    submit_batch_named(
        shape,
        &crate_identity(101).0,
        "costgate-fresh",
        "costgate-human",
    )
}

/// The accept half's batch names its own tasks: an accepted submit
/// leaves rows and edges behind, so reusing the trusted pair's task
/// identities would move the later drives from the insert path they
/// measure onto a resync one (stow#452 — the merge-queue probe caught
/// the trusted drive resyncing the accept drive's task set).
fn submit_accept_batch(shape: FixtureShape) -> Vec<EnqueueRequest> {
    submit_batch_named(
        shape,
        "costgate-accept",
        "costgate-accept-fresh",
        "costgate-accept-human",
    )
}

fn submit_batch_named(
    shape: FixtureShape,
    resync_name: &str,
    fresh_name: &str,
    human_name: &str,
) -> Vec<EnqueueRequest> {
    let target_of = dep_target;
    let dep = dep_request;
    let (_resync_crate, resync_version) = crate_identity(101);
    let resync = EnqueueRequest {
        crate_name: resync_name.parse().expect("resync crate"),
        version: resync_version.parse().expect("resync version"),
        features_json: FeaturesJson::default(),
        target: target_of(101).parse().expect("resync target"),
        rustc_version: "1.86.0".parse().expect("resync rustc"),
        downloads: 10,
        source: EnqueueSource::CacheMiss,
        depends_on: (0..30).map(|k| dep(shape.dep_row(k))).collect(),
        preserve_lockfile: false,
        host_side: false,
    };
    let mut fresh = resync.clone();
    fresh.crate_name = fresh_name.parse().expect("fresh crate");
    fresh.depends_on = vec![dep(shape.dep_row(31))];
    let mut human = resync.clone();
    human.crate_name = human_name.parse().expect("human crate");
    human.source = EnqueueSource::HumanRequest;
    human.depends_on = Vec::new();
    vec![resync, fresh, human]
}

/// The request record the drives admit and settle — a `req-drive`
/// id `rearm_fixture` deletes between runs, so every probe measures the
/// fresh-admission path rather than a dedup hit.
const DRIVE_REQUEST_ID: &str = "req-costgate-drive";

/// The drive's admission — a fresh `req-` record per probe run.
fn drive_admission() -> stow_types::api::RequestAdmission {
    stow_types::api::RequestAdmission {
        request_id: DRIVE_REQUEST_ID.to_owned(),
        crate_name: "costgate-request".parse().expect("request crate"),
        version: "1.0.0".parse().expect("request version"),
        features_json: FeaturesJson::default(),
        rustc_version: "1.86.0".parse().expect("request rustc"),
        max_closure: 500,
    }
}

/// The `POST /requests` drive: the full pass on wasm (credential arm +
/// the dispatch hop), the queue-layer calls on host.
async fn admit_request_drive(
    db: &DurableDb,
    settings: &SchedulerSettings,
    ctx: &DriveContext,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let env = ctx
            .env
            .as_ref()
            .ok_or_else(|| "requests drive needs a Worker env".to_owned())?;
        super::object::admit_request_pass(env, db, settings, &drive_admission(), 0)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = ctx;
        queue::admit_request(db, &drive_admission(), 0, settings)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// The outcome report the outcome drive applies — a one-dep
/// `HumanRequest` batch whose root is its own fresh task plus a root
/// that names an existing completed row (the `was_queued` arm).
fn request_report(shape: FixtureShape) -> stow_types::api::RequestOutcomeReport {
    let crate_name = "costgate-request-root";
    let version = "1.0.0";
    let target = stow_types::api::CI_TARGET_TRIPLES[0];
    let rustc = "1.86.0";
    let root_task = EnqueueRequest {
        crate_name: crate_name.parse().expect("request crate"),
        version: version.parse().expect("request version"),
        features_json: FeaturesJson::default(),
        target: target.parse().expect("request target"),
        rustc_version: rustc.parse().expect("request rustc"),
        downloads: 1,
        source: EnqueueSource::HumanRequest,
        depends_on: vec![dep_request(shape.dep_row(2))],
        preserve_lockfile: false,
        host_side: false,
    };
    let root_id = queue::task_id(crate_name, version, "[]", target, rustc, false);
    stow_types::api::RequestOutcomeReport {
        attempt: 1,
        outcome: stow_types::api::RequestOutcome::Resolved {
            tasks: vec![root_task],
            roots: vec![
                stow_types::api::RequestRootOutcome {
                    target: target.parse().expect("root target"),
                    task_id: Some(root_id),
                    cached: false,
                },
                stow_types::api::RequestRootOutcome {
                    target: stow_types::api::CI_TARGET_TRIPLES[1]
                        .parse()
                        .expect("second target"),
                    // An existing completed row — the `was_queued` arm.
                    // Row 3 stays clear of the purge drive's row-0/1
                    // deletes, which run earlier in this list.
                    task_id: Some(hex_id(u64::from(shape.completed_row(3)))),
                    cached: false,
                },
            ],
        },
    }
}

/// The fixture-row target the dep identities spread over.
fn dep_target(n: u32) -> &'static str {
    stow_types::api::CI_TARGET_TRIPLES[usize::try_from(n).unwrap() % 9]
}

/// One dependency edge on fixture row `n` — the same identity formulas
/// the queue seed wrote, so the edge resolves.
fn dep_request(n: u32) -> EnqueueDependency {
    let (crate_name, version) = crate_identity(n);
    EnqueueDependency {
        crate_name: crate_name.parse().expect("dep crate"),
        version: version.parse().expect("dep version"),
        features_json: FeaturesJson::default(),
        target: dep_target(n).parse().expect("dep target"),
        rustc_version: if n % 3 < 2 {
            "1.85.0".parse().expect("dep rustc")
        } else {
            "1.86.0".parse().expect("dep rustc")
        },
        host_side: n.is_multiple_of(10),
    }
}

/// The report's unit shape — every published row serves the target-side
/// linked unit of a native invocation.
const GATE_UNIT: Option<UnitShape> = Some(UnitShape {
    side: UnitSide::Target,
    invocation: UnitInvocation::Native,
    kind: UnitKind::Linked,
});

/// The full-report drive's slice: a held-size membership (100 rows) on
/// a dedicated slice — `CI_TARGET_TRIPLES[8]` / `9.9.9` — that the seed
/// never writes, so the same report shape applies at both fixture
/// sizes.
fn full_slice_report() -> Vec<PublishedSliceRow> {
    (0..100)
        .map(|i| PublishedSliceRow {
            crate_name: format!("stow-gate-full-{i}").parse().expect("full crate"),
            version: "1.0.0".parse().expect("full version"),
            features_json: FeaturesJson::default(),
            unit_shape: GATE_UNIT,
        })
        .collect()
}

/// The delta report for `(CI_TARGET_TRIPLES[0], '1.85.0')`: retire the
/// slice's [`DELTA_ROWS`] tail members and add as many fresh rows — a
/// `2 * DELTA_ROWS` change set. The fixture's live members are the
/// completed rows whose `n % 9` lands on that target — `n % 9 == 0`
/// implies `n % 3 == 0`, the `1.85.0` rustc arm.
fn delta_slice_report(shape: FixtureShape) -> (Vec<PublishedSliceRow>, Vec<PublishedSliceRow>) {
    let live = shape.slice_live_rows(0);
    let first = shape.slice_first_row(0);
    let mut retired = Vec::new();
    let mut added = Vec::new();
    for i in 0..DELTA_ROWS {
        let (crate_name, version) = crate_identity(first + (live - 1 - i) * 9);
        retired.push(PublishedSliceRow {
            crate_name: crate_name.parse().expect("retire crate"),
            version: version.parse().expect("retire version"),
            features_json: FeaturesJson::default(),
            unit_shape: GATE_UNIT,
        });
        added.push(PublishedSliceRow {
            crate_name: format!("stow-gate-delta-{i}").parse().expect("delta crate"),
            version: "9.9.9".parse().expect("delta version"),
            features_json: FeaturesJson::default(),
            unit_shape: GATE_UNIT,
        });
    }
    (added, retired)
}
