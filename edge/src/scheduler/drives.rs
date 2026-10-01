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
/// sequential `trigger_build` fan-out — and the report can price the
/// coverage lookup's D1 rows against what the pass claimed.
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
        // A batch of one human-lane pending row and one completed row.
        // The human id is a pinned tail row
        // (`FixtureShape::HUMAN_LANE_ROWS - 5`): its edge always lands
        // on a completed dep, so `blocked` is size-invariant and its
        // lane-position probe — bounded by the held lane depth — runs
        // at every fixture size.
        name: "GET /tasks/status (batch)",
        run: |db, shape, _settings, _ctx| {
            Box::pin(async move {
                queue::tasks_status(
                    db,
                    &[
                        hex_id(u64::from(FixtureShape::HUMAN_LANE_ROWS - 5)),
                        hex_id(u64::from(shape.completed_row(0))),
                    ],
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
    },
    Drive {
        // A single human-lane pending row — the pinned tail row, for
        // the same reason as the batch drive: its position probe reads
        // the lane's full held depth at every size rather than
        // silently dropping to zero if a fixed row flips `blocked`.
        name: "GET /tasks/{id}",
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::tasks_status(db, &[hex_id(u64::from(FixtureShape::HUMAN_LANE_ROWS - 5))])
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
                queue::enqueue(db, &submit_batch(shape), &lifted)
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
        // coverage lookup, and the sequential `trigger_build` fan-out,
        // the serialized HTTP hop the launch gate's peak-wall bound
        // exists to measure. On host the claim runs the same queue
        // code against the empty-catalog oracle — the host gate checks
        // statements and counters only.
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
/// SQL uses, kept in one place so a drive always names a real row.
fn crate_identity(n: u32) -> (String, String) {
    (format!("crate{}", n % 20000), format!("1.0.{}", n % 500))
}

/// A submit batch: a resync of fixture row 101's identity (its edge set
/// is rewritten — the delta edge sync), one fresh miss task, and one
/// human-lane request — the request mix the enqueue path sees in
/// production. Deps name completed fixture rows, so the edges resolve.
fn submit_batch(shape: FixtureShape) -> Vec<EnqueueRequest> {
    let target_of = |n: u32| stow_types::api::CI_TARGET_TRIPLES[usize::try_from(n).unwrap() % 9];
    let dep = |n: u32| {
        let (crate_name, version) = crate_identity(n);
        EnqueueDependency {
            crate_name: crate_name.parse().expect("dep crate"),
            version: version.parse().expect("dep version"),
            features_json: FeaturesJson::default(),
            target: target_of(n).parse().expect("dep target"),
            rustc_version: if n % 3 < 2 {
                "1.85.0".parse().expect("dep rustc")
            } else {
                "1.86.0".parse().expect("dep rustc")
            },
            host_side: n.is_multiple_of(10),
        }
    };
    let (resync_crate, resync_version) = crate_identity(101);
    let resync = EnqueueRequest {
        crate_name: resync_crate.parse().expect("resync crate"),
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
    fresh.crate_name = "costgate-fresh".parse().expect("fresh crate");
    fresh.depends_on = vec![dep(shape.dep_row(31))];
    let mut human = resync.clone();
    human.crate_name = "costgate-human".parse().expect("human crate");
    human.source = EnqueueSource::HumanRequest;
    human.depends_on = Vec::new();
    vec![resync, fresh, human]
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
