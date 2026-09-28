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
use super::queue::{self, CoverageOracle, QueueMutation, SchedulerSettings, SemanticTaskIdentity};

/// What a [`Drive`] runs: the route's queue-layer calls exactly once
/// against `db`. `FixtureShape` is copied — four bytes.
type DriveRun = for<'a> fn(
    &'a DurableDb,
    FixtureShape,
    &'a SchedulerSettings,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

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
        run: |db, _shape, _settings| {
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
        run: |db, _shape, _settings| {
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
        run: |db, _shape, _settings| {
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
        run: |db, _shape, _settings| {
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
        run: |db, _shape, _settings| {
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
        run: |db, _shape, _settings| {
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
        run: |db, _shape, _settings| {
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
        run: |db, _shape, _settings| {
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
        run: |db, _shape, _settings| {
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
        run: |db, shape, _settings| {
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
        run: |db, shape, _settings| {
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
        run: |db, _shape, _settings| {
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
        run: |db, shape, _settings| {
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
        run: |db, shape, settings| {
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
        run: |db, _shape, settings| {
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
        run: |db, _shape, settings| {
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
        run: |db, shape, settings| {
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
        run: |db, shape, settings| {
            Box::pin(async move {
                // The fixture's pending depth always exceeds
                // `max_queue_pending`, so the drive measures the
                // refusal path — the write path is the trusted drive's.
                // QueueFull is the pass; anything else is a failure.
                match queue::enqueue(db, &submit_batch(shape), settings).await {
                    Ok(_) | Err(crate::errors::QueueError::QueueFull { .. }) => Ok(()),
                    Err(error) => Err(error.to_string()),
                }
            })
        },
    },
    Drive {
        name: "POST /admin/enqueue (trusted)",
        run: |db, shape, settings| {
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
        run: |db, shape, settings| {
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
        run: |db, _shape, _settings| {
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
        run: |db, shape, _settings| {
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
        // The claim pages at `2 × open slots` rows and the coverage
        // oracle sees one lookup per page, so the pass's read is
        // bounded by the dispatch cap — the held quantity — plus the
        // fixed probes, never by the eligible frontier or the queue.
        name: "alarm pass",
        run: |db, _shape, settings| {
            Box::pin(async move {
                // One alarm pass: the dispatch claim and the
                // wake-time re-arm.
                queue::claim_dispatchable_tasks(db, settings, &NoCoverage)
                    .await
                    .map_err(|error| error.to_string())?;
                queue::next_alarm(db, 0, settings)
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(())
            })
        },
    },
];

/// Slice rows a delta report moves — retired from the live set plus the
/// same number added. The dependent refresh must stay proportional to
/// this, not to the slice.
const DELTA_ROWS: u32 = 30;

/// A coverage oracle that answers "not covered" for every row — the
/// catalog is empty under the fixture, which is the shape a cold cache
/// presents.
struct NoCoverage;

impl CoverageOracle for NoCoverage {
    fn covered(
        &self,
        _identities: &[SemanticTaskIdentity],
    ) -> impl Future<Output = Result<BTreeSet<SemanticTaskIdentity>, crate::errors::QueueError>> + Send
    {
        std::future::ready(Ok(BTreeSet::new()))
    }
}

/// The fixture's `task_id` for queue row `n` — `printf('%064x', n)` in
/// the seed.
fn hex_id(n: u64) -> String {
    format!("{n:064x}")
}

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
