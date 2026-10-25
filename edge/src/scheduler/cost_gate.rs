//! The stow#433 host-side cost gate — a fast pre-check that runs in
//! `cargo test -p stow-edge`. The scheduler's store is a flat log and
//! snapshot (stow#878), so the host backend's statement results are the
//! same rows the Durable Object bills: `rows_read` is the rows the
//! statements returned and `rows_written` their `changes()`. The billed
//! gate is still the workerd harness (`budget.rs` +
//! `scripts/traffic-cost.sh`), which replays this same [`drives`] list
//! on the production fixture inside the Durable Object and reports the
//! real cursor counters; this test keeps a regression that goes
//! graph-size-proportional from waiting for a workerd run.
//!
//! Three rules hold on every drive:
//!
//! * its counts stay inside its `DO_BUDGETS` row;
//! * no `CREATE`/`ALTER`/`DROP`/`PRAGMA` — schema work is operations
//!   work (stow#432), so a route whose log contains one fails even when
//!   it fits its budget;
//! * it leaves the claimable surface as it found it — pending depth and
//!   the in-flight set — because the next drive's pass would otherwise
//!   price the leak.
//!
//! Budgets are measured values with headroom, not ceilings a change may
//! drift under: a route that gets cheaper gets a tighter budget — it
//! may never be raised to pass a regression. The scale test runs two
//! fixture sizes and requires every drive but the two that touch the
//! graph's bulk (the wake and the snapshot) to cost the same on both.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use skyzen_services::durable::DurableDb;
use stow_types::do_budgets::{DO_BUDGETS, DriveBudget, grew};

use super::drives::{self, DriveContext};
use super::fixture::{self, FixtureShape};
use super::graph::{GraphCell, LoadedGraph};
use super::queue::SchedulerSettings;
use super::test_db::{LoggedStatement, counting_memory_db};

/// The two drives whose job is the graph's bulk: the wake reads the
/// snapshot, the snapshot writes it. Every other drive is an event and
/// costs the same at any size.
const BULK_DRIVES: &[&str] = &["wake (snapshot + log replay)", "snapshot write"];

/// One measured drive run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Measured {
    name: &'static str,
    statements: u64,
    rows_read: u64,
    rows_written: u64,
}

impl Measured {
    fn of(name: &'static str, statements: &[LoggedStatement]) -> Self {
        Self {
            name,
            statements: statements.len() as u64,
            rows_read: statements.iter().map(|s| s.rows_read).sum(),
            rows_written: statements.iter().map(|s| s.rows_written).sum(),
        }
    }
}

fn budget_of(name: &str) -> &'static DriveBudget {
    DO_BUDGETS
        .iter()
        .find(|budget| budget.name == name)
        .unwrap_or_else(|| panic!("{name} has no entry in the scheduler cost-budget table"))
}

/// Whether `sql` is schema work: the first keyword of the statement.
fn has_schema_head(sql: &str) -> bool {
    sql.split_whitespace().next().is_some_and(|head| {
        ["CREATE", "ALTER", "DROP", "PRAGMA"]
            .iter()
            .any(|keyword| head.eq_ignore_ascii_case(keyword))
    })
}

/// The drive list and the workerd budget table must cover each other
/// exactly: every drive has exactly one row, and no row has no drive.
/// A drifted row is the defect the workerd probe would otherwise turn
/// into an error inside the Durable Object.
#[test]
fn every_drive_has_exactly_one_budget_row() {
    let drives = drives::DRIVES
        .iter()
        .map(|drive| drive.name)
        .collect::<Vec<_>>();
    let budgets = DO_BUDGETS.iter().map(|b| b.name).collect::<Vec<_>>();
    assert_eq!(
        drives.len(),
        drives.iter().copied().collect::<BTreeSet<_>>().len(),
        "duplicate drive"
    );
    assert_eq!(
        budgets.len(),
        budgets.iter().copied().collect::<BTreeSet<_>>().len(),
        "duplicate budget row"
    );
    assert_eq!(
        drives.iter().copied().collect::<BTreeSet<_>>(),
        budgets.iter().copied().collect::<BTreeSet<_>>(),
        "DO_BUDGETS and the drive list drifted apart"
    );
    // Route-level coverage, not just table parity: every demand-feed
    // route the object registers must have at least one priced drive
    // (stow#523); drive names carry ` (variant)` suffixes for the same
    // route's distinct event shapes.
    for route in ["begin", "page", "complete", "cleanup", "deliver", "status"] {
        assert!(
            drives.iter().any(|name| {
                name.ends_with(&format!("/demand-feed/{route}"))
                    || name.contains(&format!("/demand-feed/{route} ("))
            }),
            "no drive prices /demand-feed/{route}",
        );
    }
}

/// stow#567: a wall breach is reported, never gated — the local
/// workerd lane's `wall_ms` is mostly the in-window `db.sync()`
/// durability barrier, so `over_wall` marks it while `over_budget`
/// stays clear. A statements/rows breach still gates.
#[test]
fn a_wall_breach_is_reported_not_gated() {
    let budget = DO_BUDGETS.first().expect("a drive budget");
    assert!(budget.over_wall(budget.wall_ms + 1));
    assert!(
        !budget.over_budget(budget.statements, budget.rows_read, budget.rows_written),
        "the wall is reported, not gated"
    );
    assert!(budget.over_budget(budget.statements, budget.rows_read + 1, budget.rows_written));
    assert!(!budget.over_wall(budget.wall_ms));
}

/// What a drive may not leave behind: a pending node it added or moved
/// is claimable by the next pass, and a slot it took changes the next
/// capacity read.
fn claimable_surface(cell: LoadedGraph<'_>) -> (u32, (u32, u32)) {
    cell.with(|graph| (graph.pending_depth(), graph.inflight()))
}

/// One drive's unmetered hooks plus its metered pass, measured. The
/// phase ordering lives in [`drives::drive_lifecycle`] — shared with
/// the workerd probe — while this observer owns the gate's bookkeeping:
/// setup and cleanup statements are fixture work, not the priced
/// event, so the log truncates back to the mark each phase opened at
/// (stow#525).
async fn run_one_drive(
    db: &DurableDb,
    shape: FixtureShape,
    settings: &SchedulerSettings,
    ctx: &DriveContext,
    log: &Arc<Mutex<Vec<LoggedStatement>>>,
    drive: &drives::Drive,
) -> Result<Measured, String> {
    let mut keep = 0;
    let mut base = 0;
    let before = claimable_surface(ctx.loaded());
    let outcome =
        drives::drive_lifecycle(
            drive,
            db,
            db,
            shape,
            settings,
            ctx,
            &mut |mark| match mark {
                drives::PhaseMark::Starting(
                    drives::LifecyclePhase::Setup | drives::LifecyclePhase::Cleanup,
                ) => keep = log.lock().expect("statement log").len(),
                drives::PhaseMark::Finished(
                    drives::LifecyclePhase::Setup | drives::LifecyclePhase::Cleanup,
                ) => log.lock().expect("statement log").truncate(keep),
                drives::PhaseMark::Finished(drives::LifecyclePhase::PreSync) => {
                    base = log.lock().expect("statement log").len();
                }
                _ => {}
            },
        )
        .await;
    if let Err(error) = outcome.setup {
        return Err(format!("{} setup failed: {error}", drive.name));
    }
    let failures: Vec<String> = [&outcome.pre_sync, &outcome.run, &outcome.post_sync]
        .into_iter()
        .filter_map(|phase| {
            phase
                .as_ref()
                .and_then(|result| result.as_ref().err().cloned())
        })
        .collect();
    let run_result = if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    };
    let cleanup_result = match &outcome.cleanup {
        Some(Err(error)) => Err(format!("{} cleanup failed: {error}", drive.name)),
        _ => Ok(()),
    };
    let statements = log.lock().expect("statement log")[base..].to_vec();
    for statement in &statements {
        assert!(
            drives::append_bills_replay_cost(
                &statement.sql,
                statement.rows_read,
                statement.rows_written,
            ),
            "{} appended event_log at {} R + {} W — the replay re-count is 1 R + 1 W",
            drive.name,
            statement.rows_read,
            statement.rows_written,
        );
    }
    let after = claimable_surface(ctx.loaded());
    match (run_result, cleanup_result) {
        (Ok(()), Ok(())) => {
            if before != after {
                return Err(format!(
                    "{} left the claimable surface changed: pending/in-flight {before:?} -> {after:?}",
                    drive.name
                ));
            }
            Ok(Measured::of(drive.name, &statements))
        }
        (Err(run_error), Ok(())) => Err(format!("{} failed: {run_error}", drive.name)),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(run_error), Err(cleanup_error)) => Err(format!(
            "{} failed: {run_error}; cleanup also failed: {cleanup_error}",
            drive.name
        )),
    }
}

/// Seed `shape` into a fresh counting database and run every drive.
async fn measure_all(shape: FixtureShape) -> Vec<Measured> {
    let settings = SchedulerSettings::default();
    let (db, log) = counting_memory_db().await.expect("counting db");
    let cell = GraphCell::default();
    let seed_base = log.lock().expect("log").len();
    fixture::seed(&db, &cell, shape, drives::HOST_NOW_MS)
        .await
        .expect("seed fixture");
    // The fixture obeys the gate too: it is seeded with DML only.
    for statement in &log.lock().expect("log")[seed_base..] {
        assert!(
            !has_schema_head(&statement.sql),
            "fixture seeding issued schema work: {}",
            statement.sql
        );
    }
    let ctx = DriveContext::host(cell);
    let mut measured = Vec::new();
    for drive in drives::DRIVES {
        measured.push(
            run_one_drive(&db, shape, &settings, &ctx, &log, drive)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
    }
    measured
}

/// Check one measurement against its budget row, printing the measured
/// line so a tuning run still reports every route.
fn check(measured: &Measured) {
    eprintln!(
        "BUDGET {:<56} statements={:<4} rows_read={:<7} rows_written={:<7}",
        measured.name, measured.statements, measured.rows_read, measured.rows_written,
    );
    let budget = budget_of(measured.name);
    assert!(
        !budget.over_budget(
            measured.statements,
            measured.rows_read,
            measured.rows_written
        ),
        "{} measured {measured:?} over its budget {budget:?}",
        measured.name,
    );
}

/// Every entry of [`drives::DRIVES`] holds its budget on the 10k gate
/// fixture.
#[tokio::test]
async fn per_request_cost_gate() {
    for measured in measure_all(fixture::GATE).await {
        check(&measured);
    }
}

/// Event drives cost the same at any fixture size: two sizes, and no
/// drive but the bulk ones may grow past the shared growth tolerance.
#[tokio::test]
async fn event_drives_are_flat_across_fixture_sizes() {
    let small = measure_all(FixtureShape { queue_rows: 5_000 }).await;
    let large = measure_all(fixture::GATE).await;
    for (small, large) in small.iter().zip(&large) {
        assert_eq!(small.name, large.name);
        if BULK_DRIVES.contains(&small.name) {
            continue;
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "row counts fit f64 exactly to 2^53"
        )]
        for (dimension, earlier, later) in [
            ("rows_read", small.rows_read, large.rows_read),
            ("rows_written", small.rows_written, large.rows_written),
        ] {
            assert!(
                !grew(earlier as f64, later as f64),
                "{} {dimension} grew with the fixture: {earlier} at 5k -> {later} at 10k",
                small.name
            );
        }
    }
}

/// The probe repeats on a persisted fixture: a reseed over a store the
/// first run churned restores the canonical graph, and the second run
/// holds every budget again.
#[tokio::test]
async fn budget_probe_repeats_on_a_persisted_fixture() {
    let settings = SchedulerSettings::default();
    let (db, log) = counting_memory_db().await.expect("counting db");
    let cell = GraphCell::default();
    let shape = fixture::GATE;
    let mut runs = Vec::new();
    for _ in 0..2 {
        fixture::seed(&db, &cell, shape, drives::HOST_NOW_MS)
            .await
            .expect("seed fixture");
        let ctx = DriveContext::host(cell.clone());
        let mut measured = Vec::new();
        for drive in drives::DRIVES {
            measured.push(
                run_one_drive(&db, shape, &settings, &ctx, &log, drive)
                    .await
                    .unwrap_or_else(|error| panic!("{error}")),
            );
        }
        runs.push(measured);
    }
    for measured in &runs[1] {
        check(measured);
    }
    for (first, second) in runs[0].iter().zip(&runs[1]) {
        assert_eq!(first, second, "a repeat run measured differently");
    }
}

fn injected_run_failure<'a>(
    _db: &'a DurableDb,
    _shape: FixtureShape,
    _settings: &'a SchedulerSettings,
    _ctx: &'a DriveContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async { Err("injected run failure".to_owned()) })
}

fn marking_cleanup<'a>(
    db: &'a DurableDb,
    _shape: FixtureShape,
    _settings: &'a SchedulerSettings,
    _ctx: &'a DriveContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        db.query("INSERT INTO store_meta (key, value) VALUES ('cleanup-marker', 1)")
            .execute()
            .await
            .map_err(|error| error.to_string())
            .map(|_| ())
    })
}

fn injected_cleanup_failure<'a>(
    _db: &'a DurableDb,
    _shape: FixtureShape,
    _settings: &'a SchedulerSettings,
    _ctx: &'a DriveContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async { Err("injected cleanup failure".to_owned()) })
}

/// A drive that fails mid-pass must still see its cleanup run — the
/// isolation promise holds on the error path too — and when the
/// cleanup itself also fails, the error names both failures.
#[tokio::test]
async fn cleanup_still_runs_after_a_failing_drive() {
    let (db, log) = counting_memory_db().await.expect("counting db");
    let cell = GraphCell::default();
    fixture::seed(&db, &cell, fixture::GATE, drives::HOST_NOW_MS)
        .await
        .expect("seed fixture");
    let ctx = DriveContext::host(cell);
    let settings = SchedulerSettings::default();
    let drive = drives::Drive {
        name: "probe-isolation",
        setup: None,
        run: injected_run_failure,
        cleanup: Some(marking_cleanup),
    };
    let error = run_one_drive(&db, fixture::GATE, &settings, &ctx, &log, &drive)
        .await
        .expect_err("the failing drive must propagate its error");
    assert_eq!(error, "probe-isolation failed: injected run failure");
    let marked = db
        .query("SELECT COUNT(*) FROM store_meta WHERE key = 'cleanup-marker'")
        .fetch_scalar::<u64>()
        .await
        .expect("marker read");
    assert_eq!(marked, 1, "cleanup ran after the failed run");

    let drive = drives::Drive {
        name: "probe-double-failure",
        setup: None,
        run: injected_run_failure,
        cleanup: Some(injected_cleanup_failure),
    };
    let error = run_one_drive(&db, fixture::GATE, &settings, &ctx, &log, &drive)
        .await
        .expect_err("both failures must propagate");
    assert_eq!(
        error,
        "probe-double-failure failed: injected run failure; \
         cleanup also failed: probe-double-failure cleanup failed: injected cleanup failure"
    );
}

/// Re-arming reloads the seed's snapshot and replays its tail, so a
/// run the lanes completed is in flight again and the graph matches a
/// fresh seed - without building the fixture a second time.
#[tokio::test]
async fn rearm_restores_the_seeded_state() {
    let db = crate::scheduler::test_db::memory_db().await.expect("db");
    let cell = GraphCell::default();
    let shape = FixtureShape { queue_rows: 5_000 };
    fixture::seed(&db, &cell, shape, drives::HOST_NOW_MS)
        .await
        .expect("seed fixture");
    let cell = cell.loaded().expect("seeded");
    let seeded = cell.with(|graph| graph.status_counts());
    let run = shape.in_flight_run(0);
    let finished = cell.with(|graph| {
        graph.run_finished(
            &run.task_id,
            run.run_id,
            true,
            false,
            None,
            drives::HOST_NOW_MS,
        )
    });
    assert_eq!(finished, super::graph::FinishOutcome::Applied);
    assert_ne!(cell.with(|graph| graph.status_counts()), seeded);
    fixture::rearm(&db, cell, shape, drives::HOST_NOW_MS)
        .await
        .expect("rearm");
    assert_eq!(cell.with(|graph| graph.status_counts()), seeded);
}
