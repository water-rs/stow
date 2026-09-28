//! The scheduler Durable Object's self-metered cost trip — the
//! event-driven replacement for the deleted cron probe (which cost one
//! Worker invocation + GraphQL read every ten minutes forever, and
//! duplicated the #450 watchdog's view of the same account budgets).
//!
//! `MeteringBackend` is a [`DurableDbBackend`] that forwards each
//! statement through [`QuerySource`] and books the returned
//! [`DbExecResult`]'s `rows_read`/`rows_written` — which `CfDurableDb`
//! reads off the `SqlStorageCursor` — into a per-operation `pending`
//! counter. Handlers keep extracting a plain `DurableDb` (the
//! middleware re-inserts the wrapped handle under the same type), so
//! `queue.rs` never knows it is metered. [`Meter::settle`] folds the
//! pending counts into a per-UTC-day `do_meter` row once per request
//! (and once per alarm pass) — the DO bills `rowsRead` and
//! `rowsWritten`, so the meter measures exactly what costs money.
//!
//! The day the meter crosses `monthly allowance / 30 *
//! STOW_COST_BUDGET_MULTIPLIER`, dispatch freezes on the operation that
//! crossed it — not on a later poll. The `incident` issue record and
//! the while-frozen digest stay the watchdog's (#450); the edge sends
//! only the transition email.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use skyzen_services::durable::{DurableDb, DurableDbBackend, DurableDbError};
use skyzen_services::{DbExecResult, DbValue, QuerySource};

use crate::errors::QueueError;

/// DO `rowsRead` monthly allowance on Workers Paid — the meter's budget
/// line for reads. <https://developers.cloudflare.com/durable-objects/platform/pricing/>
/// lists 25 billion rows read/month included.
pub const DO_ROWS_READ_MONTHLY: f64 = 25e9;
/// DO `rowsWritten` monthly allowance on Workers Paid.
/// <https://developers.cloudflare.com/durable-objects/platform/pricing/>
/// lists 50 million rows written/month included.
pub const DO_ROWS_WRITTEN_MONTHLY: f64 = 50e6;

/// `STOW_COST_BUDGET_MULTIPLIER`'s default — scales every daily
/// budget, so a shared account can trip earlier by lowering it.
pub const DEFAULT_COST_BUDGET_MULTIPLIER: f64 = 1.0;

/// Parse a float-valued binding (`STOW_COST_BUDGET_MULTIPLIER`): a value
/// that is set but unparseable is a misconfiguration, so the parse fails
/// like every other binding's does rather than quietly defaulting.
pub fn parse_f64_binding(binding_name: &str, raw: &str) -> Result<f64, QueueError> {
    raw.parse::<f64>().map_err(|error| {
        QueueError::Invariant(format!("parse binding '{binding_name}' as f64: {error}"))
    })
}

/// The per-day budget is the included month spread over thirty days —
/// the same convention the deleted GraphQL probe used, now applied to
/// what the DO itself measured instead of what analytics reported.
const fn daily_budget(monthly: f64, multiplier: f64) -> f64 {
    monthly / 30.0 * multiplier
}

/// The day's meter row after the pending counts folded in — the values
/// the budget comparison and the cost-trip alert both read.
#[derive(Debug, Clone, Copy)]
pub struct MeterTotals {
    /// `rowsRead` billed to the DO today (UTC).
    pub rows_read: u64,
    /// `rowsWritten` billed to the DO today (UTC).
    pub rows_written: u64,
}

/// The operation's accumulated counts — atomics because the cloned
/// backend handles all feed it and handler futures must stay `Send`.
#[derive(Debug, Default)]
struct Pending {
    rows_read: AtomicU64,
    rows_written: AtomicU64,
}

impl Pending {
    fn add(&self, rows_read: u64, rows_written: u64) {
        self.rows_read.fetch_add(rows_read, Ordering::Relaxed);
        self.rows_written.fetch_add(rows_written, Ordering::Relaxed);
    }

    /// Read-and-clear — a settled operation's counts must not ride
    /// into the next settle's write.
    fn take(&self) -> (u64, u64) {
        (
            self.rows_read.swap(0, Ordering::Relaxed),
            self.rows_written.swap(0, Ordering::Relaxed),
        )
    }
}

/// The metering seam: a [`DurableDbBackend`] that forwards to the real
/// backend and accumulates each statement's row counts. `DurableDb`'s
/// `query().bind().fetch_*` builder reaches this through `QuerySource`,
/// so the placeholder counting, `LIMIT 1` append and row decode stay
/// skyzen's — nothing is re-implemented here.
#[derive(Clone)]
pub struct MeteringBackend {
    inner: Arc<DurableDb>,
    pending: Arc<Pending>,
}

impl MeteringBackend {
    async fn counted(
        inner: &Arc<DurableDb>,
        pending: &Arc<Pending>,
        sql: String,
        params: Vec<DbValue>,
        write: bool,
    ) -> Result<DbExecResult, DurableDbError> {
        let mut source: &DurableDb = inner;
        let result = if write {
            QuerySource::execute(&mut source, &sql, &params).await?
        } else {
            QuerySource::query(&mut source, &sql, &params).await?
        };
        pending.add(result.rows_read, result.rows_written);
        Ok(result)
    }
}

impl DurableDbBackend for MeteringBackend {
    fn query(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> impl Future<Output = Result<DbExecResult, DurableDbError>> + Send {
        Self::counted(
            &self.inner,
            &self.pending,
            query.to_owned(),
            params.to_vec(),
            false,
        )
    }

    fn execute(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> impl Future<Output = Result<DbExecResult, DurableDbError>> + Send {
        Self::counted(
            &self.inner,
            &self.pending,
            query.to_owned(),
            params.to_vec(),
            true,
        )
    }

    fn database_size(&self) -> impl Future<Output = Result<u64, DurableDbError>> + Send {
        let inner = Arc::clone(&self.inner);
        async move { inner.database_size().await }
    }
}

/// One operation's metering session: [`Meter::wrap`] returns the
/// wrapped `DurableDb` the handler runs on, and the `Meter` itself
/// settles the operation's counts afterward — through the unwrapped
/// inner handle, since metering the meter's own write would recurse
/// (and charge its row to a request that already ended).
#[derive(Clone)]
pub struct Meter {
    inner: Arc<DurableDb>,
    pending: Arc<Pending>,
}

#[derive(skyzen::FromRow)]
struct MeterRow {
    rows_read: u64,
    rows_written: u64,
}

impl Meter {
    /// Wrap `db` in the metering backend: the returned `DurableDb` is
    /// what handlers and queue functions see; the returned `Meter`
    /// settles and trips once the operation's work is done.
    pub fn wrap(db: DurableDb) -> (DurableDb, Self) {
        let inner = Arc::new(db);
        let pending = Arc::new(Pending::default());
        let metered = DurableDb::new(MeteringBackend {
            inner: Arc::clone(&inner),
            pending: Arc::clone(&pending),
        });
        (metered, Self { inner, pending })
    }

    /// The unmetered handle — the meter row's own write and the freeze
    /// trip's bookkeeping go through it.
    pub fn unmetered(&self) -> &DurableDb {
        &self.inner
    }

    /// Drain the pending counts into today's `do_meter` row and answer
    /// the totals. `Ok(None)` when the operation ran no statements (the
    /// row write would itself cost a write — skipped, not metered).
    ///
    /// The merge is one upsert keyed on the UTC day so a request that
    /// straddles midnight books its work to the day it ended in — a
    /// boundary skew of a few requests is acceptable and keeps the
    /// write single-statement.
    pub async fn settle(&self) -> Result<Option<MeterTotals>, QueueError> {
        let (read, written) = self.pending.take();
        if read == 0 && written == 0 {
            return Ok(None);
        }
        let totals = self
            .inner
            .query(
                "INSERT INTO do_meter (day, rows_read, rows_written) \
                 VALUES (strftime('%Y-%m-%d', 'now'), ?, ?) \
                 ON CONFLICT(day) DO UPDATE SET \
                   rows_read = do_meter.rows_read + excluded.rows_read, \
                   rows_written = do_meter.rows_written + excluded.rows_written \
                 RETURNING rows_read, rows_written",
            )
            .bind(i64::try_from(read).unwrap_or(i64::MAX))
            .bind(i64::try_from(written).unwrap_or(i64::MAX))
            .fetch_one::<MeterRow>()
            .await
            .map_err(|error| format!("settle do meter: {error}"))?;
        Ok(Some(MeterTotals {
            rows_read: totals.rows_read,
            rows_written: totals.rows_written,
        }))
    }

    /// The settled totals versus the budgets — the over-budget entries
    /// the cost-trip trigger carries, or `None` when `settle` saw no
    /// statements or the day is inside budget.
    #[expect(
        clippy::cast_precision_loss,
        reason = "row counts fit f64 exactly to 2^53"
    )]
    pub async fn budget_verdict(
        &self,
        multiplier: f64,
    ) -> Result<Option<Vec<stow_types::api::DispatchFreezeCostEntry>>, QueueError> {
        let Some(totals) = self.settle().await? else {
            return Ok(None);
        };
        let mut over = Vec::new();
        let read_budget = daily_budget(DO_ROWS_READ_MONTHLY, multiplier);
        let write_budget = daily_budget(DO_ROWS_WRITTEN_MONTHLY, multiplier);
        if totals.rows_read as f64 > read_budget {
            over.push(stow_types::api::DispatchFreezeCostEntry {
                metric: stow_types::api::CostMetric::DurableObjectRowsRead,
                used: totals.rows_read as f64,
                budget: read_budget,
            });
        }
        if totals.rows_written as f64 > write_budget {
            over.push(stow_types::api::DispatchFreezeCostEntry {
                metric: stow_types::api::CostMetric::DurableObjectRowsWritten,
                used: totals.rows_written as f64,
                budget: write_budget,
            });
        }
        if over.is_empty() {
            Ok(None)
        } else {
            Ok(Some(over))
        }
    }

    /// The whole event-driven cost trip, platform-free so host tests
    /// exercise what `settle_meter` wires: settle the operation's
    /// counts, and if the day just crossed budget engage the freeze
    /// with one transition email via `sink`. `store`/`sink` are seams:
    /// the wasm callers pass the DO's `DbStore` and `EdgeAlerter`, the
    /// tests fake both.
    ///
    /// A live freeze returns `Unchanged` — the meter keeps accruing
    /// (statements still cost), but the alert went out on the first
    /// transition; the while-frozen digest is the watchdog's (#450).
    pub async fn settle_and_trip(
        &self,
        store: &(impl crate::freeze::FreezeStore + Sync),
        sink: &(impl crate::freeze::AlertSink + Sync),
        multiplier: f64,
        now: &str,
    ) -> Result<Option<crate::freeze::FreezeTransition>, QueueError> {
        let Some(over) = self.budget_verdict(multiplier).await? else {
            return Ok(None);
        };
        let trigger =
            stow_types::api::DispatchFreezeTrigger::Cost(stow_types::api::DispatchFreezeCost {
                metric: over[0].metric,
                used: over[0].used,
                budget: over[0].budget,
                over,
                // Route shape comes from the watchdog's account view;
                // the DO sees statements, not URLs.
                top_routes: Vec::new(),
            });
        let transition = crate::freeze::apply_transition(
            store,
            sink,
            crate::freeze::FreezeAction::Freeze,
            trigger,
            now,
        )
        .await?;
        Ok(Some(transition))
    }
}

/// The fetch routes' metering middleware: swaps the request's
/// `DurableDb` extension for the metered wrapper before the handler
/// runs, then settles the operation's counts and — when the day
/// crossed the budget — engages the freeze on this request, not a
/// later poll.
#[cfg(target_arch = "wasm32")]
pub struct MeterGuard;

#[cfg(target_arch = "wasm32")]
impl skyzen::middleware::Middleware for MeterGuard {
    async fn handle(
        &self,
        request: &mut skyzen::Request,
        next: skyzen::middleware::Next<'_>,
    ) -> skyzen::Result<skyzen::Response> {
        let Some(db) = request.extensions().get::<DurableDb>().cloned() else {
            return next.run(request).await;
        };
        let (metered, meter) = Meter::wrap(db);
        request.extensions_mut().insert(metered);
        let env = request
            .extensions()
            .get::<skyzen::runtime::wasm::WasmEnv>()
            .cloned();
        let multiplier = match &env {
            Some(env) => super::object::cost_budget_multiplier(env)?,
            None => DEFAULT_COST_BUDGET_MULTIPLIER,
        };
        let response = next.run(request).await;
        if let Some(env) = env {
            super::object::settle_meter(&meter, &env, multiplier).await;
        }
        response
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::future::Future;
    use std::sync::Mutex;

    use stow_types::api::{ChannelOutcome, DispatchFreezeRecord};

    use skyzen_services::durable::DurableDb;

    use super::{DO_ROWS_WRITTEN_MONTHLY, Meter, daily_budget};
    use crate::errors::QueueError;
    use crate::freeze::{AlertDraft, AlertSink, FreezeStore, FreezeTransition};
    use crate::scheduler::queue;
    use crate::scheduler::test_db::memory_db;

    /// The `settings`-row freeze store the DO hands `settle_and_trip`,
    /// over the meter's unmetered inner handle.
    struct Store<'a>(&'a DurableDb);

    impl FreezeStore for Store<'_> {
        fn record(
            &self,
        ) -> impl Future<Output = Result<Option<DispatchFreezeRecord>, QueueError>> + Send {
            queue::freeze_record(self.0)
        }

        fn set(
            &self,
            record: &DispatchFreezeRecord,
        ) -> impl Future<Output = Result<(), QueueError>> + Send {
            queue::set_freeze(self.0, record)
        }

        fn delete(&self) -> impl Future<Output = Result<(), QueueError>> + Send {
            queue::delete_freeze(self.0)
        }
    }

    /// The email sink, faked: records `(verb, subject)` per send.
    #[derive(Default)]
    struct Sink(Mutex<Vec<(&'static str, String)>>);

    impl AlertSink for Sink {
        fn opened(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sink")
                .push(("opened", draft.subject.clone()));
            async { ChannelOutcome::Sent { message_id: None } }
        }

        fn updated(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sink")
                .push(("updated", draft.subject.clone()));
            async { ChannelOutcome::Sent { message_id: None } }
        }

        fn resolved(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sink")
                .push(("resolved", draft.subject.clone()));
            async { ChannelOutcome::Sent { message_id: None } }
        }
    }

    /// A metered handle plus its settle meter over the in-memory
    /// backend — the same `Meter::wrap` shape production installs.
    async fn metered() -> Result<(DurableDb, Meter), QueueError> {
        Ok(Meter::wrap(memory_db().await?))
    }

    #[tokio::test]
    async fn settle_skips_the_write_when_nothing_ran() {
        let (_db, meter) = metered().await.expect("db");
        assert!(meter.settle().await.expect("settle").is_none());
        // An unmetered check: the do_meter row must not exist.
        let row = meter
            .unmetered()
            .query("SELECT 1 FROM do_meter")
            .fetch_optional::<skyzen_services::Row>()
            .await
            .expect("meter row");
        assert!(row.is_none());
    }

    /// `STOW_COST_BUDGET_MULTIPLIER` parses like every other binding: a
    /// set-but-unparseable value is an error, not a quiet default.
    #[test]
    fn a_set_but_unparseable_budget_multiplier_is_an_error() {
        assert!(
            super::parse_f64_binding("STOW_COST_BUDGET_MULTIPLIER", "0.5")
                .is_ok_and(|value| (value - 0.5).abs() < f64::EPSILON)
        );
        let error = super::parse_f64_binding("STOW_COST_BUDGET_MULTIPLIER", "lots").unwrap_err();
        assert!(error.to_string().contains("STOW_COST_BUDGET_MULTIPLIER"));
    }

    #[tokio::test]
    async fn metered_statements_fold_into_the_day_row() {
        let (db, meter) = metered().await.expect("db");
        // A handful of real statements through the wrapped handle.
        db.query("INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version) \
                  VALUES ('t1', 'serde', '1.0.0', '[]', 'x86_64-unknown-linux-gnu', '1.98.1')")
            .execute()
            .await
            .expect("insert");
        db.query("SELECT COUNT(*) AS n FROM queue")
            .fetch_all::<skyzen_services::Row>()
            .await
            .expect("count");
        let totals = meter.settle().await.expect("settle").expect("a settle");
        assert!(totals.rows_read >= 1, "the SELECT read ≥1 row");
        assert!(totals.rows_written >= 1, "the INSERT wrote ≥1 row");
        // A second settle with no intervening work writes nothing.
        assert!(meter.settle().await.expect("settle again").is_none());
    }

    #[tokio::test]
    async fn the_write_is_the_only_meter_cost_per_request() {
        let (db, meter) = metered().await.expect("db");
        db.query("SELECT 1")
            .fetch_all::<skyzen_services::Row>()
            .await
            .expect("select");
        meter.settle().await.expect("settle");
        // Settle's own upsert is unmetered: pending stays empty.
        assert_eq!(meter.pending.take(), (0, 0));
        drop(db);
    }

    #[tokio::test]
    async fn crossing_the_budget_freezes_on_the_operation_that_crossed_it() {
        let (db, meter) = metered().await.expect("db");
        let sink = Sink::default();
        // A burst of writes through the wrapped handle; a tiny
        // multiplier puts the write budget under the burst.
        for index in 0..8 {
            db.query("INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version) \
                      VALUES (?, ?, '1.0.0', '[]', 'x86_64-unknown-linux-gnu', '1.98.1')")
                .bind(format!("t{index}"))
                .bind(format!("serde-{index}"))
                .execute()
                .await
                .expect("insert");
        }
        let multiplier = 1.0e-9;
        let transition = meter
            .settle_and_trip(
                &Store(meter.unmetered()),
                &sink,
                multiplier,
                "2026-09-27T01:00:00Z",
            )
            .await
            .expect("trip")
            .expect("a trip");
        let FreezeTransition::Engaged(record) = transition else {
            panic!("expected Engaged");
        };
        assert!(matches!(
            record.trigger,
            stow_types::api::DispatchFreezeTrigger::Cost(_)
        ));
        // The operation froze dispatch on its own settle — no poll.
        assert!(queue::freeze_enabled(&db).await.expect("enabled"));
        assert_eq!(
            sink.0.lock().expect("sink").as_slice(),
            [(
                "opened",
                "[stow] dispatch frozen — durable object rows written over daily budget".to_owned()
            )],
            "exactly one transition email"
        );

        // More metered work while frozen: the meter still accrues, the
        // trip re-evaluates, and the store answers Unchanged — the email
        // count stays at one.
        db.query("SELECT COUNT(*) AS n FROM queue")
            .fetch_all::<skyzen_services::Row>()
            .await
            .expect("count");
        let again = meter
            .settle_and_trip(
                &Store(meter.unmetered()),
                &sink,
                multiplier,
                "2026-09-27T01:05:00Z",
            )
            .await
            .expect("re-trip")
            .expect("still over");
        assert!(matches!(again, FreezeTransition::Unchanged));
        assert_eq!(sink.0.lock().expect("sink").len(), 1);
    }

    #[tokio::test]
    async fn under_budget_settles_without_a_trip() {
        let (db, meter) = metered().await.expect("db");
        let sink = Sink::default();
        db.query("SELECT 1")
            .fetch_all::<skyzen_services::Row>()
            .await
            .expect("select");
        let transition = meter
            .settle_and_trip(
                &Store(meter.unmetered()),
                &sink,
                1.0,
                "2026-09-27T01:00:00Z",
            )
            .await
            .expect("trip check");
        assert!(transition.is_none());
        assert!(sink.0.lock().expect("sink").is_empty());
        // The settle itself landed in do_meter under today's key.
        let day = meter
            .unmetered()
            .query("SELECT day FROM do_meter")
            .fetch_scalar::<String>()
            .await
            .expect("meter day");
        assert_eq!(day.len(), 10, "YYYY-MM-DD");
    }

    #[tokio::test]
    async fn budget_scales_with_the_multiplier() {
        let budget = daily_budget(DO_ROWS_WRITTEN_MONTHLY, 1.0);
        assert!((budget - DO_ROWS_WRITTEN_MONTHLY / 30.0).abs() < f64::EPSILON);
        assert!((daily_budget(30.0, 2.0) - 2.0).abs() < f64::EPSILON);
    }
}
