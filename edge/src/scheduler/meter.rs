//! The scheduler Durable Object's self-metered cost trip — the
//! event-driven replacement for the deleted cron probe (which cost one
//! Worker invocation + GraphQL read every ten minutes forever, and
//! duplicated the #450 watchdog's view of the same account budgets).
//!
//! `MeteringBackend` is a [`DurableDbBackend`] that forwards each
//! statement through [`QuerySource`] and books the returned
//! [`DbExecResult`]'s `rows_read`/`rows_written` — which `CfDurableDb`
//! reads off the `SqlStorageCursor` — into a per-operation `pending`
//! counter and the isolate-wide `unsettled` accumulator on the
//! [`GraphCell`]. Handlers keep extracting a plain `DurableDb` (the
//! middleware re-inserts the wrapped handle under the same type), so
//! `queue.rs` never knows it is metered. [`Meter::settle`] folds the
//! pending counts into the graph's per-UTC-day meter once per request
//! (and once per alarm pass) and subtracts them from `unsettled` — the
//! DO bills `rowsRead` and `rowsWritten`, so the meter measures
//! exactly what costs money. The one-row `meter` table checkpoints
//! `graph.meter + unsettled` at each wake and snapshot (stow#931), so
//! the stored row covers every operation in flight: the snapshot head
//! can never contain the cost of its own statements, and the durable
//! row is the single source a wake restores.
//!
//! Exactness rests on one rule the schema cannot enforce: between two
//! checkpoints the only billed statements are `event_log` appends —
//! the wake's replay re-counts each append at its billed 1 R + 1 W,
//! so a settled read or write after the last checkpoint would die
//! with the isolate, uncounted. Every statement outside a wake or
//! snapshot is an append; the budget probe's seed record rides the
//! snapshot head instead of a `store_meta` row for the same reason.
//!
//! The day the meter crosses `80% of the monthly allowance / 30 *
//! STOW_COST_BUDGET_MULTIPLIER` — one day of the stow#883 cost line —
//! dispatch freezes on the operation that crossed it — not on a later
//! poll. The `incident` issue record and
//! the while-frozen digest stay the watchdog's (#450); the edge sends
//! only the transition email.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use skyzen_services::durable::{DurableDb, DurableDbBackend, DurableDbError};
use skyzen_services::{DbExecResult, DbValue, QuerySource};

use super::graph::{GraphCell, LoadedGraph, Unsettled};
use crate::errors::QueueError;

/// The Workers Paid DO allowances the meter's daily budget lines divide
/// — one table in `stow-types`, shared with the watchdog and the
/// `Preheat cost` lane — and the daily derivation of the stow#883 line
/// they are checked against.
pub use stow_types::do_budgets::{DO_ROWS_READ_MONTHLY, DO_ROWS_WRITTEN_MONTHLY, daily_budget};

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

/// The day's meter after the pending counts folded in — the values the
/// budget comparison and the cost-trip alert both read.
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
    /// into the next settle.
    fn take(&self) -> (u64, u64) {
        (
            self.rows_read.swap(0, Ordering::Relaxed),
            self.rows_written.swap(0, Ordering::Relaxed),
        )
    }
}

/// The metering seam: a [`DurableDbBackend`] that forwards to the real
/// backend and accumulates each statement's row counts — once into the
/// operation's `pending` (what `settle` drains) and once into the
/// cell's `unsettled` (what a checkpoint folds in, so it covers every
/// operation in flight, not only the one that writes it). `DurableDb`'s
/// `query().bind().fetch_*` builder reaches this through `QuerySource`,
/// so the placeholder counting, `LIMIT 1` append and row decode stay
/// skyzen's — nothing is re-implemented here.
#[derive(Clone)]
pub struct MeteringBackend {
    inner: Arc<DurableDb>,
    pending: Arc<Pending>,
    unsettled: Arc<Unsettled>,
}

impl MeteringBackend {
    async fn counted(
        inner: &Arc<DurableDb>,
        pending: &Arc<Pending>,
        unsettled: &Arc<Unsettled>,
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
        unsettled.add(result.rows_read, result.rows_written);
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
            &self.unsettled,
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
            &self.unsettled,
            query.to_owned(),
            params.to_vec(),
            true,
        )
    }

    fn database_size(&self) -> impl Future<Output = Result<u64, DurableDbError>> + Send {
        let inner = Arc::clone(&self.inner);
        async move { inner.database_size().await }
    }

    fn sync(&self) -> impl Future<Output = Result<(), DurableDbError>> + Send {
        let inner = Arc::clone(&self.inner);
        async move { inner.sync().await }
    }
}

/// One operation's metering session: [`Meter::wrap`] returns the
/// wrapped `DurableDb` the handler runs on, and the `Meter` itself
/// settles the operation's counts into the graph's day meter afterward.
/// The day's durable copy is the `meter` row's checkpoint, written at
/// each wake and snapshot — settling itself costs no storage row.
#[derive(Clone)]
pub struct Meter {
    pending: Arc<Pending>,
    /// The cell's isolate-wide accumulator this meter's backend also
    /// books into — `settle` subtracts what it takes so `graph.meter +
    /// unsettled` stays the exact billed total (stow#931).
    unsettled: Arc<Unsettled>,
    /// The probe-ledger op this operation also books under — set only
    /// on the budget-probe deploy (`STOW_SCHEDULER_BUDGET=1`), where the
    /// `Preheat cost` lane reads cost per event kind.
    ledger_op: Option<String>,
}

impl Meter {
    /// Wrap `db` in the metering backend, bound to `cell`'s unsettled
    /// accumulator: the returned `DurableDb` is what handlers and store
    /// functions see; the returned `Meter` settles and trips once the
    /// operation's work is done.
    pub fn wrap(db: DurableDb, cell: &GraphCell) -> (DurableDb, Self) {
        let pending = Arc::new(Pending::default());
        let metered = DurableDb::new(MeteringBackend {
            inner: Arc::new(db),
            pending: Arc::clone(&pending),
            unsettled: Arc::clone(cell.unsettled()),
        });
        (
            metered,
            Self {
                pending,
                unsettled: Arc::clone(cell.unsettled()),
                ledger_op: None,
            },
        )
    }

    /// Also book this operation's counts under `op` in the probe ledger
    /// when it settles. Only the budget-probe deploy asks for it.
    #[must_use]
    pub fn with_ledger_op(mut self, op: String) -> Self {
        self.ledger_op = Some(op);
        self
    }

    /// Drain the pending counts into the graph's day meter at `now_ms`
    /// and answer the day's totals. `None` when the operation ran no
    /// statements.
    pub fn settle(&self, graph: LoadedGraph<'_>, now_ms: i64) -> Option<MeterTotals> {
        let (read, written) = self.pending.take();
        self.unsettled.sub(read, written);
        graph.with(|graph| {
            graph.meter.roll_to(&super::graph::utc_day(now_ms));
            match &self.ledger_op {
                Some(op) => graph.meter.record(op, read, written),
                None if read == 0 && written == 0 => return None,
                None => graph.meter.add(read, written),
            }
            Some(MeterTotals {
                rows_read: graph.meter.rows_read,
                rows_written: graph.meter.rows_written,
            })
        })
    }

    /// The settled totals versus the budgets — the over-budget entries
    /// the cost-trip trigger carries, or `None` when `settle` saw no
    /// statements or the day is inside budget.
    #[expect(
        clippy::cast_precision_loss,
        reason = "row counts fit f64 exactly to 2^53"
    )]
    pub fn budget_verdict(
        &self,
        graph: LoadedGraph<'_>,
        now_ms: i64,
        multiplier: f64,
    ) -> Option<Vec<stow_types::api::DispatchFreezeCostEntry>> {
        let totals = self.settle(graph, now_ms)?;
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
        (!over.is_empty()).then_some(over)
    }

    /// The whole event-driven cost trip, platform-free so host tests
    /// exercise what `settle_meter` wires: settle the operation's
    /// counts, and if the day just crossed budget engage the freeze
    /// with one transition email via `sink`. `store`/`sink` are seams:
    /// the wasm callers pass the graph-backed store and `EdgeAlerter`,
    /// the tests fake the sink.
    ///
    /// A live freeze returns `Unchanged` — the meter keeps accruing
    /// (statements still cost), but the alert went out on the first
    /// transition; the while-frozen digest is the watchdog's (#450).
    pub async fn settle_and_trip(
        &self,
        graph: LoadedGraph<'_>,
        now_ms: i64,
        store: &(impl crate::freeze::FreezeStore + Sync),
        sink: &(impl crate::freeze::AlertSink + Sync),
        multiplier: f64,
        now: &str,
    ) -> Result<Option<crate::freeze::FreezeTransition>, QueueError> {
        let Some(over) = self.budget_verdict(graph, now_ms, multiplier) else {
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

/// The probe ledger's op name for one request: `<METHOD> <route>`, with
/// a request-record id collapsed to `{id}` and a batch's completion
/// collapsed to [`LEDGER_OP_BATCH_COMPLETE`], so every record's reads
/// and every batch's completion land on one row each.
///
/// [`LEDGER_OP_BATCH_COMPLETE`]: stow_types::do_budgets::LEDGER_OP_TASK_COMPLETE
#[must_use]
pub fn ledger_op(method: &str, path: &str) -> String {
    if method == "POST"
        && path
            .strip_prefix("/batches/")
            .and_then(|rest| rest.strip_suffix("/complete"))
            .is_some_and(|batch_id| !batch_id.is_empty() && !batch_id.contains('/'))
    {
        return stow_types::do_budgets::LEDGER_OP_TASK_COMPLETE.to_owned();
    }
    let route = path.strip_prefix("/requests/").map_or_else(
        || path.to_owned(),
        |rest| {
            rest.split_once('/').map_or_else(
                || "/requests/{id}".to_owned(),
                |(_, tail)| format!("/requests/{{id}}/{tail}"),
            )
        },
    );
    format!("{method} {route}")
}

/// Every op the day meter booked since the last reset — the
/// `GET /budget/ledger` answer. Bounded by the number of distinct
/// operations the object serves, never by the queue.
pub fn ledger(graph: LoadedGraph<'_>) -> stow_types::api::SchedulerLedger {
    graph.with(|graph| stow_types::api::SchedulerLedger {
        woken_at_ms: graph.woken_at_ms,
        ops: graph
            .meter
            .ops
            .iter()
            .map(
                |(op, &(events, rows_read, rows_written))| stow_types::api::SchedulerLedgerOp {
                    op: op.clone(),
                    events,
                    rows_read,
                    rows_written,
                },
            )
            .collect(),
    })
}

/// The fetch routes' metering middleware: swaps the request's
/// `DurableDb` extension for the metered wrapper before the handler
/// runs, then settles the operation's counts and — when the day
/// crossed the budget — engages the freeze on this request, not a
/// later poll. The wrap binds to the object's `GraphCell`: every
/// statement books into the cell's isolate-wide `unsettled`, so a
/// wake's or a snapshot's meter checkpoint covers every operation in
/// flight, not only the checkpointing one (stow#931).
#[cfg(target_arch = "wasm32")]
pub struct MeterGuard {
    graph: GraphCell,
}

#[cfg(target_arch = "wasm32")]
impl MeterGuard {
    /// The object's graph cell — the wraps bind to its `unsettled`.
    pub const fn new(graph: GraphCell) -> Self {
        Self { graph }
    }
}

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
        let (metered, meter) = Meter::wrap(db.clone(), &self.graph);
        request.extensions_mut().insert(metered);
        let env = request
            .extensions()
            .get::<skyzen::runtime::wasm::WasmEnv>()
            .cloned();
        let meter = if env
            .as_ref()
            .is_some_and(super::object::budget_probe_enabled)
        {
            meter.with_ledger_op(ledger_op(request.method().as_str(), request.uri().path()))
        } else {
            meter
        };
        let multiplier = match &env {
            Some(env) => super::object::cost_budget_multiplier(env)?,
            None => DEFAULT_COST_BUDGET_MULTIPLIER,
        };
        let response = next.run(request).await;
        if let Some(env) = env {
            super::object::settle_meter(&self.graph, &db, &meter, &env, multiplier).await;
        }
        response
    }
}

/// `object::settle_meter`'s measured tail, platform-free so host tests
/// run the real freeze-append wiring (stow#931): settle `aux` — whose
/// metered `db` the caller already woke the graph on, so the wake's
/// own reads are in the verdict's totals — evaluate the cost trip,
/// append whatever `Freeze` events the transition staged **on the
/// metered handle** (booking the append, so a later checkpoint covers
/// its seq and a wake replays the row exactly once), then settle `aux`
/// again. `at` is the transition's ISO timestamp.
///
/// # Errors
/// `QueueError` from the trip evaluation; a failed freeze append is
/// logged, never raised — a metering bug must not take dispatch down.
#[expect(
    clippy::too_many_arguments,
    reason = "settle_meter's whole context: the two meters, both handles, the sink and the stamps"
)]
pub async fn trip_and_persist(
    aux: &Meter,
    metered_db: &DurableDb,
    meter: &Meter,
    graph: LoadedGraph<'_>,
    sink: &(impl crate::freeze::AlertSink + Sync),
    multiplier: f64,
    now_ms: i64,
    at: &str,
) -> Result<Option<crate::freeze::FreezeTransition>, QueueError> {
    aux.settle(graph, now_ms);
    let store = super::graph::GraphFreezeStore::new(graph, at.to_owned(), now_ms);
    let transition = meter
        .settle_and_trip(graph, now_ms, &store, sink, multiplier, at)
        .await?;
    if let Err(error) = super::routes::persist_freeze(metered_db, &store, now_ms).await {
        tracing::error!(%error, "persist cost-trip freeze failed");
    }
    aux.settle(graph, now_ms);
    Ok(transition)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::future::Future;
    use std::sync::Mutex;

    use stow_types::api::{ChannelOutcome, SchedulerEvent};

    use skyzen_services::durable::DurableDb;

    use super::{DO_ROWS_WRITTEN_MONTHLY, Meter, daily_budget};
    use crate::freeze::{AlertDraft, AlertSink, FreezeTransition};
    use crate::scheduler::graph::{Graph, GraphCell, GraphFreezeStore};
    use crate::scheduler::{store, test_db};

    const NOW_MS: i64 = 1_790_000_000_000;

    /// A loaded graph cell — the substrate the meter settles into and
    /// the freeze store gates on.
    fn cell() -> GraphCell {
        let cell = GraphCell::default();
        cell.install(Graph::default());
        cell
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

    /// A metered handle over the in-memory store plus its meter — the
    /// same `Meter::wrap` shape production installs, bound to `cell`'s
    /// unsettled accumulator.
    async fn metered(cell: &GraphCell) -> (DurableDb, Meter) {
        Meter::wrap(test_db::memory_db().await.expect("db"), cell)
    }

    fn mutate() -> SchedulerEvent {
        SchedulerEvent::Mutate {
            op: stow_types::api::MutationKind::Retry,
            task_ids: vec!["t".to_owned()],
        }
    }

    /// Every request record books under one op per route.
    #[test]
    fn a_request_record_id_collapses_to_its_route() {
        assert_eq!(
            super::ledger_op("GET", "/requests/7f3a"),
            "GET /requests/{id}"
        );
        assert_eq!(
            super::ledger_op("POST", "/requests/7f3a/outcome"),
            "POST /requests/{id}/outcome"
        );
        assert_eq!(super::ledger_op("POST", "/requests"), "POST /requests");
    }

    /// Every batch's completion books under the one op the Preheat cost
    /// report reads as its `Completion` kind; nothing else under
    /// `/batches/` collapses into it.
    #[test]
    fn a_batch_completion_collapses_to_the_shared_ledger_op() {
        let completion = stow_types::do_budgets::LEDGER_OP_TASK_COMPLETE;
        assert_eq!(
            super::ledger_op("POST", "/batches/00000000000000000000000000000001/complete"),
            completion
        );
        assert_eq!(
            super::ledger_op("POST", "/batches/a/complete"),
            super::ledger_op("POST", "/batches/b/complete")
        );
        assert_eq!(
            stow_types::preheat_cost::EventKind::Completion.ledger_op(),
            completion
        );
        assert_ne!(super::ledger_op("GET", "/batches/a/complete"), completion);
        assert_ne!(super::ledger_op("POST", "/batches//complete"), completion);
        assert_ne!(
            super::ledger_op("POST", "/batches/a/b/complete"),
            completion
        );
    }

    #[tokio::test]
    async fn settle_books_nothing_when_nothing_ran() {
        let owner = cell();
        let (_db, meter) = metered(&owner).await;
        let cell = owner.loaded().expect("installed");
        assert!(meter.settle(cell, NOW_MS).is_none());
        assert_eq!(cell.with(|graph| graph.meter.rows_written), 0);
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
    async fn metered_statements_fold_into_the_day_meter() {
        let owner = cell();
        let (db, meter) = metered(&owner).await;
        let cell = owner.loaded().expect("installed");
        store::append_events(&db, &[mutate(), mutate()], NOW_MS)
            .await
            .expect("append");
        store::log_tail(&db, 0).await.expect("tail");
        let totals = meter.settle(cell, NOW_MS).expect("a settle");
        assert!(totals.rows_written >= 2, "two appended rows");
        assert!(totals.rows_read >= 2, "the tail read both rows back");
        // A second settle with no intervening work books nothing new.
        let again = meter.settle(cell, NOW_MS);
        assert!(again.is_none());
        assert_eq!(
            cell.with(|graph| graph.meter.rows_written),
            totals.rows_written
        );
    }

    #[tokio::test]
    async fn the_probe_ledger_books_one_event_per_operation() {
        let owner = cell();
        let (db, meter) = metered(&owner).await;
        let meter = meter.with_ledger_op("POST /tasks/retry".to_owned());
        let cell = owner.loaded().expect("installed");
        cell.with(|graph| graph.woken_at_ms = NOW_MS - 5);
        store::append_events(&db, &[mutate()], NOW_MS)
            .await
            .expect("append");
        meter.settle(cell, NOW_MS);
        // An operation with no statements still counts as an event.
        meter.settle(cell, NOW_MS);
        let ledger = super::ledger(cell);
        // The reader tells this graph's ledger from a reloaded one's.
        assert_eq!(ledger.woken_at_ms, NOW_MS - 5);
        let [op] = ledger.ops.as_slice() else {
            panic!("one op row");
        };
        assert_eq!(op.op, "POST /tasks/retry");
        assert_eq!(op.events, 2);
        assert!(op.rows_written >= 1);
    }

    #[tokio::test]
    async fn the_day_rolls_at_utc_midnight() {
        let owner = cell();
        let (db, meter) = metered(&owner).await;
        let cell = owner.loaded().expect("installed");
        store::append_events(&db, &[mutate()], NOW_MS)
            .await
            .expect("append");
        let first = meter.settle(cell, NOW_MS).expect("settle");
        store::append_events(&db, &[mutate()], NOW_MS + 86_400_000)
            .await
            .expect("append");
        let next = meter.settle(cell, NOW_MS + 86_400_000).expect("settle");
        assert!(first.rows_written >= 1);
        assert_eq!(next.rows_written, 1, "the new day starts from zero");
    }

    #[tokio::test]
    async fn crossing_the_budget_freezes_on_the_operation_that_crossed_it() {
        let owner = cell();
        let (db, meter) = metered(&owner).await;
        let sink = Sink::default();
        let cell = owner.loaded().expect("installed");
        // A burst of writes through the wrapped handle; a tiny
        // multiplier puts the write budget under the burst.
        for _ in 0..8 {
            store::append_events(&db, &[mutate()], NOW_MS)
                .await
                .expect("append");
        }
        let multiplier = 1.0e-9;
        let freeze_store = GraphFreezeStore::new(cell, "2026-09-27T01:00:00Z".to_owned(), NOW_MS);
        let transition = meter
            .settle_and_trip(
                cell,
                NOW_MS,
                &freeze_store,
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
        // The operation froze dispatch on its own settle — no poll —
        // and staged the `Freeze` event for the log.
        assert!(cell.with(|g| g.freeze().is_some()));
        assert_eq!(freeze_store.take_events().len(), 1);
        assert_eq!(
            sink.0.lock().expect("sink").as_slice(),
            [(
                "opened",
                "[stow] dispatch frozen — durable object rows read over daily budget".to_owned()
            )],
            "exactly one transition email, naming the first metric over (an append's RETURNING \
             row reads one)"
        );

        // More metered work while frozen: the meter still accrues, the
        // trip re-evaluates, and the store answers Unchanged — the email
        // count stays at one.
        store::log_tail(&db, 0).await.expect("tail");
        let again = meter
            .settle_and_trip(
                cell,
                NOW_MS,
                &GraphFreezeStore::new(cell, "2026-09-27T01:00:00Z".to_owned(), NOW_MS),
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
        let owner = cell();
        let (db, meter) = metered(&owner).await;
        let sink = Sink::default();
        let cell = owner.loaded().expect("installed");
        store::log_tail(&db, 0).await.expect("tail");
        let transition = meter
            .settle_and_trip(
                cell,
                NOW_MS,
                &GraphFreezeStore::new(cell, "2026-09-27T01:00:00Z".to_owned(), NOW_MS),
                &sink,
                1.0,
                "2026-09-27T01:00:00Z",
            )
            .await
            .expect("trip check");
        assert!(transition.is_none());
        assert!(sink.0.lock().expect("sink").is_empty());
        assert_eq!(
            cell.with(|graph| graph.meter.day.clone()),
            super::super::graph::utc_day(NOW_MS)
        );
    }

    #[tokio::test]
    async fn budget_scales_with_the_multiplier() {
        let budget = daily_budget(DO_ROWS_WRITTEN_MONTHLY, 1.0);
        let expected = DO_ROWS_WRITTEN_MONTHLY * stow_types::do_budgets::DAILY_SHARE;
        assert!((budget - expected).abs() < f64::EPSILON);
        assert!((daily_budget(30.0, 2.0) - 1.6).abs() < f64::EPSILON);
    }
}
