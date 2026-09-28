//! The scheduler Durable Object's self-metered cost trip — the
//! event-driven replacement for the deleted cron probe (which cost one
//! Worker invocation + GraphQL read every ten minutes forever, and
//! duplicated the #450 watchdog's view of the same account budgets).
//!
//! `MeteredDb` wraps `DurableDb` with the same `query().bind().fetch_*`
//! builder shape; the difference is at the seam: [`QuerySource`] hands
//! back [`DbExecResult`], whose `rows_read`/`rows_written` the real
//! `CfDurableDb` populates from `SqlStorageCursor`, so every statement
//! the object runs feeds the meter without the query code knowing.
//! Pending counts settle into a per-UTC-day `do_meter` row once per
//! request (and once per alarm pass) — the DO bills `rowsRead` and
//! `rowsWritten`, so the meter measures exactly what costs money.
//!
//! The day the meter crosses `monthly allowance / 30 *
//! STOW_COST_BUDGET_MULTIPLIER`, dispatch freezes on the operation that
//! crossed it — not on a later poll. The `incident` record and the
//! while-frozen digest stay the watchdog's (#450); the edge sends only
//! the transition email.

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use skyzen::extract::Extractor;
use skyzen_services::durable::sql::DurableDbNotConfigured;
use skyzen_services::durable::{DurableDb, DurableDbError};
use skyzen_services::sqlparser::dialect::SQLiteDialect;
use skyzen_services::sqlparser::keywords::Keyword;
use skyzen_services::sqlparser::tokenizer::{Token, Tokenizer};
use skyzen_services::{DbExecResult, DbValue, FromColumn, FromRow, QuerySource, Row};

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

/// `DurableDb` plus the statement counters it feeds. Extraction hands
/// out clones sharing one `pending` accumulator per request; queue
/// functions take `&MeteredDb` and never see the metering.
///
/// Constructed three ways: `MeterGuard` inserts one into request
/// extensions (wasm), `run_alarm` wraps its `DurableDb` directly, and
/// host tests build it over the in-memory backend.
#[derive(Debug)]
pub struct MeteredDb {
    db: DurableDb,
    pending: Arc<Pending>,
}

/// The request's accumulated counts — atomics because the cloned
/// handles all feed it and handler futures must stay `Send`.
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

    /// Read-and-clear — a settled request's counts must not ride into
    /// the next settle's write.
    fn take(&self) -> (u64, u64) {
        (
            self.rows_read.swap(0, Ordering::Relaxed),
            self.rows_written.swap(0, Ordering::Relaxed),
        )
    }
}

impl Clone for MeteredDb {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            pending: Arc::clone(&self.pending),
        }
    }
}

impl Extractor for MeteredDb {
    type Error = DurableDbNotConfigured;

    async fn extract(request: &mut skyzen::Request) -> Result<Self, Self::Error> {
        // The middleware-installed metered handle wins so its pending
        // accumulator is the one `settle` drains after the handler runs.
        if let Some(metered) = request.extensions().get::<Self>() {
            return Ok(metered.clone());
        }
        DurableDb::extract(request).await.map(Self::new)
    }
}

impl MeteredDb {
    /// Wrap a `DurableDb` — every statement through [`query`](Self::query)
    /// from now on lands its row counts in `pending`.
    pub fn new(db: DurableDb) -> Self {
        Self {
            db,
            pending: Arc::new(Pending::default()),
        }
    }

    /// The un-metered handle — schema/bootstrap and the meter row's own
    /// write go through it, since metering the meter would recurse.
    pub const fn raw(&self) -> &DurableDb {
        &self.db
    }

    /// Start building a query — same fluent shape as
    /// [`DurableDb::query`], so call sites only change the argument type.
    pub const fn query<'a>(&'a self, sql: &'a str) -> MeteredQuery<'a> {
        MeteredQuery {
            metered: self,
            sql,
            params: Vec::new(),
        }
    }

    /// Drain the pending counts into today's `do_meter` row and answer
    /// the totals. `Ok(None)` when the request ran no statements (the
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
            .raw()
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
    /// (one transition email via `sink`) and flip the panic switch —
    /// an over-budget day is not the moment to keep paying anonymous
    /// miss lookups. `store`/`sink` are seams: the wasm callers pass
    /// the DO's `DbStore` and `EdgeAlerter`, the tests fake both.
    ///
    /// A live freeze returns `Unchanged` — the meter keeps accruing
    /// (statements still cost), but the alert went out on the first
    /// transition; the while-frozen digest is the watchdog's (#450).
    #[allow(clippy::future_not_send)]
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
        if matches!(transition, crate::freeze::FreezeTransition::Engaged(_)) {
            super::queue::set_panic(self, true).await?;
        }
        Ok(Some(transition))
    }
}

#[derive(skyzen::FromRow)]
struct MeterRow {
    rows_read: u64,
    rows_written: u64,
}

/// The statement builder [`MeteredDb::query`] hands back — mirrors
/// `DurableDbQuery`'s surface (`bind` → `execute` / `fetch_*`) so a
/// `&DurableDb` → `&MeteredDb` signature change is the whole refactor.
pub struct MeteredQuery<'a> {
    metered: &'a MeteredDb,
    sql: &'a str,
    params: Vec<DbValue>,
}

impl<'a> MeteredQuery<'a> {
    /// Bind a parameter value to the query.
    #[must_use]
    pub fn bind<T>(mut self, value: T) -> Self
    where
        T: Into<DbValue>,
    {
        self.params.push(value.into());
        self
    }

    /// The `?` placeholders the statement declares — counted with the
    /// same sqlparser tokenizer skyzen uses, so a mismatch fails as the
    /// same `ParameterCountMismatch` it would have raised.
    fn expected_params(&self) -> Result<usize, DurableDbError> {
        let tokens = Tokenizer::new(&SQLiteDialect {}, self.sql)
            .tokenize_with_location()
            .map_err(|error| DurableDbError::SqlParse(error.to_string()))?;
        Ok(tokens
            .iter()
            .filter(|token| matches!(&token.token, Token::Placeholder(value) if value == "?"))
            .count())
    }

    /// `LIMIT 1` appended when the statement is an unbounded `SELECT` —
    /// the same bound `fetch_optional`/`fetch_one` get from skyzen's
    /// builder, so one-row fetches never scan (or bill) a result set
    /// only the first row of which is used. Anything exotic — its own
    /// `LIMIT`/`TOP`/`OFFSET`, `FOR`, `INTO`, or a multi-statement
    /// string — passes through untouched.
    fn bound_single_row(&self) -> Result<Cow<'a, str>, DurableDbError> {
        const BLOCKING: &[Keyword] = &[
            Keyword::LIMIT,
            Keyword::FETCH,
            Keyword::TOP,
            Keyword::OFFSET,
            Keyword::FOR,
            Keyword::INTO,
        ];
        let tokens = Tokenizer::new(&SQLiteDialect {}, self.sql)
            .tokenize_with_location()
            .map_err(|error| DurableDbError::SqlParse(error.to_string()))?;
        let meaningful: Vec<&Token> = tokens
            .iter()
            .map(|token| &token.token)
            .filter(|token| !matches!(token, Token::Whitespace(_)))
            .collect();
        let first_is_select = matches!(
            meaningful.first(),
            Some(Token::Word(word)) if matches!(word.keyword, Keyword::SELECT | Keyword::WITH)
        );
        let blocked = meaningful
            .iter()
            .any(|token| matches!(token, Token::Word(word) if BLOCKING.contains(&word.keyword)));
        let inner_semicolon = meaningful
            .iter()
            .take(meaningful.len().saturating_sub(1))
            .any(|token| matches!(token, Token::SemiColon));
        if first_is_select && !blocked && !inner_semicolon {
            Ok(Cow::Owned(format!("{} LIMIT 1", self.sql)))
        } else {
            Ok(Cow::Borrowed(self.sql))
        }
    }

    async fn run(&self, sql: &str, write: bool) -> Result<DbExecResult, DurableDbError> {
        let expected = self.expected_params()?;
        if expected != self.params.len() {
            return Err(DurableDbError::ParameterCountMismatch {
                expected,
                actual: self.params.len(),
            });
        }
        let mut source = &self.metered.db;
        let result = if write {
            QuerySource::execute(&mut source, sql, &self.params).await?
        } else {
            QuerySource::query(&mut source, sql, &self.params).await?
        };
        self.metered
            .pending
            .add(result.rows_read, result.rows_written);
        Ok(result)
    }

    /// Execute a statement that does not return rows.
    ///
    /// # Errors
    ///
    /// Returns [`DurableDbError`] on placeholder mismatch or backend
    /// failure.
    pub async fn execute(self) -> Result<DbExecResult, DurableDbError> {
        let sql = self.sql.to_owned();
        self.run(&sql, true).await
    }

    /// Execute a query and decode every row into `T`.
    ///
    /// # Errors
    ///
    /// Returns [`DurableDbError`] on placeholder mismatch, backend
    /// failure, or row decode failure.
    pub async fn fetch_all<T>(self) -> Result<Vec<T>, DurableDbError>
    where
        T: FromRow,
    {
        let sql = self.sql.to_owned();
        let result = self.run(&sql, false).await?;
        result
            .rows
            .into_iter()
            .map(|value| Row::try_from_value(value).and_then(T::from_row))
            .collect::<Result<Vec<T>, _>>()
            .map_err(DurableDbError::Decode)
    }

    /// Execute a query and decode the first row, if present — bounded
    /// to one row on the backend side when the statement allows it.
    ///
    /// # Errors
    ///
    /// Returns [`DurableDbError`] on placeholder mismatch, backend
    /// failure, or row decode failure.
    pub async fn fetch_optional<T>(self) -> Result<Option<T>, DurableDbError>
    where
        T: FromRow,
    {
        let sql = self.bound_single_row()?;
        let result = self.run(&sql, false).await?;
        result
            .rows
            .into_iter()
            .next()
            .map(|value| Row::try_from_value(value).and_then(T::from_row))
            .transpose()
            .map_err(DurableDbError::Decode)
    }

    /// Execute a query and decode exactly one row.
    ///
    /// # Errors
    ///
    /// Returns [`DurableDbError::RowNotFound`] when the row is absent.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub async fn fetch_one<T>(self) -> Result<T, DurableDbError>
    where
        T: FromRow,
    {
        self.fetch_optional()
            .await?
            .ok_or(DurableDbError::RowNotFound)
    }

    /// Execute a single-column query and decode that column of the
    /// first row.
    ///
    /// # Errors
    ///
    /// Returns [`DurableDbError::RowNotFound`] when the row is absent.
    pub async fn fetch_scalar<T>(self) -> Result<T, DurableDbError>
    where
        T: FromColumn,
    {
        let row = self.fetch_optional::<Row>().await?;
        let row = row.ok_or(DurableDbError::RowNotFound)?;
        row.scalar().map_err(DurableDbError::Decode)
    }

    /// Execute a single-column query and decode that column of the
    /// first row, if there is one.
    ///
    /// # Errors
    ///
    /// Returns [`DurableDbError`] on failure or decode mismatch.
    pub async fn fetch_scalar_optional<T>(self) -> Result<Option<T>, DurableDbError>
    where
        T: FromColumn,
    {
        self.fetch_optional::<Row>()
            .await?
            .map(|row| row.scalar().map_err(DurableDbError::Decode))
            .transpose()
    }
}

/// The fetch routes' metering middleware: installs the shared
/// `MeteredDb` into the request extensions before the handler runs,
/// then settles the request's counts and — when the day crossed the
/// budget — engages the freeze on this request, not a later poll.
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
        let metered = MeteredDb::new(db);
        request.extensions_mut().insert(metered.clone());
        let env = request
            .extensions()
            .get::<skyzen::runtime::wasm::WasmEnv>()
            .cloned();
        let response = next.run(request).await;
        if let Some(env) = env {
            super::object::settle_meter(&metered, &env).await;
        }
        response
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::future::Future;
    use std::sync::Mutex;

    use stow_types::api::{ChannelOutcome, DispatchFreezeRecord};

    use super::{DO_ROWS_WRITTEN_MONTHLY, MeteredDb, daily_budget};
    use crate::freeze::{AlertDraft, AlertSink, FreezeStore, FreezeTransition};
    use crate::scheduler::queue;
    use crate::scheduler::test_db::memory_db;

    /// The `settings`-row freeze store the DO hands `settle_and_trip`,
    /// over the same `MeteredDb` the operation ran on.
    struct Store<'a>(&'a MeteredDb);

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

    use crate::errors::QueueError;

    /// The email sink, faked: records `(verb, subject)` per send.
    #[derive(Default)]
    struct Sink(Mutex<Vec<(&'static str, String)>>);

    impl AlertSink for Sink {
        fn opened(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sink")
                .push(("opened", draft.subject.clone()));
            std::future::ready(ChannelOutcome::Sent { message_id: None })
        }

        fn updated(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sink")
                .push(("updated", draft.subject.clone()));
            std::future::ready(ChannelOutcome::Sent { message_id: None })
        }

        fn resolved(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sink")
                .push(("resolved", draft.subject.clone()));
            std::future::ready(ChannelOutcome::Sent { message_id: None })
        }
    }

    /// A burst of statements crosses the day budget → the freeze
    /// engages on the operation's own settle, dispatch is gated
    /// immediately, panic flips, and exactly one email goes out — the
    /// next operation's settle does not resend it.
    #[tokio::test]
    async fn meter_burst_freezes_dispatch_on_the_settling_operation() {
        let db = MeteredDb::new(memory_db().await.expect("memory db"));
        let sink = Sink::default();

        // A burst of writes — each lands rows_written on the meter.
        for i in 0..40 {
            db.query("INSERT INTO settings (key, value) VALUES (?, '1')")
                .bind(format!("burst-{i}"))
                .execute()
                .await
                .expect("insert");
        }

        // A budget near zero makes the burst a trip — the multiplier
        // binding's job in miniature.
        let transition = db
            .settle_and_trip(&Store(&db), &sink, 1e-12, "2026-09-28T00:00:00Z")
            .await
            .expect("settle")
            .expect("over budget");
        let record = match transition {
            FreezeTransition::Engaged(record) => record,
            other => panic!("expected Engaged, got {other:?}"),
        };
        assert!(matches!(
            record.trigger,
            stow_types::api::DispatchFreezeTrigger::Cost(_)
        ));

        // The operation froze dispatch on its own settle — no poll.
        assert!(queue::freeze_enabled(&db).await.expect("enabled"));
        assert!(queue::panic_enabled(&db).await.expect("panic"));
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
        db.query("INSERT INTO settings (key, value) VALUES ('burst-extra', '1')")
            .execute()
            .await
            .expect("insert");
        let transition = db
            .settle_and_trip(&Store(&db), &sink, 1e-12, "2026-09-28T00:01:00Z")
            .await
            .expect("settle")
            .expect("still over");
        assert!(matches!(transition, FreezeTransition::Unchanged));
        assert_eq!(sink.0.lock().expect("sink").len(), 1);
    }

    /// The meter is honest arithmetic: reads and writes accumulate
    /// separately, `settle` drains `pending` so a settled request's
    /// counts never ride into the next settle's write, and an idle
    /// request writes nothing at all.
    #[tokio::test]
    async fn meter_counts_rows_and_settle_is_idempotent() {
        let db = MeteredDb::new(memory_db().await.expect("memory db"));

        // No work → no settle write, no verdict.
        assert!(db.settle().await.expect("settle").is_none());

        db.query("INSERT INTO settings (key, value) VALUES ('a', '1')")
            .execute()
            .await
            .expect("insert");
        let _rows: Vec<skyzen_services::Row> = db
            .query("SELECT key, value FROM settings")
            .fetch_all()
            .await
            .expect("read");

        let totals = db.settle().await.expect("settle").expect("worked");
        assert!(totals.rows_written >= 1, "writes counted: {totals:?}");
        assert!(totals.rows_read >= 1, "reads counted: {totals:?}");

        // Drained — a second settle without new work adds nothing.
        assert!(db.settle().await.expect("settle").is_none());

        // Inside a sane multiplier the day does not trip.
        assert!(
            db.budget_verdict(crate::scheduler::meter::DEFAULT_COST_BUDGET_MULTIPLIER)
                .await
                .expect("verdict")
                .is_none()
        );
    }

    /// The write budget is reachable on its own — writes alone cross
    /// it without any read traffic. (The read budget is 833M/day, the
    /// write budget ~1.67M/day: writes trip first in practice.)
    #[tokio::test]
    async fn write_budget_trips_independently() {
        let db = MeteredDb::new(memory_db().await.expect("memory db"));
        for i in 0..8 {
            db.query("INSERT INTO settings (key, value) VALUES (?, '1')")
                .bind(format!("w-{i}"))
                .execute()
                .await
                .expect("insert");
        }
        // A multiplier that leaves the read budget alone but pinches
        // the write budget under the burst.
        let over = db
            .budget_verdict(1e-12)
            .await
            .expect("verdict")
            .expect("over");
        assert!(
            over.iter().any(|entry| matches!(
                entry.metric,
                stow_types::api::CostMetric::DurableObjectRowsWritten
            )),
            "write metric reported: {over:?}"
        );
        assert!(daily_budget(DO_ROWS_WRITTEN_MONTHLY, 1.0) < DO_ROWS_WRITTEN_MONTHLY);
    }

    /// The whole point of the design: the edge declares no cron
    /// trigger — nothing wakes on a timer. Parse the manifest the
    /// deploy actually emits (`Skyzen.toml` is the source
    /// `cloudflare.triggers` would live in).
    #[test]
    fn edge_declares_no_cron_triggers() {
        let manifest = include_str!("../../Skyzen.toml");
        let parsed: toml::Table = toml::from_str(manifest).expect("Skyzen.toml parses");
        assert!(
            parsed
                .get("cloudflare")
                .and_then(|cloudflare| cloudflare.get("triggers"))
                .is_none(),
            "cloudflare.triggers must stay absent — no cron wakes"
        );
        assert!(!manifest.contains("crons"), "no `crons` line anywhere");
    }
}
