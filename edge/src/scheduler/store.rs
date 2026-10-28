//! The scheduler's flat persistence substrate (stow#878): an
//! append-only `event_log`, chunked `snapshot_chunks`, and one
//! `store_meta` row carrying the snapshot watermark — the only tables
//! the in-memory [`super::graph::Graph`] survives a forced eviction by.
//!
//! Every accepted event is appended, stamped with the instant it was
//! accepted at, before the request or pass that produced it is
//! acknowledged; replay applies each event at its own instant, so a
//! wake rebuilds the claim, request and sample times the isolate it
//! replaces saw. On the DO the statements inside one request's input
//! gate land as one turn. A snapshot writes its chunks, then the
//! watermark, then drops the covered log rows — the drop is the commit
//! point, so a crash mid-snapshot replays the old snapshot plus the
//! full log.
//!
//! Billed rows are counted where the platform bills them — the
//! metering backend wrapped around the handle (`meter.rs`) books each
//! statement's cursor counters into `Graph::meter`. The one-row
//! `meter` table checkpoints the day's totals and the last covered
//! `event_log` seq at each wake and snapshot (stow#931); a wake
//! restores them and re-counts only the tail rows past the
//! checkpoint.
//!
//! The schema is `schema.sql`, created only by [`reset`]; request code
//! and the alarm never issue DDL, so a store nobody reset fails the
//! wake's first read.

use skyzen_services::durable::DurableDb;
use skyzen_services::{DbValue, QuerySource};
use stow_types::api::{
    SchedulerEvent, SchedulerResetReport, SubmissionNode, SubmissionSource, SubmissionTree,
};

use super::graph::{
    ChunkSpan, Graph, GraphCell, Meter, SNAPSHOT_SPAN_ROWS, SnapshotLoader, SnapshotPlan,
    SpanEncoder, utc_day,
};
use crate::errors::QueueError;

/// Nodes per `Submit` log part — bounds a part's serialized size far
/// under the platform's ~2 MB row bound.
const SUBMIT_PART_NODES: usize = 1024;

/// The log length (events appended since the last snapshot) that
/// triggers a snapshot at the tail of the turn that crossed it.
pub const SNAPSHOT_EVENT_THRESHOLD: u64 = 8192;

/// The log size (bytes appended since the last snapshot) that triggers
/// one as well: whichever threshold is crossed first. Submit parts run
/// to ~0.5 MB, so the event count alone would let a wake replay
/// gigabytes.
pub const SNAPSHOT_BYTE_THRESHOLD: u64 = 8 << 20;

/// One replayed log row: the instant it was accepted at and the event.
#[derive(Debug, Clone)]
pub struct Logged {
    /// Unix milliseconds the event was accepted at.
    pub at: i64,
    /// The event.
    pub event: SchedulerEvent,
    /// The size of the row's JSON text, as appended.
    pub bytes: u64,
}

/// What an append wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    /// The last sequence number written (`0` for an empty batch).
    pub seq: i64,
    /// The JSON bytes of every row written.
    pub bytes: u64,
}

/// One `sqlite_master` row — the store objects [`reset`] drops.
#[derive(Debug, skyzen::FromRow)]
struct SchemaObject {
    kind: String,
    name: String,
}

/// Reset the scheduler store — the only code that may issue DDL on the
/// queue database. Drops every table, index, trigger and view the
/// store holds, then executes `schema.sql`; it reads no row data — a
/// schema change is applied by this reset, never by reading an older
/// shape, and the store refills from the lanes that feed it. Reached
/// from `POST /api/v1/admin/scheduler/reset` (the Durable Object's
/// `/reset` handler); `stow-admin scheduler reset --yes` is the manual
/// path.
///
/// The reset zeroes the meter along with the rest: `schema.sql`
/// reseeds `meter` to `('', 0, 0, 0)`, so the day meter drops up to
/// one full day's already-billed totals — the operator's bound for the
/// reset, taken while dispatch stays frozen.
///
/// # Errors
/// `QueueError::Sql` on a failed statement.
pub async fn reset(db: &DurableDb) -> Result<SchedulerResetReport, QueueError> {
    // The store's objects minus SQLite's own (`sqlite_sequence` and
    // friends) and the platform's internal tables — GLOB keeps the
    // `_` literals.
    let objects = db
        .query(
            "SELECT type AS kind, name FROM sqlite_master \
             WHERE type IN ('table', 'index', 'trigger', 'view') \
               AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*'",
        )
        .fetch_all::<SchemaObject>()
        .await
        .map_err(|error| format!("list scheduler store objects: {error}"))?;
    // A table's drop takes its indexes and triggers with it, so the
    // `IF EXISTS` statements below only ever fire on objects still
    // standing — an orphaned name is a no-op, never an error.
    for (kind, keyword) in [
        ("trigger", "TRIGGER"),
        ("view", "VIEW"),
        ("table", "TABLE"),
        ("index", "INDEX"),
    ] {
        for object in objects.iter().filter(|object| object.kind == kind) {
            db.query(&format!("DROP {keyword} IF EXISTS {}", object.name))
                .execute()
                .await
                .map_err(|error| format!("drop {kind} {}: {error}", object.name))?;
        }
    }
    db.query(include_str!("schema.sql"))
        .execute()
        .await
        .map_err(|error| format!("create scheduler schema: {error}"))?;
    Ok(SchedulerResetReport {
        dropped: objects.len() as u64,
    })
}

/// Serialize one event for the log.
///
/// # Errors
/// `QueueError::Invariant` when the event cannot serialize — a bug,
/// never data-dependent.
pub fn encode_event(event: &SchedulerEvent) -> Result<String, QueueError> {
    serde_json::to_string(event)
        .map_err(|error| QueueError::Invariant(format!("event encode: {error}")))
}

/// A log row attributed to the run that requested it: the event's own
/// fields plus `actor`. No [`SchedulerEvent`] variant has a top-level
/// `actor` field, and [`decode_event`] ignores the extra key, so replay
/// reads an attributed row exactly as an unattributed one.
#[derive(serde::Serialize)]
struct AttributedRow<'a> {
    actor: &'a str,
    #[serde(flatten)]
    event: &'a SchedulerEvent,
}

/// Serialize one event attributed to `actor` (stow#955).
///
/// # Errors
/// `QueueError::Invariant` when the event cannot serialize — a bug,
/// never data-dependent.
pub fn encode_attributed(actor: &str, event: &SchedulerEvent) -> Result<String, QueueError> {
    serde_json::to_string(&AttributedRow { actor, event })
        .map_err(|error| QueueError::Invariant(format!("event encode: {error}")))
}

/// Decode one log row.
///
/// # Errors
/// `QueueError::Invariant` on undecodable bytes — corrupt store.
pub fn decode_event(text: &str) -> Result<SchedulerEvent, QueueError> {
    serde_json::from_str(text)
        .map_err(|error| QueueError::Invariant(format!("event decode: {error}")))
}

/// Split a submission tree into its `Submit` log events — `parts`
/// chunks sized so no serialized row nears the row bound.
#[must_use]
pub fn submission_events(tree: &SubmissionTree) -> Vec<SchedulerEvent> {
    let parts =
        u32::try_from(tree.nodes.len().div_ceil(SUBMIT_PART_NODES).max(1)).unwrap_or(u32::MAX);
    if parts == 1 {
        return vec![SchedulerEvent::Submit {
            source: tree.source,
            part: 0,
            parts,
            roots: tree.roots.clone(),
            nodes: tree.nodes.clone(),
        }];
    }
    tree.nodes
        .chunks(SUBMIT_PART_NODES)
        .enumerate()
        .map(|(part, nodes)| SchedulerEvent::Submit {
            source: tree.source,
            part: u32::try_from(part).expect("submit part fits u32"),
            parts,
            roots: if part == 0 {
                tree.roots.clone()
            } else {
                Vec::new()
            },
            nodes: nodes.to_vec(),
        })
        .collect()
}

/// Append events in submission order, stamped `at`; returns the last
/// sequence number written (`0` for an empty batch) and the bytes
/// appended. One call's rows
/// land in one turn of the request that produced them — the single
/// append transaction the submit path acknowledges after.
///
/// # Errors
/// `QueueError::Sql` on a failed insert.
///
/// `actor` attributes the batch's first row to the verified `actor`
/// claim of the GitHub Actions run whose request produced it
/// (stow#955); `None` for the lanes no workflow identity reaches. The
/// attribution rides inside that row, so an attributed append writes
/// exactly the rows and statements an unattributed one does.
pub async fn append_events(
    db: &DurableDb,
    actor: Option<&str>,
    events: &[SchedulerEvent],
    at: i64,
) -> Result<Appended, QueueError> {
    let mut appended = Appended { seq: 0, bytes: 0 };
    for (index, event) in events.iter().enumerate() {
        let text = match actor {
            Some(actor) if index == 0 => encode_attributed(actor, event)?,
            _ => encode_event(event)?,
        };
        appended.bytes += u64::try_from(text.len()).expect("row length fits u64");
        appended.seq = db
            .query("INSERT INTO event_log(at, event) VALUES (?, ?) RETURNING seq")
            .bind(at)
            .bind(text)
            .fetch_scalar::<i64>()
            .await
            .map_err(|error| QueueError::Sql(format!("log append: {error}")))?;
    }
    Ok(appended)
}

#[derive(skyzen::FromRow)]
struct LogRow {
    seq: i64,
    at: i64,
    event: String,
}

/// Read `event_log` rows after `seq` in order.
///
/// # Errors
/// `QueueError::Sql` on a failed select, `QueueError::Invariant` on an
/// undecodable row.
pub async fn log_tail(db: &DurableDb, seq: i64) -> Result<Vec<(i64, Logged)>, QueueError> {
    db.query("SELECT seq, at, event FROM event_log WHERE seq > ? ORDER BY seq")
        .bind(seq)
        .fetch_all::<LogRow>()
        .await
        .map_err(|error| QueueError::Sql(format!("log tail: {error}")))?
        .into_iter()
        .map(|row| {
            Ok((
                row.seq,
                Logged {
                    at: row.at,
                    bytes: u64::try_from(row.event.len()).expect("row length fits u64"),
                    event: decode_event(&row.event)?,
                },
            ))
        })
        .collect()
}

/// The snapshot watermark — the highest `seq` the current snapshot
/// covers (`0` before the first snapshot).
///
/// # Errors
/// `QueueError::Sql` on a failed read.
pub async fn watermark(db: &DurableDb) -> Result<i64, QueueError> {
    let seq = db
        .query("SELECT value FROM store_meta WHERE key = 'snapshot_seq'")
        .fetch_scalar_optional::<i64>()
        .await
        .map_err(|error| QueueError::Sql(format!("watermark: {error}")))?;
    Ok(seq.unwrap_or(0))
}

/// The `meter` table's one row — the checkpoint the day meter
/// restores from (stow#931).
#[derive(skyzen::FromRow)]
struct MeterRow {
    day: String,
    rows_read: i64,
    rows_written: i64,
    seq: i64,
}

/// The billed cost of the meter checkpoint's `UPDATE meter ..
/// RETURNING` — the edge's only UPDATE — as `(rows_read,
/// rows_written)`. workerd bills an UPDATE one read per row it
/// changes plus one per row its RETURNING clause returns, so the
/// one-row primary-key update costs 2 reads + 1 written: release
/// gate run 40186665163's statement log measured `rows_returned 1`,
/// `rows_read 2`, `rows_written 1` on it (stow#931). Named once and
/// shared: [`checkpoint_meter`] folds it into the stored totals and
/// [`super::drives::predicted_bill_mismatch`] gates the statement on
/// it.
pub const METER_CHECKPOINT_BILL: (u64, u64) = (2, 1);

/// Write the meter checkpoint — the row's day totals are the restored
/// in-memory meter plus the isolate's unsettled counts (`cell`'s
/// `unsettled`: every billed statement no settle has folded in yet —
/// the wake's reads, the snapshot turn's appends and every snapshot
/// statement, and any other in-flight operation's counts — stow#931),
/// plus the UPDATE's own cost, [`METER_CHECKPOINT_BILL`]. `seq` is the
/// last `event_log` seq the totals cover — `covered` at a snapshot,
/// the meter's own `seq` at a wake.
///
/// Exactness rests on one rule the schema cannot enforce: between two
/// checkpoints the only billed statements are `event_log` appends —
/// replay re-counts each append at its billed 1 R + 1 W, so a settled
/// read or write after the last checkpoint dies with the isolate,
/// uncounted. Every production statement outside a wake or snapshot
/// is an append; the budget probe's seed record rides the snapshot
/// head for the same reason (stow#931).
///
/// The statement's real counters are compared with
/// [`METER_CHECKPOINT_BILL`]: a mismatch is a metering defect —
/// logged, its actual counts already booked by the metering backend,
/// never a dispatch failure. An UPDATE landing on no row means the
/// store was never reset: `QueueError::Invariant`.
///
/// # Errors
/// `QueueError::Sql` on a failed statement, `QueueError::Invariant`
/// when the row is missing.
pub async fn checkpoint_meter(
    db: &DurableDb,
    meter: &Meter,
    cell: &GraphCell,
    seq: i64,
    now_ms: i64,
) -> Result<(), QueueError> {
    let mut value = meter.clone();
    // The unsettled counts belong to this instant's UTC day.
    value.roll_to(&utc_day(now_ms));
    value.seq = seq;
    let (unsettled_read, unsettled_written) = cell.unsettled().counts();
    value.rows_read += unsettled_read + METER_CHECKPOINT_BILL.0;
    value.rows_written += unsettled_written + METER_CHECKPOINT_BILL.1;
    let mut source: &DurableDb = db;
    let result = QuerySource::query(
        &mut source,
        "UPDATE meter SET day = ?, rows_read = ?, rows_written = ?, seq = ? \
         WHERE id = 0 RETURNING id",
        &[
            DbValue::Text(value.day),
            DbValue::Integer(
                i64::try_from(value.rows_read)
                    .map_err(|_| QueueError::Invariant("meter rows_read overflows i64".into()))?,
            ),
            DbValue::Integer(
                i64::try_from(value.rows_written).map_err(|_| {
                    QueueError::Invariant("meter rows_written overflows i64".into())
                })?,
            ),
            DbValue::Integer(seq),
        ],
    )
    .await
    .map_err(|error| QueueError::Sql(format!("meter checkpoint: {error}")))?;
    if result.rows.is_empty() {
        return Err(QueueError::Invariant(
            "scheduler meter row missing — the store was never reset".into(),
        ));
    }
    if (result.rows_read, result.rows_written) != METER_CHECKPOINT_BILL {
        tracing::error!(
            rows_read = result.rows_read,
            rows_written = result.rows_written,
            "meter checkpoint billed other than the predicted {} R + {} W — the actual \
             counts are already booked",
            METER_CHECKPOINT_BILL.0,
            METER_CHECKPOINT_BILL.1
        );
    }
    Ok(())
}

/// Serialize the graph into `snapshot_chunks` row by row — see
/// [`write_snapshot_parts`]. `cell` supplies the isolate's unsettled
/// counts the meter checkpoint folds in; `now_ms` stamps the
/// checkpoint's day.
///
/// # Errors
/// `QueueError::Sql`/`QueueError::Invariant` on a failed write.
pub async fn write_snapshot(
    db: &DurableDb,
    graph: &mut Graph,
    cell: &GraphCell,
    now_ms: i64,
) -> Result<i64, QueueError> {
    graph.compact();
    let plan = graph.snapshot_plan()?;
    let graph_ref = &*graph;
    let covered = write_snapshot_parts(
        db,
        &plan,
        |span, encoder| {
            if encoder.is_none() {
                *encoder = Some(graph_ref.snapshot_encoder(span));
            }
            encoder.as_mut().expect("encoder").next_row(graph_ref)
        },
        &graph_ref.meter,
        cell,
        now_ms,
    )
    .await?;
    graph.snapshot_written();
    Ok(covered)
}

/// Write a snapshot's dirty spans, the rows produced one at a time by
/// a sync provider — the Durable Object's graph lives behind a lock
/// that cannot be held across an `.await`, so the caller encodes each
/// row between writes. The statements are all storage operations, held
/// under the object's input gate, so no other request mutates the
/// graph between two rows. Peak memory is one row's bytes plus the
/// span's own materialization.
///
/// Each span upserts its emitted rows (`INSERT .. ON CONFLICT`), then
/// deletes the range's stale sub-rows — a span that shrank or emptied
/// leaves nothing behind. An `all` plan drops every row first, which
/// also retires the extents a compaction shrank. The watermark stamps
/// after the rows and the covered log drops last: the drop is the
/// commit point. The meter checkpoint lands after it, in the same
/// storage-only turn, covering every append through `covered`.
///
/// Returns the watermark the snapshot covers.
///
/// # Errors
/// `QueueError` on a failed storage op or the provider's own error.
pub async fn write_snapshot_parts(
    db: &DurableDb,
    plan: &SnapshotPlan,
    mut row: impl FnMut(ChunkSpan, &mut Option<SpanEncoder>) -> Result<Option<String>, QueueError>,
    meter: &Meter,
    cell: &GraphCell,
    now_ms: i64,
) -> Result<i64, QueueError> {
    let covered = db
        .query("SELECT COALESCE(MAX(seq), 0) FROM event_log")
        .fetch_scalar::<i64>()
        .await
        .map_err(|error| QueueError::Sql(format!("snapshot watermark: {error}")))?;
    if plan.all {
        db.query("DELETE FROM snapshot_chunks")
            .execute()
            .await
            .map_err(|error| QueueError::Sql(format!("snapshot clear: {error}")))?;
    }
    // Rows upsert in batches — a statement's row count is what the
    // store bills, and one multi-row UPSERT keeps a many-span plan a
    // few statements instead of one per row. The buffer holds at most
    // UPSERT_BATCH payloads: still one row at a time in flight, never
    // a serialized graph.
    let mut pending: Vec<(i64, String)> = Vec::with_capacity(UPSERT_BATCH);
    let mut stale: Vec<(i64, i64)> = Vec::new();
    for &span in &plan.spans {
        let mut encoder = None;
        let mut sub = 0i64;
        while let Some(payload) = row(span, &mut encoder)? {
            if sub >= SNAPSHOT_SPAN_ROWS {
                return Err(QueueError::Invariant(format!(
                    "snapshot span at key {} exceeded {SNAPSHOT_SPAN_ROWS} rows",
                    span.lo_key()
                )));
            }
            pending.push((span.lo_key() + sub, payload));
            if pending.len() == UPSERT_BATCH {
                flush_upserts(db, &mut pending).await?;
            }
            sub += 1;
        }
        // The span's emitted rows stay; anything past them is a stale
        // sub-row of a longer previous encoding — cleared with every
        // span's tail in one statement below, not one per span.
        stale.push((span.lo_key() + sub, span.hi_key()));
    }
    flush_upserts(db, &mut pending).await?;
    if !plan.all && !stale.is_empty() {
        let mut clear = String::from("DELETE FROM snapshot_chunks WHERE ");
        for at in 0..stale.len() {
            if at != 0 {
                clear.push_str(" OR ");
            }
            clear.push_str("(chunk >= ? AND chunk <= ?)");
        }
        let mut query = db.query(&clear);
        for (lo, hi) in stale {
            query = query.bind(lo).bind(hi);
        }
        query
            .execute()
            .await
            .map_err(|error| QueueError::Sql(format!("snapshot span clear: {error}")))?;
    }
    db.query(
        "INSERT INTO store_meta(key, value) VALUES ('snapshot_seq', ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(covered)
    .execute()
    .await
    .map_err(|error| QueueError::Sql(format!("snapshot meta: {error}")))?;
    // The row at the watermark stays: `seq` is a plain rowid, so an
    // emptied log would number the next append from 1 - under the
    // watermark, where a wake's tail read skips it. The tail read is
    // `seq > watermark`, so the kept row is never replayed.
    db.query("DELETE FROM event_log WHERE seq < ?")
        .bind(covered)
        .execute()
        .await
        .map_err(|error| QueueError::Sql(format!("snapshot drop: {error}")))?;
    // The checkpoint lands after the commit point, still inside this
    // storage-only turn: the isolate's unsettled counts — by now
    // holding the turn's appends and every statement above — fold
    // into the stored totals.
    checkpoint_meter(db, meter, cell, covered, now_ms).await?;
    Ok(covered)
}

/// Rows one UPSERT statement carries: bounded so the in-flight
/// payload stays a few MB — never a second copy of the graph.
const UPSERT_BATCH: usize = 8;

/// Write the buffered `(key, payload)` rows as one multi-row UPSERT.
async fn flush_upserts(db: &DurableDb, pending: &mut Vec<(i64, String)>) -> Result<(), QueueError> {
    if pending.is_empty() {
        return Ok(());
    }
    let mut sql = String::from("INSERT INTO snapshot_chunks(chunk, payload) VALUES (?, ?)");
    for _ in 1..pending.len() {
        sql.push_str(", (?, ?)");
    }
    sql.push_str(" ON CONFLICT(chunk) DO UPDATE SET payload = excluded.payload");
    let mut query = db.query(&sql);
    for (key, payload) in pending.drain(..) {
        query = query.bind(key).bind(payload);
    }
    query
        .execute()
        .await
        .map_err(|error| QueueError::Sql(format!("snapshot chunk: {error}")))?;
    Ok(())
}

/// Snapshot rows one wake statement reads. The buffer bound is
/// `WAKE_READ_BATCH` × the ~1 MiB row cap ≈ 16 MB of payload in flight
/// — a few percent of the 128 MiB object limit atop the arenas'
/// measured ~50 MB at the largest fixture — while turning a ~470-row
/// snapshot into ~30 statements instead of ~470.
const WAKE_READ_BATCH: u32 = 16;

#[derive(skyzen::FromRow)]
struct SnapshotRow {
    chunk: i64,
    payload: String,
}

/// Wake: read the watermark, then the snapshot in batches of
/// [`WAKE_READ_BATCH`] rows per statement — each row decodes into the
/// graph as it is read, so the serialized image is never held whole —
/// then the meter checkpoint's row and the log tail. Returns the
/// rebuilt graph — its meter carries the checkpointed day totals and
/// covered `seq` — and the log tail (`seq`, row) pairs to apply
/// through [`apply_events`].
///
/// # Errors
/// `QueueError::Sql`/`QueueError::Invariant` on a failed read or
/// corrupt row.
pub async fn load(db: &DurableDb) -> Result<(Graph, Vec<(i64, Logged)>), QueueError> {
    let seq = watermark(db).await?;
    let mut loader = SnapshotLoader::default();
    let mut key = -1i64;
    loop {
        let batch = db
            .query(
                "SELECT chunk, payload FROM snapshot_chunks WHERE chunk > ? \
                 ORDER BY chunk LIMIT ?",
            )
            .bind(key)
            .bind(i64::from(WAKE_READ_BATCH))
            .fetch_all::<SnapshotRow>()
            .await
            .map_err(|error| QueueError::Sql(format!("snapshot read: {error}")))?;
        let done = batch.len() < WAKE_READ_BATCH as usize;
        for row in batch {
            loader.apply(row.chunk, &row.payload)?;
            key = row.chunk;
        }
        if done {
            break;
        }
    }
    let mut graph = loader.finish()?;
    let row = db
        .query("SELECT day, rows_read, rows_written, seq FROM meter WHERE id = 0")
        .fetch_one::<MeterRow>()
        .await
        .map_err(|error| QueueError::Sql(format!("meter row: {error}")))?;
    graph.meter.day = row.day;
    graph.meter.rows_read = u64::try_from(row.rows_read)
        .map_err(|_| QueueError::Invariant("meter rows_read went negative".into()))?;
    graph.meter.rows_written = u64::try_from(row.rows_written)
        .map_err(|_| QueueError::Invariant("meter rows_written went negative".into()))?;
    graph.meter.seq = row.seq;
    // A checkpoint seq under the watermark means a snapshot committed
    // its drop without its checkpoint — rows between the two would
    // replay with their cost never stored. Corrupt store: fail.
    if graph.meter.seq < seq {
        return Err(QueueError::Invariant(format!(
            "meter checkpoint seq {} predates the snapshot watermark {seq}",
            graph.meter.seq
        )));
    }
    let tail = log_tail(db, seq).await?;
    Ok((graph, tail))
}

/// The wake sequence `ensure_graph` and the `wake` drive share —
/// [`load`] the snapshot plus log tail, [`apply_events`] to replay it,
/// then write the wake checkpoint: the restored totals, plus the
/// isolate's unsettled counts (this operation's own reads among them),
/// plus the checkpoint UPDATE itself — before any non-storage await
/// opens the input gate (stow#931). Returns the rebuilt graph;
/// `woken_at_ms` and `install` are the caller's.
///
/// # Errors
/// `QueueError::Sql`/`QueueError::Invariant` on a failed read or
/// checkpoint write.
pub async fn wake(db: &DurableDb, cell: &GraphCell, now_ms: i64) -> Result<Graph, QueueError> {
    let (mut graph, events) = load(db).await?;
    apply_events(&mut graph, &events);
    checkpoint_meter(db, &graph.meter, cell, graph.meter.seq, now_ms).await?;
    Ok(graph)
}

/// Apply the log tail to the graph, each event at its own instant:
/// `Submit` parts reassemble into one merge — a truncated tail (a
/// submit whose ack never left, appended but never completed) drops,
/// consistent with it never having been acknowledged — and every
/// other kind goes through [`Graph::apply`]. Each row re-counts as
/// one written row plus its `RETURNING` read on its day's meter —
/// only rows past the checkpoint's `seq`.
pub fn apply_events(graph: &mut Graph, events: &[(i64, Logged)]) {
    struct Pending {
        source: SubmissionSource,
        parts: u32,
        received: u32,
        at: i64,
        roots: Vec<u32>,
        nodes: Vec<SubmissionNode>,
    }
    let complete = |graph: &mut Graph, pending: &mut Option<Pending>| {
        if let Some(p) = pending.take()
            && p.received == p.parts
        {
            let _ = graph.merge(
                &SubmissionTree {
                    source: p.source,
                    roots: p.roots,
                    nodes: p.nodes,
                },
                p.at,
            );
        }
    };
    let mut pending: Option<Pending> = None;
    for (seq, Logged { at, event, bytes }) in events {
        graph.meter.replayed(*at, *seq);
        graph.log_appended(*bytes, *seq);
        match event {
            SchedulerEvent::Submit {
                source,
                part,
                parts,
                roots,
                nodes,
            } => {
                let next = match &mut pending {
                    Some(p) if p.source == *source && p.parts == *parts => p,
                    other => {
                        complete(graph, other);
                        other.insert(Pending {
                            source: *source,
                            parts: *parts,
                            received: 0,
                            at: *at,
                            roots: Vec::new(),
                            nodes: Vec::new(),
                        })
                    }
                };
                if *part == 0 {
                    next.roots.clone_from(roots);
                }
                next.nodes.extend(nodes.iter().cloned());
                next.received += 1;
                if *part + 1 == *parts {
                    complete(graph, &mut pending);
                }
            }
            other => {
                complete(graph, &mut pending);
                graph.apply(other, *at);
            }
        }
    }
    complete(graph, &mut pending);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::test_db;
    use stow_types::api::{
        DispatchBinding, DispatchClaim, MutationKind, PublishedSliceRow, RunnerFamily,
        SubmissionNode, SubmissionSource,
    };
    use stow_types::ci::{CiRunListing, CiRunStatus};
    use stow_types::identity::{
        CrateName, CrateVersion, DependencyIdentity, FeaturesJson, TargetTriple, WireRustcVersion,
    };
    use stow_types::public_cache::{
        ExplicitSpelling, UnitInvocation, UnitKind, UnitShape, UnitSide,
    };

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.85.0";
    const NOW_MS: i64 = 0;

    fn node(name: &str) -> SubmissionNode {
        let mut node = SubmissionNode {
            task_id: String::new(),
            crate_name: CrateName::parse(name).expect("crate"),
            version: CrateVersion::new(semver::Version::new(1, 0, 0)),
            features_json: FeaturesJson::from_sorted(Vec::new()).expect("features"),
            target: TargetTriple::parse(TARGET).expect("target"),
            rustc_version: WireRustcVersion::parse(RUSTC).expect("rustc"),
            host_side: false,
            explicit_spelling: ExplicitSpelling::KeysAsNative,
            preserve_lockfile: false,
            dependency_identity: DependencyIdentity::from_task_ids([name]).expect("dep identity"),
            deps: Vec::new(),
            downloads: 5,
        };
        node.task_id = stow_types::task_graph::canonical_task_id(
            name,
            "1.0.0",
            &node.features_json.raw(),
            TARGET,
            RUSTC,
            node.dependency_identity.as_str(),
            false,
        );
        node
    }

    /// The canonical task id of the test node `name`.
    fn id(name: &str) -> String {
        node(name).task_id
    }

    /// a → b → c (a depends on b, b on c), nodes leaf-first.
    fn chain() -> SubmissionTree {
        let mut b = node("b");
        b.deps = vec![0];
        let mut a = node("a");
        a.deps = vec![1];
        SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![2],
            nodes: vec![node("c"), b, a],
        }
    }

    fn c_rows() -> Vec<PublishedSliceRow> {
        [UnitKind::Linked, UnitKind::Unlinked]
            .map(|kind| PublishedSliceRow {
                crate_name: CrateName::parse("c").expect("crate"),
                version: CrateVersion::new(semver::Version::new(1, 0, 0)),
                features_json: FeaturesJson::from_sorted(Vec::new()).expect("features"),
                unit_shape: UnitShape {
                    side: UnitSide::Target,
                    invocation: UnitInvocation::Native,
                    kind,
                },
                dependency_identity: DependencyIdentity::from_task_ids(["c"])
                    .expect("dep identity"),
            })
            .into()
    }

    async fn store() -> DurableDb {
        test_db::memory_db().await.expect("db")
    }

    /// Append `events` and apply them — the store-and-graph pair a
    /// route's commit leaves.
    async fn commit_to(db: &DurableDb, graph: &mut Graph, events: &[SchedulerEvent], at: i64) {
        let appended = append_events(db, None, events, at).await.expect("append");
        apply_events(graph, &logged(events, at, appended));
    }

    /// The tail a wake reads, as `apply_events` takes it — the batch's
    /// appended rows carry consecutive seqs ending at `appended.seq`.
    fn logged(events: &[SchedulerEvent], at: i64, appended: Appended) -> Vec<(i64, Logged)> {
        let count = i64::try_from(events.len()).expect("event count fits i64");
        events
            .iter()
            .enumerate()
            .map(|(k, event)| {
                (
                    appended.seq - count + i64::try_from(k).expect("event index fits i64") + 1,
                    Logged {
                        at,
                        bytes: 0,
                        event: event.clone(),
                    },
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn snapshot_round_trip_replays_the_graph() {
        let db = store().await;
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        let claims = graph.claim(45, 16, 0, 3_600_000).expect("claim c");
        let generation = claims[0].generation;
        graph.bind(&id("c"), generation, 700, 1_000);
        graph.run_finished(&id("c"), 700, true, false, None, 10_000);
        graph.apply_slice_report(TARGET, RUSTC, &c_rows(), &[]);

        // The log records the wave; the snapshot then drops it.
        let events = vec![
            SchedulerEvent::Claims {
                claims: vec![DispatchClaim {
                    task_id: id("c"),
                    generation: 1,
                    attempt: 1,
                }],
            },
            SchedulerEvent::Bindings {
                bindings: vec![DispatchBinding {
                    task_id: id("c"),
                    generation: 1,
                    run_id: "700".into(),
                }],
            },
            SchedulerEvent::RunFinished {
                run_id: "700".into(),
                task_id: id("c"),
                success: true,
                cancelled: false,
                error: None,
            },
        ];
        append_events(&db, None, &events, 0).await.expect("append");
        let covered = write_snapshot(&db, &mut graph, &GraphCell::default(), NOW_MS)
            .await
            .expect("snapshot");
        assert!(covered > 0);
        assert_eq!(log_tail(&db, covered).await.expect("tail").len(), 0);

        // Forced eviction: reload from the store only.
        let (mut restored, tail) = load(&db).await.expect("load");
        assert!(tail.is_empty(), "snapshot covered the whole log");
        apply_events(&mut restored, &tail);
        assert_eq!(restored.status(), graph.status());
        let claimed = restored.claim(45, 16, 20_000, 3_600_000).expect("claim b");
        assert_eq!(claimed[0].task_id, id("b"));
    }

    /// A wake after any mixture of incremental snapshots — each
    /// rewriting only the spans its wave dirtied — reassembles the
    /// live graph exactly (stow#902).
    #[tokio::test]
    async fn a_wake_after_mixed_incremental_snapshots_equals_the_live_graph() {
        let db = store().await;
        let mut graph = Graph::default();
        // Wave 1: the merge and a claim — the first snapshot is the
        // store's full write.
        commit_to(
            &db,
            &mut graph,
            &[
                SchedulerEvent::Mutate {
                    op: MutationKind::Retry,
                    task_ids: vec![id("a")],
                },
                SchedulerEvent::Demand {
                    batch_id: "wave-1".into(),
                    input_hash: "hash-1".into(),
                    entries: vec![stow_types::api::DemandEntry {
                        task_id: id("b"),
                        delta: 3,
                    }],
                },
            ],
            0,
        )
        .await;
        graph.merge(&chain(), 0).expect("merge");
        let covered = write_snapshot(&db, &mut graph, &GraphCell::default(), NOW_MS)
            .await
            .expect("snapshot 1");
        // Wave 2: claim, bind, finish and publish c — node and
        // published spans rewrite on top of the first write's rows.
        let claims = graph.claim(45, 16, 1_000, 3_600_000).expect("claim");
        let generation = claims[0].generation;
        commit_to(
            &db,
            &mut graph,
            &[
                SchedulerEvent::Claims {
                    claims: vec![DispatchClaim {
                        task_id: claims[0].task_id.clone(),
                        generation,
                        attempt: 1,
                    }],
                },
                SchedulerEvent::Bindings {
                    bindings: vec![DispatchBinding {
                        task_id: claims[0].task_id.clone(),
                        generation,
                        run_id: "700".into(),
                    }],
                },
                SchedulerEvent::RunFinished {
                    run_id: "700".into(),
                    task_id: claims[0].task_id.clone(),
                    success: true,
                    cancelled: false,
                    error: None,
                },
            ],
            2_000,
        )
        .await;
        graph.apply_slice_report(TARGET, RUSTC, &c_rows(), &[]);
        let covered2 = write_snapshot(&db, &mut graph, &GraphCell::default(), NOW_MS)
            .await
            .expect("snapshot 2");
        assert!(covered2 > covered);
        // Wave 3: a cancellation and a fresh demand — a third
        // incremental write over both earlier chunk sets.
        commit_to(
            &db,
            &mut graph,
            &[SchedulerEvent::Mutate {
                op: MutationKind::Cancel,
                task_ids: vec![id("a")],
            }],
            3_000,
        )
        .await;
        let covered3 = write_snapshot(&db, &mut graph, &GraphCell::default(), NOW_MS)
            .await
            .expect("snapshot 3");
        assert!(covered3 > covered2);

        // The wake reads every chunk set and replays nothing.
        let (mut restored, tail) = load(&db).await.expect("load");
        assert!(tail.is_empty());
        apply_events(&mut restored, &tail);
        assert_eq!(restored.status(), graph.status());
        assert_eq!(restored.sizes(), graph.sizes());
        let claimed = restored.claim(45, 16, 20_000, 3_600_000).expect("claim b");
        assert_eq!(claimed[0].task_id, id("b"));
    }

    /// `snapshot write`'s rows scale with the events since the last
    /// snapshot, never with the stored graph (stow#902): the same
    /// event wave over a 4×-larger fixture writes the same rows.
    #[tokio::test]
    async fn a_snapshot_writes_rows_proportional_to_the_events_not_the_graph() {
        let mut counts = Vec::new();
        for queue_rows in [1_000u32, 4_000] {
            let shape = stow_types::fixture::FixtureShape { queue_rows };
            let (db, log) = test_db::counting_memory_db().await.expect("db");
            let mut graph = crate::scheduler::fixture::build(shape, 0).expect("build");
            write_snapshot(&db, &mut graph, &GraphCell::default(), NOW_MS)
                .await
                .expect("seed snapshot");
            log.lock().expect("log").clear();
            // The same wave: 32 demand batches against the same node
            // ids plus one slice report publishing into the live
            // map — the dirty set is identical at both sizes, so the
            // published-bucket rewrites are measured too.
            let (added, retired) = crate::scheduler::fixture::delta_slice_report(shape);
            let mut events: Vec<SchedulerEvent> = (0..32)
                .map(|k| SchedulerEvent::Demand {
                    batch_id: format!("b{k}"),
                    input_hash: format!("h{k}"),
                    entries: vec![stow_types::api::DemandEntry {
                        task_id: stow_types::fixture::fixture_task_id(u64::from(
                            stow_types::fixture::FixtureShape::HUMAN_LANE_ROWS + 1 + k,
                        )),
                        delta: 1,
                    }],
                })
                .collect();
            events.push(SchedulerEvent::SliceReport {
                target: TargetTriple::parse(stow_types::api::CI_TARGET_TRIPLES[0]).expect("target"),
                rustc_version: WireRustcVersion::parse("1.85.0").expect("rustc"),
                base_generation: None,
                generation: Some(1),
                added,
                retired,
            });
            for event in &events {
                append_events(&db, None, std::slice::from_ref(event), 0)
                    .await
                    .expect("append");
            }
            apply_events(
                &mut graph,
                &logged(
                    &events,
                    0,
                    Appended {
                        seq: i64::try_from(events.len()).expect("event count fits i64"),
                        bytes: 0,
                    },
                ),
            );
            write_snapshot(&db, &mut graph, &GraphCell::default(), NOW_MS)
                .await
                .expect("snapshot");
            counts.push(
                log.lock()
                    .expect("log")
                    .iter()
                    .filter(|s| s.sql.contains("INSERT INTO snapshot_chunks"))
                    .count(),
            );
            // With no new events the rewrite is the meta row alone.
            log.lock().expect("log").clear();
            write_snapshot(&db, &mut graph, &GraphCell::default(), NOW_MS)
                .await
                .expect("idle snapshot");
            let idle = log
                .lock()
                .expect("log")
                .iter()
                .filter(|s| s.sql.contains("INSERT INTO snapshot_chunks"))
                .count();
            assert_eq!(idle, 1, "only the meta row rides an idle snapshot");
        }
        assert!(
            counts[0].abs_diff(counts[1]) <= 2,
            "the same 32 events rewrite {counts:?} spans at 4x the graph"
        );
        assert!(
            counts[0] > 1 && counts[1] <= 64,
            "{counts:?} chunk rows ride 33 events, not the graph"
        );
    }

    #[tokio::test]
    async fn claim_without_binding_reconciles_after_eviction() {
        let db = store().await;
        let mut graph = Graph::default();
        let tree = SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![0],
            nodes: vec![node("solo")],
        };
        let events = submission_events(&tree);
        append_events(&db, None, &events, 0).await.expect("submit");
        apply_events(
            &mut graph,
            &logged(
                &events,
                0,
                Appended {
                    seq: i64::try_from(events.len()).expect("event count fits i64"),
                    bytes: 0,
                },
            ),
        );
        let claims = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        let generation = claims[0].generation;
        // The pass appends ONE row for the claims before posting —
        // then the isolate is evicted before the bindings land.
        append_events(
            &db,
            None,
            &[SchedulerEvent::Claims {
                claims: vec![DispatchClaim {
                    task_id: id("solo"),
                    generation,
                    attempt: 1,
                }],
            }],
            100,
        )
        .await
        .expect("claims row");

        let (mut restored, tail) = load(&db).await.expect("wake");
        apply_events(&mut restored, &tail);
        // The claim replays as dispatched-unbound — no dispatch is lost
        // and nothing re-dispatches.
        assert_eq!(restored.status().dispatched, 1);
        // The post-wake status reconcile binds by run title, and a
        // run listed `in_progress` moves the claim to `running`
        // (stow#940).
        restored.reconcile_runs(
            &[CiRunListing {
                workflow_run_id: 4242,
                title: format!("{RUSTC}-{}", id("solo")),
                family: Some(RunnerFamily::Linux),
                status: CiRunStatus::InProgress,
            }],
            200,
        );
        assert_eq!(restored.status().running, 1);
        let outcome = restored.run_finished(&id("solo"), 4242, true, false, None, 300);
        assert_eq!(outcome, super::super::graph::FinishOutcome::Applied);
        assert_eq!(restored.status().completed, 1);
    }

    #[tokio::test]
    async fn parked_completion_applies_on_replayed_binding() {
        let db = store().await;
        let tree = SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![0],
            nodes: vec![node("solo")],
        };
        append_events(&db, None, &submission_events(&tree), 0)
            .await
            .expect("submit");
        // completed arrives before its binding in the log — parked on
        // replay, applied when the binding lands.
        let events = vec![
            SchedulerEvent::Claims {
                claims: vec![DispatchClaim {
                    task_id: id("solo"),
                    generation: 7,
                    attempt: 1,
                }],
            },
            SchedulerEvent::RunFinished {
                run_id: "909".into(),
                task_id: id("solo"),
                success: true,
                cancelled: false,
                error: None,
            },
            SchedulerEvent::Bindings {
                bindings: vec![DispatchBinding {
                    task_id: id("solo"),
                    generation: 7,
                    run_id: "909".into(),
                }],
            },
        ];
        append_events(&db, None, &events, 0)
            .await
            .expect("deliveries");
        let (mut restored, tail) = load(&db).await.expect("wake");
        apply_events(&mut restored, &tail);
        assert_eq!(restored.status().completed, 1);
    }

    /// A submit whose tail was cut mid-parts never reached its ack, so a
    /// wake drops it rather than merging a truncated tree.
    #[tokio::test]
    async fn a_truncated_submit_drops_on_replay() {
        let db = store().await;
        let nodes: Vec<SubmissionNode> = (0..=SUBMIT_PART_NODES)
            .map(|k| node(&format!("n{k}")))
            .collect();
        let tree = SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![0],
            nodes,
        };
        let events = submission_events(&tree);
        assert_eq!(events.len(), 2);
        // Only the first part landed before the eviction.
        append_events(&db, None, &events[..1], 0)
            .await
            .expect("part 0");
        let (mut restored, tail) = load(&db).await.expect("wake");
        apply_events(&mut restored, &tail);
        assert_eq!(restored.sizes().0, 0, "the unacknowledged submit dropped");
    }

    #[tokio::test]
    async fn the_meter_counts_appends_and_replays() {
        let db = store().await;
        let tree = SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![0],
            nodes: vec![node("one"), node("two")],
        };
        let last = append_events(&db, None, &submission_events(&tree), 5_000)
            .await
            .expect("submit");
        assert_eq!(last.seq, 1, "one Submit part, one appended row");
        let events = vec![
            SchedulerEvent::Mutate {
                op: MutationKind::Retry,
                task_ids: vec![id("one")],
            },
            SchedulerEvent::Mutate {
                op: MutationKind::Cancel,
                task_ids: vec![id("two")],
            },
        ];
        let last = append_events(&db, None, &events, 5_000)
            .await
            .expect("mutations");
        assert_eq!(last.seq, 3);

        // A wake re-counts what it replays: each appended row bills
        // one written row plus its `RETURNING` read (stow#931).
        let (mut restored, tail) = load(&db).await.expect("load");
        assert_eq!(tail.len(), 3);
        apply_events(&mut restored, &tail);
        assert_eq!(restored.meter.rows_written, 3);
        assert_eq!(restored.meter.rows_read, 3);
        assert_eq!(restored.meter.seq, 3);
    }

    /// An append right after a snapshot emptied the log is replayed: the
    /// next `seq` must stay above the watermark.
    #[tokio::test]
    async fn an_append_after_a_snapshot_is_in_the_next_tail() {
        let db = store().await;
        let mut graph = Graph::default();
        append_events(
            &db,
            None,
            &[SchedulerEvent::Mutate {
                op: MutationKind::Retry,
                task_ids: Vec::new(),
            }],
            0,
        )
        .await
        .expect("append");
        let covered = write_snapshot(&db, &mut graph, &GraphCell::default(), NOW_MS)
            .await
            .expect("snapshot");
        let appended = append_events(
            &db,
            None,
            &[SchedulerEvent::Mutate {
                op: MutationKind::Cancel,
                task_ids: Vec::new(),
            }],
            1,
        )
        .await
        .expect("append");
        assert!(appended.seq > covered);
        let (_, tail) = load(&db).await.expect("load");
        assert_eq!(tail.len(), 1);
    }

    /// The stored row after a fresh checkpoint must equal every row the
    /// store billed from `base` on — the reset/schema statements before
    /// it are the operator bound `reset`'s doc comment states, never a
    /// metered operation. Each operation here is a fresh `Meter::wrap`
    /// bound to the isolate's cell, the shape production's guard
    /// installs.
    /// The audit SELECTs a test issues to read the stored row bill real
    /// reads on the counting backend, but they are harness
    /// observation, not a metered operation — the marker keeps them
    /// out of [`billed`]'s sum.
    const AUDIT: &str = " /* audit */";

    /// Rows the store billed since `base`, excluding the audit reads.
    fn billed(log: &std::sync::Mutex<Vec<test_db::LoggedStatement>>, base: usize) -> (u64, u64) {
        let log = log.lock().expect("log");
        (
            log[base..]
                .iter()
                .filter(|s| !s.sql.contains(AUDIT))
                .map(|s| s.rows_read)
                .sum(),
            log[base..]
                .iter()
                .filter(|s| !s.sql.contains(AUDIT))
                .map(|s| s.rows_written)
                .sum(),
        )
    }

    /// The stored meter row, read through an audit-marked SELECT.
    async fn audit_meter(db: &DurableDb) -> MeterRow {
        db.query("SELECT day, rows_read, rows_written, seq FROM meter WHERE id = 0 /* audit */")
            .fetch_one::<MeterRow>()
            .await
            .expect("meter row")
    }

    /// The stored row equals every row the store billed since `base`,
    /// minus `lost_reads` — the settled non-append reads a restart
    /// provably drops, the one gap the appends-only rule leaves.
    async fn stored_equals_billed(
        db: &DurableDb,
        log: &std::sync::Mutex<Vec<test_db::LoggedStatement>>,
        base: usize,
        lost_reads: u64,
    ) {
        let (read, written) = billed(log, base);
        let row = audit_meter(db).await;
        assert_eq!(
            u64::try_from(row.rows_read).expect("read"),
            read - lost_reads
        );
        assert_eq!(u64::try_from(row.rows_written).expect("written"), written);
    }

    /// An alert sink that swallows the trip's transition email — the
    /// freeze evaluation needs one and the counts do not depend on it.
    struct Sink;

    impl crate::freeze::AlertSink for Sink {
        fn opened(
            &self,
            _draft: &crate::freeze::AlertDraft,
        ) -> impl std::future::Future<Output = stow_types::api::ChannelOutcome> + Send {
            core::future::ready(stow_types::api::ChannelOutcome::Sent { message_id: None })
        }
        fn updated(
            &self,
            _draft: &crate::freeze::AlertDraft,
        ) -> impl std::future::Future<Output = stow_types::api::ChannelOutcome> + Send {
            core::future::ready(stow_types::api::ChannelOutcome::Sent { message_id: None })
        }
        fn resolved(
            &self,
            _draft: &crate::freeze::AlertDraft,
        ) -> impl std::future::Future<Output = stow_types::api::ChannelOutcome> + Send {
            core::future::ready(stow_types::api::ChannelOutcome::Sent { message_id: None })
        }
    }

    /// A restart: drop the isolate's cell, wake a fresh one through a
    /// metered wrap bound to it — the same [`wake`] sequence
    /// `ensure_graph` runs — stamp `woken_at_ms`, install and settle,
    /// the way `settle_meter` ends the waking request.
    async fn restart(db: &DurableDb, now_ms: i64) -> GraphCell {
        use crate::scheduler::meter::Meter;
        let cell = GraphCell::default();
        let (metered, meter) = Meter::wrap(db.clone(), &cell);
        let mut graph = wake(&metered, &cell, now_ms).await.expect("wake");
        graph.woken_at_ms = now_ms;
        let loaded = cell.install(graph);
        meter.settle(loaded, now_ms);
        cell
    }

    /// stow#931 §5.7: every row the store bills lands in the stored
    /// meter row exactly once — appends, reads, snapshots, wakes, and
    /// the real freeze path — through restarts and interleaved
    /// operations. `stored_equals_billed` runs after EVERY checkpoint
    /// so a checkpoint that drops its operation's counts fails where it
    /// lands, not at the end.
    #[tokio::test]
    async fn the_meter_row_accounts_every_billed_row_once() {
        use crate::scheduler::meter::Meter;

        let (db, log) = test_db::counting_memory_db().await.expect("db");
        let base = log.lock().expect("log").len();
        let cell = GraphCell::default();
        let loaded = cell.install(Graph::default());
        let tree = SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![0],
            nodes: vec![node("one"), node("two")],
        };
        let retry = [SchedulerEvent::Mutate {
            op: MutationKind::Retry,
            task_ids: vec![id("one")],
        }];

        // A request: its appends and read settle like the guard's.
        let (metered, meter) = Meter::wrap(db.clone(), &cell);
        let events = submission_events(&tree);
        let appended = append_events(&metered, None, &events, NOW_MS)
            .await
            .expect("submit");
        loaded.with(|graph| {
            graph.log_appended(appended.bytes, appended.seq);
            apply_events(graph, &logged(&events, NOW_MS, appended));
        });
        log_tail(&metered, 0).await.expect("tail read");
        meter.settle(loaded, NOW_MS);

        // The snapshot turn appends before snapshotting: the
        // checkpoint covers its own appends plus every snapshot
        // statement (§5.2 instances 1–2).
        let (metered, _meter) = Meter::wrap(db.clone(), &cell);
        let appended = append_events(&metered, None, &retry, NOW_MS)
            .await
            .expect("snapshot turn append");
        loaded.with(|graph| graph.log_appended(appended.bytes, appended.seq));
        crate::scheduler::routes::snapshot(loaded, &metered, NOW_MS)
            .await
            .expect("snapshot");
        stored_equals_billed(&db, &log, base, 0).await;

        // An operation that never settles: its append's seq lifts,
        // its cost stays in the cell's unsettled counts, and a later
        // wake must not re-count the row.
        let (metered, _dead) = Meter::wrap(db.clone(), &cell);
        let more = vec![
            SchedulerEvent::Mutate {
                op: MutationKind::Retry,
                task_ids: vec![id("two")],
            },
            SchedulerEvent::Mutate {
                op: MutationKind::Cancel,
                task_ids: vec![id("one")],
            },
        ];
        let appended = append_events(&metered, None, &more, NOW_MS + 1)
            .await
            .expect("tail appends");
        loaded.with(|graph| graph.log_appended(appended.bytes, appended.seq));

        // A wake: the checkpoint carries the two unsettled appends,
        // replayed at their billed cost, plus the wake's own reads.
        let cell = restart(&db, NOW_MS).await;
        stored_equals_billed(&db, &log, base, 0).await;

        // A read-only request settles reads and nothing else; the
        // restart before the next checkpoint then loses exactly its
        // reads — settled non-append statements are the one gap the
        // appends-only rule leaves (§5.7 step 3) — while the wake's
        // own reads land in its checkpoint. The tail must return
        // rows: an empty read bills nothing and proves nothing.
        let loaded = cell.loaded().expect("woken");
        let (metered, meter) = Meter::wrap(db.clone(), &cell);
        let tail = log_tail(&metered, 0).await.expect("read-only tail");
        assert!(!tail.is_empty(), "the read-only step must bill rows");
        meter.settle(loaded, NOW_MS);
        let lost = u64::try_from(tail.len()).expect("tail length fits u64");
        let cell = restart(&db, NOW_MS).await;
        stored_equals_billed(&db, &log, base, lost).await;

        // The real freeze path `settle_meter` runs (`meter.rs`'s
        // `trip_and_persist`): the operation appends, the `Freeze`
        // event appends through the metered handle. A snapshot then
        // covers the freeze row's seq — had the append gone out on the
        // unmetered handle (§5.2 instance 5), the stored row would
        // lack its cost, and this assert catches it: a wake alone
        // could not, since replay re-counts any uncovered row.
        let loaded = cell.loaded().expect("woken");
        let (metered, aux) = Meter::wrap(db.clone(), &cell);
        let (op_db, meter) = Meter::wrap(db.clone(), &cell);
        let appended = append_events(&op_db, None, &retry, NOW_MS + 2)
            .await
            .expect("op append before the trip");
        loaded.with(|graph| graph.log_appended(appended.bytes, appended.seq));
        let freeze_seq = crate::scheduler::meter::trip_and_persist(
            &aux,
            &metered,
            &meter,
            loaded,
            &Sink,
            1.0e-9,
            NOW_MS,
            "2026-10-25T00:00:00Z",
        )
        .await
        .expect("trip and persist");
        assert!(matches!(
            freeze_seq,
            Some(crate::freeze::FreezeTransition::Engaged(_))
        ));
        let (metered, _meter) = Meter::wrap(db.clone(), &cell);
        crate::scheduler::routes::snapshot(loaded, &metered, NOW_MS)
            .await
            .expect("snapshot over the freeze row");
        stored_equals_billed(&db, &log, base, lost).await;
        let cell = restart(&db, NOW_MS).await;
        stored_equals_billed(&db, &log, base, lost).await;

        let _ = cell;
    }

    /// stow#931: an operation that appends and then awaits non-storage
    /// I/O can interleave with another operation's snapshot — the
    /// checkpoint's `seq` covers A's row while its cost still sits
    /// unsettled. The isolate-wide `unsettled` accumulator makes the
    /// stored totals exact anyway; the old per-operation `pending`
    /// would have dropped it.
    #[tokio::test]
    async fn a_checkpoint_covers_an_interleaved_operations_appends() {
        use crate::scheduler::meter::Meter;

        let (db, log) = test_db::counting_memory_db().await.expect("db");
        let base = log.lock().expect("log").len();
        let cell = GraphCell::default();
        let loaded = cell.install(Graph::default());
        let tree = SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![0],
            nodes: vec![node("one")],
        };
        let (metered, meter) = Meter::wrap(db.clone(), &cell);
        let events = submission_events(&tree);
        let appended = append_events(&metered, None, &events, NOW_MS)
            .await
            .expect("submit");
        loaded.with(|graph| {
            graph.log_appended(appended.bytes, appended.seq);
            apply_events(graph, &logged(&events, NOW_MS, appended));
        });
        meter.settle(loaded, NOW_MS);

        // A appends and does not settle; B's snapshot checkpoint's seq
        // covers A's row and its totals must cover A's unsettled cost.
        let (metered_a, meter_a) = Meter::wrap(db.clone(), &cell);
        let appended = append_events(
            &metered_a,
            None,
            &[SchedulerEvent::Mutate {
                op: MutationKind::Retry,
                task_ids: vec![id("one")],
            }],
            NOW_MS + 1,
        )
        .await
        .expect("interleaved append");
        loaded.with(|graph| graph.log_appended(appended.bytes, appended.seq));
        let (metered_b, _meter_b) = Meter::wrap(db.clone(), &cell);
        crate::scheduler::routes::snapshot(loaded, &metered_b, NOW_MS)
            .await
            .expect("interleaved snapshot");
        stored_equals_billed(&db, &log, base, 0).await;
        meter_a.settle(loaded, NOW_MS);
        let cell = restart(&db, NOW_MS).await;
        stored_equals_billed(&db, &log, base, 0).await;
        let _ = cell;
    }

    /// stow#931 §5.7: a wake after the UTC day rolls writes the new
    /// day's totals alone — the old day's counters never carry over.
    /// A tail row stamped on the earlier day was still billed after
    /// the checkpoint, so replay books its 1 R + 1 W on the meter's
    /// current day: the stored day moves forward, never backwards.
    #[tokio::test]
    async fn a_day_roll_starts_the_stored_day_fresh() {
        const DAY_MS: i64 = 86_400_000;
        use crate::scheduler::meter::Meter;

        let (db, log) = test_db::counting_memory_db().await.expect("db");
        let cell = GraphCell::default();
        let (metered, _dead) = Meter::wrap(db.clone(), &cell);
        let events = vec![SchedulerEvent::Mutate {
            op: MutationKind::Retry,
            task_ids: Vec::new(),
        }];
        append_events(&metered, None, &events, NOW_MS)
            .await
            .expect("append");

        // The next day's wake: the tail re-counts under its event's
        // old day and rolls away with it — the stored row is the
        // wake's own reads plus the checkpoint.
        let base = log.lock().expect("log").len();
        let _woken = restart(&db, NOW_MS + DAY_MS).await;
        let row = audit_meter(&db).await;
        assert_eq!(row.day, utc_day(NOW_MS + DAY_MS));
        let (read, written) = billed(&log, base);
        assert_eq!(u64::try_from(row.rows_read).expect("read"), read);
        assert_eq!(u64::try_from(row.rows_written).expect("written"), written);
        let prior = (
            u64::try_from(row.rows_read).expect("read"),
            u64::try_from(row.rows_written).expect("written"),
        );

        // A row stamped on the earlier day — its operation took `at`
        // before midnight and appended after — was billed after the
        // checkpoint, so replay books its 1 R + 1 W on the meter's
        // current day. `base` is taken before the append so the stored
        // row must carry its cost: a replay that dropped it would come
        // up short.
        let base = log.lock().expect("log").len();
        append_events(
            &db,
            None,
            &[SchedulerEvent::Mutate {
                op: MutationKind::Cancel,
                task_ids: Vec::new(),
            }],
            NOW_MS,
        )
        .await
        .expect("stale-stamped append");
        let _woken = restart(&db, NOW_MS + DAY_MS).await;
        let row = audit_meter(&db).await;
        assert_eq!(row.day, utc_day(NOW_MS + DAY_MS));
        let (read, written) = billed(&log, base);
        // The restored totals survived: the replayed row's append cost
        // booked on today's meter, and the wake's own statements and
        // the checkpoint join the prior stored totals.
        assert_eq!(u64::try_from(row.rows_read).expect("read"), prior.0 + read,);
        assert_eq!(
            u64::try_from(row.rows_written).expect("written"),
            prior.1 + written,
        );
    }

    /// The checkpoint's `UPDATE meter .. RETURNING` bills exactly
    /// [`METER_CHECKPOINT_BILL`] through the counting backend — the
    /// workerd bill (release gate run 40186665163: `rows_returned 1`,
    /// `rows_read 2`, `rows_written 1`) the host backend mirrors.
    #[tokio::test]
    async fn the_checkpoint_update_bills_its_predicted_cost() {
        let (db, log) = test_db::counting_memory_db().await.expect("db");
        let base = log.lock().expect("log").len();
        checkpoint_meter(&db, &Meter::default(), &GraphCell::default(), 0, NOW_MS)
            .await
            .expect("checkpoint");
        let statement = {
            let log = log.lock().expect("log");
            assert_eq!(log.len() - base, 1, "the checkpoint is one statement");
            log[base].clone()
        };
        assert!(
            statement.sql.starts_with("UPDATE meter"),
            "the checkpoint statement: {}",
            statement.sql
        );
        assert_eq!(
            (statement.rows_read, statement.rows_written),
            METER_CHECKPOINT_BILL
        );
    }

    /// stow#955: an attributed append names the requesting run's actor
    /// on its batch's first row only, bills exactly the statements and
    /// rows an unattributed append does, and replays to the same
    /// events — the unit `StoreReset` row included.
    #[tokio::test]
    async fn an_attributed_append_names_the_actor_on_the_first_row_at_no_extra_rows() {
        let mut batch = submission_events(&chain());
        batch.push(SchedulerEvent::Mutate {
            op: MutationKind::Cancel,
            task_ids: vec![id("a")],
        });
        let mut bills = Vec::new();
        let mut stored = Vec::new();
        for actor in [Some("octo-dispatcher"), None] {
            let (db, log) = test_db::counting_memory_db().await.expect("db");
            let base = log.lock().expect("log").len();
            append_events(&db, actor, &[SchedulerEvent::StoreReset], 0)
                .await
                .expect("reset row");
            append_events(&db, actor, &batch, 0).await.expect("batch");
            let statements = log.lock().expect("log").len() - base;
            bills.push((statements, billed(&log, base)));
            let rows = db
                .query(&format!(
                    "SELECT seq, at, event FROM event_log ORDER BY seq{AUDIT}"
                ))
                .fetch_all::<LogRow>()
                .await
                .expect("rows");
            stored.push(rows);
        }
        assert_eq!(
            bills[0], bills[1],
            "attribution must not add statements or rows"
        );

        let actors: Vec<Option<String>> = stored[0]
            .iter()
            .map(|row| {
                serde_json::from_str::<serde_json::Value>(&row.event).expect("row json")["actor"]
                    .as_str()
                    .map(str::to_owned)
            })
            .collect();
        let mut expected = vec![None; 1 + batch.len()];
        expected[0] = Some("octo-dispatcher".to_owned());
        expected[1] = Some("octo-dispatcher".to_owned());
        assert_eq!(
            actors, expected,
            "each append attributes its first row only"
        );

        for (attributed, plain) in stored[0].iter().zip(&stored[1]) {
            let decoded = decode_event(&attributed.event).expect("attributed row decodes");
            assert_eq!(
                encode_event(&decoded).expect("encode"),
                plain.event,
                "an attributed row decodes to the unattributed event"
            );
        }
    }
}
