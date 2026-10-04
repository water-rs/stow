//! The hourly demand feed's durable state machine (stow#523).
//!
//! `stow-admin scheduler demand-feed` materializes one closed
//! Analytics Engine hour into bounded staged pages under a typed hour
//! header, freezes the whole response at a single completion barrier,
//! and then delivers the frozen pages into the demand ledger
//! (stow#522) one `demand-feed/{hour}/{page_no}` batch at a time.
//!
//! - `begin` opens the `staging` attempt — or, on a staging hour,
//!   rotates it: the generation bumps and the staging counters reset
//!   in one guarded statement, so a restarted materialization is a
//!   fresh attempt whose bytes can never merge into the abandoned
//!   one's. Abandoned-generation pages retire in bounded chunks via
//!   `cleanup`, not in one statement inside `begin`. A `begin` on a
//!   frozen hour — or at or below the delivered watermark — refuses:
//!   a complete hour is never re-queried.
//! - `page` stages one bounded immutable payload (≤256 entries, ≤512
//!   KiB for the whole encoded request — below the 100-bound-parameter,
//!   statement-size and row-size native limits). Pages stage strictly
//!   in order under the attempt generation: `page_no` must equal the
//!   header's `staged_pages` counter (bumped by the insert trigger in
//!   the same statement), and each new row carries `chain_hash` — the
//!   rolling blake3 `chain(p) = blake3(chain(p-1) || page_hash(p))`
//!   seeded by page 0 — so the completion barrier can bind the frozen
//!   set to one ordered manifest. A replay of an already-staged page
//!   is a no-op only when the stored `page_hash` matches byte-for-byte;
//!   a changed payload on the same page refuses.
//! - `complete` is one guarded statement: `staging` + generation CAS +
//!   `staged_pages`/`staged_entries` == declared count/entry total +
//!   the last page's `chain_hash` == the materializer's declared
//!   manifest hash. No header stamp precedes its pages.
//! - `deliver` replays the next unapplied page verbatim: the frozen
//!   bytes, never a fresh AE answer. The demand ledger's own replay
//!   contract makes a lost ack a zero-write re-arm, and the page's
//!   `applied` mark advances only after the batch reports; the apply
//!   trigger counts each ack exactly once. With every original page
//!   acknowledged the call performs the guarded `complete → delivered`
//!   transition — which requires `applied_pages = page_count` and that
//!   this hour is the canonical `next` of the watermark (or the first
//!   ever delivered) — and the `demand_feed_hour_delivered` trigger
//!   stamps the monotonic watermark in the same statement. Payload
//!   retirement happens only after that durable cursor: bounded
//!   `LIMIT`-chunked deletes through `cleanup`, explicit event work
//!   with zero idle cost.
//! - `status` is the durable resume cursor: the oldest unfinished hour
//!   through the partial index (a bounded probe, never a `MIN()` over
//!   every header) plus the watermark.

use skyzen::FromRow;
use skyzen_services::durable::DurableDb;
use stow_types::api::{
    DEMAND_FEED_BATCH_PREFIX, DEMAND_FEED_PAGE_MAX_BYTES, DEMAND_FEED_PAGE_MAX_ENTRIES,
    DEMAND_FEED_RETIRE_CHUNK, DemandFeedBeginReport, DemandFeedCleanupReport,
    DemandFeedCompleteRequest, DemandFeedDeliverReport, DemandFeedHour, DemandFeedPageRequest,
    DemandFeedStatus, DemandFeedUnfinished, SchedulerDemandEntry, SchedulerDemandRequest,
    demand_feed_chain, demand_feed_page_payload,
};

use super::queue::{self, AlarmPlan, SchedulerSettings};
use crate::errors::QueueError;

/// The `settings` key the watermark lives under — the durable cursor
/// below which every hour is fully delivered. Text form matches the
/// hour key so comparisons sort lexicographically.
const WATERMARK_KEY: &str = "demand_feed_watermark";

/// One `demand_feed_hours` row.
#[derive(Debug, FromRow)]
struct HourRow {
    generation: i64,
    state: String,
    staged_pages: i64,
    page_count: i64,
}

/// The unfinished-index probe row.
#[derive(Debug, FromRow)]
struct UnfinishedRow {
    hour: String,
    generation: i64,
    state: String,
    staged_pages: i64,
    staged_entries: i64,
}

/// One staged page row the deliver walk reads.
#[derive(Debug, FromRow)]
struct PageRow {
    page_no: i64,
    payload: String,
}

/// The columns every header read shares.
const HOUR_COLS: &str = "generation, state, staged_pages, page_count";

/// Read the hour's header row.
async fn read_hour(db: &DurableDb, hour: &str) -> Result<Option<HourRow>, QueueError> {
    db.query(&format!(
        "SELECT {HOUR_COLS} FROM demand_feed_hours WHERE hour = ?"
    ))
    .bind(hour)
    .fetch_optional::<HourRow>()
    .await
    .map_err(|error| format!("read demand feed hour {hour}: {error}").into())
}

/// The stored watermark, when any hour has delivered.
async fn read_watermark(db: &DurableDb) -> Result<Option<String>, QueueError> {
    db.query("SELECT value FROM settings WHERE key = ?")
        .bind(WATERMARK_KEY)
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("read demand feed watermark: {error}").into())
}

/// Reject a begin that is not the watermark's canonical successor.
/// Once any hour has delivered, the only admissible new attempt —
/// fresh insert or staging rotation alike — is the hour immediately
/// after the cursor: an out-of-order begin would freeze demand the
/// cursor can never pass, and wedging it below a gap blocks the
/// genuine successor's recovery. One point read, no history scan.
async fn require_canonical_successor(
    db: &DurableDb,
    hour: &DemandFeedHour,
) -> Result<(), QueueError> {
    let Some(watermark) = read_watermark(db).await? else {
        return Ok(());
    };
    let watermark_hour = DemandFeedHour::parse(&watermark).map_err(|error| {
        QueueError::Invariant(format!(
            "demand feed watermark {watermark:?} is not a canonical hour: {error}"
        ))
    })?;
    let successor = watermark_hour.next().map_err(QueueError::Invariant)?;
    if hour != &successor {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {hour} is not the watermark's canonical              successor {successor} — earlier hours must finish first"
        )));
    }
    Ok(())
}

/// `true` while `hour` still holds page rows that `cleanup` may
/// retire — abandoned-generation leftovers, or a delivered hour's
/// acknowledged payloads. One bounded `EXISTS` probe that only ever
/// walks the retirable range: a delivered hour probes the bare `hour`
/// PK prefix, an in-flight hour probes `generation < current` —
/// generations only grow, so every obsolete attempt sorts below the
/// live one and current-generation pages are never visited.
async fn cleanup_pending(
    db: &DurableDb,
    hour: &str,
    generation: i64,
    delivered: bool,
) -> Result<bool, QueueError> {
    let exists = if delivered {
        db.query("SELECT EXISTS(SELECT 1 FROM demand_feed_pages WHERE hour = ? LIMIT 1)")
            .bind(hour)
            .fetch_scalar::<i64>()
            .await
    } else {
        db.query(
            "SELECT EXISTS(SELECT 1 FROM demand_feed_pages \
             WHERE hour = ? AND generation < ? LIMIT 1)",
        )
        .bind(hour)
        .bind(generation)
        .fetch_scalar::<i64>()
        .await
    };
    exists
        .map(|exists| exists != 0)
        .map_err(|error| format!("probe demand feed cleanup for {hour}: {error}").into())
}

/// `GET /demand-feed/status` — the durable resume cursor: the oldest
/// unfinished hour through the partial index (a bounded probe, never
/// a `MIN()` over every header) plus the delivered watermark.
pub async fn feed_status(db: &DurableDb) -> Result<DemandFeedStatus, QueueError> {
    let watermark = read_watermark(db).await?;
    let unfinished = db
        .query(
            "SELECT hour, generation, state, staged_pages, staged_entries \
             FROM demand_feed_hours \
             WHERE state IN ('staging', 'complete') \
             ORDER BY hour LIMIT 1",
        )
        .fetch_optional::<UnfinishedRow>()
        .await
        .map_err(|error| format!("read unfinished demand feed hour: {error}"))?;
    Ok(DemandFeedStatus {
        watermark,
        unfinished: unfinished.map(|row| DemandFeedUnfinished {
            hour: row.hour,
            state: row.state,
            generation: row.generation,
            staged_pages: row.staged_pages,
            staged_entries: row.staged_entries,
        }),
    })
}

/// `POST /demand-feed/begin` — open or resume the staging attempt.
/// A frozen hour refuses — once complete, the hour's input is final —
/// and an hour at or below the watermark can never re-materialize.
/// A staging hour rotates: one guarded statement bumps the generation
/// and resets the staging counters, then one bounded delete chunk
/// retires abandoned-generation pages; `cleanup` drains any rest.
pub async fn feed_begin(
    db: &DurableDb,
    hour: &DemandFeedHour,
    now_unix_secs: i64,
) -> Result<DemandFeedBeginReport, QueueError> {
    hour.ensure_closed(now_unix_secs)
        .map_err(QueueError::Invariant)?;
    require_canonical_successor(db, hour).await?;
    if let Some(row) = read_hour(db, hour.as_str()).await? {
        if row.state != "staging" {
            return Err(QueueError::Invariant(format!(
                "demand feed hour {hour} is {}; frozen hours never re-materialize",
                row.state
            )));
        }
        // Rotate and reset atomically — a staging restart is a fresh
        // attempt, never a merge into the abandoned generation's pages.
        // The monotonically bumped generation stays distinct even when
        // two begins land inside the same wall-clock second.
        db.query(
            "UPDATE demand_feed_hours \
             SET generation = generation + 1, staged_pages = 0, \
                 staged_entries = 0, applied_pages = 0 \
             WHERE hour = ? AND state = 'staging'",
        )
        .bind(hour.as_str())
        .execute()
        .await
        .map_err(|error| format!("rotate demand feed generation {hour}: {error}"))?;
        let generation = db
            .query("SELECT generation FROM demand_feed_hours WHERE hour = ?")
            .bind(hour.as_str())
            .fetch_scalar::<i64>()
            .await
            .map_err(|error| format!("read back demand feed generation {hour}: {error}"))?;
        // Bound the event: retire one chunk of obsolete-generation rows
        // now; `cleanup` drains the remainder on explicit calls.
        retire_chunk(db, hour.as_str(), generation, false).await?;
        return Ok(DemandFeedBeginReport {
            hour: hour.clone(),
            generation,
            stale_pages_pending: cleanup_pending(db, hour.as_str(), generation, false).await?,
        });
    }
    // The generation is the attempt's identity — the wall-clock
    // second the attempt opened.
    db.query(
        "INSERT INTO demand_feed_hours (hour, generation, state) \
         VALUES (?, CAST(strftime('%s', 'now') AS INTEGER), 'staging')",
    )
    .bind(hour.as_str())
    .execute()
    .await
    .map_err(|error| format!("open demand feed hour {hour}: {error}"))?;
    let generation = db
        .query("SELECT generation FROM demand_feed_hours WHERE hour = ?")
        .bind(hour.as_str())
        .fetch_scalar::<i64>()
        .await
        .map_err(|error| format!("read back demand feed generation {hour}: {error}"))?;
    Ok(DemandFeedBeginReport {
        hour: hour.clone(),
        generation,
        stale_pages_pending: false,
    })
}

/// `POST /demand-feed/page` — stage one bounded immutable page under
/// the attempt generation. The whole encoded request must fit the
/// byte bound — a large feature list simply makes more pages — and
/// pages stage strictly in order: `page_no` must equal the header's
/// `staged_pages`, so a late or skipped page can never slot into a
/// frozen-in-progress manifest. Each insert carries `chain_hash`, the
/// rolling blake3 over the ordered page hashes, and the same-statement
/// trigger bumps `staged_pages`/`staged_entries` — counters and pages
/// can never disagree. A replayed page (`page_no` < `staged_pages`) is a
/// no-op only when its stored hash matches; changed bytes refuse.
pub async fn feed_page(
    db: &DurableDb,
    request: &DemandFeedPageRequest,
    now_unix_secs: i64,
) -> Result<(), QueueError> {
    request
        .hour
        .ensure_closed(now_unix_secs)
        .map_err(QueueError::Invariant)?;
    if request.entries.is_empty() {
        return Err(QueueError::Invariant(format!(
            "demand feed page {}/{} is empty",
            request.hour, request.page_no
        )));
    }
    if request.entries.len() > DEMAND_FEED_PAGE_MAX_ENTRIES {
        return Err(QueueError::Invariant(format!(
            "demand feed page {}/{} carries {} entries; the bound is {}",
            request.hour,
            request.page_no,
            request.entries.len(),
            DEMAND_FEED_PAGE_MAX_ENTRIES
        )));
    }
    // The byte bound covers the whole encoded request envelope — the
    // entries plus the framing fields — measured on the same serde
    // serialization the wire carried.
    let envelope = serde_json::to_vec(request).map_err(|error| {
        QueueError::Invariant(format!(
            "serialize demand feed page {}/{}: {error}",
            request.hour, request.page_no
        ))
    })?;
    if envelope.len() > DEMAND_FEED_PAGE_MAX_BYTES {
        return Err(QueueError::Invariant(format!(
            "demand feed page {}/{} encodes to {} bytes; the bound is {}",
            request.hour,
            request.page_no,
            envelope.len(),
            DEMAND_FEED_PAGE_MAX_BYTES
        )));
    }
    let Some(row) = read_hour(db, request.hour.as_str()).await? else {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {} has no open attempt — begin first",
            request.hour
        )));
    };
    if row.state != "staging" {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {} is {}; staged pages are immutable once frozen",
            request.hour, row.state
        )));
    }
    if row.generation != request.generation {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {} attempt is generation {}, not {}",
            request.hour, row.generation, request.generation
        )));
    }
    let page_no = i64::from(request.page_no);
    if page_no > row.staged_pages {
        return Err(QueueError::Invariant(format!(
            "demand feed page {}/{page_no} arrives out of order; \
             {} pages are staged",
            request.hour, row.staged_pages
        )));
    }
    let payload = demand_feed_page_payload(&request.entries).map_err(|error| {
        QueueError::Invariant(format!(
            "serialize demand feed page {}/{}: {error}",
            request.hour, request.page_no
        ))
    })?;
    let page_hash = blake3::hash(payload.as_bytes());
    if page_no < row.staged_pages {
        return feed_page_replay(db, request, page_no, page_hash).await;
    }
    feed_page_extend(db, request, page_no, page_hash, payload).await
}

/// Idempotent replay of an already-staged page: the same generation's
/// page with the same bytes is a no-op, never a replace — changed
/// bytes on a staged page refuse.
async fn feed_page_replay(
    db: &DurableDb,
    request: &DemandFeedPageRequest,
    page_no: i64,
    page_hash: blake3::Hash,
) -> Result<(), QueueError> {
    let stored = db
        .query(
            "SELECT page_hash FROM demand_feed_pages \
             WHERE hour = ? AND generation = ? AND page_no = ?",
        )
        .bind(request.hour.as_str())
        .bind(request.generation)
        .bind(page_no)
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("read staged page {}/{page_no}: {error}", request.hour))?;
    match stored.as_deref() {
        Some(existing) if existing == page_hash.to_hex().as_str() => Ok(()),
        Some(_) => Err(QueueError::Invariant(format!(
            "demand feed page {}/{page_no} is immutable: \
             the staged payload differs",
            request.hour
        ))),
        // The row is missing but the counter says it staged — the
        // staging counters are trigger-maintained, so this is a
        // storage inconsistency, not a retry.
        None => Err(QueueError::Invariant(format!(
            "demand feed page {}/{page_no} counted but absent",
            request.hour
        ))),
    }
}

/// Sequential extension: chain this page's hash onto the previous
/// page's (page 0 seeds the chain with its own hash), so the last
/// staged page proves the ordered set. The predecessor read is one PK
/// lookup, and the plain INSERT — never a replace — keeps same-page
/// changed bytes from overwriting staged input while the trigger
/// counts the stage in the same statement the row lands.
async fn feed_page_extend(
    db: &DurableDb,
    request: &DemandFeedPageRequest,
    page_no: i64,
    page_hash: blake3::Hash,
    payload: String,
) -> Result<(), QueueError> {
    let chain_hash = if page_no == 0 {
        page_hash
    } else {
        let previous = db
            .query(
                "SELECT chain_hash FROM demand_feed_pages \
                 WHERE hour = ? AND generation = ? AND page_no = ?",
            )
            .bind(request.hour.as_str())
            .bind(request.generation)
            .bind(page_no - 1)
            .fetch_scalar::<String>()
            .await
            .map_err(|error| {
                format!(
                    "read previous page chain for {}/{page_no}: {error}",
                    request.hour
                )
            })?;
        let previous_hash = blake3::Hash::from_hex(previous.as_str()).map_err(|error| {
            QueueError::Invariant(format!(
                "stored chain hash for {}/{} does not decode: {error}",
                request.hour,
                page_no - 1
            ))
        })?;
        demand_feed_chain(&previous_hash, &page_hash)
    };
    let entry_count = i64::try_from(request.entries.len()).map_err(|_| QueueError::Overflow {
        field: "demand feed page entry count",
        value: u64::try_from(request.entries.len()).unwrap_or(u64::MAX),
    })?;
    db.query(
        "INSERT INTO demand_feed_pages \
         (hour, generation, page_no, entry_count, page_hash, chain_hash, payload, applied) \
         VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
    )
    .bind(request.hour.as_str())
    .bind(request.generation)
    .bind(page_no)
    .bind(entry_count)
    .bind(page_hash.to_hex().to_string())
    .bind(chain_hash.to_hex().to_string())
    .bind(payload)
    .execute()
    .await
    .map_err(|error| format!("stage demand feed page {}/{page_no}: {error}", request.hour))?;
    Ok(())
}

/// `POST /demand-feed/complete` — the single completion barrier: one
/// guarded statement verifies the trigger-maintained staged counters
/// and the ordered page-hash manifest against the materializer's
/// declared totals while freezing the hour, so a header can never
/// claim completeness its pages do not prove. `changes == 1` is the
/// acceptance; anything else is a staging-incomplete, wrong-generation
/// or wrong-manifest refusal.
pub async fn feed_complete(
    db: &DurableDb,
    request: &DemandFeedCompleteRequest,
    now_unix_secs: i64,
) -> Result<(), QueueError> {
    request
        .hour
        .ensure_closed(now_unix_secs)
        .map_err(QueueError::Invariant)?;
    if request.page_count > 0 && request.manifest_hash.len() != 64 {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {} manifest hash is not a blake3 hex digest",
            request.hour
        )));
    }
    let entry_count = i64::try_from(request.entry_count).map_err(|_| QueueError::Overflow {
        field: "demand feed entry count",
        value: request.entry_count,
    })?;
    let page_count = i64::from(request.page_count);
    db.query(
        "UPDATE demand_feed_hours \
         SET state = 'complete', page_count = ?, entry_count = ? \
         WHERE hour = ? AND state = 'staging' AND generation = ? \
           AND staged_pages = ? AND staged_entries = ? \
           AND (? = 0 OR \
                (SELECT p.chain_hash FROM demand_feed_pages p \
                 WHERE p.hour = demand_feed_hours.hour \
                   AND p.generation = demand_feed_hours.generation \
                   AND p.page_no = ? - 1) = ?)",
    )
    .bind(page_count)
    .bind(entry_count)
    .bind(request.hour.as_str())
    .bind(request.generation)
    .bind(page_count)
    .bind(entry_count)
    .bind(page_count)
    .bind(page_count)
    .bind(request.manifest_hash.as_str())
    .execute()
    .await
    .map_err(|error| format!("complete demand feed hour {}: {error}", request.hour))?;
    if queue::changes(db).await? != 1 {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {} generation {} refused completion: \
             staging incomplete, wrong generation, or manifest mismatch",
            request.hour, request.generation
        )));
    }
    Ok(())
}

/// `POST /demand-feed/deliver` — one bounded page of work: the next
/// unapplied page replays verbatim into the demand ledger as batch
/// `demand-feed/{hour}/{page_no}`, its `applied` mark advancing only
/// after the ledger's own report — a lost ack re-arms the same page,
/// which #522's accepted-batch contract answers as a zero-write
/// replay, and the apply trigger counts the ack exactly once. With no
/// unapplied page left, the call performs the terminal transition:
/// one guarded statement requires `applied_pages = page_count` and
/// watermark contiguity — this hour must be the canonical `next` of
/// the durable cursor (or the first delivered hour ever) — and the
/// delivered trigger stamps the watermark in the same statement.
/// Payloads retire later through `cleanup`'s bounded chunks.
///
/// Returns the deliver report plus the alarm plan the shared pass
/// decided — the caller arms it exactly like `/demand` does.
pub async fn feed_deliver(
    db: &DurableDb,
    hour: &DemandFeedHour,
    now_ms: i64,
    settings: &SchedulerSettings,
) -> Result<(DemandFeedDeliverReport, AlarmPlan), QueueError> {
    hour.ensure_closed(now_ms / 1_000)
        .map_err(QueueError::Invariant)?;
    let row = read_hour(db, hour.as_str()).await?.ok_or_else(|| {
        QueueError::Invariant(format!("demand feed hour {hour} was never staged"))
    })?;
    if row.state == "staging" {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {hour} is still staging — only complete hours deliver"
        )));
    }
    if row.state == "delivered" {
        let plan = queue::next_alarm(db, now_ms, settings).await?;
        return Ok((
            DemandFeedDeliverReport {
                hour: hour.to_string(),
                state: "delivered".to_owned(),
                delivered_page: None,
                applied: false,
                touched_tasks: 0,
                remaining_pages: 0,
            },
            plan,
        ));
    }

    // Before any demand or acknowledgment write: this hour must be
    // the watermark's canonical successor AND have no unfinished
    // header below it — refuse here rather than let demand land and
    // only then fail the terminal contiguity check. The canonical
    // point read needs no scan; the older-unfinished probe is the
    // existing bounded partial-index lookup, one row maximum.
    require_canonical_successor(db, hour).await?;
    let older = db
        .query(
            "SELECT hour FROM demand_feed_hours \
             WHERE hour < ? AND state != 'delivered' LIMIT 1",
        )
        .bind(hour.as_str())
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("probe unfinished predecessors of {hour}: {error}"))?;
    if let Some(older) = older {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {hour} cannot deliver while {older} is unfinished"
        )));
    }

    let page = db
        .query(
            "SELECT page_no, payload FROM demand_feed_pages \
             WHERE hour = ? AND generation = ? AND applied = 0 \
             ORDER BY page_no LIMIT 1",
        )
        .bind(hour.as_str())
        .bind(row.generation)
        .fetch_optional::<PageRow>()
        .await
        .map_err(|error| format!("read next undelivered page for {hour}: {error}"))?;

    let Some(page) = page else {
        return finish_feed_deliver(db, hour, now_ms, settings).await;
    };
    apply_feed_page(db, hour, &row, &page, now_ms, settings).await
}

/// The terminal transition: every original page acknowledged, so the
/// hour marks `delivered` in one guarded statement — all acked
/// (header counters) AND this hour is the watermark's canonical
/// successor (or the first delivered hour), so the cursor can neither
/// leap over missing hours nor move backwards.
async fn finish_feed_deliver(
    db: &DurableDb,
    hour: &DemandFeedHour,
    now_ms: i64,
    settings: &SchedulerSettings,
) -> Result<(DemandFeedDeliverReport, AlarmPlan), QueueError> {
    let predecessor = hour.prev().map_err(QueueError::Invariant)?;
    db.query(
        "UPDATE demand_feed_hours SET state = 'delivered' \
             WHERE hour = ? AND state = 'complete' \
               AND applied_pages = page_count \
               AND (NOT EXISTS (SELECT 1 FROM settings WHERE key = ?) OR \
                    (SELECT value FROM settings WHERE key = ?) = ?) \
               AND NOT EXISTS ( \
                    SELECT 1 FROM demand_feed_hours older \
                    WHERE older.hour < demand_feed_hours.hour \
                      AND older.state IN ('staging', 'complete'))",
    )
    .bind(hour.as_str())
    .bind(WATERMARK_KEY)
    .bind(WATERMARK_KEY)
    .bind(predecessor.as_str())
    .execute()
    .await
    .map_err(|error| format!("mark demand feed hour {hour} delivered: {error}"))?;
    if queue::changes(db).await? != 1 {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {hour} cannot complete delivery: \
                 unacknowledged pages remain, the watermark is not at {predecessor}, \
                 or an unfinished hour sits below it"
        )));
    }
    let plan = queue::next_alarm(db, now_ms, settings).await?;
    Ok((
        DemandFeedDeliverReport {
            hour: hour.to_string(),
            state: "delivered".to_owned(),
            delivered_page: None,
            applied: false,
            touched_tasks: 0,
            remaining_pages: 0,
        },
        plan,
    ))
}

/// Replay one frozen page verbatim into the demand ledger — never a
/// fresh Analytics Engine answer — and mark it applied. The parse
/// failure of a staged payload is an invariant: `complete` verified
/// the manifest, and the bytes were serialized by serde at staging
/// time.
async fn apply_feed_page(
    db: &DurableDb,
    hour: &DemandFeedHour,
    row: &HourRow,
    page: &PageRow,
    now_ms: i64,
    settings: &SchedulerSettings,
) -> Result<(DemandFeedDeliverReport, AlarmPlan), QueueError> {
    let entries: Vec<SchedulerDemandEntry> =
        serde_json::from_str(&page.payload).map_err(|error| {
            QueueError::Invariant(format!(
                "demand feed page {hour}/{} payload does not decode: {error}",
                page.page_no
            ))
        })?;
    let batch_id = format!("{DEMAND_FEED_BATCH_PREFIX}{hour}/{}", page.page_no);
    let request = SchedulerDemandRequest { batch_id, entries };
    let (report, plan) = queue::demand_pass(db, &request, now_ms, settings).await?;
    db.query(
        "UPDATE demand_feed_pages SET applied = 1 \
         WHERE hour = ? AND generation = ? AND page_no = ?",
    )
    .bind(hour.as_str())
    .bind(row.generation)
    .bind(page.page_no)
    .execute()
    .await
    .map_err(|error| {
        format!(
            "mark demand feed page {hour}/{} applied: {error}",
            page.page_no
        )
    })?;
    // `applied_pages` moved in the same statement the mark did — read
    // the header counter, never a COUNT over remaining pages.
    let applied_pages = db
        .query("SELECT applied_pages FROM demand_feed_hours WHERE hour = ?")
        .bind(hour.as_str())
        .fetch_scalar::<i64>()
        .await
        .map_err(|error| format!("read applied page count for {hour}: {error}"))?;
    let remaining = row.page_count.checked_sub(applied_pages).ok_or_else(|| {
        QueueError::Invariant(format!(
            "demand feed hour {hour} applied_pages {applied_pages} exceeds page_count {}",
            row.page_count
        ))
    })?;
    Ok((
        DemandFeedDeliverReport {
            hour: hour.to_string(),
            state: "complete".to_owned(),
            delivered_page: Some(u32::try_from(page.page_no).map_err(|_| {
                QueueError::Overflow {
                    field: "demand feed page_no",
                    value: u64::try_from(page.page_no).unwrap_or(u64::MAX),
                }
            })?),
            applied: report.applied,
            touched_tasks: report.touched_tasks,
            remaining_pages: u64::try_from(remaining).map_err(|_| {
                QueueError::Invariant(format!(
                    "demand feed hour {hour} applied_pages {applied_pages} exceeds page_count {}",
                    row.page_count
                ))
            })?,
        },
        plan,
    ))
}

/// `POST /demand-feed/cleanup` — retire up to
/// [`DEMAND_FEED_RETIRE_CHUNK`] page rows for `hour`: obsolete
/// generations of an in-flight staging attempt, or every payload of a
/// `delivered` hour — payloads survive exactly as long as
/// unacknowledged delivery needs them, and the watermark makes every
/// older replay a no-op before the delete runs. Explicit bounded
/// event work; nothing schedules it.
pub async fn feed_cleanup(
    db: &DurableDb,
    hour: &DemandFeedHour,
    now_unix_secs: i64,
) -> Result<DemandFeedCleanupReport, QueueError> {
    hour.ensure_closed(now_unix_secs)
        .map_err(QueueError::Invariant)?;
    let row = read_hour(db, hour.as_str()).await?.ok_or_else(|| {
        QueueError::Invariant(format!("demand feed hour {hour} was never staged"))
    })?;
    let delivered = row.state == "delivered";
    let retired = retire_chunk(db, hour.as_str(), row.generation, delivered).await?;
    Ok(DemandFeedCleanupReport {
        hour: hour.clone(),
        retired,
        remaining: cleanup_pending(db, hour.as_str(), row.generation, delivered).await?,
    })
}

/// One bounded delete chunk: at most `DEMAND_FEED_RETIRE_CHUNK` rows,
/// chosen through the PK prefix — `generation < current` while the
/// attempt is in flight (obsolete attempts always sort below the live
/// generation) and the bare `hour` prefix once delivered. Returns the
/// rows retired.
async fn retire_chunk(
    db: &DurableDb,
    hour: &str,
    generation: i64,
    delivered: bool,
) -> Result<u64, QueueError> {
    if delivered {
        db.query(
            "DELETE FROM demand_feed_pages WHERE rowid IN ( \
                 SELECT rowid FROM demand_feed_pages WHERE hour = ? LIMIT ?)",
        )
        .bind(hour)
        .bind(DEMAND_FEED_RETIRE_CHUNK)
        .execute()
        .await
    } else {
        db.query(
            "DELETE FROM demand_feed_pages WHERE rowid IN ( \
                 SELECT rowid FROM demand_feed_pages \
                 WHERE hour = ? AND generation < ? LIMIT ?)",
        )
        .bind(hour)
        .bind(generation)
        .bind(DEMAND_FEED_RETIRE_CHUNK)
        .execute()
        .await
    }
    .map_err(|error| format!("retire demand feed pages for {hour}: {error}"))?;
    queue::changes(db).await
}

#[cfg(test)]
mod tests {
    use super::{feed_begin, feed_cleanup, feed_complete, feed_deliver, feed_page, read_hour};
    use crate::scheduler::queue::{Dispatch, SchedulerSettings};
    use crate::scheduler::test_db::{counting_memory_db, memory_db};
    use stow_types::api::{
        DemandFeedCompleteRequest, DemandFeedHour, DemandFeedPageRequest, EnqueueRequest,
        EnqueueSource, SchedulerDemandEntry, demand_feed_manifest, demand_feed_page_hash,
    };
    use stow_types::identity::FeaturesJson;

    /// Far enough past every hour the tests use that each is closed.
    const NOW_SECS: i64 = 2_000_000_000;
    const NOW_MS: i64 = 2_000_000_000_000;

    /// `2033-05-18T03` contains `NOW_SECS` (03:33 UTC) — the open hour.
    const OPEN_HOUR: &str = "2033-05-18T03";
    /// `2033-05-18T02` ended at 03:00 — the just-closed hour.
    const JUST_CLOSED: &str = "2033-05-18T02";

    const H1: &str = "2026-01-01T00";
    const H2: &str = "2026-01-01T01";
    const H4: &str = "2026-01-01T04";

    const fn settings() -> SchedulerSettings {
        SchedulerSettings {
            dispatch: Dispatch::from_max_concurrent_jobs(10),
            max_concurrent_macos_jobs: 16,
            dispatch_min_age_minutes: 5,
            stale_dispatch_minutes: 60,
            max_queue_pending: 2_000,
            human_daily_task_budget: 2_000,
            min_dispatch_value: 0,
        }
    }

    fn hour(raw: &str) -> DemandFeedHour {
        DemandFeedHour::parse(raw).expect("test hour")
    }

    fn entry(crate_name: &str, demand: u64) -> SchedulerDemandEntry {
        SchedulerDemandEntry {
            crate_name: crate_name.parse().expect("demand crate"),
            version: "1.0.0".parse().expect("demand version"),
            features_json: FeaturesJson::default(),
            target: "x86_64-unknown-linux-gnu".parse().expect("demand target"),
            rustc_version: "1.85.0".parse().expect("demand rustc"),
            demand,
        }
    }

    /// An entry padded with `features` full-length feature names — the
    /// vehicle the byte-bound test grows the encoded envelope with.
    fn fat_entry(crate_name: &str, features: usize) -> SchedulerDemandEntry {
        SchedulerDemandEntry {
            features_json: FeaturesJson::canonicalize(
                (0..features).map(|i| format!("feat{i:0124}")).collect(),
            )
            .expect("features"),
            ..entry(crate_name, 1)
        }
    }

    fn page(
        hour: &DemandFeedHour,
        generation: i64,
        page_no: u32,
        entries: Vec<SchedulerDemandEntry>,
    ) -> DemandFeedPageRequest {
        DemandFeedPageRequest {
            hour: hour.clone(),
            generation,
            page_no,
            entries,
        }
    }

    /// The ordered page-hash manifest a materializer declares at
    /// `complete` — the canonical [`demand_feed_manifest`] over the
    /// same serialized page bytes the DO stages.
    fn manifest(pages: &[Vec<SchedulerDemandEntry>]) -> String {
        let page_hashes: Vec<blake3::Hash> = pages
            .iter()
            .map(|entries| demand_feed_page_hash(entries).expect("entries serialize"))
            .collect();
        demand_feed_manifest(&page_hashes)
            .map(|hash| hash.to_hex().to_string())
            .unwrap_or_default()
    }

    fn complete(
        hour: &DemandFeedHour,
        generation: i64,
        pages: &[Vec<SchedulerDemandEntry>],
    ) -> DemandFeedCompleteRequest {
        DemandFeedCompleteRequest {
            hour: hour.clone(),
            generation,
            page_count: u32::try_from(pages.len()).expect("test page count"),
            entry_count: u64::try_from(pages.iter().map(Vec::len).sum::<usize>())
                .expect("test entry count"),
            manifest_hash: manifest(pages),
        }
    }

    /// Open `hour`, stage `pages` in order, and freeze it.
    async fn stage_and_freeze(
        db: &skyzen_services::durable::DurableDb,
        hour: &DemandFeedHour,
        pages: &[Vec<SchedulerDemandEntry>],
    ) -> i64 {
        let generation = feed_begin(db, hour, NOW_SECS)
            .await
            .expect("begin")
            .generation;
        for (index, entries) in pages.iter().enumerate() {
            feed_page(
                db,
                &page(
                    hour,
                    generation,
                    u32::try_from(index).expect("test page index"),
                    entries.clone(),
                ),
                NOW_SECS,
            )
            .await
            .expect("page");
        }
        feed_complete(db, &complete(hour, generation, pages), NOW_SECS)
            .await
            .expect("complete");
        generation
    }

    /// Deliver every page of a frozen hour plus the terminal call.
    /// A real queued task whose demand the h4 page would fold into —
    /// the refused apply must leave its demand/value/batch and every
    /// acknowledgment untouched, not merely no-op on an absent
    /// identity.
    async fn enqueue_alpha(db: &skyzen_services::durable::DurableDb) {
        super::queue::enqueue(
            db,
            &[EnqueueRequest {
                crate_name: "alpha".parse().expect("alpha crate"),
                version: "1.0.0".parse().expect("alpha version"),
                features_json: FeaturesJson::default(),
                target: "x86_64-unknown-linux-gnu".parse().expect("target"),
                rustc_version: "1.85.0".parse().expect("rustc"),
                downloads: 0,
                source: EnqueueSource::CacheMiss,
                depends_on: Vec::new(),
                preserve_lockfile: false,
                host_side: false,
            }],
            &settings(),
        )
        .await
        .expect("enqueue alpha");
    }

    /// Alpha's queued demand and value as text — a verbatim snapshot
    /// the refusal must leave byte-identical and the canonical
    /// delivery must fold exactly once.
    async fn alpha_state(db: &skyzen_services::durable::DurableDb) -> serde_json::Value {
        db.query(
            "SELECT CAST(demand AS TEXT) AS demand, CAST(value AS TEXT) AS value \
             FROM queue WHERE crate_name = 'alpha'",
        )
        .fetch_one::<serde_json::Value>()
        .await
        .expect("read alpha state")
    }

    /// No page of `hour` applied and no ledger batch of it exists.
    async fn feed_writes_absent(
        db: &skyzen_services::durable::DurableDb,
        hour: &DemandFeedHour,
    ) -> bool {
        let applied = db
            .query(
                "SELECT COUNT(*) FROM demand_feed_pages \
                 WHERE hour = ? AND applied = 1",
            )
            .bind(hour.as_str())
            .fetch_scalar::<i64>()
            .await
            .expect("count applied");
        let batches = db
            .query(
                "SELECT COUNT(*) FROM demand_batches \
                 WHERE batch_id LIKE 'demand-feed/' || ? || '/%'",
            )
            .bind(hour.as_str())
            .fetch_scalar::<i64>()
            .await
            .expect("count batches");
        let contributions = db
            .query(
                "SELECT COUNT(*) FROM demand_contributions \
                 WHERE batch_id LIKE 'demand-feed/' || ? || '/%'",
            )
            .bind(hour.as_str())
            .fetch_scalar::<i64>()
            .await
            .expect("count contributions");
        applied == 0 && batches == 0 && contributions == 0
    }

    /// Complete and deliver the canonical chain h2 → h3 → h3b → h4 —
    /// each stage advancing the watermark to the expected hour.
    async fn finish_predecessors(
        db: &skyzen_services::durable::DurableDb,
        h2: &DemandFeedHour,
        g2: i64,
        h3: &DemandFeedHour,
        h4: &DemandFeedHour,
    ) {
        feed_complete(db, &complete(h2, g2, &[]), NOW_SECS)
            .await
            .expect("complete h2");
        deliver_all(db, h2, 0).await;
        assert_eq!(watermark(db).await.as_deref(), Some(H2));
        stage_and_freeze(db, h3, &[]).await;
        deliver_all(db, h3, 0).await;
        assert_eq!(watermark(db).await.as_deref(), Some("2026-01-01T02"));
        let h3b = hour("2026-01-01T03");
        stage_and_freeze(db, &h3b, &[]).await;
        deliver_all(db, &h3b, 0).await;
        assert_eq!(watermark(db).await.as_deref(), Some("2026-01-01T03"));
        deliver_all(db, h4, 1).await;
    }

    /// Stage a complete hour under an inserted header — exercises the
    /// deliver-side guards on pre-existing out-of-order data that a
    /// refused begin cannot produce.
    async fn seed_complete_hour(
        db: &skyzen_services::durable::DurableDb,
        hour: &DemandFeedHour,
        generation: i64,
        pages: &[Vec<SchedulerDemandEntry>],
    ) {
        db.query(
            "INSERT INTO demand_feed_hours (hour, generation, state) \
             VALUES (?, ?, 'staging')",
        )
        .bind(hour.as_str())
        .bind(generation)
        .execute()
        .await
        .expect("insert hour");
        for (i, entries) in pages.iter().enumerate() {
            feed_page(
                db,
                &DemandFeedPageRequest {
                    hour: hour.clone(),
                    generation,
                    page_no: u32::try_from(i).expect("page index"),
                    entries: entries.clone(),
                },
                NOW_SECS,
            )
            .await
            .expect("stage page");
        }
        feed_complete(db, &complete(hour, generation, pages), NOW_SECS)
            .await
            .expect("freeze hour");
    }

    async fn deliver_all(
        db: &skyzen_services::durable::DurableDb,
        hour: &DemandFeedHour,
        pages: u32,
    ) {
        for page_no in 0..pages {
            let (report, _) = feed_deliver(db, hour, NOW_MS, &settings())
                .await
                .expect("deliver");
            assert_eq!(report.delivered_page, Some(page_no));
            assert_eq!(report.state, "complete");
        }
        let (report, _) = feed_deliver(db, hour, NOW_MS, &settings())
            .await
            .expect("terminal deliver");
        assert_eq!(report.state, "delivered");
        assert_eq!(report.delivered_page, None);
    }

    async fn watermark(db: &skyzen_services::durable::DurableDb) -> Option<String> {
        db.query("SELECT value FROM settings WHERE key = 'demand_feed_watermark'")
            .fetch_scalar_optional::<String>()
            .await
            .expect("watermark")
    }

    async fn applied_pages(db: &skyzen_services::durable::DurableDb, hour: &str) -> i64 {
        db.query("SELECT applied_pages FROM demand_feed_hours WHERE hour = ?")
            .bind(hour)
            .fetch_scalar::<i64>()
            .await
            .expect("applied_pages")
    }

    /// A rotated attempt freezes only its own generation: the stale
    /// materializer's pages and completion refuse by generation CAS,
    /// and the frozen hour delivers exactly the new attempt's ordered
    /// pages.
    #[tokio::test]
    async fn restarted_attempt_cannot_mix_pages() {
        let db = memory_db().await.expect("memory db");
        let h = hour(H1);
        let pages_a = vec![vec![entry("alpha", 1)]];
        let g1 = feed_begin(&db, &h, NOW_SECS)
            .await
            .expect("begin a")
            .generation;
        feed_page(&db, &page(&h, g1, 0, pages_a[0].clone()), NOW_SECS)
            .await
            .expect("a page 0");
        // Materializer B begins — a restart, not a merge.
        let g2 = feed_begin(&db, &h, NOW_SECS)
            .await
            .expect("begin b")
            .generation;
        assert_ne!(g1, g2, "a resumed begin must rotate the generation");
        // A's stale requests fail on the generation CAS.
        feed_page(&db, &page(&h, g1, 1, vec![entry("beta", 1)]), NOW_SECS)
            .await
            .expect_err("stale generation page");
        feed_complete(&db, &complete(&h, g1, &pages_a), NOW_SECS)
            .await
            .expect_err("stale generation complete");
        // B freezes its own two pages.
        let pages_b = vec![vec![entry("gamma", 1)], vec![entry("delta", 1)]];
        feed_page(&db, &page(&h, g2, 0, pages_b[0].clone()), NOW_SECS)
            .await
            .expect("b page 0");
        feed_page(&db, &page(&h, g2, 1, pages_b[1].clone()), NOW_SECS)
            .await
            .expect("b page 1");
        feed_complete(&db, &complete(&h, g2, &pages_b), NOW_SECS)
            .await
            .expect("b complete");
        deliver_all(&db, &h, 2).await;
        // The abandoned generation's staged row retired — nothing of
        // attempt A survives or applies.
        let stale: i64 = db
            .query("SELECT COUNT(*) FROM demand_feed_pages WHERE generation != ?")
            .bind(g2)
            .fetch_scalar::<i64>()
            .await
            .expect("stale pages");
        assert_eq!(stale, 0, "obsolete generation payloads retired");
    }

    /// Same-page replay is a no-op only byte-for-byte; changed bytes
    /// on a staged page refuse — staged input is immutable.
    #[tokio::test]
    async fn staged_page_replays_identically_and_refuses_change() {
        let db = memory_db().await.expect("memory db");
        let h = hour(H1);
        let g = feed_begin(&db, &h, NOW_SECS)
            .await
            .expect("begin")
            .generation;
        let entries = vec![entry("alpha", 1)];
        feed_page(&db, &page(&h, g, 0, entries.clone()), NOW_SECS)
            .await
            .expect("stage");
        feed_page(&db, &page(&h, g, 0, entries), NOW_SECS)
            .await
            .expect("identical replay is a no-op");
        feed_page(&db, &page(&h, g, 0, vec![entry("omega", 2)]), NOW_SECS)
            .await
            .expect_err("changed payload on a staged page refuses");
        // A skipped page can never slot in ahead of the sequence.
        feed_page(&db, &page(&h, g, 2, vec![entry("late", 1)]), NOW_SECS)
            .await
            .expect_err("out-of-order page refuses");
    }

    /// The completion barrier refuses while staging is incomplete or
    /// the declared manifest does not match the staged chain — the
    /// hour stays undeliverable.
    #[tokio::test]
    async fn freeze_requires_full_manifest() {
        let db = memory_db().await.expect("memory db");
        let h = hour(H1);
        let pages = vec![vec![entry("alpha", 1)], vec![entry("beta", 1)]];
        let g = feed_begin(&db, &h, NOW_SECS)
            .await
            .expect("begin")
            .generation;
        feed_page(&db, &page(&h, g, 0, pages[0].clone()), NOW_SECS)
            .await
            .expect("page 0");
        // Page 1 never staged: every freeze attempt refuses, the hour
        // is undeliverable.
        feed_complete(&db, &complete(&h, g, &pages), NOW_SECS)
            .await
            .expect_err("missing page refuses completion");
        feed_deliver(&db, &h, NOW_MS, &settings())
            .await
            .expect_err("staging hour never delivers");
        // A forged manifest refuses too.
        let mut forged = complete(&h, g, &pages[..1]);
        forged.manifest_hash = "0".repeat(64);
        feed_complete(&db, &forged, NOW_SECS)
            .await
            .expect_err("wrong manifest refuses");
        let mut wrong_count = complete(&h, g, &pages[..1]);
        wrong_count.entry_count += 1;
        feed_complete(&db, &wrong_count, NOW_SECS)
            .await
            .expect_err("wrong entry total refuses");
        // The declared manifest of the staged set accepts.
        feed_complete(&db, &complete(&h, g, &pages[..1]), NOW_SECS)
            .await
            .expect("manifest of staged set completes");
    }

    /// A delivered page's ack lands exactly once in the header: a
    /// retried `applied = 1` mark (a lost write-result replay) does
    /// not recount, and a re-sent page batch replays through the
    /// demand ledger as a zero-write accepted batch.
    #[tokio::test]
    async fn acknowledged_page_counts_once_and_replays_verbatim() {
        let db = memory_db().await.expect("memory db");
        let h = hour(H1);
        let pages = vec![vec![entry("alpha", 1)], vec![entry("beta", 1)]];
        let g = stage_and_freeze(&db, &h, &pages).await;
        let (first, _) = feed_deliver(&db, &h, NOW_MS, &settings())
            .await
            .expect("deliver page 0");
        assert_eq!(first.delivered_page, Some(0));
        assert!(first.applied, "first delivery accepts the batch");
        assert_eq!(applied_pages(&db, H1).await, 1);
        // A retried mark on the already-applied row: the trigger only
        // counts the 0 → 1 transition, never the 1 → 1 rewrite.
        db.query(
            "UPDATE demand_feed_pages SET applied = 1 \
             WHERE hour = ? AND generation = ? AND page_no = 0",
        )
        .bind(H1)
        .bind(g)
        .execute()
        .await
        .expect("duplicate mark");
        assert_eq!(
            applied_pages(&db, H1).await,
            1,
            "duplicate ack never doubles"
        );
        // A lost page-mark replay delivers the same frozen bytes: the
        // ledger answers the same batch id as an exact replay, writing
        // nothing.
        db.query(
            "UPDATE demand_feed_pages SET applied = 0 \
             WHERE hour = ? AND generation = ? AND page_no = 0",
        )
        .bind(H1)
        .bind(g)
        .execute()
        .await
        .expect("reset mark");
        db.query("UPDATE demand_feed_hours SET applied_pages = applied_pages - 1 WHERE hour = ?")
            .bind(H1)
            .execute()
            .await
            .expect("reset counter");
        let (replay, _) = feed_deliver(&db, &h, NOW_MS, &settings())
            .await
            .expect("lost-ack redelivery");
        assert_eq!(replay.delivered_page, Some(0));
        assert!(!replay.applied, "same bytes replay as the accepted batch");
        assert_eq!(applied_pages(&db, H1).await, 1);
        let (second, _) = feed_deliver(&db, &h, NOW_MS, &settings())
            .await
            .expect("deliver page 1");
        assert_eq!(second.delivered_page, Some(1));
        let (terminal, _) = feed_deliver(&db, &h, NOW_MS, &settings())
            .await
            .expect("terminal");
        assert_eq!(terminal.state, "delivered");
    }

    /// The watermark moves only to the canonical next hour — a
    /// finished hour cannot deliver past an unfinished predecessor,
    /// cannot leap over a missing hour, and never moves backwards.
    #[tokio::test]
    async fn watermark_requires_canonical_succession() {
        let db = memory_db().await.expect("memory db");
        let h1 = hour(H1);
        let h2 = hour(H2);
        let h4 = hour(H4);
        let page1 = vec![vec![entry("alpha", 1)]];
        // h2 finishes while h1 is still staging: delivery refuses
        // before a single page applies — the cursor may not pass h1,
        // and no demand may land out of order.
        let g1 = feed_begin(&db, &h1, NOW_SECS)
            .await
            .expect("begin h1")
            .generation;
        stage_and_freeze(&db, &h2, &page1).await;
        feed_deliver(&db, &h2, NOW_MS, &settings())
            .await
            .expect_err("unfinished predecessor blocks delivery");
        assert_eq!(watermark(&db).await, None);
        // h1 delivers first — the bootstrap hour — then h2 follows
        // canonically. h1 completes as the empty hour it staged.
        feed_complete(&db, &complete(&h1, g1, &[]), NOW_SECS)
            .await
            .expect("complete empty h1");
        deliver_all(&db, &h1, 0).await;
        assert_eq!(watermark(&db).await.as_deref(), Some(H1));
        let (report, _) = feed_deliver(&db, &h2, NOW_MS, &settings())
            .await
            .expect("deliver h2 page");
        assert_eq!(report.delivered_page, Some(0));
        let (terminal, _) = feed_deliver(&db, &h2, NOW_MS, &settings())
            .await
            .expect("h2 terminal");
        assert_eq!(terminal.state, "delivered");
        assert_eq!(watermark(&db).await.as_deref(), Some(H2));
        // h4 completes with no unfinished headers below, but the
        // watermark is at h2 — its begin refuses as non-canonical,
        // so seed the row directly to prove the terminal guard still
        // cannot leap over missing h3 either.
        feed_begin(&db, &h4, NOW_SECS)
            .await
            .expect_err("non-canonical begin refuses");
        seed_complete_hour(&db, &h4, 7, &page1).await;
        // The deliver-side canonical check refuses before the first
        // page applies — no demand or acknowledgment may land.
        feed_deliver(&db, &h4, NOW_MS, &settings())
            .await
            .expect_err("non-canonical delivery refuses before demand");
        let applied = db
            .query("SELECT applied_pages FROM demand_feed_hours WHERE hour = ?")
            .bind(h4.as_str())
            .fetch_scalar::<i64>()
            .await
            .expect("h4 applied count");
        assert_eq!(applied, 0, "non-canonical delivery applied a page");
        assert_eq!(watermark(&db).await.as_deref(), Some(H2));
        // An hour at or below the cursor can never re-materialize.
        feed_begin(&db, &h1, NOW_SECS)
            .await
            .expect_err("begin below the watermark refuses");
        feed_begin(&db, &h2, NOW_SECS)
            .await
            .expect_err("begin at the watermark refuses");
    }

    /// Two nonempty out-of-order hours: a begin that is not the
    /// watermark's successor refuses before staging a single page —
    /// no frozen wedge blocks the genuine successor, and a complete
    /// hour refuses to deliver while any older hour is unfinished, so
    /// no demand mutates the ledger out of order.
    #[tokio::test]
    async fn out_of_order_hours_never_mutate() {
        let db = memory_db().await.expect("memory db");
        let h1 = hour(H1);
        let h2 = hour(H2);
        let h3 = hour("2026-01-01T02");
        let h4 = hour(H4);
        let page = vec![vec![entry("alpha", 1)]];
        // A real queued task the h4 page's demand would fold into —
        // the refused apply must leave its demand/value/batch and
        // every acknowledgment untouched, not merely no-op on an
        // absent identity.
        enqueue_alpha(&db).await;
        // The reachable pre-staged state — no synthetic header INSERT:
        // h4 stages and freezes during bootstrap while NO watermark
        // exists, alongside the genuinely earlier h1.
        stage_and_freeze(&db, &h1, &page).await;
        stage_and_freeze(&db, &h4, &page).await;
        deliver_all(&db, &h1, 1).await;
        assert_eq!(watermark(&db).await.as_deref(), Some(H1));
        let before = alpha_state(&db).await;
        // The leap: h3 is not the canonical successor — begin refuses
        // before inserting a header or staging a page.
        feed_begin(&db, &h3, NOW_SECS)
            .await
            .expect_err("begin past the canonical successor refuses");
        assert!(
            read_hour(&db, h3.as_str())
                .await
                .expect("read h3")
                .is_none(),
            "refused begin left a header row"
        );
        // The missing-header case the indexed probe cannot see: h4
        // is complete, yet h2/h3 have NO header rows — the
        // unfinished-index probe finds nothing and alone would let
        // demand land. The canonical-successor guard refuses before
        // any page/demand/ack write.
        feed_deliver(&db, &h4, NOW_MS, &settings())
            .await
            .expect_err("non-canonical delivery refuses before writes");
        assert!(
            feed_writes_absent(&db, &h4).await,
            "refused delivery applied a page or wrote a ledger batch"
        );
        assert_eq!(
            alpha_state(&db).await,
            before,
            "refused delivery moved real queued demand/value"
        );
        // The missing predecessors then materialize and deliver in
        // order; the frozen original page succeeds exactly once.
        let g2 = feed_begin(&db, &h2, NOW_SECS)
            .await
            .expect("begin canonical h2")
            .generation;
        finish_predecessors(&db, &h2, g2, &h3, &h4).await;
        assert_eq!(watermark(&db).await.as_deref(), Some(H4));
        // The frozen original page applied exactly once: alpha's
        // demand gained the page's delta once — the staged
        // contribution set retires at acceptance, so the batch
        // header and the folded value are the record — and a
        // delivered replay stays the early no-op.
        let accepted = db
            .query(
                "SELECT COUNT(*) FROM demand_batches \
                 WHERE batch_id = 'demand-feed/2026-01-01T04/0' AND state = 'accepted'",
            )
            .fetch_scalar::<i64>()
            .await
            .expect("count h4 batch");
        assert_eq!(accepted, 1, "h4 page did not accept exactly once");
        let after = alpha_state(&db).await;
        let folded: i64 = after["demand"]
            .as_str()
            .and_then(|value| value.parse().ok())
            .expect("alpha demand parses");
        let was: i64 = before["demand"]
            .as_str()
            .and_then(|value| value.parse().ok())
            .expect("alpha demand parses");
        assert_eq!(folded, was + 1, "h4 page's demand did not fold once");
        let (replay, _) = feed_deliver(&db, &h4, NOW_MS, &settings())
            .await
            .expect("delivered replay");
        assert!(!replay.applied, "delivered replay reapplied");
        assert_eq!(
            alpha_state(&db).await,
            after,
            "delivered replay moved demand"
        );
    }

    /// `cleanup` retires dead page rows in bounded chunks: obsolete
    /// generations and a delivered hour's payloads — each call a
    /// constant statement cost, never a scan proportional to history.
    #[tokio::test]
    async fn cleanup_retires_in_bounded_chunks() {
        let (db, log) = counting_memory_db().await.expect("memory db");
        let h = hour(H1);
        let g = feed_begin(&db, &h, NOW_SECS)
            .await
            .expect("begin")
            .generation;
        feed_complete(&db, &complete(&h, g, &[]), NOW_SECS)
            .await
            .expect("complete empty h1");
        // 300 staged rows of an obsolete generation: more than one
        // retirement chunk.
        let obsolete = g - 1;
        for page_no in 0..300_i64 {
            db.query(
                "INSERT INTO demand_feed_pages \
                 (hour, generation, page_no, entry_count, page_hash, chain_hash, payload, applied) \
                 VALUES (?, ?, ?, 1, 'h', 'c', '[]', 1)",
            )
            .bind(H1)
            .bind(obsolete)
            .bind(page_no)
            .execute()
            .await
            .expect("plant obsolete page");
        }
        let first = feed_cleanup(&db, &h, NOW_SECS)
            .await
            .expect("cleanup chunk");
        assert_eq!(first.retired, 256);
        assert!(first.remaining);
        let second = feed_cleanup(&db, &h, NOW_SECS).await.expect("cleanup rest");
        assert_eq!(second.retired, 44);
        assert!(!second.remaining);
        // Each bounded call costs a constant few statements regardless
        // of the rows it retires.
        log.lock().expect("log").clear();
        let third = feed_cleanup(&db, &h, NOW_SECS)
            .await
            .expect("cleanup empty");
        assert_eq!(third.retired, 0);
        assert!(!third.remaining);
        assert!(
            log.lock().expect("log").len() <= 4,
            "a cleanup call stays a constant few statements"
        );
        // A delivered hour's payloads retire the same bounded way.
        // Finish h1 (empty) first so the watermark can reach h2.
        deliver_all(&db, &h, 0).await;
        let h2 = hour(H2);
        stage_and_freeze(&db, &h2, &[vec![entry("a", 1)], vec![entry("b", 1)]]).await;
        deliver_all(&db, &h2, 2).await;
        let report = feed_cleanup(&db, &h2, NOW_SECS)
            .await
            .expect("delivered cleanup");
        assert_eq!(report.retired, 2);
        assert!(!report.remaining);
        assert_eq!(
            db.query("SELECT COUNT(*) FROM demand_feed_pages WHERE hour = ?")
                .bind(H2)
                .fetch_scalar::<i64>()
                .await
                .expect("remaining pages"),
            0
        );
    }

    /// Cleanup never visits live pages: an in-flight attempt staging
    /// hundreds of current-generation pages with nothing obsolete
    /// reports no retirable rows, and a mixed hour retires only the
    /// obsolete-generation range while every current payload — and its
    /// staged counters — survive intact through freeze and replay.
    #[tokio::test]
    async fn cleanup_leaves_current_generation_untouched() {
        let db = memory_db().await.expect("memory db");
        let h = hour(H4);
        // The first attempt stages 302 real pages — more than one
        // retire chunk once its generation is abandoned.
        let g1 = feed_begin(&db, &h, NOW_SECS)
            .await
            .expect("begin")
            .generation;
        for index in 0..302_u32 {
            feed_page(
                &db,
                &page(&h, g1, index, vec![entry("old", u64::from(index))]),
                NOW_SECS,
            )
            .await
            .expect("old page");
        }
        // Rotation retires one chunk; 46 obsolete rows remain.
        let rotated = feed_begin(&db, &h, NOW_SECS).await.expect("rotate");
        assert!(rotated.stale_pages_pending);
        let g = rotated.generation;
        // The live attempt stages 300 pages of its own generation.
        let entries: Vec<Vec<SchedulerDemandEntry>> =
            (0..300).map(|n| vec![entry("bulk", n)]).collect();
        for (index, page_entries) in entries.iter().enumerate() {
            feed_page(
                &db,
                &page(
                    &h,
                    g,
                    u32::try_from(index).expect("test page index"),
                    page_entries.clone(),
                ),
                NOW_SECS,
            )
            .await
            .expect("page");
        }
        // Bounded calls drain the obsolete range; the live 300 are
        // never candidates, so the empty probe stays a constant few
        // statements however many current pages exist.
        let first = feed_cleanup(&db, &h, NOW_SECS)
            .await
            .expect("cleanup obsolete");
        assert_eq!(first.retired, 46);
        assert!(!first.remaining);
        let second = feed_cleanup(&db, &h, NOW_SECS)
            .await
            .expect("cleanup empty");
        assert_eq!(second.retired, 0);
        assert!(!second.remaining);
        // All 300 current payloads survived: identical replay no-ops,
        // counters intact, and the attempt freezes on its own manifest.
        feed_page(&db, &page(&h, g, 0, entries[0].clone()), NOW_SECS)
            .await
            .expect("replay");
        feed_complete(&db, &complete(&h, g, &entries), NOW_SECS)
            .await
            .expect("complete");
        assert_eq!(
            db.query("SELECT COUNT(*) FROM demand_feed_pages WHERE hour = ? AND generation = ?")
                .bind(H4)
                .bind(g)
                .fetch_scalar::<i64>()
                .await
                .expect("current pages"),
            300
        );
    }

    /// Real calendar and closed-window validation: impossible dates
    /// and the still-open hour refuse before any write or query.
    #[tokio::test]
    async fn hour_validation_uses_the_real_calendar() {
        assert!(DemandFeedHour::parse("2025-02-31T00").is_err());
        assert!(DemandFeedHour::parse("2023-02-29T10").is_err());
        assert!(DemandFeedHour::parse("2024-02-29T10").is_ok());
        assert!(DemandFeedHour::parse("2026-1-1T00").is_err());
        assert!(DemandFeedHour::parse("2026-01-01T0030").is_err());
        assert!(DemandFeedHour::parse("2026-13-01T00").is_err());
        // Calendar shifts stay inside the canonical domain: ordinary
        // neighbors round-trip, and the representable edges refuse
        // gracefully instead of panicking or storing a malformed key.
        assert_eq!(
            hour("2024-12-31T23").next().expect("next").as_str(),
            "2025-01-01T00"
        );
        assert_eq!(
            hour("2024-02-29T23").prev().expect("prev").as_str(),
            "2024-02-29T22"
        );
        let first = DemandFeedHour::parse("0000-01-01T00").expect("first hour");
        assert!(first.prev().is_err());
        assert!(first.next().is_ok());
        let last = DemandFeedHour::parse("9999-12-31T23").expect("last hour");
        assert!(last.next().is_err());
        // The last representable hour's end is unrepresentable, so
        // closure is refused gracefully rather than panicking on the
        // unchecked construction the type used to allow.
        assert!(last.ensure_closed(i64::MAX).is_err());
        // The current open hour cannot be fed.
        assert!(DemandFeedHour::parse("2033-05-18T03").is_ok());
        let db = memory_db().await.expect("memory db");
        feed_begin(&db, &hour(OPEN_HOUR), NOW_SECS)
            .await
            .expect_err("the open hour refuses to stage");
        feed_begin(&db, &hour(JUST_CLOSED), NOW_SECS)
            .await
            .expect("the just-closed hour stages");
    }

    /// Both page bounds are real: >256 entries refuse, an empty page
    /// refuses, and the whole encoded envelope over 512 KiB refuses
    /// without staging anything — a large feature set means more
    /// pages, never a truncated request.
    #[tokio::test]
    async fn page_envelope_respects_both_bounds() {
        let db = memory_db().await.expect("memory db");
        let h = hour(H1);
        let g = feed_begin(&db, &h, NOW_SECS)
            .await
            .expect("begin")
            .generation;
        feed_page(&db, &page(&h, g, 0, Vec::new()), NOW_SECS)
            .await
            .expect_err("empty page refuses");
        let too_many: Vec<SchedulerDemandEntry> =
            (0..257).map(|i| entry(&format!("c{i:04}"), 1)).collect();
        feed_page(&db, &page(&h, g, 0, too_many), NOW_SECS)
            .await
            .expect_err("257 entries refuse");
        // One entry carrying ~530 KiB of feature names: the whole
        // encoded request crosses the byte bound.
        feed_page(
            &db,
            &page(&h, g, 0, vec![fat_entry("fat", 4_100)]),
            NOW_SECS,
        )
        .await
        .expect_err("oversized envelope refuses");
        assert_eq!(
            db.query("SELECT staged_pages FROM demand_feed_hours WHERE hour = ?")
                .bind(H1)
                .fetch_scalar::<i64>()
                .await
                .expect("staged_pages"),
            0,
            "a refused page stages nothing"
        );
        // 256 small entries — the in-bound page — stages fine.
        let in_bound: Vec<SchedulerDemandEntry> =
            (0..256).map(|i| entry(&format!("d{i:04}"), 1)).collect();
        feed_page(&db, &page(&h, g, 0, in_bound), NOW_SECS)
            .await
            .expect("256 entries stage");
    }

    /// A frozen hour's input is final: `begin` refuses, and a
    /// fully-delivered hour answers `deliver` as a no-op without
    /// touching the retained payloads.
    #[tokio::test]
    async fn frozen_input_never_rematerializes() {
        let db = memory_db().await.expect("memory db");
        let h = hour(H1);
        stage_and_freeze(&db, &h, &[vec![entry("alpha", 1)]]).await;
        feed_begin(&db, &h, NOW_SECS)
            .await
            .expect_err("a complete hour never re-materializes");
        deliver_all(&db, &h, 1).await;
        // Delivered hours replay as no-ops — and still arm the shared
        // alarm plan, the existing-cost route behavior.
        let (again, _) = feed_deliver(&db, &h, NOW_MS, &settings())
            .await
            .expect("delivered hour no-ops");
        assert_eq!(again.state, "delivered");
        assert_eq!(again.delivered_page, None);
        assert_eq!(watermark(&db).await.as_deref(), Some(H1));
    }

    /// A zero-entry hour completes and delivers with zero demand
    /// calls — the empty-hour contract.
    #[tokio::test]
    async fn empty_hour_completes_without_pages() {
        let db = memory_db().await.expect("memory db");
        let h = hour(H1);
        let g = feed_begin(&db, &h, NOW_SECS)
            .await
            .expect("begin")
            .generation;
        feed_complete(
            &db,
            &DemandFeedCompleteRequest {
                hour: h.clone(),
                generation: g,
                page_count: 0,
                entry_count: 0,
                manifest_hash: String::new(),
            },
            NOW_SECS,
        )
        .await
        .expect("empty hour completes");
        let (report, _) = feed_deliver(&db, &h, NOW_MS, &settings())
            .await
            .expect("empty hour delivers");
        assert_eq!(report.state, "delivered");
        assert_eq!(report.delivered_page, None);
        assert_eq!(watermark(&db).await.as_deref(), Some(H1));
    }
}
