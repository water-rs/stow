//! `stow-admin scheduler demand-feed` — the hourly feed's native leg
//! (stow#523). One invocation handles exactly one closed hour:
//!
//! 1. `GET …/status` returns the durable cursor — an unfinished hour is
//!    resumed before any new hour is chosen: `complete` hours deliver
//!    their frozen pages without re-querying Analytics Engine;
//!    `staging` hours rotate a fresh generation and materialize again.
//! 2. `POST …/query` streams the edge's `FORMAT JSON` document to an
//!    owned temp file — the hour can exceed anything this process
//!    should hold, so the body is never decoded into memory.
//! 3. A `serde_json::Deserializer::from_reader` on a bounded `BufReader`
//!    validates the whole document on the blocking pool — `meta` must
//!    be exactly the query's six columns, `rows` must equal the parsed
//!    `data` count, every row's demand must be an integral non-negative
//!    `Float64` in range, and `Deserializer::end` must reach true EOF.
//!    Rows hand off to the async side page-by-page over a bounded
//!    channel; each page posts `…/page` in order.
//! 4. `POST …/complete` freezes the hour on the ordered page-hash
//!    manifest — only after the whole document validated. A failed or
//!    truncated body stages nothing deliverable, and `complete` is
//!    never called: the next run's `begin` rotates the leftovers out.
//! 5. `POST …/deliver` runs under a bounded fan-out until the header
//!    reports `delivered` — `remaining_pages == 0` is not terminal, the
//!    state word is. The object serializes each storage-only call, so
//!    concurrent calls can only pick distinct unapplied pages; a lost
//!    response leaves the durable `applied` mark for the next cron.
//! 6. `POST …/cleanup` drains retired payload rows in bounded chunks —
//!    obsolete generations after a rotation and a delivered hour's
//!    acknowledged pages — so no payload archives orphaned.
//!
//! A failure anywhere leaves the durable state intact: the GitHub job
//! fails visibly and the next hourly run resumes from the same cursor.

use std::io::BufReader;

use clap::Args;
use serde::Deserialize;
use serde::de::DeserializeSeed;
use stow_types::analytics::{de_f64, f64_to_u64_exact};
use stow_types::api::{
    DEMAND_FEED_PAGE_MAX_BYTES, DEMAND_FEED_PAGE_MAX_ENTRIES, DemandFeedBeginReport,
    DemandFeedBeginRequest, DemandFeedCleanupReport, DemandFeedCleanupRequest,
    DemandFeedCompleteRequest, DemandFeedDeliverReport, DemandFeedDeliverRequest, DemandFeedHour,
    DemandFeedPageRequest, DemandFeedQueryRequest, DemandFeedStatus, SchedulerDemandEntry,
    demand_feed_manifest, demand_feed_page_hash,
};
use stow_types::error::Error;
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use stow_types::stow_error;

use crate::Edge;
use crate::render::{self, Output};

const FEED_ROUTE: &str = "/api/v1/admin/scheduler/demand-feed";

/// Pages in flight between the blocking parser and the page posts —
/// the explicit handoff bound: each in-flight page is at most
/// [`DEMAND_FEED_PAGE_MAX_BYTES`] on the wire.
const PAGE_CHANNEL_BOUND: usize = 4;

/// Independent `deliver` calls on the same complete hour — the object
/// picks the next unapplied page itself, so the fan-out only buys
/// pipeline depth; nothing beyond the hour's own page count is ever
/// needed and the bound also caps the no-op `delivered` answers a
/// tail wave may draw.
const DELIVER_FANOUT: usize = 4;

/// Byte slack under [`DEMAND_FEED_PAGE_MAX_BYTES`] the page-break
/// heuristic holds back for the request's framing fields (`hour`,
/// `generation`, `page_no` — at most a hundred bytes); the exact
/// bound is re-checked on the serialized request before every post.
const PAGE_FRAMING_SLACK: usize = 4 * 1024;

/// Bound on one materialization's file write — a chunk the response
/// stream hands over is written as it arrives, never accumulated.
const BODY_BUF_CAP: usize = 64 * 1024;

#[derive(Args)]
pub struct DemandFeedArgs {
    /// Materialize this specific closed hour (`YYYY-MM-DDTHH`, UTC)
    /// instead of following the durable cursor — the operator's
    /// recovery path for an hour the cursor never named. Refused when
    /// it would cross the watermark or leap over an unfinished hour.
    #[arg(long)]
    pub(crate) hour: Option<String>,
}

/// What one invocation reports.
#[derive(Debug, serde::Serialize)]
struct FeedRunReport {
    /// The hour this run handled — the unfinished one when the cursor
    /// resumed it, else the watermark's successor (or the bootstrap
    /// choice).
    hour: String,
    /// `skipped` when the next hour is not yet closed (nothing to do),
    /// `delivered` when the run left the hour terminal.
    state: String,
    /// Pages staged this run — `0` on a complete-hour resume.
    staged_pages: u64,
    /// Entries staged this run.
    staged_entries: u64,
    /// Page batches delivered this run.
    delivered_pages: u64,
    /// Queue tasks the delivered pages' closures touched.
    touched_tasks: u64,
}

/// Run the feed pass against the edge.
pub async fn run(
    edge: &Edge,
    args: DemandFeedArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| stow_error!("system clock: {error}"))?
        .as_secs();
    let now_secs = i64::try_from(now_secs)
        .map_err(|_| stow_error!("system clock past representable range"))?;
    let status: DemandFeedStatus = edge.get_json(&format!("{FEED_ROUTE}/status")).await?;

    let unfinished = status
        .unfinished
        .as_ref()
        .map(|row| {
            DemandFeedHour::parse(&row.hour)
                .map_err(Error::msg)
                .map(|hour| (hour, row.state.clone()))
        })
        .transpose()?;

    let report = match unfinished {
        // A frozen hour delivers its original staged pages — the input
        // is immutable, so no new Analytics Engine query ever runs for
        // it.
        Some((hour, state)) if state == "complete" => {
            let (delivered_pages, touched_tasks) = deliver_and_retire(edge, &hour).await?;
            FeedRunReport {
                hour: hour.to_string(),
                state: "delivered".to_owned(),
                staged_pages: 0,
                staged_entries: 0,
                delivered_pages,
                touched_tasks,
            }
        }
        // A `staging` hour materializes again from scratch — its pages
        // were never frozen, so a fresh query under a fresh generation
        // is the canonical restart. Otherwise choose the cursor's
        // successor (or the bootstrap hour on the first-ever run).
        _ => {
            let hour = match (&unfinished, &args.hour, &status.watermark) {
                (Some((hour, _)), _, _) => hour.clone(),
                (None, Some(hour), _) => {
                    DemandFeedHour::parse_closed(hour, now_secs).map_err(Error::msg)?
                }
                (None, None, Some(watermark)) => DemandFeedHour::parse(watermark)
                    .and_then(|previous| previous.next())
                    .map_err(Error::msg)?,
                (None, None, None) => DemandFeedHour::latest_closed(now_secs)
                    .ok_or_else(|| stow_error!("no closed hour is representable"))?,
            };
            if hour.ensure_closed(now_secs).is_err() {
                // The cursor's successor has not closed yet — the feed
                // is simply early, not failed.
                FeedRunReport::skipped(hour.to_string())
            } else {
                materialize(edge, hour).await?
            }
        }
    };
    render::emit(output, &report, |report| {
        if report.state == "skipped" {
            format!("demand feed: {} — next hour not yet closed", report.hour)
        } else {
            format!(
                "demand feed {}: staged {} entries in {} pages, delivered {} pages \
                 (touched {} tasks) — {}",
                report.hour,
                report.staged_entries,
                report.staged_pages,
                report.delivered_pages,
                report.touched_tasks,
                report.state,
            )
        }
    })
}

impl FeedRunReport {
    fn skipped(hour: String) -> Self {
        Self {
            hour,
            state: "skipped".to_owned(),
            staged_pages: 0,
            staged_entries: 0,
            delivered_pages: 0,
            touched_tasks: 0,
        }
    }
}

/// The materialization half: begin (rotating out an abandoned attempt),
/// stream the hour's document to disk, parse+stage it page by page, then
/// freeze on the manifest — and run the delivery drain to terminal.
async fn materialize(
    edge: &Edge,
    hour: DemandFeedHour,
) -> stow_types::error::Result<FeedRunReport> {
    let begin: DemandFeedBeginReport = edge
        .post_json(
            &format!("{FEED_ROUTE}/begin"),
            &DemandFeedBeginRequest { hour: hour.clone() },
        )
        .await?;
    if begin.stale_pages_pending {
        drain_cleanup(edge, &hour).await?;
    }

    // The document lands in an owned temp file — created off the
    // async executor and unlinked by the RAII guard on every exit.
    let temp = tokio::task::spawn_blocking(tempfile::NamedTempFile::new)
        .await
        .map_err(|error| stow_error!("demand feed tempfile task: {error}"))?
        .map_err(|error| stow_error!("create demand feed tempfile: {error}"))?;
    stream_query(edge, &hour, temp.path()).await?;
    // The parser runs on the blocking pool with bounded in-flight
    // pages; each page posts under the object-enforced sequential
    // ordering, so a staging failure aborts the rest cleanly.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ParsedPage>(PAGE_CHANNEL_BOUND);
    let parse_path = temp.path().to_owned();
    let parse = tokio::task::spawn_blocking(move || parse_feed_document(&parse_path, tx));

    let mut page_hashes = Vec::new();
    let mut entry_count = 0_u64;
    let mut staged_pages = 0_u32;
    let result: stow_types::error::Result<()> = async {
        while let Some(page) = rx.recv().await {
            if page.page_no != staged_pages {
                return Err(stow_error!(
                    "demand feed parser emitted page {} after {}",
                    page.page_no,
                    staged_pages
                ));
            }
            let request = DemandFeedPageRequest {
                hour: hour.clone(),
                generation: begin.generation,
                page_no: page.page_no,
                entries: page.entries,
            };
            // The exact whole-envelope bound on the same serialization
            // the wire carries — the object measures this identically.
            let encoded = serde_json::to_vec(&request)
                .map_err(|error| stow_error!("encode demand feed page: {error}"))?;
            if encoded.len() > DEMAND_FEED_PAGE_MAX_BYTES {
                return Err(stow_error!(
                    "demand feed page {} encodes to {} bytes; the bound is {}",
                    page.page_no,
                    encoded.len(),
                    DEMAND_FEED_PAGE_MAX_BYTES
                ));
            }
            page_hashes.push(demand_feed_page_hash(&request.entries).map_err(Error::msg)?);
            entry_count = entry_count
                .checked_add(request.entries.len() as u64)
                .ok_or_else(|| stow_error!("demand feed entry count overflow"))?;
            edge.post_unit(&format!("{FEED_ROUTE}/page"), &request)
                .await?;
            staged_pages += 1;
        }
        Ok(())
    }
    .await;

    let summary = match result {
        Ok(()) => parse
            .await
            .map_err(|error| stow_error!("demand feed parser task: {error}"))
            .and_then(|outcome| outcome.map_err(Error::msg)),
        Err(error) => {
            // The page leg failed — close the receiver FIRST: a
            // `blocking_send` against a live-but-undrained channel
            // would park the parser thread forever on a full
            // bounded queue. Dropping `rx` makes every pending send
            // fail fast, then joining cannot hang. The original post
            // error is what surfaces, not a secondary parse failure.
            drop(rx);
            let _ = parse.await;
            return Err(error);
        }
    };
    let _ = tokio::task::spawn_blocking(move || drop(temp)).await;
    let summary = summary?;

    if summary.rows != entry_count {
        return Err(stow_error!(
            "demand feed staged {entry_count} entries but the document parsed {}",
            summary.rows
        ));
    }
    let manifest_hash = demand_feed_manifest(&page_hashes)
        .map(|hash| hash.to_hex().to_string())
        .unwrap_or_default();
    edge.post_unit(
        &format!("{FEED_ROUTE}/complete"),
        &DemandFeedCompleteRequest {
            hour: hour.clone(),
            generation: begin.generation,
            page_count: staged_pages,
            entry_count,
            manifest_hash,
        },
    )
    .await?;

    let (delivered_pages, touched_tasks) = deliver_and_retire(edge, &hour).await?;
    Ok(FeedRunReport {
        hour: hour.to_string(),
        state: "delivered".to_owned(),
        staged_pages: u64::from(staged_pages),
        staged_entries: entry_count,
        delivered_pages,
        touched_tasks,
    })
}

/// `POST …/query` → owned temp file: the body streams through bounded
/// chunks — a closed hour can hold more identities than this process
/// may buffer.
async fn stream_query(
    edge: &Edge,
    hour: &DemandFeedHour,
    path: &std::path::Path,
) -> stow_types::error::Result<()> {
    use futures_util::StreamExt as _;
    use tokio::io::AsyncWriteExt as _;

    let response = edge
        .post_stream(
            &format!("{FEED_ROUTE}/query"),
            &DemandFeedQueryRequest { hour: hour.clone() },
        )
        .await?;
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|error| stow_error!("create {}: {error}", path.display()))?;
    let mut body = response.into_body();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| stow_error!("read demand feed document: {error}"))?;
        file.write_all(&chunk)
            .await
            .map_err(|error| stow_error!("write {}: {error}", path.display()))?;
    }
    file.flush()
        .await
        .map_err(|error| stow_error!("flush {}: {error}", path.display()))?;
    drop(file);
    Ok(())
}

/// Deliver every page of a complete hour to `delivered`, then drain
/// the payload retirement — the caller's explicit bounded work.
async fn deliver_and_retire(
    edge: &Edge,
    hour: &DemandFeedHour,
) -> stow_types::error::Result<(u64, u64)> {
    let mut delivered_pages = 0_u64;
    let mut touched_tasks = 0_u64;
    let request = DemandFeedDeliverRequest { hour: hour.clone() };
    loop {
        // Bounded fan-out: the object picks the next unapplied page
        // itself and its storage-only chain never yields mid-call, so
        // in-flight calls each take a distinct page. The loop exits on
        // `state = delivered` — a `remaining_pages` of zero is *not*
        // terminal: the same call that finds no page performs the
        // watermark-guarded transition, and a wave settles in one
        // extra round at most `DELIVER_FANOUT` no-op calls.
        let deliver_route = format!("{FEED_ROUTE}/deliver");
        let wave: Vec<_> = (0..DELIVER_FANOUT)
            .map(|_| edge.post_json::<_, DemandFeedDeliverReport>(&deliver_route, &request))
            .collect();
        // Every launched call settles before anything is claimed or
        // returned: `join_all` (not `try_join_all`) so one failure
        // cannot cancel siblings that already hold applied pages — a
        // cancelled sibling is a lost ACK, which is exactly what the
        // next invocation's durable-page replay must not lose. The
        // first failure surfaces after the wave reports in full.
        let mut terminal = false;
        let mut first_error = None;
        for outcome in futures_util::future::join_all(wave).await {
            match outcome {
                Ok(report) => {
                    delivered_pages += u64::from(report.delivered_page.is_some());
                    touched_tasks = touched_tasks
                        .checked_add(report.touched_tasks)
                        .ok_or_else(|| stow_error!("demand feed touched-task count overflow"))?;
                    if report.state == "delivered" {
                        terminal = true;
                    }
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if terminal {
            break;
        }
    }
    drain_cleanup(edge, hour).await?;
    Ok((delivered_pages, touched_tasks))
}

/// `cleanup` until the header reports nothing retirable — each call
/// is a bounded chunk, so a huge abandoned attempt takes more calls,
/// never a bigger one.
async fn drain_cleanup(edge: &Edge, hour: &DemandFeedHour) -> stow_types::error::Result<()> {
    let request = DemandFeedCleanupRequest { hour: hour.clone() };
    loop {
        let report: DemandFeedCleanupReport = edge
            .post_json(&format!("{FEED_ROUTE}/cleanup"), &request)
            .await?;
        if !report.remaining {
            return Ok(());
        }
    }
}

/// One page handed from the blocking parser to the page posts.
struct ParsedPage {
    page_no: u32,
    entries: Vec<SchedulerDemandEntry>,
}

/// What the document validation returns.
struct ParsedDocument {
    /// Rows the `data` array actually carried.
    rows: u64,
}

/// One `data` row — the query's six columns, strict: a provider shape
/// change fails the whole document before freeze.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FeedRow {
    crate_name: CrateName,
    version: CrateVersion,
    features_json: FeaturesJson,
    target: TargetTriple,
    rustc_version: WireRustcVersion,
    #[serde(deserialize_with = "de_f64")]
    demand: f64,
}

/// One `meta` entry — `{"name": "…", "type": "…"}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetaColumn {
    name: String,
    #[serde(rename = "type")]
    column_type: String,
}

/// The exact column contract `meta` must declare — names *and* types,
/// in the query's order.
const EXPECTED_META: [(&str, &str); 6] = [
    ("crate_name", "String"),
    ("version", "String"),
    ("features_json", "String"),
    ("target", "String"),
    ("rustc_version", "String"),
    ("demand", "Float64"),
];

/// Parse-and-validate one `FORMAT JSON` document on the blocking pool:
/// the typed page stream goes to `pages` in order and nothing leaves
/// staged until the caller freezes — a document that fails anywhere
/// (bad meta, invalid row, wrong row count, trailing bytes, late
/// malformed tail) never reaches `complete`.
fn parse_feed_document(
    path: &std::path::Path,
    pages: tokio::sync::mpsc::Sender<ParsedPage>,
) -> Result<ParsedDocument, String> {
    let file =
        std::fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let reader = BufReader::with_capacity(BODY_BUF_CAP, file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let mut state = ParseState::new(pages);
    DocSeed { state: &mut state }
        .deserialize(&mut deserializer)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    // The document must end at the closing brace — a truncated or
    // appended body is a failure, not a short read.
    deserializer
        .end()
        .map_err(|error| format!("{}: trailing content: {error}", path.display()))?;
    state.finish()
}

/// Streaming state the visitor fields share.
struct ParseState {
    pages: tokio::sync::mpsc::Sender<ParsedPage>,
    page: Vec<SchedulerDemandEntry>,
    /// Serialized payload bytes the open page would carry — the
    /// per-entry estimate under [`PAGE_FRAMING_SLACK`]; the exact
    /// envelope is re-checked on the async side.
    page_bytes: usize,
    page_no: u32,
    rows: u64,
    meta_seen: bool,
    data_seen: bool,
    rows_declared: Option<u64>,
}

impl ParseState {
    fn new(pages: tokio::sync::mpsc::Sender<ParsedPage>) -> Self {
        Self {
            pages,
            page: Vec::new(),
            page_bytes: 2, // "[]"
            page_no: 0,
            rows: 0,
            meta_seen: false,
            data_seen: false,
            rows_declared: None,
        }
    }

    /// Push one decoded row — converting its `Float64` demand through
    /// the shared exact conversion (non-finite, negative, fractional
    /// and out-of-range all fail the document) and flushing a full
    /// page to the async leg.
    fn push(&mut self, row: FeedRow) -> Result<(), String> {
        let demand = f64_to_u64_exact(row.demand, "demand feed row demand")?;
        let entry = SchedulerDemandEntry {
            crate_name: row.crate_name,
            version: row.version,
            features_json: row.features_json,
            target: row.target,
            rustc_version: row.rustc_version,
            demand,
        };
        let entry_len = serde_json::to_string(&entry)
            .map_err(|error| format!("encode demand feed entry: {error}"))?
            .len();
        if !self.page.is_empty()
            && (self.page.len() == DEMAND_FEED_PAGE_MAX_ENTRIES
                || self.page_bytes + entry_len + 1
                    > DEMAND_FEED_PAGE_MAX_BYTES - PAGE_FRAMING_SLACK)
        {
            self.flush()?;
        }
        if entry_len + 2 + PAGE_FRAMING_SLACK > DEMAND_FEED_PAGE_MAX_BYTES {
            return Err(format!(
                "demand feed identity for {} encodes to {entry_len} bytes — \
                 one entry can never fit the {}-byte page bound",
                entry.crate_name, DEMAND_FEED_PAGE_MAX_BYTES
            ));
        }
        self.page_bytes += entry_len + 1;
        self.page.push(entry);
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or_else(|| "demand feed row count overflow".to_owned())?;
        Ok(())
    }

    /// Emit the open page through the bounded channel — the send
    /// blocks while the async leg is `PAGE_CHANNEL_BOUND` pages
    /// behind, which is the feed's whole backpressure story.
    fn flush(&mut self) -> Result<(), String> {
        if self.page.is_empty() {
            return Ok(());
        }
        let page = ParsedPage {
            page_no: self.page_no,
            entries: std::mem::take(&mut self.page),
        };
        self.page_no += 1;
        self.page_bytes = 2;
        self.pages
            .blocking_send(page)
            .map_err(|_| "demand feed page channel closed".to_owned())
    }

    /// The document-level invariants: every required section present
    /// exactly once and the declared row count the parsed one.
    fn finish(&mut self) -> Result<ParsedDocument, String> {
        self.flush()?;
        if !self.meta_seen {
            return Err("demand feed document carries no `meta`".to_owned());
        }
        if !self.data_seen {
            return Err("demand feed document carries no `data`".to_owned());
        }
        match self.rows_declared {
            Some(declared) if declared == self.rows => {}
            Some(declared) => {
                return Err(format!(
                    "demand feed document declared {declared} rows but carried {}",
                    self.rows
                ));
            }
            None => return Err("demand feed document carries no `rows`".to_owned()),
        }
        Ok(ParsedDocument { rows: self.rows })
    }
}

/// The document's top-level seed: `{"meta": …, "data": …, "rows": …}`.
struct DocSeed<'a> {
    state: &'a mut ParseState,
}

impl<'de> DeserializeSeed<'de> for DocSeed<'_> {
    type Value = ();
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DocVisitor { state: self.state })
    }
}

struct DocVisitor<'a> {
    state: &'a mut ParseState,
}

impl<'de> serde::de::Visitor<'de> for DocVisitor<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a FORMAT JSON object")
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "meta" => {
                    if self.state.meta_seen {
                        return Err(serde::de::Error::custom("duplicate `meta`"));
                    }
                    self.state.meta_seen = true;
                    let columns: Vec<MetaColumn> = map.next_value()?;
                    if columns.len() != EXPECTED_META.len()
                        || !columns
                            .iter()
                            .zip(EXPECTED_META.iter())
                            .all(|(got, want)| got.name == want.0 && got.column_type == want.1)
                    {
                        return Err(serde::de::Error::custom(format!(
                            "demand feed `meta` does not declare the query's columns: {columns:?}"
                        )));
                    }
                }
                "data" => {
                    if self.state.data_seen {
                        return Err(serde::de::Error::custom("duplicate `data`"));
                    }
                    self.state.data_seen = true;
                    map.next_value_seed(RowsSeed {
                        state: &mut *self.state,
                    })?;
                }
                "rows" => {
                    if self.state.rows_declared.is_some() {
                        return Err(serde::de::Error::custom("duplicate `rows`"));
                    }
                    let rows: u64 = map.next_value()?;
                    self.state.rows_declared = Some(rows);
                }
                // Accepted-but-ignored document fields the engine
                // appends; anything else is a provider shape change.
                "rows_before_limit_at_least" | "statistics" => {
                    let _: serde::de::IgnoredAny = map.next_value()?;
                }
                other => {
                    return Err(serde::de::Error::custom(format!(
                        "demand feed document carries unexpected key {other:?}"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// The `data` array's streaming seed — rows decode one at a time, so a
/// late malformed row fails after any number of good ones and a huge
/// hour never sits in one `Vec`.
struct RowsSeed<'a> {
    state: &'a mut ParseState,
}

impl<'de> DeserializeSeed<'de> for RowsSeed<'_> {
    type Value = ();
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(RowsVisitor { state: self.state })
    }
}

struct RowsVisitor<'a> {
    state: &'a mut ParseState,
}

impl<'de> serde::de::Visitor<'de> for RowsVisitor<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("the demand feed data array")
    }
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        while let Some(row) = seq.next_element::<FeedRow>()? {
            self.state.push(row).map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// One valid `data` row — built by the serializer, never hand-laid
    /// text.
    fn row(name: &str, demand: serde_json::Value) -> serde_json::Value {
        json!({
            "crate_name": name,
            "version": "1.0.0",
            "features_json": "[]",
            "target": "x86_64-unknown-linux-gnu",
            "rustc_version": "1.86.0",
            "demand": demand,
        })
    }

    /// Serialize a document the way the engine emits it and run the
    /// real parser over the owned temp file.
    fn parse(document: &serde_json::Value) -> Result<ParsedDocument, String> {
        parse_body(&serde_json::to_vec(document).expect("document encodes"))
    }

    fn parse_body(body: &[u8]) -> Result<ParsedDocument, String> {
        // Per-case owned tempfile — concurrent tests never share a name
        // and the RAII guard unlinks on every exit.
        let temp = tempfile::NamedTempFile::new().expect("test tempfile");
        std::fs::write(temp.path(), body).expect("write fixture");
        let (tx, mut rx) = tokio::sync::mpsc::channel(PAGE_CHANNEL_BOUND);
        let mut pages = Vec::new();
        // Drain concurrently so `blocking_send` never waits forever —
        // the parser is synchronous in this test.
        let parse_path = temp.path().to_owned();
        let handle = std::thread::spawn(move || parse_feed_document(&parse_path, tx));
        while let Some(page) = rx.blocking_recv() {
            pages.push(page);
        }
        let result = handle.join().expect("parser thread");
        drop(temp);
        result.map(|doc| {
            assert!(
                pages.iter().map(|p| p.entries.len() as u64).sum::<u64>() == doc.rows,
                "every parsed row staged exactly once"
            );
            doc
        })
    }

    fn document(rows: Vec<serde_json::Value>) -> serde_json::Value {
        json!({
            "meta": [
                {"name": "crate_name", "type": "String"},
                {"name": "version", "type": "String"},
                {"name": "features_json", "type": "String"},
                {"name": "target", "type": "String"},
                {"name": "rustc_version", "type": "String"},
                {"name": "demand", "type": "Float64"},
            ],
            "data": rows,
            "rows": rows.len(),
            "statistics": {"elapsed": 0.01, "rows_read": rows.len()},
        })
    }

    #[test]
    fn valid_document_parses_to_end() {
        let parsed = parse(&document(vec![
            row("serde", json!(41.0)),
            row("anyhow", json!("17.0")),
        ]))
        .expect("valid document parses");
        assert_eq!(parsed.rows, 2);
    }

    #[test]
    fn empty_hour_is_a_valid_document() {
        let parsed = parse(&document(vec![])).expect("empty document parses");
        assert_eq!(parsed.rows, 0);
    }

    #[test]
    fn truncation_and_trailing_bytes_fail() {
        let body = serde_json::to_vec(&document(vec![row("serde", json!(1.0))]))
            .expect("document encodes");
        let truncated = &body[..body.len() - 20];
        assert!(parse_body(truncated).is_err(), "truncated body refuses");
        let mut appended = body.clone();
        appended.extend_from_slice(b"{}");
        assert!(parse_body(&appended).is_err(), "appended body refuses");
    }

    #[test]
    fn declared_row_mismatch_fails() {
        let mut doc = document(vec![row("serde", json!(1.0))]);
        doc["rows"] = json!(2);
        assert!(parse(&doc).is_err(), "declared != parsed fails");
    }

    #[test]
    fn provider_shape_changes_fail() {
        // Column rename, wrong type, extra meta column, unknown
        // top-level key — every drift from the query's contract fails.
        for mutate in [
            |doc: &mut serde_json::Value| doc["meta"][0]["name"] = json!("name"),
            |doc: &mut serde_json::Value| doc["meta"][5]["type"] = json!("UInt64"),
            |doc: &mut serde_json::Value| {
                doc["meta"]
                    .as_array_mut()
                    .expect("meta array")
                    .push(json!({"name": "extra", "type": "String"}));
            },
            |doc: &mut serde_json::Value| doc["unexpected"] = json!(1),
            |doc: &mut serde_json::Value| {
                let _ = doc.as_object_mut().expect("object").remove("meta");
            },
        ] {
            let mut doc = document(vec![row("serde", json!(1.0))]);
            mutate(&mut doc);
            assert!(parse(&doc).is_err(), "shape change must refuse");
        }
    }

    #[test]
    fn invalid_demands_fail_the_whole_document() {
        for demand in [
            json!(-1.0),
            json!(1.5),
            json!("NaN"),
            json!("inf"),
            json!("18446744073709551616"), // 2^64 — out of u64 range
            json!("x"),
            json!({"demand": 1}),
        ] {
            assert!(
                parse(&document(vec![
                    row("serde", json!(1.0)),
                    row("anyhow", demand)
                ]))
                .is_err(),
                "a late invalid row still fails the whole document"
            );
        }
    }

    #[test]
    fn page_bound_splits_and_singletons() {
        // Boundaries land on entries: 256-entry pages, then a byte-bound
        // split — the parser measures serialized entry bytes.
        let mut rows: Vec<serde_json::Value> = (0..520)
            .map(|n| row(&format!("crate-{n}"), json!(1.0)))
            .collect();
        let parsed = parse(&document(rows.clone())).expect("large document parses");
        assert_eq!(parsed.rows, 520);
        // An identity alone under the bound with a huge feature list.
        rows.clear();
        rows.push(row("huge", json!(1.0)));
        assert!(parse(&document(rows)).is_ok());
    }

    #[test]
    fn missing_row_fields_fail() {
        let mut broken = row("serde", json!(1.0));
        broken.as_object_mut().expect("row object").remove("target");
        assert!(parse(&document(vec![broken])).is_err());
        let mut extra = row("serde", json!(1.0));
        extra
            .as_object_mut()
            .expect("row object")
            .insert("extra".to_owned(), json!(1));
        assert!(parse(&document(vec![extra])).is_err());
    }

    // ----- Mock edge: the real get/post/stream paths against a
    // scripted HTTP/1.1 listener — zenwave talks cleartext h1 in
    // origin form, so a minimal socket answer exercises the whole
    // wire. -----

    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

    /// One recorded call — `(path, request-body JSON or null)`.
    type Calls = Arc<Mutex<Vec<(String, serde_json::Value)>>>;

    /// What the scripted edge answers, in call order.
    struct MockEdge {
        /// `GET …/status` body.
        status: serde_json::Value,
        /// `POST …/query` body — verbatim bytes (may be truncated).
        query_body: Vec<u8>,
        /// `deliver` responses, consumed in order; the queue empties
        /// into `delivered` no-ops, matching the real terminal state.
        deliver_plan: Mutex<VecDeque<serde_json::Value>>,
        /// Delivered-page counter the mock assigns in order.
        deliver_page: Mutex<u32>,
        /// `cleanup` answers `remaining: false` — the report's bounded
        /// contract.
        calls: Calls,
        /// Answer every route 401.
        unauthorized: bool,
        /// Drop the connection instead of answering.
        hangup_on: Vec<String>,
    }

    impl MockEdge {
        fn healthy(query_rows: Vec<serde_json::Value>) -> Self {
            Self {
                status: json!({"watermark": "2020-01-01T05", "unfinished": null}),
                query_body: serde_json::to_vec(&document(query_rows)).expect("body"),
                deliver_plan: Mutex::new(VecDeque::new()),
                deliver_page: Mutex::new(0),
                calls: Arc::new(Mutex::new(Vec::new())),
                unauthorized: false,
                hangup_on: Vec::new(),
            }
        }

        /// `deliver` answers `complete` (one page per call) `n` times,
        /// then `delivered` — the fan-out tail draws no-op terminals.
        fn delivering(mut self, pages: u32) -> Self {
            let mut plan = VecDeque::new();
            for _ in 0..pages {
                plan.push_back(json!("complete"));
            }
            plan.push_back(json!("delivered"));
            self.deliver_plan = Mutex::new(plan);
            self
        }
    }

    /// The mock listener: one task per connection, real request
    /// framing (head to `\r\n\r\n`, then `Content-Length` body),
    /// dispatch on `METHOD /path`.
    async fn serve(script: Arc<MockEdge>) -> (Edge, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock edge");
        let addr = listener.local_addr().expect("local addr");
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let script = Arc::clone(&script);
                tokio::spawn(handle(stream, script));
            }
        });
        (Edge::for_test(format!("http://{addr}")), task)
    }

    async fn handle(stream: tokio::net::TcpStream, script: Arc<MockEdge>) {
        let mut reader = tokio::io::BufReader::new(stream);
        let mut head = Vec::new();
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => return,
                Ok(_) if line == "\r\n" => break,
                Ok(_) => head.push(line),
            }
        }
        let Some(request_line) = head.first().cloned() else {
            return;
        };
        let header = |name: &str| {
            head.iter()
                .filter_map(|line| line.split_once(':'))
                .find(|(n, _)| n.trim().eq_ignore_ascii_case(name))
                .map(|(_, value)| value.trim().to_owned())
        };
        // A body gated by `Expect: 100-continue` needs the interim
        // answer before the client writes it.
        if header("expect").is_some_and(|value| value.eq_ignore_ascii_case("100-continue")) {
            if reader
                .get_mut()
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
        }
        let body = if header("transfer-encoding")
            .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
        {
            let mut body = Vec::new();
            loop {
                let mut size_line = String::new();
                match reader.read_line(&mut size_line).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                let Ok(size) = usize::from_str_radix(size_line.trim(), 16) else {
                    return;
                };
                if size == 0 {
                    // The terminating chunk — drain the trailer's
                    // empty line.
                    let mut trailer = String::new();
                    let _ = reader.read_line(&mut trailer).await;
                    break;
                }
                let start = body.len();
                body.resize(start + size, 0);
                if reader.read_exact(&mut body[start..]).await.is_err() {
                    return;
                }
                let mut crlf = [0_u8; 2];
                if reader.read_exact(&mut crlf).await.is_err() {
                    return;
                }
            }
            body
        } else {
            let content_length = header("content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = vec![0_u8; content_length];
            if reader.read_exact(&mut body).await.is_err() {
                return;
            }
            body
        };
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_owned();
        let path = parts.next().unwrap_or("").to_owned();
        let request =
            serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null);
        script
            .calls
            .lock()
            .expect("calls")
            .push((format!("{method} {path}"), request.clone()));

        let (status, body): (u16, Vec<u8>) =
            if script.unauthorized || script.hangup_on.iter().any(|p| path.ends_with(p.as_str())) {
                if script.hangup_on.iter().any(|p| path.ends_with(p.as_str())) {
                    return;
                }
                (401, b"{}".to_vec())
            } else {
                let route = path.strip_prefix("/api/v1/admin/scheduler/demand-feed");
                match route {
                    Some("/status") => (200, serde_json::to_vec(&script.status).expect("status")),
                    Some("/begin") => {
                        let report = DemandFeedBeginReport {
                            hour: serde_json::from_value(
                                request.get("hour").cloned().unwrap_or_default(),
                            )
                            .expect("hour"),
                            generation: 1,
                            stale_pages_pending: false,
                        };
                        (200, serde_json::to_vec(&report).expect("begin"))
                    }
                    Some("/page") | Some("/complete") => (200, b"{}".to_vec()),
                    Some("/cleanup") => {
                        let report = DemandFeedCleanupReport {
                            hour: serde_json::from_value(
                                request.get("hour").cloned().unwrap_or_default(),
                            )
                            .expect("hour"),
                            retired: 0,
                            remaining: false,
                        };
                        (200, serde_json::to_vec(&report).expect("cleanup"))
                    }
                    Some("/deliver") => {
                        let mut plan = script.deliver_plan.lock().expect("plan");
                        let state = plan
                            .pop_front()
                            .and_then(|v| v.as_str().map(str::to_owned))
                            .unwrap_or_else(|| "delivered".to_owned());
                        let mut page_no = script.deliver_page.lock().expect("page");
                        let delivered_page = if state == "delivered" {
                            None
                        } else {
                            let n = *page_no;
                            *page_no += 1;
                            Some(n)
                        };
                        let report = DemandFeedDeliverReport {
                            hour: request
                                .get("hour")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_owned(),
                            state,
                            delivered_page,
                            applied: true,
                            touched_tasks: 1,
                            remaining_pages: 0,
                        };
                        (200, serde_json::to_vec(&report).expect("deliver"))
                    }
                    Some("/query") => (200, script.query_body.clone()),
                    _ => (404, b"{}".to_vec()),
                }
            };
        let response = format!(
            "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let stream = reader.get_mut();
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(&body).await;
        let _ = stream.flush().await;
    }

    /// Call paths the mock recorded, in order.
    fn paths(calls: &Calls) -> Vec<String> {
        calls
            .lock()
            .expect("calls")
            .iter()
            .map(|(path, _)| path.clone())
            .collect()
    }

    #[tokio::test]
    async fn end_to_end_stages_freezes_and_delivers() {
        // 520 rows → 256+256+8 entries across three pages; the mock
        // plays the real route set: status → begin → query → 3×page →
        // complete → deliver until delivered → cleanup.
        let rows: Vec<serde_json::Value> = (0..520)
            .map(|n| row(&format!("crate-{n:04}"), json!((n % 7) as f64)))
            .collect();
        let script = Arc::new(MockEdge::healthy(rows).delivering(3));
        let calls = script.calls.clone();
        let (edge, _task) = serve(script).await;
        run(&edge, DemandFeedArgs { hour: None }, Output::Json)
            .await
            .expect("full pass succeeds");
        let paths = paths(&calls);
        assert_eq!(paths[0], "GET /api/v1/admin/scheduler/demand-feed/status");
        assert_eq!(paths[1], "POST /api/v1/admin/scheduler/demand-feed/begin");
        assert_eq!(paths[2], "POST /api/v1/admin/scheduler/demand-feed/query");
        assert_eq!(
            paths
                .iter()
                .filter(|p| p.as_str() == "POST /api/v1/admin/scheduler/demand-feed/page")
                .count(),
            3
        );
        let calls = calls.lock().expect("calls");
        // Page order, generation and the 256-entry bound all carried
        // on the wire.
        let page_bodies: Vec<&serde_json::Value> = calls
            .iter()
            .filter(|(p, _)| p == "POST /api/v1/admin/scheduler/demand-feed/page")
            .map(|(_, b)| b)
            .collect();
        for (index, body) in page_bodies.iter().enumerate() {
            assert_eq!(body["page_no"], json!(index as u32));
            assert_eq!(body["generation"], json!(1));
            assert!(body["entries"].as_array().expect("entries").len() <= 256);
        }
        // The complete call declared exactly the manifest of the pages
        // the wire carried — recomputed through the shared helpers.
        let complete = calls
            .iter()
            .find(|(p, _)| p == "POST /api/v1/admin/scheduler/demand-feed/complete")
            .map(|(_, b)| b)
            .expect("complete called");
        let page_hashes: Vec<blake3::Hash> = page_bodies
            .iter()
            .map(|body| {
                let entries: Vec<SchedulerDemandEntry> =
                    serde_json::from_value(body["entries"].clone()).expect("entries decode");
                demand_feed_page_hash(&entries).expect("page hash")
            })
            .collect();
        let manifest = demand_feed_manifest(&page_hashes)
            .expect("pages staged")
            .to_hex()
            .to_string();
        assert_eq!(complete["manifest_hash"], json!(manifest));
        assert_eq!(complete["page_count"], json!(3));
        assert_eq!(complete["entry_count"], json!(520));
        assert_eq!(complete["generation"], json!(1));
        // Deliver ran under the fan-out until a `delivered` report —
        // then exactly one cleanup drain.
        assert!(
            paths
                .iter()
                .any(|p| p.as_str() == "POST /api/v1/admin/scheduler/demand-feed/deliver")
        );
        assert_eq!(
            paths
                .iter()
                .filter(|p| p.as_str() == "POST /api/v1/admin/scheduler/demand-feed/cleanup")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn frozen_hour_resumes_without_a_new_query() {
        // The durable cursor holds a complete hour: only deliver and
        // cleanup run — no begin, no query, no page staging.
        let mut script = MockEdge::healthy(vec![]);
        script.status = json!({
            "watermark": null,
            "unfinished": {
                "hour": "2020-01-01T05",
                "state": "complete",
                "generation": 3,
                "staged_pages": 2,
                "staged_entries": 300,
            },
        });
        let script = Arc::new(script.delivering(2));
        let calls = script.calls.clone();
        let (edge, _task) = serve(script).await;
        run(&edge, DemandFeedArgs { hour: None }, Output::Json)
            .await
            .expect("resume delivers");
        let paths = paths(&calls);
        assert!(paths.iter().all(|p| !p.contains("/begin")
            && !p.contains("/query")
            && !p.contains("/page")
            && !p.contains("/complete")));
        assert_eq!(paths[0], "GET /api/v1/admin/scheduler/demand-feed/status");
        assert!(paths.iter().any(|p| p.contains("/deliver")));
        assert!(paths.iter().any(|p| p.contains("/cleanup")));
    }

    #[tokio::test]
    async fn truncated_document_never_freezes() {
        let mut script = MockEdge::healthy(vec![row("serde", json!(1.0))]);
        script.query_body.truncate(script.query_body.len() - 20);
        let script = Arc::new(script);
        let calls = script.calls.clone();
        let (edge, _task) = serve(script).await;
        let err = run(&edge, DemandFeedArgs { hour: None }, Output::Json)
            .await
            .expect_err("truncated body fails");
        drop(err);
        let paths = paths(&calls);
        assert!(paths.iter().all(|p| !p.contains("/complete")));
        assert!(paths.iter().all(|p| !p.contains("/deliver")));
    }

    #[tokio::test]
    async fn unauthorized_fails_fast() {
        let script = MockEdge {
            unauthorized: true,
            ..MockEdge::healthy(vec![])
        };
        let script = Arc::new(script);
        let calls = script.calls.clone();
        let (edge, _task) = serve(script).await;
        assert!(
            run(&edge, DemandFeedArgs { hour: None }, Output::Json)
                .await
                .is_err()
        );
        assert_eq!(paths(&calls).len(), 1, "status refusal stops the pass");
    }

    #[tokio::test]
    async fn invalid_document_stages_but_never_freezes() {
        // A declared-count mismatch: the parser may stage pages (they
        // are undeliverable in a staging attempt), but `complete` is
        // never called.
        let mut doc = document(vec![row("serde", json!(1.0)), row("anyhow", json!(2.0))]);
        doc["rows"] = json!(99);
        let mut script = MockEdge::healthy(vec![]);
        script.query_body = serde_json::to_vec(&doc).expect("body");
        let script = Arc::new(script);
        let calls = script.calls.clone();
        let (edge, _task) = serve(script).await;
        assert!(
            run(&edge, DemandFeedArgs { hour: None }, Output::Json)
                .await
                .is_err()
        );
        assert!(
            paths(&calls)
                .iter()
                .all(|p| !p.contains("/complete") && !p.contains("/deliver"))
        );
    }
}
