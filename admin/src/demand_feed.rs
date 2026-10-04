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
    DemandFeedBeginReport, DemandFeedBeginRequest, DemandFeedCleanupReport,
    DemandFeedCleanupRequest, DemandFeedCompleteRequest, DemandFeedDeliverReport,
    DemandFeedDeliverRequest, DemandFeedHour, DemandFeedPageBuilder, DemandFeedPageRequest,
    DemandFeedQueryRequest, DemandFeedStatus, SchedulerDemandEntry, demand_feed_manifest,
    demand_feed_page_hash,
};
use stow_types::error::Error;
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use stow_types::stow_error;

use crate::Edge;
use crate::render::{self, Output};

const FEED_ROUTE: &str = "/api/v1/admin/scheduler/demand-feed";

/// Pages in flight between the blocking parser and the page posts —
/// the explicit handoff bound: each in-flight page is at most
/// `DEMAND_FEED_PAGE_MAX_BYTES` on the wire.
const PAGE_CHANNEL_BOUND: usize = 4;

/// Independent `deliver` calls on the same complete hour — the object
/// picks the next unapplied page itself, so the fan-out only buys
/// pipeline depth; nothing beyond the hour's own page count is ever
/// needed and the bound also caps the no-op `delivered` answers a
/// tail wave may draw.
const DELIVER_FANOUT: usize = 4;

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

/// What one feed pass does with the durable cursor.
enum Selected {
    /// Resume the unfinished hour sitting at the cursor.
    Resume(DemandFeedHour, String),
    /// Materialize the chronological next hour.
    Materialize(DemandFeedHour),
}

/// The chronological cursor: the watermark's successor decides one
/// pass — resume the unfinished hour AT the successor, or materialize
/// the successor itself. An unfinished hour past a gap keeps its
/// frozen/staging bytes until the stream reaches it. Bootstrap (no
/// watermark) resumes any unfinished hour, else the explicit/latest
/// closed hour.
fn select(
    status: &DemandFeedStatus,
    explicit: Option<&DemandFeedHour>,
    now_secs: i64,
) -> stow_types::error::Result<Selected> {
    let canonical = status
        .watermark
        .as_deref()
        .map(|raw| {
            DemandFeedHour::parse(raw)
                .and_then(|watermark| watermark.next())
                .map_err(|error| Error::msg(format!("feed status watermark {raw:?}: {error}")))
        })
        .transpose()?;
    let unfinished = status
        .unfinished
        .as_ref()
        .map(|row| {
            DemandFeedHour::parse(&row.hour)
                .map_err(|error| Error::msg(format!("feed status unfinished hour: {error}")))
                .map(|hour| (hour, row.state.clone()))
        })
        .transpose()?;
    Ok(match (unfinished, canonical) {
        (Some((hour, _)), Some(canonical)) if hour < canonical => {
            // An unfinished row at or below the watermark means the
            // durable cursor disagrees with itself — refuse rather
            // than guess which side is real.
            return Err(Error::msg(format!(
                "feed cursor inconsistent: unfinished hour {hour} is not after \
                 the watermark's successor {canonical}"
            )));
        }
        (Some((hour, state)), Some(canonical)) if hour == canonical => {
            Selected::Resume(hour, state)
        }
        (Some((hour, state)), None) => Selected::Resume(hour, state),
        // Either no unfinished row, or the unfinished hour sits past a
        // gap: keep its frozen/staging bytes untouched and materialize
        // the canonical missing hour; later cron passes fill forward
        // until the stored hour is reached and resumes.
        (_, Some(canonical)) => Selected::Materialize(canonical),
        (None, None) => match explicit {
            Some(hour) => Selected::Materialize(hour.clone()),
            None => Selected::Materialize(
                DemandFeedHour::latest_closed(now_secs)
                    .ok_or_else(|| stow_error!("no closed hour is representable"))?,
            ),
        },
    })
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
    // An explicit `--hour` is parsed and closure-validated BEFORE any
    // side effect — a malformed or unfinished explicit hour errors even
    // when the cursor holds a frozen unfinished hour.
    let explicit = args
        .hour
        .as_deref()
        .map(|raw| {
            DemandFeedHour::parse_closed(raw, now_secs)
                .map_err(|error| Error::msg(format!("--hour {raw:?}: {error}")))
        })
        .transpose()?;
    let status: DemandFeedStatus = edge.get_json(&format!("{FEED_ROUTE}/status")).await?;

    // The chronological cursor is the watermark's successor whenever a
    // watermark exists — an unfinished hour later than it is a frozen
    // future the stream will reach in order, not the next hour to run.
    let selected = select(&status, explicit.as_ref(), now_secs)?;
    let selected_hour = match &selected {
        Selected::Resume(hour, _) | Selected::Materialize(hour) => hour,
    };
    // An explicit `--hour` must name the hour the cursor selects — a
    // gap fill IS permitted to name the canonical missing hour, but
    // anything past it (or a different resume) refuses before any
    // begin/query/stage write.
    if let Some(explicit) = &explicit
        && explicit != selected_hour
    {
        return Err(Error::msg(format!(
            "--hour {explicit} but the durable cursor selects {selected_hour} \
                 — refusing to leap over it"
        )));
    }

    let report = match selected {
        Selected::Resume(hour, state) => match state.as_str() {
            // A frozen hour delivers its original staged pages —
            // the input is immutable, so no new Analytics Engine
            // query ever runs for it.
            "complete" => {
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
            // A `staging` hour materializes again from scratch —
            // its pages were never frozen, so a fresh query under
            // a fresh generation is the canonical restart.
            "staging" => materialize(edge, hour).await?,
            // An unknown state is an error — never a silent
            // re-materialize.
            other => {
                return Err(Error::msg(format!(
                    "demand feed hour {hour} reports unknown state {other:?}"
                )));
            }
        },
        Selected::Materialize(hour) => {
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

    // The document lands in an owned tempfile — created off the async
    // executor, and `close`d off it again once the operation's own
    // outcome is known, so EVERY return path (stream failure, stage
    // failure, parse failure, success) does its unlink/close work on
    // the blocking pool rather than the executor.
    let temp = tokio::task::spawn_blocking(tempfile::NamedTempFile::new)
        .await
        .map_err(|error| stow_error!("demand feed tempfile task: {error}"))?
        .map_err(|error| stow_error!("create demand feed tempfile: {error}"))?;
    let staging_path = temp.path().to_owned();
    let outcome = stage_and_freeze(edge, &hour, &staging_path, begin.generation).await;

    // The owned guard's close joins the blocking pool whichever way
    // the operation resolved — a close failure only ever replaces a
    // successful outcome; the operation's own error always wins, with
    // the cleanup failure attached as diagnostics.
    let closed = tokio::task::spawn_blocking(move || temp.close())
        .await
        .map_err(|error| stow_error!("demand feed tempfile close task: {error}"))
        .and_then(|result| {
            result.map_err(|error| stow_error!("close demand feed tempfile: {error}"))
        });
    let (entry_count, staged_pages) = match (outcome, closed) {
        (Ok((entry_count, staged_pages)), Ok(())) => (entry_count, staged_pages),
        (Ok(_), Err(close)) => return Err(close),
        (Err(error), Ok(())) => return Err(error),
        (Err(error), Err(close)) => {
            return Err(Error::msg(format!(
                "{error:#} — additionally failed to close the staging tempfile: {close:#}"
            )));
        }
    };

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

/// The staging leg: stream the hour's document to disk, parse and
/// post it page by page under the object-enforced ordering, then
/// freeze on the manifest. The parser runs on the blocking pool with
/// bounded in-flight pages, so a staging failure aborts the rest
/// cleanly.
async fn stage_and_freeze(
    edge: &Edge,
    hour: &DemandFeedHour,
    staging_path: &std::path::Path,
    generation: i64,
) -> stow_types::error::Result<(u64, u32)> {
    stream_query(edge, hour, staging_path).await?;
    let staged_hour = hour.clone();
    // The parser runs on the blocking pool with bounded in-flight
    // pages; each page posts under the object-enforced sequential
    // ordering, so a staging failure aborts the rest cleanly.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<DemandFeedPageRequest>(PAGE_CHANNEL_BOUND);
    let parse_path = staging_path.to_owned();
    let parse = tokio::task::spawn_blocking(move || {
        parse_feed_document(&parse_path, &staged_hour, generation, tx)
    });

    let mut page_hashes = Vec::new();
    let mut entry_count = 0_u64;
    let mut staged_pages = 0_u32;
    let staging: stow_types::error::Result<()> = async {
        while let Some(request) = rx.recv().await {
            // The shared builder already guarantees the exact
            // whole-envelope bound; ordering is checked here.
            if request.page_no != staged_pages {
                return Err(stow_error!(
                    "demand feed parser emitted page {} after {}",
                    request.page_no,
                    staged_pages
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

    let summary = match staging {
        Ok(()) => parse
            .await
            .map_err(|error| stow_error!("demand feed parser task: {error}"))
            .and_then(|outcome| outcome.map_err(Error::msg))?,
        Err(error) => {
            // The page leg failed — close the receiver FIRST: a
            // `blocking_send` against a live-but-undrained channel
            // would park the parser thread forever on a full
            // bounded queue. Dropping `rx` makes every pending
            // send fail fast, then joining cannot hang. The
            // original post error is what surfaces, not a
            // secondary parse failure.
            drop(rx);
            let _ = parse.await;
            return Err(error);
        }
    };

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
            generation,
            page_count: staged_pages,
            entry_count,
            manifest_hash,
        },
    )
    .await?;
    Ok((entry_count, staged_pages))
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
/// completed [`DemandFeedPageRequest`]s go to `pages` in order and
/// nothing leaves staged until the caller freezes — a document that
/// fails anywhere (bad meta, invalid row, wrong row count, trailing
/// bytes, late malformed tail) never reaches `complete`.
fn parse_feed_document(
    path: &std::path::Path,
    hour: &DemandFeedHour,
    generation: i64,
    pages: tokio::sync::mpsc::Sender<DemandFeedPageRequest>,
) -> Result<ParsedDocument, String> {
    let file =
        std::fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let reader = BufReader::with_capacity(BODY_BUF_CAP, file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let mut state = ParseState::new(pages, hour, generation)?;
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
    pages: tokio::sync::mpsc::Sender<DemandFeedPageRequest>,
    /// The shared exact-envelope page builder — the byte bound and the
    /// 256-entry cap are enforced inside it on the same serialization
    /// the wire carries.
    builder: DemandFeedPageBuilder,
    rows: u64,
    meta_seen: bool,
    data_seen: bool,
    rows_declared: Option<u64>,
}

impl ParseState {
    fn new(
        pages: tokio::sync::mpsc::Sender<DemandFeedPageRequest>,
        hour: &DemandFeedHour,
        generation: i64,
    ) -> Result<Self, String> {
        Ok(Self {
            pages,
            builder: DemandFeedPageBuilder::new(hour.clone(), generation)?,
            rows: 0,
            meta_seen: false,
            data_seen: false,
            rows_declared: None,
        })
    }

    /// Push one decoded row — converting its `Float64` demand through
    /// the shared exact conversion (non-finite, negative, fractional
    /// and out-of-range all fail the document) and handing any page
    /// the builder completes to the async leg.
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
        if let Some(page) = self.builder.push(entry)? {
            self.send_page(page)?;
        }
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or_else(|| "demand feed row count overflow".to_owned())?;
        Ok(())
    }

    /// Emit one completed page through the bounded channel — the send
    /// blocks while the async leg is `PAGE_CHANNEL_BOUND` pages
    /// behind, which is the feed's whole backpressure story.
    fn send_page(&self, page: DemandFeedPageRequest) -> Result<(), String> {
        self.pages
            .blocking_send(page)
            .map_err(|_| "demand feed page channel closed".to_owned())
    }

    /// The document-level invariants: every required section present
    /// exactly once and the declared row count the parsed one. The
    /// builder's open page becomes the final remainder — sent here,
    /// after the whole document validated.
    fn finish(&mut self) -> Result<ParsedDocument, String> {
        if let Some(page) = self.builder.finish_page()? {
            self.send_page(page)?;
        }
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
    pub(super) fn row(name: &str, demand: &serde_json::Value) -> serde_json::Value {
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
        let parse_hour = DemandFeedHour::parse("2020-01-01T00").expect("test hour");
        let handle =
            std::thread::spawn(move || parse_feed_document(&parse_path, &parse_hour, 1, tx));
        while let Some(page) = rx.blocking_recv() {
            pages.push(page);
        }
        let result = handle.join().expect("parser thread");
        drop(temp);
        result.inspect(|doc| {
            assert!(
                pages.iter().map(|p| p.entries.len() as u64).sum::<u64>() == doc.rows,
                "every parsed row staged exactly once"
            );
        })
    }

    pub(super) fn document(rows: &[serde_json::Value]) -> serde_json::Value {
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
        let parsed = parse(&document(&[
            row("serde", &json!(41.0)),
            row("anyhow", &json!("17.0")),
        ]))
        .expect("valid document parses");
        assert_eq!(parsed.rows, 2);
    }

    #[test]
    fn empty_hour_is_a_valid_document() {
        let parsed = parse(&document(&[])).expect("empty document parses");
        assert_eq!(parsed.rows, 0);
    }

    #[test]
    fn truncation_and_trailing_bytes_fail() {
        let body =
            serde_json::to_vec(&document(&[row("serde", &json!(1.0))])).expect("document encodes");
        let truncated = &body[..body.len() - 20];
        assert!(parse_body(truncated).is_err(), "truncated body refuses");
        let mut appended = body.clone();
        appended.extend_from_slice(b"{}");
        assert!(parse_body(&appended).is_err(), "appended body refuses");
    }

    #[test]
    fn declared_row_mismatch_fails() {
        let mut doc = document(&[row("serde", &json!(1.0))]);
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
            let mut doc = document(&[row("serde", &json!(1.0))]);
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
                parse(&document(&[
                    row("serde", &json!(1.0)),
                    row("anyhow", &demand)
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
            .map(|n| row(&format!("crate-{n}"), &json!(1.0)))
            .collect();
        let parsed = parse(&document(&rows)).expect("large document parses");
        assert_eq!(parsed.rows, 520);
        // An identity alone under the bound with a huge feature list.
        rows.clear();
        rows.push(row("huge", &json!(1.0)));
        assert!(parse(&document(&rows)).is_ok());
    }

    #[test]
    fn missing_row_fields_fail() {
        let mut broken = row("serde", &json!(1.0));
        broken.as_object_mut().expect("row object").remove("target");
        assert!(parse(&document(&[broken])).is_err());
        let mut extra = row("serde", &json!(1.0));
        extra
            .as_object_mut()
            .expect("row object")
            .insert("extra".to_owned(), json!(1));
        assert!(parse(&document(&[extra])).is_err());
    }

    // ----- Mock edge: the real get/post/stream paths against the
    // maintained axum listener the mock-registry already runs —
    // scripted bodies over real HTTP/1.1. One owned state behind
    // axum's `State`; recorded calls and scripted `deliver` replies
    // flow through the two bounded channels — no global locks, no
    // statics. -----

    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::{mpsc, oneshot};

    /// Calls the mock records — the bounded channel is the whole
    /// recording path; the test drains it once `run` has settled.
    const MOCK_CALL_BOUND: usize = 64;

    /// What the scripted edge answers, in call order.
    struct MockEdge {
        /// `GET …/status` body.
        status: serde_json::Value,
        /// `POST …/query` body — verbatim bytes (may be truncated).
        query_body: Vec<u8>,
        /// `deliver` reply states, indexed by the atomic sequence —
        /// immutable once staged, so no lock mediates the read. An
        /// index past the plan answers `delivered`, matching the real
        /// terminal state.
        deliver_plan: Vec<String>,
        /// Answer every route 401.
        unauthorized: bool,
        /// Abort the response body mid-stream instead of answering.
        hangup_on: Vec<String>,
    }

    impl MockEdge {
        fn healthy(query_rows: &[serde_json::Value]) -> Self {
            Self {
                status: json!({"watermark": "2020-01-01T05", "unfinished": null}),
                query_body: serde_json::to_vec(&document(query_rows)).expect("body"),
                deliver_plan: Vec::new(),
                unauthorized: false,
                hangup_on: Vec::new(),
            }
        }

        /// `deliver` answers `complete` (one page per call) `n` times,
        /// then `delivered` — the fan-out tail draws no-op terminals.
        fn delivering(mut self, pages: u32) -> Self {
            for _ in 0..pages {
                self.deliver_plan.push("complete".to_owned());
            }
            self.deliver_plan.push("delivered".to_owned());
            self
        }
    }

    /// The owned state every handler shares — `State` carries one Arc;
    /// the call log is the only mutation and it flows through a
    /// bounded channel; the scripted replies are immutable and the
    /// deliver sequence is one atomic index.
    struct MockShared {
        edge: MockEdge,
        calls: mpsc::Sender<(String, serde_json::Value)>,
        deliver_seq: AtomicU32,
    }

    /// A running mock server the test drains and shuts down through
    /// the same graceful mechanism the production listener uses —
    /// `shutdown` signals the accept loop and awaits it, and Drop's
    /// abort is only the panic backup.
    struct MockServer {
        edge: Edge,
        calls: mpsc::Receiver<(String, serde_json::Value)>,
        shutdown: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl MockServer {
        /// Every recorded `(method path, request JSON)` in order.
        fn drain(&mut self) -> Vec<(String, serde_json::Value)> {
            let mut calls = Vec::new();
            while let Ok(call) = self.calls.try_recv() {
                calls.push(call);
            }
            calls
        }

        fn paths(&mut self) -> Vec<String> {
            self.drain().iter().map(|(path, _)| path.clone()).collect()
        }
    }

    /// Signal the graceful shutdown and await the accept task —
    /// bounded so a wedged listener fails the test instead of
    /// hanging the suite. Dropping without `shutdown` aborts as the
    /// panic-path backup; either way no accept or connection task
    /// outlives the test.
    impl MockServer {
        /// Signal the graceful shutdown and await the accept task —
        /// a wedged or panicked listener fails the test, it does not
        /// pass silently: a `JoinError` surfaces the panic, and a
        /// timeout aborts then awaits the owned task so the handle is
        /// genuinely joined before the error reports.
        async fn shutdown(mut self) -> Result<(), String> {
            if let Some(signal) = self.shutdown.take() {
                let _ = signal.send(());
            }
            match tokio::time::timeout(std::time::Duration::from_secs(5), &mut self.task).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(format!("mock server task failed: {error}")),
                Err(_) => {
                    self.task.abort();
                    let _ = (&mut self.task).await;
                    Err("mock server shutdown timed out; task aborted".to_owned())
                }
            }
        }
    }

    /// Dropping an un-shutdown server aborts its accept task — the
    /// panic-path backup; `shutdown` is the graceful path tests take.
    impl Drop for MockServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve(mock: MockEdge) -> MockServer {
        let (calls_tx, calls_rx) = mpsc::channel(MOCK_CALL_BOUND);
        let shared = Arc::new(MockShared {
            edge: mock,
            calls: calls_tx,
            deliver_seq: AtomicU32::new(0),
        });
        let app = axum::Router::new()
            .fallback(axum::routing::any(mock_handler))
            .with_state(shared);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock edge");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("mock edge server");
        });
        MockServer {
            edge: Edge::for_test(format!("http://{addr}")),
            calls: calls_rx,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    /// One entry point for every route: record the call on the
    /// bounded channel, apply the scripted transport failures, then
    /// answer the scripted route.
    async fn mock_handler(
        axum::extract::State(shared): axum::extract::State<Arc<MockShared>>,
        request: axum::extract::Request,
    ) -> axum::response::Response {
        use axum::response::IntoResponse as _;

        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let Ok(body) = axum::body::to_bytes(request.into_body(), 16 * 1024 * 1024).await else {
            return axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response();
        };
        let request_json = serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default();
        let call = format!("{method} {path}");
        // The channel is the whole record — a full one means the test
        // staged more calls than the bound covers, which must fail
        // loud rather than drop a path silently.
        if shared.calls.try_send((call, request_json.clone())).is_err() {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        if shared
            .edge
            .hangup_on
            .iter()
            .any(|suffix| path.ends_with(suffix.as_str()))
        {
            // An aborted response stream — the client's body read
            // fails mid-transfer, the transport-level failure a lost
            // response exercises.
            let stream = futures_util::stream::once(async {
                Err::<axum::body::Bytes, std::io::Error>(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "mock edge hangup",
                ))
            });
            return axum::body::Body::from_stream(stream).into_response();
        }
        if shared.edge.unauthorized {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
        let route = path.strip_prefix("/api/v1/admin/scheduler/demand-feed");
        match (method, route) {
            (_, Some("/status")) => axum::Json(shared.edge.status.clone()).into_response(),
            (axum::http::Method::POST, Some("/begin")) => axum::Json(DemandFeedBeginReport {
                hour: serde_json::from_value(request_json["hour"].clone()).expect("hour"),
                generation: 1,
                stale_pages_pending: false,
            })
            .into_response(),
            (axum::http::Method::POST, Some("/page" | "/complete")) => {
                axum::Json(json!({})).into_response()
            }
            (axum::http::Method::POST, Some("/cleanup")) => axum::Json(DemandFeedCleanupReport {
                hour: serde_json::from_value(request_json["hour"].clone()).expect("hour"),
                retired: 0,
                remaining: false,
            })
            .into_response(),
            (axum::http::Method::POST, Some("/deliver")) => {
                let index = shared.deliver_seq.fetch_add(1, Ordering::Relaxed) as usize;
                let state = shared
                    .edge
                    .deliver_plan
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| "delivered".to_owned());
                let delivered_page = if state == "delivered" {
                    None
                } else {
                    Some(u32::try_from(index).expect("deliver index fits u32"))
                };
                axum::Json(DemandFeedDeliverReport {
                    hour: request_json["hour"].as_str().unwrap_or_default().to_owned(),
                    state,
                    delivered_page,
                    applied: true,
                    touched_tasks: 1,
                    remaining_pages: 0,
                })
                .into_response()
            }
            (axum::http::Method::POST, Some("/query")) => (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                shared.edge.query_body.clone(),
            )
                .into_response(),
            _ => axum::http::StatusCode::NOT_FOUND.into_response(),
        }
    }

    #[tokio::test]
    async fn scripted_transport_stages_freezes_and_delivers() {
        // 520 rows → 256+256+8 entries across three pages; the mock
        // plays the real route set: status → begin → query → 3×page →
        // complete → deliver until delivered → cleanup.
        let rows: Vec<serde_json::Value> = (0..520)
            .map(|n| row(&format!("crate-{n:04}"), &json!(f64::from(n % 7))))
            .collect();
        let mut server = serve(MockEdge::healthy(&rows).delivering(3)).await;
        run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
            .await
            .expect("full pass succeeds");
        let calls = server.drain();
        let paths: Vec<String> = calls.iter().map(|(p, _)| p.clone()).collect();
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
        // Page order, generation and the 256-entry bound all carried
        // on the wire.
        let page_bodies: Vec<&serde_json::Value> = calls
            .iter()
            .filter(|(p, _)| p == "POST /api/v1/admin/scheduler/demand-feed/page")
            .map(|(_, b)| b)
            .collect();
        for (index, body) in page_bodies.iter().enumerate() {
            assert_eq!(body["page_no"], json!(index));
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
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn frozen_hour_resumes_without_a_new_query() {
        // The durable cursor holds a complete hour: only deliver and
        // cleanup run — no begin, no query, no page staging.
        let mut script = MockEdge::healthy(&[]);
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
        let mut server = serve(script.delivering(2)).await;
        run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
            .await
            .expect("resume delivers");
        let paths = server.paths();
        assert!(paths.iter().all(|p| !p.contains("/begin")
            && !p.contains("/query")
            && !p.contains("/page")
            && !p.contains("/complete")));
        assert_eq!(paths[0], "GET /api/v1/admin/scheduler/demand-feed/status");
        assert!(paths.iter().any(|p| p.contains("/deliver")));
        assert!(paths.iter().any(|p| p.contains("/cleanup")));
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn truncated_document_never_freezes() {
        let mut script = MockEdge::healthy(&[row("serde", &json!(1.0))]);
        script.query_body.truncate(script.query_body.len() - 20);
        let mut server = serve(script).await;
        let err = run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
            .await
            .expect_err("truncated body fails");
        drop(err);
        let paths = server.paths();
        assert!(paths.iter().all(|p| !p.contains("/complete")));
        assert!(paths.iter().all(|p| !p.contains("/deliver")));
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn unauthorized_fails_fast() {
        let script = MockEdge {
            unauthorized: true,
            ..MockEdge::healthy(&[])
        };
        let mut server = serve(script).await;
        assert!(
            run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
                .await
                .is_err()
        );
        assert_eq!(server.paths().len(), 1, "status refusal stops the pass");
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn invalid_document_stages_but_never_freezes() {
        // A declared-count mismatch: the parser may stage pages (they
        // are undeliverable in a staging attempt), but `complete` is
        // never called.
        let mut doc = document(&[row("serde", &json!(1.0)), row("anyhow", &json!(2.0))]);
        doc["rows"] = json!(99);
        let mut script = MockEdge::healthy(&[]);
        script.query_body = serde_json::to_vec(&doc).expect("body");
        let mut server = serve(script).await;
        assert!(
            run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
                .await
                .is_err()
        );
        assert!(
            server
                .paths()
                .iter()
                .all(|p| !p.contains("/complete") && !p.contains("/deliver"))
        );
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn stage_failure_with_buffered_pages_finishes() {
        // More rows than the page channel can hold (>4 pages at 256
        // entries): the first page post hangs up, the receiver drops,
        // and the blocked parser unblocks — the run must return under
        // a bounded timeout instead of parking on a full channel.
        let rows: Vec<serde_json::Value> = (0..(4 * 256 + 10))
            .map(|n| row(&format!("crate-{n:04}"), &json!(1.0)))
            .collect();
        let mut script = MockEdge::healthy(&rows);
        script.hangup_on = vec!["/page".to_owned()];
        let mut server = serve(script).await;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            run(&server.edge, DemandFeedArgs { hour: None }, Output::Json),
        )
        .await;
        assert!(
            matches!(outcome, Ok(Err(_))),
            "stage failure must return promptly, got {outcome:?}"
        );
        let paths = server.paths();
        assert!(paths.iter().all(|p| !p.contains("/complete")));
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn stage_failure_on_the_last_page_never_freezes() {
        // Five pages of rows with only the complete-stage POST failing:
        // every earlier page is staged, the freeze is refused, nothing
        // delivers.
        let rows: Vec<serde_json::Value> = (0..(4 * 256 + 8))
            .map(|n| row(&format!("crate-{n:04}"), &json!(1.0)))
            .collect();
        let mut script = MockEdge::healthy(&rows);
        script.hangup_on = vec!["/complete".to_owned()];
        let mut server = serve(script).await;
        assert!(
            run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
                .await
                .is_err()
        );
        let calls = server.drain();
        assert_eq!(calls.iter().filter(|(p, _)| p.contains("/page")).count(), 5);
        assert!(calls.iter().all(|(p, _)| !p.contains("/deliver")));
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn deliver_failure_surfaces_after_the_wave_settles() {
        // A lost response on `deliver`: the whole fan-out wave still
        // settles before the error surfaces — no sibling call is left
        // cancelled, and retirement never runs on a failed leg.
        let rows: Vec<serde_json::Value> = (0..520)
            .map(|n| row(&format!("crate-{n:04}"), &json!(1.0)))
            .collect();
        let mut script = MockEdge::healthy(&rows).delivering(3);
        script.hangup_on = vec!["/deliver".to_owned()];
        let mut server = serve(script).await;
        assert!(
            run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
                .await
                .is_err()
        );
        let paths = server.paths();
        assert_eq!(
            paths.iter().filter(|p| p.contains("/deliver")).count(),
            DELIVER_FANOUT,
            "every launched deliver call was made before the error surfaced"
        );
        assert!(paths.iter().all(|p| !p.contains("/cleanup")));
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn explicit_hour_refuses_to_leap_an_unfinished_hour() {
        // The cursor holds a complete hour; `--hour` naming a
        // different closed hour refuses — it would cross the cursor's
        // order — and nothing runs.
        let mut script = MockEdge::healthy(&[]);
        script.status = json!({
            "watermark": "2020-01-01T04",
            "unfinished": {
                "hour": "2020-01-01T05",
                "state": "complete",
                "generation": 1,
                "staged_pages": 1,
                "staged_entries": 10,
            },
        });
        let mut server = serve(script).await;
        let error = run(
            &server.edge,
            DemandFeedArgs {
                hour: Some("2020-01-01T03".to_owned()),
            },
            Output::Json,
        )
        .await
        .expect_err("explicit hour across unfinished refuses");
        assert!(format!("{error:#}").contains("leap"), "{error:#}");
        let paths = server.paths();
        assert_eq!(paths.len(), 1, "only the status read ran: {paths:?}");
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn explicit_hour_resumes_the_same_unfinished_hour() {
        // `--hour` naming the cursor's unfinished hour resumes its
        // canonical state — a complete hour delivers, no new query.
        let mut script = MockEdge::healthy(&[]);
        script.status = json!({
            "watermark": null,
            "unfinished": {
                "hour": "2020-01-01T05",
                "state": "complete",
                "generation": 1,
                "staged_pages": 1,
                "staged_entries": 10,
            },
        });
        let mut server = serve(script.delivering(1)).await;
        run(
            &server.edge,
            DemandFeedArgs {
                hour: Some("2020-01-01T05".to_owned()),
            },
            Output::Json,
        )
        .await
        .expect("same unfinished hour resumes");
        let paths = server.paths();
        assert!(paths.iter().any(|p| p.contains("/deliver")));
        assert!(paths.iter().all(|p| !p.contains("/query")));
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn frozen_future_hour_keeps_its_pages_while_the_gap_fills() {
        // The bootstrap-reachable gap: watermark T00 and a complete
        // frozen T04. The cursor's next hour is T01 — the run
        // materializes T01 and never touches T04's begin/query/deliver.
        let mut script = MockEdge::healthy(&[row("crate-0000", &json!(1.0))]);
        script.status = json!({
            "watermark": "2020-01-01T00",
            "unfinished": {
                "hour": "2020-01-01T04",
                "state": "complete",
                "generation": 9,
                "staged_pages": 2,
                "staged_entries": 40,
            },
        });
        let mut server = serve(script.delivering(1)).await;
        run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
            .await
            .expect("the canonical missing hour materializes");
        let calls = server.drain();
        let begin = calls
            .iter()
            .find(|(p, _)| p == "POST /api/v1/admin/scheduler/demand-feed/begin")
            .map(|(_, b)| b)
            .expect("begin ran for the missing hour");
        assert_eq!(begin["hour"], json!("2020-01-01T01"));
        assert!(
            calls.iter().any(|(p, _)| p.contains("/query")),
            "the gap fill queries the demand document"
        );
        for (_, body) in &calls {
            assert_ne!(
                body["hour"],
                json!("2020-01-01T04"),
                "the frozen future hour is never written"
            );
        }
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn explicit_gap_hour_materializes() {
        // `--hour` naming the canonical missing hour is the permitted
        // gap fill — same run as the default cursor, explicit.
        let mut script = MockEdge::healthy(&[row("crate-0000", &json!(1.0))]);
        script.status = json!({
            "watermark": "2020-01-01T00",
            "unfinished": {
                "hour": "2020-01-01T04",
                "state": "complete",
                "generation": 9,
                "staged_pages": 2,
                "staged_entries": 40,
            },
        });
        let mut server = serve(script.delivering(1)).await;
        run(
            &server.edge,
            DemandFeedArgs {
                hour: Some("2020-01-01T01".to_owned()),
            },
            Output::Json,
        )
        .await
        .expect("explicit canonical gap hour materializes");
        let calls = server.drain();
        let begin = calls
            .iter()
            .find(|(p, _)| p == "POST /api/v1/admin/scheduler/demand-feed/begin")
            .map(|(_, b)| b)
            .expect("begin ran");
        assert_eq!(begin["hour"], json!("2020-01-01T01"));
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn frozen_hour_resumes_its_original_pages_after_the_gap_fills() {
        // Once the watermark advances to T03, the still-frozen T04 IS
        // the canonical successor: it delivers its original staged
        // pages — no new query, no restage.
        let mut script = MockEdge::healthy(&[]);
        script.status = json!({
            "watermark": "2020-01-01T03",
            "unfinished": {
                "hour": "2020-01-01T04",
                "state": "complete",
                "generation": 9,
                "staged_pages": 2,
                "staged_entries": 40,
            },
        });
        let mut server = serve(script.delivering(1)).await;
        run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
            .await
            .expect("the reached frozen hour resumes");
        let calls = server.drain();
        let deliver = calls
            .iter()
            .find(|(p, _)| p == "POST /api/v1/admin/scheduler/demand-feed/deliver")
            .map(|(_, b)| b)
            .expect("deliver ran");
        assert_eq!(deliver["hour"], json!("2020-01-01T04"));
        let paths: Vec<&String> = calls.iter().map(|(p, _)| p).collect();
        assert!(
            paths.iter().all(|p| !p.contains("/query")
                && !p.contains("/page")
                && !p.contains("/begin")
                && !p.contains("/complete")),
            "a frozen hour never re-queries or re-stages: {paths:?}"
        );
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn explicit_future_hour_past_the_gap_refuses() {
        // `--hour T04` while the canonical hour is T01 refuses before
        // any begin/query/stage write — the frozen T04's bytes stay
        // exactly as staged.
        let mut script = MockEdge::healthy(&[]);
        script.status = json!({
            "watermark": "2020-01-01T00",
            "unfinished": {
                "hour": "2020-01-01T04",
                "state": "complete",
                "generation": 9,
                "staged_pages": 2,
                "staged_entries": 40,
            },
        });
        let mut server = serve(script).await;
        let error = run(
            &server.edge,
            DemandFeedArgs {
                hour: Some("2020-01-01T04".to_owned()),
            },
            Output::Json,
        )
        .await
        .expect_err("explicit future past the gap refuses");
        assert!(format!("{error:#}").contains("leap"), "{error:#}");
        let paths = server.paths();
        assert_eq!(paths.len(), 1, "only the status read ran: {paths:?}");
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn unfinished_at_or_below_the_watermark_is_inconsistent() {
        // A cursor reporting an unfinished hour the watermark already
        // covers disagrees with itself — refuse rather than guess.
        let mut script = MockEdge::healthy(&[]);
        script.status = json!({
            "watermark": "2020-01-01T04",
            "unfinished": {
                "hour": "2020-01-01T02",
                "state": "complete",
                "generation": 1,
                "staged_pages": 1,
                "staged_entries": 10,
            },
        });
        let mut server = serve(script).await;
        let error = run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
            .await
            .expect_err("stale unfinished refuses");
        assert!(format!("{error:#}").contains("inconsistent"), "{error:#}");
        let paths = server.paths();
        assert_eq!(paths.len(), 1, "only the status read ran: {paths:?}");
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn malformed_explicit_hour_fails_before_any_side_effect() {
        // Even with a frozen unfinished hour the cursor would resume,
        // a malformed `--hour` errors first — the explicit argument is
        // validated before any network side effect.
        let mut script = MockEdge::healthy(&[]);
        script.status = json!({
            "watermark": null,
            "unfinished": {
                "hour": "2020-01-01T05",
                "state": "complete",
                "generation": 1,
                "staged_pages": 1,
                "staged_entries": 10,
            },
        });
        let mut server = serve(script).await;
        let error = run(
            &server.edge,
            DemandFeedArgs {
                hour: Some("not-an-hour".to_owned()),
            },
            Output::Json,
        )
        .await
        .expect_err("malformed --hour refuses");
        assert!(format!("{error:#}").contains("--hour"), "{error:#}");
        assert!(
            server.paths().is_empty(),
            "no side effect before validation"
        );
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn unfinished_explicit_hour_fails_before_any_side_effect() {
        // An explicit hour that has not closed refuses even though
        // the cursor could have served one.
        let mut server = serve(MockEdge::healthy(&[])).await;
        assert!(
            run(
                &server.edge,
                DemandFeedArgs {
                    hour: Some("2999-01-01T00".to_owned()),
                },
                Output::Json,
            )
            .await
            .is_err()
        );
        assert_eq!(server.paths(), Vec::<String>::new());
        server.shutdown().await.expect("mock server shutdown");
    }

    #[tokio::test]
    async fn unknown_unfinished_state_is_an_error() {
        // An unfinished row in a state this build does not know is an
        // error — never a silent re-materialize.
        let mut script = MockEdge::healthy(&[]);
        script.status = json!({
            "watermark": null,
            "unfinished": {
                "hour": "2020-01-01T05",
                "state": "mysterious",
                "generation": 1,
                "staged_pages": 1,
                "staged_entries": 10,
            },
        });
        let server = serve(script).await;
        let error = run(&server.edge, DemandFeedArgs { hour: None }, Output::Json)
            .await
            .expect_err("unknown state refuses");
        assert!(format!("{error:#}").contains("unknown state"), "{error:#}");
        server.shutdown().await.expect("mock server shutdown");
    }
}
