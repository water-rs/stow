//! The hourly demand feed's state machine (stow#523), held in the
//! scheduler graph's `feed_sessions` and moved by `Feed` events
//! (stow#878).
//!
//! `stow-admin scheduler demand-feed` materializes one closed
//! Analytics Engine hour into bounded staged pages, freezes the whole
//! response at a single completion barrier, and then delivers the
//! frozen pages into the demand ledger (stow#522) one
//! `demand-feed/{hour}/{page_no}` batch at a time. Every function here
//! is a pure read of the graph that answers with the event the route
//! appends and applies; nothing here touches storage.
//!
//! - `begin` opens the `staging` attempt — or, on a staging hour,
//!   rotates it: the generation bumps and the staged pages clear in the
//!   apply, so a restarted materialization is a fresh attempt whose
//!   bytes can never merge into the abandoned one's. A `begin` on a
//!   frozen hour — or at or below the delivered watermark — refuses: a
//!   complete hour is never re-queried.
//! - `page` stages one bounded immutable payload (at most
//!   `DEMAND_FEED_PAGE_MAX_ENTRIES` entries, `DEMAND_FEED_PAGE_MAX_BYTES`
//!   for the whole encoded request). Pages stage strictly in order
//!   under the attempt generation, and each carries a rolling blake3
//!   chain over the page hashes, so the completion barrier binds the
//!   frozen set to one ordered manifest. A replay of an already-staged
//!   page is a no-op only when its hash matches byte-for-byte; a
//!   changed payload refuses.
//! - `complete` is the single barrier: `staging` + generation +
//!   declared page and entry totals + the chain's last hash equal to
//!   the materializer's manifest.
//! - `deliver` replays the next unapplied page verbatim: the frozen
//!   bytes, never a fresh AE answer. The ledger's batch dedup makes a
//!   redelivered page a zero-fold replay, and the page's `applied`
//!   cursor advances with the fold. With every page acknowledged the
//!   call emits the `delivered` transition, which requires this hour
//!   to be the canonical successor of the watermark (or the first ever
//!   delivered) and stamps the monotonic watermark.
//! - `cleanup` expires a delivered hour's session; abandoned
//!   generations never outlive their `begin` rotation.
//! - `status` is the durable resume cursor: the oldest unfinished hour
//!   plus the watermark.

use stow_types::api::{
    DEMAND_FEED_BATCH_PREFIX, DEMAND_FEED_PAGE_MAX_BYTES, DEMAND_FEED_PAGE_MAX_ENTRIES,
    DemandFeedBeginReport, DemandFeedCleanupReport, DemandFeedCompleteRequest,
    DemandFeedDeliverReport, DemandFeedHour, DemandFeedPageRequest, DemandFeedStatus,
    DemandFeedUnfinished, SchedulerDemandRequest, SchedulerEvent,
};

use super::graph::Graph;
use super::queue::{self, AlarmPlan, SchedulerSettings};
use crate::errors::QueueError;

/// Reject a begin that is not the watermark's canonical successor.
/// Once any hour has delivered, the only admissible new attempt —
/// fresh insert or staging rotation alike — is the hour immediately
/// after the cursor: an out-of-order begin would freeze demand the
/// cursor can never pass, and wedging it below a gap blocks the
/// genuine successor's recovery. One point read, no history scan.
fn require_canonical_successor(graph: &Graph, hour: &DemandFeedHour) -> Result<(), QueueError> {
    let Some(watermark) = &graph.feed_watermark else {
        return Ok(());
    };
    let watermark = watermark.clone();
    let watermark_hour = DemandFeedHour::parse(&watermark).map_err(|error| {
        QueueError::Invariant(format!(
            "demand feed watermark {watermark:?} is not a canonical hour: {error}"
        ))
    })?;
    let successor = watermark_hour.next().map_err(QueueError::Invariant)?;
    if hour != &successor {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {hour} is not the watermark's canonical successor {successor} — earlier hours must finish first"
        )));
    }
    Ok(())
}

/// `GET /demand-feed/status` — the resume cursor: the delivered
/// watermark plus the oldest unfinished hour.
pub fn feed_status(graph: &Graph) -> DemandFeedStatus {
    let unfinished = graph
        .feed_sessions
        .iter()
        .find(|(_, session)| session.state != "delivered")
        .map(|(hour, session)| DemandFeedUnfinished {
            hour: hour.clone(),
            state: session.state.clone(),
            generation: session.generation,
            staged_pages: i64::from(session.staged_pages),
            staged_entries: i64::from(session.staged_entries),
        });
    DemandFeedStatus {
        watermark: graph.feed_watermark.clone(),
        unfinished,
    }
}

/// `POST /demand-feed/begin` — open or resume the staging attempt.
/// A frozen hour refuses — once complete, the hour's input is final —
/// and an hour at or below the watermark can never re-materialize. A
/// staging hour rotates: the generation bumps and the apply clears the
/// abandoned attempt's pages.
pub fn feed_begin(
    graph: &Graph,
    hour: &DemandFeedHour,
    now_unix_secs: i64,
) -> Result<(DemandFeedBeginReport, SchedulerEvent), QueueError> {
    hour.ensure_closed(now_unix_secs)
        .map_err(QueueError::Invariant)?;
    require_canonical_successor(graph, hour)?;
    let generation = match graph.feed_sessions.get(hour.as_str()) {
        Some(session) if session.state == "staging" => session.generation + 1,
        Some(session) => {
            return Err(QueueError::Invariant(format!(
                "demand feed hour {hour} is {}; frozen hours never re-materialize",
                session.state
            )));
        }
        None => now_unix_secs,
    };
    let event = SchedulerEvent::Feed {
        hour: hour.as_str().to_owned(),
        kind: stow_types::api::FeedEvent::Begin { generation },
    };
    Ok((
        DemandFeedBeginReport {
            hour: hour.clone(),
            generation,
            // The apply's reset clears the abandoned generation's
            // staging wholesale — there is no stored chunk left over.
            stale_pages_pending: false,
        },
        event,
    ))
}

/// `POST /demand-feed/page` — stage one bounded immutable page under
/// the attempt generation. The whole encoded request must fit the
/// byte bound — a large feature list simply makes more pages — and
/// pages stage strictly in order: `page_no` may not exceed the
/// session's `staged_pages`, so a late or skipped page can never slot
/// into a frozen-in-progress manifest. A replayed page (`page_no` <
/// `staged_pages`) answers no event when its stored hash matches;
/// changed bytes refuse.
pub fn feed_page(
    graph: &Graph,
    request: &DemandFeedPageRequest,
    now_unix_secs: i64,
) -> Result<Option<SchedulerEvent>, QueueError> {
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
    let Some(session) = graph.feed_sessions.get(request.hour.as_str()) else {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {} has no open attempt — begin first",
            request.hour
        )));
    };
    if session.state != "staging" {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {} is {}; staged pages are immutable once frozen",
            request.hour, session.state
        )));
    }
    if session.generation != request.generation {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {} attempt is generation {}, not {}",
            request.hour, session.generation, request.generation
        )));
    }
    if request.page_no > session.staged_pages {
        return Err(QueueError::Invariant(format!(
            "demand feed page {}/{} arrives out of order; {} pages are staged",
            request.hour, request.page_no, session.staged_pages
        )));
    }
    let page_hash = stow_types::api::demand_feed_page_hash(&request.entries)
        .map_err(|error| {
            QueueError::Invariant(format!(
                "hash demand feed page {}/{}: {error}",
                request.hour, request.page_no
            ))
        })?
        .to_hex()
        .to_string();
    if request.page_no < session.staged_pages {
        // Replay: the stored page's hash must match exactly — the
        // apply already proved the page immutable; a mismatch refuses.
        return match session.page_hashes.get(request.page_no as usize) {
            Some(existing) if existing == &page_hash => Ok(None),
            Some(_) => Err(QueueError::Invariant(format!(
                "demand feed page {}/{} is immutable: the staged payload differs",
                request.hour, request.page_no
            ))),
            None => Err(QueueError::Invariant(format!(
                "demand feed page {}/{} counted but absent",
                request.hour, request.page_no
            ))),
        };
    }
    Ok(Some(SchedulerEvent::Feed {
        hour: request.hour.as_str().to_owned(),
        kind: stow_types::api::FeedEvent::Page {
            generation: request.generation,
            page_no: request.page_no,
            entries: request.entries.clone(),
        },
    }))
}

/// `POST /demand-feed/complete` — the single completion barrier: the
/// staged counters and the ordered chain hash are checked against the
/// materializer's declared totals, so a session can never claim
/// completeness its pages do not prove. Anything short of an exact
/// match is a staging-incomplete, wrong-generation or wrong-manifest
/// refusal.
pub fn feed_complete(
    graph: &Graph,
    request: &DemandFeedCompleteRequest,
    now_unix_secs: i64,
) -> Result<SchedulerEvent, QueueError> {
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
    let Some(session) = graph.feed_sessions.get(request.hour.as_str()) else {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {} was never staged",
            request.hour
        )));
    };
    let manifest_ok = request.page_count == 0
        || session
            .chain_hashes
            .get(request.page_count as usize - 1)
            .is_some_and(|chain| chain == &request.manifest_hash);
    if session.state != "staging"
        || session.generation != request.generation
        || session.staged_pages != request.page_count
        || i64::from(session.staged_entries) != entry_count
        || !manifest_ok
    {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {} generation {} refused completion: staging incomplete, wrong generation, or manifest mismatch",
            request.hour, request.generation
        )));
    }
    Ok(SchedulerEvent::Feed {
        hour: request.hour.as_str().to_owned(),
        kind: stow_types::api::FeedEvent::Complete {
            generation: request.generation,
        },
    })
}

/// Whether `hour` is already delivered. `deliver` only ever stamps the
/// canonical successor, so the watermark is a contiguous cursor: an
/// hour at or below it was delivered — and its session may already be
/// expired, `cleanup`'s `Expire` removing the `feed_sessions` entry
/// wholesale. The watermark is the delivered proof that survives
/// expiry, so replay answers consult it rather than the session.
fn already_delivered(graph: &Graph, hour: &DemandFeedHour) -> bool {
    graph
        .feed_watermark
        .as_deref()
        .is_some_and(|watermark| hour.as_str() <= watermark)
}

/// The terminal no-op a delivered hour answers to a `deliver` replay —
/// whether the session still sits `delivered` or `cleanup` already
/// expired it.
fn delivered_report(hour: &DemandFeedHour) -> DemandFeedDeliverReport {
    DemandFeedDeliverReport {
        hour: hour.to_string(),
        state: "delivered".to_owned(),
        delivered_page: None,
        applied: false,
        touched_tasks: 0,
        remaining_pages: 0,
    }
}

/// `POST /demand-feed/deliver` — one bounded page of work: the next
/// unapplied page replays verbatim into the demand ledger as batch
/// `demand-feed/{hour}/{page_no}`, its `applied` cursor advancing with
/// the same events — a lost ack re-arms the same page, which the
/// ledger's batch dedup answers as a zero-fold replay. With no
/// unapplied page left, the call emits the terminal `Deliver`, which
/// requires watermark contiguity — this hour must be the canonical
/// successor of the cursor (or the first delivered hour ever).
///
/// Returns the deliver report, the events to append, and the alarm
/// plan the shared pass decided — the caller arms it exactly like
/// `/demand` does.
pub fn feed_deliver(
    graph: &Graph,
    hour: &DemandFeedHour,
    now_ms: i64,
    settings: &SchedulerSettings,
) -> Result<(DemandFeedDeliverReport, Vec<SchedulerEvent>, AlarmPlan), QueueError> {
    hour.ensure_closed(now_ms / 1_000)
        .map_err(QueueError::Invariant)?;
    let plan = |graph: &Graph| graph.wake_plan(now_ms, settings);
    let Some(session) = graph.feed_sessions.get(hour.as_str()) else {
        // A session absent at or below the watermark was delivered and
        // expired: the replay answers the same no-op a still-present
        // `delivered` session does — the contract the lost-ack retry
        // needs. Anything else is a genuine never-staged refusal.
        return if already_delivered(graph, hour) {
            Ok((delivered_report(hour), Vec::new(), plan(graph)))
        } else {
            Err(QueueError::Invariant(format!(
                "demand feed hour {hour} was never staged"
            )))
        };
    };
    if session.state == "staging" {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {hour} is still staging — only complete hours deliver"
        )));
    }
    if session.state == "delivered" {
        return Ok((delivered_report(hour), Vec::new(), plan(graph)));
    }
    require_canonical_successor(graph, hour)?;
    if let Some((older, _)) = graph
        .feed_sessions
        .iter()
        .find(|(other, session)| other.as_str() < hour.as_str() && session.state != "delivered")
    {
        return Err(QueueError::Invariant(format!(
            "demand feed hour {hour} cannot deliver while {older} is unfinished"
        )));
    }
    let next_page = session.applied_pages as usize;
    if next_page < session.staged.len() {
        // One page per call — the page's entries fold through a
        // `Demand` batch (`demand-feed/{hour}/{page_no}`), whose
        // `demand_batches` dedup makes a redelivered page a no-op;
        // the paired `ApplyPage` advances the cursor either way —
        // the original delivery already folded the demand.
        let request = SchedulerDemandRequest {
            batch_id: format!("{DEMAND_FEED_BATCH_PREFIX}{hour}/{next_page}"),
            entries: session.staged[next_page].clone(),
        };
        let (report, demand_event, _plan) = queue::demand_pass(graph, &request, now_ms, settings)?;
        let mut events = Vec::new();
        if let Some(event) = demand_event {
            events.push(event);
        }
        events.push(SchedulerEvent::Feed {
            hour: hour.as_str().to_owned(),
            kind: stow_types::api::FeedEvent::ApplyPage {
                page_no: u32::try_from(next_page).unwrap_or(u32::MAX),
            },
        });
        let remaining = u64::from(
            u32::try_from(session.staged.len()).unwrap_or(u32::MAX) - (session.applied_pages + 1),
        );
        return Ok((
            DemandFeedDeliverReport {
                hour: hour.to_string(),
                state: "complete".to_owned(),
                delivered_page: Some(u32::try_from(next_page).unwrap_or(u32::MAX)),
                applied: report.applied,
                touched_tasks: report.touched_tasks,
                remaining_pages: remaining,
            },
            events,
            plan(graph),
        ));
    }
    // Every page acknowledged — the terminal `Deliver` stamps the
    // watermark through the apply.
    let events = vec![SchedulerEvent::Feed {
        hour: hour.as_str().to_owned(),
        kind: stow_types::api::FeedEvent::Deliver {
            generation: session.generation,
        },
    }];
    Ok((
        DemandFeedDeliverReport {
            hour: hour.to_string(),
            state: "delivered".to_owned(),
            delivered_page: None,
            applied: false,
            touched_tasks: 0,
            remaining_pages: 0,
        },
        events,
        plan(graph),
    ))
}

/// `POST /demand-feed/cleanup` — expire a `delivered` hour's session.
/// A staging hour has nothing to retire: the `begin` rotation already
/// cleared the abandoned generation. Explicit event work; nothing
/// schedules it.
pub fn feed_cleanup(
    graph: &Graph,
    hour: &DemandFeedHour,
    now_unix_secs: i64,
) -> Result<(DemandFeedCleanupReport, Option<SchedulerEvent>), QueueError> {
    hour.ensure_closed(now_unix_secs)
        .map_err(QueueError::Invariant)?;
    let Some(session) = graph.feed_sessions.get(hour.as_str()) else {
        // A replayed cleanup of a delivered-and-expired hour has
        // nothing left to retire — the watermark proves the delivery
        // the session row no longer records.
        if already_delivered(graph, hour) {
            return Ok((
                DemandFeedCleanupReport {
                    hour: hour.clone(),
                    retired: 0,
                    remaining: false,
                },
                None,
            ));
        }
        return Err(QueueError::Invariant(format!(
            "demand feed hour {hour} was never staged"
        )));
    };
    if session.state == "delivered" {
        let retired = u64::from(session.page_count);
        let event = SchedulerEvent::Feed {
            hour: hour.as_str().to_owned(),
            kind: stow_types::api::FeedEvent::Expire,
        };
        return Ok((
            DemandFeedCleanupReport {
                hour: hour.clone(),
                retired,
                remaining: false,
            },
            Some(event),
        ));
    }
    // A staging hour's Begin reset already retired the abandoned
    // generation's pages — nothing stale remains to drain.
    Ok((
        DemandFeedCleanupReport {
            hour: hour.clone(),
            retired: 0,
            remaining: false,
        },
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::{feed_begin, feed_cleanup, feed_complete, feed_deliver, feed_page, feed_status};
    use crate::errors::QueueError;
    use crate::scheduler::graph::{FeedSession, Graph};
    use crate::scheduler::queue::{Dispatch, SchedulerSettings};
    use stow_types::api::{
        DemandFeedCompleteRequest, DemandFeedDeliverReport, DemandFeedHour, DemandFeedPageRequest,
        EnqueueRequest, EnqueueSource, SchedulerDemandEntry, demand_feed_manifest,
        demand_feed_page_hash,
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
    /// same serialized page bytes the graph stages.
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

    /// `feed_begin`, applied the way a route does: the guard answers,
    /// the event applies. Returns the attempt generation.
    fn begin(g: &mut Graph, hour: &DemandFeedHour) -> Result<i64, QueueError> {
        let (report, event) = feed_begin(g, hour, NOW_SECS)?;
        g.apply(&event, NOW_MS);
        Ok(report.generation)
    }

    /// `feed_page`, applied: a replayed page answers no event.
    fn stage(g: &mut Graph, request: &DemandFeedPageRequest) -> Result<(), QueueError> {
        if let Some(event) = feed_page(g, request, NOW_SECS)? {
            g.apply(&event, NOW_MS);
        }
        Ok(())
    }

    /// `feed_complete`, applied.
    fn freeze(g: &mut Graph, request: &DemandFeedCompleteRequest) -> Result<(), QueueError> {
        let event = feed_complete(g, request, NOW_SECS)?;
        g.apply(&event, NOW_MS);
        Ok(())
    }

    /// One `feed_deliver` call, its events applied in order.
    fn deliver(
        g: &mut Graph,
        hour: &DemandFeedHour,
    ) -> Result<DemandFeedDeliverReport, QueueError> {
        let (report, events, _) = feed_deliver(g, hour, NOW_MS, &settings())?;
        for event in &events {
            g.apply(event, NOW_MS);
        }
        Ok(report)
    }

    /// Open `hour`, stage `pages` in order, and freeze it. Returns the
    /// attempt generation.
    fn stage_and_freeze(
        g: &mut Graph,
        hour: &DemandFeedHour,
        pages: &[Vec<SchedulerDemandEntry>],
    ) -> i64 {
        let generation = begin(g, hour).expect("begin");
        for (index, entries) in pages.iter().enumerate() {
            let index = u32::try_from(index).expect("test page index");
            stage(g, &page(hour, generation, index, entries.clone())).expect("page");
        }
        freeze(g, &complete(hour, generation, pages)).expect("complete");
        generation
    }

    /// Alpha's node merged straight onto the graph — the task the
    /// demand fold reaches.
    fn enqueue_alpha(g: &mut Graph) {
        let tree = stow_types::api::SubmissionTree::from_enqueue_requests(
            stow_types::api::SubmissionSource::CacheMiss,
            &[EnqueueRequest {
                dependency_subgraph: stow_types::api::TaskSubgraph {
                    root_deps: Vec::new(),
                    nodes: Vec::new(),
                },
                crate_name: "alpha".parse().expect("alpha crate"),
                version: "1.0.0".parse().expect("alpha version"),
                features_json: FeaturesJson::default(),
                target: "x86_64-unknown-linux-gnu".parse().expect("target"),
                rustc_version: "1.85.0".parse().expect("rustc"),
                downloads: 0,
                source: EnqueueSource::CacheMiss,
                preserve_lockfile: false,
                host_side: false,
                explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            }],
        )
        .expect("alpha tree");
        g.merge(&tree, 0).expect("merge alpha");
    }

    /// No page of `hour` applied and no ledger batch of it exists.
    fn feed_writes_absent(g: &Graph, hour: &DemandFeedHour) -> bool {
        let unapplied = g
            .feed_sessions
            .get(hour.as_str())
            .is_none_or(|session| session.applied_pages == 0);
        let prefix = format!("demand-feed/{}/", hour.as_str());
        unapplied && !g.demand_batches.keys().any(|id| id.starts_with(&prefix))
    }

    /// Complete and deliver the canonical chain h2 → h3 → h3b → h4 —
    /// each stage advancing the watermark to the expected hour.
    fn finish_predecessors(g: &mut Graph, h2: &DemandFeedHour, g2: i64, h4: &DemandFeedHour) {
        freeze(g, &complete(h2, g2, &[])).expect("complete h2");
        deliver_all(g, h2, 0);
        assert_eq!(watermark(g).as_deref(), Some(H2));
        let h3 = hour("2026-01-01T02");
        stage_and_freeze(g, &h3, &[]);
        deliver_all(g, &h3, 0);
        assert_eq!(watermark(g).as_deref(), Some("2026-01-01T02"));
        let h3b = hour("2026-01-01T03");
        stage_and_freeze(g, &h3b, &[]);
        deliver_all(g, &h3b, 0);
        assert_eq!(watermark(g).as_deref(), Some("2026-01-01T03"));
        deliver_all(g, h4, 1);
    }

    /// Stage a complete hour under an inserted session — exercises the
    /// deliver-side guards on pre-existing out-of-order data that a
    /// refused begin cannot produce.
    fn seed_complete_hour(
        g: &mut Graph,
        hour: &DemandFeedHour,
        generation: i64,
        pages: &[Vec<SchedulerDemandEntry>],
    ) {
        g.feed_sessions.insert(
            hour.as_str().to_owned(),
            FeedSession {
                generation,
                state: "staging".to_owned(),
                staged_pages: 0,
                staged_entries: 0,
                applied_pages: 0,
                page_count: 0,
                entry_count: 0,
                staged: Vec::new(),
                page_hashes: Vec::new(),
                chain_hashes: Vec::new(),
            },
        );
        for (i, entries) in pages.iter().enumerate() {
            let index = u32::try_from(i).expect("page index");
            stage(g, &page(hour, generation, index, entries.clone())).expect("stage page");
        }
        freeze(g, &complete(hour, generation, pages)).expect("freeze hour");
    }

    /// Deliver every page of a frozen hour plus the terminal call.
    fn deliver_all(g: &mut Graph, hour: &DemandFeedHour, pages: u32) {
        for page_no in 0..pages {
            let report = deliver(g, hour).expect("deliver");
            assert_eq!(report.delivered_page, Some(page_no));
            assert_eq!(report.state, "complete");
        }
        let report = deliver(g, hour).expect("terminal deliver");
        assert_eq!(report.state, "delivered");
        assert_eq!(report.delivered_page, None);
    }

    fn watermark(g: &Graph) -> Option<String> {
        g.feed_watermark.clone()
    }

    fn applied_pages(g: &Graph, hour: &str) -> u32 {
        g.feed_sessions
            .get(hour)
            .map_or(0, |session| session.applied_pages)
    }

    /// A rotated attempt freezes only its own generation: the stale
    /// materializer's pages and completion refuse by generation, and
    /// the frozen hour delivers exactly the new attempt's ordered pages.
    #[test]
    fn restarted_attempt_cannot_mix_pages() {
        let mut g = Graph::default();
        let h = hour(H1);
        let pages_a = vec![vec![entry("alpha", 1)]];
        let g1 = begin(&mut g, &h).expect("begin a");
        stage(&mut g, &page(&h, g1, 0, pages_a[0].clone())).expect("a page 0");
        // Materializer B begins — a restart, not a merge.
        let g2 = begin(&mut g, &h).expect("begin b");
        assert_ne!(g1, g2, "a resumed begin must rotate the generation");
        // A's stale requests fail on the generation check.
        stage(&mut g, &page(&h, g1, 0, pages_a[0].clone())).expect_err("stale generation page");
        freeze(&mut g, &complete(&h, g1, &pages_a)).expect_err("stale generation complete");
        // B freezes its own two pages.
        let pages_b = vec![vec![entry("gamma", 1)], vec![entry("delta", 1)]];
        stage(&mut g, &page(&h, g2, 0, pages_b[0].clone())).expect("b page 0");
        stage(&mut g, &page(&h, g2, 1, pages_b[1].clone())).expect("b page 1");
        freeze(&mut g, &complete(&h, g2, &pages_b)).expect("b complete");
        assert_eq!(
            g.feed_sessions[H1].staged, pages_b,
            "only B's pages survive the rotation"
        );
        deliver_all(&mut g, &h, 2);
        assert!(
            g.demand_batches.contains_key("demand-feed/2026-01-01T00/1"),
            "B's second page folded"
        );
    }

    /// Same-page replay is a no-op only byte-for-byte; changed bytes
    /// on a staged page refuse — staged input is immutable.
    #[test]
    fn staged_page_replays_identically_and_refuses_change() {
        let mut g = Graph::default();
        let h = hour(H1);
        let generation = begin(&mut g, &h).expect("begin");
        let entries = vec![entry("alpha", 1)];
        stage(&mut g, &page(&h, generation, 0, entries.clone())).expect("stage");
        stage(&mut g, &page(&h, generation, 0, entries)).expect("identical replay is a no-op");
        stage(&mut g, &page(&h, generation, 0, vec![entry("omega", 2)]))
            .expect_err("changed payload on a staged page refuses");
        // A skipped page can never slot in ahead of the sequence.
        stage(&mut g, &page(&h, generation, 2, vec![entry("late", 1)]))
            .expect_err("out-of-order page refuses");
        assert_eq!(g.feed_sessions[H1].staged_pages, 1);
    }

    /// The completion barrier refuses while staging is incomplete or
    /// the declared manifest does not match the staged chain — the
    /// hour stays undeliverable.
    #[test]
    fn freeze_requires_full_manifest() {
        let mut g = Graph::default();
        let h = hour(H1);
        let pages = vec![vec![entry("alpha", 1)], vec![entry("beta", 1)]];
        let generation = begin(&mut g, &h).expect("begin");
        stage(&mut g, &page(&h, generation, 0, pages[0].clone())).expect("page 0");
        // Page 1 never staged: every freeze attempt refuses, the hour
        // is undeliverable.
        freeze(&mut g, &complete(&h, generation, &pages))
            .expect_err("missing page refuses completion");
        deliver(&mut g, &h).expect_err("staging hour never delivers");
        // A forged manifest refuses too.
        let mut forged = complete(&h, generation, &pages[..1]);
        forged.manifest_hash = "0".repeat(64);
        freeze(&mut g, &forged).expect_err("wrong manifest refuses");
        let mut wrong_count = complete(&h, generation, &pages[..1]);
        wrong_count.entry_count += 1;
        freeze(&mut g, &wrong_count).expect_err("wrong entry total refuses");
        // The declared manifest of the staged set accepts.
        freeze(&mut g, &complete(&h, generation, &pages[..1]))
            .expect("manifest of staged set completes");
        assert_eq!(g.feed_sessions[H1].state, "complete");
    }

    /// A delivered page's ack lands exactly once: a repeated
    /// `ApplyPage` never recounts, and a page whose ack was lost
    /// redelivers as the ledger's accepted batch, folding nothing.
    #[test]
    fn acknowledged_page_counts_once_and_replays_verbatim() {
        let mut g = Graph::default();
        let h = hour(H1);
        let pages = vec![vec![entry("alpha", 1)], vec![entry("beta", 1)]];
        stage_and_freeze(&mut g, &h, &pages);
        let (first, events, _) = feed_deliver(&g, &h, NOW_MS, &settings()).expect("deliver page 0");
        assert_eq!(first.delivered_page, Some(0));
        assert!(first.applied, "first delivery accepts the batch");
        // Only the demand fold lands; the ack is lost.
        let demand = events
            .iter()
            .find(|event| matches!(event, stow_types::api::SchedulerEvent::Demand { .. }))
            .expect("demand event");
        g.apply(demand, NOW_MS);
        assert_eq!(applied_pages(&g, H1), 0);
        // The redelivery finds the batch accepted: same frozen bytes,
        // zero fold.
        let (replay, events, _) =
            feed_deliver(&g, &h, NOW_MS, &settings()).expect("lost-ack redelivery");
        assert_eq!(replay.delivered_page, Some(0));
        assert!(!replay.applied, "same bytes replay as the accepted batch");
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, stow_types::api::SchedulerEvent::Demand { .. })),
            "a replay never folds again"
        );
        for event in &events {
            g.apply(event, NOW_MS);
        }
        assert_eq!(applied_pages(&g, H1), 1);
        // A repeated ack of the same page is a no-op, never a double.
        let ack = stow_types::api::SchedulerEvent::Feed {
            hour: H1.to_owned(),
            kind: stow_types::api::FeedEvent::ApplyPage { page_no: 0 },
        };
        g.apply(&ack, NOW_MS);
        assert_eq!(applied_pages(&g, H1), 1, "duplicate ack never doubles");
        let second = deliver(&mut g, &h).expect("deliver page 1");
        assert_eq!(second.delivered_page, Some(1));
        let terminal = deliver(&mut g, &h).expect("terminal");
        assert_eq!(terminal.state, "delivered");
    }

    /// The watermark moves only to the canonical next hour — a
    /// finished hour cannot deliver past an unfinished predecessor,
    /// cannot leap over a missing hour, and never moves backwards.
    #[test]
    fn watermark_requires_canonical_succession() {
        let mut g = Graph::default();
        let h1 = hour(H1);
        let h2 = hour(H2);
        let h4 = hour(H4);
        let page1 = vec![vec![entry("alpha", 1)]];
        // h2 finishes while h1 is still staging: delivery refuses
        // before a single page applies — the cursor may not pass h1,
        // and no demand may land out of order.
        let g1 = begin(&mut g, &h1).expect("begin h1");
        stage_and_freeze(&mut g, &h2, &page1);
        deliver(&mut g, &h2).expect_err("unfinished predecessor blocks delivery");
        assert_eq!(watermark(&g), None);
        // h1 delivers first — the bootstrap hour — then h2 follows
        // canonically. h1 completes as the empty hour it staged.
        freeze(&mut g, &complete(&h1, g1, &[])).expect("complete empty h1");
        deliver_all(&mut g, &h1, 0);
        assert_eq!(watermark(&g).as_deref(), Some(H1));
        let report = deliver(&mut g, &h2).expect("deliver h2 page");
        assert_eq!(report.delivered_page, Some(0));
        let terminal = deliver(&mut g, &h2).expect("h2 terminal");
        assert_eq!(terminal.state, "delivered");
        assert_eq!(watermark(&g).as_deref(), Some(H2));
        // h4's begin refuses as non-canonical, so seed the session
        // directly to prove the terminal guard still cannot leap over
        // missing h3 either.
        begin(&mut g, &h4).expect_err("non-canonical begin refuses");
        seed_complete_hour(&mut g, &h4, 7, &page1);
        // The deliver-side canonical check refuses before the first
        // page applies — no demand or acknowledgment may land.
        deliver(&mut g, &h4).expect_err("non-canonical delivery refuses before demand");
        assert_eq!(
            applied_pages(&g, h4.as_str()),
            0,
            "non-canonical delivery applied a page"
        );
        assert_eq!(watermark(&g).as_deref(), Some(H2));
        // An hour at or below the cursor can never re-materialize.
        begin(&mut g, &h1).expect_err("begin below the watermark refuses");
        begin(&mut g, &h2).expect_err("begin at the watermark refuses");
    }

    /// Two nonempty out-of-order hours: a begin that is not the
    /// watermark's successor refuses before staging a single page —
    /// no frozen wedge blocks the genuine successor, and a complete
    /// hour refuses to deliver while any older hour is unfinished, so
    /// no demand mutates the ledger out of order.
    #[test]
    fn out_of_order_hours_never_mutate() {
        let mut g = Graph::default();
        let h1 = hour(H1);
        let h2 = hour(H2);
        let h3 = hour("2026-01-01T02");
        let h4 = hour(H4);
        let page = vec![vec![entry("alpha", 1)]];
        // A real queued task the h4 page's demand folds into.
        enqueue_alpha(&mut g);
        // The reachable pre-staged state: h4 stages and freezes during
        // bootstrap while NO watermark exists, alongside the genuinely
        // earlier h1.
        stage_and_freeze(&mut g, &h1, &page);
        stage_and_freeze(&mut g, &h4, &page);
        deliver_all(&mut g, &h1, 1);
        assert_eq!(watermark(&g).as_deref(), Some(H1));
        let batches_before = g.demand_batches.clone();
        // The leap: h3 is not the canonical successor — begin refuses
        // before a session exists or a page stages.
        begin(&mut g, &h3).expect_err("begin past the canonical successor refuses");
        assert!(
            !g.feed_sessions.contains_key(h3.as_str()),
            "refused begin left a session"
        );
        // h4 is complete, yet h2/h3 have NO sessions: the canonical
        // successor guard refuses before any page/demand/ack event.
        deliver(&mut g, &h4).expect_err("non-canonical delivery refuses before writes");
        assert!(
            feed_writes_absent(&g, &h4),
            "refused delivery applied a page or wrote a ledger batch"
        );
        assert_eq!(
            g.demand_batches, batches_before,
            "refused delivery moved the ledger"
        );
        // The missing predecessors then materialize and deliver in
        // order; the frozen original page succeeds exactly once.
        let g2 = begin(&mut g, &h2).expect("begin canonical h2");
        finish_predecessors(&mut g, &h2, g2, &h4);
        assert_eq!(watermark(&g).as_deref(), Some(H4));
        let accepted = g
            .demand_batches
            .get("demand-feed/2026-01-01T04/0")
            .expect("h4 batch accepted");
        assert_eq!(accepted.1, 1, "h4 page touched alpha exactly once");
        // A delivered replay stays the early no-op.
        let replay = deliver(&mut g, &h4).expect("delivered replay");
        assert!(!replay.applied, "delivered replay reapplied");
        assert_eq!(g.demand_batches.len(), batches_before.len() + 1);
    }

    /// `cleanup` expires a delivered hour's session and leaves the
    /// watermark; a staging hour has nothing to retire.
    #[test]
    fn cleanup_expires_delivered_sessions_only() {
        let mut g = Graph::default();
        let h = hour(H1);
        let generation = begin(&mut g, &h).expect("begin");
        let (report, event) = feed_cleanup(&g, &h, NOW_SECS).expect("staging cleanup");
        assert_eq!(report.retired, 0);
        assert!(!report.remaining);
        assert!(event.is_none(), "a staging hour retires nothing");
        freeze(&mut g, &complete(&h, generation, &[])).expect("complete empty h1");
        deliver_all(&mut g, &h, 0);
        // A delivered hour's payloads retire in one expire.
        let h2 = hour(H2);
        stage_and_freeze(&mut g, &h2, &[vec![entry("a", 1)], vec![entry("b", 1)]]);
        deliver_all(&mut g, &h2, 2);
        let (report, event) = feed_cleanup(&g, &h2, NOW_SECS).expect("delivered cleanup");
        assert_eq!(report.retired, 2);
        assert!(!report.remaining);
        g.apply(&event.expect("expire event"), NOW_MS);
        assert!(!g.feed_sessions.contains_key(H2));
        assert_eq!(watermark(&g).as_deref(), Some(H2), "the cursor survives");
        begin(&mut g, &h2).expect_err("an expired hour never re-materializes");
        // The lost-ack replays still answer from the watermark: a
        // redelivered `deliver` is the delivered no-op, a redelivered
        // `cleanup` retires nothing.
        let replay = deliver(&mut g, &h2).expect("delivered replay after expire");
        assert_eq!(replay.state, "delivered");
        assert_eq!(replay.delivered_page, None);
        assert!(!replay.applied);
        assert_eq!(replay.touched_tasks, 0);
        assert_eq!(replay.remaining_pages, 0);
        let (report, event) = feed_cleanup(&g, &h2, NOW_SECS).expect("cleanup replay");
        assert_eq!(report.retired, 0);
        assert!(!report.remaining);
        assert!(event.is_none(), "an expired hour retires nothing again");
        // A never-staged hour still refuses both calls.
        let h9 = hour("2026-01-01T09");
        deliver(&mut g, &h9).expect_err("a never-staged hour never delivers");
        feed_cleanup(&g, &h9, NOW_SECS).expect_err("a never-staged hour cleans nothing");
        assert!(feed_status(&g).unfinished.is_none());
    }

    /// A rotation drops the abandoned attempt's pages wholesale; the
    /// live attempt stages hundreds of pages of its own, replays one
    /// verbatim, and freezes on its own manifest.
    #[test]
    fn rotation_retires_the_abandoned_generation() {
        let mut g = Graph::default();
        let h = hour(H4);
        let g1 = begin(&mut g, &h).expect("begin");
        for index in 0..302_u32 {
            stage(
                &mut g,
                &page(&h, g1, index, vec![entry("old", u64::from(index))]),
            )
            .expect("old page");
        }
        assert_eq!(g.feed_sessions[H4].staged.len(), 302);
        let (rotated, event) = feed_begin(&g, &h, NOW_SECS).expect("rotate");
        assert!(!rotated.stale_pages_pending, "the apply clears the pages");
        g.apply(&event, NOW_MS);
        let generation = rotated.generation;
        assert_eq!(g.feed_sessions[H4].staged_pages, 0);
        assert_eq!(g.feed_sessions[H4].staged.len(), 0);
        let entries: Vec<Vec<SchedulerDemandEntry>> =
            (0..300).map(|n| vec![entry("bulk", n)]).collect();
        for (index, page_entries) in entries.iter().enumerate() {
            let index = u32::try_from(index).expect("test page index");
            stage(&mut g, &page(&h, generation, index, page_entries.clone())).expect("page");
        }
        stage(&mut g, &page(&h, generation, 0, entries[0].clone())).expect("replay");
        freeze(&mut g, &complete(&h, generation, &entries)).expect("complete");
        assert_eq!(g.feed_sessions[H4].staged.len(), 300);
        assert_eq!(g.feed_sessions[H4].generation, generation);
    }

    /// Real calendar and closed-window validation: impossible dates
    /// and the still-open hour refuse before any event exists.
    #[test]
    fn hour_validation_uses_the_real_calendar() {
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
        // closure is refused gracefully rather than panicking.
        assert!(last.ensure_closed(i64::MAX).is_err());
        // The current open hour cannot be fed.
        assert!(DemandFeedHour::parse("2033-05-18T03").is_ok());
        let mut g = Graph::default();
        begin(&mut g, &hour(OPEN_HOUR)).expect_err("the open hour refuses to stage");
        assert!(g.feed_sessions.is_empty());
        begin(&mut g, &hour(JUST_CLOSED)).expect("the just-closed hour stages");
    }

    /// Both page bounds are real: >256 entries refuse, an empty page
    /// refuses, and the whole encoded envelope over 512 KiB refuses
    /// without staging anything — a large feature set means more
    /// pages, never a truncated request.
    #[test]
    fn page_envelope_respects_both_bounds() {
        let mut g = Graph::default();
        let h = hour(H1);
        let generation = begin(&mut g, &h).expect("begin");
        stage(&mut g, &page(&h, generation, 0, Vec::new())).expect_err("empty page refuses");
        let too_many: Vec<SchedulerDemandEntry> =
            (0..257).map(|i| entry(&format!("c{i:04}"), 1)).collect();
        stage(&mut g, &page(&h, generation, 0, too_many)).expect_err("257 entries refuse");
        // One entry carrying ~530 KiB of feature names: the whole
        // encoded request crosses the byte bound.
        stage(
            &mut g,
            &page(&h, generation, 0, vec![fat_entry("fat", 4_100)]),
        )
        .expect_err("oversized envelope refuses");
        assert_eq!(
            g.feed_sessions[H1].staged_pages, 0,
            "a refused page stages nothing"
        );
        // 256 small entries — the in-bound page — stages fine.
        let in_bound: Vec<SchedulerDemandEntry> =
            (0..256).map(|i| entry(&format!("d{i:04}"), 1)).collect();
        stage(&mut g, &page(&h, generation, 0, in_bound)).expect("256 entries stage");
        assert_eq!(g.feed_sessions[H1].staged_pages, 1);
    }

    /// A frozen hour's input is final: `begin` refuses, and a
    /// fully-delivered hour answers `deliver` as a no-op.
    #[test]
    fn frozen_input_never_rematerializes() {
        let mut g = Graph::default();
        let h = hour(H1);
        stage_and_freeze(&mut g, &h, &[vec![entry("alpha", 1)]]);
        begin(&mut g, &h).expect_err("a complete hour never re-materializes");
        deliver_all(&mut g, &h, 1);
        // Delivered hours replay as no-ops — and still arm the shared
        // alarm plan, the existing-cost route behavior.
        let again = deliver(&mut g, &h).expect("delivered hour no-ops");
        assert_eq!(again.state, "delivered");
        assert_eq!(again.delivered_page, None);
        assert_eq!(watermark(&g).as_deref(), Some(H1));
    }

    /// A zero-entry hour completes and delivers with zero demand
    /// calls — the empty-hour contract.
    #[test]
    fn empty_hour_completes_without_pages() {
        let mut g = Graph::default();
        let h = hour(H1);
        let generation = begin(&mut g, &h).expect("begin");
        freeze(
            &mut g,
            &DemandFeedCompleteRequest {
                hour: h.clone(),
                generation,
                page_count: 0,
                entry_count: 0,
                manifest_hash: String::new(),
            },
        )
        .expect("empty hour completes");
        let report = deliver(&mut g, &h).expect("empty hour delivers");
        assert_eq!(report.state, "delivered");
        assert_eq!(report.delivered_page, None);
        assert_eq!(watermark(&g).as_deref(), Some(H1));
        assert!(g.demand_batches.is_empty());
    }
}
