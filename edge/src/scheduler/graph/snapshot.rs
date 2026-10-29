//! The graph's incremental chunked snapshot (stow#878 §3.3, stow#902).
//!
//! The persisted graph is split into fixed chunks addressed by a
//! stable key — `kind * 2^48 + range * 64 + sub` — so a snapshot
//! rewrites only the ranges a mutation touched: node state and
//! adjacency by node/edge index range, interned strings by id range
//! (append-only, only the tail range changes), the published map and
//! the unbounded side tables by key-hash bucket, and the small global
//! state in one unconditional `meta` row. `sub` bounds a range to 64
//! rows (`SNAPSHOT_SPAN_ROWS`): a range whose items spill past one row
//! — a giant interned string, a skewed bucket — splits instead of
//! nearing the platform's ~2 MB row bound.
//!
//! Dirty tracking lives in memory (`Graph::dirty` plus the interner's
//! `intern_committed` watermark), never persisted: a wake starts clean
//! and the replayed log tail marks its own changes. A compaction
//! renumbers every index, so it marks `all` and the next snapshot
//! takes the full path — delete every row, then write every range —
//! which is also how a shrunk extent's stale rows go.
//!
//! The node, edge and published rows are fixed-size records written
//! little-endian, back to back, as base64 (`TEXT` payloads); a node's
//! optional [`Extra`] rides its record as a length-prefixed
//! `MessagePack` blob. The side states are `MessagePack` in base64;
//! the meta row, interned strings, requests, feed pages and batches
//! are JSON. What the loader can recompute is not written: edge spans,
//! retention counts, unmet counts, state slab indexes and every
//! lookup table.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::index::hash_of;
use super::node::{Extra, Flags, NO_STATE, Node, State, Status};
use super::{AttemptOutcome, FeedSession, Graph, IdKey, RequestRecord};
use crate::errors::QueueError;

/// The payload text one row carries, about: a range's row closes once
/// its encoded items reach this size, so a row is this plus at most
/// one item — far under the platform's 2 MB row bound.
const CHUNK_TEXT_BYTES: usize = 1 << 20;

/// The binary bytes that encode to [`CHUNK_TEXT_BYTES`] of base64.
const CHUNK_BINARY_BYTES: usize = CHUNK_TEXT_BYTES / 4 * 3;

/// Rows one range may emit — the sub-key bound of a chunk key. A range
/// needing more fails the snapshot as an invariant rather than
/// silently colliding with the next range's keys.
pub const SNAPSHOT_SPAN_ROWS: i64 = 64;

/// Interned strings per `intern` range: the dirty granularity of an
/// append-only table — only the tail range is ever rewritten, so this
/// bounds one snapshot's string rewrite. ~50 bytes a name keeps a
/// range near the ~1 MiB row density today's snapshot kept.
const INTERN_RANGE: u32 = 16_384;

/// Nodes per `nodes` range: ~100 bytes of node + state + a rare extra
/// in the common case keeps a rewrite near the ~1 MiB row density
/// today's snapshot kept; oversize ranges sub-split.
const NODES_RANGE: u32 = 8_192;

/// Edges per `edges` range: five fixed bytes an edge, 640 KB a range.
const EDGES_RANGE: u32 = 131_072;

/// Published-mask buckets: the dense table — 17 fixed bytes an entry —
/// sized so a bucket rewrite stays one row at the largest graph the
/// 128 MiB object holds (#878 measured ~345k nodes at 480k rows): an
/// all-published graph is 345k x 17 B / 16 = ~367 KB a bucket, ~47% of
/// the ~786 KB binary row bound, still one row at twice that size.
const PUBLISHED_BUCKETS: u32 = 16;

/// Request-record buckets, by request-id hash: ~512 bytes of JSON a
/// record, and the request history a 345k-node graph carries stays
/// far under ~100k admissions (each admits at least one node) — 96k x
/// 512 B / 64 = ~770 KB a bucket, ~98% of a row at that bound.
const REQUESTS_BUCKETS: u32 = 64;

/// Staged-page buckets, by hour hash: staged pages live only until a
/// session delivers or expires, so the staged set is bounded by live
/// sessions, not the graph — ~50 pages x ~50 KB / 16 = ~160 KB a
/// bucket.
const FEED_BUCKETS: u32 = 16;

/// Demand-batch buckets, by batch-id hash: ~60 bytes of JSON a
/// `(id, hash, count)` entry — batches accrue for the graph's life;
/// at 64 buckets a ~780k-batch history fills a bucket at ~730 KB,
/// ~93% of a row, and the object hits its memory bound first.
const BATCHES_BUCKETS: u32 = 64;

/// How a row's payload is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// A JSON array of the row's items.
    Json,
    /// Base64 of the items' `MessagePack` encodings, back to back.
    Packed,
    /// Base64 of the items' fixed little-endian records, back to back.
    Raw,
}

/// A chunk kind — the high bits of every row's key, in load order:
/// `meta` first (the loader allocates against it), then the arenas,
/// then the keyed tables. `feed` rides on `meta`'s sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkKind {
    Meta,
    Intern,
    Nodes,
    Edges,
    Published,
    Outcomes,
    Requests,
    Feed,
    Batches,
}

impl ChunkKind {
    const fn key(self) -> i64 {
        (self as i64) << 48
    }

    const fn tag(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Intern => "intern",
            Self::Nodes => "nodes",
            Self::Edges => "edges",
            Self::Published => "published",
            Self::Outcomes => "outcomes",
            Self::Requests => "requests",
            Self::Feed => "feed",
            Self::Batches => "batches",
        }
    }

    fn of_key(key: i64) -> Result<Self, QueueError> {
        Ok(match key >> 48 {
            0 => Self::Meta,
            1 => Self::Intern,
            2 => Self::Nodes,
            3 => Self::Edges,
            4 => Self::Published,
            5 => Self::Outcomes,
            6 => Self::Requests,
            7 => Self::Feed,
            8 => Self::Batches,
            other => {
                return Err(QueueError::Invariant(format!(
                    "unknown snapshot kind {other}"
                )));
            }
        })
    }

    const fn encoding(self) -> Encoding {
        match self {
            Self::Nodes | Self::Edges | Self::Published => Encoding::Raw,
            Self::Outcomes => Encoding::Packed,
            Self::Meta | Self::Intern | Self::Requests | Self::Feed | Self::Batches => {
                Encoding::Json
            }
        }
    }
}

/// One dirty range of one kind — the snapshot's unit of rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSpan {
    kind: ChunkKind,
    /// The range ordinal: `first item index / range width` for the
    /// indexed kinds, the bucket for the keyed kinds.
    range: u32,
}

impl ChunkSpan {
    const fn new(kind: ChunkKind, range: u32) -> Self {
        Self { kind, range }
    }

    /// The first row key this span may write.
    pub(crate) const fn lo_key(self) -> i64 {
        self.kind.key() | ((self.range as i64) * SNAPSHOT_SPAN_ROWS)
    }

    /// The last row key this span may write.
    pub(crate) const fn hi_key(self) -> i64 {
        self.lo_key() + SNAPSHOT_SPAN_ROWS - 1
    }
}

/// What the next snapshot rewrites. `all` after a compaction
/// renumbered the arena — the full path drops every row first, which
/// also retires the stale rows of a shrunk extent.
#[derive(Debug)]
pub struct SnapshotPlan {
    /// Whether every chunk rewrites.
    pub all: bool,
    /// The spans to rewrite, in key order; the meta row leads.
    pub spans: Vec<ChunkSpan>,
}

/// The chunks a mutation dirtied — in memory only, cleared by the
/// wake and the snapshot write.
#[derive(Debug, Default)]
pub(super) struct Dirty {
    /// A compaction renumbered every index: all ranges rewrite.
    pub all: bool,
    /// Node-index ranges (`ix / NODES_RANGE`).
    pub nodes: BTreeSet<u32>,
    /// Edge-index ranges.
    pub edges: BTreeSet<u32>,
    /// Published-mask buckets.
    pub published: BTreeSet<u32>,
    /// Request-record buckets.
    pub requests: BTreeSet<u32>,
    /// Feed-page buckets.
    pub feed: BTreeSet<u32>,
    /// Demand-batch buckets.
    pub batches: BTreeSet<u32>,
    /// The bounded outcome ring — one range, so one flag.
    pub outcomes: bool,
}

/// The published map's bucket of one key — its leading bytes.
const fn published_bucket(key: &IdKey) -> u32 {
    u32::from_le_bytes([key[0], key[1], key[2], key[3]]) % PUBLISHED_BUCKETS
}

/// A keyed map's bucket — the key's hash modulo the bucket count.
fn keyed_bucket(key: &str, buckets: u32) -> u32 {
    u32::try_from(hash_of(key) % u64::from(buckets)).unwrap_or(u32::MAX)
}

/// The feed map's bucket of one hour — a free function so a call site
/// holding a `feed_sessions` borrow never takes `&mut self`.
pub(super) fn feed_bucket(hour: &str) -> u32 {
    keyed_bucket(hour, FEED_BUCKETS)
}

/// The snapshot's first row — the scalar state, the name vocabularies,
/// and every arena's length so the loader allocates each once at its
/// final size and a missing row fails the wake.
#[derive(Serialize, Deserialize)]
struct SnapshotHead {
    next_generation: u64,
    /// The probe-only per-operation ledger. The day totals stay out of
    /// the head (stow#931): the `meter` row is their single durable
    /// source — totals written here could not account for the
    /// snapshot's own statements. `ops` cannot be re-counted on
    /// replay, so it still rides the snapshot.
    meter_ops: BTreeMap<String, (u64, u64, u64)>,
    /// The budget probe's seeded fixture size (`Graph::seeded_rows`) —
    /// probe state a `store_meta` row cannot hold without a billed
    /// statement the replay cannot re-count.
    seeded_rows: Option<u32>,
    freeze: Option<stow_types::api::DispatchFreezeRecord>,
    /// The operator's dispatch-cap setting (stow#1039) — `None` until
    /// the first `set`, when the deploy bindings apply.
    dispatch_cap: Option<stow_types::api::DispatchCapSetting>,
    external_runs: Vec<(u64, u8)>,
    human_budget: (i64, i64),
    freeze_history: std::collections::VecDeque<stow_types::api::DispatchFreezeTransition>,
    /// Feed sessions without their staged pages — those ride the
    /// `feed` chunks.
    feed_sessions: BTreeMap<String, FeedSession>,
    feed_watermark: Option<String>,
    /// Target names, in id order.
    targets: Vec<String>,
    /// Rustc versions, in id order.
    rustcs: Vec<String>,
    /// The trailing-day outcome tally by hour and target.
    outcome_hours: Vec<((i64, u8), (u32, u32))>,
    /// The instant the last `workflow_run` delivery was accepted
    /// (stow#860) — the health check's last-delivery age reads it.
    last_run_update_ms: Option<i64>,
    lens: SectionLens,
}

/// Item counts of every decodable kind — the load check a missing row
/// fails.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SectionLens {
    intern: usize,
    nodes: usize,
    edges: usize,
    published: usize,
    outcomes: usize,
    requests: usize,
    feed_pages: usize,
    batches: usize,
}

/// One row being encoded.
struct ChunkWriter {
    encoding: Encoding,
    buf: Vec<u8>,
    items: u32,
}

impl ChunkWriter {
    const fn new(encoding: Encoding) -> Self {
        Self {
            encoding,
            buf: Vec::new(),
            items: 0,
        }
    }

    const fn limit(&self) -> usize {
        match self.encoding {
            Encoding::Json => CHUNK_TEXT_BYTES,
            Encoding::Packed | Encoding::Raw => CHUNK_BINARY_BYTES,
        }
    }

    /// Encode items until the row is full or the items run out;
    /// returns how many it took.
    fn fill<T: Serialize>(&mut self, items: impl Iterator<Item = T>) -> Result<u32, QueueError> {
        let limit = self.limit();
        for item in items {
            match self.encoding {
                Encoding::Json => {
                    self.buf.push(if self.items == 0 { b'[' } else { b',' });
                    serde_json::to_writer(&mut self.buf, &item).map_err(encode_error)?;
                }
                Encoding::Packed => {
                    rmp_serde::encode::write(&mut self.buf, &item).map_err(encode_error)?;
                }
                Encoding::Raw => unreachable!("raw rows fill through fill_raw"),
            }
            self.items += 1;
            if self.buf.len() >= limit {
                break;
            }
        }
        Ok(self.items)
    }

    /// Append raw records until the row is full or the items run out;
    /// returns how many it took.
    fn fill_raw<T>(
        &mut self,
        items: impl Iterator<Item = T>,
        mut write: impl FnMut(&mut Vec<u8>, T) -> Result<(), QueueError>,
    ) -> Result<u32, QueueError> {
        let limit = self.limit();
        for item in items {
            write(&mut self.buf, item)?;
            self.items += 1;
            if self.buf.len() >= limit {
                break;
            }
        }
        Ok(self.items)
    }

    fn finish(mut self) -> Result<String, QueueError> {
        match self.encoding {
            Encoding::Json => {
                if self.items > 0 {
                    self.buf.push(b']');
                }
                String::from_utf8(self.buf).map_err(encode_error)
            }
            Encoding::Packed | Encoding::Raw => {
                Ok(base64::engine::general_purpose::STANDARD.encode(&self.buf))
            }
        }
    }
}

fn encode_error(error: impl std::fmt::Display) -> QueueError {
    QueueError::Invariant(format!("snapshot encode: {error}"))
}

/// One node's snapshot record: the fixed fields, its inline state when
/// it carries one, then the extra's presence byte and — when present —
/// a `u32` length and the `MessagePack` blob.
fn write_node(
    buf: &mut Vec<u8>,
    node: &Node,
    state: Option<&State>,
    extra: Option<&Extra>,
) -> Result<(), QueueError> {
    buf.extend_from_slice(&node.digest);
    buf.extend_from_slice(&node.crate_name.to_le_bytes());
    buf.extend_from_slice(&node.version.to_le_bytes());
    buf.extend_from_slice(&node.features.to_le_bytes());
    buf.extend_from_slice(&node.id_tag.to_le_bytes());
    buf.extend_from_slice(&node.edges_len.to_le_bytes());
    buf.push(node.target);
    buf.push(node.rustc);
    buf.push(node.status as u8);
    buf.push(node.flags.0);
    if let Some(state) = state {
        buf.extend_from_slice(&state.first_requested.to_le_bytes());
        buf.extend_from_slice(&state.updated.to_le_bytes());
        buf.extend_from_slice(&state.priority.to_le_bytes());
        buf.extend_from_slice(&state.demand.to_le_bytes());
        buf.extend_from_slice(&state.downloads.to_le_bytes());
        buf.push(state.attempt);
        buf.extend_from_slice(&state.dispatch_attempts.to_le_bytes());
    }
    match extra {
        None => buf.push(0),
        Some(extra) => {
            let bytes = rmp_serde::to_vec(extra).map_err(encode_error)?;
            buf.push(1);
            buf.extend_from_slice(
                &u32::try_from(bytes.len())
                    .map_err(|_| QueueError::Invariant("node extra exceeds u32".into()))?
                    .to_le_bytes(),
            );
            buf.extend_from_slice(&bytes);
        }
    }
    Ok(())
}

/// A cursor over a record stream's bytes.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], QueueError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or_else(|| QueueError::Invariant("snapshot record cut short".into()))?;
        self.0 = rest;
        Ok(*head)
    }

    fn bytes(&mut self, len: usize) -> Result<&[u8], QueueError> {
        if self.0.len() < len {
            return Err(QueueError::Invariant("snapshot record cut short".into()));
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, QueueError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, QueueError> {
        Ok(u16::from_le_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, QueueError> {
        Ok(u32::from_le_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, QueueError> {
        Ok(u64::from_le_bytes(self.take()?))
    }

    fn i64(&mut self) -> Result<i64, QueueError> {
        Ok(i64::from_le_bytes(self.take()?))
    }

    const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn decode_base64(kind: ChunkKind, payload: &str) -> Result<Vec<u8>, QueueError> {
    base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|error| QueueError::Invariant(format!("snapshot {} decode: {error}", kind.tag())))
}

/// Decode one row's items, handing each to `sink` as it decodes.
fn decode_items<T: DeserializeOwned>(
    kind: ChunkKind,
    payload: &str,
    mut sink: impl FnMut(T) -> Result<(), QueueError>,
) -> Result<(), QueueError> {
    let tag = kind.tag();
    let invalid = |error: &dyn std::fmt::Display| {
        QueueError::Invariant(format!("snapshot {tag} decode: {error}"))
    };
    match kind.encoding() {
        Encoding::Json => {
            let items: Vec<T> = serde_json::from_str(payload).map_err(|e| invalid(&e))?;
            items.into_iter().try_for_each(sink)
        }
        Encoding::Packed => {
            let bytes = decode_base64(kind, payload)?;
            let mut rest = bytes.as_slice();
            while !rest.is_empty() {
                sink(rmp_serde::from_read(&mut rest).map_err(|e| invalid(&e))?)?;
            }
            Ok(())
        }
        Encoding::Raw => unreachable!("raw rows decode through decode_raw"),
    }
}

/// Decode one raw row, handing the byte cursor to `sink` once per record.
fn decode_raw(
    kind: ChunkKind,
    payload: &str,
    mut sink: impl FnMut(&mut Bytes<'_>) -> Result<(), QueueError>,
) -> Result<(), QueueError> {
    let bytes = decode_base64(kind, payload)?;
    let mut cursor = Bytes(&bytes);
    while !cursor.is_empty() {
        sink(&mut cursor)?;
    }
    Ok(())
}

/// One keyed span's materialized entries — collected sorted at the
/// encoder's creation, bounded by the bucket's own size (the graph is
/// never copied whole).
enum SpanItem {
    Published(IdKey, u8),
    Requests(String, RequestRecord),
    Feed(String, usize, Vec<stow_types::api::SchedulerDemandEntry>),
    Batches(String, (String, i64)),
    Outcomes(AttemptOutcome),
}

/// The rows of one dirty span, emitted one at a time so peak memory is
/// one row plus the span's own materialization.
pub struct SpanEncoder {
    span: ChunkSpan,
    /// The next item inside the span — the absolute index for the
    /// indexed kinds, a position in `items` for the keyed kinds.
    at: u32,
    /// The keyed kinds' entries, sorted for a stable encoding.
    items: Vec<SpanItem>,
}

impl SpanEncoder {
    /// The span's next row, or `None` once it is exhausted. `graph` is
    /// the same graph the plan was made from — the store's writes ride
    /// the object's input gate, so nothing mutates it between rows.
    ///
    /// # Errors
    /// `QueueError::Invariant` on an item that fails to serialize.
    pub fn next_row(&mut self, graph: &Graph) -> Result<Option<String>, QueueError> {
        let kind = self.span.kind;
        let mut writer = ChunkWriter::new(kind.encoding());
        let at = self.at as usize;
        let taken = match kind {
            ChunkKind::Meta => {
                if self.at != 0 {
                    return Ok(None);
                }
                self.at = 1;
                return serde_json::to_string(&graph.snapshot_head())
                    .map(Some)
                    .map_err(encode_error);
            }
            ChunkKind::Intern => {
                let end = self.span_end(graph.intern.len());
                writer.fill(graph.intern.iter_from(at).take(end - at))?
            }
            ChunkKind::Nodes => {
                let end = self.span_end(graph.nodes.len());
                writer.fill_raw(at..end, |buf, ix| {
                    let node = &graph.nodes[ix];
                    let state =
                        (node.state != NO_STATE).then(|| &graph.states[node.state as usize]);
                    let extra = graph
                        .extras
                        .get(&u32::try_from(ix).expect("node indexes fit u32"));
                    write_node(buf, node, state, extra)
                })?
            }
            ChunkKind::Edges => {
                let end = self.span_end(graph.edges.len());
                writer.fill_raw(at..end, |buf, edge| {
                    buf.extend_from_slice(&graph.edges.dep(edge).to_le_bytes());
                    buf.push(graph.edges.raw_flags(edge));
                    Ok(())
                })?
            }
            ChunkKind::Published => {
                writer.fill_raw(self.items[at..].iter(), |buf, item| match item {
                    SpanItem::Published(key, mask) => {
                        buf.extend_from_slice(key);
                        buf.push(*mask);
                        Ok(())
                    }
                    _ => unreachable!("a published span holds published items"),
                })?
            }
            ChunkKind::Requests => writer.fill(self.items[at..].iter().map(|item| match item {
                SpanItem::Requests(id, record) => (id, record),
                _ => unreachable!("a requests span holds request items"),
            }))?,
            ChunkKind::Feed => writer.fill(self.items[at..].iter().map(|item| match item {
                SpanItem::Feed(hour, page, entries) => (hour, page, entries),
                _ => unreachable!("a feed span holds feed items"),
            }))?,
            ChunkKind::Batches => writer.fill(self.items[at..].iter().map(|item| match item {
                SpanItem::Batches(id, batch) => (id, batch),
                _ => unreachable!("a batches span holds batch items"),
            }))?,
            ChunkKind::Outcomes => writer.fill(self.items[at..].iter().map(|item| match item {
                SpanItem::Outcomes(outcome) => outcome,
                _ => unreachable!("an outcomes span holds outcome items"),
            }))?,
        };
        if taken == 0 {
            return Ok(None);
        }
        self.at += taken;
        Ok(Some(writer.finish()?))
    }

    /// The index one past this span's last item — the range's own end
    /// or the arena's, whichever is smaller.
    fn span_end(&self, len: usize) -> usize {
        let width = match self.span.kind {
            ChunkKind::Intern => INTERN_RANGE,
            ChunkKind::Nodes => NODES_RANGE,
            ChunkKind::Edges => EDGES_RANGE,
            _ => unreachable!("only the indexed kinds range"),
        } as usize;
        ((self.span.range as usize + 1) * width).min(len)
    }
}

impl Graph {
    /// Mark node `ix`'s chunk dirty — every mutation of its record,
    /// its queue state or its extra.
    pub(super) fn touch(&mut self, ix: u32) {
        self.dirty.nodes.insert(ix / NODES_RANGE);
    }

    /// Mark edge `edge`'s chunk dirty.
    pub(super) fn touch_edge(&mut self, edge: u32) {
        self.dirty.edges.insert(edge / EDGES_RANGE);
    }

    /// Mark the published bucket of `key` dirty.
    pub(super) fn touch_published(&mut self, key: &IdKey) {
        self.dirty.published.insert(published_bucket(key));
    }

    /// Mark the request bucket of `request_id` dirty.
    pub(super) fn touch_request(&mut self, request_id: &str) {
        self.dirty
            .requests
            .insert(keyed_bucket(request_id, REQUESTS_BUCKETS));
    }

    /// Mark the feed bucket of `hour` dirty.
    pub(super) fn touch_feed(&mut self, hour: &str) {
        self.dirty.feed.insert(feed_bucket(hour));
    }

    /// Mark the batch bucket of `batch_id` dirty.
    pub(super) fn touch_batch(&mut self, batch_id: &str) {
        self.dirty
            .batches
            .insert(keyed_bucket(batch_id, BATCHES_BUCKETS));
    }

    /// The ranges the next snapshot rewrites — always the meta row,
    /// every dirty range, and the intern ranges the append-only
    /// interner grew past its persisted watermark.
    ///
    /// # Errors
    /// `QueueError::Invariant` when freed nodes are still in the arena
    /// (the caller compacts first).
    pub fn snapshot_plan(&self) -> Result<SnapshotPlan, QueueError> {
        if self.counts[Status::Free.index()] != 0 {
            return Err(QueueError::Invariant(
                "snapshot written over freed nodes: compact first".into(),
            ));
        }
        let all = self.dirty.all;
        let ranges = |len: usize, width: u32| {
            u32::try_from(len.div_ceil(width as usize)).unwrap_or(u32::MAX)
        };
        let mut spans = vec![ChunkSpan::new(ChunkKind::Meta, 0)];
        // Append-only: every range at or above the persisted watermark's
        // range may hold new strings.
        let intern_from = if all {
            0
        } else if self.intern.len() > self.intern_committed {
            // The persisted tail range is partial only when new
            // strings landed: rewrite from its range up.
            u32::try_from(self.intern_committed / INTERN_RANGE as usize).unwrap_or(u32::MAX)
        } else {
            ranges(self.intern.len(), INTERN_RANGE)
        };
        spans.extend(
            (intern_from..ranges(self.intern.len(), INTERN_RANGE))
                .map(|range| ChunkSpan::new(ChunkKind::Intern, range)),
        );
        let add =
            |spans: &mut Vec<ChunkSpan>, kind: ChunkKind, count: u32, dirty: &BTreeSet<u32>| {
                if all {
                    spans.extend((0..count).map(|range| ChunkSpan::new(kind, range)));
                } else {
                    spans.extend(dirty.iter().map(|&range| ChunkSpan::new(kind, range)));
                }
            };
        add(
            &mut spans,
            ChunkKind::Nodes,
            ranges(self.nodes.len(), NODES_RANGE),
            &self.dirty.nodes,
        );
        add(
            &mut spans,
            ChunkKind::Edges,
            ranges(self.edges.len(), EDGES_RANGE),
            &self.dirty.edges,
        );
        add(
            &mut spans,
            ChunkKind::Published,
            PUBLISHED_BUCKETS,
            &self.dirty.published,
        );
        if all || self.dirty.outcomes {
            spans.push(ChunkSpan::new(ChunkKind::Outcomes, 0));
        }
        add(
            &mut spans,
            ChunkKind::Requests,
            REQUESTS_BUCKETS,
            &self.dirty.requests,
        );
        add(&mut spans, ChunkKind::Feed, FEED_BUCKETS, &self.dirty.feed);
        add(
            &mut spans,
            ChunkKind::Batches,
            BATCHES_BUCKETS,
            &self.dirty.batches,
        );
        Ok(SnapshotPlan { all, spans })
    }

    /// The row producer of one dirty span: the keyed kinds materialize
    /// their entries once, sorted so the encoding is stable; the
    /// indexed kinds read the arena by index at each `next_row`.
    pub fn snapshot_encoder(&self, span: ChunkSpan) -> SpanEncoder {
        let bucket = span.range;
        let items = match span.kind {
            ChunkKind::Published => {
                let mut items: Vec<_> = self
                    .published
                    .iter()
                    .filter(|(key, _)| published_bucket(key) == bucket)
                    .map(|(&key, &mask)| SpanItem::Published(key, mask))
                    .collect();
                items.sort_by_key(|item| match item {
                    SpanItem::Published(key, _) => *key,
                    _ => unreachable!("a published span holds published items"),
                });
                items
            }
            ChunkKind::Requests => self
                .requests
                .iter()
                .filter(|(id, _)| keyed_bucket(id, REQUESTS_BUCKETS) == bucket)
                .map(|(id, record)| SpanItem::Requests(id.clone(), record.clone()))
                .collect(),
            ChunkKind::Feed => self
                .feed_sessions
                .iter()
                .filter(|(hour, _)| keyed_bucket(hour, FEED_BUCKETS) == bucket)
                .flat_map(|(hour, session)| {
                    session
                        .staged
                        .iter()
                        .enumerate()
                        .map(move |(page, entries)| {
                            SpanItem::Feed(hour.clone(), page, entries.clone())
                        })
                })
                .collect(),
            ChunkKind::Batches => self
                .demand_batches
                .iter()
                .filter(|(id, _)| keyed_bucket(id, BATCHES_BUCKETS) == bucket)
                .map(|(id, batch)| SpanItem::Batches(id.clone(), batch.clone()))
                .collect(),
            ChunkKind::Outcomes => self
                .attempt_outcomes
                .iter()
                .map(|outcome| SpanItem::Outcomes(outcome.clone()))
                .collect(),
            _ => Vec::new(),
        };
        // The indexed kinds start at their range's first index.
        let at = match span.kind {
            ChunkKind::Intern => span.range * INTERN_RANGE,
            ChunkKind::Nodes => span.range * NODES_RANGE,
            ChunkKind::Edges => span.range * EDGES_RANGE,
            _ => 0,
        };
        SpanEncoder { span, at, items }
    }

    /// The store holds every dirty range: clear the marks and lift the
    /// intern watermark to the interner's end.
    pub(crate) fn snapshot_written(&mut self) {
        self.dirty = Dirty::default();
        self.intern_committed = self.intern.len();
    }

    fn snapshot_head(&self) -> SnapshotHead {
        SnapshotHead {
            next_generation: self.next_generation,
            meter_ops: self.meter.ops.clone(),
            seeded_rows: self.seeded_rows,
            freeze: self.freeze.clone(),
            dispatch_cap: self.dispatch_cap.clone(),
            external_runs: self.external_runs.iter().map(|(&k, &v)| (k, v)).collect(),
            human_budget: self.human_budget,
            freeze_history: self.freeze_history.clone(),
            feed_sessions: self
                .feed_sessions
                .iter()
                .map(|(hour, session)| {
                    (
                        hour.clone(),
                        FeedSession {
                            generation: session.generation,
                            state: session.state.clone(),
                            staged_pages: session.staged_pages,
                            staged_entries: session.staged_entries,
                            applied_pages: session.applied_pages,
                            page_count: session.page_count,
                            entry_count: session.entry_count,
                            staged: Vec::new(),
                            page_hashes: session.page_hashes.clone(),
                            chain_hashes: session.chain_hashes.clone(),
                        },
                    )
                })
                .collect(),
            feed_watermark: self.feed_watermark.clone(),
            targets: self.targets.iter().map(|t| t.name.to_string()).collect(),
            rustcs: self.rustcs.iter().map(ToString::to_string).collect(),
            outcome_hours: self
                .outcome_hours
                .iter()
                .map(|(&key, &tally)| (key, tally))
                .collect(),
            last_run_update_ms: self.last_run_update_ms,
            lens: self.section_lens(),
        }
    }

    fn section_lens(&self) -> SectionLens {
        SectionLens {
            intern: self.intern.len(),
            nodes: self.nodes.len(),
            edges: self.edges.len(),
            published: self.published.len(),
            outcomes: self.attempt_outcomes.len(),
            requests: self.requests.len(),
            feed_pages: self
                .feed_sessions
                .values()
                .map(|session| session.staged.len())
                .sum(),
            batches: self.demand_batches.len(),
        }
    }
}

/// A wake's graph under construction: rows apply in key order — `meta`
/// first, then each kind's ranges and buckets — then [`Self::finish`]
/// rebuilds the derived state.
#[derive(Default)]
pub struct SnapshotLoader {
    graph: Graph,
    lens: Option<SectionLens>,
}

impl SnapshotLoader {
    /// Decode one row into the graph.
    ///
    /// # Errors
    /// `QueueError::Invariant` on an unknown kind, a row before the
    /// meta row, or a corrupt payload.
    pub fn apply(&mut self, chunk: i64, payload: &str) -> Result<(), QueueError> {
        let kind = ChunkKind::of_key(chunk)?;
        if kind != ChunkKind::Meta && self.lens.is_none() {
            return Err(QueueError::Invariant(format!(
                "snapshot {} row before the meta row",
                kind.tag()
            )));
        }
        let graph = &mut self.graph;
        match kind {
            ChunkKind::Meta => Self::apply_head(graph, &mut self.lens, payload),
            ChunkKind::Intern => decode_items(kind, payload, |s: String| {
                graph.intern.load(&s);
                Ok(())
            }),
            ChunkKind::Nodes => decode_raw(kind, payload, |bytes| Self::load_node(graph, bytes)),
            ChunkKind::Edges => decode_raw(kind, payload, |bytes| {
                let dep = bytes.u32()?;
                let flags = bytes.u8()?;
                graph.edges.load(dep, flags);
                Ok(())
            }),
            ChunkKind::Published => decode_raw(kind, payload, |bytes| {
                let key: IdKey = bytes.take()?;
                let mask = bytes.u8()?;
                graph.published.insert(key, mask);
                Ok(())
            }),
            ChunkKind::Outcomes => decode_items(kind, payload, |outcome: AttemptOutcome| {
                graph.attempt_outcomes.push_back(outcome);
                Ok(())
            }),
            ChunkKind::Requests => {
                decode_items(kind, payload, |(id, record): (String, RequestRecord)| {
                    graph.requests.insert(id, record);
                    Ok(())
                })
            }
            ChunkKind::Feed => decode_items(
                kind,
                payload,
                |(hour, page, entries): (
                    String,
                    usize,
                    Vec<stow_types::api::SchedulerDemandEntry>,
                )| {
                    let session = graph.feed_sessions.get_mut(&hour).ok_or_else(|| {
                        QueueError::Invariant(format!("feed page for unknown hour {hour}"))
                    })?;
                    if session.staged.len() != page {
                        return Err(QueueError::Invariant(format!(
                            "feed page {page} of {hour} out of order"
                        )));
                    }
                    session.staged.push(entries);
                    Ok(())
                },
            ),
            ChunkKind::Batches => {
                decode_items(kind, payload, |(id, batch): (String, (String, i64))| {
                    graph.demand_batches.insert(id, batch);
                    Ok(())
                })
            }
        }
    }

    fn load_node(graph: &mut Graph, bytes: &mut Bytes<'_>) -> Result<(), QueueError> {
        let digest = bytes.take::<32>()?;
        let crate_name = bytes.u32()?;
        let version = bytes.u32()?;
        let features = bytes.u32()?;
        let id_tag = bytes.u32()?;
        let edges_len = bytes.u16()?;
        let target = bytes.u8()?;
        let rustc = bytes.u8()?;
        let status = Status::from_byte(bytes.u8()?)?;
        let flags = Flags(bytes.u8()?);
        let state = if status.has_state() {
            let state = State {
                first_requested: bytes.i64()?,
                updated: bytes.i64()?,
                priority: bytes.i64()?,
                demand: bytes.i64()?,
                downloads: bytes.u64()?,
                attempt: bytes.u8()?,
                dispatch_attempts: bytes.u16()?,
            };
            let at = u32::try_from(graph.states.len())
                .map_err(|_| QueueError::Invariant("snapshot state slab overflows u32".into()))?;
            graph.states.push(state);
            at
        } else {
            NO_STATE
        };
        let node = Node {
            digest,
            crate_name,
            version,
            features,
            id_tag,
            state,
            edges_start: 0,
            refs: 0,
            edges_len,
            unmet: 0,
            target,
            rustc,
            status,
            flags,
        };
        let ix = u32::try_from(graph.nodes.len())
            .map_err(|_| QueueError::Invariant("node count overflows u32".into()))?;
        graph.nodes.push(node);
        match bytes.u8()? {
            0 => Ok(()),
            1 => {
                let len = bytes.u32()? as usize;
                let extra: Extra =
                    rmp_serde::from_slice(bytes.bytes(len)?).map_err(encode_error)?;
                graph.extras.insert(ix, extra);
                Ok(())
            }
            flag => Err(QueueError::Invariant(format!(
                "snapshot node extra flag {flag}"
            ))),
        }
    }

    fn apply_head(
        graph: &mut Graph,
        lens: &mut Option<SectionLens>,
        payload: &str,
    ) -> Result<(), QueueError> {
        if lens.is_some() {
            return Err(QueueError::Invariant("snapshot carries two heads".into()));
        }
        let head: SnapshotHead = serde_json::from_str(payload).map_err(|e| encode_error(&e))?;
        graph.next_generation = head.next_generation;
        graph.meter.ops = head.meter_ops;
        graph.seeded_rows = head.seeded_rows;
        graph.freeze = head.freeze;
        graph.dispatch_cap = head.dispatch_cap;
        graph.external_runs = head.external_runs.into_iter().collect();
        graph.human_budget = head.human_budget;
        graph.freeze_history = head.freeze_history;
        graph.feed_sessions = head.feed_sessions;
        graph.feed_watermark = head.feed_watermark;
        for (at, name) in head.targets.iter().enumerate() {
            if usize::from(graph.target_id(name)?) != at {
                return Err(QueueError::Invariant(format!(
                    "snapshot target {name} repeats"
                )));
            }
        }
        for (at, name) in head.rustcs.iter().enumerate() {
            if usize::from(graph.rustc_id(name)?) != at {
                return Err(QueueError::Invariant(format!(
                    "snapshot rustc {name} repeats"
                )));
            }
        }
        graph.outcome_hours = head.outcome_hours.into_iter().collect();
        graph.last_run_update_ms = head.last_run_update_ms;
        graph.intern.reserve_exact(head.lens.intern);
        graph.nodes.reserve_exact(head.lens.nodes);
        graph.states.reserve(head.lens.nodes);
        graph.edges.reserve_exact(head.lens.edges);
        graph.published.reserve(head.lens.published);
        *lens = Some(head.lens);
        Ok(())
    }

    /// The loaded graph, its derived state rebuilt and its dirty
    /// tracking reset — the replayed log tail marks what it changes.
    ///
    /// # Errors
    /// `QueueError::Invariant` when the rows decoded a different item
    /// count than the head recorded — a snapshot missing rows.
    pub fn finish(mut self) -> Result<Graph, QueueError> {
        let Some(lens) = self.lens else {
            // No snapshot yet: the log alone replays the graph.
            return Ok(self.graph);
        };
        let mut graph = std::mem::take(&mut self.graph);
        let loaded = graph.section_lens();
        if loaded != lens {
            return Err(QueueError::Invariant(format!(
                "snapshot head records {lens:?} but its rows decoded {loaded:?}"
            )));
        }
        graph.intern.index();
        graph.rebuild_after_load()?;
        graph.snapshot_written();
        Ok(graph)
    }
}
