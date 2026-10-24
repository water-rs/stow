//! The graph's chunked snapshot (stow#878 §3.3).
//!
//! A snapshot is a sequence of sections written in a fixed order -
//! the head, then the bulk arenas and the side states - each cut into
//! `snapshot_chunks` rows of about [`CHUNK_TEXT_BYTES`] of payload
//! text. The writer serializes one row at a time from a
//! [`SnapshotCursor`] and the loader decodes one row at a time into a
//! [`SnapshotLoader`], so neither side ever holds the serialized image:
//! peak memory beyond the graph is one row.
//!
//! The node, edge and published sections are fixed-size records
//! written little-endian, back to back, as base64 (a row's payload is
//! `TEXT`). The side states (extras, outcomes, cost windows) are
//! `MessagePack` in base64; the head, the interned strings and the
//! small stow-types states stay JSON.
//!
//! What the loader can recompute is not written: edge spans, the
//! retention counts, unmet counts, state slab indexes, the cost
//! medians and every lookup table. The writer refuses a graph with
//! freed nodes: the caller compacts first.

use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::node::{Extra, Flags, NO_STATE, Node, State, Status};
use super::{AttemptOutcome, FeedSession, Graph, IdKey, Meter, RequestRecord};
use crate::errors::QueueError;

/// The payload text one row carries, about: a section's row closes
/// once its encoded items reach this size, so a row is this plus at
/// most one item - far under the platform's 2 MB row bound.
const CHUNK_TEXT_BYTES: usize = 1 << 20;

/// The binary bytes that encode to [`CHUNK_TEXT_BYTES`] of base64.
const CHUNK_BINARY_BYTES: usize = CHUNK_TEXT_BYTES / 4 * 3;

/// How a section's payload is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// A JSON array of the section's items.
    Json,
    /// Base64 of the items' `MessagePack` encodings, back to back.
    Packed,
    /// Base64 of the items' fixed little-endian records, back to back.
    Raw,
}

/// A snapshot section, in write order - the `tag` column's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Head,
    Intern,
    Nodes,
    Edges,
    Published,
    Extras,
    Outcomes,
    Requests,
    FeedPages,
    Batches,
}

impl Section {
    const ALL: [Self; 10] = [
        Self::Head,
        Self::Intern,
        Self::Nodes,
        Self::Edges,
        Self::Published,
        Self::Extras,
        Self::Outcomes,
        Self::Requests,
        Self::FeedPages,
        Self::Batches,
    ];

    const fn tag(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Intern => "intern",
            Self::Nodes => "nodes",
            Self::Edges => "edges",
            Self::Published => "published",
            Self::Extras => "extras",
            Self::Outcomes => "outcomes",
            Self::Requests => "requests",
            Self::FeedPages => "feed_page",
            Self::Batches => "batches",
        }
    }

    fn of_tag(tag: &str) -> Result<Self, QueueError> {
        Self::ALL
            .into_iter()
            .find(|section| section.tag() == tag)
            .ok_or_else(|| QueueError::Invariant(format!("unknown snapshot tag {tag}")))
    }

    const fn encoding(self) -> Encoding {
        match self {
            Self::Nodes | Self::Edges | Self::Published => Encoding::Raw,
            Self::Extras | Self::Outcomes => Encoding::Packed,
            Self::Head | Self::Intern | Self::Requests | Self::FeedPages | Self::Batches => {
                Encoding::Json
            }
        }
    }
}

/// One `snapshot_chunks` row: its section tag and payload text.
pub struct SnapshotChunk {
    /// The section this row carries.
    pub tag: &'static str,
    /// The encoded items.
    pub payload: String,
}

/// Where the next snapshot row starts: a section and the item inside
/// it. The graph must not change between two rows of one snapshot -
/// the writer's statements are storage operations under the object's
/// input gate, so no other request runs between them.
#[derive(Debug, Default)]
pub struct SnapshotCursor {
    section: usize,
    at: usize,
}

/// The snapshot's first row - the scalar state, the name vocabularies,
/// and every arena's length so the loader allocates each once at its
/// final size.
#[derive(Serialize, Deserialize)]
struct SnapshotHead {
    next_generation: u64,
    meter: Meter,
    freeze: Option<stow_types::api::DispatchFreezeRecord>,
    external_runs: Vec<(u64, u8)>,
    human_budget: (i64, i64),
    freeze_history: std::collections::VecDeque<stow_types::api::DispatchFreezeTransition>,
    /// Feed sessions without their staged pages - those ride the
    /// `feed_page` section.
    feed_sessions: std::collections::BTreeMap<String, FeedSession>,
    feed_watermark: Option<String>,
    /// Target names, in id order.
    targets: Vec<String>,
    /// Rustc versions, in id order.
    rustcs: Vec<String>,
    /// The trailing-day outcome tally by hour and target.
    outcome_hours: Vec<((i64, u8), (u32, u32))>,
    lens: SectionLens,
}

/// Item counts of the sections the loader preallocates - and checks,
/// so a snapshot missing a row fails the wake instead of loading short.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SectionLens {
    intern: usize,
    nodes: usize,
    edges: usize,
    published: usize,
}

/// One row being encoded.
struct ChunkWriter {
    encoding: Encoding,
    buf: Vec<u8>,
    items: usize,
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
    fn fill<T: Serialize>(&mut self, items: impl Iterator<Item = T>) -> Result<usize, QueueError> {
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
                Encoding::Raw => unreachable!("raw sections fill through fill_raw"),
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
        mut write: impl FnMut(&mut Vec<u8>, T),
    ) -> usize {
        let limit = self.limit();
        for item in items {
            write(&mut self.buf, item);
            self.items += 1;
            if self.buf.len() >= limit {
                break;
            }
        }
        self.items
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

fn write_node(buf: &mut Vec<u8>, node: &Node, state: Option<&State>) {
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

fn decode_base64(section: Section, payload: &str) -> Result<Vec<u8>, QueueError> {
    base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|error| {
            QueueError::Invariant(format!("snapshot {} decode: {error}", section.tag()))
        })
}

/// Decode one row's items, handing each to `sink` as it decodes.
fn decode_items<T: DeserializeOwned>(
    section: Section,
    payload: &str,
    mut sink: impl FnMut(T) -> Result<(), QueueError>,
) -> Result<(), QueueError> {
    let tag = section.tag();
    let invalid = |error: &dyn std::fmt::Display| {
        QueueError::Invariant(format!("snapshot {tag} decode: {error}"))
    };
    match section.encoding() {
        Encoding::Json => {
            let items: Vec<T> = serde_json::from_str(payload).map_err(|e| invalid(&e))?;
            items.into_iter().try_for_each(sink)
        }
        Encoding::Packed => {
            let bytes = decode_base64(section, payload)?;
            let mut rest = bytes.as_slice();
            while !rest.is_empty() {
                sink(rmp_serde::from_read(&mut rest).map_err(|e| invalid(&e))?)?;
            }
            Ok(())
        }
        Encoding::Raw => unreachable!("raw sections decode through decode_raw"),
    }
}

/// Decode one raw row, handing the byte cursor to `sink` once per record.
fn decode_raw(
    section: Section,
    payload: &str,
    mut sink: impl FnMut(&mut Bytes<'_>) -> Result<(), QueueError>,
) -> Result<(), QueueError> {
    let bytes = decode_base64(section, payload)?;
    let mut cursor = Bytes(&bytes);
    while !cursor.is_empty() {
        sink(&mut cursor)?;
    }
    Ok(())
}

impl Graph {
    /// Encode the snapshot row `cursor` points at and advance it;
    /// `None` once every section is written.
    ///
    /// # Errors
    /// `QueueError::Invariant` when freed nodes are still in the arena
    /// (the caller compacts first) or an item fails to serialize.
    pub fn next_snapshot_chunk(
        &self,
        cursor: &mut SnapshotCursor,
    ) -> Result<Option<SnapshotChunk>, QueueError> {
        if self.counts[Status::Free.index()] != 0 {
            return Err(QueueError::Invariant(
                "snapshot written over freed nodes: compact first".into(),
            ));
        }
        while let Some(&section) = Section::ALL.get(cursor.section) {
            let at = cursor.at;
            let mut writer = ChunkWriter::new(section.encoding());
            let taken = match section {
                Section::Head if at == 0 => writer.fill(std::iter::once(self.snapshot_head()))?,
                Section::Head => 0,
                Section::Intern => writer.fill(self.intern.iter_from(at))?,
                Section::Nodes => writer.fill_raw(at..self.nodes.len(), |buf, ix| {
                    let node = &self.nodes[ix];
                    let state = (node.state != NO_STATE).then(|| &self.states[node.state as usize]);
                    write_node(buf, node, state);
                }),
                Section::Edges => writer.fill_raw(at..self.edges.len(), |buf, edge| {
                    buf.extend_from_slice(&self.edges.dep(edge).to_le_bytes());
                    buf.push(self.edges.raw_flags(edge));
                }),
                Section::Published => {
                    writer.fill_raw(self.published.iter().skip(at), |buf, (key, mask)| {
                        buf.extend_from_slice(key);
                        buf.push(*mask);
                    })
                }
                Section::Extras => writer.fill(self.extras.iter().skip(at))?,
                Section::Outcomes => writer.fill(self.attempt_outcomes.iter().skip(at))?,
                Section::Requests => writer.fill(self.requests.iter().skip(at))?,
                Section::FeedPages => writer.fill(
                    self.feed_sessions
                        .iter()
                        .flat_map(|(hour, session)| {
                            session
                                .staged
                                .iter()
                                .enumerate()
                                .map(move |(page, entries)| (hour, page, entries))
                        })
                        .skip(at),
                )?,
                Section::Batches => writer.fill(self.demand_batches.iter().skip(at))?,
            };
            if taken == 0 {
                cursor.section += 1;
                cursor.at = 0;
                continue;
            }
            cursor.at += taken;
            return Ok(Some(SnapshotChunk {
                tag: section.tag(),
                payload: writer.finish()?,
            }));
        }
        Ok(None)
    }

    fn snapshot_head(&self) -> SnapshotHead {
        SnapshotHead {
            next_generation: self.next_generation,
            meter: self.meter.clone(),
            freeze: self.freeze.clone(),
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
            lens: self.section_lens(),
        }
    }

    fn section_lens(&self) -> SectionLens {
        SectionLens {
            intern: self.intern.len(),
            nodes: self.nodes.len(),
            edges: self.edges.len(),
            published: self.published.len(),
        }
    }
}

/// A wake's graph under construction: rows apply in snapshot order,
/// then [`Self::finish`] rebuilds the derived state.
#[derive(Default)]
pub struct SnapshotLoader {
    graph: Graph,
    lens: Option<SectionLens>,
}

impl SnapshotLoader {
    /// Decode one row into the graph.
    ///
    /// # Errors
    /// `QueueError::Invariant` on an unknown tag, a row before the
    /// head, or a corrupt payload.
    pub fn apply(&mut self, tag: &str, payload: &str) -> Result<(), QueueError> {
        let section = Section::of_tag(tag)?;
        if section != Section::Head && self.lens.is_none() {
            return Err(QueueError::Invariant(format!(
                "snapshot {tag} row before the head"
            )));
        }
        let graph = &mut self.graph;
        match section {
            Section::Head => Self::apply_head(graph, &mut self.lens, payload),
            Section::Intern => decode_items(section, payload, |s: String| {
                graph.intern.load(&s);
                Ok(())
            }),
            Section::Nodes => decode_raw(section, payload, |bytes| Self::load_node(graph, bytes)),
            Section::Edges => decode_raw(section, payload, |bytes| {
                let dep = bytes.u32()?;
                let flags = bytes.u8()?;
                graph.edges.load(dep, flags);
                Ok(())
            }),
            Section::Published => decode_raw(section, payload, |bytes| {
                let key: IdKey = bytes.take()?;
                let mask = bytes.u8()?;
                graph.published.insert(key, mask);
                Ok(())
            }),
            Section::Extras => decode_items(section, payload, |(ix, extra): (u32, Extra)| {
                graph.extras.insert(ix, extra);
                Ok(())
            }),
            Section::Outcomes => decode_items(section, payload, |outcome: AttemptOutcome| {
                graph.attempt_outcomes.push_back(outcome);
                Ok(())
            }),

            Section::Requests => {
                decode_items(section, payload, |(id, record): (String, RequestRecord)| {
                    graph.requests.insert(id, record);
                    Ok(())
                })
            }
            Section::FeedPages => decode_items(
                section,
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
            Section::Batches => {
                decode_items(section, payload, |(id, batch): (String, (String, i64))| {
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
        graph.nodes.push(Node {
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
        });
        Ok(())
    }

    fn apply_head(
        graph: &mut Graph,
        lens: &mut Option<SectionLens>,
        payload: &str,
    ) -> Result<(), QueueError> {
        if lens.is_some() {
            return Err(QueueError::Invariant("snapshot carries two heads".into()));
        }
        let mut decoded = None;
        decode_items(Section::Head, payload, |head: SnapshotHead| {
            match decoded.replace(head) {
                None => Ok(()),
                Some(_) => Err(QueueError::Invariant(
                    "snapshot head row holds two heads".into(),
                )),
            }
        })?;
        let head =
            decoded.ok_or_else(|| QueueError::Invariant("snapshot head row is empty".into()))?;
        graph.next_generation = head.next_generation;
        graph.meter = head.meter;
        graph.freeze = head.freeze;
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
        graph.intern.reserve_exact(head.lens.intern);
        graph.nodes.reserve_exact(head.lens.nodes);
        graph.states.reserve(head.lens.nodes);
        graph.edges.reserve_exact(head.lens.edges);
        graph.published.reserve(head.lens.published);
        *lens = Some(head.lens);
        Ok(())
    }

    /// The loaded graph, its derived state rebuilt.
    ///
    /// # Errors
    /// `QueueError::Invariant` when the rows decoded a different arena
    /// size than the head recorded - a snapshot missing rows.
    pub fn finish(self) -> Result<Graph, QueueError> {
        let Some(lens) = self.lens else {
            // No snapshot yet: the log alone replays the graph.
            return Ok(self.graph);
        };
        let mut graph = self.graph;
        let loaded = graph.section_lens();
        if loaded != lens {
            return Err(QueueError::Invariant(format!(
                "snapshot head records {lens:?} but its rows decoded {loaded:?}"
            )));
        }
        graph.intern.index();
        graph.rebuild_after_load()?;
        Ok(graph)
    }
}
