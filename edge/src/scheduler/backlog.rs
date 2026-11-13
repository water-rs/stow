//! The backlog (stow#1501): the submissions the graph's memory lines
//! had no room for, kept verbatim in SQLite until completions free
//! room, then admitted into the graph in entry-point priority order.
//!
//! A submission is never refused for memory. What does not fit goes
//! here whole — a tree is one entry of consecutive `Submit` parts, the
//! rows the event log would hold — and an admitted entry's rows
//! append to the log as they are. The graph holds only the count and
//! bytes of what the table holds ([`Tally`]); the table is read by
//! entry, one bounded read per entry, never scanned.

use skyzen_services::durable::DurableDb;
use stow_types::api::{SchedulerEvent, SubmissionSource, SubmissionTree};

use super::graph::LoadedGraph;
use super::store;
use crate::errors::QueueError;

/// The `store_meta` key of one lane's entry count.
fn entries_key(lane: Lane) -> String {
    format!("backlog_entries_{}", lane.index())
}

/// The `store_meta` key of the bytes the table holds.
const BYTES_KEY: &str = "backlog_bytes";

/// The entry points in admission order: a request from stow.waterui.dev
/// first, then operations, the CLI's misses and last preheat. The
/// discriminant is the `lane` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lane {
    /// A Turnstile-admitted human request.
    Human = 0,
    /// An operations submission.
    Operations = 1,
    /// The CLI: a cache miss or an inexact hit.
    Cli = 2,
    /// A preheat tree.
    Preheat = 3,
}

impl Lane {
    /// Every lane, in admission order.
    pub const ALL: [Self; 4] = [Self::Human, Self::Operations, Self::Cli, Self::Preheat];

    /// The lane a submission's entry point queues under.
    #[must_use]
    pub const fn of(source: SubmissionSource) -> Self {
        match source {
            SubmissionSource::HumanRequest => Self::Human,
            SubmissionSource::Operations { .. } => Self::Operations,
            SubmissionSource::CacheMiss | SubmissionSource::InexactHit => Self::Cli,
            SubmissionSource::Preheat => Self::Preheat,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// What the backlog holds, as the graph keeps it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    /// Entries per lane, indexed by [`Lane`].
    entries: [u32; 4],
    /// Bytes of the stored rows' event text.
    bytes: u64,
}

impl Tally {
    /// Entries held across the lanes.
    #[must_use]
    pub fn entries(&self) -> u32 {
        self.entries.iter().sum()
    }

    /// Entries held in one lane.
    #[cfg(test)]
    #[must_use]
    pub const fn lane_entries(&self, lane: Lane) -> u32 {
        self.entries[lane.index()]
    }

    /// Bytes of the stored rows' event text.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The first lane holding an entry, in admission order.
    #[must_use]
    pub fn first_lane(&self) -> Option<Lane> {
        Lane::ALL
            .into_iter()
            .find(|&lane| self.entries[lane.index()] > 0)
    }

    const fn add(&mut self, lane: Lane, bytes: u64) {
        self.entries[lane.index()] += 1;
        self.bytes += bytes;
    }

    const fn remove(&mut self, lane: Lane, bytes: u64) {
        self.entries[lane.index()] -= 1;
        self.bytes -= bytes;
    }
}

/// The head entry the last admission pass could not fit: its lane and
/// the increment it needed against the most room the graph could make.
/// In memory only — a wake re-reads the head once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blocked {
    /// The lane whose head it is.
    pub lane: Lane,
    /// The bytes the entry would have added.
    pub increment: u64,
}

#[derive(skyzen::FromRow)]
struct MetaRow {
    key: String,
    value: i64,
}

/// Read the tally a wake installs: the few `store_meta` rows the
/// writes below keep.
///
/// # Errors
/// `QueueError::Sql` on a failed read, `QueueError::Invariant` on a
/// negative or unknown count.
pub async fn load_tally(db: &DurableDb) -> Result<Tally, QueueError> {
    let rows = db
        .query("SELECT key, value FROM store_meta WHERE key GLOB 'backlog_*'")
        .fetch_all::<MetaRow>()
        .await
        .map_err(|error| QueueError::Sql(format!("backlog tally: {error}")))?;
    let mut tally = Tally::default();
    for MetaRow { key, value } in rows {
        let value = u64::try_from(value)
            .map_err(|_| QueueError::Invariant(format!("backlog counter {key} went negative")))?;
        if key == BYTES_KEY {
            tally.bytes = value;
        } else if let Some(lane) = Lane::ALL.into_iter().find(|&lane| key == entries_key(lane)) {
            tally.entries[lane.index()] = u32::try_from(value)
                .map_err(|_| QueueError::Invariant(format!("backlog counter {key} overflows")))?;
        } else {
            return Err(QueueError::Invariant(format!(
                "unknown backlog counter {key}"
            )));
        }
    }
    Ok(tally)
}

/// Move the two counters of `lane` by one entry of `bytes`, in the
/// turn that writes or deletes its rows. `add` says which way.
async fn move_counters(
    db: &DurableDb,
    lane: Lane,
    bytes: u64,
    add: bool,
) -> Result<(), QueueError> {
    let sign = if add { 1i64 } else { -1 };
    let bytes = i64::try_from(bytes).expect("an entry's bytes fit i64");
    for (key, delta) in [
        (entries_key(lane), sign),
        (BYTES_KEY.to_owned(), sign * bytes),
    ] {
        db.query(
            "INSERT INTO store_meta(key, value) VALUES (?, ?) \
             ON CONFLICT(key) DO UPDATE SET value = value + excluded.value",
        )
        .bind(key)
        .bind(delta)
        .execute()
        .await
        .map_err(|error| QueueError::Sql(format!("backlog counter: {error}")))?;
    }
    Ok(())
}

/// Store `tree` whole: one row per `Submit` part, the first carrying
/// the `actor` of the request. The graph's tally moves with the write.
///
/// # Errors
/// `QueueError::Sql` on a failed write.
pub async fn push(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    tree: &SubmissionTree,
    actor: Option<&str>,
) -> Result<(), QueueError> {
    let lane = Lane::of(tree.source);
    let mut bytes = 0u64;
    for event in store::submission_events(tree) {
        let SchedulerEvent::Submit { part, parts, .. } = &event else {
            unreachable!("a submission's parts are Submit events");
        };
        let (part, parts) = (*part, *parts);
        let text = store::encode_event(&event)?;
        bytes += u64::try_from(text.len()).expect("row length fits u64");
        db.query("INSERT INTO backlog(lane, part, parts, actor, event) VALUES (?, ?, ?, ?, ?)")
            .bind(i64::from(lane as u8))
            .bind(i64::from(part))
            .bind(i64::from(parts))
            .bind(if part == 0 {
                actor.map(str::to_owned)
            } else {
                None
            })
            .bind(text)
            .execute()
            .await
            .map_err(|error| QueueError::Sql(format!("backlog push: {error}")))?;
    }
    move_counters(db, lane, bytes, true).await?;
    graph.with(|graph| graph.backlog.add(lane, bytes));
    Ok(())
}

/// One stored submission: its rows' span, size and tree.
#[derive(Debug)]
pub struct Entry {
    first: i64,
    last: i64,
    lane: Lane,
    bytes: u64,
    /// The verified run behind the request that submitted it.
    pub actor: Option<String>,
    /// The tree, reassembled from its parts.
    pub tree: SubmissionTree,
}

#[derive(skyzen::FromRow)]
struct PartRow {
    seq: i64,
    parts: i64,
    actor: Option<String>,
    event: String,
}

/// The oldest entry of `lane`, read whole: its first row, then the
/// rest of its parts, consecutive after it. `None` when the lane is
/// empty.
///
/// # Errors
/// `QueueError::Sql` on a failed read, `QueueError::Invariant` on an
/// entry whose rows do not make one tree.
pub async fn head(db: &DurableDb, lane: Lane) -> Result<Option<Entry>, QueueError> {
    let first = db
        .query(
            "SELECT seq, parts, actor, event FROM backlog WHERE lane = ? \
             ORDER BY seq LIMIT 1",
        )
        .bind(i64::from(lane as u8))
        .fetch_all::<PartRow>()
        .await
        .map_err(|error| QueueError::Sql(format!("backlog head: {error}")))?
        .pop();
    let Some(first) = first else {
        return Ok(None);
    };
    let mut rows = vec![first];
    let parts = rows[0].parts;
    if parts > 1 {
        rows.extend(
            db.query(
                "SELECT seq, parts, actor, event FROM backlog WHERE seq > ? ORDER BY seq LIMIT ?",
            )
            .bind(rows[0].seq)
            .bind(parts - 1)
            .fetch_all::<PartRow>()
            .await
            .map_err(|error| QueueError::Sql(format!("backlog parts: {error}")))?,
        );
    }
    let corrupt =
        |why: &str| QueueError::Invariant(format!("backlog entry at {}: {why}", rows[0].seq));
    if i64::try_from(rows.len()).ok() != Some(parts) {
        return Err(corrupt("its parts are missing"));
    }
    let mut source = None;
    let mut roots = Vec::new();
    let mut nodes = Vec::new();
    let mut bytes = 0u64;
    for (at, row) in rows.iter().enumerate() {
        bytes += u64::try_from(row.event.len()).expect("row length fits u64");
        let SchedulerEvent::Submit {
            source: part_source,
            part,
            roots: part_roots,
            nodes: part_nodes,
            ..
        } = store::decode_event(&row.event)?
        else {
            return Err(corrupt("a row is not a submit part"));
        };
        if usize::try_from(part).ok() != Some(at) || row.parts != parts {
            return Err(corrupt("its parts are out of order"));
        }
        if source
            .replace(part_source)
            .is_some_and(|held| held != part_source)
        {
            return Err(corrupt("its parts disagree on the source"));
        }
        if at == 0 {
            roots = part_roots;
        }
        nodes.extend(part_nodes);
    }
    let last = rows.last().expect("an entry has a part").seq;
    let first_row = rows.swap_remove(0);
    Ok(Some(Entry {
        first: first_row.seq,
        last,
        lane,
        bytes,
        actor: first_row.actor,
        tree: SubmissionTree {
            source: source.expect("an entry has a part"),
            roots,
            nodes,
        },
    }))
}

/// Delete an entry's rows — it was admitted — and move the tally.
///
/// # Errors
/// `QueueError::Sql` on a failed write.
pub async fn remove(
    graph: LoadedGraph<'_>,
    db: &DurableDb,
    entry: &Entry,
) -> Result<(), QueueError> {
    db.query("DELETE FROM backlog WHERE seq BETWEEN ? AND ?")
        .bind(entry.first)
        .bind(entry.last)
        .execute()
        .await
        .map_err(|error| QueueError::Sql(format!("backlog remove: {error}")))?;
    move_counters(db, entry.lane, entry.bytes, false).await?;
    graph.with(|graph| graph.backlog.remove(entry.lane, entry.bytes));
    Ok(())
}

impl Entry {
    /// Bytes of the stored rows' event text.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}
