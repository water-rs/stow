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
//! statement's cursor counters into `Graph::meter`; the snapshot
//! carries the counters and a wake re-counts the log tail it replays.
//!
//! The schema is `schema.sql`, created only by [`reset`]; request code
//! and the alarm never issue DDL, so a store nobody reset fails the
//! wake's first read.

use skyzen_services::durable::DurableDb;
use stow_types::api::{
    SchedulerEvent, SchedulerResetReport, SubmissionNode, SubmissionSource, SubmissionTree,
};

use super::graph::{Graph, SnapshotChunk, SnapshotCursor, SnapshotLoader};
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
pub async fn append_events(
    db: &DurableDb,
    events: &[SchedulerEvent],
    at: i64,
) -> Result<Appended, QueueError> {
    let mut appended = Appended { seq: 0, bytes: 0 };
    for event in events {
        let text = encode_event(event)?;
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

/// Serialize the graph into `snapshot_chunks` row by row — see
/// [`write_snapshot_parts`].
///
/// # Errors
/// `QueueError::Sql`/`QueueError::Invariant` on a failed write.
pub async fn write_snapshot(db: &DurableDb, graph: &mut Graph) -> Result<i64, QueueError> {
    graph.compact();
    let mut cursor = SnapshotCursor::default();
    write_snapshot_parts(db, || graph.next_snapshot_chunk(&mut cursor)).await
}

/// Write a snapshot, the rows produced one at a time by a sync
/// provider — the Durable Object's graph lives behind a lock that
/// cannot be held across an `.await`, so the caller encodes each row
/// between writes. The statements are all storage operations, held
/// under the object's input gate, so no other request mutates the
/// graph between two rows. Peak memory is one row's bytes. The
/// watermark stamps after the rows and the covered log drops last:
/// the drop is the commit point, a crash mid-write leaves the old
/// watermark, so the old snapshot plus the full log still replay.
///
/// Returns the watermark the snapshot covers.
///
/// # Errors
/// `QueueError` on a failed storage op or the provider's own error.
pub async fn write_snapshot_parts(
    db: &DurableDb,
    mut next: impl FnMut() -> Result<Option<SnapshotChunk>, QueueError>,
) -> Result<i64, QueueError> {
    let covered = db
        .query("SELECT COALESCE(MAX(seq), 0) FROM event_log")
        .fetch_scalar::<i64>()
        .await
        .map_err(|error| QueueError::Sql(format!("snapshot watermark: {error}")))?;
    db.query("DELETE FROM snapshot_chunks")
        .execute()
        .await
        .map_err(|error| QueueError::Sql(format!("snapshot clear: {error}")))?;
    let mut ix = 0i64;
    while let Some(chunk) = next()? {
        db.query("INSERT INTO snapshot_chunks(chunk, tag, payload) VALUES (?, ?, ?)")
            .bind(ix)
            .bind(chunk.tag)
            .bind(chunk.payload)
            .execute()
            .await
            .map_err(|error| QueueError::Sql(format!("snapshot chunk {ix}: {error}")))?;
        ix += 1;
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
    Ok(covered)
}

#[derive(skyzen::FromRow)]
struct SnapshotRow {
    tag: String,
    payload: String,
}

/// Wake: read the watermark, then the snapshot one row per statement —
/// each row decodes into the graph before the next is read, so the
/// serialized image is never held whole — then the log tail. Returns
/// the rebuilt graph — its meter carries the snapshot's counters — and
/// the log tail to apply through [`apply_events`].
///
/// # Errors
/// `QueueError::Sql`/`QueueError::Invariant` on a failed read or
/// corrupt row.
pub async fn load(db: &DurableDb) -> Result<(Graph, Vec<Logged>), QueueError> {
    let seq = watermark(db).await?;
    let mut loader = SnapshotLoader::default();
    let mut ix = 0i64;
    while let Some(row) = db
        .query("SELECT tag, payload FROM snapshot_chunks WHERE chunk = ?")
        .bind(ix)
        .fetch_optional::<SnapshotRow>()
        .await
        .map_err(|error| QueueError::Sql(format!("snapshot read {ix}: {error}")))?
    {
        loader.apply(&row.tag, &row.payload)?;
        ix += 1;
    }
    let graph = loader.finish()?;
    let tail = log_tail(db, seq).await?;
    Ok((graph, tail.into_iter().map(|(_, logged)| logged).collect()))
}

/// Apply the log tail to the graph, each event at its own instant:
/// `Submit` parts reassemble into one merge — a truncated tail (a
/// submit whose ack never left, appended but never completed) drops,
/// consistent with it never having been acknowledged — and every
/// other kind goes through [`Graph::apply`]. Each row re-counts as one
/// written row on its day's meter.
pub fn apply_events(graph: &mut Graph, events: &[Logged]) {
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
    for Logged { at, event, bytes } in events {
        graph.meter.replayed(*at);
        graph.log_appended(*bytes);
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
        // The log already carries the samples a replayed completion
        // produces as `BuildSample` rows of its own.
        graph.take_samples();
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
    use stow_types::identity::{
        CrateName, CrateVersion, DependencyIdentity, FeaturesJson, TargetTriple, WireRustcVersion,
    };
    use stow_types::public_cache::{
        ExplicitSpelling, UnitInvocation, UnitKind, UnitShape, UnitSide,
    };

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.85.0";

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

    /// The tail a wake reads, as `apply_events` takes it.
    fn logged(events: &[SchedulerEvent], at: i64) -> Vec<Logged> {
        events
            .iter()
            .map(|event| Logged {
                at,
                bytes: 0,
                event: event.clone(),
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
        append_events(&db, &events, 0).await.expect("append");
        let covered = write_snapshot(&db, &mut graph).await.expect("snapshot");
        assert!(covered > 0);
        assert_eq!(log_tail(&db, covered).await.expect("tail").len(), 0);

        // Forced eviction: reload from the store only.
        let (mut restored, tail) = load(&db).await.expect("load");
        assert!(tail.is_empty(), "snapshot covered the whole log");
        apply_events(&mut restored, &tail);
        assert_eq!(restored.status_counts(), graph.status_counts());
        let claimed = restored.claim(45, 16, 20_000, 3_600_000).expect("claim b");
        assert_eq!(claimed[0].task_id, id("b"));
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
        append_events(&db, &events, 0).await.expect("submit");
        apply_events(&mut graph, &logged(&events, 0));
        let claims = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        let generation = claims[0].generation;
        // The pass appends ONE row for the claims before posting —
        // then the isolate is evicted before the bindings land.
        append_events(
            &db,
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
        assert_eq!(restored.status_counts()["dispatched"], 1);
        // The post-wake status reconcile binds by run title.
        restored.reconcile_runs(
            &[(4242, format!("{RUSTC}-{}", id("solo")), RunnerFamily::Linux)],
            200,
        );
        assert_eq!(restored.status_counts()["dispatched"], 1);
        let outcome = restored.run_finished(&id("solo"), 4242, true, false, None, 300);
        assert_eq!(outcome, super::super::graph::FinishOutcome::Applied);
        assert_eq!(restored.status_counts()["completed"], 1);
    }

    #[tokio::test]
    async fn parked_completion_applies_on_replayed_binding() {
        let db = store().await;
        let tree = SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![0],
            nodes: vec![node("solo")],
        };
        append_events(&db, &submission_events(&tree), 0)
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
        append_events(&db, &events, 0).await.expect("deliveries");
        let (mut restored, tail) = load(&db).await.expect("wake");
        apply_events(&mut restored, &tail);
        assert_eq!(restored.status_counts()["completed"], 1);
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
        append_events(&db, &events[..1], 0).await.expect("part 0");
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
        let last = append_events(&db, &submission_events(&tree), 5_000)
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
        let last = append_events(&db, &events, 5_000).await.expect("mutations");
        assert_eq!(last.seq, 3);

        // A wake re-counts what it replays: one written row per event.
        let (mut restored, tail) = load(&db).await.expect("load");
        assert_eq!(tail.len(), 3);
        apply_events(&mut restored, &tail);
        assert_eq!(restored.meter.rows_written, 3);
    }

    /// An append right after a snapshot emptied the log is replayed: the
    /// next `seq` must stay above the watermark.
    #[tokio::test]
    async fn an_append_after_a_snapshot_is_in_the_next_tail() {
        let db = store().await;
        let mut graph = Graph::default();
        append_events(
            &db,
            &[SchedulerEvent::Mutate {
                op: MutationKind::Retry,
                task_ids: Vec::new(),
            }],
            0,
        )
        .await
        .expect("append");
        let covered = write_snapshot(&db, &mut graph).await.expect("snapshot");
        let appended = append_events(
            &db,
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
}
