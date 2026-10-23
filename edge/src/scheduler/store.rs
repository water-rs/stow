//! The scheduler's flat persistence substrate (stow#878): an
//! append-only `event_log`, chunked `snapshot_chunks`, and one
//! `store_meta` row carrying the snapshot watermark — the only tables
//! the in-memory [`super::graph::Graph`] survives a forced eviction by.
//!
//! Every accepted event is appended before the request or pass that
//! produced it is acknowledged; on the DO the statements inside one
//! request's input gate land as one turn (the "single transaction" the
//! review requires). A snapshot writes its chunks, then the watermark,
//! then drops the covered log rows — the drop is the commit point, so
//! a crash mid-snapshot replays the old snapshot plus the full log.
//!
//! Billed rows are counted in memory (`Graph::meter`), never in a
//! table — appends and inserts book one row each, selects book the
//! rows they return, deletes book `rows_written` — and the snapshot
//! carries the counters while a wake re-counts the tail it reads.

use skyzen_services::durable::DurableDb;
use stow_types::api::{SchedulerEvent, SubmissionNode, SubmissionSource, SubmissionTree};

use super::graph::{Graph, Meter, SnapshotChunk};
use crate::errors::QueueError;

/// The three-table schema the flat store owns. `ensure_schema` is the
/// only DDL path — reset recreates it with the rest of `schema.sql`.
const STORE_SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS event_log ( \
        seq INTEGER PRIMARY KEY, \
        event BLOB NOT NULL \
    )",
    "CREATE TABLE IF NOT EXISTS snapshot_chunks ( \
        chunk INTEGER PRIMARY KEY, \
        tag TEXT NOT NULL, \
        payload BLOB NOT NULL \
    )",
    "CREATE TABLE IF NOT EXISTS store_meta ( \
        key TEXT PRIMARY KEY, \
        value BLOB NOT NULL \
    )",
];

/// Nodes per `Submit` log part — bounds a part's serialized size far
/// under the platform's ~2 MB row bound.
const SUBMIT_PART_NODES: usize = 1024;

/// The log length (events appended since the last snapshot) that
/// triggers a snapshot at the tail of the turn that crossed it.
pub const SNAPSHOT_EVENT_THRESHOLD: u64 = 8192;

/// Create the flat store's tables — idempotent.
///
/// # Errors
/// `QueueError::Sql` on a failed statement.
pub async fn ensure_schema(db: &DurableDb) -> Result<(), QueueError> {
    for statement in STORE_SCHEMA {
        db.query(statement)
            .execute()
            .await
            .map_err(|error| QueueError::Sql(format!("flat store schema: {error}")))?;
    }
    Ok(())
}

/// Serialize one event for the log.
///
/// # Errors
/// `QueueError::Invariant` when the event cannot serialize — a bug,
/// never data-dependent.
pub fn encode_event(event: &SchedulerEvent) -> Result<Vec<u8>, QueueError> {
    serde_json::to_vec(event)
        .map_err(|error| QueueError::Invariant(format!("event encode: {error}")))
}

/// Decode one log row.
///
/// # Errors
/// `QueueError::Invariant` on undecodable bytes — corrupt store.
pub fn decode_event(bytes: &[u8]) -> Result<SchedulerEvent, QueueError> {
    serde_json::from_slice(bytes)
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

/// Append events in submission order; returns the last sequence
/// number written (`0` for an empty batch). One call's rows land in
/// one turn of the request that produced them — the single append
/// transaction the submit path acknowledges after.
///
/// # Errors
/// `QueueError::Sql` on a failed insert.
pub async fn append_events(
    db: &DurableDb,
    meter: &mut Meter,
    events: &[SchedulerEvent],
) -> Result<i64, QueueError> {
    let mut last = 0;
    for event in events {
        let seq = db
            .query("INSERT INTO event_log(event) VALUES (?) RETURNING seq")
            .bind(encode_event(event)?)
            .fetch_scalar::<i64>()
            .await
            .map_err(|error| QueueError::Sql(format!("log append: {error}")))?;
        meter.record("log.append", 0, 1);
        last = seq;
    }
    Ok(last)
}

/// Append a single event — [`append_events`] of one.
///
/// # Errors
/// `QueueError::Sql` on a failed insert.
pub async fn append_event(
    db: &DurableDb,
    meter: &mut Meter,
    event: &SchedulerEvent,
) -> Result<i64, QueueError> {
    append_events(db, meter, std::slice::from_ref(event)).await
}

/// Read `event_log` rows after `seq` in order.
///
/// # Errors
/// `QueueError::Sql` on a failed select.
pub async fn log_tail(
    db: &DurableDb,
    meter: &mut Meter,
    seq: i64,
) -> Result<Vec<(i64, Vec<u8>)>, QueueError> {
    let rows = db
        .query("SELECT seq, event FROM event_log WHERE seq > ? ORDER BY seq")
        .bind(seq)
        .fetch_all::<LogRow>()
        .await
        .map_err(|error| QueueError::Sql(format!("log tail: {error}")))?;
    meter.record("log.tail", u64::try_from(rows.len()).unwrap_or(u64::MAX), 0);
    Ok(rows.into_iter().map(|row| (row.seq, row.event)).collect())
}

#[derive(skyzen::FromRow)]
struct LogRow {
    seq: i64,
    event: Vec<u8>,
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

/// Serialize the graph into `snapshot_chunks` chunk by chunk — the
/// peak is one chunk's bytes — then stamp the watermark and drop the
/// covered log. The drop is the commit point: a crash mid-write
/// leaves the old watermark, so the old snapshot plus the full log
/// still replay.
///
/// Returns the watermark the snapshot covers.
///
/// # Errors
/// `QueueError::Sql`/`QueueError::Invariant` on a failed write.
pub async fn write_snapshot(db: &DurableDb, graph: &mut Graph) -> Result<i64, QueueError> {
    let covered = db
        .query("SELECT COALESCE(MAX(seq), 0) FROM event_log")
        .fetch_scalar::<i64>()
        .await
        .map_err(|error| QueueError::Sql(format!("snapshot watermark: {error}")))?;
    graph.meter.record("snapshot.mark", 1, 0);
    let result = db
        .query("DELETE FROM snapshot_chunks")
        .execute()
        .await
        .map_err(|error| QueueError::Sql(format!("snapshot clear: {error}")))?;
    graph
        .meter
        .record("snapshot.clear", result.rows_read, result.rows_written);
    for ix in 0..graph.snapshot_chunk_count() {
        let Some(chunk) = graph.snapshot_chunk(ix)? else {
            break;
        };
        db.query("INSERT INTO snapshot_chunks(chunk, tag, payload) VALUES (?, ?, ?)")
            .bind(i64::try_from(ix).expect("chunk index fits i64"))
            .bind(chunk.tag)
            .bind(chunk.payload)
            .execute()
            .await
            .map_err(|error| QueueError::Sql(format!("snapshot chunk {ix}: {error}")))?;
        graph.meter.record("snapshot.chunk", 0, 1);
    }
    db.query(
        "INSERT INTO store_meta(key, value) VALUES ('snapshot_seq', ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(covered)
    .execute()
    .await
    .map_err(|error| QueueError::Sql(format!("snapshot meta: {error}")))?;
    graph.meter.record("snapshot.meta", 0, 1);
    let result = db
        .query("DELETE FROM event_log WHERE seq <= ?")
        .bind(covered)
        .execute()
        .await
        .map_err(|error| QueueError::Sql(format!("snapshot drop: {error}")))?;
    graph
        .meter
        .record("snapshot.drop", result.rows_read, result.rows_written);
    Ok(covered)
}

/// Read the snapshot chunks in order.
///
/// # Errors
/// `QueueError::Sql` on a failed select.
async fn snapshot_rows(
    db: &DurableDb,
    meter: &mut Meter,
) -> Result<Vec<SnapshotChunk>, QueueError> {
    let rows = db
        .query("SELECT tag, payload FROM snapshot_chunks ORDER BY chunk")
        .fetch_all::<SnapshotRow>()
        .await
        .map_err(|error| QueueError::Sql(format!("snapshot read: {error}")))?;
    meter.record(
        "snapshot.read",
        u64::try_from(rows.len()).unwrap_or(u64::MAX),
        0,
    );
    rows.into_iter()
        .map(|row| {
            Ok(SnapshotChunk {
                tag: match row.tag.as_str() {
                    "head" => "head",
                    "intern" => "intern",
                    "nodes" => "nodes",
                    "edges" => "edges",
                    "published" => "published",
                    "idents" => "idents",
                    other => {
                        return Err(QueueError::Invariant(format!(
                            "unknown snapshot tag {other}"
                        )));
                    }
                },
                payload: row.payload,
            })
        })
        .collect()
}

#[derive(skyzen::FromRow)]
struct SnapshotRow {
    tag: String,
    payload: Vec<u8>,
}

/// Wake: read the watermark, the snapshot chunks and the log tail.
/// Returns the rebuilt graph — its meter already carries the
/// snapshot's counters plus everything this wake read — and the
/// decoded log tail to apply through [`apply_events`].
///
/// # Errors
/// `QueueError::Sql`/`QueueError::Invariant` on a failed read or
/// corrupt chunk.
pub async fn load(db: &DurableDb) -> Result<(Graph, Vec<SchedulerEvent>), QueueError> {
    let seq = watermark(db).await?;
    let mut graph = Graph::default();
    // The wake's own reads count against the day on the rebuilt
    // meter — the snapshot's counters arrive inside the head chunk.
    graph.meter.rows_read += 1;
    let chunks = snapshot_rows(db, &mut graph.meter).await?;
    if !chunks.is_empty() {
        graph = Graph::from_snapshot_chunks(&chunks)?;
        // `from_snapshot_chunks` overwrote the meter from the head —
        // the wake's own reads still belong on it.
        graph.meter.rows_read += 1;
    }
    let tail = log_tail(db, &mut graph.meter, seq).await?;
    let events = tail
        .iter()
        .map(|(_, bytes)| decode_event(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((graph, events))
}

/// Apply the decoded log tail to the graph: `Submit` parts reassemble
/// into one merge — a truncated tail (a submit whose ack never left,
/// appended but never completed) drops, consistent with it never
/// having been acknowledged — and every other kind goes through
/// [`Graph::apply`].
pub fn apply_events(graph: &mut Graph, events: &[SchedulerEvent], now: i64) {
    struct Pending {
        source: SubmissionSource,
        parts: u32,
        roots: Vec<u32>,
        nodes: Vec<SubmissionNode>,
    }
    let mut pending: Option<Pending> = None;
    let complete = |graph: &mut Graph, pending: &mut Option<Pending>, now: i64| {
        if let Some(p) = pending.take()
            && u32::try_from(p.nodes.len().div_ceil(SUBMIT_PART_NODES)).unwrap_or(u32::MAX)
                <= p.parts
        {
            let _ = graph.merge(
                &SubmissionTree {
                    source: p.source,
                    roots: p.roots,
                    nodes: p.nodes,
                },
                now,
            );
        }
    };
    for event in events {
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
                        complete(graph, other, now);
                        other.insert(Pending {
                            source: *source,
                            parts: *parts,
                            roots: Vec::new(),
                            nodes: Vec::new(),
                        })
                    }
                };
                if *part == 0 {
                    next.roots.clone_from(roots);
                }
                next.nodes.extend(nodes.iter().cloned());
                if *part + 1 == *parts {
                    complete(graph, &mut pending, now);
                }
            }
            other => {
                complete(graph, &mut pending, now);
                graph.apply(other, now);
            }
        }
    }
    complete(graph, &mut pending, now);
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
        SubmissionNode {
            task_id: format!("{name}-id"),
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
        }
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
        let db = test_db::memory_db_raw().await.expect("db");
        ensure_schema(&db).await.expect("schema");
        db
    }

    #[tokio::test]
    async fn snapshot_round_trip_replays_the_graph() {
        let db = store().await;
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        let claims = graph.claim(45, 16, 0, 3_600_000).expect("claim c");
        let generation = claims[0].generation;
        graph.bind("c-id", generation, 700, 1_000);
        graph.run_finished("c-id", 700, true, false, None, 10_000);
        graph.apply_slice_report(TARGET, RUSTC, &c_rows(), &[]);

        // The log records the wave; the snapshot then drops it.
        let events = vec![
            SchedulerEvent::Claims {
                claims: vec![DispatchClaim {
                    task_id: "c-id".into(),
                    generation: 1,
                    attempt: 1,
                }],
            },
            SchedulerEvent::Bindings {
                bindings: vec![DispatchBinding {
                    task_id: "c-id".into(),
                    generation: 1,
                    run_id: "700".into(),
                }],
            },
            SchedulerEvent::RunFinished {
                run_id: "700".into(),
                task_id: "c-id".into(),
                success: true,
                cancelled: false,
                error: None,
            },
        ];
        append_events(&db, &mut graph.meter, &events)
            .await
            .expect("append");
        let covered = write_snapshot(&db, &mut graph).await.expect("snapshot");
        assert!(covered > 0);
        assert_eq!(
            log_tail(&db, &mut graph.meter, covered)
                .await
                .expect("tail")
                .len(),
            0
        );

        // Forced eviction: reload from the store only.
        let (mut restored, tail) = load(&db).await.expect("load");
        assert!(tail.is_empty(), "snapshot covered the whole log");
        apply_events(&mut restored, &tail, 20_000);
        assert_eq!(restored.status_counts(), graph.status_counts());
        let claimed = restored.claim(45, 16, 20_000, 3_600_000).expect("claim b");
        assert_eq!(claimed[0].task_id, "b-id");
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
        append_events(&db, &mut graph.meter, &events)
            .await
            .expect("submit");
        apply_events(&mut graph, &events, 0);
        let claims = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        let generation = claims[0].generation;
        // The pass appends ONE row for the claims before posting —
        // then the isolate is evicted before the bindings land.
        append_event(
            &db,
            &mut graph.meter,
            &SchedulerEvent::Claims {
                claims: vec![DispatchClaim {
                    task_id: "solo-id".into(),
                    generation,
                    attempt: 1,
                }],
            },
        )
        .await
        .expect("claims row");

        let (mut restored, tail) = load(&db).await.expect("wake");
        apply_events(&mut restored, &tail, 100);
        // The claim replays as dispatched-unbound — no dispatch is lost
        // and nothing re-dispatches.
        assert_eq!(restored.status_counts()["dispatched"], 1);
        // The post-wake status reconcile binds by run title.
        restored.reconcile_runs(
            &[(4242, format!("{RUSTC}-solo-id"), RunnerFamily::Linux)],
            200,
        );
        assert_eq!(restored.status_counts()["dispatched"], 1);
        let outcome = restored.run_finished("solo-id", 4242, true, false, None, 300);
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
        let mut meter = Meter::default();
        append_events(&db, &mut meter, &submission_events(&tree))
            .await
            .expect("submit");
        // completed arrives before its binding in the log — parked on
        // replay, applied when the binding lands.
        let events = vec![
            SchedulerEvent::Claims {
                claims: vec![DispatchClaim {
                    task_id: "solo-id".into(),
                    generation: 7,
                    attempt: 1,
                }],
            },
            SchedulerEvent::RunFinished {
                run_id: "909".into(),
                task_id: "solo-id".into(),
                success: true,
                cancelled: false,
                error: None,
            },
            SchedulerEvent::Bindings {
                bindings: vec![DispatchBinding {
                    task_id: "solo-id".into(),
                    generation: 7,
                    run_id: "909".into(),
                }],
            },
        ];
        append_events(&db, &mut meter, &events)
            .await
            .expect("deliveries");
        let (mut restored, tail) = load(&db).await.expect("wake");
        apply_events(&mut restored, &tail, 0);
        assert_eq!(restored.status_counts()["completed"], 1);
    }

    #[tokio::test]
    async fn the_meter_counts_appends_reads_and_replays() {
        let db = store().await;
        let mut meter = Meter::default();
        meter.roll_to("2026-10-23");
        let tree = SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![0],
            nodes: vec![node("one"), node("two")],
        };
        append_events(&db, &mut meter, &submission_events(&tree))
            .await
            .expect("submit");
        // One Submit part, one appended row.
        assert_eq!(meter.rows_written, 1);
        let events = vec![
            SchedulerEvent::Mutate {
                op: MutationKind::Retry,
                task_ids: vec!["one-id".into()],
            },
            SchedulerEvent::Floor { value: 3 },
        ];
        append_events(&db, &mut meter, &events)
            .await
            .expect("mutations");
        assert_eq!(meter.rows_written, 3);

        // A wake re-counts what it reads: snapshot row(s) + watermark +
        // the 3 log rows' tail.
        let mut graph = Graph::default();
        graph.merge(&tree, 0).expect("merge");
        write_snapshot(&db, &mut graph).await.expect("snapshot");
        let (restored, tail) = load(&db).await.expect("load");
        // The log tail is gone post-snapshot; the reads are the
        // watermark + the snapshot's chunks.
        assert!(tail.is_empty());
        assert!(restored.meter.rows_read >= 2);
        assert_eq!(
            restored.meter.rows_written, 0,
            "counters come from the snapshot head"
        );
    }
}
