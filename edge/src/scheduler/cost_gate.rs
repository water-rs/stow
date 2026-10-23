//! The stow#433 host-side cost gate — a fast pre-check that runs in
//! `cargo test -p stow-edge`. It is *not* the number Cloudflare bills:
//! the host backend exposes no scan-step counters, so `rows_read` here
//! is the statements' result cardinality and `rows_written` their
//! `changes()`. The billed gate is the workerd harness
//! (`budget.rs` + `scripts/traffic-cost.sh`), which replays the
//! same [`drives`] list on the 100k fixture inside the Durable Object
//! and reports the real cursor counters. This test keeps the host
//! proxies honest on a small fixture — a regression that goes
//! queue-size-proportional trips it in seconds instead of waiting for a
//! workerd run.
//!
//! Besides the numeric budgets, two mechanical rules hold on the
//! statement log of every drive:
//!
//! * no `CREATE`/`ALTER`/`DROP`/`PRAGMA` — schema work is operations
//!   work (stow#432), so a route whose log contains one fails even when
//!   it fits its budget;
//! * every logged statement is replayed under `EXPLAIN QUERY PLAN`, and
//!   a `SCAN` of `queue`, `queue_dependencies`, `published_slices` or
//!   `published_slice_rows` — under the table's name or any alias the
//!   statement gave it — fails the route unless the plan detail is on
//!   that route's allowlist, every entry of which names its reason.
//!
//! Budgets are measured values with headroom, not ceilings a change may
//! drift under: a route that gets cheaper gets a tighter budget — it
//! may never be raised to pass a regression.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use skyzen::FromRow;
use skyzen_services::durable::DurableDb;

use super::drives;
use super::fixture;
use super::queue::{self, SchedulerSettings};
use super::test_db::{LoggedStatement, counting_memory_db, counting_memory_db_raw};

/// One row of the budget table.
struct RouteBudget {
    /// The drive's name in [`drives::DRIVES`].
    name: &'static str,
    /// Upper bound on statements the route may issue.
    statements: usize,
    /// Upper bound on Σ result cardinality across those statements.
    rows_read: u64,
    /// Upper bound on Σ `changes()` across those statements.
    rows_written: u64,
    /// `EXPLAIN QUERY PLAN` detail substrings allowed to scan —
    /// every entry carries a comment naming its reason.
    scan_allowlist: &'static [&'static str],
}

/// The budget table — one entry per [`drives::DRIVES`] entry. Measured on
/// the 10k fixture; numbers carry ~2× headroom so fixture timing noise
/// never flakes a legitimate run while a real regression
/// (queue-size-proportional work) fails by orders of magnitude, not by a
/// budget's slack. The numbers that gate a merge are the workerd ones —
/// this table's job is to keep the cheap check cheap.
const BUDGETS: &[RouteBudget] = &[
    // Read paths — point lookups and bounded aggregates.
    RouteBudget {
        name: "GET /status",
        statements: 6,
        rows_read: 60,
        rows_written: 0,
        scan_allowlist: &["SCAN queue_dependencies USING INDEX idx_queue_dependencies_unresolved"],
    },
    RouteBudget {
        name: "GET /admin/status",
        statements: 12,
        rows_read: 200,
        rows_written: 0,
        scan_allowlist: &["SCAN queue_dependencies USING INDEX idx_queue_dependencies_unresolved"],
    },
    RouteBudget {
        name: "GET /tasks",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // Index-ordered tail read: the ORDER BY walks
        // `idx_queue_first_requested` and stops at the page's LIMIT —
        // the plan prints SCAN but reads only the newest page.
        scan_allowlist: &["SCAN queue USING INDEX idx_queue_first_requested"],
    },
    RouteBudget {
        name: "GET /tasks?status=failed",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // The spelled `status IN ('completed','failed')` term bounds
        // the walk to the failed group of `idx_queue_terminal_updated`;
        // the LIMIT stops it at a page.
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "GET /tasks?status=pending",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // `status = 'pending'` walks `idx_queue_pending_first` on the
        // unblocked arm; `first_requested_at` orders the page.
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "GET /tasks?status=blocked",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // `status='pending' AND blocked=1` walks the
        // `idx_queue_pending_first` partial index, whose (blocked,
        // first_requested_at) key bounds the walk to the blocked group.
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "GET /tasks?target=…",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // `idx_queue_target_first` bounds the walk to the target's
        // own group.
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "GET /tasks?crate=…",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // `idx_queue_crate_first` bounds the walk to the crate's rows.
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "GET /tasks?older_than=86400",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // `updated_at < now - older_than` keeps its exact semantics;
        // the implied `first_requested_at` bound the selector emits
        // beside it is what becomes the range probe on
        // `idx_queue_first_requested`.
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "GET /tasks?task_ids=…",
        statements: 2,
        rows_read: 40,
        rows_written: 0,
        // Explicit ids: primary-key lookups, no walk.
        scan_allowlist: &[],
    },
    // Mutation routes — one keyed statement each against a bounded
    // selector.
    RouteBudget {
        // Measured 4/4/8 once the host backend counts `RETURNING`
        // writes (stow#796): the two retried rows, their status-count
        // trigger rows and the keyed follow-up writes.
        name: "POST /tasks/retry",
        statements: 4,
        rows_read: 10,
        rows_written: 16,
        scan_allowlist: &[],
    },
    RouteBudget {
        // Measured 3/2/9 once `RETURNING` writes count (stow#796): the
        // cancelled rows, their status-count trigger rows, and the
        // dependents' `blocked` flips — failing a task that pending
        // rows depend on must wake-block them in the same request, not
        // on the next pass.
        name: "POST /tasks/cancel",
        statements: 3,
        rows_read: 10,
        rows_written: 20,
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "POST /tasks/promote",
        statements: 3,
        rows_read: 10,
        rows_written: 4,
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "POST /tasks/purge",
        statements: 3,
        rows_read: 10,
        rows_written: 8,
        scan_allowlist: &[],
    },
    // The request lane — point reads and writes on `requests`, a table
    // that never grows past the live request set.
    RouteBudget {
        name: "GET /requests/{id}",
        statements: 4,
        rows_read: 40,
        rows_written: 0,
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "POST /requests",
        statements: 4,
        rows_read: 20,
        rows_written: 6,
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "POST /requests/{id}/run-update (in_progress)",
        statements: 3,
        rows_read: 10,
        rows_written: 4,
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "POST /requests/{id}/outcome",
        statements: 14,
        rows_read: 60,
        rows_written: 40,
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "POST /requests/{id}/run-update (completed)",
        statements: 3,
        rows_read: 10,
        rows_written: 4,
        scan_allowlist: &[],
    },
    // Submit paths: a batch of three requests (one resync, one fresh,
    // one human). The untrusted route refuses on a pinned-zero pending
    // cap — that is the refusal path; the accept drive lifts the cap
    // and measures the insert; the trusted route runs the full write
    // path including edge resync.
    RouteBudget {
        name: "POST /enqueue (untrusted)",
        statements: 8,
        rows_read: 40,
        rows_written: 4,
        scan_allowlist: &[],
    },
    RouteBudget {
        // The same batch past the cap: pending-count read, the
        // human-lane budget charge and position walk, the insert.
        name: "POST /enqueue (untrusted accept)",
        statements: 20,
        rows_read: 300,
        rows_written: 100,
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "POST /admin/enqueue (trusted)",
        statements: 16,
        rows_read: 120,
        rows_written: 70,
        scan_allowlist: &[],
    },
    // The submit-by-id promote lane (stow#588): the trusted enqueue's
    // resync path plus the node-store walk — one root lookup per id and
    // one bounded query per BFS level (the drive's test subgraphs are
    // one level deep).
    RouteBudget {
        name: "POST /admin/enqueue (submit-ids)",
        statements: 24,
        rows_read: 200,
        rows_written: 20,
        scan_allowlist: &[],
    },
    // The same batch submitted again, fully deduplicated (stow#784):
    // `plan_enqueue` emits an update only when a request moves stored
    // state, so the whole resubmit is the status probe plus the
    // task_nodes upsert conflicts — two statements, zero rows written.
    // The human-lane request in the batch charges nothing either
    // (stow#796): `rows_written` would catch the spend now that the
    // host backend counts `RETURNING` writes.
    RouteBudget {
        name: "POST /admin/enqueue (resubmit)",
        statements: 3,
        rows_read: 20,
        rows_written: 0,
        scan_allowlist: &[],
    },
    RouteBudget {
        name: "POST /demand",
        statements: 14,
        rows_read: 200,
        rows_written: 60,
        // The recursive walk's working table and the json_each payload
        // scan are keyed-by-construction, not table scans.
        scan_allowlist: &["SCAN walk", "SCAN json_each"],
    },
    // The explicit full report — first publish and `index report --full`
    // resyncs — whose server-side diff reads the live slice (a
    // legitimate bound: the report body names every row).
    // The whole route (stow#785): the report — with its commit-time
    // shape repair — plus the `dispatch_pending` claiming tail and
    // wake re-plan. The 10k host gate measured 22 statements, 612
    // reads, 464 writes. The tail's pass claims at most free slots /
    // `STOW_BATCH_PARALLELISM` × `STOW_BATCH_MAX_TASKS` legs — the
    // dispatch cap bounds it, not the event: the thirty one-slot
    // in-flight tasks hold 30 of the 45 slots; the tail claims up to
    // 15 free-slot tasks, one keyed `UPDATE queue` each, plus the
    // 100 slice rows the report names. Reads and writes budgeted at the measurement
    // plus 20%.
    RouteBudget {
        name: "POST /index/published (full)",
        statements: 90,
        rows_read: 735,
        rows_written: 560,
        scan_allowlist: &[],
    },
    // A report whose membership moved by DELTA_ROWS: the gate writes
    // touch only the changed rows' matched edges and their owners'
    // counters, so its cost is proportional to the delta, never to the
    // slice or the graph (stow#521) — plus the same dispatch tail as
    // the full drive and the report-time shape repair, which can
    // requeue the deps the retire just uncovered. The 10k host gate
    // measured 25 statements, 697 reads, 530 writes, the tail's claim
    // bounded by the dispatch cap as the full drive's is: 120 claimed
    // legs, 3 writes each. Reads and writes budgeted at the
    // measurement plus 20%.
    RouteBudget {
        name: "POST /index/published (delta)",
        statements: 110,
        rows_read: 840,
        rows_written: 640,
        scan_allowlist: &[],
    },
    // The alarm's dispatch pass on a warm queue: the claim pages at
    // `2 × open slots` candidate rows and claims them, so the pass's
    // read is bounded by the dispatch cap plus the fixed probes,
    // never by the frontier or the queue. The pass fills the 15 free
    // slots with one claimed task each — the pass's claim writes are
    // bounded by the dispatch cap. Reads and writes budgeted at the
    // measurement plus 20%.
    RouteBudget {
        name: "alarm pass",
        statements: 90,
        rows_read: 930,
        rows_written: 440,
        scan_allowlist: &[],
    },
    RouteBudget {
        // The pass's fixed floor under paused dispatch: recovery probes
        // and the re-arm only — no claim work.
        name: "alarm pass (idle)",
        statements: 12,
        rows_read: 80,
        rows_written: 4,
        scan_allowlist: &[],
    },
    // The per-task run drives (stow#876). Each setup claims one task
    // from the planted window and binds it to a run; every row below
    // is event-sized, and none reads or writes in proportion to the
    // queue.
    RouteBudget {
        // `complete_run`: the binding read, the fenced settle `UPDATE`,
        // its outcome counter and window expiry, the build sample's
        // insert, cap delete, stats read and write, the keyed
        // dispatch-key refresh over the task's own `(crate, target)`
        // pending rows — the seeded `BUILD_SAMPLE_WINDOW` rings price
        // the cap delete and median recompute at production's steady
        // state (stow#833) — plus the `schedule_alarm` re-plan.
        name: "POST /tasks/complete-run (success)",
        statements: 25,
        rows_read: 60,
        rows_written: 20,
        scan_allowlist: &[],
    },
    RouteBudget {
        // The conclusion is carried verbatim: the success delivery's
        // bound, plus the failure arm's retry `UPDATE`, follow-up
        // refreshes and evidence row.
        name: "POST /tasks/complete-run (failure)",
        statements: 30,
        rows_read: 60,
        rows_written: 25,
        scan_allowlist: &[],
    },
    RouteBudget {
        // The `in_progress` delivery: one fenced `UPDATE queue`, with
        // the binding read only on a miss (stow#876).
        name: "POST /tasks/run-update (in_progress)",
        statements: 4,
        rows_read: 4,
        rows_written: 2,
        scan_allowlist: &[],
    },
    RouteBudget {
        // One stale bound row recovered by clock inside the claim
        // pass: the pending-completion discard, the keyed requeue
        // `UPDATE`, and the dispatch-key refresh on the transitioned
        // id, under the pass's fixed probes — no run-status read
        // (stow#876).
        name: "alarm pass (stale recovery)",
        statements: 40,
        rows_read: 300,
        rows_written: 40,
        scan_allowlist: &[],
    },
    RouteBudget {
        // One real dispatch pass over the floored queue — the same
        // claim/plan surface as the hot pass, priced separately so
        // the gate sees planner and claim cost under a positive
        // persisted floor (stow#525). It claims the same 120 legs in 3
        // tasks as the hot pass and is budgeted at the measurement
        // plus 20%.
        name: "alarm pass (floor claim)",
        statements: 90,
        rows_read: 930,
        rows_written: 440,
        scan_allowlist: &[],
    },
    // Every demand-feed cap below is PROVISIONAL: host-measured on the
    // 10k gate, pending actual workerd billed measurements — host
    // result cardinality is not billed rows, so only these
    // event-specific caps may move when the native pair reports, from
    // measured costs plus stated headroom. The 31 existing budgets
    // above stay unchanged (stow#523).
    RouteBudget {
        // The resume-cursor read (stow#523): one watermark probe
        // plus one unfinished-index probe — two point reads, flat in
        // retained depth.
        name: "GET /scheduler/demand-feed/status",
        statements: 4,
        rows_read: 8,
        rows_written: 0,
        scan_allowlist: &[],
    },
    RouteBudget {
        // Fresh open: closed-hour check, watermark guard, header
        // insert, generation read-back.
        name: "POST /scheduler/demand-feed/begin (fresh)",
        statements: 8,
        rows_read: 8,
        rows_written: 3,
        scan_allowlist: &[],
    },
    RouteBudget {
        // Restart with real debris: the same guarded path plus the
        // generation bump, one full 256-row obsolete retire chunk
        // and the pending probe — measured 7/4/257 on the 10k gate.
        name: "POST /scheduler/demand-feed/begin (rotation)",
        statements: 14,
        rows_read: 8,
        rows_written: 520,
        scan_allowlist: &[],
    },
    RouteBudget {
        // One staged page: header probe, ordering/generation guard,
        // payload insert whose trigger bumps counters.
        name: "POST /scheduler/demand-feed/page (append)",
        statements: 6,
        rows_read: 8,
        rows_written: 3,
        scan_allowlist: &[],
    },
    RouteBudget {
        // Same-bytes replay: the guards plus the stored-hash
        // compare — bounded reads, zero writes.
        name: "POST /scheduler/demand-feed/page (replay)",
        statements: 6,
        rows_read: 8,
        rows_written: 0,
        scan_allowlist: &[],
    },
    RouteBudget {
        // Completion barrier, populated hour: manifest verification
        // over the generation's staged hashes plus the guarded freeze.
        name: "POST /scheduler/demand-feed/complete (nonempty)",
        statements: 8,
        rows_read: 8,
        rows_written: 3,
        scan_allowlist: &[],
    },
    RouteBudget {
        // The same barrier with an empty generation — verification
        // against zero pages, still a guarded transition.
        name: "POST /scheduler/demand-feed/complete (empty)",
        statements: 8,
        rows_read: 8,
        rows_written: 3,
        scan_allowlist: &[],
    },
    RouteBudget {
        // One page-apply delivery at the protocol's maximum
        // 256-entry page: header read, bounded next-unapplied-page
        // SELECT, the `demand_pass` closure for 256 real fixture
        // identities, the acknowledged flip and the wake re-plan —
        // measured 273/640/310 on the 10k gate.
        name: "POST /scheduler/demand-feed/deliver (page apply)",
        statements: 550,
        rows_read: 1300,
        rows_written: 650,
        scan_allowlist: &[],
    },
    RouteBudget {
        // The terminal call — transition-only: every page already
        // applied, so just the probes plus the contiguous-watermark
        // guarded `delivered` transition.
        name: "POST /scheduler/demand-feed/deliver (terminal)",
        statements: 18,
        rows_read: 40,
        rows_written: 4,
        scan_allowlist: &[],
    },
    RouteBudget {
        // Delivered-hour replay: the header `delivered` early-out
        // plus the wake re-plan — two reads, no ledger writes.
        name: "POST /scheduler/demand-feed/deliver (replay)",
        statements: 12,
        rows_read: 30,
        rows_written: 0,
        scan_allowlist: &[],
    },
    RouteBudget {
        // One full retirable chunk: header read, `DELETE … LIMIT
        // 256`, pending probe — flat in archive depth.
        name: "POST /scheduler/demand-feed/cleanup (full chunk)",
        statements: 8,
        rows_read: 8,
        rows_written: 260,
        scan_allowlist: &[],
    },
    RouteBudget {
        // The retire probe on an all-live generation: header read,
        // a zero-match DELETE, pending probe.
        name: "POST /scheduler/demand-feed/cleanup (none obsolete)",
        statements: 8,
        rows_read: 8,
        rows_written: 2,
        scan_allowlist: &[],
    },
];

/// One measured route run.
struct Measurement {
    statements: Vec<LoggedStatement>,
    statement_count: usize,
    rows_read: u64,
    rows_written: u64,
}

impl Measurement {
    /// Sum a statement-log slice into its counts.
    fn of(statements: Vec<LoggedStatement>) -> Self {
        let rows_read = statements.iter().map(|s| s.rows_read).sum();
        let rows_written = statements.iter().map(|s| s.rows_written).sum();
        Self {
            statement_count: statements.len(),
            statements,
            rows_read,
            rows_written,
        }
    }
}

/// `EXPLAIN QUERY PLAN` detail rows — only the plan text matters.
#[derive(FromRow)]
struct PlanRow {
    detail: String,
}

/// The tables whose scans the gate watches — the large ones.
const GATED_TABLES: &[&str] = &[
    "queue",
    "queue_dependencies",
    "published_slices",
    "published_slice_rows",
    "attempt_outcome_buckets",
];

/// SQL keywords that may legitimately follow a table reference — a
/// gated name whose next token is one of these carries no alias.
fn is_keyword(token: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "where",
        "on",
        "set",
        "values",
        "group",
        "order",
        "limit",
        "offset",
        "join",
        "left",
        "right",
        "inner",
        "outer",
        "cross",
        "natural",
        "using",
        "indexed",
        "by",
        "returning",
        "as",
        "select",
        "union",
        "intersect",
        "except",
        "having",
        "window",
        "conflict",
        "do",
        "not",
        "and",
        "or",
        "case",
        "when",
        "then",
        "else",
        "end",
        "from",
    ];
    KEYWORDS.iter().any(|k| token.eq_ignore_ascii_case(k))
}

/// The names a statement gives the gated tables: the table itself plus
/// every alias it binds — `FROM queue_dependencies bd` plans as
/// `SCAN bd`, so the alias is what must be watched.
fn gated_names(sql: &str) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = GATED_TABLES.iter().map(|t| (*t).to_owned()).collect();
    let tokens: Vec<&str> = sql
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
        .collect();
    for index in 0..tokens.len() {
        let head = tokens[index];
        if !matches!(
            head.to_ascii_lowercase().as_str(),
            "from" | "join" | "update" | "into" | "table"
        ) {
            continue;
        }
        let Some(&table) = tokens.get(index + 1) else {
            continue;
        };
        if !GATED_TABLES.iter().any(|t| table.eq_ignore_ascii_case(t)) {
            continue;
        }
        let mut next = index + 2;
        if tokens
            .get(next)
            .is_some_and(|t| t.eq_ignore_ascii_case("as"))
        {
            next += 1;
        }
        if let Some(&alias) = tokens.get(next)
            && !is_keyword(alias)
        {
            names.insert(alias.to_owned());
        }
    }
    names
}

/// Replay one logged statement under `EXPLAIN QUERY PLAN` and return the
/// `detail` lines that scan a gated table — under its own name or an
/// alias the statement bound it to.
async fn scan_details(db: &DurableDb, statement: &LoggedStatement) -> Vec<String> {
    let gated = gated_names(&statement.sql);
    let explain_sql = format!("EXPLAIN QUERY PLAN {}", statement.sql);
    let mut explain = db.query(&explain_sql);
    for param in &statement.params {
        explain = explain.bind(param.clone());
    }
    let plan = explain
        .fetch_all::<PlanRow>()
        .await
        .expect("EXPLAIN QUERY PLAN replay of a logged statement");
    plan.iter()
        .map(|row| row.detail.as_str())
        .filter(|detail| {
            // `SCAN <name>` — word-boundary match: `SCAN queue` must not
            // swallow `SCAN queue_status_counts` (a six-row table).
            detail.starts_with("SCAN")
                && detail
                    .split_whitespace()
                    .nth(1)
                    .is_some_and(|name| gated.contains(name))
        })
        .map(str::to_owned)
        .collect()
}

/// The stow#432 mechanical rule: `true` when the statement's heads
/// contain a `CREATE`/`ALTER`/`DROP`/`PRAGMA`. Mirrors the backend's own
/// tokenizer — a statement head is the first identifier after `;`,
/// skipping literals and comments.
fn has_schema_head(sql: &str) -> bool {
    const HEADS: &[&str] = &[
        "alter", "analyze", "attach", "create", "detach", "drop", "pragma", "reindex", "vacuum",
    ];
    let bytes = sql.as_bytes();
    let mut index = 0;
    let mut statement_start = true;
    while index < bytes.len() {
        match bytes[index] {
            quote @ (b'\'' | b'"' | b'`') => {
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == quote {
                        if bytes.get(index + 1) == Some(&quote) {
                            index += 2;
                            continue;
                        }
                        index += 1;
                        break;
                    }
                    index += 1;
                }
            }
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
            }
            b';' => {
                statement_start = true;
                index += 1;
            }
            byte if byte.is_ascii_whitespace() => index += 1,
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                if statement_start
                    && HEADS.contains(&sql[start..index].to_ascii_lowercase().as_str())
                {
                    return true;
                }
                statement_start = false;
            }
            _ => {
                statement_start = false;
                index += 1;
            }
        }
    }
    false
}

/// Check one measurement against its budget entry: print the measured
/// line so a tuning run still reports every route, then assert
/// statements, rows read and written, the no-DDL-on-request-paths rule,
/// and the scan allowlist.
async fn check(db: &DurableDb, budget: &RouteBudget, measurement: &Measurement) {
    eprintln!(
        "BUDGET {:<34} statements={:<4} rows_read={:<7} rows_written={:<7}",
        budget.name, measurement.statement_count, measurement.rows_read, measurement.rows_written,
    );
    assert!(
        measurement.statement_count <= budget.statements,
        "{} issued {} statements (budget {}):\n{}",
        budget.name,
        measurement.statement_count,
        budget.statements,
        measurement
            .statements
            .iter()
            .map(|statement| statement.sql.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
    );
    assert!(
        measurement.rows_read <= budget.rows_read,
        "{} read {} rows (budget {})",
        budget.name,
        measurement.rows_read,
        budget.rows_read,
    );
    assert!(
        measurement.rows_written <= budget.rows_written,
        "{} wrote {} rows (budget {})",
        budget.name,
        measurement.rows_written,
        budget.rows_written,
    );
    for statement in &measurement.statements {
        assert!(
            !has_schema_head(&statement.sql),
            "{} issued DDL/PRAGMA on a request path: {}",
            budget.name,
            statement.sql,
        );
    }
    let mut scans = Vec::new();
    for statement in &measurement.statements {
        for detail in scan_details(db, statement).await {
            if !budget.scan_allowlist.iter().any(|a| detail.contains(a)) {
                scans.push(format!("{detail} — in {}", statement.sql));
            }
        }
    }
    assert!(
        scans.is_empty(),
        "{} scanned a gated table outside the allowlist:\n{}",
        budget.name,
        scans.join("\n"),
    );
}

fn budget_of(name: &str) -> &'static RouteBudget {
    BUDGETS
        .iter()
        .find(|budget| budget.name == name)
        .unwrap_or_else(|| panic!("{name} has no entry in the scheduler cost-budget table"))
}

/// The drive list and both budget tables (the host gate's `BUDGETS` and
/// workerd's `DO_BUDGETS`) must cover each other exactly: every drive has
/// exactly one row in each table, and no table has a row no drive
/// produces. A drifted row is the defect the workerd probe would
/// otherwise turn into a panic inside the Durable Object.
#[test]
fn every_drive_has_exactly_one_row_in_each_budget_table() {
    let drives = drives::DRIVES
        .iter()
        .map(|drive| drive.name)
        .collect::<BTreeSet<_>>();
    for name in &drives {
        assert_eq!(
            1,
            drives::DRIVES
                .iter()
                .filter(|drive| drive.name == *name)
                .count(),
            "duplicate drive {name}",
        );
    }
    let host_names = BUDGETS.iter().map(|budget| budget.name).collect::<Vec<_>>();
    let workerd_names = crate::scheduler::do_budgets::DO_BUDGETS
        .iter()
        .map(|budget| budget.name)
        .collect::<Vec<_>>();
    for (table, names) in [
        ("host BUDGETS", &host_names),
        ("workerd DO_BUDGETS", &workerd_names),
    ] {
        assert_eq!(
            drives,
            names.iter().copied().collect::<BTreeSet<_>>(),
            "{table} and the drive list drifted apart",
        );
        assert_eq!(
            names.len(),
            names.iter().copied().collect::<BTreeSet<_>>().len(),
            "{table} has a duplicate row",
        );
    }
    // Route-level coverage, not just table parity: every demand-feed
    // route the DO registers must have at least one priced drive — a
    // set-parity check alone would let a whole request path go
    // unmeasured (stow#523). Drive names carry ` (variant)` suffixes
    // for the same route's distinct event shapes.
    for route in ["begin", "page", "complete", "cleanup", "deliver", "status"] {
        assert!(
            drives.iter().any(|name| {
                name.ends_with(&format!("/demand-feed/{route}"))
                    || name.contains(&format!("/demand-feed/{route} ("))
            }),
            "no drive prices /demand-feed/{route}",
        );
    }
}

/// stow#567: a wall breach is reported, never gated — the local
/// workerd lane's `wall_ms` is mostly the in-window `db.sync()`
/// durability barrier on the runner's SQLite, so the report row's
/// `over_wall` marks it while `over_budget` stays clear. A
/// statements/rows breach still gates. (`budget_row` is wasm-only;
/// these are the predicates it delegates to.)
#[test]
fn a_wall_breach_is_reported_not_gated() {
    let budget = crate::scheduler::do_budgets::DO_BUDGETS
        .first()
        .expect("a drive budget");
    // Wall over, counts at budget: reported, not gated.
    assert!(budget.over_wall(budget.wall_ms + 1));
    assert!(
        !budget.over_budget(budget.statements, budget.rows_read, budget.rows_written),
        "the wall is reported, not gated"
    );
    // A rows_read breach still gates even with the wall inside budget.
    assert!(budget.over_budget(budget.statements, budget.rows_read + 1, budget.rows_written));
    assert!(!budget.over_wall(budget.wall_ms));
}

/// Every drive once under the gate, logging per-statement counters —
/// the loop `per_request_cost_gate` and the persisted-fixture repeat
/// share.
async fn run_drives(
    db: &DurableDb,
    shape: fixture::FixtureShape,
    settings: &SchedulerSettings,
    ctx: &drives::DriveContext,
    log: &Arc<Mutex<Vec<LoggedStatement>>>,
) {
    for drive in drives::DRIVES {
        run_one_drive(db, shape, settings, ctx, log, drive)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }
}

/// One drive's unmetered hooks plus its metered pass and budget check.
/// The phase ordering and error retention live in
/// [`drives::drive_lifecycle`] — shared with the workerd probe — while
/// this observer owns the gate's bookkeeping: setup/cleanup statements
/// are fixture work, not the priced event, so the log truncates back
/// to the mark each phase opened at (stow#525).
async fn run_one_drive(
    db: &DurableDb,
    shape: fixture::FixtureShape,
    settings: &SchedulerSettings,
    ctx: &drives::DriveContext,
    log: &Arc<Mutex<Vec<LoggedStatement>>>,
    drive: &drives::Drive,
) -> Result<(), String> {
    let mut keep = 0;
    let mut base = 0;
    let runs_before = run_surface(db).await;
    let queue_before = queue_surface(db).await;
    let outcome =
        drives::drive_lifecycle(
            drive,
            db,
            db,
            shape,
            settings,
            ctx,
            &mut |mark| match mark {
                drives::PhaseMark::Starting(
                    drives::LifecyclePhase::Setup | drives::LifecyclePhase::Cleanup,
                ) => keep = log.lock().expect("statement log").len(),
                drives::PhaseMark::Finished(
                    drives::LifecyclePhase::Setup | drives::LifecyclePhase::Cleanup,
                ) => log.lock().expect("statement log").truncate(keep),
                drives::PhaseMark::Finished(drives::LifecyclePhase::PreSync) => {
                    base = log.lock().expect("statement log").len();
                }
                _ => {}
            },
        )
        .await;
    if let Err(error) = outcome.setup {
        return Err(format!("{} setup failed: {error}", drive.name));
    }
    let failures: Vec<String> = [&outcome.pre_sync, &outcome.run, &outcome.post_sync]
        .into_iter()
        .filter_map(|phase| {
            phase
                .as_ref()
                .and_then(|result| result.as_ref().err().cloned())
        })
        .collect();
    let run_result = if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    };
    let cleanup_result = match &outcome.cleanup {
        Some(Err(error)) => Err(format!("{} cleanup failed: {error}", drive.name)),
        _ => Ok(()),
    };
    // A drive that claims leaves the in-flight set as it found it:
    // the slots its claim took must not reach the next drive's
    // capacity read.
    let end = log.lock().expect("statement log").len();
    let runs_after = run_surface(db).await;
    let queue_after = queue_surface(db).await;
    log.lock().expect("statement log").truncate(end);
    if runs_before != runs_after {
        return Err(format!(
            "{} left the in-flight set changed: before {runs_before:?}, after {runs_after:?}",
            drive.name
        ));
    }
    // A drive leaves the queue as it found it: a pending row it added
    // is claimable by the next pass drive, its edges and nodes widen
    // every later walk, and a flag it flipped changes what the claim
    // walk can open. No exemptions — a drive that moves pending rows
    // restores them in its own cleanup, so a changed count is a leak.
    if let Some(left) = queue_before.left_behind(&queue_after) {
        return Err(format!("{} left the queue changed: {left}", drive.name));
    }
    match (run_result, cleanup_result) {
        (Ok(()), Ok(())) => {
            let statements = log.lock().expect("statement log")[base..].to_vec();
            let measurement = Measurement::of(statements);
            check(db, budget_of(drive.name), &measurement).await;
            Ok(())
        }
        (Err(run_error), Ok(())) => Err(format!("{} failed: {run_error}", drive.name)),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(run_error), Err(cleanup_error)) => Err(format!(
            "{} failed: {run_error}; cleanup also failed: {cleanup_error}",
            drive.name
        )),
    }
}

/// What a drive can leave in the queue: the task ids, plus the
/// derived-id (`-`-bearing, never a fixture hex id) edge and node rows
/// its enqueue writes, and how many pending rows are unparked
/// (`dispatch_eligible = 1`) — a drive that moves the floor and does
/// not put the flags back changes every later pass's claim walk.
struct QueueSurface {
    task_ids: std::collections::BTreeSet<String>,
    eligible_pending: i64,
    derived_edges: i64,
    derived_nodes: i64,
}

impl QueueSurface {
    /// A description of how `after` differs from `self`, `None` when
    /// the drive left the surface as it found it — every drive is held
    /// to it. A route that moves pending rows restores them in its own
    /// cleanup, so a changed eligible-pending count is always a leak.
    fn left_behind(&self, after: &Self) -> Option<String> {
        let added: Vec<&String> = after.task_ids.difference(&self.task_ids).collect();
        (!added.is_empty()
            || after.eligible_pending != self.eligible_pending
            || after.derived_edges != self.derived_edges
            || after.derived_nodes != self.derived_nodes)
            .then(|| {
                format!(
                    "task ids added {added:?}, eligible pending rows {} -> {}, \
                     derived edges {} -> {}, derived nodes {} -> {}",
                    self.eligible_pending,
                    after.eligible_pending,
                    self.derived_edges,
                    after.derived_edges,
                    self.derived_nodes,
                    after.derived_nodes
                )
            })
    }
}

/// The queue's [`QueueSurface`], read unmetered.
async fn queue_surface(db: &DurableDb) -> QueueSurface {
    QueueSurface {
        task_ids: db
            .query("SELECT task_id FROM queue")
            .fetch_scalars::<String>()
            .await
            .expect("read queue ids")
            .into_iter()
            .collect(),
        eligible_pending: db
            .query("SELECT COUNT(*) FROM queue WHERE status = 'pending' AND dispatch_eligible = 1")
            .fetch_scalar()
            .await
            .expect("count eligible pending rows"),
        derived_edges: db
            .query("SELECT COUNT(*) FROM queue_dependencies WHERE task_id LIKE '%-%'")
            .fetch_scalar()
            .await
            .expect("count derived edges"),
        derived_nodes: db
            .query("SELECT COUNT(*) FROM task_nodes WHERE task_id LIKE '%-%'")
            .fetch_scalar()
            .await
            .expect("count derived nodes"),
    }
}

/// Every in-flight queue row's binding, sorted — a drive that claims
/// leaves the in-flight set as it found it: the slots its claim took
/// must not reach the next drive's capacity read.
async fn run_surface(db: &DurableDb) -> Vec<String> {
    db.query(
        "SELECT task_id || '|' || status || '|' || COALESCE(github_run_id, '') \
         FROM queue WHERE status IN ('dispatched', 'running') ORDER BY task_id",
    )
    .fetch_scalars::<String>()
    .await
    .expect("read in-flight rows")
}

/// Every entry of [`drives::DRIVES`] holds its budget on the 10k gate
/// fixture. The two tables must cover each other exactly — a drive with
/// no budget row, or a row no drive produces, is a gate bug and fails
/// either way.
#[tokio::test]
async fn per_request_cost_gate() {
    every_drive_has_exactly_one_row_in_each_budget_table();
    let settings = SchedulerSettings::default();
    let (db, log) = counting_memory_db().await.expect("counting db");
    let seed_base = log.lock().expect("log").len();
    fixture::seed_production_shape(&db, &fixture::GATE, settings.dispatch_min_age_minutes)
        .await
        .expect("seed fixture");
    // The fixture itself must obey the gate — it is seeded with DML only,
    // and this slice proves no seed statement is a schema statement.
    for statement in &log.lock().expect("log")[seed_base..] {
        assert!(
            !has_schema_head(&statement.sql),
            "fixture seeding issued schema work: {}",
            statement.sql
        );
    }
    let shape = fixture::GATE;
    let ctx = drives::DriveContext::host();
    run_drives(&db, shape, &settings, &ctx, &log).await;

    // The reset route is the only DDL path — it runs on the same seeded
    // fixture under the raw (permit-open) counting backend.
    let (raw_db, raw_log) = counting_memory_db_raw().await.expect("raw counting db");
    fixture::seed_production_shape(&raw_db, &fixture::GATE, settings.dispatch_min_age_minutes)
        .await
        .expect("seed fixture");
    let base = raw_log.lock().expect("statement log").len();
    queue::reset(&raw_db).await.expect("reset");
    let measurement = Measurement::of(raw_log.lock().expect("statement log")[base..].to_vec());
    eprintln!(
        "BUDGET {:<34} statements={:<4} rows_read={:<7} rows_written={:<7}",
        "POST /reset", measurement.statement_count, measurement.rows_read, measurement.rows_written,
    );
}

/// Σ `outcomes` and Σ `failures` over every attempt-outcome bucket.
async fn outcome_totals(db: &DurableDb) -> (i64, i64) {
    let outcomes = db
        .query("SELECT COALESCE(SUM(outcomes), 0) FROM attempt_outcome_buckets")
        .fetch_scalar::<i64>()
        .await
        .expect("outcome total");
    let failures = db
        .query("SELECT COALESCE(SUM(failures), 0) FROM attempt_outcome_buckets")
        .fetch_scalar::<i64>()
        .await
        .expect("failure total");
    (outcomes, failures)
}

async fn status_of(db: &DurableDb, task_id: &str) -> String {
    db.query("SELECT status FROM queue WHERE task_id = ?")
        .bind(task_id.to_owned())
        .fetch_scalar::<String>()
        .await
        .expect("status")
}

/// The failure evidence the completion drives leave: one row for each
/// pass's failed task, on a generation of its own.
async fn assert_failure_evidence(db: &DurableDb, expected: usize) {
    let generations = db
        .query("SELECT generation_id FROM attempt_outcomes_v2 WHERE github_run_id = ?")
        .bind(drives::RUN_DRIVE_RUN_ID.to_string())
        .fetch_scalars::<String>()
        .await
        .expect("failure generations");
    assert_eq!(
        generations.len(),
        expected,
        "each pass records its failures"
    );
    assert_eq!(
        generations
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        expected,
        "each failure belongs to a distinct generation"
    );
    assert!(generations.iter().all(|generation| generation.len() == 32
        && generation.bytes().all(|byte| byte.is_ascii_hexdigit())));
}

/// What a pass's run drives must leave behind besides their recorded
/// evidence: no build sample or stat the settled tasks filed, and no
/// row still in flight on the drive's run id: every claiming drive
/// restores its task, so a leftover binding is a failed restore.
async fn assert_run_drives_cleaned_up(db: &DurableDb) {
    // The fixture's seeded rings stay — the drives' cleanups remove
    // only their own generations — so a leftover drive sample is any
    // row outside the ring ids; the stats table still starts empty.
    for (table, predicate) in [
        (
            "crate_build_samples",
            "WHERE generation_id NOT LIKE 'seed-ring-%'",
        ),
        ("crate_build_stats", ""),
    ] {
        let rows = db
            .query(&format!("SELECT COUNT(*) FROM {table} {predicate}"))
            .fetch_scalar::<i64>()
            .await
            .expect("sample rows");
        assert_eq!(rows, 0, "{table} outlived the run drives");
    }
    let orphaned = db
        .query(
            "SELECT COUNT(*) FROM queue WHERE status IN ('dispatched', 'running') \
             AND github_run_id = ?",
        )
        .bind(drives::RUN_DRIVE_RUN_ID.to_string())
        .fetch_scalar::<i64>()
        .await
        .expect("orphaned bindings");
    assert_eq!(orphaned, 0, "a task is still bound to a drive's run");
}

/// The gate truth a re-arm must leave behind. Every stored edge flag
/// answers the strict slice predicate — the re-arm reverts the probe's
/// membership moves, so no `dep_met` may stay flipped — and on the
/// rows the refresh scopes (the restored and claimed rows plus the
/// dependents of every dep they name, pending or not) the persisted
/// `unpublished_deps` counter counts the unmet edges, `deps_met` is
/// its `= 0` derivation, and `blocked` holds while the row is pending.
async fn assert_rearm_gate_truth(db: &DurableDb, shape: fixture::FixtureShape, claimed: &[String]) {
    // The touched set `rearm` derives: its fixed restore list, the
    // pass's recorded claim set and the delta's retire-band members.
    let mut touched = vec![
        101,
        fixture::FixtureShape::pending_row(701),
        fixture::FixtureShape::pending_row(702),
        fixture::FixtureShape::pending_row(4703),
        shape.failed_row(0),
        shape.failed_row(1),
        shape.completed_row(0),
        shape.completed_row(1),
    ];
    touched.extend((0..fixture::FixtureShape::IN_FLIGHT_ROWS).map(|k| shape.in_flight_row(k)));
    touched.extend(claimed.iter().filter_map(|id| {
        u64::from_str_radix(id, 16)
            .ok()
            .and_then(|n| u32::try_from(n).ok())
    }));
    let live = shape.slice_live_rows(0);
    let first = shape.slice_first_row(0);
    for i in 0..drives::DELTA_ROWS {
        touched.push(first + (live - 1 - i) * 9);
    }
    let stale_edges: i64 = db
        .query(&format!(
            "SELECT count(*) FROM queue_dependencies d \
             WHERE d.dep_met != (CASE WHEN {unpublished} THEN 0 ELSE 1 END)",
            unpublished = queue::dep_edge_unpublished_sql("d"),
        ))
        .fetch_scalar()
        .await
        .expect("edge dep_met sweep");
    assert_eq!(
        stale_edges, 0,
        "re-arm left edges stale against the live slice"
    );
    let drifted_owners: i64 = db
        .query(&format!(
            "WITH touched(task_id) AS ( \
                 SELECT printf('%064x', value) FROM json_each(?) \
             ), owners(task_id) AS ( \
                 SELECT task_id FROM touched UNION \
                 SELECT d.task_id FROM queue_dependencies d \
                 JOIN touched t ON t.task_id = d.depends_on_task_id \
             ) \
             SELECT count(*) FROM queue \
             WHERE task_id IN (SELECT task_id FROM owners) \
               AND (unpublished_deps != {unpublished} \
                    OR deps_met != {deps_met} \
                    OR (status = 'pending' AND blocked != {blocked}))",
            unpublished = queue::unpublished_deps_sql("queue.task_id"),
            deps_met = queue::deps_met_sql("queue.task_id"),
            blocked = queue::blocked_sql("queue.task_id"),
        ))
        .bind(serde_json::to_string(&touched).expect("encode touched"))
        .fetch_scalar()
        .await
        .expect("owner counter sweep");
    assert_eq!(
        drifted_owners, 0,
        "re-arm left touched owners' counters off the production expressions"
    );
}

/// The workerd probe runs `POST /budget` repeatedly against the same
/// persisted fixture — the launch gate measures once before and once
/// after the load lane. `fixture::rearm` must return every row and
/// membership the first pass moved to the seeded truth, or the second
/// pass fails its logical assertions (the retry drive's two `failed`
/// rows) or drifts off the calibrated costs. Two full passes on one
/// fixture prove the restore covers the whole mutation class — and the
/// probe's own control state carries it: claimed rows restore from the
/// pass's recorded claim set (a non-pending row the pass never touched
/// survives), and each pass's run drives claim fresh generations, so
/// their failure evidence accumulates rather than colliding.
#[tokio::test]
async fn budget_probe_repeats_on_a_persisted_fixture() {
    every_drive_has_exactly_one_row_in_each_budget_table();
    let settings = SchedulerSettings::default();
    let (db, log) = counting_memory_db().await.expect("counting db");
    fixture::seed_production_shape(&db, &fixture::GATE, settings.dispatch_min_age_minutes)
        .await
        .expect("seed fixture");
    let shape = fixture::GATE;

    // Two non-pending rows inside the pending band that no drive names
    // and no claim can reach — the re-arm's claimed-row restore is the
    // pass's recorded set, so these must survive it untouched. The
    // `completed` marker carries the repair latch so the pass's own
    // shape-requeue sweep cannot move it either.
    let untouched = [
        (shape.pending_end() / 3, "completed", "shape_requeue = 1"),
        (
            shape.pending_end() / 3 + 1,
            "failed",
            "shape_requeue = shape_requeue",
        ),
    ];
    for (n, status, extra) in untouched {
        db.query(&format!(
            "UPDATE queue SET status = ?, {extra} \
             WHERE task_id = printf('%064x', ?)"
        ))
        .bind(status)
        .bind(i64::from(n))
        .execute()
        .await
        .expect("stage untouched marker");
    }

    // The probe's own order: `budget::run` re-arms before every metered
    // pass and records the pass's claim set after it.
    let ctx = drives::DriveContext::host();
    fixture::rearm(&db, shape, settings.dispatch_min_age_minutes)
        .await
        .expect("re-arm (baseline)");
    let seeded_runs = run_surface(&db).await;
    // The fixture seeds `attempt_outcome_buckets` to sized bulk, so the
    // totals are the seed's plus each pass's own transitions — the
    // delta is what counts once per task.
    let (seeded_outcomes, seeded_failures) = outcome_totals(&db).await;
    run_drives(&db, shape, &settings, &ctx, &log).await;

    // Each pass's two success completions count two outcomes; its
    // failure completion counts one failure and files its evidence row
    // — the retry re-enters pending rather than settling. A settled
    // task writes no raw `attempt_outcomes_v2` row on success — the
    // bucket count is its evidence — and one row on failure, on the
    // generation the claim minted. (Each drive's own cleanup already
    // proved its task reached its end state.)
    assert_eq!(
        outcome_totals(&db).await,
        (seeded_outcomes + 2, seeded_failures + 1),
        "the first pass's task transitions counted once"
    );
    assert_failure_evidence(&db, 1).await;
    let claimed = ctx.claimed_ids();
    assert!(!claimed.is_empty(), "the gate pass claims rows");
    assert_run_drives_cleaned_up(&db).await;
    fixture::record_probe_claimed(&db, &claimed)
        .await
        .expect("record claims");
    fixture::rearm(&db, shape, settings.dispatch_min_age_minutes)
        .await
        .expect("re-arm fixture");
    assert_rearm_gate_truth(&db, shape, &claimed).await;
    assert_eq!(
        run_surface(&db).await,
        seeded_runs,
        "re-arm returns the in-flight set to the fixture's bound runs"
    );

    for (n, status, _) in untouched {
        let id = format!("{n:064x}");
        assert_eq!(
            status_of(&db, &id).await,
            status,
            "unclaimed {status} row at n={n} survived the re-arm"
        );
    }
    for id in &claimed {
        if u64::from_str_radix(id, 16).is_ok() {
            assert_eq!(
                status_of(&db, id).await,
                "pending",
                "claimed row {id} returned to pending"
            );
        }
    }

    run_drives(&db, shape, &settings, &ctx, &log).await;
    // The second pass's own transitions — counted once more, on fresh
    // generations: the evidence of both passes is distinct throughout.
    assert_eq!(
        outcome_totals(&db).await,
        (seeded_outcomes + 2 * 2, seeded_failures + 2),
        "the second pass's task transitions counted once more"
    );
    assert_failure_evidence(&db, 2).await;
    assert_run_drives_cleaned_up(&db).await;
}

/// The `release-gate.yml` traffic-cost `timeout-minutes` the fixture's
/// park must outlive: the job reuses one seed for its post-peak-drive
/// budget pass ~35 minutes in, so a `not_before` park stamped shorter
/// than this bound frees every pin and `n % 20 = 1` row into the
/// claim the pass prices — the `deferred=0` failure the `+30 minutes`
/// park produced (stow#833).
const TRAFFIC_COST_JOB_MINUTES: i64 = 110;

/// stow#833: the drives must still hold on a fixture as old as the
/// traffic-cost job can run. Host SQLite's `now` cannot advance, so
/// the test moves every `now`-relative stamp the seed wrote back by
/// [`TRAFFIC_COST_JOB_MINUTES`] — the instant the job's bound lands —
/// then re-arms the way `budget::run` does (the restore set's stamps
/// return to fresh `now`-relative values, as on the persisted fixture)
/// and runs the full pass. The parked rows the restore does not name
/// keep the aged values, so a park shorter than the job reads as
/// claimable — and the human-lane pins are the witness, since a
/// claimable pin ranks ahead of every miss row the pass prices.
#[tokio::test]
async fn after_pass_drives_hold_on_a_fixture_aged_past_the_harness_run() {
    let settings = SchedulerSettings::default();
    let (db, log) = counting_memory_db().await.expect("counting db");
    fixture::seed_production_shape(&db, &fixture::GATE, settings.dispatch_min_age_minutes)
        .await
        .expect("seed fixture");
    let shape = fixture::GATE;

    let ago = format!("-{TRAFFIC_COST_JOB_MINUTES} minutes");
    // Every `now`-relative stamp `queue_seed_insert_sql` writes: the
    // `'1970-01-01 00:00:00'` `not_before` is a sentinel, not a stamp,
    // and `claimed_at` is the seed columns' only nullable stamp — the
    // in-flight rows' bound runs ride the same column. The
    // outcome buckets stay put: in the harness the peak drive's
    // completions expire them as they age, so no run ever holds an
    // aged-out backlog — shifting them past the trip window at once
    // would price a one-off expiry burst no drive event produces.
    for sql in [
        "UPDATE queue SET not_before = datetime(not_before, ?) \
         WHERE not_before != '1970-01-01 00:00:00'",
        "UPDATE queue SET wake_at = datetime(wake_at, ?)",
        "UPDATE queue SET first_requested_at = datetime(first_requested_at, ?)",
        "UPDATE queue SET created_at = datetime(created_at, ?)",
        "UPDATE queue SET updated_at = datetime(updated_at, ?)",
        "UPDATE queue SET claimed_at = datetime(claimed_at, ?) \
         WHERE claimed_at IS NOT NULL",
    ] {
        db.query(sql)
            .bind(ago.clone())
            .execute()
            .await
            .expect("age the fixture's queue stamps");
    }
    // `budget::run` re-arms before its metered pass.
    fixture::rearm(&db, shape, settings.dispatch_min_age_minutes)
        .await
        .expect("re-arm fixture");
    let ctx = drives::DriveContext::host();
    run_drives(&db, shape, &settings, &ctx, &log).await;

    // The pins the park exists for — `n` in
    // `(HUMAN_LANE_ROWS - HUMAN_PROBE_ROWS, HUMAN_LANE_ROWS]` — stay
    // parked: a lapsed `not_before` would read claimable here.
    let first_pin =
        fixture::FixtureShape::HUMAN_LANE_ROWS - fixture::FixtureShape::HUMAN_PROBE_ROWS + 1;
    let unparked: u64 = db
        .query(
            "SELECT COUNT(*) FROM queue \
             WHERE task_id >= printf('%064x', ?) AND task_id <= printf('%064x', ?) \
               AND not_before <= datetime('now')",
        )
        .bind(i64::from(first_pin))
        .bind(i64::from(fixture::FixtureShape::HUMAN_LANE_ROWS))
        .fetch_scalar()
        .await
        .expect("count unparked pins");
    assert_eq!(
        unparked, 0,
        "a human pin's `not_before` park lapsed inside the job bound"
    );
}

/// A drive that fails mid-pass must still see its cleanup run — the
/// isolation promise holds on the error path too — and when the
/// cleanup itself also fails, the error names both failures.
fn injected_run_failure<'a>(
    _db: &'a DurableDb,
    _shape: fixture::FixtureShape,
    _settings: &'a SchedulerSettings,
    _ctx: &'a drives::DriveContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async { Err("injected run failure".to_owned()) })
}

fn marking_cleanup<'a>(
    db: &'a DurableDb,
    _shape: fixture::FixtureShape,
    _settings: &'a SchedulerSettings,
    _ctx: &'a drives::DriveContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        db.query("INSERT INTO settings (key, value) VALUES ('cleanup-marker', '1')")
            .execute()
            .await
            .map_err(|error| error.to_string())
            .map(|_| ())
    })
}

fn injected_cleanup_failure<'a>(
    _db: &'a DurableDb,
    _shape: fixture::FixtureShape,
    _settings: &'a SchedulerSettings,
    _ctx: &'a drives::DriveContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async { Err("injected cleanup failure".to_owned()) })
}

#[tokio::test]
async fn cleanup_still_runs_after_a_failing_drive() {
    let (db, log) = counting_memory_db().await.expect("counting db");
    let ctx = drives::DriveContext::host();
    let settings = SchedulerSettings::default();
    let drive = drives::Drive {
        name: "probe-isolation",
        setup: None,
        run: injected_run_failure,
        cleanup: Some(marking_cleanup),
    };
    let error = run_one_drive(&db, fixture::GATE, &settings, &ctx, &log, &drive)
        .await
        .expect_err("the failing drive must propagate its error");
    assert_eq!(error, "probe-isolation failed: injected run failure");
    let marked = db
        .query("SELECT COUNT(*) FROM settings WHERE key = 'cleanup-marker'")
        .fetch_scalar::<u64>()
        .await
        .expect("marker read");
    assert_eq!(marked, 1, "cleanup ran after the failed run");

    let drive = drives::Drive {
        name: "probe-double-failure",
        setup: None,
        run: injected_run_failure,
        cleanup: Some(injected_cleanup_failure),
    };
    let error = run_one_drive(&db, fixture::GATE, &settings, &ctx, &log, &drive)
        .await
        .expect_err("both failures must propagate");
    assert_eq!(
        error,
        "probe-double-failure failed: injected run failure; \
         cleanup also failed: probe-double-failure cleanup failed: injected cleanup failure"
    );
}

/// Every `detail` line of a logged statement's `EXPLAIN QUERY PLAN`
/// replay — the seek columns a probe's plan must name, not just the
/// scans the route gate watches.
async fn explain_details(db: &DurableDb, statement: &LoggedStatement) -> Vec<String> {
    let explain_sql = format!("EXPLAIN QUERY PLAN {}", statement.sql);
    let mut explain = db.query(&explain_sql);
    for param in &statement.params {
        explain = explain.bind(param.clone());
    }
    explain
        .fetch_all::<PlanRow>()
        .await
        .expect("EXPLAIN QUERY PLAN replay")
        .iter()
        .map(|row| row.detail.clone())
        .collect()
}

/// The seeded `dispatch_eligible = 1` span is the human-lane pin plus
/// `DISPATCH_ELIGIBLE_ROWS`; every pending row outside it is parked
/// below the admission floor, so the claim's equality seek can only
/// ever examine this many rows. The pins stay inside the span — the
/// lane exemption keeps them eligible under every floor — but their
/// parked `not_before` makes the page predicate refuse them, so the
/// claimable population is the window alone (stow#833).
async fn assert_seeded_claimable_span_is_the_window(db: &DurableDb) {
    let eligible: u64 = db
        .query(
            "SELECT COUNT(*) FROM queue WHERE status = 'pending' \
             AND dispatch_eligible = 1",
        )
        .fetch_scalar()
        .await
        .expect("eligible pending count");
    assert_eq!(
        eligible,
        u64::from(
            fixture::FixtureShape::HUMAN_PROBE_ROWS + fixture::FixtureShape::DISPATCH_ELIGIBLE_ROWS
        ),
        "the fixture's claimable span must be the planted window"
    );
}

/// stow#588's sixth queue run priced each wake probe at ~16k reads on
/// the 100k queue: `dispatch_family != 'macos'` could not bound
/// `idx_queue_wake`'s trailing `wake_at` range, so every alarm pass and
/// every deliver read the whole dispatch-eligible pending set — and a
/// dropped filter when nothing was saturated (stow#833) lost the bound
/// the same way. The term is now unconditional equality —
/// `dispatch_family IN (…)` over `RunnerFamily::ALL` minus the
/// saturated families — which SQLite expands into one seek per
/// surviving family: each arm seeds the gate fixture's production
/// shape, checks the claimable span is the planted window (the bulk
/// parks `dispatch_eligible = 0`, so the claim page's
/// `dispatch_eligible=?` equality seeks into the window instead of
/// reading past parked rows — stow#597's read-past), then plants a
/// burst of eligible future-wake misses and asserts both probes' plans
/// bind `dispatch_family=?` inside the `idx_queue_wake` seek — reads
/// bounded by the family count, never the eligible set.
#[tokio::test]
async fn wake_probes_seek_each_remaining_familys_wake_range() {
    // The live `full_family` a macOS backlog produces — the family
    // the exclusion must remove from the probes' seeks.
    check_wake_probe_seeks(
        SchedulerSettings {
            max_concurrent_macos_jobs: 0,
            ..SchedulerSettings::default()
        },
        "'linux', 'windows'",
        "macos-saturated",
    )
    .await;
    // Nothing saturated: the fixture's one-slot in-flight tasks
    // leave macOS under its cap, so `saturated` is empty — the probes
    // must still carry the family equality, rendered over
    // `RunnerFamily::ALL` in its declared order, or the `wake_at`
    // range loses its bound (stow#833).
    check_wake_probe_seeks(
        SchedulerSettings::default(),
        "'linux', 'macos', 'windows'",
        "unsaturated",
    )
    .await;
}

/// One arm of [`wake_probes_seek_each_remaining_familys_wake_range`]:
/// seed the gate fixture under `settings`, defer every pending wake so
/// both probes log, and assert each statement's plan and `IN` list —
/// `expected_in` is the rendered operand list of
/// `RunnerFamily::ALL` minus the families `settings` saturates.
async fn check_wake_probe_seeks(settings: SchedulerSettings, expected_in: &str, label: &str) {
    let (db, log) = counting_memory_db().await.expect("counting db");
    fixture::seed_production_shape(&db, &fixture::GATE, settings.dispatch_min_age_minutes)
        .await
        .expect("seed fixture");
    assert_seeded_claimable_span_is_the_window(&db).await;
    // Push every pending row's persisted wake into the future and mark
    // the bulk eligible — the miss-burst shape the defect billed on —
    // so the ready probe returns nothing and the deferred probe runs:
    // both statements land in the log.
    db.query(
        "UPDATE queue SET wake_at = '2999-01-01 00:00:00', dispatch_eligible = 1 \
         WHERE status = 'pending'",
    )
    .execute()
    .await
    .expect("defer all wakes");
    let deferred: u64 = db
        .query(
            "SELECT COUNT(*) FROM queue WHERE status = 'pending' \
             AND deps_met = 1 AND dispatch_eligible = 1 \
             AND wake_at > datetime('now')",
        )
        .fetch_scalar()
        .await
        .expect("deferred eligible count");
    assert!(
        deferred >= 1_000,
        "the gate fixture must plant the miss-burst shape — {deferred} eligible future-wake rows"
    );

    let base = log.lock().expect("log").len();
    queue::next_alarm(&db, 0, &settings)
        .await
        .expect("next alarm");
    queue::select_dispatchable_frontier(&db, &settings)
        .await
        .expect("dispatchable frontier");
    let statements = log.lock().expect("log")[base..].to_vec();

    let mut ready_probe = false;
    let mut deferred_probe = false;
    let mut frontier = false;
    for statement in &statements {
        let detail;
        if statement.sql.contains("wake_at <= ?") {
            ready_probe = true;
            detail = explain_details(&db, statement).await.join("\n");
            assert!(
                detail.contains("SEARCH queue USING")
                    && detail.contains("idx_queue_wake")
                    && detail.contains("dispatch_family=?")
                    && detail.contains("wake_at<?"),
                "{label}: ready probe lost the family equality seek:\n{detail}"
            );
        } else if statement.sql.contains("wake_at > ?") {
            deferred_probe = true;
            detail = explain_details(&db, statement).await.join("\n");
            assert!(
                detail.contains("SEARCH queue USING")
                    && detail.contains("idx_queue_wake")
                    && detail.contains("dispatch_family=?")
                    && detail.contains("wake_at>?"),
                "{label}: deferred probe lost the family equality seek:\n{detail}"
            );
        } else if statement.sql.contains("q.dispatch_key > ?") {
            frontier = true;
            detail = explain_details(&db, statement).await.join("\n");
            // The claim page's seek: `dispatch_eligible=?` equality
            // bounds the walk before the `dispatch_key` range — the
            // parked bulk is outside the index span, not read-past
            // inside it (stow#597). `dispatch_family` sits behind that
            // range, so the extra `IN` is a residual term the plan
            // does not show.
            assert!(
                detail.contains("idx_queue_claim")
                    && detail.contains("dispatch_eligible=?")
                    && detail.contains("dispatch_key>?"),
                "{label}: claim page lost the eligible equality seek:\n{detail}"
            );
        } else {
            continue;
        }
        assert!(
            !detail.contains("SCAN queue"),
            "{label}: family-filtered statement scanned the queue:\n{}\nplan:\n{detail}",
            statement.sql
        );
        // The term names exactly the surviving families — the bound is
        // the family count, derived from `RunnerFamily::ALL`, not a
        // list that can drift from it.
        let column = if statement.sql.contains("q.dispatch_family") {
            "q.dispatch_family"
        } else {
            "dispatch_family"
        };
        assert!(
            statement
                .sql
                .contains(&format!("{column} IN ({expected_in})")),
            "{label}: the family term must be RunnerFamily::ALL minus the \
             saturated families: {}",
            statement.sql
        );
    }
    assert!(
        ready_probe && deferred_probe && frontier,
        "{label}: both wake probes and the frontier must carry the family \
         term (ready={ready_probe}, deferred={deferred_probe}, \
         frontier={frontier})"
    );
}

/// A coverage oracle that, on its first question, flips the head
/// candidate out of `pending` the way a concurrent pass's claim does —
/// the coverage lookup is the await between a pass's page read and its
/// claim, so a raced row reads as already claimed with no test seam
/// in the claim code.
struct RacingCoverage<'a> {
    db: &'a DurableDb,
    raced: AtomicBool,
}

impl queue::CoverageOracle for RacingCoverage<'_> {
    fn covered(
        &self,
        identities: &[queue::SemanticTaskIdentity],
    ) -> impl std::future::Future<
        Output = Result<BTreeSet<queue::SemanticTaskIdentity>, crate::errors::QueueError>,
    > + Send {
        let first = !self.raced.swap(true, Ordering::Relaxed);
        let head = identities.first().cloned();
        async move {
            if let (true, Some(head)) = (first, head) {
                self.db
                    .query(
                        "UPDATE queue \
                         SET status = 'dispatched', generation_id = 'racer' \
                         WHERE crate_name = ? AND version = ? AND features_json = ? \
                           AND target = ? AND rustc_version = ?",
                    )
                    .bind(head.crate_name)
                    .bind(head.version)
                    .bind(head.features_json)
                    .bind(head.target)
                    .bind(head.rustc_version)
                    .execute()
                    .await
                    .map_err(|error| crate::errors::QueueError::Sql(error.to_string()))?;
            }
            Ok(BTreeSet::new())
        }
    }
}

/// The per-row claim and the dispatch back-off's `json_each` payload
/// each update `queue` filtered on a status. Without the subquery's
/// `LIMIT -1` SQLite flattens the payload into the join and, with no
/// planner statistics, drives it from
/// `idx_queue_status_first (status=?)` — every row of that status times
/// every payload element, 104k reads in a release-gate preheat. This
/// replays both under `EXPLAIN QUERY PLAN` and requires the primary-key
/// seek.
#[tokio::test]
async fn payload_driven_queue_updates_seek_the_primary_key() {
    const SEEK: &str = "SEARCH queue USING INDEX sqlite_autoindex_queue_1 (task_id=?)";
    const STATUS_WALK: &str = "idx_queue_status_first";

    let (db, log) = counting_memory_db().await.expect("counting db");
    let settings = SchedulerSettings::default();
    fixture::seed_production_shape(&db, &fixture::GATE, settings.dispatch_min_age_minutes)
        .await
        .expect("seed fixture");

    let base = log.lock().expect("log").len();
    let coverage = RacingCoverage {
        db: &db,
        raced: AtomicBool::new(false),
    };
    let claimed = queue::claim_dispatchable_tasks(
        &db,
        &settings,
        &coverage,
        &stow_types::ci::Occupancy::EMPTY,
    )
    .await
    .expect("claim");
    assert!(
        !claimed.is_empty(),
        "the pass must keep a task for the back-off to fail"
    );
    queue::mark_dispatch_failed(
        &db,
        &settings,
        &claimed[0].task_id,
        &claimed[0].generation_id,
        "plan probe",
    )
    .await
    .expect("back off");
    let statements = log.lock().expect("log")[base..].to_vec();

    let mut claim = false;
    let mut back_off = false;
    for statement in &statements {
        let sql = statement.sql.as_str();
        if !sql.starts_with("UPDATE queue") {
            continue;
        }
        let which = if sql.contains("generation_id = lower(hex(randomblob(16)))") {
            &mut claim
        } else if sql.contains("SET status = 'pending', error_msg = ?") {
            &mut back_off
        } else {
            continue;
        };
        *which = true;
        let detail = explain_details(&db, statement).await.join("\n");
        assert!(
            detail.contains(SEEK) && !detail.contains(STATUS_WALK),
            "payload-driven queue update lost its primary-key seek:\n{sql}\nplan:\n{detail}"
        );
    }
    assert!(
        claim && back_off,
        "the pass must run the claim ({claim}) and the back-off ({back_off})"
    );
}

/// The freeze-trip bucket read must stay a bounded index range: the
/// dropped upper bound returned every future bucket the seed ever
/// wrote, and the `ORDER BY target, bucket` steered the planner onto
/// the `(target, bucket)` primary key — a full-table walk the host
/// gate's scan rule would name `SCAN attempt_outcome_buckets` the
/// moment the host failure drive ran the read (stow#833). The fixed
/// statement is one `idx_attempt_outcome_buckets_bucket` range bounded
/// on both ends, exactly the read the resolution failure arm now runs
/// on host through `freeze_trip_draft`.
#[tokio::test]
async fn freeze_trip_bucket_read_is_a_bounded_index_range() {
    let (db, log) = counting_memory_db().await.expect("counting db");
    queue::freeze_trip_draft(&db, &crate::freeze::FreezeSettings::default())
        .await
        .expect("freeze trip draft");
    let statements = log.lock().expect("log").to_vec();

    let mut read = false;
    for statement in &statements {
        if !statement.sql.contains("FROM attempt_outcome_buckets") {
            continue;
        }
        read = true;
        let detail = explain_details(&db, statement).await.join("\n");
        assert!(
            detail.contains(
                "SEARCH attempt_outcome_buckets USING INDEX \
                 idx_attempt_outcome_buckets_bucket (bucket>? AND bucket<?)"
            ),
            "freeze-trip bucket read lost its bounded index range:\n{}\nplan:\n{detail}",
            statement.sql
        );
    }
    assert!(read, "the trip check must read attempt_outcome_buckets");
}

/// The bounded range's read set on the seeded gate fixture: at most
/// `(window / 5 + 1)` buckets per target — the window edge can
/// straddle one extra bucket — over `CI_TARGET_TRIPLES`, never the
/// stored bulk (stow#833). The fixture seeds its bucket rows at and
/// ahead of the current bucket, so the old unbounded-above read
/// returned all of them.
#[tokio::test]
async fn freeze_trip_bucket_read_stays_inside_the_window() {
    let (db, log) = counting_memory_db().await.expect("counting db");
    let settings = SchedulerSettings::default();
    fixture::seed_production_shape(&db, &fixture::GATE, settings.dispatch_min_age_minutes)
        .await
        .expect("seed fixture");

    let freeze = crate::freeze::FreezeSettings::default();
    let base = log.lock().expect("log").len();
    queue::freeze_trip_draft(&db, &freeze)
        .await
        .expect("freeze trip draft");
    let statements = log.lock().expect("log")[base..].to_vec();

    let bound = u64::from(freeze.window_minutes / 5 + 1)
        * u64::try_from(stow_types::api::CI_TARGET_TRIPLES.len()).expect("target count fits u64");
    let mut read = false;
    for statement in &statements {
        if !statement.sql.contains("FROM attempt_outcome_buckets") {
            continue;
        }
        read = true;
        assert!(
            statement.rows_read <= bound,
            "the window read returned {} rows — the bound is \
             (window/5 + 1) × CI_TARGET_TRIPLES = {bound}",
            statement.rows_read
        );
    }
    assert!(read, "the trip check must read attempt_outcome_buckets");
}
