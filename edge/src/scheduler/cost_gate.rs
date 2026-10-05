//! The stow#433 host-side cost gate — a fast pre-check that runs in
//! `cargo test -p stow-edge`. It is *not* the number Cloudflare bills:
//! the host backend exposes no scan-step counters, so `rows_read` here
//! is the statements' result cardinality and `rows_written` their
//! `changes()`. The merge gate is the workerd harness
//! (`budget.rs` + `scripts/scheduler-budget.sh`), which replays the
//! same [`drives`] list on the 100k fixture inside the Durable Object
//! and reports the real cursor counters. This test keeps the host
//! proxies honest on a small fixture — a regression that goes
//! queue-size-proportional trips it in seconds instead of waiting for a
//! workerd run.
//!
//! Besides the numeric budgets, two mechanical rules hold on the
//! statement log of every drive:
//!
//! * no `CREATE`/`ALTER`/`DROP`/`PRAGMA` — migrations and schema checks
//!   are operations work (stow#432), so a route whose log contains one
//!   fails even when it fits its budget;
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
    /// The migrate route is the one place DDL/PRAGMA is legal (the
    /// ops-only migration contract, stow#432); every other entry's log
    /// must clear the head check.
    ddl_permitted: bool,
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
        ddl_permitted: false,
    },
    RouteBudget {
        name: "GET /admin/status",
        statements: 12,
        rows_read: 200,
        rows_written: 0,
        scan_allowlist: &["SCAN queue_dependencies USING INDEX idx_queue_dependencies_unresolved"],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "GET /tasks",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // Index-ordered tail read: the ORDER BY walks
        // `idx_queue_updated_at` and stops at the page's LIMIT — the
        // plan prints SCAN but reads only the newest page.
        scan_allowlist: &["SCAN queue USING INDEX idx_queue_updated_at"],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "GET /tasks?status=failed",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // The status equality bounds the walk to the failed group of
        // `idx_queue_status_updated`; the LIMIT stops it at a page.
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "GET /tasks?status=pending",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // `status = 'pending'` lands `idx_queue_status_updated` on the
        // pending group; `blocked` is filtered out by the residual.
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "GET /tasks?status=blocked",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // `status='pending' AND blocked=1` walks the
        // `idx_queue_pending_live` partial index, whose (blocked,
        // updated_at) key bounds the walk to the blocked group.
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "GET /tasks?target=…",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // `idx_queue_target_updated` bounds the walk to the target's
        // own group.
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "GET /tasks?crate=…",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // `idx_queue_crate_updated` bounds the walk to the crate's rows.
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "GET /tasks?older_than=86400",
        statements: 2,
        rows_read: 600,
        rows_written: 0,
        // `updated_at < now - older_than` is a range probe on
        // `idx_queue_updated_at`, not a scan.
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "GET /tasks?task_ids=…",
        statements: 2,
        rows_read: 40,
        rows_written: 0,
        // Explicit ids: primary-key lookups, no walk.
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    // Mutation routes — one keyed statement each against a bounded
    // selector.
    RouteBudget {
        // The success arm also prices the build-cost bookkeeping
        // (stow#524): one generation-keyed sample insert, the
        // newest-BUILD_SAMPLE_WINDOW cap delete, the window's
        // ≤-window read, the stats upsert and — only when the median
        // moved — a keyed refresh over exactly the same-(crate, target)
        // pending rows.
        name: "POST /tasks/complete-run",
        statements: 14,
        rows_read: 120,
        rows_written: 60,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "POST /tasks/complete-run (failure)",
        statements: 9,
        rows_read: 80,
        rows_written: 20,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "POST /tasks/retry",
        statements: 4,
        rows_read: 10,
        rows_written: 4,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        // Row 5 is a dependent's `blocked` flip: failing a task that
        // other pending rows depend on must wake-block them in the same
        // request, not on the next pass.
        name: "POST /tasks/cancel",
        statements: 3,
        rows_read: 10,
        rows_written: 5,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "POST /tasks/promote",
        statements: 3,
        rows_read: 10,
        rows_written: 4,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "POST /tasks/purge",
        statements: 3,
        rows_read: 10,
        rows_written: 8,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    // The request lane — point reads and writes on `requests`, a table
    // that never grows past the live request set.
    RouteBudget {
        name: "GET /requests/{id}",
        statements: 4,
        rows_read: 40,
        rows_written: 0,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "POST /requests",
        statements: 4,
        rows_read: 20,
        rows_written: 6,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "POST /requests/{id}/run-update (in_progress)",
        statements: 3,
        rows_read: 10,
        rows_written: 4,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "POST /requests/{id}/outcome",
        statements: 14,
        rows_read: 60,
        rows_written: 40,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "POST /requests/{id}/run-update (completed)",
        statements: 3,
        rows_read: 10,
        rows_written: 4,
        scan_allowlist: &[],
        ddl_permitted: false,
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
        ddl_permitted: false,
    },
    RouteBudget {
        // The same batch past the cap: pending-count read, the
        // human-lane budget charge and position walk, the insert.
        name: "POST /enqueue (untrusted accept)",
        statements: 20,
        rows_read: 300,
        rows_written: 100,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "POST /admin/enqueue (trusted)",
        statements: 16,
        rows_read: 120,
        rows_written: 70,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    // The same batch submitted again: writes collapse to the task
    // upserts and the budget charge — the edge set is identical, so
    // the delta sync deletes nothing and the insert conflicts out.
    RouteBudget {
        name: "POST /admin/enqueue (resubmit)",
        statements: 16,
        rows_read: 120,
        rows_written: 12,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        name: "POST /demand",
        statements: 14,
        rows_read: 200,
        rows_written: 60,
        // The recursive walk's working table and the json_each payload
        // scan are keyed-by-construction, not table scans.
        scan_allowlist: &["SCAN walk", "SCAN json_each"],
        ddl_permitted: false,
    },
    // The explicit full report — first publish and `index report --full`
    // resyncs — whose server-side diff reads the live slice (a
    // legitimate bound: the report body names every row).
    RouteBudget {
        name: "POST /index/published (full)",
        statements: 8,
        rows_read: 500,
        rows_written: 150,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    // A report whose membership moved by DELTA_ROWS: the gate writes
    // touch only the changed rows' matched edges and their owners'
    // counters, so its cost is proportional to the delta, never to the
    // slice or the graph (stow#521).
    RouteBudget {
        name: "POST /index/published (delta)",
        statements: 16,
        rows_read: 60,
        rows_written: 200,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    // The alarm's dispatch pass on a warm queue: the claim pages at
    // `2 × open slots` candidate rows and claims them, so the pass's
    // read is bounded by the dispatch cap plus the fixed probes,
    // never by the frontier or the queue.
    RouteBudget {
        name: "alarm pass",
        statements: 90,
        rows_read: 400,
        rows_written: 150,
        // `idx_queue_shape_requeue` is a partial index — `WHERE
        // status='completed' AND shape_requeue=0` — so EXPLAIN calls the
        // walk a SCAN but it covers only completed rows a prior pass
        // already flagged for repair: a ~0-entry set on a warm queue.
        scan_allowlist: &["idx_queue_shape_requeue"],
        ddl_permitted: false,
    },
    RouteBudget {
        // The pass's fixed floor under paused dispatch: recovery probes
        // and the re-arm only — no claim work.
        name: "alarm pass (idle)",
        statements: 12,
        rows_read: 80,
        rows_written: 4,
        scan_allowlist: &["idx_queue_shape_requeue"],
        ddl_permitted: false,
    },
    RouteBudget {
        // One real dispatch pass over the floored queue — the same
        // claim/plan surface as the hot pass, priced separately so
        // the gate sees planner and claim cost under a positive
        // persisted floor (stow#525).
        name: "alarm pass (floor claim)",
        statements: 90,
        rows_read: 500,
        rows_written: 150,
        scan_allowlist: &["idx_queue_shape_requeue"],
        ddl_permitted: false,
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
        ddl_permitted: false,
    },
    RouteBudget {
        // Fresh open: closed-hour check, watermark guard, header
        // insert, generation read-back.
        name: "POST /scheduler/demand-feed/begin (fresh)",
        statements: 8,
        rows_read: 8,
        rows_written: 3,
        scan_allowlist: &[],
        ddl_permitted: false,
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
        ddl_permitted: false,
    },
    RouteBudget {
        // One staged page: header probe, ordering/generation guard,
        // payload insert whose trigger bumps counters.
        name: "POST /scheduler/demand-feed/page (append)",
        statements: 6,
        rows_read: 8,
        rows_written: 3,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        // Same-bytes replay: the guards plus the stored-hash
        // compare — bounded reads, zero writes.
        name: "POST /scheduler/demand-feed/page (replay)",
        statements: 6,
        rows_read: 8,
        rows_written: 0,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        // Completion barrier, populated hour: manifest verification
        // over the generation's staged hashes plus the guarded freeze.
        name: "POST /scheduler/demand-feed/complete (nonempty)",
        statements: 8,
        rows_read: 8,
        rows_written: 3,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        // The same barrier with an empty generation — verification
        // against zero pages, still a guarded transition.
        name: "POST /scheduler/demand-feed/complete (empty)",
        statements: 8,
        rows_read: 8,
        rows_written: 3,
        scan_allowlist: &[],
        ddl_permitted: false,
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
        ddl_permitted: false,
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
        ddl_permitted: false,
    },
    RouteBudget {
        // Delivered-hour replay: the header `delivered` early-out
        // plus the wake re-plan — two reads, no ledger writes.
        name: "POST /scheduler/demand-feed/deliver (replay)",
        statements: 12,
        rows_read: 30,
        rows_written: 0,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        // One full retirable chunk: header read, `DELETE … LIMIT
        // 256`, pending probe — flat in archive depth.
        name: "POST /scheduler/demand-feed/cleanup (full chunk)",
        statements: 8,
        rows_read: 8,
        rows_written: 260,
        scan_allowlist: &[],
        ddl_permitted: false,
    },
    RouteBudget {
        // The retire probe on an all-live generation: header read,
        // a zero-match DELETE, pending probe.
        name: "POST /scheduler/demand-feed/cleanup (none obsolete)",
        statements: 8,
        rows_read: 8,
        rows_written: 2,
        scan_allowlist: &[],
        ddl_permitted: false,
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
    if !budget.ddl_permitted {
        for statement in &measurement.statements {
            assert!(
                !has_schema_head(&statement.sql),
                "{} issued DDL/PRAGMA on a request path: {}",
                budget.name,
                statement.sql,
            );
        }
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

    // The migrate route is the only DDL path — it runs on the same seeded
    // fixture under the raw (permit-open) counting backend.
    let (raw_db, raw_log) = counting_memory_db_raw().await.expect("raw counting db");
    fixture::seed_production_shape(&raw_db, &fixture::GATE, settings.dispatch_min_age_minutes)
        .await
        .expect("seed fixture");
    let base = raw_log.lock().expect("statement log").len();
    queue::migrate(&raw_db, &SchedulerSettings::default())
        .await
        .expect("migrate");
    let measurement = Measurement::of(raw_log.lock().expect("statement log")[base..].to_vec());
    eprintln!(
        "BUDGET {:<34} statements={:<4} rows_read={:<7} rows_written={:<7}",
        "POST /migrate",
        measurement.statement_count,
        measurement.rows_read,
        measurement.rows_written,
    );
}

#[derive(Debug, skyzen::FromRow)]
struct RunningTarget {
    attempt: i64,
    github_run_id: Option<String>,
    generation_id: String,
}

async fn running_target(db: &DurableDb, shape: fixture::FixtureShape) -> RunningTarget {
    db.query("SELECT attempt, github_run_id, generation_id FROM queue WHERE task_id = printf('%064x', ?)")
        .bind(i64::from(shape.running_row()))
        .fetch_optional::<RunningTarget>()
        .await
        .expect("running target query")
        .expect("running target row")
}

async fn running_outcomes(db: &DurableDb, shape: fixture::FixtureShape) -> i64 {
    db.query(
        "SELECT COALESCE(SUM(outcomes), 0) FROM attempt_outcome_buckets \
         WHERE target = (SELECT target FROM queue WHERE task_id = printf('%064x', ?))",
    )
    .bind(i64::from(shape.running_row()))
    .fetch_scalar::<i64>()
    .await
    .expect("running outcomes")
}

async fn status_of(db: &DurableDb, task_id: &str) -> String {
    db.query("SELECT status FROM queue WHERE task_id = ?")
        .bind(task_id.to_owned())
        .fetch_scalar::<String>()
        .await
        .expect("status")
}

async fn assert_failure_evidence(db: &DurableDb, shape: fixture::FixtureShape, expected: usize) {
    let generations = db
        .query("SELECT generation_id FROM attempt_outcomes_v2 WHERE task_id = printf('%064x', ?) AND attempt = 1")
        .bind(i64::from(shape.dispatched_row(0)))
        .fetch_scalars::<String>()
        .await
        .expect("failure generations");
    assert_eq!(generations.len(), expected, "each pass records its failure");
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
        shape.running_row(),
        shape.dispatched_row(0),
    ];
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
/// survives), and the running target's `attempt` steps forward so each
/// pass's completion lands on a fresh epoch.
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
    run_drives(&db, shape, &settings, &ctx, &log).await;

    // The complete drive lands `completed` + stamps the run id; the
    // same pass's shape-requeue sweep then re-enters the row as
    // `pending` at `attempt + 1` — the post-pass read is that state,
    // which is also the state the re-arm restores from. A success
    // never writes a raw `attempt_outcomes` row: the per-target
    // bucket's `outcomes` count is the completion's evidence, and it
    // must increase exactly once per landed transition.
    let first = running_target(&db, shape).await;
    let run_id = format!("run-{}", shape.running_row());
    assert_eq!(
        first.github_run_id.as_deref(),
        Some(run_id.as_str()),
        "the pass's completion landed and stamped its run id"
    );
    assert_eq!(
        running_outcomes(&db, shape).await,
        1,
        "the first pass's completed transition counted once"
    );
    let claimed = ctx.claimed_ids();
    assert_failure_evidence(&db, shape, 1).await;
    assert!(!claimed.is_empty(), "the gate pass claims rows");
    fixture::record_probe_claimed(&db, &claimed)
        .await
        .expect("record claims");
    fixture::rearm(&db, shape, settings.dispatch_min_age_minutes)
        .await
        .expect("re-arm fixture");
    assert_rearm_gate_truth(&db, shape, &claimed).await;

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
    let second = running_target(&db, shape).await;
    assert_eq!(second.github_run_id.as_deref(), Some(run_id.as_str()));
    assert_ne!(second.generation_id, first.generation_id);
    assert_failure_evidence(&db, shape, 2).await;
    // The second pass's own transition — counted once more, on a
    // fresh generation. The re-arm also steps `attempt` past whatever
    // the last pass left; the requeue's +1 rides on top, so strict
    // increase is the form, not +1.
    assert_eq!(
        running_outcomes(&db, shape).await,
        2,
        "the second pass's completed transition counted once more"
    );
    assert!(
        second.attempt > first.attempt,
        "each pass completes a fresh attempt epoch: {} then {}",
        first.attempt,
        second.attempt,
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
