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
        name: "POST /tasks/complete-run",
        statements: 7,
        rows_read: 70,
        rows_written: 20,
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
        statements: 3,
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
    // The in-flight↔GitHub reconcile pass (stow#526): the in-flight
    // scan is bounded by the dispatch cap, per-completion applies are
    // the `complete-run` work above, and the stale reclaim is the same
    // whole-table UPDATE the alarm owes.
    RouteBudget {
        name: "POST /reconcile",
        statements: 20,
        rows_read: 150,
        rows_written: 12,
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
    for drive in drives::DRIVES {
        let base = log.lock().expect("statement log").len();
        (drive.run)(&db, shape, &settings, &ctx)
            .await
            .unwrap_or_else(|error| panic!("{} failed: {error}", drive.name));
        let statements = log.lock().expect("statement log")[base..].to_vec();
        let measurement = Measurement::of(statements);
        check(&db, budget_of(drive.name), &measurement).await;
    }

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
