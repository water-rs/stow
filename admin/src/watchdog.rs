//! `stow-admin watchdog` — the external breaker of issue #450.
//!
//! Each run measures four signal groups — Cloudflare usage over the
//! current month against the 80% line of the monthly included
//! allowances (with the last hour's pace as alert-only context), edge health (Worker
//! invocation statuses, DO resource failures, `overloaded` events), the
//! build pipeline (build-crate failed-task share, dispatch retries,
//! pending age, dispatch stalls, stalled builds, preheat freshness), the
//! workflow history (failed `operations.yml` runs, a missed watchdog
//! dispatch), and the public endpoints — then acts on the
//! verdict: `Trip` breaches disable the dispatching workflows that read
//! `active` — the exact set, recorded on the incident issue for `clear`
//! to restore — and enable
//! the zone's WAF rule for the widest scope the breaching signals name
//! (`lanes` for scheduler-DO costs, `anonymous` for Worker costs), and
//! any breach opens
//! or updates the `incident`
//! issue and mails the alert. Health and latency signals alert without
//! tripping; the watchdog never un-trips on its own — recovery is the
//! manual `stow-admin watchdog clear`.
//!
//! It runs outside the edge (a GitHub Actions cron) so a broken edge
//! cannot silence it, and it exits non-zero only on its own failure —
//! an unreadable signal, a failed actuation, a failed notification —
//! never because it saw an incident.
//!
//! Costs (AGENTS.md "resources are spent deliberately"): one run is one
//! GraphQL POST for the hour and health windows plus one day-bounded
//! GraphQL POST per elapsed UTC day of the month (≤31, at most
//! [`MONTH_QUERY_CONCURRENCY`] in flight), one Analytics Engine SQL POST, ≤3 admin/endpoint calls,
//! one GHCR verified pull for the bundle probe (tag list + index
//! manifest + signature + blob), ≤ `1 + completed-runs +
//! MAX_CLASSIFIED_TASKS` GitHub REST reads (a run's jobs live only on
//! its jobs page), plus two for the liveness signals (the newest
//! build-crate run, the newest successful preheat-admin run), plus two
//! for the history signals (recent watchdog runs, the operations runs
//! of the report window), plus one per trip workflow when a trip runs, and, only
//! while an incident is open, ≤8 REST mutations
//! plus one email — idle runs issue no mutations at all.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use askama::Template;
use clap::{Args, Subcommand};
use futures_util::{StreamExt as _, TryStreamExt as _};
use stow_types::analytics;
use stow_types::api::{AdminStatus, DispatchCaps, DispatchFreeze};
use stow_types::identity::WireRustcVersion;
use stow_types::runs::{RunFailure, RunJobRow};
use stow_types::stow_error;
use stow_types::transient::Backoff;
use stow_types::trusted_builder::WORKFLOW_FILE;

use crate::maintenance::{self, MaintenanceScope};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zenwave::{Client, ResponseExt};

use crate::cloudflare::{self, API_BASE};
use crate::render::{self, Output, Table};
use crate::runs;
use crate::{Edge, github};

/// `stow-admin watchdog [clear]` args.
#[derive(Args)]
pub struct WatchdogArgs {
    #[command(subcommand)]
    pub command: Option<WatchdogCommand>,
    /// Print the evaluation and the actions it would take without
    /// applying any of them — the plan-only form of both modes.
    #[arg(long, global = true)]
    pub dry_run: bool,
}

/// `stow-admin watchdog` subcommands.
#[derive(Subcommand)]
pub enum WatchdogCommand {
    /// Manual recovery: maintenance rule off, workflows re-enabled, incident
    /// commented and closed, and the clear mail sent. The watchdog
    /// itself never does this on its own.
    Clear,
}

/// The entry point — `stow-admin watchdog` evaluates and trips,
/// `stow-admin watchdog clear` reverses it.
pub async fn run(edge: &Edge, args: WatchdogArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        Some(WatchdogCommand::Clear) => clear(edge, args.dry_run, output).await,
        None => watch(edge, args.dry_run, output).await,
    }
}

// ===== The signal table =====

/// What a breach of a signal does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// Breach trips the breaker: the zone's maintenance rule for this
    /// scope on, dispatching workflows disabled. The scope is what the
    /// breach costs: a cost the scheduler Durable Object bills sheds
    /// only the lanes that reach it, so bundle downloads and index
    /// routes keep serving.
    Trip(MaintenanceScope),
    /// Breach opens/updates the incident and alerts; nothing is cut.
    Alert,
}

/// The scopes a trip can enable, narrowest first — `clear` lifts every
/// one of them, and a trip with several breaching signals enables the
/// widest of their scopes.
const TRIP_SCOPES: [MaintenanceScope; 2] = [MaintenanceScope::Lanes, MaintenanceScope::Anonymous];

/// How much of the edge a scope sheds — the order "widest wins" reads.
const fn scope_width(scope: MaintenanceScope) -> u8 {
    match scope {
        MaintenanceScope::Lanes => 0,
        MaintenanceScope::Anonymous => 1,
        MaintenanceScope::All => 2,
    }
}

/// The history a signal's measurement covers.
#[derive(Debug, Clone, Copy)]
enum Window {
    /// A point-in-time check.
    Now,
    /// The last this-many seconds.
    Last(u64),
    /// From the start of the current UTC calendar month to now.
    MonthToDate,
}

/// One line of the threshold table — the single typed place a signal's
/// window, minimum sample, threshold and trip/alert effect live.
#[derive(Debug)]
struct Signal {
    /// Stable identifier (`cf.do.rows_read`) — incident text, tests and
    /// the JSON report key on it.
    id: &'static str,
    /// What the value means, for the rendered tables.
    label: &'static str,
    /// The history the measurement covers.
    window: Window,
    /// Smallest sample the measurement needs before its verdict counts —
    /// below it the signal reports `skipped`, never `clear` or `breach`.
    /// For rates the sample is the denominator (requests, runs); for
    /// counts and point checks it is `0`.
    min_sample: u64,
    /// Observed value at or above which the signal breaches. The
    /// hourly-pace alerts carry `0.0` here: their level is an operator
    /// setting read at run time, so each reading brings its own
    /// threshold ([`Reading::threshold`]).
    threshold: f64,
    /// Unit for rendered values ("rows", "%", "ms", "s", "runs").
    unit: &'static str,
    effect: Effect,
}

// Monthly included allowances, per Cloudflare's published pricing
// (verified against the docs 2026-09-28;  carries the
// same table for the in-edge daily budgets):
// - Workers Paid — 10M requests/mo, 30M CPU ms/mo. Per the Workers
//   pricing footnote, subrequests are not billed, so `subrequests` is
//   collected as diagnostic context only.
//   <https://developers.cloudflare.com/workers/platform/pricing/>
// - Durable Objects Paid — 1M requests/mo, 400k GB-s duration/mo,
//   25G rows read/mo, 50M rows written/mo (SQLite storage billing).
//   `activeTime` and `cpuTime` are collected as diagnostics.
//   <https://developers.cloudflare.com/durable-objects/platform/pricing/>
use stow_types::do_budgets::ALLOWANCE_FRACTION;
pub use stow_types::do_budgets::{DO_ROWS_READ_MONTHLY, DO_ROWS_WRITTEN_MONTHLY};
pub const DO_REQUESTS_MONTHLY: f64 = 1e6;
pub const DO_DURATION_GB_S_MONTHLY: f64 = 400e3;
pub const WORKER_REQUESTS_MONTHLY: f64 = 10e6;
pub const WORKER_CPU_MS_MONTHLY: f64 = 30e6;

/// One hour — the window of the health signals and of the hourly-pace
/// usage alerts; point checks and the 15-minute health window are the
/// exceptions below.
const HOUR: u64 = 3600;
/// The edge-health window — 15 minutes, matching the run cadence, so a
/// burst that straddles two cron runs is still seen whole.
const QUARTER_HOUR: u64 = 900;

/// The threshold table — every signal's window, minimum sample,
/// threshold and trip/alert effect in one place.
const SIGNALS: &[Signal] = &[
    // ── Cloudflare usage, billed dimensions: the month to date against the
    // 80% line of the monthly allowance — breach trips ──
    Signal {
        id: "cf.do.rows_read",
        label: "DO rows read this month vs 80% of the 25G/mo allowance",
        window: Window::MonthToDate,
        min_sample: 0,
        threshold: DO_ROWS_READ_MONTHLY * ALLOWANCE_FRACTION,
        unit: "rows",
        effect: Effect::Trip(MaintenanceScope::Lanes),
    },
    Signal {
        id: "cf.do.rows_written",
        label: "DO rows written this month vs 80% of the 50M/mo allowance",
        window: Window::MonthToDate,
        min_sample: 0,
        threshold: DO_ROWS_WRITTEN_MONTHLY * ALLOWANCE_FRACTION,
        unit: "rows",
        effect: Effect::Trip(MaintenanceScope::Lanes),
    },
    Signal {
        id: "cf.do.duration_gb_s",
        label: "DO billed duration this month vs 80% of the 400k GB-s/mo allowance",
        window: Window::MonthToDate,
        min_sample: 0,
        threshold: DO_DURATION_GB_S_MONTHLY * ALLOWANCE_FRACTION,
        unit: "GB-s",
        effect: Effect::Trip(MaintenanceScope::Lanes),
    },
    Signal {
        id: "cf.do.requests",
        label: "DO requests this month vs 80% of the 1M/mo allowance",
        window: Window::MonthToDate,
        min_sample: 0,
        threshold: DO_REQUESTS_MONTHLY * ALLOWANCE_FRACTION,
        unit: "requests",
        effect: Effect::Trip(MaintenanceScope::Lanes),
    },
    Signal {
        id: "cf.worker.requests",
        label: "Worker requests this month vs 80% of the 10M/mo allowance",
        window: Window::MonthToDate,
        min_sample: 0,
        threshold: WORKER_REQUESTS_MONTHLY * ALLOWANCE_FRACTION,
        unit: "requests",
        effect: Effect::Trip(MaintenanceScope::Anonymous),
    },
    Signal {
        id: "cf.worker.cpu_ms",
        label: "Worker CPU this month vs 80% of the 30M ms/mo allowance",
        window: Window::MonthToDate,
        min_sample: 0,
        threshold: WORKER_CPU_MS_MONTHLY * ALLOWANCE_FRACTION,
        unit: "ms",
        effect: Effect::Trip(MaintenanceScope::Anonymous),
    },
    // ── the last hour's pace against the allowance's hourly pace, at the
    // operator-set levels — breach alerts, never trips ──
    Signal {
        id: "cf.do.rows_read.hourly",
        label: "DO rows read in the last hour vs the hourly pace of the 25G/mo allowance",
        window: Window::Last(HOUR),
        min_sample: 0,
        threshold: 0.0,
        unit: "rows",
        effect: Effect::Alert,
    },
    Signal {
        id: "cf.do.rows_written.hourly",
        label: "DO rows written in the last hour vs the hourly pace of the 50M/mo allowance",
        window: Window::Last(HOUR),
        min_sample: 0,
        threshold: 0.0,
        unit: "rows",
        effect: Effect::Alert,
    },
    Signal {
        id: "cf.do.duration_gb_s.hourly",
        label: "DO billed duration in the last hour vs the hourly pace of the 400k GB-s/mo allowance",
        window: Window::Last(HOUR),
        min_sample: 0,
        threshold: 0.0,
        unit: "GB-s",
        effect: Effect::Alert,
    },
    Signal {
        id: "cf.do.requests.hourly",
        label: "DO requests in the last hour vs the hourly pace of the 1M/mo allowance",
        window: Window::Last(HOUR),
        min_sample: 0,
        threshold: 0.0,
        unit: "requests",
        effect: Effect::Alert,
    },
    Signal {
        id: "cf.worker.requests.hourly",
        label: "Worker requests in the last hour vs the hourly pace of the 10M/mo allowance",
        window: Window::Last(HOUR),
        min_sample: 0,
        threshold: 0.0,
        unit: "requests",
        effect: Effect::Alert,
    },
    Signal {
        id: "cf.worker.cpu_ms.hourly",
        label: "Worker CPU in the last hour vs the hourly pace of the 30M ms/mo allowance",
        window: Window::Last(HOUR),
        min_sample: 0,
        threshold: 0.0,
        unit: "ms",
        effect: Effect::Alert,
    },
    // ── edge health — breach alerts, never trips ──
    Signal {
        id: "edge.worker.errors",
        label: "Worker non-success share (scriptThrewException + internalError + exceededResources)",
        window: Window::Last(QUARTER_HOUR),
        min_sample: 100,
        threshold: 2.0,
        unit: "%",
        effect: Effect::Alert,
    },
    Signal {
        id: "edge.worker.exceeded",
        label: "Worker exceededResources + internalError invocations",
        window: Window::Last(QUARTER_HOUR),
        min_sample: 0,
        threshold: 1.0,
        unit: "invocations",
        effect: Effect::Alert,
    },
    Signal {
        id: "edge.do.exceeded",
        label: "DO exceededCpu + exceededMemory + fatalInternalErrors",
        window: Window::Last(HOUR),
        min_sample: 0,
        threshold: 1.0,
        unit: "errors",
        effect: Effect::Alert,
    },
    // The DO's own breaker — the freeze itself already cut dispatch,
    // so the watchdog records the incident and never re-trips: no
    // maintenance rule, no workflow disable.
    Signal {
        id: "edge.dispatch_frozen",
        label: "scheduler dispatch freeze engaged (the DO's own breaker fired)",
        window: Window::Now,
        min_sample: 1,
        threshold: 1.0,
        unit: "frozen",
        effect: Effect::Alert,
    },
    Signal {
        id: "edge.do.overloaded",
        label: "`overloaded` fault events (Analytics Engine stow_cache_misses)",
        window: Window::Last(HOUR),
        min_sample: 0,
        threshold: 1.0,
        unit: "events",
        effect: Effect::Alert,
    },
    // ── build pipeline ──
    // The task is the unit: one failed task is one failed run.
    Signal {
        id: "pipeline.failure_rate",
        label: "build-crate failed-task share of completed tasks",
        window: Window::Last(HOUR),
        min_sample: 20,
        threshold: 50.0,
        unit: "%",
        effect: Effect::Trip(MaintenanceScope::Lanes),
    },
    Signal {
        id: "pipeline.retry_storm",
        label: "build-crate runs at dispatch attempt ≥3",
        window: Window::Last(HOUR),
        min_sample: 0,
        threshold: 10.0,
        unit: "runs",
        effect: Effect::Trip(MaintenanceScope::Lanes),
    },
    Signal {
        id: "pipeline.oldest_pending",
        label: "oldest pending queue task age",
        window: Window::Now,
        min_sample: 1,
        threshold: 86400.0,
        unit: "s",
        effect: Effect::Alert,
    },
    Signal {
        id: "pipeline.dispatch_stall",
        label: "pending tasks with free slots and nothing dispatched",
        window: Window::Last(HOUR),
        min_sample: 1,
        threshold: 1.0,
        unit: "stalled",
        effect: Effect::Alert,
    },
    // The two liveness signals: a pipeline that does nothing raises no
    // failure, so each judges the absence. Their levels are operator
    // settings ([`LivenessLevels`]), so the table carries `0.0` and each
    // reading brings its own threshold.
    Signal {
        id: "pipeline.preheat_stale",
        label: "age of the last successful preheat-admin run (its tasks reached the scheduler)",
        window: Window::Now,
        min_sample: 1,
        threshold: 0.0,
        unit: "h",
        effect: Effect::Alert,
    },
    Signal {
        id: "pipeline.builds_stalled",
        label: "time since the last build-crate run started while dispatchable tasks and free slots exist",
        window: Window::Now,
        min_sample: 1,
        threshold: 0.0,
        unit: "h",
        effect: Effect::Alert,
    },
    // The two workflow-history signals: an operator mutation that failed
    // and a watchdog that was not dispatched on time. Their levels are
    // operator settings ([`HistoryLevels`]), so the table carries `0.0`
    // and each reading brings its own threshold (`operations.failed`
    // breaches at one failed run).
    Signal {
        id: "operations.failed",
        label: "operations.yml runs that concluded failure, timed_out or startup_failure since the previous watchdog run (at least the operator's window)",
        window: Window::Now,
        min_sample: 1,
        threshold: 0.0,
        unit: "runs",
        effect: Effect::Alert,
    },
    Signal {
        id: "watchdog.gap",
        label: "time since the previous watchdog run started (a missed periodic dispatch, reported after the fact)",
        window: Window::Now,
        min_sample: 1,
        threshold: 0.0,
        unit: "h",
        effect: Effect::Alert,
    },
    // ── public endpoints — alert ──
    Signal {
        id: "endpoint.stats",
        label: "GET /api/v1/stats answers 200",
        window: Window::Now,
        min_sample: 1,
        threshold: 5000.0,
        unit: "ms",
        effect: Effect::Alert,
    },
    Signal {
        id: "endpoint.artifact",
        label: "GET of a real bundle byte path answers 200",
        window: Window::Now,
        min_sample: 1,
        threshold: 5000.0,
        unit: "ms",
        effect: Effect::Alert,
    },
];

/// The `Signal` line for `id` — the table is the only place ids live.
fn signal(id: &str) -> &'static Signal {
    SIGNALS
        .iter()
        .find(|signal| signal.id == id)
        .unwrap_or_else(|| panic!("unknown watchdog signal `{id}`"))
}

// ===== Readings and the pure decision =====

/// What one signal measured this run.
#[derive(Debug)]
struct Reading {
    signal: &'static Signal,
    /// Denominator or count basis the verdict's `min_sample` reads —
    /// total requests for a rate, completed tasks for the task share, `1`
    /// for a point check, pending count for the dispatch stall.
    sample: u64,
    /// The measured value in the signal's unit.
    value: f64,
    /// A threshold that replaces the signal's own — set by the readings
    /// whose level is an operator setting read at run time.
    threshold: Option<f64>,
    /// One-line evidence for the incident body — top routes, run links,
    /// statuses.
    evidence: Vec<String>,
}

/// A signal group that could not be measured — the watchdog is blind
/// there and reports it as its own failure.
#[derive(Debug, serde::Serialize)]
struct CollectFailure {
    /// Which collector failed ("cloudflare-usage", "pipeline", …).
    scope: &'static str,
    error: String,
}

/// What a reading says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum Verdict {
    /// Below `min_sample` — the signal abstains.
    Skipped,
    Clear,
    Breach,
}

impl Reading {
    /// The value at or above which this reading breaches.
    fn threshold(&self) -> f64 {
        self.threshold.unwrap_or(self.signal.threshold)
    }
}

fn verdict(reading: &Reading) -> Verdict {
    if reading.sample < reading.signal.min_sample {
        Verdict::Skipped
    } else if reading.value >= reading.threshold() {
        Verdict::Breach
    } else {
        Verdict::Clear
    }
}

/// The fold of one run's readings — what the run decided.
#[derive(Debug)]
struct Decision {
    /// Breaching `Trip` signals — indices into the readings vec.
    tripped: Vec<usize>,
    /// The maintenance scope the trip enables: the widest of the
    /// breaching `Trip` signals' scopes; `None` when nothing tripped.
    trip_scope: Option<MaintenanceScope>,
    /// Breaching `Alert` signals.
    alerting: Vec<usize>,
    /// Signals below their minimum sample — reported, never acted on.
    skipped: Vec<usize>,
    /// A collector failure is itself an incident (the watchdog is blind
    /// somewhere) even when every readable signal is clear.
    incident: bool,
}

/// Fold readings into the run's decision. Pure — fixtures drive it in
/// tests.
fn decide(readings: &[Reading], collect_failures: &[CollectFailure]) -> Decision {
    let mut tripped = Vec::new();
    let mut alerting = Vec::new();
    let mut skipped = Vec::new();
    for (index, reading) in readings.iter().enumerate() {
        match verdict(reading) {
            Verdict::Breach if matches!(reading.signal.effect, Effect::Trip(_)) => {
                tripped.push(index);
            }
            Verdict::Breach => alerting.push(index),
            Verdict::Skipped => skipped.push(index),
            Verdict::Clear => {}
        }
    }
    let trip_scope = tripped
        .iter()
        .filter_map(|&index| match readings[index].signal.effect {
            Effect::Trip(scope) => Some(scope),
            Effect::Alert => None,
        })
        .max_by_key(|&scope| scope_width(scope));
    Decision {
        trip_scope,
        incident: !tripped.is_empty() || !alerting.is_empty() || !collect_failures.is_empty(),
        tripped,
        alerting,
        skipped,
    }
}

// ===== Collection =====

/// Cloudflare credentials/env the analytics calls need.
const CF_ACCOUNT_ID_ENV: &str = "CF_ACCOUNT_ID";
/// The Worker script name the Workers metrics filter on — must match
/// `cloudflare.name` in `edge/Skyzen.toml`.
const WORKER_SCRIPT_NAME: &str = "stow-edge";

/// Bound on per-run GitHub log classification — each classified failed
/// task costs one log call on top of its run's jobs read, so a
/// pathological failure storm is reported at the cap instead of
/// burning the job's minutes.
const MAX_CLASSIFIED_TASKS: usize = 25;
/// Independent jobs-page reads in flight at once — the same bound
/// `github::runs_in_range` uses for its subdivision reads.
const JOBS_READ_CONCURRENCY: usize = 8;
/// Day-bounded usage queries in flight at once. A month is at most 31
/// of them; eight keeps a run's wall time at a few round trips without
/// a burst against the analytics API.
const MONTH_QUERY_CONCURRENCY: usize = 8;
/// The repository variable (passed into the watchdog's environment)
/// that sets the hourly-pace alert levels, as comma-separated percents
/// of the hourly pace.
const HOURLY_ALERT_ENV: &str = "STOW_WATCHDOG_HOURLY_ALERT_PERCENTS";
/// The levels used while [`HOURLY_ALERT_ENV`] is unset or empty:
/// 200% and 300% of the hourly pace.
const DEFAULT_HOURLY_ALERT_PERCENTS: [f64; 2] = [200.0, 300.0];

/// The repository variable (passed into the watchdog's environment)
/// that sets how old the last successful preheat may be, in hours.
const PREHEAT_MAX_AGE_ENV: &str = "STOW_WATCHDOG_PREHEAT_MAX_AGE_HOURS";
/// The age used while [`PREHEAT_MAX_AGE_ENV`] is unset or empty: a daily
/// cron plus two hours of slack for the wave to finish.
const DEFAULT_PREHEAT_MAX_AGE_HOURS: f64 = 26.0;
/// The repository variable that sets how long dispatchable work may sit
/// with no `build-crate.yml` run starting, in hours.
const BUILD_STALL_ENV: &str = "STOW_WATCHDOG_BUILD_STALL_HOURS";
/// The window used while [`BUILD_STALL_ENV`] is unset or empty.
const DEFAULT_BUILD_STALL_HOURS: f64 = 2.0;
/// The repository variable that sets how long a failed `operations.yml`
/// run stays reported, in hours (the longer of this and the time since
/// the previous watchdog run is read).
const OPERATIONS_WINDOW_ENV: &str = "STOW_WATCHDOG_OPERATIONS_WINDOW_HOURS";
/// The window used while [`OPERATIONS_WINDOW_ENV`] is unset or empty: one
/// hour, the incident digest's cadence, so a failed run is seen by an
/// incident that lives long enough to digest it.
const DEFAULT_OPERATIONS_WINDOW_HOURS: f64 = 1.0;
/// The repository variable that sets how long after the previous
/// watchdog run started the next may start, in hours.
const RUN_GAP_ENV: &str = "STOW_WATCHDOG_RUN_GAP_HOURS";
/// The gap used while [`RUN_GAP_ENV`] is unset or empty: 45 minutes, three
/// of the 15-minute cadence.
const DEFAULT_RUN_GAP_HOURS: f64 = 0.75;
/// The operator mutation workflow whose failures `operations.failed` reads.
const OPERATIONS_WORKFLOW: &str = "operations.yml";
/// This workflow, whose run history `watchdog.gap` reads.
const WATCHDOG_WORKFLOW: &str = "watchdog.yml";
/// Completed watchdog runs read to find the newest that finished
/// `success` or `failure` — a cancelled one never evaluated.
const WATCHDOG_HISTORY_PAGE: u32 = 10;
/// How long before the report cutoff an `operations.yml` run may have
/// been created and still conclude after it: the job's 60-minute timeout
/// plus a wait behind one run of the `operations` concurrency group.
const OPERATIONS_RUN_LEAD: time::Duration = time::Duration::hours(2);
/// The workflow whose successful runs prove a preheat wave reached the
/// scheduler: the one lane that submits (the daily cron and the
/// newreleases.io delivery both dispatch it).
const PREHEAT_WORKFLOW: &str = "preheat-admin.yml";

/// Dispatching workflows a trip touches — everything that can start a
/// build wave or move the index: `build-crate` (the per-task workflow
/// the scheduler dispatches to), the index cron, and every preheat
/// lane. A trip disables only the ones reading `active`
/// and records exactly that set on the incident issue; `clear` restores
/// the record, nothing more (stow#744).
const TRIP_WORKFLOWS: &[&str] = &[
    WORKFLOW_FILE,
    "index-publish-cron.yml",
    "preheat-admin.yml",
    "preheat-cron.yml",
    "preheat-missed.yml",
    "preheat-projects.yml",
];

/// One failed task inside a completed run — the `pipeline.failure_rate`
/// numerator's unit.
struct FailedTask {
    /// Index into the completed-run list — the run carrying the task.
    run: usize,
    /// The task's classified failure.
    failure: crate::runs::TaskFailure,
}

/// Runtime context every collector and actuation shares.
struct Watcher<'a> {
    edge: &'a Edge,
    /// The job's `GITHUB_TOKEN` (or the operator's token locally) — owns
    /// the incident issue and the workflow enable/disable calls.
    gh_token: &'a str,
    /// `CLOUDFLARE_API_TOKEN`.
    cf_token: &'a str,
    /// `CF_ACCOUNT_ID`.
    account: &'a str,
    /// `CF_ZONE_ID` — the zone whose WAF rules the trip toggles.
    zone: &'a str,
    /// The edge URL's host — the `http.host` term the maintenance rules
    /// carry.
    host: &'a str,
    /// REST base `overloaded_reading` posts its Analytics Engine SQL
    /// to — `cloudflare::API_BASE` in production, a loopback fixture
    /// under `STOW_CF_ANALYTICS_SQL_BASE` (stow#888's mock seam).
    analytics_sql_base: &'a str,
    now: OffsetDateTime,
}

impl Watcher<'_> {
    /// Gather every signal; a collector that fails records a
    /// [`CollectFailure`] — one blind spot never hides the signals that
    /// did read.
    async fn collect(
        &self,
        hourly: &HourlyAlertLevels,
        liveness: &LivenessLevels,
        history: &HistoryLevels,
    ) -> (Vec<Reading>, Vec<CollectFailure>) {
        let mut readings = Vec::new();
        let mut failures = Vec::new();
        // Sequential collectors keep a run at ~20 outbound calls total —
        // deliberate under AGENTS.md's spend rules, and each run
        // already rides one HTTP request.
        macro_rules! gather {
            ($scope:literal, $fut:expr) => {
                match $fut.await {
                    Ok(group) => readings.extend(group),
                    Err(error) => failures.push(CollectFailure {
                        scope: $scope,
                        error,
                    }),
                }
            };
        }
        gather!("cloudflare-usage", self.cf_readings(hourly));
        gather!("overloaded-events", self.overloaded_reading());
        gather!("pipeline", self.pipeline_readings());
        gather!("queue", self.queue_readings(liveness));
        gather!("preheat", self.preheat_reading(liveness));
        gather!("workflow-history", self.history_readings(history));
        gather!("dispatch-freeze", self.freeze_reading());
        let (endpoint_readings, endpoint_failure) = self.endpoint_readings().await;
        readings.extend(endpoint_readings);
        if let Some(error) = endpoint_failure {
            failures.push(CollectFailure {
                scope: "endpoints",
                error,
            });
        }
        (readings, failures)
    }

    // ----- Cloudflare GraphQL -----

    /// Every Cloudflare reading: the month-to-date billed-usage trips,
    /// the last hour's pace alerts and the DO/Worker health alerts. One
    /// GraphQL POST covers the hour and health windows; the month is
    /// summed from day-bounded POSTs ([`Self::month_to_date`]).
    async fn cf_readings(&self, hourly: &HourlyAlertLevels) -> Result<Vec<Reading>, String> {
        let since_hour = self
            .now
            .checked_sub(time::Duration::seconds(
                i64::try_from(HOUR).unwrap_or(i64::MAX),
            ))
            .ok_or("window underflow")?;
        let since_quarter = self
            .now
            .checked_sub(time::Duration::seconds(
                i64::try_from(QUARTER_HOUR).unwrap_or(i64::MAX),
            ))
            .ok_or("window underflow")?;
        let (recent, month) = futures_util::future::try_join(
            self.cf_graphql(
                &format_time(since_hour),
                &format_time(since_quarter),
                &format_time(self.now),
            ),
            self.month_to_date(),
        )
        .await?;
        Ok(recent.readings(&month, hourly, self.now))
    }

    /// POST the hour/health query and decode it into a typed snapshot. A
    /// GraphQL `errors` array is a hard error — never a partial read.
    async fn cf_graphql(
        &self,
        since_hour: &str,
        since_quarter: &str,
        now: &str,
    ) -> Result<CfSnapshot, String> {
        let variables = QueryVars {
            account_tag: self.account.to_owned(),
            script_name: WORKER_SCRIPT_NAME.to_owned(),
            since_hour: since_hour.to_owned(),
            since_quarter: since_quarter.to_owned(),
            now: now.to_owned(),
        };
        let account: AccountGroups =
            cloudflare::query_account(self.cf_token, WATCHDOG_QUERY, &variables).await?;
        Ok(CfSnapshot::from(account))
    }

    /// The billed dimensions summed from the start of the current UTC
    /// month to now: one POST per UTC day, at most
    /// [`MONTH_QUERY_CONCURRENCY`] in flight. Cloudflare publishes no
    /// per-query time-range limit for these datasets, so no query asks
    /// for more than a day; any failed day fails the whole read rather
    /// than understating the month.
    async fn month_to_date(&self) -> Result<MonthTotals, String> {
        let windows = month_day_windows(self.now)?;
        futures_util::stream::iter(windows.into_iter().map(|(since, until)| async move {
            let variables = MonthQueryVars {
                account_tag: self.account.to_owned(),
                script_name: WORKER_SCRIPT_NAME.to_owned(),
                since: format_time(since),
                until: format_time(until),
            };
            let account: AccountGroups =
                cloudflare::query_account(self.cf_token, WATCHDOG_MONTH_QUERY, &variables)
                    .await
                    .map_err(|error| format!("usage {since}..{until}: {error}"))?;
            Ok::<_, String>(MonthTotals::from(&CfSnapshot::from(account)))
        }))
        .buffer_unordered(MONTH_QUERY_CONCURRENCY)
        .try_fold(MonthTotals::default(), |total, day| async move {
            Ok(total + day)
        })
        .await
    }

    // ----- Analytics Engine: DO overloaded events -----

    /// `stow_cache_misses` overload count over the hour — the edge
    /// writes `index1='#fault', blob1='overloaded'` points at every
    /// overload it detects: the platform's "Durable Object is
    /// overloaded" answer and its own queue-full refusals (stow#888).
    /// `count()` over the same window is the liveness probe: a dataset
    /// that received no points at all means the writer chain is down,
    /// and the collector fails naming the dataset rather than reporting
    /// a legitimate zero.
    async fn overloaded_reading(&self) -> Result<Vec<Reading>, String> {
        // `sumIf` keeps the additive estimate's shape — each point's
        // `_sample_interval * double1` — restricted to the overload
        // markers, so unsampled writes count as `count()` while sampled
        // ones stay scaled.
        let query = "SELECT sumIf(_sample_interval * double1, index1 = '#fault' AND blob1 = 'overloaded') AS events, \
                     count() AS points FROM stow_cache_misses \
                     WHERE timestamp >= NOW() - INTERVAL '1' HOUR \
                     FORMAT JSON";
        let rows = cloudflare::analytics_engine_sql::<AnalyticsRow>(
            self.analytics_sql_base,
            self.cf_token,
            self.account,
            query,
        )
        .await?;
        let row = rows
            .first()
            .ok_or_else(|| "stow_cache_misses aggregate query returned no row".to_owned())?;
        if row.points == 0 {
            return Err(
                "stow_cache_misses received no points in the last hour — the edge's analytics writer chain is down"
                    .to_owned(),
            );
        }
        let signal = signal("edge.do.overloaded");
        Ok(vec![Reading {
            signal,
            threshold: None,
            sample: row.points,
            value: row.events,
            evidence: vec![format!(
                "stow_cache_misses index1='#fault' blob1='overloaded' last hour: {}",
                row.events
            )],
        }])
    }

    // ----- GitHub pipeline -----

    /// build-crate completed runs over the hour → the failed-task
    /// share and dispatch-retry signals, with per-target and
    /// per-class evidence.
    ///
    /// A task's outcome lives only on its run's jobs page — one read
    /// per completed run, bounded-concurrent. A page that cannot be
    /// read or whose classification fails is a failed read: the
    /// collector returns `Err`, never an understated share.
    #[allow(clippy::too_many_lines)]
    async fn pipeline_readings(&self) -> Result<Vec<Reading>, String> {
        let since = self
            .now
            .checked_sub(time::Duration::seconds(
                i64::try_from(HOUR).unwrap_or(i64::MAX),
            ))
            .ok_or("window underflow")?;
        let runs = fetch_completed_runs(self.gh_token, since).await?;
        // One jobs read per completed run, bounded-concurrent — a
        // failed read or an unreadable page fails the reading rather
        // than understating the task share (a collector failure is an
        // incident of its own).
        let pages: Vec<Vec<RunJobRow>> =
            futures_util::stream::iter(runs.iter().map(|run| async move {
                runs::fetch_run_jobs(self.gh_token, run.id, run.run_attempt)
                    .await
                    .map_err(|error| format!("run {}: jobs fetch: {error}", run.id))
            }))
            .buffered(JOBS_READ_CONCURRENCY)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<_, _>>()?;

        // Fold every run's page into completed/failed tasks — the
        // task is the unit: one failed task is one failed run.
        let mut completed_tasks = 0u64;
        let mut failed_tasks: Vec<FailedTask> = Vec::new();
        for (index, (run, jobs)) in runs.iter().zip(&pages).enumerate() {
            let outcome = runs::classify_page(
                jobs,
                run.conclusion.as_deref().unwrap_or_default(),
                self.now,
            )
            .map_err(|error| format!("run {}: task classification: {error}", run.id))?;
            match outcome {
                // A run still settling is not a completed task.
                crate::runs::TaskOutcome::Unsettled => {}
                crate::runs::TaskOutcome::Succeeded => completed_tasks += 1,
                crate::runs::TaskOutcome::Failed(failure) => {
                    completed_tasks += 1;
                    if runs::attempted(&failure) {
                        failed_tasks.push(FailedTask {
                            run: index,
                            failure,
                        });
                    }
                }
            }
        }
        #[allow(clippy::cast_precision_loss)]
        let failure_rate = if completed_tasks == 0 {
            0.0
        } else {
            failed_tasks.len() as f64 / completed_tasks as f64 * 100.0
        };
        let retrying: Vec<&GhRun> = runs.iter().filter(|run| run.run_attempt >= 3).collect();

        let mut evidence_rate = Vec::new();
        let mut evidence_retry = Vec::new();
        if !failed_tasks.is_empty() {
            let (targets, classes) = self.classify_failed(&failed_tasks, &pages).await;
            if !targets.is_empty() {
                evidence_rate.push(format!("targets: {}", targets.join(", ")));
            }
            if !classes.is_empty() {
                evidence_rate.push(format!("classes: {}", classes.join(", ")));
            }
            let mut run_urls: BTreeSet<&str> = BTreeSet::new();
            for task in &failed_tasks {
                run_urls.insert(runs[task.run].html_url.as_str());
            }
            for url in run_urls.iter().take(5) {
                evidence_rate.push((*url).to_owned());
            }
            if failed_tasks.len() > 5 {
                evidence_rate.push(format!("+{} more failed tasks", failed_tasks.len() - 5));
            }
        }
        for run in retrying.iter().take(5) {
            evidence_retry.push(format!("{} (attempt {})", run.html_url, run.run_attempt));
        }
        if retrying.len() > 5 {
            evidence_retry.push(format!("+{} more retried runs", retrying.len() - 5));
        }

        #[allow(clippy::cast_precision_loss)]
        let retried = retrying.len() as f64;
        Ok(vec![
            Reading {
                signal: signal("pipeline.failure_rate"),
                threshold: None,
                sample: completed_tasks,
                value: failure_rate,
                evidence: evidence_rate,
            },
            Reading {
                signal: signal("pipeline.retry_storm"),
                threshold: None,
                sample: u64::try_from(runs.len()).unwrap_or(u64::MAX),
                value: retried,
                evidence: evidence_retry,
            },
        ])
    }

    /// For each failed task (≤ `MAX_CLASSIFIED_TASKS`), read its
    /// build job's label for the per-target view and fetch the failed
    /// job's log for the failure class. Log fetch failures degrade
    /// the evidence, never the signal.
    async fn classify_failed(
        &self,
        failed: &[FailedTask],
        pages: &[Vec<RunJobRow>],
    ) -> (Vec<String>, Vec<String>) {
        let mut by_target: std::collections::BTreeMap<String, u32> =
            std::collections::BTreeMap::new();
        let mut by_class: std::collections::BTreeMap<&'static str, u32> =
            std::collections::BTreeMap::new();
        for task in failed.iter().take(MAX_CLASSIFIED_TASKS) {
            let page = &pages[task.run];
            if let Some(target) = runs::build_job(page)
                .and_then(|job| runs::task_label(&job.name))
                .map(|label| label.target)
            {
                *by_target.entry(target).or_default() += 1;
            }
            let job_name = match &task.failure {
                crate::runs::TaskFailure::Run(
                    RunFailure::Verdict { job, .. } | RunFailure::Infrastructure { job, .. },
                )
                | crate::runs::TaskFailure::Concluded { job, .. } => job.as_str(),
            };
            let Some(job) = page.iter().find(|job| job.name == job_name) else {
                continue;
            };
            let log_url = format!(
                "https://api.github.com/repos/{}/actions/jobs/{}/logs",
                github::REPO,
                job.id
            );
            let log = match github::get_text(self.gh_token, &log_url, Backoff::new()).await {
                Ok(log) => log,
                Err(error) => {
                    tracing::warn!(job_id = job.id, %error, "job log unavailable");
                    continue;
                }
            };
            *by_class.entry(classify_one(&log)).or_default() += 1;
        }
        let targets = by_target
            .iter()
            .map(|(target, count)| format!("{target} ×{count}"))
            .collect::<Vec<_>>();
        let classes = by_class
            .iter()
            .map(|(class, count)| format!("{class} ×{count}"))
            .collect::<Vec<_>>();
        (targets, classes)
    }

    // ----- scheduler queue (admin status) -----

    /// `GET /api/v1/admin/status` → oldest-pending age and the
    /// dispatch-stall check: pending work, free slots, and no in-flight
    /// row touched inside the window.
    async fn queue_readings(&self, liveness: &LivenessLevels) -> Result<Vec<Reading>, String> {
        // The cap in force is the operator's to set, so a stall is
        // judged against it rather than against any fixed pool size.
        let (status, caps) = futures_util::join!(
            self.edge.get_json::<AdminStatus>("/api/v1/admin/status"),
            self.edge
                .get_json::<DispatchCaps>("/api/v1/admin/dispatch-cap"),
        );
        let status = status.map_err(|error| error.to_string())?;
        let caps = caps.map_err(|error| error.to_string())?;
        let cap = usize::try_from(caps.max_concurrent_jobs)
            .map_err(|error| format!("dispatch cap does not fit usize: {error}"))?;
        let pending = status.pending_miss + status.pending_human;
        let cutoff = sqlite_now_minus(self.now, HOUR);
        let freshest = status
            .in_flight
            .iter()
            .map(|task| task.claimed_at.as_str())
            .max()
            .map(str::to_owned);
        let stalled = pending > 0
            && status.in_flight.len() < cap
            && freshest.as_deref().is_none_or(|at| at < cutoff.as_str());
        let mut stall_evidence = vec![
            format!("pending={pending}"),
            format!("in_flight={}", status.in_flight.len()),
            format!("dispatch_cap={cap}"),
        ];
        if let Some(freshest) = freshest {
            stall_evidence.push(format!("newest dispatch {freshest}"));
        }
        #[allow(clippy::cast_precision_loss)]
        let oldest_pending = status.oldest_pending_seconds.map_or(0.0, |s| s as f64);
        let latest_build = latest_run(self.gh_token, github::BUILD_WORKFLOW, "")
            .await?
            .map(|run| (run.created_at, run.html_url));
        let stalled_builds = builds_stalled_reading(
            self.now,
            &BuildQueue {
                ready: status.ready,
                in_flight: status.in_flight.len(),
                cap,
                frozen: status.dispatch_frozen,
            },
            latest_build.as_ref().map(|(at, url)| (*at, url.as_str())),
            liveness.build_stall_hours,
        );
        Ok(vec![
            stalled_builds,
            Reading {
                signal: signal("pipeline.oldest_pending"),
                threshold: None,
                sample: u64::from(status.oldest_pending_seconds.is_some()),
                value: oldest_pending,
                evidence: vec![format!("pending={pending}")],
            },
            Reading {
                signal: signal("pipeline.dispatch_stall"),
                threshold: None,
                sample: u64::from(pending),
                value: f64::from(u8::from(stalled)),
                evidence: stall_evidence,
            },
        ])
    }

    // ----- preheat freshness -----

    /// The newest successful `preheat-admin.yml` run. A success means
    /// every submit step exited zero, so its tasks were accepted by the
    /// scheduler; it is the one workflow that submits, whoever
    /// dispatched it. One REST read.
    async fn preheat_reading(&self, liveness: &LivenessLevels) -> Result<Vec<Reading>, String> {
        let latest = latest_run(self.gh_token, PREHEAT_WORKFLOW, "&status=success")
            .await?
            .map(|run| (run.updated_at, run.html_url));
        Ok(vec![preheat_stale_reading(
            self.now,
            latest.as_ref().map(|(at, url)| (*at, url.as_str())),
            liveness.preheat_max_age_hours,
        )])
    }

    // ----- workflow history -----

    /// `watchdog.gap` and `operations.failed`. The newest completed
    /// watchdog run that finished `success` or `failure` is one REST read
    /// (the run in progress is not completed, so it is never its own
    /// predecessor). The `operations.yml` runs are then enumerated over
    /// the closed created-window that can hold a run concluding after the
    /// report cutoff — `OPERATIONS_RUN_LEAD` before it — so the window is
    /// covered however many successes fill it, with no page size to
    /// outgrow; the failed conclusions are kept in code.
    async fn history_readings(&self, levels: &HistoryLevels) -> Result<Vec<Reading>, String> {
        let watchdogs = recent_runs(
            self.gh_token,
            WATCHDOG_WORKFLOW,
            "&status=completed",
            WATCHDOG_HISTORY_PAGE,
        )
        .await?;
        let previous = watchdogs
            .into_iter()
            .find(|run| matches!(run.conclusion.as_deref(), Some("success" | "failure")));
        let previous = previous
            .as_ref()
            .map(|run| (run.created_at, run.html_url.as_str()));
        let cutoff = operations_cutoff(
            self.now,
            previous.map(|(at, _)| at),
            levels.operations_window_hours,
        );
        let gh_token = self.gh_token;
        let operations: Vec<GhRunStamp> = github::runs_in_range(
            OPERATIONS_WORKFLOW,
            "status=completed",
            (cutoff - OPERATIONS_RUN_LEAD).min(self.now),
            self.now,
            |path| async move {
                github::get::<github::RunsPage<GhRunStamp>>(gh_token, &path, Backoff::new()).await
            },
        )
        .await
        .map_err(|error| error.to_string())?;
        let runs: Vec<OperationRun<'_>> = operations
            .iter()
            .map(|run| OperationRun {
                concluded: run.updated_at,
                conclusion: run.conclusion.as_deref().unwrap_or_default(),
                name: &run.display_title,
                url: &run.html_url,
            })
            .collect();
        Ok(vec![
            operations_failed_reading(
                self.now,
                previous.map(|(at, _)| at),
                levels.operations_window_hours,
                &runs,
            ),
            watchdog_gap_reading(self.now, previous, levels.run_gap_hours),
        ])
    }

    // ----- the DO's own breaker -----

    /// `GET /api/v1/admin/dispatch-freeze` — the freeze flag, its
    /// record and the transition log. A `1.0` reading breaches the
    /// signal, which is `Alert`: the freeze is the breaker's cut
    /// itself, so the watchdog's job is the `incident` issue — reason,
    /// since, and the last transitions land in the body.
    async fn freeze_reading(&self) -> Result<Vec<Reading>, String> {
        let freeze: DispatchFreeze = self
            .edge
            .get_json("/api/v1/admin/dispatch-freeze")
            .await
            .map_err(|error| error.to_string())?;
        let mut evidence = Vec::new();
        if let Some(record) = &freeze.record {
            evidence.push(format!(
                "reason: {}",
                crate::summarize_trigger(&record.trigger)
            ));
            evidence.push(format!("since: {}", record.frozen_at));
        }
        for transition in freeze.transitions.iter().take(3) {
            let trigger = transition
                .trigger
                .as_ref()
                .map(|trigger| format!(" — {}", crate::summarize_trigger(trigger)))
                .unwrap_or_default();
            evidence.push(format!(
                "{:?} at {}{}",
                transition.event, transition.at, trigger
            ));
        }
        Ok(vec![Reading {
            signal: signal("edge.dispatch_frozen"),
            threshold: None,
            sample: 1,
            value: f64::from(u8::from(freeze.enabled)),
            evidence,
        }])
    }

    // ----- public endpoints -----

    /// `GET /api/v1/stats` and a `GET` of one real bundle's byte path —
    /// the two anonymous answers a user depends on, checked as a user.
    /// Returns the readings plus an optional collector failure — the
    /// index pull failing blinds `endpoint.artifact` while
    /// `endpoint.stats` still gets its probe.
    async fn endpoint_readings(&self) -> (Vec<Reading>, Option<String>) {
        let mut readings = Vec::new();
        readings.push(
            self.probe("endpoint.stats", "/api/v1/stats", zenwave::Method::GET)
                .await,
        );

        // Pick a real bundle so the GET exercises the byte path: the
        // signed index slice on GHCR — the verified pull `index export`
        // uses — a row's `bundle_digest`. GET, not
        // HEAD: the route registers no HEAD handler, and the probe's job
        // is the real user fetch anyway.
        match self.pick_bundle_digest().await {
            Ok(Some((rustc_version, digest))) => {
                readings.push(
                    self.probe(
                        "endpoint.artifact",
                        &format!("/api/v1/bundles/{rustc_version}/{digest}"),
                        zenwave::Method::GET,
                    )
                    .await,
                );
            }
            Ok(None) => readings.push(Reading {
                signal: signal("endpoint.artifact"),
                threshold: None,
                sample: 0,
                value: 0.0,
                evidence: vec!["no artifacts in the published index".to_owned()],
            }),
            Err(error) => {
                return (readings, Some(format!("index pull: {error}")));
            }
        }
        (readings, None)
    }

    /// One timed anonymous request; the reading breaches on a non-200 or
    /// a latency over the signal's threshold. Transport failure counts as
    /// a breach — the endpoint did not answer.
    async fn probe(&self, id: &str, path: &str, method: zenwave::Method) -> Reading {
        let spec = signal(id);
        let url = format!("{}{path}", self.edge.base());
        let start = std::time::Instant::now();
        let mut client = zenwave::client().timeout(std::time::Duration::from_secs(30));
        let result = match client.method(method, &url) {
            Ok(request) => request.await.map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let (status_text, value) = match &result {
            Ok(response) => {
                let status = response.status().as_u16();
                if status == 200 {
                    (status.to_string(), latency_ms)
                } else {
                    // A non-200 is a breach regardless of how fast it was.
                    (status.to_string(), latency_ms.max(spec.threshold))
                }
            }
            Err(error) => (
                format!("request failed: {error}"),
                spec.threshold.max(latency_ms),
            ),
        };
        Reading {
            signal: spec,
            threshold: None,
            sample: 1,
            value,
            evidence: vec![format!("{path} → {status_text} in {latency_ms:.0}ms")],
        }
    }

    /// One `bundle_digest` out of a published index slice of the current
    /// stable toolchain — returned with the rustc the byte path names —
    /// or `None` when none of its slices carries rows.
    /// The slice is pulled and verified off GHCR — the same signed source
    /// `index export` and `preheat manual` pull — so the probe depends on
    /// the store the CLI itself reads. Only the current
    /// stable rustc's `index.<target>.<rustc>` tags answer: another
    /// toolchain's slice proves nothing about what users are served.
    async fn pick_bundle_digest(
        &self,
    ) -> stow_types::error::Result<Option<(WireRustcVersion, String)>> {
        let rustc_version = crate::rust_channel::stable_rustc_version().await?;
        let base = crate::index_cmd::registry_base()?;
        let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
        let repository = stow_types::registry::cache_repository(&rustc_version);
        let session = base.session(&repository, &http);
        let trust = stow_oci::verify::records_trust().await?;
        for target in stow_types::api::CI_TARGET_TRIPLES {
            let tag = stow_types::index::index_tag(target, rustc_version.as_str());
            let Some(pulled) =
                stow_oci::pull_index(&session, target, rustc_version.as_str()).await?
            else {
                continue;
            };
            let reference = session.reference(&tag)?;
            crate::index_cmd::verify_artifact(
                &session,
                &trust,
                &reference,
                &repository.reference(&tag),
                &pulled.manifest_digest,
                crate::index_cmd::INDEX_CERT_URL,
            )
            .await?;
            let index = crate::index_cmd::decode_published_slice(
                &reference,
                &rustc_version,
                &pulled.bytes,
            )?;
            if let Some(row) = index.rows.first() {
                return Ok(Some((rustc_version, row.bundle_digest.clone())));
            }
        }
        Ok(None)
    }
}

/// The operator-set levels of the hourly-pace alerts, in percent of the
/// hourly pace, ascending.
#[derive(Debug, Clone, PartialEq)]
struct HourlyAlertLevels(Vec<f64>);

impl HourlyAlertLevels {
    /// Read [`HOURLY_ALERT_ENV`]; unset or empty is the default pair.
    fn from_env() -> stow_types::error::Result<Self> {
        match std::env::var(HOURLY_ALERT_ENV) {
            Ok(text) if !text.trim().is_empty() => Self::parse(&text),
            _ => Ok(Self(DEFAULT_HOURLY_ALERT_PERCENTS.to_vec())),
        }
    }

    /// Parse comma-separated percents. The values carry no ceiling or
    /// floor — they are the operator's call — but each must be a
    /// number.
    fn parse(text: &str) -> stow_types::error::Result<Self> {
        let mut levels = text
            .split(',')
            .map(|part| {
                part.trim()
                    .parse::<f64>()
                    .ok()
                    .filter(|level| level.is_finite())
                    .ok_or_else(|| {
                        stow_error!("{HOURLY_ALERT_ENV}: `{}` is not a number", part.trim())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        levels.sort_by(f64::total_cmp);
        Ok(Self(levels))
    }
}

/// The operator-set levels of the two liveness signals, in hours.
#[derive(Debug, Clone, Copy, PartialEq)]
struct LivenessLevels {
    /// Age of the last successful preheat at which `pipeline.preheat_stale` breaches.
    preheat_max_age_hours: f64,
    /// Time without a started build run, with work ready, at which
    /// `pipeline.builds_stalled` breaches.
    build_stall_hours: f64,
}

impl LivenessLevels {
    /// Read [`PREHEAT_MAX_AGE_ENV`] and [`BUILD_STALL_ENV`]; an unset or
    /// empty variable is its default.
    fn from_env() -> stow_types::error::Result<Self> {
        let read = |name: &str| std::env::var(name).ok();
        Self::parse(
            read(PREHEAT_MAX_AGE_ENV).as_deref(),
            read(BUILD_STALL_ENV).as_deref(),
        )
    }

    /// Parse the two settings. The values carry no ceiling or floor —
    /// they are the operator's call — but each must be a number.
    fn parse(
        preheat_max_age: Option<&str>,
        build_stall: Option<&str>,
    ) -> stow_types::error::Result<Self> {
        let hours = |name: &str, text: Option<&str>, default: f64| match text.map(str::trim) {
            Some(text) if !text.is_empty() => text
                .parse::<f64>()
                .ok()
                .filter(|hours| hours.is_finite())
                .ok_or_else(|| stow_error!("{name}: `{text}` is not a number")),
            _ => Ok(default),
        };
        Ok(Self {
            preheat_max_age_hours: hours(
                PREHEAT_MAX_AGE_ENV,
                preheat_max_age,
                DEFAULT_PREHEAT_MAX_AGE_HOURS,
            )?,
            build_stall_hours: hours(BUILD_STALL_ENV, build_stall, DEFAULT_BUILD_STALL_HOURS)?,
        })
    }
}

/// The operator-set levels of the two workflow-history signals, in hours.
#[derive(Debug, Clone, Copy, PartialEq)]
struct HistoryLevels {
    /// How long a failed `operations.yml` run stays reported at least.
    operations_window_hours: f64,
    /// Time since the previous watchdog run started at which
    /// `watchdog.gap` breaches.
    run_gap_hours: f64,
}

impl HistoryLevels {
    /// Read [`OPERATIONS_WINDOW_ENV`] and [`RUN_GAP_ENV`]; an unset or
    /// empty variable is its default.
    fn from_env() -> stow_types::error::Result<Self> {
        let read = |name: &str| std::env::var(name).ok();
        Self::parse(
            read(OPERATIONS_WINDOW_ENV).as_deref(),
            read(RUN_GAP_ENV).as_deref(),
        )
    }

    /// Parse the two settings. The values carry no ceiling or floor —
    /// they are the operator's call — but each must be a number.
    fn parse(
        operations_window: Option<&str>,
        run_gap: Option<&str>,
    ) -> stow_types::error::Result<Self> {
        let hours = |name: &str, text: Option<&str>, default: f64| match text.map(str::trim) {
            Some(text) if !text.is_empty() => text
                .parse::<f64>()
                .ok()
                .filter(|hours| hours.is_finite())
                .ok_or_else(|| stow_error!("{name}: `{text}` is not a number")),
            _ => Ok(default),
        };
        Ok(Self {
            operations_window_hours: hours(
                OPERATIONS_WINDOW_ENV,
                operations_window,
                DEFAULT_OPERATIONS_WINDOW_HOURS,
            )?,
            run_gap_hours: hours(RUN_GAP_ENV, run_gap, DEFAULT_RUN_GAP_HOURS)?,
        })
    }
}

/// A completed `operations.yml` run.
#[derive(Debug, Clone, Copy)]
struct OperationRun<'a> {
    /// When the run concluded (the row's `updated_at`).
    concluded: OffsetDateTime,
    /// The run's conclusion (`success`, `failure`, `cancelled`, …).
    conclusion: &'a str,
    /// The run-name: `stow-admin <argv> (by <actor>)`.
    name: &'a str,
    /// The run's page.
    url: &'a str,
}

/// The conclusions `operations.failed` reports: a command that failed,
/// ran out of time, or never started. `cancelled` is an operator's own
/// choice and stays unreported.
fn is_operations_failure(conclusion: &str) -> bool {
    matches!(conclusion, "failure" | "timed_out" | "startup_failure")
}

/// The earliest conclusion `operations.failed` reports: the previous
/// watchdog run's start, or the operator's window back from `now` when
/// that reaches further (and when there is no previous run).
fn operations_cutoff(
    now: OffsetDateTime,
    previous_watchdog: Option<OffsetDateTime>,
    window_hours: f64,
) -> OffsetDateTime {
    #[allow(clippy::cast_possible_truncation)]
    let window = now - time::Duration::seconds((window_hours * 3600.0) as i64);
    previous_watchdog.map_or(window, |previous| previous.min(window))
}

/// `operations.failed`: the failed runs that concluded since
/// [`operations_cutoff`], newest first, each named with its argv
/// run-name and its conclusion.
fn operations_failed_reading(
    now: OffsetDateTime,
    previous_watchdog: Option<OffsetDateTime>,
    window_hours: f64,
    runs: &[OperationRun<'_>],
) -> Reading {
    let cutoff = operations_cutoff(now, previous_watchdog, window_hours);
    let mut failed: Vec<&OperationRun<'_>> = runs
        .iter()
        .filter(|run| is_operations_failure(run.conclusion) && run.concluded >= cutoff)
        .collect();
    failed.sort_by_key(|run| std::cmp::Reverse(run.concluded));
    let evidence: Vec<String> = failed
        .iter()
        .map(|run| {
            format!(
                "{} concluded {} {} — {}",
                run.name,
                run.conclusion,
                format_time(run.concluded),
                run.url
            )
        })
        .collect();
    #[allow(clippy::cast_precision_loss)]
    let value = evidence.len() as f64;
    Reading {
        signal: signal("operations.failed"),
        sample: 1,
        value,
        threshold: Some(1.0),
        evidence,
    }
}

/// `watchdog.gap`: hours since the previous watchdog run started,
/// `previous` being its `(created, url)`. The first run on record has no
/// predecessor and abstains.
fn watchdog_gap_reading(
    now: OffsetDateTime,
    previous: Option<(OffsetDateTime, &str)>,
    gap_hours: f64,
) -> Reading {
    let (sample, value, evidence) = match previous {
        Some((at, url)) => (
            1,
            age_hours(now, at),
            vec![format!(
                "previous {WATCHDOG_WORKFLOW} run started {} — {url}",
                format_time(at)
            )],
        ),
        None => (
            0,
            0.0,
            vec![format!("no earlier {WATCHDOG_WORKFLOW} run on record")],
        ),
    };
    Reading {
        signal: signal("watchdog.gap"),
        sample,
        value,
        threshold: Some(gap_hours),
        evidence,
    }
}

/// Hours between `at` and `now`; a stamp in the future (clock skew) is age zero.
fn age_hours(now: OffsetDateTime, at: OffsetDateTime) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let secs = (now - at).whole_seconds().max(0) as f64;
    secs / 3600.0
}

/// `pipeline.preheat_stale`: the age of the newest successful preheat
/// run, `latest` being its `(finished, url)`. No successful run at all
/// is an infinite age.
fn preheat_stale_reading(
    now: OffsetDateTime,
    latest: Option<(OffsetDateTime, &str)>,
    max_age_hours: f64,
) -> Reading {
    let (value, evidence) = match latest {
        Some((at, url)) => (
            age_hours(now, at),
            vec![format!(
                "last successful {PREHEAT_WORKFLOW} run finished {} — {url}",
                format_time(at)
            )],
        ),
        None => (
            f64::INFINITY,
            vec![format!(
                "no successful {PREHEAT_WORKFLOW} run in the repository's run history"
            )],
        ),
    };
    Reading {
        signal: signal("pipeline.preheat_stale"),
        sample: 1,
        value,
        threshold: Some(max_age_hours),
        evidence,
    }
}

/// What the scheduler's admin status says about dispatchable work.
#[derive(Debug, Clone, Copy)]
struct BuildQueue {
    /// Pending tasks dispatchable now (`AdminStatus::ready`).
    ready: u32,
    /// Tasks dispatched or running.
    in_flight: usize,
    /// The dispatch cap in force.
    cap: usize,
    /// The dispatch freeze is engaged — `edge.dispatch_frozen` owns that case.
    frozen: bool,
}

/// `pipeline.builds_stalled`: the sample is the ready count, so a queue
/// with nothing dispatchable abstains. With work ready, a free slot and
/// no freeze the value is the time since the newest `build-crate.yml`
/// run was created, `latest_run` being its `(created, url)`; no run at
/// all is an infinite wait. A full pool or an engaged freeze explains
/// the idle itself and reads zero.
fn builds_stalled_reading(
    now: OffsetDateTime,
    queue: &BuildQueue,
    latest_run: Option<(OffsetDateTime, &str)>,
    stall_hours: f64,
) -> Reading {
    let mut evidence = vec![
        format!("ready={}", queue.ready),
        format!("in_flight={}", queue.in_flight),
        format!("dispatch_cap={}", queue.cap),
    ];
    let value = if queue.frozen {
        evidence.push("dispatch freeze engaged — reported by edge.dispatch_frozen".to_owned());
        0.0
    } else if queue.in_flight >= queue.cap {
        evidence.push("every dispatch slot is in use".to_owned());
        0.0
    } else if let Some((at, url)) = latest_run {
        evidence.push(format!(
            "newest build-crate run created {} — {url}",
            format_time(at)
        ));
        age_hours(now, at)
    } else {
        evidence.push("no build-crate run in the repository's run history".to_owned());
        f64::INFINITY
    };
    Reading {
        signal: signal("pipeline.builds_stalled"),
        sample: u64::from(queue.ready),
        value,
        threshold: Some(stall_hours),
        evidence,
    }
}

/// The billed dimensions summed over a span of the month.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct MonthTotals {
    do_rows_read: f64,
    do_rows_written: f64,
    do_duration_gb_s: f64,
    do_requests: f64,
    worker_requests: f64,
    worker_cpu_ms: f64,
}

impl From<&CfSnapshot> for MonthTotals {
    fn from(snapshot: &CfSnapshot) -> Self {
        Self {
            do_rows_read: snapshot.do_periodic.rows_read,
            do_rows_written: snapshot.do_periodic.rows_written,
            do_duration_gb_s: snapshot.do_periodic.duration,
            do_requests: snapshot.do_invoke.requests,
            worker_requests: snapshot.worker.requests,
            worker_cpu_ms: snapshot.worker.cpu_time_us / 1000.0,
        }
    }
}

impl std::ops::Add for MonthTotals {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            do_rows_read: self.do_rows_read + other.do_rows_read,
            do_rows_written: self.do_rows_written + other.do_rows_written,
            do_duration_gb_s: self.do_duration_gb_s + other.do_duration_gb_s,
            do_requests: self.do_requests + other.do_requests,
            worker_requests: self.worker_requests + other.worker_requests,
            worker_cpu_ms: self.worker_cpu_ms + other.worker_cpu_ms,
        }
    }
}

/// The day-bounded `[since, until)` windows from the start of `now`'s
/// UTC calendar month to `now` — the billing-month anchor: the code
/// knows no account billing anchor, and Cloudflare's included
/// allowances are stated per month, so the UTC calendar month is the
/// month. The last window ends at `now`.
fn month_day_windows(now: OffsetDateTime) -> Result<Vec<(OffsetDateTime, OffsetDateTime)>, String> {
    let mut since = now
        .replace_day(1)
        .map_err(|error| error.to_string())?
        .replace_time(time::Time::MIDNIGHT);
    let mut windows = Vec::new();
    while since < now {
        let until = (since + time::Duration::days(1)).min(now);
        windows.push((since, until));
        since = until;
    }
    Ok(windows)
}

/// Hours in `now`'s UTC calendar month — the divisor of the hourly
/// pace.
fn hours_in_month(now: OffsetDateTime) -> f64 {
    f64::from(time::util::days_in_month(now.month(), now.year())) * 24.0
}

/// `now` minus `secs`, rendered the way SQL writes `datetime('now')` —
/// `YYYY-MM-DD HH:MM:SS` UTC, lexically comparable.
fn sqlite_now_minus(now: OffsetDateTime, secs: u64) -> String {
    let at = now - time::Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX));
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// RFC3339 UTC for GraphQL `Time`/`DateTime` filters.
fn format_time(at: OffsetDateTime) -> String {
    at.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// Classify one job log through `runs`' classifier.
fn classify_one(log: &str) -> &'static str {
    let (class, _) = runs::classify_log(log);
    class.as_str()
}

// ===== Cloudflare GraphQL wire types =====
//
// Dataset fields: the four datasets below are filtered on
// `datetime_geq`/`datetime_leq` (Time scalars). Every field was
// confirmed against the live schema by `__type` introspection on
// 2026-09-28 — the `workersInvocationsAdaptive` sum carries
// `clientDisconnects cpuTimeUs duration errors requestDuration requests
// responseBodySize subrequests wallTime`, the DO invocations sum
// `errors requests responseBodySize wallTime`, and the DO periodic
// sums match the uses below.

/// The watchdog's single GraphQL request — one POST covers every
/// dataset: DO periodic sums (usage + resource failures), DO invocations
/// (requests), Worker invocations over the hour (usage) and grouped by
/// invocation status over the last 15 minutes (health).
const WATCHDOG_QUERY: &str = include_str!("../queries/watchdog.graphql");

/// Query variables — account tag, Worker script name, and the two
/// window cutoffs (hour for usage, quarter-hour for health).
#[derive(Debug, serde::Serialize)]
struct QueryVars {
    #[serde(rename = "accountTag")]
    account_tag: String,
    #[serde(rename = "scriptName")]
    script_name: String,
    #[serde(rename = "sinceHour")]
    since_hour: String,
    #[serde(rename = "sinceQuarter")]
    since_quarter: String,
    now: String,
}

/// The day-bounded month-to-date usage query — see
/// [`Watcher::month_to_date`].
const WATCHDOG_MONTH_QUERY: &str = include_str!("../queries/watchdog_month.graphql");

/// Variables of [`WATCHDOG_MONTH_QUERY`].
#[derive(Debug, serde::Serialize)]
struct MonthQueryVars {
    #[serde(rename = "accountTag")]
    account_tag: String,
    #[serde(rename = "scriptName")]
    script_name: String,
    since: String,
    until: String,
}

/// The aliased groups of [`WATCHDOG_QUERY`] and [`WATCHDOG_MONTH_QUERY`].
#[derive(Debug, serde::Deserialize)]
struct AccountGroups {
    #[serde(rename = "doPeriodic", default)]
    do_periodic: Vec<DoPeriodicGroup>,
    #[serde(rename = "doInvoke", default)]
    do_invoke: Vec<DoInvokeGroup>,
    #[serde(default)]
    worker: Vec<WorkerGroup>,
    #[serde(rename = "workerStatus", default)]
    worker_status: Vec<WorkerStatusGroup>,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DoPeriodicSum {
    #[serde(default)]
    active_time: f64,
    #[serde(default)]
    cpu_time: f64,
    #[serde(default)]
    duration: f64,
    #[serde(default)]
    exceeded_cpu_errors: f64,
    #[serde(default)]
    exceeded_memory_errors: f64,
    #[serde(default)]
    fatal_internal_errors: f64,
    #[serde(default)]
    rows_read: f64,
    #[serde(default)]
    rows_written: f64,
    #[serde(default)]
    storage_deletes: f64,
    #[serde(default)]
    storage_read_units: f64,
    #[serde(default)]
    storage_write_units: f64,
    #[serde(default)]
    subrequests: f64,
}

#[derive(Debug, serde::Deserialize)]
struct DoPeriodicGroup {
    #[serde(default)]
    sum: DoPeriodicSum,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DoInvokeSum {
    #[serde(default)]
    requests: f64,
    #[serde(default)]
    wall_time: f64,
    #[serde(default)]
    errors: f64,
}

#[derive(Debug, serde::Deserialize)]
struct DoInvokeGroup {
    #[serde(default)]
    sum: DoInvokeSum,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct WorkerSum {
    #[serde(default)]
    client_disconnects: f64,
    #[serde(default)]
    cpu_time_us: f64,
    #[serde(default)]
    duration: f64,
    #[serde(default)]
    errors: f64,
    #[serde(default)]
    request_duration: f64,
    #[serde(default)]
    requests: f64,
    #[serde(default)]
    response_body_size: f64,
    #[serde(default)]
    subrequests: f64,
    #[serde(default)]
    wall_time: f64,
}

#[derive(Debug, serde::Deserialize)]
struct WorkerGroup {
    #[serde(default)]
    sum: WorkerSum,
}

#[derive(Debug, serde::Deserialize)]
struct WorkerStatusGroup {
    #[serde(default)]
    dimensions: WorkerStatusDimensions,
    #[serde(default)]
    sum: WorkerStatusSum,
}

#[derive(Debug, serde::Deserialize, Default)]
struct WorkerStatusDimensions {
    /// `workersInvocationsAdaptive.dimensions.status` — the invocation
    /// status enum (`success`, `clientDisconnected`,
    /// `scriptThrewException`, `exceededResources`, `internalError`).
    status: Option<String>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct WorkerStatusSum {
    #[serde(default)]
    requests: f64,
}

/// The decoded analytics snapshot the readings are built from — kept
/// whole so diagnostics (unbilled fields) reach the report.
#[derive(Debug, Default)]
struct CfSnapshot {
    do_periodic: DoPeriodicSum,
    do_invoke: DoInvokeSum,
    worker: WorkerSum,
    /// `(status, requests)` pairs from the status-grouped query.
    worker_status: Vec<(String, f64)>,
}

impl From<AccountGroups> for CfSnapshot {
    fn from(groups: AccountGroups) -> Self {
        let fold = |groups: Vec<DoPeriodicGroup>| {
            groups
                .iter()
                .fold(DoPeriodicSum::default(), |mut acc, group| {
                    acc.active_time += group.sum.active_time;
                    acc.cpu_time += group.sum.cpu_time;
                    acc.duration += group.sum.duration;
                    acc.exceeded_cpu_errors += group.sum.exceeded_cpu_errors;
                    acc.exceeded_memory_errors += group.sum.exceeded_memory_errors;
                    acc.fatal_internal_errors += group.sum.fatal_internal_errors;
                    acc.rows_read += group.sum.rows_read;
                    acc.rows_written += group.sum.rows_written;
                    acc.storage_deletes += group.sum.storage_deletes;
                    acc.storage_read_units += group.sum.storage_read_units;
                    acc.storage_write_units += group.sum.storage_write_units;
                    acc.subrequests += group.sum.subrequests;
                    acc
                })
        };
        let do_invoke = groups
            .do_invoke
            .iter()
            .fold(DoInvokeSum::default(), |mut acc, group| {
                acc.requests += group.sum.requests;
                acc.wall_time += group.sum.wall_time;
                acc.errors += group.sum.errors;
                acc
            });
        let worker = groups
            .worker
            .iter()
            .fold(WorkerSum::default(), |mut acc, group| {
                acc.client_disconnects += group.sum.client_disconnects;
                acc.cpu_time_us += group.sum.cpu_time_us;
                acc.duration += group.sum.duration;
                acc.errors += group.sum.errors;
                acc.request_duration += group.sum.request_duration;
                acc.requests += group.sum.requests;
                acc.response_body_size += group.sum.response_body_size;
                acc.subrequests += group.sum.subrequests;
                acc.wall_time += group.sum.wall_time;
                acc
            });
        let worker_status = groups
            .worker_status
            .iter()
            .filter_map(|group| {
                group
                    .dimensions
                    .status
                    .clone()
                    .map(|status| (status, group.sum.requests))
            })
            .collect();
        Self {
            do_periodic: fold(groups.do_periodic),
            do_invoke,
            worker,
            worker_status,
        }
    }
}

/// The month-to-date trip reading of one billed dimension.
fn month_reading(id: &str, allowance: f64, total: f64) -> Reading {
    let line = allowance * ALLOWANCE_FRACTION;
    Reading {
        signal: signal(id),
        sample: 1,
        value: total,
        threshold: None,
        evidence: vec![format!(
            "{:.1}% of the 80% line this UTC month ({:.1}% of the allowance)",
            total / line * 100.0,
            total / allowance * 100.0
        )],
    }
}

/// The hourly-pace alert reading of one billed dimension: the last
/// hour's usage against the highest operator level it crossed, or the
/// lowest level while it crossed none. The hourly pace is the
/// allowance over the hours of the current month.
fn hourly_reading(
    id: &str,
    allowance: f64,
    hours: f64,
    last_hour: f64,
    levels: &HourlyAlertLevels,
    context: String,
) -> Reading {
    let pace = allowance / hours;
    let percent = last_hour / pace * 100.0;
    let level = levels
        .0
        .iter()
        .copied()
        .rfind(|level| percent >= *level)
        .or_else(|| levels.0.first().copied())
        .expect("hourly alert levels are never empty");
    let mut evidence = vec![format!(
        "{percent:.0}% of the hourly pace ({pace:.0} per hour); alert level {level}%"
    )];
    if !context.is_empty() {
        evidence.push(context);
    }
    Reading {
        signal: signal(&format!("{id}.hourly")),
        sample: 1,
        value: last_hour,
        threshold: Some(pace * level / 100.0),
        evidence,
    }
}

/// Invocation statuses that mean the Worker failed the request.
const WORKER_BAD_STATUSES: &[&str] =
    &["scriptThrewException", "internalError", "exceededResources"];

impl CfSnapshot {
    /// Expand the last-hour snapshot and the month-to-date totals into
    /// the run's Cloudflare readings — the month's billed usage as
    /// trips, the last hour's pace and health as alerts, unbilled
    /// diagnostics as evidence on the readings that fire.
    #[allow(clippy::too_many_lines)]
    fn readings(
        &self,
        month: &MonthTotals,
        hourly: &HourlyAlertLevels,
        now: OffsetDateTime,
    ) -> Vec<Reading> {
        let hours = hours_in_month(now);
        let dimensions = [
            (
                "cf.do.rows_read",
                DO_ROWS_READ_MONTHLY,
                month.do_rows_read,
                self.do_periodic.rows_read,
                String::new(),
            ),
            (
                "cf.do.rows_written",
                DO_ROWS_WRITTEN_MONTHLY,
                month.do_rows_written,
                self.do_periodic.rows_written,
                String::new(),
            ),
            (
                "cf.do.duration_gb_s",
                DO_DURATION_GB_S_MONTHLY,
                month.do_duration_gb_s,
                self.do_periodic.duration,
                format!(
                    "activeTime={:.0} cpuTime={:.0} storage: read_units={:.0} write_units={:.0} deletes={:.0} (unbilled context)",
                    self.do_periodic.active_time,
                    self.do_periodic.cpu_time,
                    self.do_periodic.storage_read_units,
                    self.do_periodic.storage_write_units,
                    self.do_periodic.storage_deletes,
                ),
            ),
            (
                "cf.do.requests",
                DO_REQUESTS_MONTHLY,
                month.do_requests,
                self.do_invoke.requests,
                format!(
                    "wallTime={:.0} errors={:.0} subrequests={:.0}",
                    self.do_invoke.wall_time, self.do_invoke.errors, self.do_periodic.subrequests,
                ),
            ),
            (
                "cf.worker.requests",
                WORKER_REQUESTS_MONTHLY,
                month.worker_requests,
                self.worker.requests,
                format!(
                    "subrequests={:.0} (not billed per Workers pricing)",
                    self.worker.subrequests
                ),
            ),
            (
                "cf.worker.cpu_ms",
                WORKER_CPU_MS_MONTHLY,
                month.worker_cpu_ms,
                self.worker.cpu_time_us / 1000.0,
                format!("errors={:.0}", self.worker.errors),
            ),
        ];
        let mut usage = Vec::new();
        for (id, allowance, month_total, last_hour, context) in dimensions {
            usage.push(month_reading(id, allowance, month_total));
            usage.push(hourly_reading(
                id, allowance, hours, last_hour, hourly, context,
            ));
        }
        usage.extend(self.health_readings());
        usage
    }

    /// The DO/Worker health alerts over the last 15 minutes and hour.
    fn health_readings(&self) -> Vec<Reading> {
        let do_exceeded = self.do_periodic.exceeded_cpu_errors
            + self.do_periodic.exceeded_memory_errors
            + self.do_periodic.fatal_internal_errors;
        let total_requests: f64 = self.worker_status.iter().map(|(_, n)| n).sum();
        let bad_requests: f64 = self
            .worker_status
            .iter()
            .filter(|(status, _)| WORKER_BAD_STATUSES.contains(&status.as_str()))
            .map(|(_, n)| n)
            .sum();
        let exceeded_requests: f64 = self
            .worker_status
            .iter()
            .filter(|(status, _)| matches!(status.as_str(), "exceededResources" | "internalError"))
            .map(|(_, n)| n)
            .sum();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let request_sample = total_requests as u64;
        #[allow(clippy::cast_precision_loss)]
        let error_share = if total_requests <= 0.0 {
            0.0
        } else {
            bad_requests / total_requests * 100.0
        };
        let status_evidence = self
            .worker_status
            .iter()
            .map(|(status, n)| format!("{status}={n:.0}"))
            .collect::<Vec<_>>()
            .join(" ");
        vec![
            Reading {
                signal: signal("edge.worker.errors"),
                threshold: None,
                sample: request_sample,
                value: error_share,
                evidence: vec![status_evidence.clone()],
            },
            Reading {
                signal: signal("edge.worker.exceeded"),
                threshold: None,
                sample: request_sample,
                value: exceeded_requests,
                evidence: vec![status_evidence],
            },
            Reading {
                signal: signal("edge.do.exceeded"),
                threshold: None,
                sample: 1,
                value: do_exceeded,
                evidence: vec![format!(
                    "exceededCpu={:.0} exceededMemory={:.0} fatalInternal={:.0}",
                    self.do_periodic.exceeded_cpu_errors,
                    self.do_periodic.exceeded_memory_errors,
                    self.do_periodic.fatal_internal_errors,
                )],
            },
        ]
    }
}

// ----- Analytics Engine wire -----

#[derive(Debug, serde::Deserialize)]
struct AnalyticsRow {
    // `sumIf(_sample_interval * double1, …)` is a Float64 — a plain
    // JSON number (the quoted form is accepted too).
    #[serde(default, deserialize_with = "analytics::de_f64")]
    events: f64,
    /// `count()` over the window — the liveness probe; `UInt64` arrives
    /// quoted on the wire.
    #[serde(default, deserialize_with = "analytics::de_u64")]
    points: u64,
}

// ----- GitHub wire types -----

#[derive(Debug, serde::Deserialize)]
struct GhRun {
    id: u64,
    html_url: String,
    #[serde(default)]
    conclusion: Option<String>,
    /// The run's latest attempt — GitHub answers it on every workflow
    /// run row, and the jobs read is scoped to it (stow#852).
    run_attempt: u64,
}

impl github::RunRow for GhRun {
    fn run_id(&self) -> u64 {
        self.id
    }
}

/// The two timestamps of a workflow-run row the liveness signals read.
#[derive(Debug, serde::Deserialize)]
struct GhRunStamp {
    id: u64,
    html_url: String,
    /// The run-name (`operations.yml` sets one carrying its argv); the
    /// workflow's name otherwise.
    #[serde(default)]
    display_title: String,
    /// `success`, `failure`, … once completed.
    #[serde(default)]
    conclusion: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl github::RunRow for GhRunStamp {
    fn run_id(&self) -> u64 {
        self.id
    }
}

/// The newest run (by creation) of `workflow` under `filters`
/// (`&status=success`), or `None` when it has none. One REST read.
async fn latest_run(
    gh_token: &str,
    workflow: &str,
    filters: &str,
) -> Result<Option<GhRunStamp>, String> {
    Ok(recent_runs(gh_token, workflow, filters, 1)
        .await?
        .into_iter()
        .next())
}

/// The newest `per_page` runs (by creation) of `workflow` under
/// `filters`, newest first. One REST read.
async fn recent_runs(
    gh_token: &str,
    workflow: &str,
    filters: &str,
    per_page: u32,
) -> Result<Vec<GhRunStamp>, String> {
    let page: github::RunsPage<GhRunStamp> = github::get(
        gh_token,
        &format!("actions/workflows/{workflow}/runs?per_page={per_page}{filters}"),
        Backoff::new(),
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(page.workflow_runs)
}

#[derive(Debug, serde::Deserialize)]
pub struct GhIssue {
    /// The issue number.
    pub number: u64,
    /// The issue title.
    pub title: String,
    /// Browser URL.
    pub html_url: String,
    /// The issue body — the disabled-workflow record (the
    /// `stow-watchdog:disabled` marker) lives here (stow#744).
    #[serde(default)]
    pub body: Option<String>,
    /// Present on pull requests — `…/issues` returns both; PRs are not
    /// incidents.
    #[serde(default)]
    pub pull_request: Option<serde_json::Value>,
}

/// `GET /actions/workflows/{file}`'s answer — `state` is the only field
/// the trip reads (`active`, `disabled_manually`, `disabled_inactivity`,
/// …): only `active` earns a disable.
#[derive(Debug, serde::Deserialize)]
struct GhWorkflow {
    state: String,
}

#[derive(Debug, serde::Deserialize)]
struct GhComment {
    created_at: String,
    #[serde(default)]
    body: Option<String>,
}

/// Every `completed` build-crate run in the closed window `[since, now]`
/// — both outcomes, since the task share needs the denominator: range
/// enumeration reads past GitHub's 1000-row listing cap so a dense wave
/// cannot silently shrink the denominator (stow#555).
async fn fetch_completed_runs(gh_token: &str, since: OffsetDateTime) -> Result<Vec<GhRun>, String> {
    github::runs_in_range(
        github::BUILD_WORKFLOW,
        "status=completed",
        since,
        OffsetDateTime::now_utc(),
        |path| async move {
            github::get::<github::RunsPage<GhRun>>(gh_token, &path, Backoff::new()).await
        },
    )
    .await
    .map_err(|error| error.to_string())
}

// ===== Actuation =====

/// The whole apply step of a breach: every attempted action lands in
/// `actions` as a line; every failed actuation or notification lands in
/// `failures` — the watchdog's own failures, which exit non-zero.
#[derive(Debug, Default)]
struct ApplyOutcome {
    actions: Vec<String>,
    failures: Vec<String>,
    incident_url: Option<String>,
    mailed: bool,
}

/// One trip workflow's state read — the name and what the GET answered.
struct TripState {
    workflow: &'static str,
    state: Result<String, String>,
}

/// Read every trip workflow's `state` at once — the list is a fixed
/// six, so `join_all` over it is the whole bound.
async fn read_trip_states(gh_token: &str) -> Vec<TripState> {
    let reads = TRIP_WORKFLOWS.iter().map(|workflow| async move {
        let state = github::get::<GhWorkflow>(
            gh_token,
            &format!("actions/workflows/{workflow}"),
            Backoff::new(),
        )
        .await
        .map(|body| body.state)
        .map_err(|error| error.to_string());
        TripState { workflow, state }
    });
    futures_util::future::join_all(reads).await
}

/// The trip's selection, pure for tests: the set to disable is exactly
/// the workflows that read `active` — the same set the incident marker
/// records for `clear` to restore (stow#744). A failed read names the
/// workflow and leaves it alone: the record can only promise restores
/// for workflows whose prior state is known.
fn select_trip_set(reads: &[TripState]) -> (BTreeSet<String>, Vec<String>) {
    let mut active = BTreeSet::new();
    let mut failures = Vec::new();
    for read in reads {
        match &read.state {
            Ok(state) if state == "active" => {
                active.insert(read.workflow.to_owned());
            }
            Ok(_) => {}
            Err(error) => failures.push(format!("read {} state: {error}", read.workflow)),
        }
    }
    (active, failures)
}

/// Trip the breaker: disable every dispatching workflow that reads
/// `active` — the returned set is the trip's record, which the incident
/// issue carries for `clear` to restore — then enable the
/// zone's WAF rule for `scope`, the widest scope of the breaching
/// signals — the shed happens in the
/// security phase, before the Worker, so a broken edge cannot keep the
/// breaker open. Both kinds of failure are collected — one failed disable
/// never skips the rule enable. A workflow whose disable write failed
/// stays in the record regardless: it read `active`, so enabling it is
/// always the right restore.
async fn apply_trip(
    watcher: &Watcher<'_>,
    scope: MaintenanceScope,
    outcome: &mut ApplyOutcome,
) -> BTreeSet<String> {
    let (disabled, read_failures) = select_trip_set(&read_trip_states(watcher.gh_token).await);
    outcome.failures.extend(read_failures);
    let writes = disabled.iter().map(|workflow| async move {
        let result = github::put(
            watcher.gh_token,
            &format!("actions/workflows/{workflow}/disable"),
        )
        .await;
        (workflow, result)
    });
    for (workflow, result) in futures_util::future::join_all(writes).await {
        match result {
            Ok(()) => outcome.actions.push(format!("disabled {workflow}")),
            Err(error) => outcome
                .failures
                .push(format!("disable {workflow}: {error}")),
        }
    }
    match maintenance::set_scope(watcher.cf_token, watcher.zone, scope, true, watcher.host).await {
        Ok(_) => outcome.actions.push(format!(
            "maintenance rule `{}` enabled",
            scope.description()
        )),
        Err(error) => outcome
            .failures
            .push(format!("enable maintenance rule: {error}")),
    }
    disabled
}

/// Lift the breaker — `watchdog clear`'s actuation half. The workflows
/// re-enabled are exactly the incident's recorded set; every other trip
/// workflow keeps whatever state it has, and the report says so
/// (stow#744).
async fn apply_clear(
    watcher: &Watcher<'_>,
    restore: &BTreeSet<String>,
    outcome: &mut ApplyOutcome,
) {
    // Each scope is its own rule, patched by id, so the lifts are independent.
    let lifts = TRIP_SCOPES.map(|scope| async move {
        let result =
            maintenance::set_scope(watcher.cf_token, watcher.zone, scope, false, watcher.host)
                .await;
        (scope, result)
    });
    for (scope, result) in futures_util::future::join_all(lifts).await {
        match result {
            Ok(_) => outcome.actions.push(format!(
                "maintenance rule `{}` disabled",
                scope.description()
            )),
            Err(error) => outcome.failures.push(format!(
                "disable maintenance rule `{}`: {error}",
                scope.description()
            )),
        }
    }
    let enables = restore.iter().map(|workflow| async move {
        let result = github::put(
            watcher.gh_token,
            &format!("actions/workflows/{workflow}/enable"),
        )
        .await;
        (workflow, result)
    });
    for (workflow, result) in futures_util::future::join_all(enables).await {
        match result {
            Ok(()) => outcome.actions.push(format!("enabled {workflow}")),
            Err(error) => outcome.failures.push(format!("enable {workflow}: {error}")),
        }
    }
    for workflow in TRIP_WORKFLOWS {
        if !restore.contains(*workflow) {
            outcome.actions.push(format!("left {workflow} untouched"));
        }
    }
}

// ===== The incident issue =====

pub const INCIDENT_LABEL: &str = "incident";
/// Stable title prefix — dedup keys on it together with the label.
const INCIDENT_TITLE_PREFIX: &str = "stow incident:";
/// HTML marker stamped on digest comments so cadence is derivable.
const DIGEST_MARKER: &str = "<!-- stow-watchdog:update -->";
const CLEAR_MARKER: &str = "<!-- stow-watchdog:clear -->";
/// The machine-readable trip record on the incident body —
/// `watchdog/incident.md` renders it as
/// `<!-- stow-watchdog:disabled a.yml,b.yml -->`; `watchdog clear`
/// restores exactly the set it names (stow#744).
const DISABLED_MARKER: &str = "<!-- stow-watchdog:disabled";
/// Digest cadence — at most one comment an hour while open.
const DIGEST_PERIOD_SECS: i64 = 3600;

/// Alert addresses — the verified Email Sending pair.
const ALERT_FROM: &str = "alerts@stow.waterui.dev";
const ALERT_TO: &str = "me@lexo.cool";

/// Find the open incident — the issue carrying `incident` whose title
/// starts with the stable prefix. There is at most one; a duplicate is
/// impossible because creation goes through this lookup.
async fn find_incident(gh_token: &str) -> Result<Option<GhIssue>, String> {
    let issues: Vec<GhIssue> = github::get(
        gh_token,
        &format!("issues?labels={INCIDENT_LABEL}&state=open&per_page=100"),
        Backoff::new(),
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(issues.into_iter().find(|issue| {
        issue.pull_request.is_none() && issue.title.starts_with(INCIDENT_TITLE_PREFIX)
    }))
}

/// Parse the [`DISABLED_MARKER`] set out of an incident issue body:
/// `Ok(None)` when the body carries no marker — nothing was recorded,
/// so nothing is restored; `Ok(Some(set))`
/// for the recorded set, empty included; `Err` when a marker is present
/// but does not parse. `issue` only names the record in the error.
fn parse_disabled_marker(issue: u64, body: &str) -> Result<Option<BTreeSet<String>>, String> {
    let Some(at) = body.find(DISABLED_MARKER) else {
        return Ok(None);
    };
    let tail = &body[at + DISABLED_MARKER.len()..];
    // The key ends at a word boundary — a comment whose key merely
    // starts with `disabled` is not the record.
    if !tail.starts_with(' ') && !tail.starts_with("-->") {
        return Ok(None);
    }
    let Some(end) = tail.find("-->") else {
        return Err(format!(
            "incident #{issue}: unterminated `{DISABLED_MARKER}` marker"
        ));
    };
    let payload = tail[..end].trim();
    let mut set = BTreeSet::new();
    if payload.is_empty() {
        return Ok(Some(set));
    }
    for entry in payload.split(',') {
        let name = entry.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(format!(
                "incident #{issue}: malformed entry {entry:?} in the `{DISABLED_MARKER}` marker"
            ));
        }
        set.insert(name.to_owned());
    }
    Ok(Some(set))
}

/// What `watchdog clear` re-enables, decided by the open incident's
/// record — every variant but `Set` enables nothing (stow#744).
enum RestoreSet {
    /// No open incident exists.
    NoIncident,
    /// The open incident's body has no marker — nothing was recorded,
    /// so nothing is restored.
    NoRecord(u64),
    /// The marker is present but does not parse — the recorded set is
    /// unknowable, so nothing is enabled and the error is reported.
    Malformed(String),
    /// Exactly this set returns to `active`.
    Set(BTreeSet<String>),
}

/// `clear`'s restore decision from the open incident.
fn clear_restore(incident: Option<&GhIssue>) -> RestoreSet {
    let Some(issue) = incident else {
        return RestoreSet::NoIncident;
    };
    match parse_disabled_marker(issue.number, issue.body.as_deref().unwrap_or_default()) {
        Ok(Some(set)) => RestoreSet::Set(set),
        Ok(None) => RestoreSet::NoRecord(issue.number),
        Err(error) => RestoreSet::Malformed(error),
    }
}

/// Is `error` the typed `zenwave::Error::Http` carrying `code`? Other
/// kinds — transport, URI, decode — carry no status.
const fn is_http_status(error: &zenwave::Error, code: u16) -> bool {
    matches!(error, zenwave::Error::Http { status, .. } if status.as_u16() == code)
}

/// The named label's GET body — `name` is the only field read.
#[derive(Debug, serde::Deserialize)]
struct NamedLabel {
    name: String,
}

/// GitHub's structured 422 body — each row names the resource, field
/// and rule it rejected.
#[derive(Debug, serde::Deserialize)]
struct LabelValidationError {
    errors: Vec<LabelValidationRow>,
}

#[derive(Debug, serde::Deserialize)]
struct LabelValidationRow {
    resource: String,
    field: String,
    code: String,
}

/// The concurrent-create win — a 422 whose validation body names only
/// `Label`/`name`/`already_exists` rows. A malformed body, other codes
/// or mixed rows are not a race: they stay failures.
fn is_duplicate_label_conflict(error: &zenwave::Error) -> bool {
    if !is_http_status(error, 422) {
        return false;
    }
    let Some(validation) = error.deserialize_http_error::<LabelValidationError>() else {
        return false;
    };
    !validation.errors.is_empty()
        && validation.errors.iter().all(|row| {
            row.resource == "Label" && row.field == "name" && row.code == "already_exists"
        })
}

/// Ensure the `incident` label exists without mutating it when present.
/// `GET /labels/{name}` answers first — a 200 costs one named lookup
/// and no POST; the typed `Error::Http` 404 is the only normal missing
/// case and falls through to one bounded `POST /labels`. zenwave lifts
/// 4xx/5xx into `Err(Error::Http)` at `.await`, so every status read
/// happens on the error, never on a response branch that cannot run.
/// A 200 names a different entity → hard failure. The POST accepts 201;
/// a racing create answers 422, success only via
/// [`is_duplicate_label_conflict`]. A rate-limited answer waits out
/// the reset it names and resends, like every operator-token path.
/// Everything else — auth, transport, server and validation failures —
/// propagates. `request_timeout` bounds each whole read — send, status,
/// body decode, and any rate-limit wait — so a stalled body or a far
/// reset cannot outlive it.
pub async fn ensure_label(
    api_base: &str,
    gh_token: &str,
    request_timeout: std::time::Duration,
) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct NewLabel {
        name: &'static str,
        color: &'static str,
        description: &'static str,
    }
    let label = NewLabel {
        name: INCIDENT_LABEL,
        color: "B60205",
        description: "stow watchdog incident — one open issue per incident",
    };
    let get_url = format!("{api_base}/repos/{}/labels/{INCIDENT_LABEL}", github::REPO);
    // The shared read path — transient retries and the rate-limit waits
    // `send_get` holds — under the same whole-read deadline: a reset
    // that outlasts the bound surfaces as the timeout rather than
    // hanging the mail that follows.
    let found = tokio::time::timeout(request_timeout, {
        let url = get_url.clone();
        async move {
            let response = match github::send_get(
                Some(gh_token),
                &url,
                Some("application/vnd.github+json"),
                None,
                Backoff::new(),
            )
            .await
            {
                // A backend that delivers 4xx/5xx as `Ok` meets the same
                // gate: `error_for_status` lifts it into the `Err` arm.
                Ok(response) => response.error_for_status().await,
                Err(error) => Err(error),
            };
            match response {
                Ok(response) => response
                    .into_json::<NamedLabel>()
                    .await
                    .map(Some)
                    .map_err(|error| format!("GET {url}: {error}")),
                Err(error) if is_http_status(&error, 404) => Ok(None),
                Err(error) => Err(format!("GET {url}: {error}")),
            }
        }
    })
    .await
    .map_err(|_| format!("GET {get_url}: timed out"))??;
    if let Some(found) = found {
        return if found.name == INCIDENT_LABEL {
            Ok(())
        } else {
            Err(format!(
                "GET {get_url}: label `{}` is not `{INCIDENT_LABEL}`",
                found.name
            ))
        };
    }

    let post_url = format!("{api_base}/repos/{}/labels", github::REPO);
    // Same whole-read bound: `error_for_status` reads the error body
    // where a backend delivers non-2xx on `Ok`, so it lives inside the
    // deadline too; the 422 check's `body_text` arrives inside
    // `Error::Http` and needs no further read. A rate-limited answer is
    // the write settled as not-happened — the wait it names is slept
    // and the ask rebuilt and resent, inside the same deadline. The
    // block answers `Some(response)` for a live response and `None`
    // when the duplicate-label race already achieved the end state.
    let created = tokio::time::timeout(request_timeout, async {
        loop {
            let mut client = zenwave::client();
            let request = client
                .post(&post_url)
                .and_then(|request| {
                    request.header("Authorization", format!("Bearer {gh_token}"))
                })
                .and_then(|request| request.header("User-Agent", github::USER_AGENT))
                .and_then(|request| request.header("Accept", "application/vnd.github+json"))
                .and_then(|request| request.json_body(&label))
                .map_err(|error| format!("POST {post_url}: {error}"))?;
            let outcome = match request.await {
                Ok(response) => response.error_for_status().await,
                Err(error) => Err(error),
            };
            let error = match outcome {
                Ok(response) => break Ok(Some(response)),
                Err(error) => error,
            };
            if is_duplicate_label_conflict(&error) {
                break Ok(None);
            }
            match github::classify_write(&format!("POST {post_url}"), &error) {
                github::WriteFailure::RateLimited { hint: Some(wait), .. } => {
                    tracing::warn!(url = %post_url, wait = ?wait, "rate-limited; waiting for the reset");
                    tokio::time::sleep(wait).await;
                }
                failure => break Err(failure.to_string()),
            }
        }
    })
    .await
    .map_err(|_| format!("POST {post_url}: timed out"))??;
    created.map_or(Ok(()), |created| {
        if created.status() == zenwave::StatusCode::CREATED {
            Ok(())
        } else {
            Err(format!(
                "POST {post_url}: unexpected status {}",
                created.status()
            ))
        }
    })
}

/// `digest_due` — is it an hour or more since the last watchdog comment?
fn digest_due(last: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
    last.is_none_or(|at| (now - at) >= time::Duration::seconds(DIGEST_PERIOD_SECS))
}

/// Newest digest comment time on the issue.
async fn last_digest_at(gh_token: &str, issue: u64) -> Result<Option<OffsetDateTime>, String> {
    let comments: Vec<GhComment> = github::get(
        gh_token,
        &format!("issues/{issue}/comments?per_page=100"),
        Backoff::new(),
    )
    .await
    .map_err(|error| error.to_string())?;
    let mut latest = None;
    for comment in &comments {
        let body = comment.body.as_deref().unwrap_or_default();
        if !(body.contains(DIGEST_MARKER) || body.contains(CLEAR_MARKER)) {
            continue;
        }
        if let Ok(at) = OffsetDateTime::parse(&comment.created_at, &Rfc3339) {
            latest = latest.max(Some(at));
        }
    }
    Ok(latest)
}

/// Render the incident title via askama.
fn incident_title(primary: &str, extra: usize) -> String {
    #[derive(Template)]
    #[template(path = "watchdog/title.txt")]
    struct TitleTemplate<'a> {
        primary: &'a str,
        extra: usize,
    }
    TitleTemplate { primary, extra }
        .render()
        .unwrap_or_else(|_| format!("{INCIDENT_TITLE_PREFIX} {primary}"))
}

/// Askama context for the incident body / digest / cleared views.
#[derive(Template)]
#[template(path = "watchdog/incident.md")]
struct IncidentTemplate<'a> {
    now: &'a str,
    dry_run: bool,
    /// Every breaching signal, rendered.
    breaches: &'a [BreachView<'a>],
    /// What the trip applied (or would apply).
    actions: &'a [String],
    /// Collector and actuation failures — the watchdog's own failures.
    failures: &'a [String],
    /// The union of every workflow the incident's trips disabled —
    /// rendered as the `disabled` marker `clear` restores from.
    disabled: &'a BTreeSet<String>,
}

/// One signal's breach, template-shaped.
struct BreachView<'a> {
    id: &'static str,
    label: &'static str,
    effect: &'static str,
    window: String,
    observed: String,
    threshold: String,
    evidence: &'a [String],
}

/// Render a human threshold/observed number — `34.7M`, `2.0%`-style
/// compact forms so the issue table stays readable.
///
/// `float_cmp` is allowed: the integral check chooses `42` over
/// `42.0` — exact equality is the intent, not an approximation.
#[allow(clippy::float_cmp)]
fn fmt_value(value: f64, unit: &str) -> String {
    if !value.is_finite() {
        return "never".to_owned();
    }
    let scaled = [(1e12, "T"), (1e9, "G"), (1e6, "M"), (1e3, "k")];
    for (divisor, suffix) in scaled {
        if value.abs() >= divisor {
            return format!("{:.1}{suffix} {unit}", value / divisor);
        }
    }
    if value == value.trunc() {
        format!("{value:.0} {unit}")
    } else {
        format!("{value:.1} {unit}")
    }
}

/// `Reading` → `BreachView`.
fn breach_view(reading: &Reading) -> BreachView<'_> {
    let window = match reading.signal.window {
        Window::Now => "now".to_owned(),
        Window::MonthToDate => "month".to_owned(),
        Window::Last(secs) if secs.is_multiple_of(3600) => format!("{}h", secs / 3600),
        Window::Last(secs) => format!("{}m", secs / 60),
    };
    BreachView {
        id: reading.signal.id,
        label: reading.signal.label,
        effect: match reading.signal.effect {
            Effect::Trip(_) => "trip",
            Effect::Alert => "alert",
        },
        window,
        observed: fmt_value(reading.value, reading.signal.unit),
        threshold: fmt_value(reading.threshold(), reading.signal.unit),
        evidence: &reading.evidence,
    }
}

#[derive(Template)]
#[template(path = "watchdog/digest.md")]
struct DigestTemplate<'a> {
    now: &'a str,
    breaches: &'a [BreachView<'a>],
    failures: &'a [String],
    actions: &'a [String],
}

#[derive(Template)]
#[template(path = "watchdog/cleared.md")]
struct ClearedTemplate<'a> {
    now: &'a str,
    /// What `clear` applied.
    actions: &'a [String],
}

// ===== Email =====

/// The REST send call's request body.
#[derive(Debug, serde::Serialize)]
struct MailBody<'a> {
    to: &'a str,
    from: &'a str,
    subject: &'a str,
    text: &'a str,
    html: &'a str,
}

/// Email Sending's answer — `{success, errors, result:{…}}`. A non-empty
/// `permanent_bounces` or `suppressed_recipients` is a delivery failure.
#[derive(Debug, serde::Deserialize)]
struct MailResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
    #[serde(default)]
    result: Option<MailResult>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct MailResult {
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    permanent_bounces: Vec<serde_json::Value>,
    #[serde(default)]
    suppressed_recipients: Vec<serde_json::Value>,
}

/// Which mail a run sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MailKind {
    /// Incident opened.
    Open,
    /// The ≤1/h digest while it stays open.
    Digest,
    /// Signals cleared or `watchdog clear` ran.
    Cleared,
    /// The watchdog's own failure — an unreadable signal, a failed
    /// actuation or notification.
    Failure,
}

/// Render the mail text+html via askama.
fn render_mail(
    kind: MailKind,
    breaches: &[BreachView<'_>],
    actions: &[String],
    failures: &[String],
    issue_url: Option<&str>,
    now: &str,
) -> Result<(String, String, String), askama::Error> {
    let kind_text = match kind {
        MailKind::Open => "incident opened",
        MailKind::Digest => "incident digest",
        MailKind::Cleared => "incident cleared",
        MailKind::Failure => "watchdog failure",
    };
    let primary = breaches.first().map_or("watchdog", |b| b.id);
    let subject = SubjectTemplate {
        kind: kind_text,
        primary,
    }
    .render()?;
    let text = MailTextTemplate {
        kind: kind_text,
        now,
        breaches,
        actions,
        failures,
        issue_url,
    }
    .render()?;
    let html = MailHtmlTemplate {
        kind: kind_text,
        now,
        breaches,
        actions,
        failures,
        issue_url,
    }
    .render()?;
    Ok((subject, text, html))
}

/// Mail subject line — `mail_subject.txt`.
#[derive(Template)]
#[template(path = "watchdog/mail_subject.txt")]
struct SubjectTemplate<'a> {
    kind: &'a str,
    primary: &'a str,
}

/// Mail plain-text body — `mail.txt`.
#[derive(Template)]
#[template(path = "watchdog/mail.txt")]
struct MailTextTemplate<'a> {
    kind: &'a str,
    now: &'a str,
    breaches: &'a [BreachView<'a>],
    actions: &'a [String],
    failures: &'a [String],
    issue_url: Option<&'a str>,
}

/// Mail HTML body — `mail.html`.
#[derive(Template)]
#[template(path = "watchdog/mail.html")]
struct MailHtmlTemplate<'a> {
    kind: &'a str,
    now: &'a str,
    breaches: &'a [BreachView<'a>],
    actions: &'a [String],
    failures: &'a [String],
    issue_url: Option<&'a str>,
}

/// `POST …/email/sending/send` — one alert mail. Non-success, any
/// `errors` entry, or a bounce/suppression is a send failure. Returns
/// the accepted `message_id` for the action log.
async fn send_mail(
    cf_token: &str,
    account: &str,
    subject: &str,
    text: &str,
    html: &str,
) -> Result<Option<String>, String> {
    let url = format!("{API_BASE}/accounts/{account}/email/sending/send");
    let body = MailBody {
        to: ALERT_TO,
        from: ALERT_FROM,
        subject,
        text,
        html,
    };
    let mut client = zenwave::client().timeout(std::time::Duration::from_secs(30));
    let response = client
        .post(&url)
        .and_then(|request| request.header("Authorization", format!("Bearer {cf_token}")))
        .and_then(|request| request.json_body(&body))
        .map_err(|error| format!("POST {url}: {error}"))?
        .await
        .map_err(|error| format!("POST {url}: {error}"))?;
    let envelope: MailResponse = response
        .into_json()
        .await
        .map_err(|error| format!("decode {url}: {error}"))?;
    if !envelope.success {
        return Err(format!("mail send rejected: {:?}", envelope.errors));
    }
    if !envelope.errors.is_empty() {
        return Err(format!("mail send errors: {:?}", envelope.errors));
    }
    if let Some(result) = &envelope.result {
        if !result.permanent_bounces.is_empty() {
            return Err(format!("permanent bounces: {:?}", result.permanent_bounces));
        }
        if !result.suppressed_recipients.is_empty() {
            return Err(format!(
                "suppressed recipients: {:?}",
                result.suppressed_recipients
            ));
        }
        return Ok(result.message_id.clone());
    }
    Ok(None)
}

// ===== The two modes =====

/// The serialized run report — `--json` and the table view share it.
/// The four bools are the report's serialized state, not a hidden
/// state machine.
#[derive(Debug, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct WatchdogReport {
    dry_run: bool,
    /// Any breaching or unreadable signal.
    incident: bool,
    /// A `Trip` signal breached — the breaker moved.
    tripped: bool,
    signals: Vec<SignalReport>,
    failures: Vec<CollectFailure>,
    /// Every action applied (or planned under `--dry-run`).
    actions: Vec<String>,
    /// Notification/action failures — these make the run itself fail.
    own_failures: Vec<String>,
    incident_url: Option<String>,
    mailed: bool,
}

#[derive(Debug, serde::Serialize)]
struct SignalReport {
    id: &'static str,
    effect: &'static str,
    verdict: &'static str,
    sample: u64,
    observed: String,
    threshold: String,
    window: String,
    evidence: Vec<String>,
}

fn signal_report(reading: &Reading) -> SignalReport {
    let view = breach_view(reading);
    SignalReport {
        id: view.id,
        effect: view.effect,
        verdict: match verdict(reading) {
            Verdict::Skipped => "skipped",
            Verdict::Clear => "clear",
            Verdict::Breach => "breach",
        },
        sample: reading.sample,
        observed: view.observed,
        threshold: view.threshold,
        window: view.window,
        evidence: reading.evidence.clone(),
    }
}

/// `stow-admin watchdog` — collect, decide, act, notify, report.
///
/// Exit discipline: a detected incident is a normal outcome (exit 0);
/// the run exits non-zero only on its own failure — an unreadable
/// signal group, a failed trip actuation, a failed notification.
#[allow(clippy::too_many_lines)]
async fn watch(edge: &Edge, dry_run: bool, output: Output) -> stow_types::error::Result<()> {
    let gh_token = crate::github_token().await?;
    let cf_token = cloudflare::api_token()?;
    let account =
        std::env::var(CF_ACCOUNT_ID_ENV).map_err(|_| stow_error!("missing {CF_ACCOUNT_ID_ENV}"))?;
    let zone = maintenance::zone_id()?;
    let host = maintenance::host_from_url(edge.base()).map_err(|error| stow_error!("{error}"))?;
    let sql_base = cloudflare::analytics_sql_base()?;
    let hourly_levels = HourlyAlertLevels::from_env()?;
    let liveness = LivenessLevels::from_env()?;
    let history = HistoryLevels::from_env()?;
    let watcher = Watcher {
        edge,
        gh_token: &gh_token,
        cf_token: &cf_token,
        account: &account,
        zone: &zone,
        host: &host,
        analytics_sql_base: &sql_base,
        now: OffsetDateTime::now_utc(),
    };

    let (readings, collect_failures) = watcher.collect(&hourly_levels, &liveness, &history).await;
    let decision = decide(&readings, &collect_failures);
    let mut outcome = ApplyOutcome::default();
    let now_text = format_time(watcher.now);
    let mut issue_number: Option<u64> = None;
    // The trip's record — the workflows it disabled, for the incident
    // body's marker.
    let mut disabled = BTreeSet::new();

    if decision.incident {
        let mut breach_views: Vec<BreachView<'_>> = decision
            .tripped
            .iter()
            .chain(decision.alerting.iter())
            .map(|&index| breach_view(&readings[index]))
            .collect();
        breach_views.sort_by_key(|view| (view.effect != "trip", view.id));

        if decision.tripped.is_empty() {
            outcome
                .actions
                .push("alert only — nothing tripped".to_owned());
        } else if dry_run {
            let reads = read_trip_states(&gh_token).await;
            let (planned, read_failures) = select_trip_set(&reads);
            for read in &reads {
                match &read.state {
                    Ok(_) if planned.contains(read.workflow) => outcome
                        .actions
                        .push(format!("would disable {}", read.workflow)),
                    Ok(state) => outcome.actions.push(format!(
                        "would leave {} untouched (state {state})",
                        read.workflow
                    )),
                    Err(_) => {}
                }
            }
            outcome.failures.extend(read_failures);
            let scope = decision
                .trip_scope
                .expect("a tripped decision carries a scope");
            outcome
                .actions
                .push(format!("would enable `{}`", scope.description()));
        } else {
            let scope = decision
                .trip_scope
                .expect("a tripped decision carries a scope");
            disabled = apply_trip(&watcher, scope, &mut outcome).await;
        }

        let mut failure_lines: Vec<String> = collect_failures
            .iter()
            .map(|failure| format!("{}: {}", failure.scope, failure.error))
            .chain(outcome.failures.iter().cloned())
            .collect();
        let breaches = decision.tripped.len() + decision.alerting.len();
        let primary = decision
            .tripped
            .first()
            .or_else(|| decision.alerting.first())
            .map_or("watchdog blind", |&index| readings[index].signal.id);
        let title = incident_title(primary, breaches.saturating_sub(1));

        // ----- durable record: the `incident` issue -----
        let mut issue_failure: Option<String> = None;
        let mut digest_posted = false;
        let mut issue_opened = false;
        if dry_run {
            outcome
                .actions
                .push("would open/update the incident issue".to_owned());
        } else {
            let issue = update_incident(
                GhChannel {
                    api_base: github::API_BASE,
                    token: &gh_token,
                },
                watcher.now,
                &title,
                &breach_views,
                &failure_lines,
                &disabled,
                &mut outcome,
            )
            .await?;
            issue_failure = issue.failure;
            digest_posted = issue.digest_posted;
            issue_opened = issue.opened;
            issue_number = issue.number;
        }
        if let Some(failure) = &issue_failure {
            // The issue channel failed — the mail still goes, and the
            // failure rides inside it (the cross-channel rule).
            failure_lines.push(format!("incident issue: {failure}"));
            outcome.failures.push(failure.clone());
        }

        // ----- notify: the mail -----
        // A mail goes out when the incident opened, when an hourly
        // digest just posted, or when the watchdog itself failed. A
        // persisting incident with no digest due stays silent.
        if dry_run {
            outcome.actions.push("would send the alert mail".to_owned());
        } else {
            let mail_kind = if !collect_failures.is_empty() || !outcome.failures.is_empty() {
                Some(MailKind::Failure)
            } else if digest_posted {
                Some(MailKind::Digest)
            } else if issue_opened {
                Some(MailKind::Open)
            } else {
                None
            };
            let mut mail_error: Option<String> = None;
            if let Some(kind) = mail_kind {
                match render_mail(
                    kind,
                    &breach_views,
                    &outcome.actions,
                    &failure_lines,
                    outcome.incident_url.as_deref(),
                    &now_text,
                ) {
                    Err(error) => {
                        mail_error = Some(format!("render mail: {error}"));
                    }
                    Ok((subject, text, html)) => {
                        match send_mail(&cf_token, &account, &subject, &text, &html).await {
                            Ok(message_id) => {
                                outcome.mailed = true;
                                outcome.actions.push(format!(
                                    "mail sent (id: {})",
                                    message_id.as_deref().unwrap_or("none")
                                ));
                            }
                            Err(error) => mail_error = Some(error),
                        }
                    }
                }
            }
            if let Some(mail_error) = mail_error {
                // The mail channel failed — record it on the issue (the
                // cross-channel rule). A markerless comment: it does not
                // consume the digest cadence.
                outcome.failures.push(mail_error.clone());
                if let Some(number) = issue_number {
                    let note = format!("mail send failed: {mail_error}");
                    let _ = post_comment(&gh_token, number, &note).await;
                }
            }
        }

        let report = build_report(dry_run, &decision, &readings, collect_failures, outcome);
        return finish(output, &report);
    }

    // ----- no breach: an open incident gets commented+closed -----
    if !dry_run {
        match find_incident(&gh_token).await {
            Err(error) => outcome
                .failures
                .push(format!("find incident issue: {error}")),
            Ok(None) => {}
            Ok(Some(issue)) => {
                auto_close(
                    &gh_token,
                    &cf_token,
                    &account,
                    issue,
                    &now_text,
                    &mut outcome,
                )
                .await;
            }
        }
    }

    let report = build_report(dry_run, &decision, &readings, collect_failures, outcome);
    finish(output, &report)
}

/// A clean run over an open incident — comment+close the issue and send
/// the cleared mail. The breaker stays tripped; only `watchdog clear`
/// reverses it.
async fn auto_close(
    gh_token: &str,
    cf_token: &str,
    account: &str,
    issue: GhIssue,
    now_text: &str,
    outcome: &mut ApplyOutcome,
) {
    let comment = ClearedTemplate {
        now: now_text,
        actions: &[
            "signals cleared on their own — the breaker stays tripped until `stow-admin watchdog clear`"
                .to_owned(),
        ],
    }
    .render()
    .unwrap_or_else(|_| "signals cleared".to_owned());
    match close_incident(gh_token, issue.number, &comment).await {
        Ok(()) => {
            outcome
                .actions
                .push(format!("incident cleared: {}", issue.html_url));
            outcome.incident_url = Some(issue.html_url);
        }
        Err(error) => outcome.failures.push(format!("close incident: {error}")),
    }
    match render_mail(
        MailKind::Cleared,
        &[],
        &outcome.actions,
        &[],
        outcome.incident_url.as_deref(),
        now_text,
    ) {
        Ok((subject, text, html)) => {
            match send_mail(cf_token, account, &subject, &text, &html).await {
                Ok(message_id) => {
                    outcome.mailed = true;
                    outcome.actions.push(format!(
                        "mail sent (id: {})",
                        message_id.as_deref().unwrap_or("none")
                    ));
                }
                Err(error) => outcome.failures.push(error),
            }
        }
        Err(error) => outcome.failures.push(format!("render mail: {error}")),
    }
}

/// Assemble the run's report.
fn build_report(
    dry_run: bool,
    decision: &Decision,
    readings: &[Reading],
    collect_failures: Vec<CollectFailure>,
    outcome: ApplyOutcome,
) -> WatchdogReport {
    let mut actions = outcome.actions;
    if !decision.skipped.is_empty() {
        // Under-sampled signals surface in the action log — a reading
        // that could not reach a verdict is still worth seeing.
        actions.push(format!(
            "{} signal(s) below minimum sample — no verdict",
            decision.skipped.len()
        ));
    }
    WatchdogReport {
        dry_run,
        incident: decision.incident,
        tripped: !decision.tripped.is_empty(),
        signals: readings.iter().map(signal_report).collect(),
        failures: collect_failures,
        actions,
        own_failures: outcome.failures,
        incident_url: outcome.incident_url,
        mailed: outcome.mailed,
    }
}

/// Emit the report, then convert the watchdog's own failures into the
/// non-zero exit.
fn finish(output: Output, report: &WatchdogReport) -> stow_types::error::Result<()> {
    let failed = !report.failures.is_empty() || !report.own_failures.is_empty();
    render::emit(output, report, render_report)?;
    if failed {
        return Err(stow_error!(
            "watchdog partial failure — collector/notification failures in the report"
        ));
    }
    Ok(())
}

/// `watchdog clear` — maintenance rule off, the workflows the incident's
/// trip record names re-enabled (no incident or no record: nothing),
/// incident commented+closed, clear-mail. Manual recovery; the watchdog
/// never does this on its own.
#[allow(clippy::too_many_lines)]
async fn clear(edge: &Edge, dry_run: bool, output: Output) -> stow_types::error::Result<()> {
    let gh_token = crate::github_token().await?;
    let cf_token = cloudflare::api_token()?;
    let account =
        std::env::var(CF_ACCOUNT_ID_ENV).map_err(|_| stow_error!("missing {CF_ACCOUNT_ID_ENV}"))?;
    let zone = maintenance::zone_id()?;
    let host = maintenance::host_from_url(edge.base()).map_err(|error| stow_error!("{error}"))?;
    let sql_base = cloudflare::analytics_sql_base()?;
    let watcher = Watcher {
        edge,
        gh_token: &gh_token,
        cf_token: &cf_token,
        account: &account,
        zone: &zone,
        host: &host,
        analytics_sql_base: &sql_base,
        now: OffsetDateTime::now_utc(),
    };
    let mut outcome = ApplyOutcome::default();
    let now_text = format_time(watcher.now);
    // The restore record is the open incident's marker — read it before
    // any workflow moves, so a missing or unreadable record enables
    // nothing (stow#744).
    let (incident, restore) = match find_incident(&gh_token).await {
        Err(error) => {
            outcome
                .failures
                .push(format!("find incident issue: {error}"));
            (None, BTreeSet::new())
        }
        Ok(incident) => {
            let restore = match clear_restore(incident.as_ref()) {
                RestoreSet::Set(set) => set,
                RestoreSet::NoIncident => {
                    outcome
                        .actions
                        .push("no open incident — no workflows re-enabled".to_owned());
                    BTreeSet::new()
                }
                RestoreSet::NoRecord(number) => {
                    outcome.actions.push(format!(
                        "incident #{number} has no disabled-workflow record — no workflows re-enabled"
                    ));
                    BTreeSet::new()
                }
                RestoreSet::Malformed(error) => {
                    outcome.failures.push(error);
                    BTreeSet::new()
                }
            };
            (incident, restore)
        }
    };
    if dry_run {
        for scope in TRIP_SCOPES {
            outcome
                .actions
                .push(format!("would disable `{}`", scope.description()));
        }
        for workflow in &restore {
            outcome.actions.push(format!("would enable {workflow}"));
        }
        for workflow in TRIP_WORKFLOWS {
            if !restore.contains(*workflow) {
                outcome
                    .actions
                    .push(format!("would leave {workflow} untouched"));
            }
        }
        outcome
            .actions
            .push("would comment+close the open incident and send the clear mail".to_owned());
    } else {
        apply_clear(&watcher, &restore, &mut outcome).await;
        if let Some(issue) = incident {
            let comment = ClearedTemplate {
                now: &now_text,
                actions: &outcome.actions,
            }
            .render()
            .unwrap_or_else(|_| "cleared by operator".to_owned());
            match close_incident(&gh_token, issue.number, &comment).await {
                Ok(()) => {
                    outcome.incident_url = Some(issue.html_url.clone());
                    outcome
                        .actions
                        .push(format!("incident closed: {}", issue.html_url));
                }
                Err(error) => outcome.failures.push(format!("close incident: {error}")),
            }
        }
        match render_mail(
            MailKind::Cleared,
            &[],
            &outcome.actions,
            &outcome.failures,
            outcome.incident_url.as_deref(),
            &now_text,
        ) {
            Ok((subject, text, html)) => {
                match send_mail(&cf_token, &account, &subject, &text, &html).await {
                    Ok(message_id) => {
                        outcome.mailed = true;
                        outcome.actions.push(format!(
                            "mail sent (id: {})",
                            message_id.as_deref().unwrap_or("none")
                        ));
                    }
                    Err(error) => outcome.failures.push(error),
                }
            }
            Err(error) => outcome.failures.push(format!("render mail: {error}")),
        }
    }
    let report = WatchdogReport {
        dry_run,
        incident: false,
        tripped: false,
        signals: Vec::new(),
        failures: Vec::new(),
        actions: outcome.actions,
        own_failures: outcome.failures,
        incident_url: outcome.incident_url,
        mailed: outcome.mailed,
    };
    render::emit(output, &report, |report| {
        let mut out = String::new();
        for action in &report.actions {
            let _ = writeln!(out, "{action}");
        }
        for failure in &report.own_failures {
            let _ = writeln!(out, "FAILED {failure}");
        }
        if report.mailed {
            let _ = writeln!(out, "clear mail sent");
        }
        out.trim_end().to_owned()
    })?;
    if report.own_failures.is_empty() {
        Ok(())
    } else {
        Err(stow_error!("watchdog clear partially failed — see report"))
    }
}

/// Write the incident issue — PATCH the open one, POST a fresh issue
/// otherwise. `existing` is the caller's `find_incident` result, which
/// it already read for the marker union; the open-vs-update branch is
/// what keeps a later run from opening a duplicate.
async fn upsert_incident(
    gh_token: &str,
    existing: Option<&GhIssue>,
    title: &str,
    body: &str,
) -> Result<(GhIssue, bool), String> {
    match existing {
        Some(issue) => github::patch::<GhIssue>(
            gh_token,
            &format!("issues/{}", issue.number),
            &IssuePatch { title, body },
        )
        .await
        .map(|updated| (updated, false))
        .map_err(|error| format!("PATCH issue #{}: {error}", issue.number)),
        None => github::post::<GhIssue>(
            gh_token,
            "issues",
            &IssueNew {
                title,
                body,
                labels: [INCIDENT_LABEL],
            },
        )
        .await
        .map(|issue| (issue, true))
        .map_err(|error| format!("POST issue: {error}")),
    }
}

/// `PATCH /issues/{n}` — title/body rewrite on update, close on `clear`.
#[derive(serde::Serialize)]
struct IssuePatch<'a> {
    title: &'a str,
    body: &'a str,
}

/// `POST /issues` — a fresh incident.
#[derive(serde::Serialize)]
pub struct IssueNew<'a> {
    /// Issue title.
    pub title: &'a str,
    /// Issue body.
    pub body: &'a str,
    /// Labels to apply.
    pub labels: [&'a str; 1],
}

/// `PATCH /issues/{n}` close marker.
#[derive(serde::Serialize)]
struct IssueClose<'a> {
    state: &'a str,
}

/// `POST /issues/{n}/comments`.
#[derive(serde::Serialize)]
struct IssueComment<'a> {
    body: &'a str,
}

pub async fn post_comment(gh_token: &str, issue: u64, body: &str) -> Result<(), String> {
    let _: serde_json::Value = github::post(
        gh_token,
        &format!("issues/{issue}/comments"),
        &IssueComment { body },
    )
    .await
    .map_err(|error| format!("POST comment on #{issue}: {error}"))?;
    Ok(())
}

/// Comment and close — `clear` and the auto-clear path share it.
pub async fn close_incident(gh_token: &str, issue: u64, comment: &str) -> Result<(), String> {
    post_comment(gh_token, issue, comment).await?;
    let _: GhIssue = github::patch(
        gh_token,
        &format!("issues/{issue}"),
        &IssueClose { state: "closed" },
    )
    .await
    .map_err(|error| format!("close issue #{issue}: {error}"))?;
    Ok(())
}

/// What the issue channel produced this run.
#[derive(Debug, Default)]
struct IssueOutcome {
    /// The incident issue's number once it exists.
    number: Option<u64>,
    /// This run created the issue (vs updating an open one).
    opened: bool,
    /// A digest comment went out this run.
    digest_posted: bool,
    /// Any step of the channel that failed — the mail still goes
    /// afterwards with the failure folded into it.
    failure: Option<String>,
}

/// The GitHub API the issue channel writes to — production passes
/// `github::API_BASE`; tests hand an owned loopback URL, so the
/// endpoint is explicit state rather than a global.
#[derive(Clone, Copy)]
struct GhChannel<'a> {
    /// API root — `https://api.github.com` or a test loopback.
    api_base: &'a str,
    /// The operator's GitHub token.
    token: &'a str,
}

/// Open-or-update the incident issue and hold its comment cadence — the
/// durable record channel. Called only on a real (non-dry-run) run with
/// an incident; any step that fails lands in `failure` rather than
/// aborting the mail that follows.
async fn update_incident(
    gh: GhChannel<'_>,
    now: OffsetDateTime,
    title: &str,
    breaches: &[BreachView<'_>],
    failure_lines: &[String],
    disabled: &BTreeSet<String>,
    outcome: &mut ApplyOutcome,
) -> stow_types::error::Result<IssueOutcome> {
    let now_text = format_time(now);
    let mut issue_outcome = IssueOutcome::default();
    if let Err(error) =
        ensure_label(gh.api_base, gh.token, std::time::Duration::from_secs(30)).await
    {
        issue_outcome.failure = Some(format!("label: {error}"));
        return Ok(issue_outcome);
    }
    let existing = match find_incident(gh.token).await {
        Ok(existing) => existing,
        Err(error) => {
            issue_outcome.failure = Some(format!("find incident: {error}"));
            return Ok(issue_outcome);
        }
    };
    // The record accumulates: a second trip under one open incident
    // unions its disabled set into the marker `clear` restores from,
    // and an alert-only update leaves the standing marker untouched.
    let mut disabled_set = disabled.clone();
    if let Some(issue) = &existing {
        match parse_disabled_marker(issue.number, issue.body.as_deref().unwrap_or_default()) {
            Ok(Some(prior)) => disabled_set.extend(prior),
            Ok(None) => {}
            Err(error) => issue_outcome.failure = Some(error),
        }
    }
    let body = IncidentTemplate {
        now: &now_text,
        dry_run: false,
        breaches,
        actions: &outcome.actions,
        failures: failure_lines,
        disabled: &disabled_set,
    }
    .render()
    .map_err(|error| stow_error!("render incident body: {error}"))?;
    match upsert_incident(gh.token, existing.as_ref(), title, &body).await {
        Err(error) => {
            issue_outcome.failure = Some(match issue_outcome.failure.take() {
                Some(prior) => format!("{prior}; {error}"),
                None => error,
            });
        }
        Ok((issue, opened)) => {
            issue_outcome.opened = opened;
            issue_outcome.number = Some(issue.number);
            outcome.incident_url = Some(issue.html_url.clone());
            outcome.actions.push(if opened {
                format!("incident opened: {}", issue.html_url)
            } else {
                format!("incident updated: {}", issue.html_url)
            });
            if !opened {
                // Digest cadence: at most one comment an hour; a
                // freshly opened issue needs none.
                match last_digest_at(gh.token, issue.number).await {
                    Ok(last) => {
                        if digest_due(last, now) {
                            let comment = DigestTemplate {
                                now: &now_text,
                                breaches,
                                failures: failure_lines,
                                actions: &outcome.actions,
                            }
                            .render()
                            .map_err(|error| stow_error!("render digest: {error}"))?;
                            match post_comment(gh.token, issue.number, &comment).await {
                                Ok(()) => {
                                    issue_outcome.digest_posted = true;
                                    outcome.actions.push("digest comment posted".to_owned());
                                }
                                Err(error) => {
                                    issue_outcome.failure = Some(format!("comment: {error}"));
                                }
                            }
                        }
                    }
                    Err(error) => {
                        issue_outcome.failure = Some(format!("comments: {error}"));
                    }
                }
            }
        }
    }
    Ok(issue_outcome)
}

/// The human report for `render::emit`.
fn render_report(report: &WatchdogReport) -> String {
    let mut out = String::new();
    if report.dry_run {
        let _ = writeln!(out, "dry run — nothing applied");
    }
    if report.signals.is_empty() {
        let _ = writeln!(out, "no signals");
    } else {
        let mut table = Table::new(&[
            "signal",
            "verdict",
            "observed",
            "threshold",
            "window",
            "sample",
        ]);
        for signal in &report.signals {
            table.push([
                signal.id.to_owned(),
                signal.verdict.to_owned(),
                signal.observed.clone(),
                signal.threshold.clone(),
                signal.window.clone(),
                signal.sample.to_string(),
            ]);
        }
        let _ = writeln!(out, "{}", table.render());
    }
    for action in &report.actions {
        let _ = writeln!(out, "{action}");
    }
    for failure in &report.failures {
        let _ = writeln!(out, "unreadable {}: {}", failure.scope, failure.error);
    }
    for failure in &report.own_failures {
        let _ = writeln!(out, "FAILED {failure}");
    }
    if let Some(url) = &report.incident_url {
        let _ = writeln!(out, "incident {url}");
    }
    if report.mailed {
        let _ = writeln!(out, "mail sent");
    }
    let _ = write!(
        out,
        "{}",
        if report.tripped {
            "TRIPPED"
        } else if report.incident {
            "alerting"
        } else {
            "ok"
        }
    );
    out
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(id: &str, sample: u64, value: f64) -> Reading {
        Reading {
            signal: signal(id),
            threshold: None,
            sample,
            value,
            evidence: vec![],
        }
    }

    /// Trip: a billed usage dimension's month-to-date total over the 80%
    /// line → the decision is incident + tripped.
    #[test]
    fn month_over_the_line_trips() {
        let readings = vec![reading(
            "cf.do.rows_written",
            1,
            DO_ROWS_WRITTEN_MONTHLY * ALLOWANCE_FRACTION,
        )];
        let decision = decide(&readings, &[]);
        assert!(decision.incident);
        assert_eq!(decision.tripped.len(), 1);
        assert_eq!(decision.alerting, [] as [usize; 0]);
    }

    /// Every billed dimension trips on a month total at the line and
    /// stays clear just under it.
    #[test]
    fn every_billed_dimension_trips_at_the_line() {
        for (id, allowance) in [
            ("cf.do.rows_read", DO_ROWS_READ_MONTHLY),
            ("cf.do.rows_written", DO_ROWS_WRITTEN_MONTHLY),
            ("cf.do.duration_gb_s", DO_DURATION_GB_S_MONTHLY),
            ("cf.do.requests", DO_REQUESTS_MONTHLY),
            ("cf.worker.requests", WORKER_REQUESTS_MONTHLY),
            ("cf.worker.cpu_ms", WORKER_CPU_MS_MONTHLY),
        ] {
            let line = allowance * ALLOWANCE_FRACTION;
            let under = decide(&[reading(id, 1, line * 0.99)], &[]);
            assert!(!under.incident, "{id} just under the line");
            let over = decide(&[reading(id, 1, line)], &[]);
            assert_eq!(over.tripped.len(), 1, "{id} at the line");
        }
    }

    /// The DO duration guard can fire: a month of one 128 MB object
    /// billed continuously is 0.125 GB x 3600 s x 24 x 30 = 324k GB-s,
    /// past the 320k line — and the guard reads exactly that total.
    #[test]
    fn duration_guard_can_fire() {
        let month = MonthTotals {
            do_duration_gb_s: 0.125 * 3600.0 * 24.0 * 30.0,
            ..MonthTotals::default()
        };
        let readings = CfSnapshot::default().readings(&month, &levels(), october_29());
        let tripped: Vec<_> = decide(&readings, &[])
            .tripped
            .iter()
            .map(|&i| readings[i].signal.id)
            .collect();
        assert_eq!(tripped, ["cf.do.duration_gb_s"]);
    }

    fn levels() -> HourlyAlertLevels {
        HourlyAlertLevels(DEFAULT_HOURLY_ALERT_PERCENTS.to_vec())
    }

    fn october_29() -> OffsetDateTime {
        time::Date::from_calendar_date(2026, time::Month::October, 29)
            .unwrap()
            .with_hms(0, 38, 0)
            .unwrap()
            .assume_utc()
    }

    /// A snapshot whose last hour used `multiple` x the hourly pace of
    /// every DO and Worker dimension.
    fn hour_at(multiple: f64, now: OffsetDateTime) -> CfSnapshot {
        let hours = hours_in_month(now);
        let mut snapshot = CfSnapshot::default();
        snapshot.do_periodic.rows_read = DO_ROWS_READ_MONTHLY / hours * multiple;
        snapshot.do_periodic.rows_written = DO_ROWS_WRITTEN_MONTHLY / hours * multiple;
        snapshot.do_periodic.duration = DO_DURATION_GB_S_MONTHLY / hours * multiple;
        snapshot.do_invoke.requests = DO_REQUESTS_MONTHLY / hours * multiple;
        snapshot.worker.requests = WORKER_REQUESTS_MONTHLY / hours * multiple;
        snapshot.worker.cpu_time_us = WORKER_CPU_MS_MONTHLY * 1000.0 / hours * multiple;
        snapshot
    }

    /// The 2026-10-29 incident: 1.4k DO requests in an hour against
    /// 1,389 tripped the old hourly share. A peak hour or a wave with
    /// the month under the line alerts at its pace level and never
    /// trips.
    #[test]
    fn a_within_budget_peak_hour_alerts_and_never_trips() {
        let now = october_29();
        // The month so far is at 10% of the line on every dimension.
        let month = MonthTotals {
            do_rows_read: DO_ROWS_READ_MONTHLY * 0.08,
            do_rows_written: DO_ROWS_WRITTEN_MONTHLY * 0.08,
            do_duration_gb_s: DO_DURATION_GB_S_MONTHLY * 0.08,
            do_requests: DO_REQUESTS_MONTHLY * 0.08,
            worker_requests: WORKER_REQUESTS_MONTHLY * 0.08,
            worker_cpu_ms: WORKER_CPU_MS_MONTHLY * 0.08,
        };
        let readings = hour_at(10.0, now).readings(&month, &levels(), now);
        let decision = decide(&readings, &[]);
        assert_eq!(decision.tripped, [] as [usize; 0]);
        assert_eq!(decision.trip_scope, None);
        let alerting: BTreeSet<_> = decision
            .alerting
            .iter()
            .map(|&i| readings[i].signal.id)
            .collect();
        assert_eq!(alerting.len(), 6);
        assert!(alerting.iter().all(|id| id.ends_with(".hourly")));
    }

    /// The hourly view alerts at 200% and again at 300% of the pace
    /// (reporting the higher level), and not below 200%.
    #[test]
    fn hourly_pace_alerts_at_the_set_levels() {
        let now = october_29();
        let month = MonthTotals::default();
        let breaches = |multiple: f64, levels: &HourlyAlertLevels| {
            let readings = hour_at(multiple, now).readings(&month, levels, now);
            let decision = decide(&readings, &[]);
            assert_eq!(decision.tripped, [] as [usize; 0]);
            decision
                .alerting
                .iter()
                .map(|&i| (readings[i].signal.id, readings[i].threshold()))
                .collect::<Vec<_>>()
        };
        assert_eq!(breaches(1.9, &levels()), []);
        let at_200 = breaches(2.5, &levels());
        assert_eq!(at_200.len(), 6);
        let pace = DO_REQUESTS_MONTHLY / hours_in_month(now);
        let requests = at_200
            .iter()
            .find(|(id, _)| *id == "cf.do.requests.hourly")
            .unwrap();
        assert!(pace.mul_add(-2.0, requests.1).abs() < 1e-6);
        let at_300 = breaches(3.5, &levels());
        let requests = at_300
            .iter()
            .find(|(id, _)| *id == "cf.do.requests.hourly")
            .unwrap();
        assert!(pace.mul_add(-3.0, requests.1).abs() < 1e-6);
        // An operator-set level replaces the default with no guard.
        let custom = HourlyAlertLevels::parse("50, 1000").unwrap();
        assert_eq!(custom, HourlyAlertLevels(vec![50.0, 1000.0]));
        assert_eq!(breaches(0.6, &custom).len(), 6);
        assert!(HourlyAlertLevels::parse("two hundred").is_err());
    }

    /// The month window starts at the UTC month's first midnight, is cut
    /// in contiguous day-bounded windows and ends at `now`.
    #[test]
    fn month_windows_are_day_bounded_and_contiguous() {
        let now = october_29();
        let windows = month_day_windows(now).unwrap();
        assert_eq!(windows.len(), 29);
        assert_eq!(
            windows[0].0,
            time::Date::from_calendar_date(2026, time::Month::October, 1)
                .unwrap()
                .midnight()
                .assume_utc()
        );
        assert_eq!(windows.last().unwrap().1, now);
        for pair in windows.windows(2) {
            assert_eq!(pair[0].1, pair[1].0);
        }
        for (since, until) in &windows {
            assert!(*until - *since <= time::Duration::days(1));
        }
        assert_eq!(hours_in_month(now), 31.0 * 24.0);
    }

    fn scope_of(ids: &[&str]) -> Option<MaintenanceScope> {
        let readings: Vec<_> = ids.iter().map(|id| reading(id, 1_000_000, 1e18)).collect();
        decide(&readings, &[]).trip_scope
    }

    /// A DO-billed breach sheds only the scheduler lanes; a Worker-billed
    /// one sheds the anonymous surface; mixed breaches take the widest.
    #[test]
    fn trip_scope_follows_the_cost() {
        assert_eq!(
            scope_of(&["cf.do.rows_read", "cf.do.requests"]),
            Some(MaintenanceScope::Lanes)
        );
        assert_eq!(
            scope_of(&["cf.worker.cpu_ms"]),
            Some(MaintenanceScope::Anonymous)
        );
        assert_eq!(
            scope_of(&["cf.do.duration_gb_s", "cf.worker.requests"]),
            Some(MaintenanceScope::Anonymous)
        );
        assert_eq!(
            scope_of(&["pipeline.failure_rate"]),
            Some(MaintenanceScope::Lanes)
        );
        assert_eq!(scope_of(&["endpoint.stats"]), None);
    }

    /// Below threshold → clear, no incident.
    #[test]
    fn usage_below_allowance_clears() {
        let readings = vec![reading("cf.do.rows_written", 1, 1000.0)];
        let decision = decide(&readings, &[]);
        assert!(!decision.incident);
    }

    /// Minimum sample: 5 failed tasks of 5 completed is 100% but below
    /// `min_sample` 20 → skipped, no trip.
    #[test]
    fn failure_rate_respects_minimum_sample() {
        let readings = vec![reading("pipeline.failure_rate", 5, 100.0)];
        let decision = decide(&readings, &[]);
        assert!(!decision.incident);
        assert_eq!(decision.skipped.len(), 1);
    }

    /// At the minimum sample, a breach trips.
    #[test]
    fn failure_rate_at_sample_trips() {
        let readings = vec![reading("pipeline.failure_rate", 25, 60.0)];
        let decision = decide(&readings, &[]);
        assert_eq!(decision.tripped.len(), 1);
    }

    /// An alert-only breach opens the incident but never trips.
    #[test]
    fn alert_only_breach_does_not_trip() {
        let readings = vec![
            reading("edge.worker.errors", 500, 5.0),
            reading("endpoint.stats", 1, 9000.0),
        ];
        let decision = decide(&readings, &[]);
        assert!(decision.incident);
        assert_eq!(decision.tripped, [] as [usize; 0]);
        assert_eq!(decision.alerting.len(), 2);
    }

    /// A frozen dispatch status is an incident the watchdog records —
    /// alert, never a re-trip: the freeze already cut dispatch, so no
    /// maintenance rule or workflow disable.
    #[test]
    fn a_frozen_status_yields_an_incident() {
        let readings = vec![reading("edge.dispatch_frozen", 1, 1.0)];
        let decision = decide(&readings, &[]);
        assert!(decision.incident);
        assert_eq!(decision.tripped, [] as [usize; 0]);
        assert_eq!(decision.alerting.len(), 1);
        // And cleared dispatch stays clear.
        let cleared = decide(&[reading("edge.dispatch_frozen", 1, 0.0)], &[]);
        assert!(!cleared.incident);
    }

    /// A collector failure alone is an incident — the watchdog is blind.
    #[test]
    fn collector_failure_is_an_incident() {
        let decision = decide(
            &[reading("cf.do.rows_read", 1, 1.0)],
            &[CollectFailure {
                scope: "pipeline",
                error: "403".to_owned(),
            }],
        );
        assert!(decision.incident);
        assert_eq!(decision.tripped, [] as [usize; 0]);
    }

    /// Fixture: the GraphQL response decodes into a snapshot — trip
    /// readings land on the billed fields.
    #[test]
    fn graphql_fixture_decodes() {
        let json = r#"{"data":{"viewer":{"accounts":[{
            "doPeriodic":[{"sum":{"activeTime":12,"cpuTime":5,"duration":700,"exceededCpuErrors":0,"exceededMemoryErrors":0,"fatalInternalErrors":0,"rowsRead":40000000000,"rowsWritten":1000,"storageDeletes":0,"storageReadUnits":0,"storageWriteUnits":0,"subrequests":9}}],
            "doInvoke":[{"sum":{"requests":2000,"wallTime":9,"errors":0}}],
            "worker":[{"sum":{"clientDisconnects":0,"cpuTimeUs":45000000,"duration":1,"errors":0,"requestDuration":2,"requests":15000,"responseBodySize":0,"subrequests":300,"wallTime":4}}],
            "workerStatus":[{"dimensions":{"status":"success"},"sum":{"requests":100}},{"dimensions":{"status":"scriptThrewException"},"sum":{"requests":4}}]
        }]}}}"#;
        let envelope: cloudflare::Envelope<AccountGroups> = serde_json::from_str(json).unwrap();
        let account = envelope.into_account().unwrap();
        let snapshot = CfSnapshot::from(account);
        // Read as the month so far: rows_read 40G is past the 20G line.
        let month = MonthTotals::from(&snapshot);
        let readings = snapshot.readings(&month, &levels(), october_29());
        let decision = decide(&readings, &[]);
        assert!(decision.incident);
        let tripped: Vec<_> = decision
            .tripped
            .iter()
            .map(|&i| readings[i].signal.id)
            .collect();
        assert_eq!(tripped, ["cf.do.rows_read"]);
        // 4/104 scriptThrew = 3.8% > 2% → alert
        assert_eq!(
            decision
                .alerting
                .iter()
                .map(|&i| readings[i].signal.id)
                .collect::<Vec<_>>(),
            vec!["cf.do.rows_read.hourly", "edge.worker.errors"]
        );
    }

    /// The Analytics Engine `FORMAT JSON` response quotes 64-bit
    /// aggregates — `"0"` decodes just like `0` (issue #485).
    #[test]
    fn analytics_response_decodes_quoted_numbers() {
        let json = r#"{"meta":[{"name":"events","type":"Float64"},{"name":"points","type":"UInt64"}],"data":[{"events":"0","points":"42"}],"rows":1}"#;
        let envelope: analytics::Envelope<AnalyticsRow> = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.data[0].events, 0.0);
        assert_eq!(envelope.data[0].points, 42);
        // An unquoted number decodes too — a Float64 column stays a
        // plain JSON number on the wire.
        let envelope: analytics::Envelope<AnalyticsRow> =
            serde_json::from_str(r#"{"data":[{"events":17,"points":5}]}"#).unwrap();
        assert_eq!(envelope.data[0].events, 17.0);
        assert_eq!(envelope.data[0].points, 5);
    }

    /// A `Watcher` pointed at a loopback Analytics Engine fixture —
    /// every field but `analytics_sql_base` is inert for the overload
    /// collector.
    fn sql_watcher<'a>(edge: &'a crate::Edge, sql_base: &'a str) -> Watcher<'a> {
        Watcher {
            edge,
            gh_token: "gh-test",
            cf_token: "cf-test",
            account: "test-account",
            zone: "zone-test",
            host: "stow.waterui.dev",
            analytics_sql_base: sql_base,
            now: OffsetDateTime::now_utc(),
        }
    }

    fn sql_edge() -> crate::Edge {
        crate::Edge {
            base: "http://127.0.0.1:1".to_owned(),
            token: None,
            version_override: None,
        }
    }

    /// The watchdog query must name the live dataset and carry both the
    /// fault marker and the liveness aggregate — asserted off the
    /// captured request, not presumed.
    fn assert_watchdog_sql(body: &[u8]) {
        let sql = std::str::from_utf8(body).expect("SQL body is UTF-8");
        assert!(sql.contains("stow_cache_misses"), "{sql}");
        assert!(sql.contains("index1 = '#fault'"), "{sql}");
        assert!(sql.contains("blob1 = 'overloaded'"), "{sql}");
        assert!(sql.contains("count() AS points"), "{sql}");
    }

    /// Overload points over the trailing hour → the reading breaches
    /// the `edge.do.overloaded` threshold (`Effect::Alert`), with the
    /// dataset point count as the sample basis.
    #[tokio::test]
    async fn overloaded_reading_alerts_above_threshold() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 200,
            retry_after: None,
            body: r#"{"meta":[],"data":[{"events":"3","points":"17"}],"rows":1}"#,
        }])
        .await;
        let edge = sql_edge();
        let watcher = sql_watcher(&edge, &server.url);
        let readings = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            watcher.overloaded_reading(),
        )
        .await
        .expect("read completes within the deadline")
        .expect("a live dataset with overload points reads");
        assert_eq!(readings.len(), 1);
        assert_eq!(readings[0].signal.id, "edge.do.overloaded");
        assert_eq!(readings[0].sample, 17);
        assert_eq!(verdict(&readings[0]), Verdict::Breach);
        let requests = server.join().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].head.uri.path(),
            "/accounts/test-account/analytics_engine/sql"
        );
        assert_watchdog_sql(&requests[0].body);
    }

    /// A live dataset (`points` > 0) with zero overload markers → the
    /// signal is `clear`, not an incident.
    #[tokio::test]
    async fn overloaded_reading_clears_on_live_dataset() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 200,
            retry_after: None,
            body: r#"{"meta":[],"data":[{"events":"0","points":"42"}],"rows":1}"#,
        }])
        .await;
        let edge = sql_edge();
        let watcher = sql_watcher(&edge, &server.url);
        let readings = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            watcher.overloaded_reading(),
        )
        .await
        .expect("read completes within the deadline")
        .expect("a live dataset reads");
        assert_eq!(verdict(&readings[0]), Verdict::Clear);
        assert_watchdog_sql(&server.join().await[0].body);
    }

    /// A dataset that received no points at all in the window is a dead
    /// writer chain — the collector fails and the error names
    /// `stow_cache_misses`, never a silent zero.
    #[tokio::test]
    async fn overloaded_reading_fails_on_dead_dataset() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 200,
            retry_after: None,
            body: r#"{"meta":[],"data":[{"events":"0","points":"0"}],"rows":1}"#,
        }])
        .await;
        let edge = sql_edge();
        let watcher = sql_watcher(&edge, &server.url);
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            watcher.overloaded_reading(),
        )
        .await
        .expect("read completes within the deadline")
        .expect_err("a pointless dataset is a collector failure");
        assert!(error.contains("stow_cache_misses"), "{error}");
        server.join().await;
    }

    /// A GraphQL `errors` array is a hard error — never a partial read.
    #[test]
    fn graphql_errors_array_is_a_hard_error() {
        let json = r#"{"data":null,"errors":[{"message":"bad field"}]}"#;
        let envelope: cloudflare::Envelope<AccountGroups> = serde_json::from_str(json).unwrap();
        assert_eq!(
            envelope.into_account().unwrap_err(),
            "Cloudflare GraphQL errors: bad field"
        );
    }

    /// Digest cadence — at most one comment an hour.
    #[test]
    fn digest_cadence_is_one_per_hour() {
        let now = OffsetDateTime::now_utc();
        assert!(!digest_due(Some(now - time::Duration::minutes(30)), now));
        assert!(digest_due(Some(now - time::Duration::minutes(61)), now));
        assert!(digest_due(None, now));
    }

    /// Open vs update: `find_incident` prefers the labelled issue whose
    /// title starts with the prefix; PRs never match.
    #[test]
    fn incident_dedup_skips_pull_requests() {
        let pr = GhIssue {
            number: 7,
            title: format!("{INCIDENT_TITLE_PREFIX} x"),
            html_url: String::new(),
            body: None,
            pull_request: Some(serde_json::json!({"url": "x"})),
        };
        assert!(pr.pull_request.is_some());
    }

    /// `endpoint.*` breaches on a non-200 regardless of latency.
    #[test]
    fn non_200_is_a_breach() {
        let reading = Reading {
            signal: signal("endpoint.stats"),
            threshold: None,
            sample: 1,
            value: 5000.0,
            evidence: vec![],
        };
        assert_eq!(verdict(&reading), Verdict::Breach);
    }

    /// The incident body renders through askama, not string concat.
    #[test]
    fn incident_body_renders() {
        let breach = BreachView {
            id: "cf.do.rows_written",
            label: "DO rows",
            effect: "trip",
            window: "1h".to_owned(),
            observed: "1.4M rows".to_owned(),
            threshold: "69.4k rows".to_owned(),
            evidence: &[],
        };
        let disabled = BTreeSet::new();
        let body = IncidentTemplate {
            now: "2026-09-28T00:00:00Z",
            dry_run: false,
            breaches: &[breach],
            actions: &["disabled build-crate.yml".to_owned()],
            failures: &[],
            disabled: &disabled,
        }
        .render()
        .unwrap();
        assert!(body.contains("cf.do.rows_written"));
        assert!(body.contains("disabled build-crate.yml"));
    }

    /// Marker render + parse round-trip: the set the template writes is
    /// the set the clear reads back (stow#744).
    #[test]
    fn disabled_marker_round_trips() {
        let disabled =
            BTreeSet::from(["build-crate.yml".to_owned(), "preheat-cron.yml".to_owned()]);
        let body = IncidentTemplate {
            now: "2026-10-14T00:00:00Z",
            dry_run: false,
            breaches: &[],
            actions: &[],
            failures: &[],
            disabled: &disabled,
        }
        .render()
        .unwrap();
        assert!(
            body.contains("<!-- stow-watchdog:disabled build-crate.yml,preheat-cron.yml -->"),
            "unexpected body:\n{body}"
        );
        assert_eq!(parse_disabled_marker(42, &body), Ok(Some(disabled)));
    }

    /// The empty record — an alert-only incident — still renders a
    /// marker, and it parses to the empty set rather than to "absent".
    #[test]
    fn disabled_marker_empty_set() {
        let disabled = BTreeSet::new();
        let body = IncidentTemplate {
            now: "2026-10-14T00:00:00Z",
            dry_run: false,
            breaches: &[],
            actions: &[],
            failures: &[],
            disabled: &disabled,
        }
        .render()
        .unwrap();
        assert!(body.contains("<!-- stow-watchdog:disabled -->"));
        assert_eq!(parse_disabled_marker(42, &body), Ok(Some(disabled)));
    }

    /// No marker parses to `None`; a malformed marker is an error that
    /// names the issue.
    #[test]
    fn disabled_marker_parsing() {
        assert_eq!(parse_disabled_marker(42, "no marker here"), Ok(None));
        // An adjacent key (`disabled-else`) is not the record.
        assert_eq!(
            parse_disabled_marker(42, "<!-- stow-watchdog:disabled-else a.yml -->"),
            Ok(None)
        );
        let error = parse_disabled_marker(42, "<!-- stow-watchdog:disabled build-crate.yml, -->")
            .unwrap_err();
        assert!(error.contains("incident #42"), "unexpected error: {error}");
        let error =
            parse_disabled_marker(42, "<!-- stow-watchdog:disabled build-crate.yml").unwrap_err();
        assert!(error.contains("incident #42"), "unexpected error: {error}");
        let error =
            parse_disabled_marker(42, "<!-- stow-watchdog:disabled not a file -->").unwrap_err();
        assert!(error.contains("incident #42"), "unexpected error: {error}");
    }

    /// The trip's selection: only `active` reads land in the set; a
    /// read failure names the workflow and keeps it out.
    #[test]
    fn trip_selects_only_the_active() {
        let reads = vec![
            TripState {
                workflow: "build-crate.yml",
                state: Ok("active".to_owned()),
            },
            TripState {
                workflow: "preheat-cron.yml",
                state: Ok("disabled_manually".to_owned()),
            },
            TripState {
                workflow: "index-publish-cron.yml",
                state: Err("boom".to_owned()),
            },
        ];
        let (set, failures) = select_trip_set(&reads);
        assert_eq!(set, BTreeSet::from(["build-crate.yml".to_owned()]));
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("index-publish-cron.yml"));
    }

    /// The clear restores exactly the marker's set; no incident and no
    /// marker both enable nothing.
    #[test]
    fn clear_restores_only_the_recorded_set() {
        let issue = |body: Option<&str>| GhIssue {
            number: 7,
            title: format!("{INCIDENT_TITLE_PREFIX} x"),
            html_url: String::new(),
            body: body.map(str::to_owned),
            pull_request: None,
        };
        match clear_restore(Some(&issue(Some(
            "<!-- stow-watchdog:disabled build-crate.yml,preheat-cron.yml -->",
        )))) {
            RestoreSet::Set(set) => assert_eq!(
                set,
                BTreeSet::from(["build-crate.yml".to_owned(), "preheat-cron.yml".to_owned()])
            ),
            _ => panic!("a recorded set restores"),
        }
        assert!(matches!(clear_restore(None), RestoreSet::NoIncident));
        assert!(matches!(
            clear_restore(Some(&issue(Some("no marker")))),
            RestoreSet::NoRecord(7)
        ));
        assert!(matches!(
            clear_restore(Some(&issue(None))),
            RestoreSet::NoRecord(7)
        ));
        assert!(matches!(
            clear_restore(Some(&issue(Some(
                "<!-- stow-watchdog:disabled broken entry -->"
            )))),
            RestoreSet::Malformed(_)
        ));
    }

    /// The trip list stays exactly the dispatch lanes — `build-crate`
    /// plus the five cron/preheat workflows — each a workflow file the
    /// API names by path.
    #[test]
    fn trip_workflows_are_the_dispatch_lanes() {
        assert_eq!(TRIP_WORKFLOWS.len(), 6);
        assert!(TRIP_WORKFLOWS.contains(&WORKFLOW_FILE));
        assert!(TRIP_WORKFLOWS.iter().all(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("yml"))
        }));
    }

    /// `pipeline_readings`'s evidence path — a build job name
    /// carries the target verbatim, logs classify through `runs`'s
    /// table.
    #[test]
    fn build_job_name_parses() {
        let label = runs::task_label("build serde_json 1.0.149 (aarch64-apple-darwin)")
            .expect("task label");
        assert_eq!(label.target, "aarch64-apple-darwin");
        assert_eq!(label.crate_name, "serde_json");
        assert_eq!(label.version, "1.0.149");
    }

    // ===== `ensure_label` against a real client on a loopback =====
    //
    // The #565 regression suite: zenwave lifts 4xx/5xx into
    // `Err(Error::Http)` at `.await`, so the scripted steps below feed
    // the real default client through the pinned Hyper error path — no
    // mock, no other backend. Each server is owned by its test, joined
    // for the captured requests, and bounded by `test_server`'s
    // own connection/join timeouts.

    /// The captured request at `index` — method and path, in order.
    fn request_at(
        heads: &[crate::test_server::CapturedRequest],
        index: usize,
    ) -> (&http::Method, &str) {
        let head = &heads[index].head;
        (&head.method, head.uri.path())
    }

    /// `GET /labels/incident` 200 → no mutation at all.
    #[tokio::test]
    async fn present_incident_label_costs_one_get() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 200,
            retry_after: None,
            body: r#"{"id":123,"name":"incident","color":"B60205","default":false}"#,
        }])
        .await;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ensure_label(
                &server.url,
                "test-token",
                std::time::Duration::from_secs(30),
            ),
        )
        .await
        .expect("ensure_label completes within the deadline")
        .expect("a present label is success");
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
        assert_eq!(
            request_at(&heads, 0),
            (&http::Method::GET, "/repos/water-rs/stow/labels/incident")
        );
    }

    /// A 200 naming a different entity is not the label's presence —
    /// fail rather than silently accept it.
    #[tokio::test]
    async fn mismatched_label_name_fails() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 200,
            retry_after: None,
            body: r#"{"id":124,"name":"incidents","color":"B60205","default":false}"#,
        }])
        .await;
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ensure_label(
                &server.url,
                "test-token",
                std::time::Duration::from_secs(30),
            ),
        )
        .await
        .expect("ensure_label completes within the deadline")
        .expect_err("a different entity is not `incident`");
        assert!(error.contains("is not"), "unexpected error: {error}");
        server.join().await;
    }

    /// 404 → exactly one bounded `POST /labels` accepted at 201.
    #[tokio::test]
    async fn missing_incident_label_posts_once() {
        let server = crate::test_server::Loopback::start(vec![
            crate::test_server::Step::Respond {
                status: 404,
                retry_after: None,
                body: r#"{"message":"Not Found","documentation_url":"https://docs.github.com"}"#,
            },
            crate::test_server::Step::Respond {
                status: 201,
                retry_after: None,
                body: r#"{"id":123,"name":"incident","color":"B60205","default":false}"#,
            },
        ])
        .await;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ensure_label(
                &server.url,
                "test-token",
                std::time::Duration::from_secs(30),
            ),
        )
        .await
        .expect("ensure_label completes within the deadline")
        .expect("a missing label is created");
        let heads = server.join().await;
        assert_eq!(heads.len(), 2);
        assert_eq!(
            request_at(&heads, 0),
            (&http::Method::GET, "/repos/water-rs/stow/labels/incident")
        );
        assert_eq!(
            request_at(&heads, 1),
            (&http::Method::POST, "/repos/water-rs/stow/labels")
        );
    }

    /// The primary rate limit is a settled "not yet", on the read and
    /// on the write alike — each waits out the reset it names and the
    /// label still lands, all inside the request bound.
    #[tokio::test]
    async fn rate_limited_label_calls_wait_out_the_reset() {
        let server = crate::test_server::Loopback::start(vec![
            crate::test_server::Step::RateLimited {
                status: 403,
                reset_in: 1,
                body: "{}",
            },
            crate::test_server::Step::Respond {
                status: 404,
                retry_after: None,
                body: r#"{"message":"Not Found"}"#,
            },
            crate::test_server::Step::RateLimited {
                status: 403,
                reset_in: 1,
                body: "{}",
            },
            crate::test_server::Step::Respond {
                status: 201,
                retry_after: None,
                body: r#"{"id":123,"name":"incident","color":"B60205","default":false}"#,
            },
        ])
        .await;
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            ensure_label(
                &server.url,
                "test-token",
                std::time::Duration::from_secs(30),
            ),
        )
        .await
        .expect("ensure_label completes within the deadline")
        .expect("the limits are waited out and the label lands");
        let heads = server.join().await;
        assert_eq!(heads.len(), 4);
    }

    /// The racing create: 422 whose every validation row is
    /// `Label`/`name`/`already_exists` — GitHub's own duplicate body.
    #[tokio::test]
    async fn concurrent_label_create_is_success() {
        let server = crate::test_server::Loopback::start(vec![
            crate::test_server::Step::Respond {
                status: 404,
                retry_after: None,
                body: r#"{"message":"Not Found"}"#,
            },
            crate::test_server::Step::Respond {
                status: 422,
                retry_after: None,
                body: r#"{"message":"Validation Failed","errors":[{"resource":"Label","code":"already_exists","field":"name","message":"name already exists"}],"documentation_url":"https://docs.github.com/rest/issues/labels"}"#,
            },
        ])
        .await;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ensure_label(
                &server.url,
                "test-token",
                std::time::Duration::from_secs(30),
            ),
        )
        .await
        .expect("ensure_label completes within the deadline")
        .expect("a concurrent duplicate is the race win");
        let heads = server.join().await;
        assert_eq!(heads.len(), 2);
    }

    /// Every other 422 stays a failure: another rule, a mixed body,
    /// an empty `errors`, a missing `errors` — none is the race.
    #[tokio::test]
    async fn other_422_validation_failures_propagate() {
        let bodies = [
            // another rule rejected the name
            r#"{"message":"Validation Failed","errors":[{"resource":"Label","code":"custom","field":"name","message":"name is disallowed"}]}"#,
            // already_exists alongside an unrelated row
            r#"{"message":"Validation Failed","errors":[{"resource":"Label","code":"already_exists","field":"name"},{"resource":"Label","code":"custom","field":"color","message":"color is invalid"}]}"#,
            // an empty errors array names nothing
            r#"{"message":"Validation Failed","errors":[]}"#,
            // no errors array at all — malformed for the gate
            r#"{"message":"Validation Failed"}"#,
        ];
        for body in bodies {
            let server = crate::test_server::Loopback::start(vec![
                crate::test_server::Step::Respond {
                    status: 404,
                    retry_after: None,
                    body: r#"{"message":"Not Found"}"#,
                },
                crate::test_server::Step::Respond {
                    status: 422,
                    retry_after: None,
                    body,
                },
            ])
            .await;
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                ensure_label(
                    &server.url,
                    "test-token",
                    std::time::Duration::from_secs(30),
                ),
            )
            .await
            .expect("ensure_label completes within the deadline")
            .expect_err("non-duplicate 422s stay failures");
            let heads = server.join().await;
            assert_eq!(heads.len(), 2);
        }
    }

    /// A non-2xx on the POST that is not the duplicate race — 403 on
    /// create — propagates rather than being read as success.
    #[tokio::test]
    async fn forbidden_label_create_fails() {
        let server = crate::test_server::Loopback::start(vec![
            crate::test_server::Step::Respond {
                status: 404,
                retry_after: None,
                body: r#"{"message":"Not Found"}"#,
            },
            crate::test_server::Step::Respond {
                status: 403,
                retry_after: None,
                body: r#"{"message":"Forbidden"}"#,
            },
        ])
        .await;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ensure_label(
                &server.url,
                "test-token",
                std::time::Duration::from_secs(30),
            ),
        )
        .await
        .expect("ensure_label completes within the deadline")
        .expect_err("a forbidden create is a failure");
        server.join().await;
    }

    /// Authorization and server failures on the named GET propagate —
    /// neither is the missing case. A 403 is terminal after one
    /// request; a 500 is transient under the shared read policy and its
    /// error surfaces only once the four-attempt budget is spent.
    #[tokio::test]
    async fn label_get_failures_propagate() {
        for (status, attempts) in [(403u16, 1usize), (500, 4)] {
            let server = crate::test_server::Loopback::start(
                (0..attempts)
                    .map(|_| crate::test_server::Step::Respond {
                        status,
                        retry_after: None,
                        body: r#"{"message":"broken"}"#,
                    })
                    .collect(),
            )
            .await;
            tokio::time::timeout(
                std::time::Duration::from_secs(20),
                ensure_label(
                    &server.url,
                    "test-token",
                    std::time::Duration::from_secs(30),
                ),
            )
            .await
            .expect("ensure_label completes within the deadline")
            .expect_err("a non-404 GET failure propagates");
            let heads = server.join().await;
            assert_eq!(heads.len(), attempts, "status {status}");
        }
    }

    /// A 200 whose headers land but whose body never completes must die
    /// on the request deadline — the named-label read is bounded end to
    /// end, not just to the headers.
    #[tokio::test]
    async fn a_stalled_label_body_fails_inside_the_deadline() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Stall {
            status: 200,
            body: r#"{"id":123,"name":"inci"#,
            content_length: 256,
        }])
        .await;
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ensure_label(
                &server.url,
                "test-token",
                std::time::Duration::from_millis(400),
            ),
        )
        .await
        .expect("ensure_label completes within the deadline")
        .expect_err("a stalled body is a failure, not a hang");
        assert!(error.contains("timed out"), "unexpected error: {error}");
        server.join().await;
    }

    /// The issue channel's failure folds into `IssueOutcome` instead of
    /// aborting `update_incident` — the mail path afterwards never sees
    /// the error, and the channel stops before touching anything else.
    #[tokio::test]
    async fn issue_channel_error_stays_off_the_mail_path() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 403,
            retry_after: None,
            body: r#"{"message":"Forbidden"}"#,
        }])
        .await;
        let mut outcome = ApplyOutcome::default();
        let issue = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            update_incident(
                GhChannel {
                    api_base: &server.url,
                    token: "test-token",
                },
                OffsetDateTime::now_utc(),
                "stow incident: cf.do.rows_written",
                &[],
                &[],
                &BTreeSet::new(),
                &mut outcome,
            ),
        )
        .await
        .expect("update_incident completes within the deadline")
        .expect("the issue channel's failure is not fatal");
        assert!(
            issue
                .failure
                .as_deref()
                .is_some_and(|f| f.contains("label:")),
            "expected the label failure in the outcome, got {:?}",
            issue.failure
        );
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
    }

    // ----- liveness signals -----

    fn hours_ago(now: OffsetDateTime, hours: f64) -> OffsetDateTime {
        #[allow(clippy::cast_possible_truncation)]
        let secs = (hours * 3600.0) as i64;
        now - time::Duration::seconds(secs)
    }

    fn verdict_of(reading: &Reading) -> Verdict {
        verdict(reading)
    }

    /// The 2026-10-29 outage: a preheat 26h or older breaches, a fresher
    /// one is clear, and no successful run ever is a breach reading
    /// "never".
    #[test]
    fn preheat_stale_fires_at_the_operator_age() {
        let now = october_29();
        let url = "https://github.com/water-rs/stow/actions/runs/1";
        let fresh = preheat_stale_reading(now, Some((hours_ago(now, 25.9), url)), 26.0);
        assert_eq!(verdict_of(&fresh), Verdict::Clear);
        let stale = preheat_stale_reading(now, Some((hours_ago(now, 26.0), url)), 26.0);
        assert_eq!(verdict_of(&stale), Verdict::Breach);
        let never = preheat_stale_reading(now, None, 26.0);
        assert_eq!(verdict_of(&never), Verdict::Breach);
        assert_eq!(signal_report(&never).observed, "never");
        // The operator's level replaces the default, in both directions.
        let tight = preheat_stale_reading(now, Some((hours_ago(now, 5.0), url)), 4.0);
        assert_eq!(verdict_of(&tight), Verdict::Breach);
        let loose = preheat_stale_reading(now, Some((hours_ago(now, 30.0), url)), 48.0);
        assert_eq!(verdict_of(&loose), Verdict::Clear);
        // It alerts and never trips.
        let decision = decide(&[stale], &[]);
        assert!(decision.incident);
        assert_eq!(decision.tripped, [] as [usize; 0]);
        assert_eq!(decision.alerting.len(), 1);
    }

    fn queue(ready: u32, in_flight: usize, cap: usize, frozen: bool) -> BuildQueue {
        BuildQueue {
            ready,
            in_flight,
            cap,
            frozen,
        }
    }

    /// Ready work, a free slot and no run started inside the window
    /// breaches — the state `failure_rate` reports as `skipped`.
    #[test]
    fn builds_stalled_fires_with_ready_work_and_no_recent_run() {
        let now = october_29();
        let url = "https://github.com/water-rs/stow/actions/runs/2";
        let idle = |latest, q| builds_stalled_reading(now, &q, latest, 2.0);

        let stalled = idle(Some((hours_ago(now, 6.0), url)), queue(40, 0, 20, false));
        assert_eq!(verdict_of(&stalled), Verdict::Breach);
        let none_ever = idle(None, queue(40, 0, 20, false));
        assert_eq!(verdict_of(&none_ever), Verdict::Breach);

        // A run started inside the window keeps it clear.
        let busy = idle(Some((hours_ago(now, 1.9), url)), queue(40, 3, 20, false));
        assert_eq!(verdict_of(&busy), Verdict::Clear);
        // Nothing dispatchable: the signal abstains, whatever the age.
        let empty = idle(Some((hours_ago(now, 30.0), url)), queue(0, 0, 20, false));
        assert_eq!(verdict_of(&empty), Verdict::Skipped);
        // A full pool and an engaged freeze explain the idle.
        let full = idle(Some((hours_ago(now, 30.0), url)), queue(40, 20, 20, false));
        assert_eq!(verdict_of(&full), Verdict::Clear);
        let frozen = idle(Some((hours_ago(now, 30.0), url)), queue(40, 0, 20, true));
        assert_eq!(verdict_of(&frozen), Verdict::Clear);
        // The operator's window replaces the default.
        let wide = builds_stalled_reading(
            now,
            &queue(40, 0, 20, false),
            Some((hours_ago(now, 6.0), url)),
            12.0,
        );
        assert_eq!(verdict_of(&wide), Verdict::Clear);

        // With no build events, failure_rate abstains and this reports.
        let readings = [reading("pipeline.failure_rate", 0, 0.0), stalled];
        let decision = decide(&readings, &[]);
        assert_eq!(decision.skipped, [0]);
        assert_eq!(decision.alerting, [1]);
        assert_eq!(decision.tripped, [] as [usize; 0]);
    }

    #[test]
    fn liveness_levels_parse_with_defaults_and_no_ceiling() {
        assert_eq!(
            LivenessLevels::parse(None, Some("  ")).unwrap(),
            LivenessLevels {
                preheat_max_age_hours: 26.0,
                build_stall_hours: 2.0
            }
        );
        assert_eq!(
            LivenessLevels::parse(Some("100000"), Some("0.5")).unwrap(),
            LivenessLevels {
                preheat_max_age_hours: 100_000.0,
                build_stall_hours: 0.5
            }
        );
        assert!(LivenessLevels::parse(Some("a day"), None).is_err());
        assert!(LivenessLevels::parse(None, Some("inf")).is_err());
    }

    /// The runs listing's row shape decodes into the stamps both signals
    /// read, extra fields ignored, and an empty listing is no run.
    #[test]
    fn run_listing_decodes_to_stamps() {
        let page: github::RunsPage<GhRunStamp> = serde_json::from_str(
            r#"{"total_count":1,"workflow_runs":[{"id":7,"name":"Preheat popular crates",
            "html_url":"https://github.com/water-rs/stow/actions/runs/7",
            "created_at":"2026-10-28T00:01:10Z","updated_at":"2026-10-28T00:41:02Z",
            "conclusion":"success"}]}"#,
        )
        .unwrap();
        let run = page.workflow_runs.into_iter().next().unwrap();
        assert_eq!(run.created_at.unix_timestamp(), 1_793_145_670);
        assert_eq!(run.updated_at.unix_timestamp(), 1_793_148_062);
        let empty: github::RunsPage<GhRunStamp> =
            serde_json::from_str(r#"{"total_count":0,"workflow_runs":[]}"#).unwrap();
        assert!(empty.workflow_runs.is_empty());
    }

    fn failed_op<'a>(
        now: OffsetDateTime,
        ago: f64,
        name: &'a str,
        url: &'a str,
    ) -> OperationRun<'a> {
        OperationRun {
            concluded: hours_ago(now, ago),
            conclusion: "failure",
            name,
            url,
        }
    }

    /// A failed operations run is reported when it concluded after the
    /// previous watchdog run started, or inside the operator's window,
    /// whichever reaches further back; it names the run and its argv.
    #[test]
    fn operations_failed_reports_runs_since_the_previous_watchdog_run() {
        let now = october_29();
        let reset = failed_op(
            now,
            0.1,
            r#"stow-admin ["scheduler","reset","--yes"] (by lexoliu)"#,
            "https://github.com/water-rs/stow/actions/runs/11",
        );
        let older = failed_op(
            now,
            0.6,
            r#"stow-admin ["queue","purge","--yes"] (by lexoliu)"#,
            "https://github.com/water-rs/stow/actions/runs/10",
        );
        let runs = [older, reset];
        let previous = Some(hours_ago(now, 0.25));

        // 15 minutes back with a 6-minute window: only the newer run.
        let recent = operations_failed_reading(now, previous, 0.1, &runs);
        assert_eq!(verdict_of(&recent), Verdict::Breach);
        assert!((recent.value - 1.0).abs() < f64::EPSILON);
        assert!(recent.evidence[0].contains(r#"["scheduler","reset","--yes"]"#));
        assert!(recent.evidence[0].contains("actions/runs/11"));

        // The default hour reaches the older run too, newest first.
        let hour = operations_failed_reading(now, previous, 1.0, &runs);
        assert!((hour.value - 2.0).abs() < f64::EPSILON);
        assert!(hour.evidence[0].contains("actions/runs/11"));

        // A missed dispatch widens the read to the previous run's start.
        let gap = operations_failed_reading(now, Some(hours_ago(now, 3.0)), 0.1, &runs);
        assert!((gap.value - 2.0).abs() < f64::EPSILON);

        // No previous run: the window alone decides; nothing in it is clear.
        let first = operations_failed_reading(now, None, 0.2, &runs);
        assert!((first.value - 1.0).abs() < f64::EPSILON);
        let none = operations_failed_reading(now, previous, 0.1, &[older]);
        assert_eq!(verdict_of(&none), Verdict::Clear);
        assert_eq!(none.evidence, [] as [String; 0]);

        // It alerts and never trips.
        let decision = decide(&[recent], &[]);
        assert!(decision.incident);
        assert_eq!(decision.tripped, [] as [usize; 0]);
        assert_eq!(decision.alerting.len(), 1);
    }

    /// Failure, timeout and a run that never started are reported; a
    /// success, a cancellation and an unfinished conclusion are not.
    #[test]
    fn operations_failed_keeps_failure_timeout_and_startup_failure() {
        let now = october_29();
        let url = "https://github.com/water-rs/stow/actions/runs/30";
        let run = |conclusion| OperationRun {
            concluded: hours_ago(now, 0.1),
            conclusion,
            name: r#"stow-admin ["queue","purge","--yes"] (by lexoliu)"#,
            url,
        };
        for conclusion in ["failure", "timed_out", "startup_failure"] {
            let reading = operations_failed_reading(now, None, 1.0, &[run(conclusion)]);
            assert_eq!(verdict_of(&reading), Verdict::Breach, "{conclusion}");
            assert!(reading.evidence[0].contains(conclusion), "{conclusion}");
        }
        for conclusion in ["success", "cancelled", "skipped", ""] {
            let reading = operations_failed_reading(now, None, 1.0, &[run(conclusion)]);
            assert_eq!(verdict_of(&reading), Verdict::Clear, "{conclusion}");
        }
    }

    /// A previous run that started 45 minutes or more ago breaches at
    /// the default level, the operator's level replaces it, and the
    /// first run on record abstains.
    #[test]
    fn watchdog_gap_fires_at_the_operator_level() {
        let now = october_29();
        let url = "https://github.com/water-rs/stow/actions/runs/20";
        let gap = |minutes: f64, level| {
            watchdog_gap_reading(now, Some((hours_ago(now, minutes / 60.0), url)), level)
        };
        assert_eq!(verdict_of(&gap(44.0, 0.75)), Verdict::Clear);
        let missed = gap(45.0, 0.75);
        assert_eq!(verdict_of(&missed), Verdict::Breach);
        assert!(missed.evidence[0].contains("actions/runs/20"));
        assert_eq!(verdict_of(&gap(30.0, 0.25)), Verdict::Breach);
        assert_eq!(verdict_of(&gap(180.0, 4.0)), Verdict::Clear);
        let first = watchdog_gap_reading(now, None, 0.75);
        assert_eq!(verdict_of(&first), Verdict::Skipped);
        let decision = decide(&[missed], &[]);
        assert!(decision.incident);
        assert_eq!(decision.tripped, [] as [usize; 0]);
    }

    #[test]
    fn history_levels_parse_with_defaults_and_no_ceiling() {
        assert_eq!(
            HistoryLevels::parse(None, Some("  ")).unwrap(),
            HistoryLevels {
                operations_window_hours: 1.0,
                run_gap_hours: 0.75
            }
        );
        assert_eq!(
            HistoryLevels::parse(Some("100000"), Some("0.1")).unwrap(),
            HistoryLevels {
                operations_window_hours: 100_000.0,
                run_gap_hours: 0.1
            }
        );
        assert!(HistoryLevels::parse(Some("an hour"), None).is_err());
        assert!(HistoryLevels::parse(None, Some("inf")).is_err());
    }

    /// The history rows carry the run-name and the conclusion.
    #[test]
    fn run_listing_decodes_the_run_name_and_conclusion() {
        let page: github::RunsPage<GhRunStamp> = serde_json::from_str(
            r#"{"total_count":1,"workflow_runs":[{"id":9,"name":"stow-admin [\"queue\"] (by a)",
            "display_title":"stow-admin [\"queue\"] (by a)",
            "html_url":"https://github.com/water-rs/stow/actions/runs/9",
            "created_at":"2026-10-28T00:01:10Z","updated_at":"2026-10-28T00:41:02Z",
            "conclusion":"failure"}]}"#,
        )
        .unwrap();
        let run = page.workflow_runs.into_iter().next().unwrap();
        assert_eq!(run.display_title, r#"stow-admin ["queue"] (by a)"#);
        assert_eq!(run.conclusion.as_deref(), Some("failure"));
    }
}
