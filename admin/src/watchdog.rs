//! `stow-admin watchdog` — the external breaker of issue #450.
//!
//! Each run measures four signal groups — Cloudflare usage against the
//! hourly share of the monthly included allowances, edge health (Worker
//! invocation statuses, DO resource failures, `overloaded` events), the
//! build pipeline (build-crate failure rate, dispatch retries, pending
//! age, dispatch stalls), and the public endpoints — then acts on the
//! verdict: `Trip` breaches disable the dispatching workflows and enable
//! the zone's `stow maintenance: anonymous` WAF rule, and any breach opens
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
//! GraphQL POST, one Analytics Engine SQL POST, ≤3 admin/endpoint calls,
//! ≤ `1 + MAX_CLASSIFIED_RUNS*2` GitHub REST reads, and, only while an
//! incident is open, ≤8 REST mutations plus one email — idle runs issue
//! no mutations at all.

use std::fmt::Write as _;

use askama::Template;
use clap::{Args, Subcommand};
use stow_types::api::AdminStatus;
use stow_types::stow_error;

use crate::maintenance::{self, CF_ZONE_ID_ENV, CLOUDFLARE_API_TOKEN_ENV, MaintenanceScope};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zenwave::{Client, ResponseExt};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum Effect {
    /// Breach trips the breaker: maintenance rule on, dispatching workflows
    /// disabled.
    Trip,
    /// Breach opens/updates the incident and alerts; nothing is cut.
    Alert,
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
    /// Seconds of history the measurement covers; `0` is a point-in-time
    /// check.
    window_secs: u64,
    /// Smallest sample the measurement needs before its verdict counts —
    /// below it the signal reports `skipped`, never `clear` or `breach`.
    /// For rates the sample is the denominator (requests, runs); for
    /// counts and point checks it is `0`.
    min_sample: u64,
    /// Observed value at or above which the signal breaches.
    threshold: f64,
    /// Unit for rendered values ("rows", "%", "ms", "s", "runs").
    unit: &'static str,
    effect: Effect,
}

/// Hours in the monthly allowance window — the hourly budget each usage
/// signal compares last-hour consumption against is `monthly / 720`.
/// Thirty days is the convention `edge/src/cost.rs` (#451) uses for its
/// daily budgets, so both layers share the allowance model.
const HOURS_PER_MONTH: f64 = 720.0;

// Monthly included allowances, per Cloudflare's published pricing
// (verified against the docs 2026-09-28; `edge/src/cost.rs` carries the
// same table for the in-edge daily budgets):
// - Workers Paid — 10M requests/mo, 30M CPU ms/mo. Per the Workers
//   pricing footnote, subrequests are not billed, so `subrequests` is
//   collected as diagnostic context only.
//   <https://developers.cloudflare.com/workers/platform/pricing/>
// - Durable Objects Paid — 1M requests/mo, 400k GB-s duration/mo,
//   25G rows read/mo, 50M rows written/mo (SQLite storage billing).
//   `activeTime` and `cpuTime` are collected as diagnostics.
//   <https://developers.cloudflare.com/durable-objects/platform/pricing/>
// - D1 Paid — 25G rows read/mo, 50M rows written/mo.
//   <https://developers.cloudflare.com/d1/platform/pricing/>
const DO_ROWS_READ_MONTHLY: f64 = 25e9;
const DO_ROWS_WRITTEN_MONTHLY: f64 = 50e6;
const DO_REQUESTS_MONTHLY: f64 = 1e6;
const DO_DURATION_GB_S_MONTHLY: f64 = 400e3;
const WORKER_REQUESTS_MONTHLY: f64 = 10e6;
const WORKER_CPU_MS_MONTHLY: f64 = 30e6;
const D1_ROWS_READ_MONTHLY: f64 = 25e9;
const D1_ROWS_WRITTEN_MONTHLY: f64 = 50e6;

/// One hour — the usage window. An hourly window trips a sustained burn
/// to the monthly allowance's hourly share within an hour instead of
/// end-of-month; point checks and the 15-minute health window are the
/// exceptions below.
const HOUR: u64 = 3600;
/// The edge-health window — 15 minutes, matching the run cadence, so a
/// burst that straddles two cron runs is still seen whole.
const QUARTER_HOUR: u64 = 900;

/// The threshold table — every signal's window, minimum sample,
/// threshold and trip/alert effect in one place.
const SIGNALS: &[Signal] = &[
    // ── Cloudflare usage, billed dimensions — breach trips ──
    Signal {
        id: "cf.do.rows_read",
        label: "DO rows read/h vs hourly share of the 25G/mo allowance",
        window_secs: HOUR,
        min_sample: 0,
        threshold: DO_ROWS_READ_MONTHLY / HOURS_PER_MONTH,
        unit: "rows",
        effect: Effect::Trip,
    },
    Signal {
        id: "cf.do.rows_written",
        label: "DO rows written/h vs hourly share of the 50M/mo allowance",
        window_secs: HOUR,
        min_sample: 0,
        threshold: DO_ROWS_WRITTEN_MONTHLY / HOURS_PER_MONTH,
        unit: "rows",
        effect: Effect::Trip,
    },
    Signal {
        id: "cf.do.duration_gb_s",
        label: "DO billed duration/h vs hourly share of the 400k GB-s/mo allowance",
        window_secs: HOUR,
        min_sample: 0,
        threshold: DO_DURATION_GB_S_MONTHLY / HOURS_PER_MONTH,
        unit: "GB-s",
        effect: Effect::Trip,
    },
    Signal {
        id: "cf.do.requests",
        label: "DO requests/h vs hourly share of the 1M/mo allowance",
        window_secs: HOUR,
        min_sample: 0,
        threshold: DO_REQUESTS_MONTHLY / HOURS_PER_MONTH,
        unit: "requests",
        effect: Effect::Trip,
    },
    Signal {
        id: "cf.d1.rows_read",
        label: "D1 rows read/h vs hourly share of the 25G/mo allowance",
        window_secs: HOUR,
        min_sample: 0,
        threshold: D1_ROWS_READ_MONTHLY / HOURS_PER_MONTH,
        unit: "rows",
        effect: Effect::Trip,
    },
    Signal {
        id: "cf.d1.rows_written",
        label: "D1 rows written/h vs hourly share of the 50M/mo allowance",
        window_secs: HOUR,
        min_sample: 0,
        threshold: D1_ROWS_WRITTEN_MONTHLY / HOURS_PER_MONTH,
        unit: "rows",
        effect: Effect::Trip,
    },
    Signal {
        id: "cf.worker.requests",
        label: "Worker requests/h vs hourly share of the 10M/mo allowance",
        window_secs: HOUR,
        min_sample: 0,
        threshold: WORKER_REQUESTS_MONTHLY / HOURS_PER_MONTH,
        unit: "requests",
        effect: Effect::Trip,
    },
    Signal {
        id: "cf.worker.cpu_ms",
        label: "Worker CPU/h vs hourly share of the 30M ms/mo allowance",
        window_secs: HOUR,
        min_sample: 0,
        threshold: WORKER_CPU_MS_MONTHLY / HOURS_PER_MONTH,
        unit: "ms",
        effect: Effect::Trip,
    },
    // ── edge health — breach alerts, never trips ──
    Signal {
        id: "edge.worker.errors",
        label: "Worker non-success share (scriptThrewException + internalError + exceededResources)",
        window_secs: QUARTER_HOUR,
        min_sample: 100,
        threshold: 2.0,
        unit: "%",
        effect: Effect::Alert,
    },
    Signal {
        id: "edge.worker.exceeded",
        label: "Worker exceededResources + internalError invocations",
        window_secs: QUARTER_HOUR,
        min_sample: 0,
        threshold: 1.0,
        unit: "invocations",
        effect: Effect::Alert,
    },
    Signal {
        id: "edge.do.exceeded",
        label: "DO exceededCpu + exceededMemory + fatalInternalErrors",
        window_secs: HOUR,
        min_sample: 0,
        threshold: 1.0,
        unit: "errors",
        effect: Effect::Alert,
    },
    Signal {
        id: "edge.do.overloaded",
        label: "DO `overloaded` events (Analytics Engine, written by #438)",
        window_secs: HOUR,
        min_sample: 0,
        threshold: 1.0,
        unit: "events",
        effect: Effect::Alert,
    },
    // ── build pipeline ──
    Signal {
        id: "pipeline.failure_rate",
        label: "build-crate failure share of completed runs",
        window_secs: HOUR,
        min_sample: 20,
        threshold: 50.0,
        unit: "%",
        effect: Effect::Trip,
    },
    Signal {
        id: "pipeline.retry_storm",
        label: "build-crate runs at dispatch attempt ≥3",
        window_secs: HOUR,
        min_sample: 0,
        threshold: 10.0,
        unit: "runs",
        effect: Effect::Trip,
    },
    Signal {
        id: "pipeline.oldest_pending",
        label: "oldest pending queue task age",
        window_secs: 0,
        min_sample: 1,
        threshold: 86400.0,
        unit: "s",
        effect: Effect::Alert,
    },
    Signal {
        id: "pipeline.dispatch_stall",
        label: "pending tasks with free slots and nothing dispatched",
        window_secs: HOUR,
        min_sample: 1,
        threshold: 1.0,
        unit: "stalled",
        effect: Effect::Alert,
    },
    // ── public endpoints — alert ──
    Signal {
        id: "endpoint.stats",
        label: "GET /api/v1/stats answers 200",
        window_secs: 0,
        min_sample: 1,
        threshold: 5000.0,
        unit: "ms",
        effect: Effect::Alert,
    },
    Signal {
        id: "endpoint.artifact",
        label: "HEAD of a real artifact byte path answers 200",
        window_secs: 0,
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
    /// total requests for a rate, completed runs for a failure rate, `1`
    /// for a point check, pending count for the dispatch stall.
    sample: u64,
    /// The measured value in the signal's unit.
    value: f64,
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

fn verdict(reading: &Reading) -> Verdict {
    if reading.sample < reading.signal.min_sample {
        Verdict::Skipped
    } else if reading.value >= reading.signal.threshold {
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
            Verdict::Breach if reading.signal.effect == Effect::Trip => tripped.push(index),
            Verdict::Breach => alerting.push(index),
            Verdict::Skipped => skipped.push(index),
            Verdict::Clear => {}
        }
    }
    Decision {
        incident: !tripped.is_empty() || !alerting.is_empty() || !collect_failures.is_empty(),
        tripped,
        alerting,
        skipped,
    }
}

// ===== Collection =====

/// Cloudflare credentials/env the analytics calls need.
const CF_ACCOUNT_ID_ENV: &str = "CF_ACCOUNT_ID";
const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";
/// The Worker script name the Workers metrics filter on — must match
/// `cloudflare.name` in `edge/Skyzen.toml`.
const WORKER_SCRIPT_NAME: &str = "stow-edge";

/// Bound on per-run GitHub log classification — each classified failed
/// run costs one jobs call plus one log call, so a pathological failure
/// storm is reported at the cap instead of burning the job's minutes.
const MAX_CLASSIFIED_RUNS: usize = 25;
/// Actions runner capacity, used by the dispatch-stall signal —
/// AGENTS.md states 60 concurrent runners.
const RUNNER_CAPACITY: usize = 60;

/// Dispatching workflows a trip disables — everything that can start a
/// build wave or move the index: `build-crate`, the index cron, and
/// every preheat lane.
const TRIP_WORKFLOWS: &[&str] = &[
    "build-crate.yml",
    "index-publish-cron.yml",
    "preheat-admin.yml",
    "preheat-cron.yml",
    "preheat-missed.yml",
    "preheat-projects.yml",
];

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
    now: OffsetDateTime,
}

impl Watcher<'_> {
    /// Gather every signal; a collector that fails records a
    /// [`CollectFailure`] — one blind spot never hides the signals that
    /// did read.
    async fn collect(&self) -> (Vec<Reading>, Vec<CollectFailure>) {
        let mut readings = Vec::new();
        let mut failures = Vec::new();
        // Sequential collectors keep a run at ~20 outbound calls total —
        // deliberate under AGENTS.md's spend rules, and each batch
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
        gather!("cloudflare-usage", self.cf_readings());
        gather!("overloaded-events", self.overloaded_reading());
        gather!("pipeline", self.pipeline_readings());
        gather!("queue", self.queue_readings());
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

    /// One GraphQL POST yields every Cloudflare reading: the billed-usage
    /// trips plus the DO/Worker health alerts.
    async fn cf_readings(&self) -> Result<Vec<Reading>, String> {
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
        let usage = self
            .cf_graphql(
                &format_time(since_hour),
                &format_time(since_quarter),
                &format_time(self.now),
            )
            .await?;
        Ok(usage.readings())
    }

    /// POST the usage query and decode it into a typed snapshot. A
    /// GraphQL `errors` array is a hard error — never a partial read.
    async fn cf_graphql(
        &self,
        since_hour: &str,
        since_quarter: &str,
        now: &str,
    ) -> Result<CfSnapshot, String> {
        let body = GraphqlRequest {
            query: WATCHDOG_QUERY,
            variables: QueryVars {
                account_tag: self.account.to_owned(),
                script_name: WORKER_SCRIPT_NAME.to_owned(),
                since_hour: since_hour.to_owned(),
                since_quarter: since_quarter.to_owned(),
                now: now.to_owned(),
            },
        };
        let url = format!("{CLOUDFLARE_API_BASE}/graphql");
        let mut client = zenwave::client().timeout(std::time::Duration::from_secs(45));
        let response = client
            .post(&url)
            .and_then(|request| {
                request.header("Authorization", format!("Bearer {}", self.cf_token))
            })
            .and_then(|request| request.json_body(&body))
            .map_err(|error| format!("POST {url}: {error}"))?
            .await
            .map_err(|error| format!("POST {url}: {error}"))?
            .error_for_status()
            .await
            .map_err(|error| format!("POST {url}: {error}"))?;
        let envelope: GraphqlResponse = response
            .into_json()
            .await
            .map_err(|error| format!("decode {url}: {error}"))?;
        if let Some(errors) = envelope.errors
            && !errors.is_empty()
        {
            let messages = errors
                .iter()
                .map(|error| error.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!("GraphQL errors: {messages}"));
        }
        let account = envelope
            .data
            .and_then(|data| data.viewer.accounts.into_iter().next())
            .ok_or_else(|| "GraphQL response carried no account data".to_owned())?;
        Ok(CfSnapshot::from(account))
    }

    // ----- Analytics Engine: DO overloaded events -----

    /// `stow_events` `blob1='overloaded'` count over the hour — the edge
    /// writes the event at the point it catches a DO `overloaded` error
    /// (#438); until that writer lands the count is legitimately 0.
    async fn overloaded_reading(&self) -> Result<Vec<Reading>, String> {
        let query = "SELECT count() AS events FROM stow_events \
                     WHERE blob1 = 'overloaded' \
                     AND timestamp >= NOW() - INTERVAL '1' HOUR \
                     FORMAT JSON";
        let url = format!(
            "{CLOUDFLARE_API_BASE}/accounts/{}/analytics_engine/sql",
            self.account
        );
        let mut client = zenwave::client().timeout(std::time::Duration::from_secs(45));
        let response = client
            .post(&url)
            .and_then(|request| {
                request.header("Authorization", format!("Bearer {}", self.cf_token))
            })
            .map(|request| request.bytes_body(query.as_bytes().to_vec()))
            .map_err(|error| format!("POST {url}: {error}"))?
            .await
            .map_err(|error| format!("POST {url}: {error}"))?
            .error_for_status()
            .await
            .map_err(|error| format!("POST {url}: {error}"))?;
        let envelope: AnalyticsResponse = response
            .into_json()
            .await
            .map_err(|error| format!("decode {url}: {error}"))?;
        let events = envelope.data.first().map_or(0.0, |row| row.events);
        let signal = signal("edge.do.overloaded");
        Ok(vec![Reading {
            signal,
            sample: 1,
            value: events,
            evidence: vec![format!(
                "stow_events blob1='overloaded' last hour: {events:.0}"
            )],
        }])
    }

    // ----- GitHub pipeline -----

    /// build-crate completed runs over the hour → failure rate and
    /// dispatch-retry signals, with per-target and per-class evidence.
    async fn pipeline_readings(&self) -> Result<Vec<Reading>, String> {
        let since = self
            .now
            .checked_sub(time::Duration::seconds(
                i64::try_from(HOUR).unwrap_or(i64::MAX),
            ))
            .ok_or("window underflow")?;
        let since_text = since
            .format(&Rfc3339)
            .map_err(|error| format!("format window: {error}"))?;
        let runs = fetch_completed_runs(self.gh_token, &since_text).await?;
        let completed = u64::try_from(runs.len()).unwrap_or(u64::MAX);
        let failed: Vec<&GhRun> = runs
            .iter()
            .filter(|run| run.conclusion.as_deref() == Some("failure"))
            .collect();
        #[allow(clippy::cast_precision_loss)]
        let failure_rate = if completed == 0 {
            0.0
        } else {
            failed.len() as f64 / completed as f64 * 100.0
        };
        let retrying: Vec<&GhRun> = runs
            .iter()
            .filter(|run| run.run_attempt.unwrap_or(1) >= 3)
            .collect();

        let mut evidence_rate = Vec::new();
        let mut evidence_retry = Vec::new();
        if !failed.is_empty() {
            let (targets, classes) = self.classify_failed(&failed).await;
            if !targets.is_empty() {
                evidence_rate.push(format!("targets: {}", targets.join(", ")));
            }
            if !classes.is_empty() {
                evidence_rate.push(format!("classes: {}", classes.join(", ")));
            }
            for run in failed.iter().take(5) {
                evidence_rate.push(run.html_url.clone());
            }
            if failed.len() > 5 {
                evidence_rate.push(format!("+{} more failed runs", failed.len() - 5));
            }
        }
        for run in retrying.iter().take(5) {
            evidence_retry.push(format!(
                "{} (attempt {})",
                run.html_url,
                run.run_attempt.unwrap_or(1)
            ));
        }
        if retrying.len() > 5 {
            evidence_retry.push(format!("+{} more retried runs", retrying.len() - 5));
        }

        #[allow(clippy::cast_precision_loss)]
        let retried = retrying.len() as f64;
        Ok(vec![
            Reading {
                signal: signal("pipeline.failure_rate"),
                sample: completed,
                value: failure_rate,
                evidence: evidence_rate,
            },
            Reading {
                signal: signal("pipeline.retry_storm"),
                sample: completed,
                value: retried,
                evidence: evidence_retry,
            },
        ])
    }

    /// For each failed run (≤ `MAX_CLASSIFIED_RUNS`), read job names for
    /// the per-target view and fetch the job log for the failure class.
    /// Log fetch failures degrade the evidence, never the signal.
    async fn classify_failed(&self, failed: &[&GhRun]) -> (Vec<String>, Vec<String>) {
        let mut by_target: std::collections::BTreeMap<String, u32> =
            std::collections::BTreeMap::new();
        let mut by_class: std::collections::BTreeMap<&'static str, u32> =
            std::collections::BTreeMap::new();
        for run in failed.iter().take(MAX_CLASSIFIED_RUNS) {
            let jobs: GhJobsPage = match github::get(
                self.gh_token,
                &format!("actions/runs/{}/jobs?per_page=100", run.id),
            )
            .await
            {
                Ok(page) => page,
                Err(error) => {
                    tracing::warn!(run_id = run.id, %error, "jobs fetch failed; skipping");
                    continue;
                }
            };
            for job in &jobs.jobs {
                if job.conclusion.as_deref() != Some("failure") {
                    continue;
                }
                if let Some(target) = job
                    .name
                    .rsplit('(')
                    .next()
                    .and_then(|tail| tail.strip_suffix(')'))
                {
                    *by_target.entry(target.to_owned()).or_default() += 1;
                }
                let log_url = format!(
                    "https://api.github.com/repos/{}/actions/jobs/{}/logs",
                    github::REPO,
                    job.id
                );
                let log = match github::get_text(self.gh_token, &log_url).await {
                    Ok(log) => log,
                    Err(error) => {
                        tracing::warn!(job_id = job.id, %error, "job log unavailable");
                        continue;
                    }
                };
                *by_class.entry(classify_one(&log)).or_default() += 1;
            }
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
    async fn queue_readings(&self) -> Result<Vec<Reading>, String> {
        let status: AdminStatus = self
            .edge
            .get_json("/api/v1/admin/status")
            .await
            .map_err(|error| error.to_string())?;
        let pending = status.pending_miss + status.pending_human;
        let cutoff = sqlite_now_minus(self.now, HOUR);
        let freshest = status
            .in_flight
            .iter()
            .map(|task| task.updated_at.as_str())
            .max()
            .map(str::to_owned);
        let stalled = pending > 0
            && status.in_flight.len() < RUNNER_CAPACITY
            && freshest.as_deref().is_none_or(|at| at < cutoff.as_str());
        let mut stall_evidence = vec![
            format!("pending={pending}"),
            format!("in_flight={}", status.in_flight.len()),
        ];
        if let Some(freshest) = freshest {
            stall_evidence.push(format!("newest dispatch {freshest}"));
        }
        #[allow(clippy::cast_precision_loss)]
        let oldest_pending = status.oldest_pending_seconds.map_or(0.0, |s| s as f64);
        Ok(vec![
            Reading {
                signal: signal("pipeline.oldest_pending"),
                sample: u64::from(status.oldest_pending_seconds.is_some()),
                value: oldest_pending,
                evidence: vec![format!("pending={pending}")],
            },
            Reading {
                signal: signal("pipeline.dispatch_stall"),
                sample: u64::from(pending),
                value: f64::from(u8::from(stalled)),
                evidence: stall_evidence,
            },
        ])
    }

    // ----- public endpoints -----

    /// `GET /api/v1/stats` and a `HEAD` of one real artifact byte path —
    /// the two anonymous answers a user depends on, checked as a user.
    /// Returns the readings plus an optional collector failure — the
    /// admin catalog list failing blinds `endpoint.artifact` while
    /// `endpoint.stats` still gets its probe.
    async fn endpoint_readings(&self) -> (Vec<Reading>, Option<String>) {
        let mut readings = Vec::new();
        readings.push(
            self.probe("endpoint.stats", "/api/v1/stats", zenwave::Method::GET)
                .await,
        );

        // Pick a real artifact so the HEAD exercises the byte path:
        // catalog list (admin) → first record's `target/rustc/c_metadata`.
        match self.pick_artifact().await {
            Ok(Some((target, rustc, c_metadata))) => {
                readings.push(
                    self.probe(
                        "endpoint.artifact",
                        &format!("/api/v1/artifacts/{target}/{rustc}/{c_metadata}"),
                        zenwave::Method::HEAD,
                    )
                    .await,
                );
            }
            Ok(None) => readings.push(Reading {
                signal: signal("endpoint.artifact"),
                sample: 0,
                value: 0.0,
                evidence: vec!["no artifacts in the catalog".to_owned()],
            }),
            Err(error) => {
                return (readings, Some(format!("admin artifact list: {error}")));
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
            sample: 1,
            value,
            evidence: vec![format!("{path} → {status_text} in {latency_ms:.0}ms")],
        }
    }

    /// The newest catalog row's byte-path coordinates, or `None` when
    /// the catalog is empty.
    async fn pick_artifact(&self) -> stow_types::error::Result<Option<(String, String, String)>> {
        let records: Vec<stow_types::api::ArtifactRecord> = self
            .edge
            .get_json("/api/v1/admin/artifacts?limit=1")
            .await?;
        Ok(records.first().map(|record| {
            (
                record.target.as_str().to_owned(),
                record.rustc_version.as_str().to_owned(),
                record.c_metadata.as_str().to_owned(),
            )
        }))
    }
}

/// `now` minus `secs`, rendered the way D1 writes `datetime('now')` —
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
// `errors requests responseBodySize wallTime`, and the DO periodic and
// D1 sums match the uses below.

/// The watchdog's single GraphQL request — one POST covers every
/// dataset: DO periodic sums (usage + resource failures), DO invocations
/// (requests), Worker invocations over the hour (usage) and grouped by
/// invocation status over the last 15 minutes (health), and D1 rows.
const WATCHDOG_QUERY: &str = r"query StowWatchdog($accountTag: String!, $scriptName: String!, $sinceHour: Time!, $sinceQuarter: Time!, $now: Time!) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      doPeriodic: durableObjectsPeriodicGroups(filter: {datetime_geq: $sinceHour, datetime_leq: $now}, limit: 100) {
        sum { activeTime cpuTime duration exceededCpuErrors exceededMemoryErrors fatalInternalErrors rowsRead rowsWritten storageDeletes storageReadUnits storageWriteUnits subrequests }
      }
      doInvoke: durableObjectsInvocationsAdaptiveGroups(filter: {datetime_geq: $sinceHour, datetime_leq: $now}, limit: 100) {
        sum { requests wallTime errors }
      }
      worker: workersInvocationsAdaptive(filter: {datetime_geq: $sinceHour, datetime_leq: $now, scriptName: $scriptName}, limit: 100) {
        sum { clientDisconnects cpuTimeUs duration errors requestDuration requests responseBodySize subrequests wallTime }
      }
      workerStatus: workersInvocationsAdaptive(filter: {datetime_geq: $sinceQuarter, datetime_leq: $now, scriptName: $scriptName}, limit: 100) {
        dimensions { status }
        sum { requests }
      }
      d1: d1AnalyticsAdaptiveGroups(filter: {datetime_geq: $sinceHour, datetime_leq: $now}, limit: 100) {
        sum { rowsRead rowsWritten }
      }
    }
  }
}";

/// The POST body.
#[derive(Debug, serde::Serialize)]
struct GraphqlRequest {
    query: &'static str,
    variables: QueryVars,
}

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

#[derive(Debug, serde::Deserialize)]
struct GraphqlResponse {
    data: Option<GraphqlData>,
    errors: Option<Vec<GraphqlError>>,
}

#[derive(Debug, serde::Deserialize)]
struct GraphqlError {
    message: String,
}

#[derive(Debug, serde::Deserialize)]
struct GraphqlData {
    viewer: GraphqlViewer,
}

#[derive(Debug, serde::Deserialize)]
struct GraphqlViewer {
    accounts: Vec<AccountGroups>,
}

/// The aliased groups of [`WATCHDOG_QUERY`].
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
    #[serde(default)]
    d1: Vec<D1Group>,
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

#[derive(Debug, serde::Deserialize, Default)]
struct D1Group {
    #[serde(default)]
    sum: D1Sum,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct D1Sum {
    #[serde(default)]
    rows_read: f64,
    #[serde(default)]
    rows_written: f64,
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
    d1: D1Sum,
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
        let d1 = groups.d1.iter().fold(D1Sum::default(), |mut acc, group| {
            acc.rows_read += group.sum.rows_read;
            acc.rows_written += group.sum.rows_written;
            acc
        });
        Self {
            do_periodic: fold(groups.do_periodic),
            do_invoke,
            worker,
            worker_status,
            d1,
        }
    }
}

/// Invocation statuses that mean the Worker failed the request.
const WORKER_BAD_STATUSES: &[&str] =
    &["scriptThrewException", "internalError", "exceededResources"];

impl CfSnapshot {
    /// Expand the snapshot into the run's Cloudflare readings — billed
    /// usage as trips, health as alerts, unbilled diagnostics as
    /// evidence on the readings that fire.
    #[allow(clippy::too_many_lines)]
    fn readings(&self) -> Vec<Reading> {
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
                signal: signal("cf.do.rows_read"),
                sample: 1,
                value: self.do_periodic.rows_read,
                evidence: vec![],
            },
            Reading {
                signal: signal("cf.do.rows_written"),
                sample: 1,
                value: self.do_periodic.rows_written,
                evidence: vec![],
            },
            Reading {
                signal: signal("cf.do.duration_gb_s"),
                sample: 1,
                value: self.do_periodic.duration,
                evidence: vec![format!(
                    "activeTime={:.0} cpuTime={:.0} storage: read_units={:.0} write_units={:.0} deletes={:.0} (unbilled context)",
                    self.do_periodic.active_time,
                    self.do_periodic.cpu_time,
                    self.do_periodic.storage_read_units,
                    self.do_periodic.storage_write_units,
                    self.do_periodic.storage_deletes,
                )],
            },
            Reading {
                signal: signal("cf.do.requests"),
                sample: 1,
                value: self.do_invoke.requests,
                evidence: vec![format!(
                    "wallTime={:.0} errors={:.0} subrequests={:.0}",
                    self.do_invoke.wall_time, self.do_invoke.errors, self.do_periodic.subrequests,
                )],
            },
            Reading {
                signal: signal("cf.d1.rows_read"),
                sample: 1,
                value: self.d1.rows_read,
                evidence: vec![],
            },
            Reading {
                signal: signal("cf.d1.rows_written"),
                sample: 1,
                value: self.d1.rows_written,
                evidence: vec![],
            },
            Reading {
                signal: signal("cf.worker.requests"),
                sample: 1,
                value: self.worker.requests,
                evidence: vec![format!(
                    "subrequests={:.0} (not billed per Workers pricing)",
                    self.worker.subrequests
                )],
            },
            Reading {
                signal: signal("cf.worker.cpu_ms"),
                sample: 1,
                value: self.worker.cpu_time_us / 1000.0,
                evidence: vec![format!("errors={:.0}", self.worker.errors)],
            },
            Reading {
                signal: signal("edge.worker.errors"),
                sample: request_sample,
                value: error_share,
                evidence: vec![status_evidence.clone()],
            },
            Reading {
                signal: signal("edge.worker.exceeded"),
                sample: request_sample,
                value: exceeded_requests,
                evidence: vec![status_evidence],
            },
            Reading {
                signal: signal("edge.do.exceeded"),
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
struct AnalyticsResponse {
    #[serde(default)]
    data: Vec<AnalyticsRow>,
}

#[derive(Debug, serde::Deserialize)]
struct AnalyticsRow {
    #[serde(default)]
    events: f64,
}

// ----- GitHub wire types -----

#[derive(Debug, serde::Deserialize)]
struct GhRunsPage {
    #[serde(default)]
    workflow_runs: Vec<GhRun>,
}

#[derive(Debug, serde::Deserialize)]
struct GhRun {
    id: u64,
    html_url: String,
    #[serde(default)]
    conclusion: Option<String>,
    #[serde(default)]
    run_attempt: Option<u32>,
}

#[derive(Debug, serde::Deserialize)]
struct GhJobsPage {
    #[serde(default)]
    jobs: Vec<GhJob>,
}

#[derive(Debug, serde::Deserialize)]
struct GhJob {
    id: u64,
    name: String,
    #[serde(default)]
    conclusion: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct GhIssue {
    number: u64,
    title: String,
    html_url: String,
    /// Present on pull requests — `…/issues` returns both; PRs are not
    /// incidents.
    #[serde(default)]
    pull_request: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct GhComment {
    created_at: String,
    #[serde(default)]
    body: Option<String>,
}

/// Page through build-crate's `completed` runs since `since_iso`
/// (RFC3339) — both outcomes: the failure rate needs the denominator.
async fn fetch_completed_runs(gh_token: &str, since_iso: &str) -> Result<Vec<GhRun>, String> {
    let mut runs = Vec::new();
    let mut page = 1u32;
    loop {
        let page_runs: GhRunsPage = github::get(
            gh_token,
            &format!(
                "actions/workflows/{}/runs?status=completed&created=%3E%3D{since_iso}&per_page=100&page={page}",
                github::BUILD_WORKFLOW
            ),
        )
        .await
        .map_err(|error| error.to_string())?;
        let count = page_runs.workflow_runs.len();
        runs.extend(page_runs.workflow_runs);
        if count < 100 {
            break;
        }
        page += 1;
    }
    Ok(runs)
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

/// Trip the breaker: disable every dispatching workflow, then enable the
/// zone's `stow maintenance: anonymous` WAF rule — the shed happens in the
/// security phase, before the Worker, so a broken edge cannot keep the
/// breaker open. Both kinds of failure are collected — one failed disable
/// never skips the rule enable.
async fn apply_trip(watcher: &Watcher<'_>, outcome: &mut ApplyOutcome) {
    for workflow in TRIP_WORKFLOWS {
        match github::put(
            watcher.gh_token,
            &format!("actions/workflows/{workflow}/disable"),
        )
        .await
        {
            Ok(()) => outcome.actions.push(format!("disabled {workflow}")),
            Err(error) => outcome
                .failures
                .push(format!("disable {workflow}: {error}")),
        }
    }
    match maintenance::set_scope(
        watcher.cf_token,
        watcher.zone,
        MaintenanceScope::Anonymous,
        true,
        watcher.host,
    )
    .await
    {
        Ok(_) => outcome
            .actions
            .push("maintenance rule `stow maintenance: anonymous` enabled".to_owned()),
        Err(error) => outcome
            .failures
            .push(format!("enable maintenance rule: {error}")),
    }
}

/// Lift the breaker — `watchdog clear`'s actuation half.
async fn apply_clear(watcher: &Watcher<'_>, outcome: &mut ApplyOutcome) {
    match maintenance::set_scope(
        watcher.cf_token,
        watcher.zone,
        MaintenanceScope::Anonymous,
        false,
        watcher.host,
    )
    .await
    {
        Ok(_) => outcome
            .actions
            .push("maintenance rule `stow maintenance: anonymous` disabled".to_owned()),
        Err(error) => outcome
            .failures
            .push(format!("disable maintenance rule: {error}")),
    }
    for workflow in TRIP_WORKFLOWS {
        match github::put(
            watcher.gh_token,
            &format!("actions/workflows/{workflow}/enable"),
        )
        .await
        {
            Ok(()) => outcome.actions.push(format!("enabled {workflow}")),
            Err(error) => outcome.failures.push(format!("enable {workflow}: {error}")),
        }
    }
}

// ===== The incident issue =====

const INCIDENT_LABEL: &str = "incident";
/// Stable title prefix — dedup keys on it together with the label.
const INCIDENT_TITLE_PREFIX: &str = "stow incident:";
/// HTML marker stamped on digest comments so cadence is derivable.
const DIGEST_MARKER: &str = "<!-- stow-watchdog:update -->";
const CLEAR_MARKER: &str = "<!-- stow-watchdog:clear -->";
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
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(issues.into_iter().find(|issue| {
        issue.pull_request.is_none() && issue.title.starts_with(INCIDENT_TITLE_PREFIX)
    }))
}

/// Create the `incident` label when the repo lacks it — a 422 "already
/// exists" is success.
async fn ensure_label(gh_token: &str) -> Result<(), String> {
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
    let path = "labels";
    let url = format!("https://api.github.com/repos/{}/{path}", github::REPO);
    let mut client = zenwave::client();
    let response = client
        .post(&url)
        .and_then(|request| request.header("Authorization", format!("Bearer {gh_token}")))
        .and_then(|request| request.header("User-Agent", "stow-admin"))
        .and_then(|request| request.header("Accept", "application/vnd.github+json"))
        .and_then(|request| request.json_body(&label))
        .map_err(|error| format!("POST {url}: {error}"))?
        .await
        .map_err(|error| format!("POST {url}: {error}"))?;
    let status = response.status().as_u16();
    if status == 422 || (200..300).contains(&status) {
        return Ok(());
    }
    response
        .error_for_status()
        .await
        .map_err(|error| format!("POST {url}: {error}"))?;
    Ok(())
}

/// `digest_due` — is it an hour or more since the last watchdog comment?
fn digest_due(last: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
    last.is_none_or(|at| (now - at) >= time::Duration::seconds(DIGEST_PERIOD_SECS))
}

/// Newest digest comment time on the issue.
async fn last_digest_at(gh_token: &str, issue: u64) -> Result<Option<OffsetDateTime>, String> {
    let comments: Vec<GhComment> =
        github::get(gh_token, &format!("issues/{issue}/comments?per_page=100"))
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
    let window = if reading.signal.window_secs == 0 {
        "now".to_owned()
    } else if reading.signal.window_secs.is_multiple_of(3600) {
        format!("{}h", reading.signal.window_secs / 3600)
    } else {
        format!("{}m", reading.signal.window_secs / 60)
    };
    BreachView {
        id: reading.signal.id,
        label: reading.signal.label,
        effect: match reading.signal.effect {
            Effect::Trip => "trip",
            Effect::Alert => "alert",
        },
        window,
        observed: fmt_value(reading.value, reading.signal.unit),
        threshold: fmt_value(reading.signal.threshold, reading.signal.unit),
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
    let url = format!("{CLOUDFLARE_API_BASE}/accounts/{account}/email/sending/send");
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
    let cf_token = std::env::var(CLOUDFLARE_API_TOKEN_ENV)
        .map_err(|_| stow_error!("missing {CLOUDFLARE_API_TOKEN_ENV}"))?;
    let account =
        std::env::var(CF_ACCOUNT_ID_ENV).map_err(|_| stow_error!("missing {CF_ACCOUNT_ID_ENV}"))?;
    let zone =
        std::env::var(CF_ZONE_ID_ENV).map_err(|_| stow_error!("missing {CF_ZONE_ID_ENV}"))?;
    let host = maintenance::host_from_url(edge.base()).map_err(|error| stow_error!("{error}"))?;
    let watcher = Watcher {
        edge,
        gh_token: &gh_token,
        cf_token: &cf_token,
        account: &account,
        zone: &zone,
        host: &host,
        now: OffsetDateTime::now_utc(),
    };

    let (readings, collect_failures) = watcher.collect().await;
    let decision = decide(&readings, &collect_failures);
    let mut outcome = ApplyOutcome::default();
    let now_text = format_time(watcher.now);
    let mut issue_number: Option<u64> = None;

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
            outcome
                .actions
                .push("would disable dispatching workflows".to_owned());
            outcome
                .actions
                .push("would enable `stow maintenance: anonymous`".to_owned());
        } else {
            apply_trip(&watcher, &mut outcome).await;
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
                &gh_token,
                watcher.now,
                &now_text,
                &title,
                &breach_views,
                &failure_lines,
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

/// `watchdog clear` — maintenance rule off, workflows re-enabled, incident
/// commented+closed, clear-mail. Manual recovery; the watchdog never
/// does this on its own.
#[allow(clippy::too_many_lines)]
async fn clear(edge: &Edge, dry_run: bool, output: Output) -> stow_types::error::Result<()> {
    let gh_token = crate::github_token().await?;
    let cf_token = std::env::var(CLOUDFLARE_API_TOKEN_ENV)
        .map_err(|_| stow_error!("missing {CLOUDFLARE_API_TOKEN_ENV}"))?;
    let account =
        std::env::var(CF_ACCOUNT_ID_ENV).map_err(|_| stow_error!("missing {CF_ACCOUNT_ID_ENV}"))?;
    let zone =
        std::env::var(CF_ZONE_ID_ENV).map_err(|_| stow_error!("missing {CF_ZONE_ID_ENV}"))?;
    let host = maintenance::host_from_url(edge.base()).map_err(|error| stow_error!("{error}"))?;
    let watcher = Watcher {
        edge,
        gh_token: &gh_token,
        cf_token: &cf_token,
        account: &account,
        zone: &zone,
        host: &host,
        now: OffsetDateTime::now_utc(),
    };
    let mut outcome = ApplyOutcome::default();
    let now_text = format_time(watcher.now);
    if dry_run {
        outcome
            .actions
            .push("would disable `stow maintenance: anonymous`".to_owned());
        for workflow in TRIP_WORKFLOWS {
            outcome.actions.push(format!("would enable {workflow}"));
        }
        outcome
            .actions
            .push("would comment+close the open incident and send the clear mail".to_owned());
    } else {
        apply_clear(&watcher, &mut outcome).await;
        match find_incident(&gh_token).await {
            Err(error) => outcome
                .failures
                .push(format!("find incident issue: {error}")),
            Ok(None) => {}
            Ok(Some(issue)) => {
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

/// Open or update the incident issue. The open-vs-update branch is what
/// keeps a later run from opening a duplicate.
async fn upsert_incident(
    gh_token: &str,
    title: &str,
    body: &str,
) -> Result<(GhIssue, bool), String> {
    if let Some(issue) = find_incident(gh_token).await? {
        let updated: GhIssue = github::patch(
            gh_token,
            &format!("issues/{}", issue.number),
            &IssuePatch { title, body },
        )
        .await
        .map_err(|error| format!("PATCH issue #{}: {error}", issue.number))?;
        Ok((updated, false))
    } else {
        let issue: GhIssue = github::post(
            gh_token,
            "issues",
            &IssueNew {
                title,
                body,
                labels: [INCIDENT_LABEL],
            },
        )
        .await
        .map_err(|error| format!("POST issue: {error}"))?;
        Ok((issue, true))
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
struct IssueNew<'a> {
    title: &'a str,
    body: &'a str,
    labels: [&'a str; 1],
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

async fn post_comment(gh_token: &str, issue: u64, body: &str) -> Result<(), String> {
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
async fn close_incident(gh_token: &str, issue: u64, comment: &str) -> Result<(), String> {
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

/// Open-or-update the incident issue and hold its comment cadence — the
/// durable record channel. Called only on a real (non-dry-run) run with
/// an incident; any step that fails lands in `failure` rather than
/// aborting the mail that follows.
async fn update_incident(
    gh_token: &str,
    now: OffsetDateTime,
    now_text: &str,
    title: &str,
    breaches: &[BreachView<'_>],
    failure_lines: &[String],
    outcome: &mut ApplyOutcome,
) -> stow_types::error::Result<IssueOutcome> {
    let mut issue_outcome = IssueOutcome::default();
    if let Err(error) = ensure_label(gh_token).await {
        issue_outcome.failure = Some(format!("label: {error}"));
    } else {
        let body = IncidentTemplate {
            now: now_text,
            dry_run: false,
            breaches,
            actions: &outcome.actions,
            failures: failure_lines,
        }
        .render()
        .map_err(|error| stow_error!("render incident body: {error}"))?;
        match upsert_incident(gh_token, title, &body).await {
            Err(error) => issue_outcome.failure = Some(error),
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
                    match last_digest_at(gh_token, issue.number).await {
                        Ok(last) => {
                            if digest_due(last, now) {
                                let comment = DigestTemplate {
                                    now: now_text,
                                    breaches,
                                    failures: failure_lines,
                                    actions: &outcome.actions,
                                }
                                .render()
                                .map_err(|error| stow_error!("render digest: {error}"))?;
                                match post_comment(gh_token, issue.number, &comment).await {
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
            sample,
            value,
            evidence: vec![],
        }
    }

    /// Trip: a billed usage dimension over its hourly share → the
    /// decision is incident + tripped.
    #[test]
    fn usage_over_allowance_trips() {
        let readings = vec![reading(
            "cf.d1.rows_written",
            1,
            D1_ROWS_WRITTEN_MONTHLY / HOURS_PER_MONTH * 2.0,
        )];
        let decision = decide(&readings, &[]);
        assert!(decision.incident);
        assert_eq!(decision.tripped.len(), 1);
        assert!(decision.alerting.is_empty());
    }

    /// Below threshold → clear, no incident.
    #[test]
    fn usage_below_allowance_clears() {
        let readings = vec![reading("cf.d1.rows_written", 1, 1000.0)];
        let decision = decide(&readings, &[]);
        assert!(!decision.incident);
    }

    /// Minimum sample: 5 failed runs of 5 is 100% but below `min_sample`
    /// 20 → skipped, no trip.
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
        assert!(decision.tripped.is_empty());
        assert_eq!(decision.alerting.len(), 2);
    }

    /// A collector failure alone is an incident — the watchdog is blind.
    #[test]
    fn collector_failure_is_an_incident() {
        let decision = decide(
            &[reading("cf.d1.rows_read", 1, 1.0)],
            &[CollectFailure {
                scope: "pipeline",
                error: "403".to_owned(),
            }],
        );
        assert!(decision.incident);
        assert!(decision.tripped.is_empty());
    }

    /// Fixture: the GraphQL response decodes into a snapshot — trip
    /// readings land on the billed fields.
    #[test]
    fn graphql_fixture_decodes() {
        let json = r#"{"data":{"viewer":{"accounts":[{
            "doPeriodic":[{"sum":{"activeTime":12,"cpuTime":5,"duration":700,"exceededCpuErrors":0,"exceededMemoryErrors":0,"fatalInternalErrors":0,"rowsRead":40000000000,"rowsWritten":1000,"storageDeletes":0,"storageReadUnits":0,"storageWriteUnits":0,"subrequests":9}}],
            "doInvoke":[{"sum":{"requests":2000,"wallTime":9,"errors":0}}],
            "worker":[{"sum":{"clientDisconnects":0,"cpuTimeUs":45000000,"duration":1,"errors":0,"requestDuration":2,"requests":15000,"responseBodySize":0,"subrequests":300,"wallTime":4}}],
            "workerStatus":[{"dimensions":{"status":"success"},"sum":{"requests":100}},{"dimensions":{"status":"scriptThrewException"},"sum":{"requests":4}}],
            "d1":[{"sum":{"rowsRead":10,"rowsWritten":5}}]
        }]}}}"#;
        let envelope: GraphqlResponse = serde_json::from_str(json).unwrap();
        let account = envelope
            .data
            .unwrap()
            .viewer
            .accounts
            .into_iter()
            .next()
            .unwrap();
        let snapshot = CfSnapshot::from(account);
        let readings = snapshot.readings();
        let decision = decide(&readings, &[]);
        assert!(decision.incident);
        // rows_read 40G > 34.7M threshold and worker 15k req > 13.9k → trips
        assert!(decision.tripped.len() >= 2);
        // 4/104 scriptThrew = 3.8% > 2% → alert
        assert_eq!(
            decision
                .alerting
                .iter()
                .map(|&i| readings[i].signal.id)
                .collect::<Vec<_>>(),
            vec!["edge.worker.errors"]
        );
    }

    /// A GraphQL `errors` array is a hard error — never a partial read.
    #[test]
    fn graphql_errors_array_is_a_hard_error() {
        let json = r#"{"data":null,"errors":[{"message":"bad field"}]}"#;
        let envelope: GraphqlResponse = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.errors.unwrap().len(), 1);
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
            pull_request: Some(serde_json::json!({"url": "x"})),
        };
        assert!(pr.pull_request.is_some());
    }

    /// `endpoint.*` breaches on a non-200 regardless of latency.
    #[test]
    fn non_200_is_a_breach() {
        let reading = Reading {
            signal: signal("endpoint.stats"),
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
            id: "cf.d1.rows_written",
            label: "D1 rows",
            effect: "trip",
            window: "1h".to_owned(),
            observed: "1.4M rows".to_owned(),
            threshold: "69.4k rows".to_owned(),
            evidence: &[],
        };
        let body = IncidentTemplate {
            now: "2026-09-28T00:00:00Z",
            dry_run: false,
            breaches: &[breach],
            actions: &["disabled build-crate.yml".to_owned()],
            failures: &[],
        }
        .render()
        .unwrap();
        assert!(body.contains("cf.d1.rows_written"));
        assert!(body.contains("disabled build-crate.yml"));
    }

    /// `clear` plans maintenance-off plus every workflow enable.
    #[test]
    fn clear_reverses_the_trip_list() {
        assert_eq!(TRIP_WORKFLOWS.len(), 6);
        assert!(TRIP_WORKFLOWS.contains(&"build-crate.yml"));
        assert!(TRIP_WORKFLOWS.iter().all(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("yml"))
        }));
    }

    /// `pipeline_readings`'s classifier path — job names carry targets,
    /// logs classify through `runs`'s table.
    #[test]
    fn job_name_target_parses() {
        let name = "build serde_json 1.0.149 (aarch64-apple-darwin)";
        let target = name
            .rsplit('(')
            .next()
            .and_then(|tail| tail.strip_suffix(')'));
        assert_eq!(target, Some("aarch64-apple-darwin"));
    }
}
